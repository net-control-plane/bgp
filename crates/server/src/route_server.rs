// Copyright 2021 Rayhaan Jaufeerally.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::peer::PeerCommands;
use crate::rib_manager;
use crate::rib_manager::PathSource;
use crate::rib_manager::RibSnapshot;
use crate::rib_manager::RouteManagerCommands;
use crate::route_server::route_server::bgp_server_admin_service_server::BgpServerAdminService;
use crate::route_server::route_server::route_service_server::RouteService;
use crate::route_server::route_server::AddressFamily;
use crate::route_server::route_server::DumpPathsRequest;
use crate::route_server::route_server::DumpPathsResponse;
use crate::route_server::route_server::Path;
use crate::route_server::route_server::PathSet;
use crate::route_server::route_server::Prefix;
use crate::route_server::route_server::StreamPathsRequest;
use bgp_packet::constants::AddressFamilyIdentifier;
use route_server::PeerStatusRequest;
use route_server::PeerStatusResponse;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Response;
use tonic::Status;
use tracing::warn;

pub mod route_server {
    tonic::include_proto!("bgpd.grpc");
}

#[derive(Clone)]
pub struct RouteServer {
    pub ip4_manager: UnboundedSender<RouteManagerCommands<Ipv4Addr>>,
    pub ip6_manager: UnboundedSender<RouteManagerCommands<Ipv6Addr>>,

    pub peer_state_machines: HashMap<String, UnboundedSender<PeerCommands>>,
}

impl RouteServer {
    async fn get_streaming_receiver<A>(
        &self,
        manager: UnboundedSender<RouteManagerCommands<A>>,
        // dump_tx is used to receive the current state before streaming starts.
        dump_tx: UnboundedSender<(u64, rib_manager::PathSet<A>)>,
    ) -> Result<broadcast::Receiver<(u64, rib_manager::PathSet<A>)>, Status> {
        let (stream_tx, stream_rx) =
            oneshot::channel::<broadcast::Receiver<(u64, rib_manager::PathSet<A>)>>();
        if let Err(e) = manager.send(RouteManagerCommands::StreamRib(dump_tx, stream_tx)) {
            warn!("Failed to send StreamRib command to route manager: {}", e);
            return Err(tonic::Status::internal(
                "failed to communicate with route manager".to_owned(),
            ));
        }

        stream_rx
            .await
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }

    /// Converts a rib_manager::PathSet into the proto format PathSet using the
    /// appropriate address family.
    fn transform_pathset<A>(
        mgr_ps: (u64, rib_manager::PathSet<A>),
        address_family: i32,
    ) -> PathSet {
        let mut proto_pathset = PathSet {
            epoch: mgr_ps.0,
            prefix: Some(Prefix {
                ip_prefix: mgr_ps.1.nlri.prefix,
                prefix_len: mgr_ps.1.nlri.prefixlen.into(),
                address_family,
            }),
            paths: vec![],
        };
        for (_, path) in mgr_ps.1.paths {
            let proto_path = Path {
                as_path: path.as_path.clone(),
                local_pref: path.local_pref,
                med: path.med,
                nexthop: path.nexthop.clone(),
                peer_id: match path.path_source {
                    PathSource::LocallyConfigured => vec![],
                    PathSource::BGPPeer(peer) => peer.octets().to_vec(),
                },
            };
            proto_pathset.paths.push(proto_path);
        }
        proto_pathset
    }
}

#[tonic::async_trait]
impl BgpServerAdminService for RouteServer {
    async fn peer_status(
        &self,
        request: tonic::Request<PeerStatusRequest>,
    ) -> Result<Response<PeerStatusResponse>, Status> {
        let mut result = PeerStatusResponse::default();

        for peer in &self.peer_state_machines {
            let (tx, rx) = oneshot::channel();
            if let Err(e) = peer.1.send(PeerCommands::GetStatus(tx)) {
                warn!(
                    peer = peer.0,
                    "Peer channel dead when trying to send state request"
                );
                continue;
            }
            let resp = rx.await.map_err(|e| Status::internal(format!("{}", e)))?;
            result.peer_status.push(resp);
        }

        Ok(Response::new(result))
    }
}

#[tonic::async_trait]
impl RouteService for RouteServer {
    async fn dump_paths(
        &self,
        request: tonic::Request<DumpPathsRequest>,
    ) -> Result<Response<DumpPathsResponse>, Status> {
        let mut response = DumpPathsResponse {
            epoch: 0,
            path_sets: vec![],
        };

        let afi = AddressFamilyIdentifier::try_from(request.get_ref().address_family as u16)
            .map_err(|e| tonic::Status::internal(e.to_string()))?;
        match afi {
            AddressFamilyIdentifier::Ipv4 => {
                let (tx, rx) = tokio::sync::oneshot::channel::<RibSnapshot<Ipv4Addr>>();
                if let Err(e) = self.ip4_manager.send(RouteManagerCommands::DumpRib(tx)) {
                    warn!("Failed to send DumpRib command to route manager: {}", e);
                    return Err(tonic::Status::internal(
                        "failed to communicate with route manager",
                    ));
                }
                match rx.await {
                    Ok(result) => {
                        response.epoch = result.epoch;
                        for pathset in result.routes {
                            let mut proto_pathset = PathSet {
                                epoch: result.epoch,
                                prefix: Some(Prefix {
                                    ip_prefix: pathset.nlri.prefix,
                                    prefix_len: pathset.nlri.prefixlen.into(),
                                    address_family: AddressFamily::IPv4.into(),
                                }),
                                paths: vec![],
                            };
                            for (_, path) in pathset.paths {
                                let proto_path = Path {
                                    as_path: path.as_path.clone(),
                                    local_pref: path.local_pref,
                                    med: path.med,
                                    nexthop: path.nexthop.clone(),
                                    peer_id: match path.path_source {
                                        PathSource::LocallyConfigured => vec![],
                                        PathSource::BGPPeer(peer) => peer.octets().to_vec(),
                                    },
                                };
                                proto_pathset.paths.push(proto_path);
                            }
                            response.path_sets.push(proto_pathset);
                        }

                        Ok(tonic::Response::new(response))
                    }
                    Err(e) => {
                        warn!("Failed to get response from route manager: {}", e);
                        return Err(tonic::Status::internal(
                            "failed to get response from route manager",
                        ));
                    }
                }
            }
            AddressFamilyIdentifier::Ipv6 => {
                let (tx, rx) = tokio::sync::oneshot::channel::<RibSnapshot<Ipv6Addr>>();
                if let Err(e) = self.ip6_manager.send(RouteManagerCommands::DumpRib(tx)) {
                    warn!("Failed to send DumpRib command to route manager: {}", e);
                    return Err(tonic::Status::internal(
                        "failed to communicate with route manager",
                    ));
                }
                match rx.await {
                    Ok(result) => {
                        response.epoch = result.epoch;
                        for pathset in result.routes {
                            let mut proto_pathset = PathSet {
                                epoch: result.epoch,
                                prefix: Some(Prefix {
                                    ip_prefix: pathset.nlri.prefix,
                                    prefix_len: pathset.nlri.prefixlen.into(),
                                    address_family: AddressFamily::IPv6.into(),
                                }),
                                paths: vec![],
                            };
                            for (_, path) in pathset.paths {
                                let proto_path = Path {
                                    as_path: path.as_path.clone(),
                                    local_pref: path.local_pref,
                                    med: path.med,
                                    nexthop: path.nexthop.clone(),
                                    peer_id: match path.path_source {
                                        PathSource::LocallyConfigured => vec![],
                                        PathSource::BGPPeer(peer) => peer.octets().to_vec(),
                                    },
                                };
                                proto_pathset.paths.push(proto_path);
                            }
                            response.path_sets.push(proto_pathset);
                        }

                        Ok(tonic::Response::new(response))
                    }
                    Err(e) => {
                        warn!("Failed to get response from route manager: {}", e);
                        return Err(tonic::Status::internal(
                            "failed to get response from route manager",
                        ));
                    }
                }
            }
        }
    }

    type StreamPathsStream = ReceiverStream<Result<PathSet, Status>>;

    async fn stream_paths(
        &self,
        request: tonic::Request<StreamPathsRequest>,
    ) -> Result<Response<Self::StreamPathsStream>, Status> {
        match request.get_ref().address_family {
            1 => {
                let (dump_tx, mut dump_rx) = mpsc::unbounded_channel();
                let mut receiver = self
                    .get_streaming_receiver::<Ipv4Addr>(self.ip4_manager.clone(), dump_tx)
                    .await?;

                let (tx, rx) = mpsc::channel(10_000);
                // Spawn a task for receving values from the manager and send them to the peer.
                tokio::spawn(async move {
                    // Consume the dump before moving to the streamed paths.
                    while let Some(next) = dump_rx.recv().await {
                        let pathset =
                            RouteServer::transform_pathset(next, AddressFamily::IPv4.into());
                        if let Err(e) = tx.send(Ok(pathset)).await {
                            warn!("Failed to send path to peer: {}", e);
                            return;
                        }
                    }

                    loop {
                        let next = receiver.recv().await;
                        if let Err(e) = next {
                            warn!("Failed to get next streaming route from manager: {}", e);
                            let _ = tx
                                .send(Err(tonic::Status::internal(format!(
                                    "Failed to get next route from manager: {}",
                                    e
                                ))))
                                .await;
                            return;
                        }
                        let route = next.unwrap();
                        if let Err(e) = tx
                            .send(Ok(RouteServer::transform_pathset(
                                route,
                                AddressFamily::IPv4.into(),
                            )))
                            .await
                        {
                            warn!("Failed to send streaming route to peer: {}", e);
                            return;
                        }
                    }
                });

                return Ok(Response::new(ReceiverStream::new(rx)));
            }
            2 => {
                let (dump_tx, mut dump_rx) = mpsc::unbounded_channel();
                let mut receiver = self
                    .get_streaming_receiver::<Ipv6Addr>(self.ip6_manager.clone(), dump_tx)
                    .await?;

                let (tx, rx) = mpsc::channel(10_000);
                // Spawn a task for receving values from the manager and send them to the peer.
                tokio::spawn(async move {
                    // Consume the dump before moving to the streamed paths.
                    while let Some(next) = dump_rx.recv().await {
                        let pathset =
                            RouteServer::transform_pathset(next, AddressFamily::IPv4.into());
                        if let Err(e) = tx.send(Ok(pathset)).await {
                            warn!("Failed to send path to peer: {}", e);
                            return;
                        }
                    }
                    loop {
                        let next = receiver.recv().await;
                        if let Err(e) = next {
                            warn!("Failed to get next streaming route from manager: {}", e);
                            let _ = tx
                                .send(Err(tonic::Status::internal(format!(
                                    "Failed to get next route from manager: {}",
                                    e
                                ))))
                                .await;
                            return;
                        }
                        let route = next.unwrap();
                        if let Err(e) = tx
                            .send(Ok(RouteServer::transform_pathset(
                                route,
                                AddressFamily::IPv6.into(),
                            )))
                            .await
                        {
                            warn!("Failed to send streaming route to peer: {}", e);
                            return;
                        }
                    }
                });

                return Ok(Response::new(ReceiverStream::new(rx)));
            }
            _ => return Err(tonic::Status::internal("Unknown address family")),
        };
    }
}

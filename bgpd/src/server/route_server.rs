// Copyright 2021 Google LLC.
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

use crate::bgp_packet::constants::address_family_identifier_values;
use crate::bgp_packet::constants::AddressFamilyIdentifier;
use crate::server::rib_manager;
use crate::server::rib_manager::RibSnapshot;
use crate::server::rib_manager::RouteManagerCommands;
use crate::server::route_server::route_server::route_service_server::RouteService;
use crate::server::route_server::route_server::AddressFamily;
use crate::server::route_server::route_server::DumpPathsRequest;
use crate::server::route_server::route_server::DumpPathsResponse;
use crate::server::route_server::route_server::Path;
use crate::server::route_server::route_server::PathSet;
use crate::server::route_server::route_server::Prefix;
use crate::server::route_server::route_server::StreamPathsRequest;
use log::warn;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Response;
use tonic::Status;

pub mod route_server {
    tonic::include_proto!("bgpd.grpc");
}

pub struct RouteServer {
    pub ip4_manager: UnboundedSender<RouteManagerCommands<Ipv4Addr>>,
    pub ip6_manager: UnboundedSender<RouteManagerCommands<Ipv6Addr>>,
}

impl RouteServer {
    async fn get_streaming_receiver<A>(
        &self,
        manager: UnboundedSender<RouteManagerCommands<A>>,
    ) -> Result<broadcast::Receiver<rib_manager::PathSet<A>>, Status> {
        let (tx, rx) = oneshot::channel::<broadcast::Receiver<rib_manager::PathSet<A>>>();
        if let Err(e) = manager.send(RouteManagerCommands::StreamRib(tx)) {
            warn!("Failed to send StreamRib command to route manager: {}", e);
            return Err(tonic::Status::internal(
                "failed to communicate with route manager".to_owned(),
            ));
        }

        rx.await.map_err(|e| tonic::Status::internal(e.to_string()))
    }

    fn transform_pathset<A>(mgr_ps: rib_manager::PathSet<A>, address_family: i32) -> PathSet {
        let mut proto_pathset = PathSet {
            epoch: 0,
            prefix: Some(Prefix {
                ip_prefix: mgr_ps.nlri.prefix,
                prefix_len: mgr_ps.nlri.prefixlen.into(),
                address_family,
            }),
            paths: vec![],
        };
        for (_, path) in mgr_ps.paths {
            let proto_path = Path {
                as_path: path.as_path,
                local_pref: path.local_pref,
                med: path.med,
                nexthop: path.nexthop,
                peer_name: path.peer_name,
            };
            proto_pathset.paths.push(proto_path);
        }
        proto_pathset
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
        match AddressFamilyIdentifier(request.get_ref().address_family as u16) {
            address_family_identifier_values::IPV4 => {
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
                                    as_path: path.as_path,
                                    local_pref: path.local_pref,
                                    med: path.med,
                                    nexthop: path.nexthop,
                                    peer_name: path.peer_name,
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
            address_family_identifier_values::IPV6 => {
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
                                    as_path: path.as_path,
                                    local_pref: path.local_pref,
                                    med: path.med,
                                    nexthop: path.nexthop,
                                    peer_name: path.peer_name,
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
            _ => {
                return Err(tonic::Status::invalid_argument("Unknown address_family"));
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
                let mut receiver = self
                    .get_streaming_receiver::<Ipv4Addr>(self.ip4_manager.clone())
                    .await?;

                let (tx, rx) = mpsc::channel(10_000);
                // Spawn a task for receving values from the manager and send them to the peer.
                tokio::spawn(async move {
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
                let mut receiver = self
                    .get_streaming_receiver::<Ipv6Addr>(self.ip6_manager.clone())
                    .await?;

                let (tx, rx) = mpsc::channel(10_000);
                // Spawn a task for receving values from the manager and send them to the peer.
                tokio::spawn(async move {
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

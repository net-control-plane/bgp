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

pub mod fib_state;
pub mod netlink;
pub mod southbound_interface;

use std::convert::TryInto;
use std::net::IpAddr;
use std::net::Ipv4Addr;

use std::net::Ipv6Addr;
use std::str::FromStr;
use std::time::Duration;

use bgp_packet::constants::AddressFamilyIdentifier;
use bgp_packet::nlri::NLRI;

use eyre::{anyhow, Result};
use ip_network_table_deps_treebitmap::IpLookupTable;
use tonic::transport::Endpoint;
use tonic::transport::Uri;
use tracing::{info, trace, warn};

use crate::fib_state::FibState;
use crate::proto::route_service_client::RouteServiceClient;
use crate::southbound_interface::SouthboundInterface;

pub mod proto {
    tonic::include_proto!("bgpd.grpc");
}

fn vec_to_array<T, const N: usize>(v: Vec<T>) -> Result<[T; N]> {
    v.try_into()
        .map_err(|_| eyre::Error::msg("Wrong size of Vec".to_string()))
}

/// Temporary hack to select the route to install to the FIB.
/// TODO: Implement proper route selection logic.
fn select_best_route(ps: &proto::PathSet) -> Option<proto::Path> {
    let mut selected: Option<proto::Path> = None;
    for path in &ps.paths {
        if let Some(current) = selected.as_ref() {
            if path.local_pref < current.local_pref {
                selected = Some(path.clone());
            }
        } else {
            selected = Some(path.clone());
        }
    }
    selected
}

pub async fn run_connector_v4<S: SouthboundInterface>(
    route_server: String,
    dry_run: bool,
    southbound: S,
) -> Result<()> {
    // Create netlink socket.
    let mut fib_state = FibState::<Ipv4Addr, S> {
        fib: IpLookupTable::new(),
        southbound,
        af: AddressFamilyIdentifier::Ipv4,
    };

    let uri = Uri::from_str(route_server.as_str()).unwrap();
    let endpoint = Endpoint::from(uri).keep_alive_timeout(Duration::from_secs(10));
    let mut client = RouteServiceClient::connect(endpoint).await?;
    let request = proto::StreamPathsRequest {
        address_family: proto::AddressFamily::IPv4.into(),
    };

    let mut stream = client.stream_paths(request).await?.into_inner();
    let mut msg_ctr: u64 = 0;
    while let Some(route) = stream.message().await? {
        let nlri = NLRI {
            afi: AddressFamilyIdentifier::Ipv4,
            prefixlen: route.prefix.as_ref().unwrap().prefix_len as u8,
            prefix: route.prefix.as_ref().unwrap().ip_prefix.clone(),
        };

        trace!("IPv4 Update {} for: {} ", msg_ctr, nlri);
        msg_ctr += 1;

        if !dry_run {
            if !route.paths.is_empty() {
                if let Some(best) = select_best_route(&route) {
                    // Hack to convert the nexthop into a v4 addr
                    let nh_bytes: [u8; 4] = vec_to_array(best.nexthop.clone())?;
                    let nh_addr: Ipv4Addr = Ipv4Addr::from(nh_bytes);
                    if let Err(e) = fib_state.route_add(&nlri, IpAddr::V4(nh_addr)).await {
                        warn!("Failed to add route into kernel: {}: {}", nlri, e);
                    }
                }
            } else {
                // No more paths, delete
                if let Err(e) = fib_state.route_del(nlri).await {
                    warn!("Failed to delete route from kernel: {}", e);
                }
            }
        }

        trace!("Number of paths: {}", route.paths.len());
        for path in &route.paths {
            // TODO: have a proper error here not unwrap.
            let nexthop_bytes: [u8; 4] = path.nexthop.clone().try_into().unwrap();
            let nexthop: Ipv4Addr = nexthop_bytes.into();
            trace!(
                "nexthop: {}, peer_id: {:x?}, local_pref: {}, med: {}, as_path: {:?}",
                nexthop,
                path.peer_id,
                path.local_pref,
                path.med,
                path.as_path
            );
        }
    }

    unreachable!()
}

pub async fn run_connector_v6<S: SouthboundInterface>(
    route_server: String,
    dry_run: bool,
    southbound: S,
) -> Result<()> {
    let mut fib_state = FibState::<Ipv6Addr, S> {
        fib: IpLookupTable::new(),
        southbound,
        af: AddressFamilyIdentifier::Ipv6,
    };

    let uri = Uri::from_str(route_server.as_str()).unwrap();
    let endpoint = Endpoint::from(uri).keep_alive_timeout(Duration::from_secs(10));
    let mut client = RouteServiceClient::connect(endpoint).await?;
    let request = proto::StreamPathsRequest {
        address_family: proto::AddressFamily::IPv6.into(),
    };
    info!("Request: {:?}", request);

    let mut stream = client.stream_paths(request).await?.into_inner();
    let mut msg_ctr: u64 = 0;
    while let Some(route) = stream.message().await? {
        let nlri = NLRI {
            afi: AddressFamilyIdentifier::Ipv6,
            prefixlen: route.prefix.as_ref().unwrap().prefix_len as u8,
            prefix: route.prefix.as_ref().unwrap().ip_prefix.clone(),
        };

        trace!("IPv6 Update {} for: {} ", msg_ctr, nlri);
        msg_ctr += 1;

        if !dry_run {
            if !route.paths.is_empty() {
                if let Some(best) = select_best_route(&route) {
                    // Hack to convert the nexthop into a v6 addr
                    let nh_bytes: [u8; 16] = vec_to_array(best.nexthop.clone())?;
                    let nh_addr: Ipv6Addr = Ipv6Addr::from(nh_bytes);
                    if let Err(e) = fib_state.route_add(&nlri, IpAddr::V6(nh_addr)).await {
                        warn!("Failed to add route into kernel: {}: {}", nlri, e);
                    }
                }
            } else {
                // No more paths, delete
                if let Err(e) = fib_state.route_del(nlri).await {
                    warn!("Failed to delete route from kernel: {}", e);
                }
            }
        }

        trace!("Number of paths: {}", route.paths.len());
        for path in &route.paths {
            // TODO: have a proper error here not unwrap.
            let nexthop_bytes: [u8; 16] = path.nexthop.clone().try_into().unwrap();
            let nexthop: Ipv6Addr = nexthop_bytes.into();
            trace!(
                "nexthop: {}, peer_id: {:x?}, local_pref: {}, med: {}, as_path: {:?}",
                nexthop,
                path.peer_id,
                path.local_pref,
                path.med,
                path.as_path
            );
        }
    }

    unreachable!()
}

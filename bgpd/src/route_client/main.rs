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

use bgpd::route_client::netlink::NetlinkConnector;
use bgpd::route_client::southbound_interface::SouthboundInterface;
use clap::Parser;
use log::trace;
use std::convert::TryInto;
use std::net::IpAddr;
use std::net::Ipv4Addr;

use std::net::Ipv6Addr;
use std::str::FromStr;
use std::time::Duration;
use tonic::transport::Uri;

use bgpd::bgp_packet::constants::AddressFamilyIdentifier;
use bgpd::bgp_packet::nlri::NLRI;
use bgpd::route_client::fib_state::FibState;

use ip_network_table_deps_treebitmap::IpLookupTable;
use tonic::transport::Endpoint;
use tracing::{info, warn};

use anyhow::{anyhow, Result};

use crate::proto::route_service_client::RouteServiceClient;

pub mod proto {
    tonic::include_proto!("bgpd.grpc");
}

fn vec_to_array<T, const N: usize>(v: Vec<T>) -> Result<[T; N], anyhow::Error> {
    v.try_into()
        .map_err(|_| anyhow::Error::msg("Wrong size of Vec".to_string()))
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

async fn run_connector_v4<S: SouthboundInterface>(
    route_server: String,
    rt_table: u32,
    dry_run: bool,
    southbound: S,
) -> Result<(), anyhow::Error> {
    // Create netlink socket.
    let mut fib_state = FibState::<Ipv4Addr, S> {
        fib: IpLookupTable::new(),
        southbound,
        af: AddressFamilyIdentifier::Ipv4,
        table: rt_table,
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
                        return Err(anyhow!("Failed to add route {}: {}", nlri, e));
                    }
                }
            } else {
                // No more paths, delete
                if let Err(e) = fib_state.route_del(nlri).await {
                    return Err(anyhow!("Failed to delete route: {}", e));
                }
            }
        }

        trace!("Number of paths: {}", route.paths.len());
        for path in &route.paths {
            // TODO: have a proper error here not unwrap.
            let nexthop_bytes: [u8; 4] = path.nexthop.clone().try_into().unwrap();
            let nexthop: Ipv4Addr = nexthop_bytes.into();
            trace!(
                "nexthop: {}, peer: {}, local_pref: {}, med: {}, as_path: {:?}",
                nexthop,
                path.peer_name,
                path.local_pref,
                path.med,
                path.as_path
            );
        }
    }

    unreachable!()
}

async fn run_connector_v6<S: SouthboundInterface>(
    route_server: String,
    rt_table: u32,
    dry_run: bool,
    southbound: S,
) -> Result<()> {
    let mut fib_state = FibState::<Ipv6Addr, S> {
        fib: IpLookupTable::new(),
        southbound,
        af: AddressFamilyIdentifier::Ipv6,
        table: rt_table,
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
                        return Err(anyhow!("Failed to add route {}: {}", nlri, e));
                    }
                }
            } else {
                // No more paths, delete
                if let Err(e) = fib_state.route_del(nlri).await {
                    return Err(anyhow!("Failed to delete route: {}", e));
                }
            }
        }

        trace!("Number of paths: {}", route.paths.len());
        for path in &route.paths {
            // TODO: have a proper error here not unwrap.
            let nexthop_bytes: [u8; 16] = path.nexthop.clone().try_into().unwrap();
            let nexthop: Ipv6Addr = nexthop_bytes.into();
            trace!(
                "nexthop: {}, peer: {}, local_pref: {}, med: {}, as_path: {:?}",
                nexthop,
                path.peer_name,
                path.local_pref,
                path.med,
                path.as_path
            );
        }
    }

    unreachable!()
}

#[derive(Parser)]
#[clap(
    author = "Rayhaan Jaufeerally <rayhaan@rayhaan.ch>",
    version = "0.1",
    about = "Installs routes from a BGP speaker via streaming RPC to the forwarding plane"
)]
struct Cli {
    #[clap(long = "route_server")]
    route_server: String,
    #[clap(long = "rt_table")]
    rt_table: Option<u32>,
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    let _init_log = stderrlog::new()
        .verbosity(2) // Shows info level.
        .show_module_names(true)
        .init();
    info!("Starting route client");

    let rt_table = match args.rt_table {
        Some(table) => table,
        None => 201,
    };

    let v4_joinhandle = {
        let server_addr = args.route_server.clone();
        tokio::task::spawn(async move {
            run_connector_v4::<NetlinkConnector>(
                server_addr.clone(),
                rt_table,
                args.dry_run,
                NetlinkConnector::new(Some(rt_table)).await.unwrap(),
            )
            .await
            .unwrap();
        })
    };

    let v6_joinhandle = {
        let server_addr = args.route_server.clone();
        tokio::task::spawn(async move {
            run_connector_v6::<NetlinkConnector>(
                server_addr,
                rt_table,
                args.dry_run,
                NetlinkConnector::new(Some(rt_table)).await.unwrap(),
            )
            .await
            .unwrap();
        })
    };

    tokio::select! {
        _ = v4_joinhandle => {
            warn!("Unexpected exit of IPv4 connector");
        },
        _ = v6_joinhandle => {
            warn!("Unexpected exit of IPv6 connector");
        }
    }

    Ok(())
}

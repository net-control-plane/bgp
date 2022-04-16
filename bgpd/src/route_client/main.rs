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
use clap::Arg;
use clap::Command;
use std::convert::TryInto;
use std::net::Ipv4Addr;

use std::net::Ipv6Addr;
use std::str::FromStr;
use std::time::Duration;
use tonic::transport::Uri;

use bgpd::bgp_packet::constants::AddressFamilyIdentifier;
use bgpd::bgp_packet::nlri::NLRI;
use bgpd::route_client::fib_state::FibState;
use bgpd::server::route_server::route_server::{
    route_service_client::RouteServiceClient, StreamPathsRequest,
};
use netlink::netlink_interface::NetlinkInterface;

use tonic::transport::Endpoint;
use tracing::{info, warn};
use treebitmap::IpLookupTable;

fn vec_to_array<T, const N: usize>(v: Vec<T>) -> Result<[T; N], anyhow::Error> {
    v.try_into()
        .map_err(|_| anyhow::Error::msg("Wrong size of Vec".to_string()))
}

async fn run_connector_v4(
    route_server: &str,
    rt_table: u32,
    dry_run: bool,
) -> Result<(), anyhow::Error> {
    // Create netlink socket.
    unsafe {
        let nl_iface = NetlinkInterface::new().unwrap();

        let mut fib_state = FibState::<Ipv4Addr> {
            fib: IpLookupTable::new(),
            nl_iface,
            af: libc::AF_INET as u8,
            table: rt_table,
        };

        let uri = Uri::from_str(route_server).unwrap();
        let endpoint = Endpoint::from(uri).keep_alive_timeout(Duration::from_secs(10));
        let mut client = RouteServiceClient::connect(endpoint).await?;
        let request = StreamPathsRequest {
            address_family: (AddressFamilyIdentifier::Ipv4 as u16) as i32,
        };

        let mut stream = client.stream_paths(request).await?.into_inner();
        let mut msg_ctr: u64 = 0;
        while let Some(route) = stream.message().await? {
            let nlri = NLRI {
                afi: AddressFamilyIdentifier::Ipv4,
                prefixlen: route.prefix.as_ref().unwrap().prefix_len as u8,
                prefix: route.prefix.as_ref().unwrap().ip_prefix.clone(),
            };

            info!("IPv4 Update {} for: {} ", msg_ctr, nlri);
            msg_ctr += 1;

            if !dry_run {
                if !route.paths.is_empty() {
                    // Install the best route
                    let best_path = &route.paths[0];

                    // Hack to convert the nexthop into a v6 addr
                    let nh_bytes: [u8; 4] = vec_to_array(best_path.nexthop.clone())?;
                    let nh_addr: Ipv4Addr = Ipv4Addr::from(nh_bytes);
                    if let Err(e) = fib_state.route_add(&nlri, nh_addr) {
                        warn!("Failed to add route {}: {}", nlri, e);
                    }
                } else {
                    // No more paths, delete
                    if let Err(e) = fib_state.route_del(nlri) {
                        warn!("Failed to delete route: {}", e);
                    }
                }
            }

            info!("Number of paths: {}", route.paths.len());
            for path in &route.paths {
                // TODO: have a proper error here not unwrap.
                let nexthop_bytes: [u8; 4] = path.nexthop.clone().try_into().unwrap();
                let nexthop: Ipv4Addr = nexthop_bytes.into();
                info!(
                    "nexthop: {}, peer: {}, local_pref: {}, med: {}, as_path: {:?}",
                    nexthop, path.peer_name, path.local_pref, path.med, path.as_path
                );
            }
        }
    }
    unreachable!()
}

async fn run_connector_v6(
    route_server: &str,
    rt_table: u32,
    dry_run: bool,
) -> Result<(), anyhow::Error> {
    // Create netlink socket.
    unsafe {
        let nl_iface = NetlinkInterface::new().unwrap();

        let mut fib_state = FibState::<Ipv6Addr> {
            fib: IpLookupTable::new(),
            nl_iface,
            af: libc::AF_INET6 as u8,
            table: rt_table,
        };

        let uri = Uri::from_str(route_server).unwrap();
        let endpoint = Endpoint::from(uri).keep_alive_timeout(Duration::from_secs(10));
        let mut client = RouteServiceClient::connect(endpoint).await?;
        let request = StreamPathsRequest {
            address_family: (AddressFamilyIdentifier::Ipv6 as u16) as i32,
        };

        let mut stream = client.stream_paths(request).await?.into_inner();
        let mut msg_ctr: u64 = 0;
        while let Some(route) = stream.message().await? {
            let nlri = NLRI {
                afi: AddressFamilyIdentifier::Ipv6,
                prefixlen: route.prefix.as_ref().unwrap().prefix_len as u8,
                prefix: route.prefix.as_ref().unwrap().ip_prefix.clone(),
            };

            info!("IPv6 Update {} for: {} ", msg_ctr, nlri);
            msg_ctr += 1;

            if !dry_run {
                if !route.paths.is_empty() {
                    // Install the best route
                    let best_path = &route.paths[0];

                    // Hack to convert the nexthop into a v6 addr
                    let nh_bytes: [u8; 16] = vec_to_array(best_path.nexthop.clone())?;
                    let nh_addr: Ipv6Addr = Ipv6Addr::from(nh_bytes);
                    if let Err(e) = fib_state.route_add(&nlri, nh_addr) {
                        warn!("Failed to add route {}: {}", nlri, e);
                    }
                } else {
                    // No more paths, delete
                    if let Err(e) = fib_state.route_del(nlri) {
                        warn!("Failed to delete route: {}", e);
                    }
                }
            }

            info!("Number of paths: {}", route.paths.len());
            for path in &route.paths {
                // TODO: have a proper error here not unwrap.
                let nexthop_bytes: [u8; 16] = path.nexthop.clone().try_into().unwrap();
                let nexthop: Ipv6Addr = nexthop_bytes.into();
                info!(
                    "nexthop: {}, peer: {}, local_pref: {}, med: {}, as_path: {:?}",
                    nexthop, path.peer_name, path.local_pref, path.med, path.as_path
                );
            }
        }
    }
    unreachable!()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("route_client")
        .author("Rayhaan Jaufeerally <rayahaan@rayhaan.ch>")
        .version("0.1")
        .about("Installs routes from a streaming API into Netlink.")
        .arg(
            Arg::new("route_server")
                .long("route_server")
                .takes_value(true)
                .help("The address of the gRPC server to stream route updates from"),
        )
        .arg(
            Arg::new("rt_table")
                .long("rt_table")
                .takes_value(true)
                .help("ID of routing table to insert the routes into."),
        )
        .arg(
            Arg::new("dry_run")
                .takes_value(false)
                .help("When set, does not install routes in the kernel."),
        )
        .get_matches();

    let _init_log = stderrlog::new()
        .verbosity(2) // Shows info level.
        .show_module_names(true)
        .init();
    info!("Starting route client");

    let mut rt_table: u32 = 201;

    if let Some(rt_id_arg) = matches.value_of("rt_table") {
        match rt_id_arg.parse::<u32>() {
            Ok(n) => {
                rt_table = n;
            }
            Err(e) => {
                panic!("Failed to parse rt_table: {}, {}", rt_id_arg, e);
            }
        }
    }

    let server_addr: String = matches.value_of("route_server").unwrap().to_string();
    let dry_run: bool = matches.is_present("dry_run");

    let run_v4 = {
        let server_addr = server_addr.clone();
        let dry_run = dry_run.clone();
        async move {
            run_connector_v4(&server_addr, rt_table, dry_run)
                .await
                .unwrap();
        }
    };

    let v4_joinhandle = tokio::task::spawn(run_v4);

    let v6_joinhandle = tokio::task::spawn(async move {
        run_connector_v6(&server_addr, rt_table, dry_run)
            .await
            .unwrap();
    });

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

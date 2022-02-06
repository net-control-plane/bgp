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

use bgpd::bgp_packet::nlri::NLRI;
use bgpd::route_client::fib_state::FibState;
use bgpd::server::route_server::route_server::PathSet;

use std::convert::TryInto;
use std::net::Ipv6Addr;
use std::time::Duration;
use tokio::task::JoinHandle;
use tonic::transport::Endpoint;

use bgpd::bgp_packet::constants::address_family_identifier_values;
use bgpd::server::route_server::route_server::{
    route_service_client::RouteServiceClient, StreamPathsRequest,
};
use netlink::netlink_interface::NetlinkInterface;
use tracing::{info, warn};
use treebitmap::IpLookupTable;

fn vec_to_array<T, const N: usize>(v: Vec<T>) -> Result<[T; N], String> {
    v.try_into().map_err(|_| "Wrong size of Vec".to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _init_log = stderrlog::new()
        .verbosity(2) // Shows info level.
        .show_module_names(true)
        .init();
    info!("Starting route client");

    // Create netlink socket.
    unsafe {
        let nl_iface = NetlinkInterface::new().unwrap();

        let mut fib_state = FibState::<Ipv6Addr> {
            fib: IpLookupTable::new(),
            nl_iface,
            af: libc::AF_INET6 as u8,
            table: 201,
        };

        let endpoint = Endpoint::from_static("http://193.36.105.1:9180")
            .keep_alive_timeout(Duration::from_secs(10));

        let mut client = RouteServiceClient::connect(endpoint).await?;

        let request = StreamPathsRequest { address_family: 2 };
        let mut stream = client.stream_paths(request).await?.into_inner();

        let mut msg_ctr: u32 = 0;

        while let Some(route) = stream.message().await? {
            let nlri = NLRI {
                afi: address_family_identifier_values::IPV6,
                prefixlen: route.prefix.as_ref().unwrap().prefix_len as u8,
                prefix: route.prefix.as_ref().unwrap().ip_prefix.clone(),
            };

            print!("Update {} for: {} ", msg_ctr, nlri);
            msg_ctr += 1;

            if route.paths.len() > 0 {
                // Install the best route
                let best_path = &route.paths[0];

                // Hack to convert the nexthop into a v6 addr
                let nh_bytes: [u8; 16] = vec_to_array(best_path.nexthop.clone())?;
                let nh_addr: Ipv6Addr = Ipv6Addr::from(nh_bytes);
                match fib_state.route_add(nlri, nh_addr) {
                    Err(e) => {
                        warn!("Failed to add route: {}", e);
                    }
                    _ => {}
                }
            } else {
                // No more paths, delete
                match fib_state.route_del(nlri) {
                    Err(e) => {
                        warn!("Failed to delete route: {}", e);
                    }
                    _ => {}
                }
            }

            println!("Number of paths: {}", route.paths.len());
            for path in &route.paths {
                // TODO: have a proper error here not unwrap.
                let nexthop_bytes: [u8; 16] = path.nexthop.clone().try_into().unwrap();
                let nexthop: Ipv6Addr = nexthop_bytes.into();
                print!(
                    "nexthop: {}, peer: {}, local_pref: {}, med: {}, as_path: {:?}",
                    nexthop, path.peer_name, path.local_pref, path.med, path.as_path
                );
            }
            print!("\n");
        }
    }

    Ok(())
}

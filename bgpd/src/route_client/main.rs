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

// Configuration of route_client

// NorthboundInterface represents a source of control plane routing data.
// Currently this is hardcoded to be a gRPC endpoint, but in the future
// more interfaces can be implemented.
struct NorthboundInterfaceConfig {
    name: String,
    grpc_endpoint: String,
    address_family: u16,
}

// SouthboundInterface represents a sink for installing routes into.
// Currently this is hardcoded to be the Kernel Netlink connector, but
// in the future more interfaces can be implemented.
struct SouthboundInterfaceConfig {
    name: String,
    rt_table: u16,
    address_family: u16,
}

struct RouteClientConfig {
    northbounds: Vec<NorthboundInterfaceConfig>,
    southbounds: Vec<SouthboundInterfaceConfig>,
}

type SouthboundSink = tokio::sync::mpsc::Sender<SouthboundCommands>;

enum SouthboundCommands {
    RouteUpdate(PathSet),
    Reset(),
}

/// NorthboundConnector implements the interface that gets routes from
/// the northbound route source, and sends it into the southbound sink,
/// implementing graceful connection handling, flushing routes out and
/// reinserting them on reconnection.
struct NorthboundConnector {
    config: NorthboundInterfaceConfig,
    sink: SouthboundSink,
}

impl NorthboundConnector {
    async fn run(&self) -> Result<(), String> {
        let endpoint = Endpoint::from_shared(self.config.grpc_endpoint.clone())
            .map_err(|e| e.to_string())?
            .keep_alive_timeout(Duration::from_secs(10));
        let mut client = RouteServiceClient::connect(endpoint)
            .await
            .map_err(|e| e.to_string())?;

        // 1. First subscribe to the route feed and put these into an unbounded channel.
        let (stream_tx, stream_rx) = tokio::sync::mpsc::unbounded_channel::<PathSet>();
        let request = StreamPathsRequest {
            address_family: self.config.address_family as i32,
        };
        let recv_handle: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            let mut rpc_stream = client
                .stream_paths(request)
                .await
                .map_err(|e| e.to_string())?
                .into_inner();
            while let Some(route) = rpc_stream.message().await.map_err(|e| e.to_string())? {
                stream_tx.send(route).map_err(|e| e.to_string())?;
            }
            Err("Stream closed".to_string())
        });

        // 2. Dump the entire RIB and put these into another structure.

        // 3. Drop all the entries in the deque with an epoch < dump epoch.

        // 4. Stream all routes into the sink from here on out.

        Err("Connection dropped to northbound".to_string())
    }
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

        while let Some(route) = stream.message().await? {
            let nlri = NLRI {
                afi: address_family_identifier_values::IPV6,
                prefixlen: route.prefix.as_ref().unwrap().prefix_len as u8,
                prefix: route.prefix.as_ref().unwrap().ip_prefix.clone(),
            };
            print!("Update for: {} ", nlri);

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

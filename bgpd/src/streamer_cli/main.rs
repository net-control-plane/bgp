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

use bgpd::bgp_packet::constants::AddressFamilyIdentifier;
use bgpd::bgp_packet::nlri::NLRI;
use bgpd::server::route_server::route_server::route_service_client::RouteServiceClient;
use bgpd::server::route_server::route_server::DumpPathsRequest;
use bgpd::server::route_server::route_server::PathSet;
use bgpd::server::route_server::route_server::StreamPathsRequest;
use clap::Parser;
use std::process::exit;
use std::time::Duration;
use tokio::task::JoinHandle;
use tonic::transport::Endpoint;
use tracing::{info, warn};

extern crate clap;

#[derive(clap::Parser)]
#[clap(
    author = "Rayhaan Jaufeerally <rayhaan@rayhaan.ch>",
    version = "0.1",
    about = "A program to install routes from BGP into the Linux control plane"
)]
struct Cli {
    server_address: String,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let subscriber = tracing_subscriber::fmt();

    match subscriber.try_init() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("Failed to initialize logger: {:?}", e);
            exit(1);
        }
    }

    let cli = Cli::parse();

    info!("Starting client");
    let grpc_endpoint = cli.server_address;
    let endpoint = Endpoint::from_shared(grpc_endpoint)
        .map_err(|e| e.to_string())?
        .keep_alive_timeout(Duration::from_secs(10));
    let mut client = RouteServiceClient::connect(endpoint)
        .await
        .map_err(|e| e.to_string())?;

    info!("Connected");

    // 1. First subscribe to the route feed and put these into an unbounded channel.
    let (stream_tx, mut stream_rx) = tokio::sync::mpsc::unbounded_channel::<PathSet>();
    let request = StreamPathsRequest {
        address_family: 2_i32,
    };

    let mut client_copy = client.clone();
    let _recv_handle: JoinHandle<Result<(), String>> = tokio::spawn(async move {
        let mut rpc_stream = client_copy
            .stream_paths(request)
            .await
            .map_err(|e| e.to_string())?
            .into_inner();
        while let Some(route) = rpc_stream.message().await.map_err(|e| e.to_string())? {
            stream_tx.send(route).map_err(|e| e.to_string())?;
        }
        Err("Stream closed".to_string())
    });

    // 2. Dump the whole RIB
    let dump_request = DumpPathsRequest {
        address_family: 2_i32,
    };
    let dump_response = client.dump_paths(dump_request).await.unwrap().into_inner();
    let dump_epoch = dump_response.epoch;

    info!("Dump epoch was: {}", dump_epoch);

    let overrun_slot: Option<PathSet>;
    loop {
        let item = stream_rx.recv().await;
        match &item {
            Some(pathset) => {
                if pathset.epoch >= dump_epoch {
                    overrun_slot = Some(pathset.clone());
                    break;
                } else {
                    info!("Skipping already-dumped epoch: {}", pathset.epoch);
                }
            }
            None => {
                return Err("Stream unexpectedly closed".to_owned());
            }
        }
    }

    // Replay all the pathsets from dump_response
    for pathset in dump_response.path_sets {
        info!("Got pathset: {:?}", pathset);
        // Parse an NLRI from the pathset
        if let Some(prefix) = &pathset.prefix {
            let nlri = NLRI::from_bytes(
                AddressFamilyIdentifier::Ipv6,
                prefix.ip_prefix.clone(),
                prefix.prefix_len as u8,
            )
            .unwrap();
            info!("Parsed NLRI: {}", nlri.to_string());
        }
    }

    // Replay the overrun slot
    if let Some(pathset) = overrun_slot {
        if let Some(prefix) = &pathset.prefix {
            let nlri = NLRI::from_bytes(
                AddressFamilyIdentifier::Ipv6,
                prefix.ip_prefix.clone(),
                prefix.prefix_len as u8,
            )
            .unwrap();
            info!("Parsed NLRI: {}", nlri.to_string());
        }
    }

    loop {
        let item = stream_rx.recv().await;

        match &item {
            Some(pathset) => {
                info!("Got pathset: {:?}", pathset);
                // Parse an NLRI from the pathset
                if let Some(prefix) = &pathset.prefix {
                    let nlri = NLRI::from_bytes(
                        AddressFamilyIdentifier::Ipv6,
                        prefix.ip_prefix.clone(),
                        prefix.prefix_len as u8,
                    )
                    .unwrap();
                    info!("Parsed NLRI: {}", nlri.to_string());
                }
            }
            None => {
                warn!("stream_rx closed");
                break;
            }
        }
    }

    Err("Program exited unexpectedly.".to_owned())
}

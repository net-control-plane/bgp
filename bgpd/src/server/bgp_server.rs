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

use crate::bgp_packet::constants::AddressFamilyIdentifier;
use crate::server::config::PeerConfig;
use crate::server::config::ServerConfig;
use crate::server::peer::PeerCommands;
use crate::server::peer::PeerStateMachine;
use crate::server::rib_manager::RibManager;
use crate::server::rib_manager::RibSnapshot;
use crate::server::rib_manager::RouteManagerCommands;
use crate::server::route_server;
use crate::server::route_server::route_server::route_service_server::RouteServiceServer;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tracing::{info, warn};
use warp::Filter;
use warp::Reply;

// socket_listener starts listening on the given address, and passes clients that have
// made an inbound connection to the provided stream. It also implements logic for
// recreating the listener in the event that it fails.
// Notifier is sent the restult of the first attempt to start the listener.
async fn socket_listener(
    c: UnboundedSender<(TcpStream, SocketAddr)>,
    listen_addr: String,
    notifier: oneshot::Sender<Result<(), String>>,
    mut shutdown: broadcast::Receiver<()>,
) {
    info!("Starting to listen on addr: {}", listen_addr);
    let listener_result = TcpListener::bind(&listen_addr).await;
    if let Err(e) = listener_result {
        warn!("Listener for {} failed: {}", listen_addr, e.to_string());
        match notifier.send(Err(e.to_string())) {
            Ok(_) => {}
            Err(e) => warn!("Failed to send notification of channel error: {:?}", e),
        }
        return;
    }

    let listener = listener_result.unwrap();
    match notifier.send(Ok(())) {
        Ok(_) => {}
        Err(e) => warn!("Failed to send notification of channel ready: {:?}", e),
    }
    info!("Sucessfully spawned listner for: {}", listen_addr);
    loop {
        let conn = tokio::select! {
            res = listener.accept() => res,
            _ = shutdown.recv() => {
                info!("Shutting down listener");
                return;
            }
        };
        info!("Got something: {:?}", conn);
        match conn {
            Ok((stream, addr)) => {
                info!("Accepted socket connection from {}", addr);
                match c.send((stream, addr)) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!(
                            "Dropped connection from {} due to mpsc::channel failure: {}",
                            addr, e
                        );
                    }
                }
            }
            Err(e) => {
                warn!("Failed to accept connection: {}, aborting listener", e);
                break;
            }
        }
    }
}

async fn start_http_server(
    manager4: UnboundedSender<RouteManagerCommands<Ipv4Addr>>,
    manager6: UnboundedSender<RouteManagerCommands<Ipv6Addr>>,
    peers: HashMap<String, UnboundedSender<PeerCommands>>,
    listen_addr: SocketAddr,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    async fn manager_get_routes_handler<T: serde::ser::Serialize>(
        channel: UnboundedSender<RouteManagerCommands<T>>,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let (tx, rx) = tokio::sync::oneshot::channel::<RibSnapshot<T>>();
        if let Err(e) = channel.send(RouteManagerCommands::DumpRib(tx)) {
            warn!("Failed to send DumpRib request: {}", e);
            return Err(warp::reject());
        }

        match rx.await {
            Ok(result) => Ok(warp::reply::json(&result)),
            Err(e) => {
                warn!("Failed to get RIB from manager: {}", e);
                Err(warp::reject())
            }
        }
    }

    async fn rm_large_community(
        chan: UnboundedSender<PeerCommands>,
        ld1: u32,
        ld2: u32,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        if let Err(e) = chan.send(PeerCommands::RemoveLargeCommunity((ld1, ld2), tx)) {
            warn!("Failed to send RemoveLargeCommunity request: {}", e);
            return Err(warp::reject());
        }

        match rx.await {
            Ok(result) => Ok(warp::reply::json(&result)),
            Err(e) => {
                warn!(
                    "RemoveLargeCommunity response from peer state machine: {}",
                    e
                );
                Err(warp::reject())
            }
        }
    }

    async fn add_large_community(
        chan: UnboundedSender<PeerCommands>,
        ld1: u32,
        ld2: u32,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        if let Err(e) = chan.send(PeerCommands::AddLargeCommunity((ld1, ld2), tx)) {
            warn!("Failed to send AddLargeCommunity request: {}", e);
            return Err(warp::reject());
        }

        match rx.await {
            Ok(result) => Ok(warp::reply::json(&result)),
            Err(e) => {
                warn!("AddLargeCommunity response from peer state machine: {}", e);
                Err(warp::reject())
            }
        }
    }

    // reset_peer_connection causes the PSM to close the connection, flush state, and reconnect to the peer.
    async fn reset_peer_connection(
        peer_name: String,
        peers: HashMap<String, UnboundedSender<PeerCommands>>,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        if let Some(peer_sender) = peers.get(&peer_name) {
            if let Err(e) = peer_sender.send(PeerCommands::ConnectionClosed()) {
                Ok(warp::reply::with_status(
                    format!("Something went wrong: {}", e),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                )
                .into_response())
            } else {
                Ok(warp::reply::html(
                    "Sent restart request to PeerStateMachine. Something might happen.",
                )
                .into_response())
            }
        } else {
            Ok(
                warp::reply::with_status("No such peer found!", warp::http::StatusCode::NOT_FOUND)
                    .into_response(),
            )
        }
    }

    /// peerz is a debugging endpoint for PeerStateMachines on this server.
    async fn get_peerz(
        peers: HashMap<String, UnboundedSender<PeerCommands>>,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let mut result: String = "<!DOCTYPE html><body>".to_string();
        for (peer_name, sender) in peers {
            result += &format!("<h2>{}</h2><br/>", peer_name);
            let (tx, rx) = oneshot::channel();
            match sender.send(PeerCommands::GetStatus(tx)) {
                Ok(()) => {}
                Err(e) => {
                    warn!("Failed to send request to PSM channel: {}", e);
                    return Ok(warp::reply::with_status(
                        "Something went wrong!",
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    )
                    .into_response());
                }
            }
            match rx.await {
                Ok(resp) => {
                    result += &format!("Peer state: <b>{:?}</b><br/>", resp.state);
                    result += &format!("<code>{:?}</code>", resp.config);
                }
                Err(e) => {
                    warn!("error on rx from peer channel: {}", e);
                    return Ok(warp::reply::with_status(
                        "Something went wrong!",
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    )
                    .into_response());
                }
            }
        }
        result += "</body></html>";
        Ok(warp::http::Response::builder().body(result).into_response())
    }

    /*
        async fn modify_community_fn(
            add: bool,
            peers: HashMap<String, UnboundedSender<PeerCommands>>,
            name: String,
            ld1: u32,
            ld2: u32,
        ) -> Result<impl warp::Reply, warp::Rejection> {
            if let Some(chan) = peers.get(&name) {
                if let Err(e) = func(chan.clone(), ld1, ld2).await {
                    warn!("Failed to add large community: {:?}", e);
                    return Err(warp::reject());
                }
            } else {
                return Err(warp::reject());
            }
            Ok(warp::reply::with_status("Ok", warp::http::StatusCode::OK))
        }

        let add_community_filter = warp::post()
            .map(move || true)
            .and(warp::path::param())
            .and(warp::path!(u32 / u32))
            .and_then(modify_community_fn);

    */

    // Start the web server that has access to the rib managers so that it can expose the state.
    let v4_mgr_filter = warp::any().map(move || manager4.clone());

    let warp_v4_routes = warp::get()
        .and(warp::path("ipv4"))
        .and(warp::path("routes"))
        .and(warp::path::end())
        .and(v4_mgr_filter)
        .and_then(manager_get_routes_handler);

    let v6_mgr_filter = warp::any().map(move || manager6.clone());

    let warp_v6_routes = warp::get()
        .and(warp::path("ipv6"))
        .and(warp::path("routes"))
        .and(warp::path::end())
        .and(v6_mgr_filter)
        .and_then(manager_get_routes_handler);

    let peers_map_filter = warp::any().map(move || peers.clone());
    let peerz_route = warp::get()
        .and(warp::path("peerz"))
        .and(warp::path::end())
        .and(peers_map_filter.clone())
        .and_then(get_peerz);

    let peers_restart_route = warp::post()
        .and(warp::path("peerz"))
        .and(warp::path::param())
        .and(warp::path("restart"))
        .and(warp::path::end())
        .and(peers_map_filter)
        .and_then(reset_peer_connection);

    let routes = warp_v4_routes
        .or(warp_v6_routes)
        .or(peerz_route)
        .or(peers_restart_route);
    let (_, server) = warp::serve(routes)
        .try_bind_with_graceful_shutdown(listen_addr, async move {
            shutdown.recv().await.ok();
        })
        .map_err(|e| e.to_string())?;
    Ok(tokio::task::spawn(server))
}

/// Server encapsulates the behavior of the BGP speaker.
pub struct Server {
    config: ServerConfig,

    // shutdown is a channel that a
    shutdown: broadcast::Sender<()>,

    // worker_handles contains the JoinHandle of tasks spawned by the server so that
    // we can wait on them for shutdown.
    worker_handles: Vec<tokio::task::JoinHandle<()>>,

    mgr_v6: Option<UnboundedSender<RouteManagerCommands<Ipv6Addr>>>,
    mgr_v4: Option<UnboundedSender<RouteManagerCommands<Ipv4Addr>>>,
}

impl Server {
    pub fn new(config: ServerConfig) -> Server {
        let (shutdown, _) = broadcast::channel(1);
        Server {
            config,
            shutdown,
            worker_handles: vec![],
            mgr_v4: None,
            mgr_v6: None,
        }
    }

    // start kicks off the BGP server
    // wait_startup controls whether this function waits for the listeners to come up healthy
    // before returning. This is useful in tests and other situations where we want to wait
    // and then probe the endpoints.
    pub async fn start(&mut self, wait_startup: bool) -> Result<(), String> {
        // TODO: the following code spawns a bunch of asynchronous tasks, and it would be
        // good to have a handle on the status of these tasks so that we can restart them
        // or alert if they crash.

        // Channel for passing newly established TCP streams to the dispatcher.
        let (tcp_in_tx, mut tcp_in_rx): (UnboundedSender<(TcpStream, SocketAddr)>, _) =
            tokio::sync::mpsc::unbounded_channel();

        // For every address we are meant to listen on, we spawn a task that will listen on
        // that address. This is so that if the listening socket breaks somehow, we can
        // periodically retry to listen again.
        for listen_addr in self.config.clone().listen_addrs {
            info!("Starting listener for {}", listen_addr.to_string());
            let sender = tcp_in_tx.clone();
            let (ready_tx, ready_rx) = oneshot::channel();
            let shutdown_channel = self.shutdown.subscribe();
            let listen_handle = tokio::spawn(async move {
                socket_listener(sender, listen_addr.to_string(), ready_tx, shutdown_channel).await;
            });
            self.worker_handles.push(listen_handle);
            if wait_startup {
                let statup_result = ready_rx.await;
                match statup_result {
                    Ok(_) => {}
                    Err(err) => return Err(format!("Failed to startup listener: {}", err)),
                }
            }
        }

        // Start the route manager for IPv6 and IPv4.
        let (rp6_tx, rp6_rx) = unbounded_channel::<RouteManagerCommands<Ipv6Addr>>();
        self.mgr_v6 = Some(rp6_tx.clone());
        let mut rib_manager6: RibManager<Ipv6Addr> =
            RibManager::<Ipv6Addr>::new(rp6_rx, self.shutdown.subscribe()).unwrap();
        tokio::spawn(async move {
            match rib_manager6.run().await {
                Ok(_) => {}
                Err(e) => {
                    warn!("RIBManager exited: {}", e);
                }
            }
        });

        let (rp4_tx, rp4_rx) = unbounded_channel::<RouteManagerCommands<Ipv4Addr>>();
        self.mgr_v4 = Some(rp4_tx.clone());
        let mut rib_manager4: RibManager<Ipv4Addr> =
            RibManager::<Ipv4Addr>::new(rp4_rx, self.shutdown.subscribe()).unwrap();
        tokio::spawn(async move {
            match rib_manager4.run().await {
                Ok(_) => {}
                Err(e) => {
                    warn!("RIBManager exited: {}", e);
                }
            }
        });

        // Start a PeerStateMachine for every peer that is configured and store its channel so that
        // we can communicate with it.

        let mut peer_statemachines: HashMap<String, (PeerConfig, UnboundedSender<PeerCommands>)> =
            HashMap::new();

        for peer_config in &self.config.peers {
            let (psm_tx, psm_rx) = unbounded_channel::<PeerCommands>();
            match peer_config.afi {
                AddressFamilyIdentifier::Ipv6 => {
                    let mut psm = PeerStateMachine::<Ipv6Addr>::new(
                        self.config.clone(),
                        peer_config.clone(),
                        psm_rx,
                        psm_tx.clone(),
                        rp6_tx.clone(),
                        self.shutdown.subscribe(),
                    );
                    self.worker_handles.push(tokio::spawn(async move {
                        psm.run().await;
                        warn!("Should not reach here");
                    }));
                }
                AddressFamilyIdentifier::Ipv4 => {
                    let mut psm = PeerStateMachine::<Ipv4Addr>::new(
                        self.config.clone(),
                        peer_config.clone(),
                        psm_rx,
                        psm_tx.clone(),
                        rp4_tx.clone(),
                        self.shutdown.subscribe(),
                    );
                    self.worker_handles.push(tokio::spawn(async move {
                        psm.run().await;
                        warn!("Should not reach here");
                    }));
                }
                _ => panic!("Unsupported address family: {}", peer_config.afi),
            }

            peer_statemachines.insert(peer_config.name.clone(), (peer_config.clone(), psm_tx));
        }

        let mut peer_chan_map: HashMap<String, UnboundedSender<PeerCommands>> = HashMap::new();
        for (k, v) in &peer_statemachines {
            peer_chan_map.insert(k.to_string(), v.1.clone());
        }

        // Start the HTTP server for debugging access.
        if let Some(http_addr) = &self.config.http_addr {
            let addr = http_addr.parse().unwrap();
            start_http_server(
                rp4_tx.clone(),
                rp6_tx.clone(),
                peer_chan_map.clone(),
                addr,
                self.shutdown.subscribe(),
            )
            .await
            .unwrap();
        }

        // Start the gRPC server for streaming the RIB.
        if let Some(grpc_addr) = &self.config.grpc_addr {
            let addr = grpc_addr.parse().unwrap();
            info!("Running gRPC RouteService on {}", addr);
            let rs = route_server::RouteServer {
                ip4_manager: rp4_tx.clone(),
                ip6_manager: rp6_tx.clone(),
                peer_state_machines: peer_chan_map,
            };

            let svc = RouteServiceServer::new(rs);
            tokio::spawn(async move {
                if let Err(e) = tonic::transport::Server::builder()
                    .add_service(svc)
                    .serve(addr)
                    .await
                {
                    warn!("Failed to run gRPC server: {}", e);
                }
            });
        }

        // Event loop for processing inbound connections.
        let mut shutdown_recv = self.shutdown.subscribe();
        self.worker_handles.push(tokio::spawn(async move {
            loop {
                let next = tokio::select! {
                    cmd = tcp_in_rx.recv() => cmd,
                    _ = shutdown_recv.recv() => {
                        warn!("Peer connection dispatcher shutting down due to shutdown signal.");
                        return;
                    }
                };
                match next {
                    Some((socket, addr)) => {
                        let mut psm_opt: Option<UnboundedSender<PeerCommands>> = None;
                        for (name, handle) in &peer_statemachines {
                            if handle.0.ip == addr.ip() {
                                info!("Got connection for peer: {}", name);
                                psm_opt = Some(handle.1.clone());
                            }
                        }
                        if let Some(psm) = psm_opt {
                            psm.send(PeerCommands::NewConnection(socket)).unwrap();
                        } else {
                            info!("Dropping unrecognized connection from {}", addr);
                        }
                    }
                    None => {
                        warn!("Failed to read incoming connections, exiting");
                        break;
                    }
                }
            }
        }));

        Ok(())
    }

    pub async fn shutdown(&mut self) {
        match self.shutdown.send(()) {
            Ok(_) => {}
            Err(e) => {
                warn!("Failed to send shutdown signal: {}", e);
                return;
            }
        }
        for handle in &mut self.worker_handles {
            match handle.await {
                Ok(_) => {}
                Err(e) => {
                    warn!("Failed to shutdown task: {}", e);
                }
            }
        }
    }
}

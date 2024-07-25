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

use crate::config::PrefixAnnouncement;
use crate::config::{PeerConfig, ServerConfig};
use crate::data_structures::RouteWithdraw;
use crate::data_structures::{RouteInfo, RouteUpdate};
use crate::filter_eval::FilterEvaluator;
use crate::rib_manager::{PathData, PathSource, RouteManagerCommands};
use crate::route_server::route_server::PeerStatus;
use bgp_packet::capabilities::{
    BGPCapability, BGPCapabilityTypeValues, BGPCapabilityValue, BGPOpenOptionTypeValues,
    FourByteASNCapability, MultiprotocolCapability, OpenOption, OpenOptionCapabilities,
    OpenOptions,
};
use bgp_packet::constants::{AddressFamilyIdentifier, SubsequentAddressFamilyIdentifier, AS_TRANS};
use bgp_packet::messages::BGPMessage;
use bgp_packet::messages::BGPMessageTypeValues;
use bgp_packet::messages::BGPMessageTypeValues::OPEN_MESSAGE;
use bgp_packet::messages::BGPMessageTypeValues::UPDATE_MESSAGE;
use bgp_packet::messages::BGPSubmessage;
use bgp_packet::messages::Codec;
use bgp_packet::messages::KeepaliveMessage;
use bgp_packet::messages::NotificationMessage;
use bgp_packet::messages::OpenMessage;
use bgp_packet::messages::UpdateMessage;
use bgp_packet::nlri::NLRI;
use bgp_packet::path_attributes::ASPathAttribute;
use bgp_packet::path_attributes::NextHopPathAttribute;
use bgp_packet::path_attributes::OriginPathAttribute;
use bgp_packet::path_attributes::PathAttribute;
use bgp_packet::path_attributes::{
    LargeCommunitiesPathAttribute, LargeCommunitiesPayload, MPReachNLRIPathAttribute,
};
use bgp_packet::traits::ParserContext;
use bytes::BytesMut;
use chrono::{DateTime, Utc};
use eyre::{bail, eyre};
use ip_network_table_deps_treebitmap::address::Address;
use ip_network_table_deps_treebitmap::IpLookupTable;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::codec::{Decoder, Encoder};
use tokio_util::sync::CancellationToken;
use tracing::{info, trace, warn};

type PeerInterface = mpsc::UnboundedSender<PeerCommands>;

// Note on the threading model: Messages must be processed in order
// from the BGP peer, so we constrain PeerStateMachine to be called
// with updaates on a single thread only. Updating the state should
// not be expensive, and other tasks such as picking the best route
// will be done in a different threading model.

/// BGPState represents which state of the BGP state machine the peer
/// is currently in.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum BGPState {
    /// Idle represents the configuration existing but not trying to
    /// establish connections to or accept connections from the peer.
    Idle,
    /// Active represents a state where we are trying to establish a
    /// connection to the peer.
    Active,
    /// Connect represents a state where we have intiiated a TCP
    /// connection to the peer.
    Connect,
    /// OpenSent represents a state where we have sent a BGP OPEN
    /// message to the peer and are waiting for the corresponding
    /// OPEN message back.
    OpenSent,
    /// OpenConfirm represents a state where we have sent a
    /// KEEPALIVE message to the peer after the exachange of OPEN
    /// messages, and are waiting for the corresponding KEEPALIVE.
    OpenConfirm,
    /// Established represents the steady state of an ongoing
    /// BGP session where routes are being exchanged.
    Established,
}

// PeerStateMachine has two interfaces, one to the PeerConnector and
// another to the RIBManager.
#[derive(Debug)]
pub enum PeerCommands {
    // NewConnection is used to pass a fresh inbound connection
    // to this instance.
    NewConnection(TcpStream),
    // ConnectionClosed indicates that the connection to the peer
    // has been lost, and state cleanup should be triggered.
    ConnectionClosed(),

    SendNotification(NotificationMessage),

    // Send an UPDATE message to the peer.
    Announce(RouteUpdate),

    // Internal events for the PeerStateMachine itself
    MessageFromPeer(BGPSubmessage),

    TimerEvent(PeerTimerEvent),

    // GetStatus is a crude hack to get a status string out of the PSM for debugging.
    GetStatus(oneshot::Sender<PeerStatus>),
}

#[derive(Copy, Clone, Debug)]
pub enum PeerTimerEvent {
    ConnectTimerExpire(),
    HoldTimerExpire(),
    KeepaliveTimerExpire(),
}

async fn run_timer(
    cancel_token: CancellationToken,
    iface: PeerInterface,
    event: PeerTimerEvent,
    after: tokio::time::Duration,
) {
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("run_timer was cancelled");
                return;
            },
            _ = tokio::time::sleep(after) => {
                info!("Sending timer event: {:?}", event);
                match iface.send(PeerCommands::TimerEvent(event)) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Failed to send timer message to PeerStateMachine: {}, abort run_timer", e);
                        return;
                    }
                }
            }
        }
    }
}

// check_hold_timer tries to poll the last_msg_time every second
// to see if the time is past the hold time.
async fn check_hold_timer(
    cancel_token: CancellationToken,
    iface: PeerInterface,
    last_msg_time: Arc<RwLock<DateTime<Utc>>>,
    hold_time: std::time::Duration,
) {
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("check_hold_timer was cancelled");
                return;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                let last =  last_msg_time.read().unwrap();
                let elapsed_time = Utc::now() - *last;
                if elapsed_time.num_seconds() as u64 > hold_time.as_secs() {
                    match iface.send(PeerCommands::TimerEvent(PeerTimerEvent::HoldTimerExpire())) {
                        Ok(()) => {},
                        Err(e) => {
                            warn!("Failed to send HoldTimerExpire message: {}", e);
                        }
                    }
                    // Exit the hold timer task since it's expired already and is not needed anymore.
                    return;
                }
            }

        }
    }
}

// parse_incoming_msgs reads messages from a TCP socket and dispatches the parsed
// BGP messages to the PeerInterface.
async fn parse_incoming_msgs(
    cancel_token: CancellationToken,
    conn: &mut tcp::OwnedReadHalf,
    iface: PeerInterface,
    codec: &mut Arc<Mutex<Codec>>,
) -> Result<(), std::io::Error> {
    let mut buf = BytesMut::new();
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("check_hold_timer was cancelled");
                return Ok(());
            }
            len_res = conn.read_buf(&mut buf) => {
                match len_res {
                    Err(e) => {
                        warn!("Failed to read from buf: {}", e);
                        // Send a message that the connection has been closed.
                        iface
                            .send(PeerCommands::ConnectionClosed())
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                        return Err(e);
                    }
                    Ok(len) => {
                        if len == 0 {
                            while let Some(frame) = codec.lock().await.decode_eof(&mut buf)? {
                                iface
                                    .send(PeerCommands::MessageFromPeer(frame.payload))
                                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                                }
                                iface
                                    .send(PeerCommands::ConnectionClosed())
                                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                                info!("Exiting handler due to connection close");
                                return Ok(());
                        }

                        while let Some(frame) = codec.lock().await.decode(&mut buf)? {
                            iface
                                .send(PeerCommands::MessageFromPeer(frame.payload))
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                        }
                    }
                }
            }
        }
    }
}

/// generate_open_message creates an open message for the provided peer.
fn generate_open_message(server_config: &ServerConfig, peer_config: &PeerConfig) -> OpenMessage {
    let mut res = OpenMessage {
        version: 4,
        asn: AS_TRANS,
        hold_time: server_config.hold_time,
        identifier: server_config.identifier,
        options: Vec::new(),
    };

    // Four byte ASN.
    let asn_cap = FourByteASNCapability {
        asn: server_config.asn,
    };

    // Multiprotocol.
    let multiprotocol_cap = MultiprotocolCapability {
        afi: peer_config.afi,
        safi: peer_config.safi,
    };

    res.options.push(OpenOption {
        option_type: BGPOpenOptionTypeValues::CAPABILITIES,
        oval: OpenOptions::Capabilities(OpenOptionCapabilities {
            caps: vec![
                BGPCapability {
                    cap_type: BGPCapabilityTypeValues::FOUR_BYTE_ASN,
                    val: BGPCapabilityValue::FourByteASN(asn_cap),
                },
                BGPCapability {
                    cap_type: BGPCapabilityTypeValues::MULTPROTOCOL_BGP4,
                    val: BGPCapabilityValue::Multiprotocol(multiprotocol_cap),
                },
            ],
        }),
    });

    res
}

/// PeerStateMachine encapsulates the state of a particular peer.
/// Type parameter A refers to the type of address this peer is
/// tracking, can be Ipv4Addr or Ipv6Addr as those are the types
/// supported by treebitmap.
pub struct PeerStateMachine<A: Address> {
    // server_config is the server wide config that we use here for
    // reading global options.
    server_config: ServerConfig,

    /// The current configuration for this peer.
    // To apply a new configuration the peer must be shutdown and
    // restarted so that the new configuration can take effect.
    config: PeerConfig,

    /// FilterEvaluator checks whether a given NLRI should be accepted or not
    /// based on the installed filters.
    filter_evaluator: FilterEvaluator,

    // Store the peer's open message so we can reference it.
    peer_open_msg: Option<OpenMessage>,

    /// Current state of this peer.
    pub state: BGPState,

    tcp_stream: Option<tcp::OwnedWriteHalf>,

    codec: Arc<Mutex<Codec>>,

    /// ADJ-RIB for the peer.
    /// The RouteInfo object contians information as to whether the
    /// prefix was actually accepted and
    /// the whole structure represents ADJ-RIB-IN.
    prefixes_in: IpLookupTable<A, RouteInfo<A>>,

    // prefixes_out contains the routes we want to export to the peer.
    // TODO: Use this.
    //prefixes_out: IpLookupTable<A, RouteUpdate>,

    // Interface to this state machine
    pub iface_rx: mpsc::UnboundedReceiver<PeerCommands>,
    pub iface_tx: mpsc::UnboundedSender<PeerCommands>,

    // Interfaces to the rest of the daemon.
    /// rib_in is a channel to the route processor, all accepted
    /// updates from the peer go to rib_in.
    route_manager: mpsc::UnboundedSender<RouteManagerCommands<A>>,

    // The time at which the session was established.
    established_time: Option<DateTime<Utc>>,

    // Keep track of the time of the last message to efficiently implement
    // the hold timer.
    last_msg_time: Arc<RwLock<DateTime<Utc>>>,

    // Timers and cancellation token to spawned tasks
    connect_timer: Option<(JoinHandle<()>, CancellationToken)>,
    hold_timer: Option<(JoinHandle<()>, CancellationToken)>,
    keepalive_timer: Option<(JoinHandle<()>, CancellationToken)>,
    read_cancel_token: Option<CancellationToken>,

    shutdown: CancellationToken,
}

impl<A: Address> PeerStateMachine<A>
where
    NLRI: TryInto<A>,
    <NLRI as TryInto<A>>::Error: ToString,
    A: std::fmt::Debug,
{
    pub fn new(
        server_config: ServerConfig,
        config: PeerConfig,
        iface_rx: mpsc::UnboundedReceiver<PeerCommands>,
        iface_tx: mpsc::UnboundedSender<PeerCommands>,
        route_manager: mpsc::UnboundedSender<RouteManagerCommands<A>>,
        shutdown: CancellationToken,
    ) -> PeerStateMachine<A> {
        let afi = config.afi;
        PeerStateMachine {
            server_config,
            config: config.clone(),
            filter_evaluator: FilterEvaluator::new(config.filter_in, config.filter_out),
            peer_open_msg: None,
            state: BGPState::Active,
            tcp_stream: None,
            codec: Arc::new(Mutex::new(Codec {
                ctx: ParserContext {
                    four_octet_asn: None,
                    nlri_mode: Some(afi),
                },
            })),
            prefixes_in: IpLookupTable::new(),
            iface_rx,
            iface_tx,
            route_manager,
            established_time: None,
            last_msg_time: Arc::new(RwLock::new(DateTime::from_timestamp(0, 0).unwrap())),
            connect_timer: None,
            hold_timer: None,
            keepalive_timer: None,
            read_cancel_token: None,
            shutdown,
        }
    }

    // run implements the main loop of the peer state machine and drives the
    // events relating to this particular peer.
    pub async fn run(&mut self) {
        // TODO: Wire up other spawned tasks into the shutdown signal.
        // Initialize connect timer.
        {
            let token = CancellationToken::new();
            let token_copy = token.clone();
            let chan = self.iface_tx.clone();
            let connect_timer = tokio::spawn(async move {
                run_timer(
                    token_copy,
                    chan,
                    PeerTimerEvent::ConnectTimerExpire(),
                    std::time::Duration::from_secs(5),
                )
                .await;
            });

            self.connect_timer = Some((connect_timer, token));
        }

        loop {
            let next = tokio::select! {
                cmd = self.iface_rx.recv() => cmd,
                _ = self.shutdown.cancelled() => {
                    warn!("PSM shutting down due to shutdown signal.");
                    return;
                },
            };
            match next {
                Some(msg) => match self.handle_chan_msg(msg).await {
                    Ok(_) => {}
                    Err(e) => {
                        warn!(
                            "Failed to handle message on peer state machine channel: {}",
                            e
                        );
                    }
                },
                None => {
                    warn!("PeerStateMachine channel broken!");
                    return;
                }
            }
        }
    }

    async fn handle_chan_msg(&mut self, c: PeerCommands) -> eyre::Result<()> {
        match c {
            PeerCommands::NewConnection(mut conn) => {
                let peer_addr = conn.peer_addr()?;
                info!("Handling connection from peer: {}", peer_addr);
                // Check that the state machine is in the right state for accepting
                // a connection.
                if self.state != BGPState::Active && self.state != BGPState::Connect {
                    info!(
                        "Dropping connection from peer because PSM is in state: {:?}",
                        self.state
                    );
                    // Just let conn be dropped here, that closes it.
                    return Ok(());
                };

                // Disable connect timer
                match &self.connect_timer {
                    Some((_join_handle, cancel_token)) => {
                        cancel_token.cancel();
                        self.connect_timer = None;
                    }
                    None => {}
                }

                // Generate the OPEN message and send it to the peer.
                let open_msg = generate_open_message(&self.server_config, &self.config);
                let bgp_message = BGPMessage {
                    msg_type: OPEN_MESSAGE,
                    payload: BGPSubmessage::OpenMessage(open_msg),
                };
                let mut buf = BytesMut::new();
                self.codec.lock().await.encode(bgp_message, &mut buf)?;
                conn.write(&buf).await?;

                // Update state
                self.state = BGPState::OpenSent;

                // Split the TCP connection into onwed read and write halves.
                let (mut read_half, write_half) = conn.into_split();
                self.tcp_stream = Some(write_half);

                // Spawn a task to listen
                let chan = self.iface_tx.clone();
                let mut codec = self.codec.clone();
                let peer_name = self.config.name.clone();

                // Spawn a worker task to receive messages from the peer.
                // If the connection gets closed, then a ConnectionClosed message is sent
                // on chan so handle_chan_msg can clean up the state.
                let read_cancel_token = CancellationToken::new();
                self.read_cancel_token = Some(read_cancel_token.clone());
                tokio::spawn(async move {
                    match parse_incoming_msgs(read_cancel_token, &mut read_half, chan, &mut codec)
                        .await
                    {
                        Ok(_) => info!("reader task shutdown for peer: {}", peer_name),
                        Err(e) => warn!(
                            "reader task for peer {} exited with error: {}",
                            peer_name, e
                        ),
                    }
                });
            }

            // When the connection is lost, we need to reset the state of the PSM,
            // and clear the connection related variables out. Note that we do not
            // remove any routes because that should only be done when the hold timer
            // expires.
            PeerCommands::ConnectionClosed() => {
                self.connection_closed().await?;
            }

            PeerCommands::SendNotification(notification) => {
                self.send_notification(notification).await?
            }

            PeerCommands::Announce(_) => {
                todo!();
            }

            PeerCommands::MessageFromPeer(msg) => match self.handle_msg(msg).await {
                Ok(_) => {
                    let mut last_time = self
                        .last_msg_time
                        .write()
                        .map_err(|e| eyre!(e.to_string()))?;
                    *last_time = Utc::now();
                }
                Err(e) => {
                    bail!(e);
                }
            },
            PeerCommands::TimerEvent(timer_event) => match timer_event {
                // When the connect timer expires we want to try and initiate
                // a new connection to the peer.
                PeerTimerEvent::ConnectTimerExpire() => {
                    info!("Connect timer expired");
                    match self.try_connect(Duration::from_secs(3)).await {
                        Ok(conn) => {
                            info!("Successfully connected to {}", self.config.ip);
                            self.iface_tx
                                .send(PeerCommands::NewConnection(conn))
                                .map_err(|_| {
                                    std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        "Failed to send message on channel",
                                    )
                                })?;
                            // Disable connect timer.
                            match &self.connect_timer {
                                Some((_join_handle, cancel_token)) => {
                                    cancel_token.cancel();
                                    self.connect_timer = None;
                                }
                                None => {}
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Connection attempt to peer {} failed: {}",
                                self.config.ip, e
                            )
                        }
                    }
                }
                PeerTimerEvent::HoldTimerExpire() => {
                    trace!("Hold timer expired");
                    self.hold_timer_expired().await?;
                }
                PeerTimerEvent::KeepaliveTimerExpire() => {
                    trace!("Keepalive timer expired");
                    self.send_keepalive().await?;
                }
            },
            PeerCommands::GetStatus(sender) => {
                let state = PeerStatus {
                    peer_name: self.config.name.clone(),
                    peer_id: match &self.peer_open_msg {
                        Some(peer_open_msg) => peer_open_msg.identifier.octets().to_vec(),
                        None => vec![],
                    },
                    state: format!("{:?}", self.state),
                    session_established_time: self.established_time.map(|t| t.timestamp() as u64),
                    last_messaage_time: Some(self.last_msg_time.read().unwrap().timestamp() as u64),
                    route_updates_in: Some(0),  /* todo */
                    route_updates_out: Some(0), /* todo */
                };
                match sender.send(state) {
                    Ok(()) => {}
                    Err(e) => {
                        warn!(
                            "PeerCommands::GetStatus: Failed to send state back to requester: {:?}",
                            e
                        )
                    }
                }
            }
        }
        Ok(())
    }

    async fn send_notification(
        &mut self,
        notification: NotificationMessage,
    ) -> Result<(), std::io::Error> {
        let mut buf = BytesMut::new();
        let bgp_msg = BGPMessage {
            msg_type: BGPMessageTypeValues::NOTIFICATION_MESSAGE,
            payload: BGPSubmessage::NotificationMessage(notification),
        };
        self.codec.lock().await.encode(bgp_msg, &mut buf)?;
        match self.tcp_stream.as_mut() {
            Some(stream) => {
                stream.write(&buf).await?;
            }
            None => warn!("Dropped notification message to peer"),
        }
        Ok(())
    }

    // connection_closed handles the case where the peer connection has been terminated.
    // It deallocates the resources in this peer, unsets the TCP connection, removes the
    // routes from the inner structure as well as the routes that were propagated into the
    // RIB.
    async fn connection_closed(&mut self) -> eyre::Result<()> {
        info!("Connection closed on peer {}", self.config.name);

        // Cancel keepalive timer.
        match &self.keepalive_timer {
            Some((_join_handle, cancel_token)) => {
                cancel_token.cancel();
            }
            None => {}
        }

        // Cancel the reading task.
        if let Some(cancel_token) = &self.read_cancel_token {
            cancel_token.cancel();
        }

        // Close the TCP stream.
        if let Some(stream) = self.tcp_stream.as_mut() {
            match stream.shutdown().await {
                Ok(_) => info!("Closed TCP stream with peer: {}", self.config.name),
                Err(e) => warn!(
                    "Failed to close TCP stream with peer {}: {}",
                    self.config.name,
                    e.to_string()
                ),
            }
        }

        let peer_id = match &self.peer_open_msg {
            Some(peer_open_msg) => peer_open_msg.identifier,
            None => bail!("Missing peer open msg"),
        };

        // Iterate over every route that we've announced to the route manager
        // and withdraw it.
        let mut route_withdraw = RouteWithdraw {
            peer_id,
            prefixes: vec![],
        };

        for prefix in self.prefixes_in.iter_mut() {
            route_withdraw.prefixes.push(prefix.2.nlri.clone());
        }

        self.route_manager
            .send(RouteManagerCommands::Update(RouteUpdate::Withdraw(
                route_withdraw,
            )))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))?;

        // Clear prefixes_in.
        self.prefixes_in = IpLookupTable::new();

        // Set the state machine back to the expected.
        self.state = BGPState::Active;
        self.established_time = None;

        // Restart the connect timer to try and connect periodically.
        {
            let token = CancellationToken::new();
            let token_copy = token.clone();
            let chan = self.iface_tx.clone();
            let connect_timer = tokio::spawn(async move {
                run_timer(
                    token_copy,
                    chan,
                    PeerTimerEvent::ConnectTimerExpire(),
                    std::time::Duration::from_secs(10),
                )
                .await;
            });

            self.connect_timer = Some((connect_timer, token));
        }

        Ok(())
    }

    /// process_withdrawals creates a RouteUpdate from withdrawal announcments and sends
    /// them to the rib_in channel to be consumed by the route processor.
    fn process_withdrawals(&mut self, withdrawals: Vec<NLRI>) -> eyre::Result<()> {
        let peer_id = match &self.peer_open_msg {
            Some(peer_open_msg) => peer_open_msg.identifier,
            None => bail!("Missing peer open msg"),
        };

        let mut route_withdraw = RouteWithdraw {
            peer_id,
            prefixes: vec![],
        };
        for nlri in withdrawals {
            let addr: A = nlri.clone().try_into().map_err(|e| eyre!(e.to_string()))?;

            // remove from prefixes if present.
            self.prefixes_in.remove(addr, nlri.prefixlen.into());

            route_withdraw.prefixes.push(nlri);
        }

        if route_withdraw.prefixes.len() > 0 {
            self.route_manager
                .send(RouteManagerCommands::Update(RouteUpdate::Withdraw(
                    route_withdraw,
                )))
                .map_err(|e| eyre!(e.to_string()))?;
        }

        Ok(())
    }

    /// process_announcements creates a RouteUpdate from the announced NLRIs and path attributes
    /// and sends them to the rib_in channel to be consumed by the route processor.
    fn process_announcements(
        &mut self,
        nexthop: Vec<u8>,
        announcements: Vec<NLRI>,
        path_attributes: Vec<PathAttribute>,
    ) -> eyre::Result<()> {
        // Extract the as_path and med from the attributes.
        let mut as_path: Vec<u32> = vec![];
        let mut med: u32 = 0;
        for attr in &path_attributes {
            match attr {
                PathAttribute::ASPathAttribute(aspa) => {
                    for segment in &aspa.segments {
                        for asn in &segment.path {
                            as_path.push(*asn);
                        }
                    }
                }
                PathAttribute::MultiExitDiscPathAttribute(med_attr) => {
                    med = med_attr.0;
                }
                _ => {}
            }
        }

        let peer_id = match &self.peer_open_msg {
            Some(peer_open_msg) => peer_open_msg.identifier,
            None => bail!("missing peer open msg"),
        };

        let mut path_data = PathData {
            origin: OriginPathAttribute::EGP,
            nexthop,
            path_source: PathSource::BGPPeer(peer_id),
            local_pref: self.config.local_pref,
            med,
            as_path,
            path_attributes,
            learn_time: Utc::now(),
        };

        let mut accepted_nlris = vec![];

        for announcement in announcements {
            let addr: A = announcement
                .clone()
                .try_into()
                .map_err(|e| eyre!(e.to_string()))?;
            // Should we accept this prefix?
            let accepted = self.filter_evaluator.evaluate_in(
                &mut path_data.path_attributes,
                &path_data.as_path,
                &announcement,
            );
            let rejection_reason: Option<String> = match accepted {
                true => Some("Filtered by policy".to_owned()),
                false => None,
            };

            // Note that this logic assumes accepted routes remain accepted and the converse.
            // If this is to support live updates of filters the assumptions will need to be
            // revisited.
            match self
                .prefixes_in
                .exact_match(addr, announcement.prefixlen.into())
            {
                Some(route_info) => {
                    // Update the route_info, we need to clone it then reassign.
                    let mut new_route_info: RouteInfo<A> = route_info.clone();
                    new_route_info.path_attributes = path_data.path_attributes.clone();
                    new_route_info.updated = Utc::now();
                    self.prefixes_in
                        .insert(addr, announcement.prefixlen.into(), new_route_info);
                }
                None => {
                    // Insert new RouteInfo
                    // TODO: Maybe RouteInfo should be replaced with PathData after adding an accepted/rejected to it.
                    let route_info = RouteInfo::<A> {
                        prefix: addr,
                        prefixlen: announcement.prefixlen,
                        nlri: announcement.clone(),
                        accepted,
                        rejection_reason,
                        learned: path_data.learn_time,
                        updated: path_data.learn_time,
                        path_attributes: path_data.path_attributes.clone(),
                    };
                    self.prefixes_in
                        .insert(addr, announcement.prefixlen.into(), route_info);
                }
            }

            if accepted {
                accepted_nlris.push(announcement);
            }
        }

        if !accepted_nlris.is_empty() {
            self.route_manager
                .send(RouteManagerCommands::Update(RouteUpdate::Announce((
                    accepted_nlris,
                    Arc::new(path_data),
                ))))
                .map_err(|e| eyre!(e.to_string()))?;
        }

        Ok(())
    }

    fn decide_accept_message(&mut self, _: &[PathAttribute]) -> bool {
        // TODO: Implement filtering of Update messages.

        // TODO: Section 9.1.2 of RFC 4271:
        // * Reject the message if the next hop is not resolvable
        // * Reject the message if there is an AS loop
        true
    }

    /// try_connect attempts to connect to a remote TCP endpoint with a given timeout.
    async fn try_connect(&mut self, timeout: Duration) -> Result<TcpStream, std::io::Error> {
        let addr = self.config.ip;
        let port = self.config.port.unwrap_or(179);
        let sockaddr = SocketAddr::new(addr, port);

        let std_stream = std::net::TcpStream::connect_timeout(&sockaddr, timeout)?;
        std_stream.set_nonblocking(true)?;
        Ok(TcpStream::from_std(std_stream)?)
    }

    /// send_keepalive checks if the peer connection is still established and sends a
    /// keepalive message.
    /// Takes a lock on the peer object.
    async fn send_keepalive(&mut self) -> Result<(), std::io::Error> {
        info!("Sending keepalive");
        match self.tcp_stream.as_mut() {
            Some(conn) => {
                let keepalive = BGPMessage {
                    msg_type: BGPMessageTypeValues::KEEPALIVE_MESSAGE,
                    payload: BGPSubmessage::KeepaliveMessage(KeepaliveMessage {}),
                };
                let mut buf = BytesMut::new();
                self.codec.lock().await.encode(keepalive, &mut buf)?;
                conn.write(buf.as_ref()).await?;
                Ok(())
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Called send_keepalive with no connection set",
            )),
        }
    }

    /// handle_msg processes incoming messages and updates the state in PeerStateMachine.
    async fn handle_msg(&mut self, msg: BGPSubmessage) -> eyre::Result<()> {
        match &self.state {
            BGPState::Idle => self.handle_idle_msg().await,
            BGPState::Active => self.handle_active_msg(msg).await,
            BGPState::Connect => self.handle_connect_msg(msg).await,
            BGPState::OpenSent => self.handle_opensent_msg(msg).await,
            BGPState::OpenConfirm => self.handle_openconfirm_msg(msg).await,
            BGPState::Established => self.handle_established_msg(msg).await,
        }
    }

    async fn handle_idle_msg(&mut self) -> eyre::Result<()> {
        bail!("Peer cannot process messages when in the Idle state")
    }

    async fn handle_active_msg(&mut self, msg: BGPSubmessage) -> eyre::Result<()> {
        // In the active state a new connection should come in via the NewConnection
        // message on the PSM channel, or if we establish a connection out, then that
        // logic should handle the messages until OpenSent.
        bail!("Discarding message received in ACTIVE state: {:?}", msg)
    }

    async fn handle_connect_msg(&mut self, msg: BGPSubmessage) -> eyre::Result<()> {
        // In the connect state a new connection should come in via the NewConnection
        // message on the PSM channel, or if we establish a connection out, then that
        // logic should handle the messages until OpenSent.
        bail!("Discarding message received in CONNECT state: {:?}", msg)
    }

    // In the opensent state we still need to get the OPEN message from the peer
    async fn handle_opensent_msg(&mut self, msg: BGPSubmessage) -> eyre::Result<()> {
        info!("Handling message in OpenSent state: {:?}", msg);
        match msg {
            BGPSubmessage::OpenMessage(o) => {
                // Check that the peer has the right ASN set
                if u32::from(o.asn) != self.config.asn && o.asn != AS_TRANS {
                    warn!(
                        "peer {} did not use AS_TRANS or actual ASN: {}, closing conn",
                        self.config.name, o.asn
                    );
                    self.state = BGPState::Active;
                    self.established_time = None;
                    if let Some(stream) = self.tcp_stream.as_mut() {
                        stream.shutdown().await.map_err(|e| eyre!(e.to_string()))?;
                    }
                }

                // Unpack ASN option and assert correctness.
                let mut as4_cap: Option<FourByteASNCapability> = None;
                for option in &o.options {
                    match &option.oval {
                        OpenOptions::Capabilities(caps) => {
                            for cap in &caps.caps {
                                if let BGPCapabilityValue::FourByteASN(v) = &cap.val {
                                    as4_cap = Some(v.clone());
                                }
                            }
                        }
                    }
                }

                fn notify_error_close(
                    error_code: u8,
                    error_subcode: u8,
                    iface_tx: &mut mpsc::UnboundedSender<PeerCommands>,
                ) -> eyre::Result<()> {
                    let notification = NotificationMessage {
                        error_code,
                        error_subcode,
                        data: vec![],
                    };
                    iface_tx
                        .send(PeerCommands::SendNotification(notification))
                        .map_err(|e| eyre!(e.to_string()))?;
                    iface_tx
                        .send(PeerCommands::ConnectionClosed())
                        .map_err(|e| eyre!(e.to_string()))?;
                    Ok(())
                }

                match as4_cap {
                    Some(cap) => {
                        // We have to set the AS4 option on the BGP message parser.
                        self.codec.lock().await.ctx.four_octet_asn = Some(true);
                        if cap.asn != self.config.asn {
                            warn!(
                                "Got non-matching ASN from peer: {} want: {}",
                                cap.asn, self.config.asn
                            );
                            notify_error_close(2, 2, &mut self.iface_tx)?;
                        }
                    }
                    None => {
                        // Reject connection by sending notification then queue a close.
                        notify_error_close(2, 4, &mut self.iface_tx)?;
                    }
                }

                // Assert that the right MultiProtocol options are set
                // TODO: Handle the case where there is more than one multiprotocol cap set.
                let mut mp_cap: Option<MultiprotocolCapability> = None;
                for option in &o.options {
                    match &option.oval {
                        OpenOptions::Capabilities(caps) => {
                            for cap in &caps.caps {
                                if let BGPCapabilityValue::Multiprotocol(mp) = &cap.val {
                                    mp_cap = Some(mp.clone());
                                }
                            }
                        }
                    }
                }

                match mp_cap {
                    Some(cap) => {
                        if cap.afi != self.config.afi {
                            warn!(
                                "Mismatched multiprotocol AFI, got: {}, want: {}",
                                cap.afi, self.config.afi
                            );
                            return notify_error_close(2, 4, &mut self.iface_tx);
                        }
                        if cap.safi != self.config.safi {
                            warn!(
                                "Mismatched multiprotocol SAFI, got: {}, want: {}",
                                cap.safi, self.config.safi
                            );
                            return notify_error_close(2, 4, &mut self.iface_tx);
                        }
                    }
                    None => {
                        warn!("No multiptotocol capability found, closing conn");
                        return notify_error_close(2, 4, &mut self.iface_tx);
                    }
                }

                // Ensure that the hold time is set to an acceptable value accoring to
                // https://datatracker.ietf.org/doc/html/rfc4271#section-6.2
                match o.hold_time {
                    1 | 2 => {
                        return notify_error_close(2, 6, &mut self.iface_tx);
                    }
                    _ => {}
                }

                // Store the open message for reference / debugging.
                self.peer_open_msg = Some(o);

                // Send the Keepalive message and transition to OpenConfirm.
                self.send_keepalive()
                    .await
                    .map_err(|e| eyre!(e.to_string()))?;
                self.state = BGPState::OpenConfirm;

                Ok(())
            }
            _ => bail!("Got non-open message in state opensent"),
        }
    }

    // In the openconfirm state we are waiting for a KEEPALIVE from the peer.
    async fn handle_openconfirm_msg(&mut self, msg: BGPSubmessage) -> eyre::Result<()> {
        // In the openconfirm state we wait for a keepalive message from the peer.
        // We also compute the timer expiry time for the keepalive timer.
        // Hold time of 0 means no keepalive and hold timer.
        let hold_time = match &self.peer_open_msg {
            Some(o) => o.hold_time,
            None => {
                bail!("Logic error: reached handle_openconfirm without a open message set");
            }
        };
        match msg {
            BGPSubmessage::KeepaliveMessage(_) => {
                // Switch the state from OpenConfirm to ESTABLISHED.
                self.state = BGPState::Established;
                self.established_time = Some(Utc::now());

                if hold_time > 0 {
                    // Set keepalive timer.
                    let keepalive_duration = hold_time / 3;
                    info!(
                        "Using keepalive duration of {} for peer {}",
                        keepalive_duration, self.config.name
                    );
                    {
                        let token = CancellationToken::new();
                        let token_copy = token.clone();
                        let chan = self.iface_tx.clone();
                        let keepalive_timer = tokio::spawn(async move {
                            run_timer(
                                token_copy,
                                chan,
                                PeerTimerEvent::KeepaliveTimerExpire(),
                                std::time::Duration::from_secs(keepalive_duration.into()),
                            )
                            .await;
                        });

                        self.keepalive_timer = Some((keepalive_timer, token));
                    }

                    // Set hold timer.
                    {
                        let token = CancellationToken::new();
                        let token_copy = token.clone();
                        let chan = self.iface_tx.clone();
                        let last_msg_time = self.last_msg_time.clone();
                        let hold_timer = tokio::spawn(async move {
                            check_hold_timer(
                                token_copy,
                                chan,
                                last_msg_time,
                                std::time::Duration::from_secs(hold_time.into()),
                            )
                            .await
                        });

                        self.hold_timer = Some((hold_timer, token));
                    }
                };

                // TODO: Should not have to clone here?
                let announcements: Vec<PrefixAnnouncement> = self.config.announcements.clone();
                for announcement in announcements {
                    self.announce_static(&announcement).await?;
                }

                Ok(())
            }
            _ => bail!(
                "Got unsupported message type in handle_openconfirm_msg: {:?}",
                msg
            ),
        }
    }

    async fn hold_timer_expired(&mut self) -> eyre::Result<()> {
        let notification = NotificationMessage {
            error_code: 4,
            error_subcode: 0,
            data: vec![],
        };

        self.send_notification(notification).await?;
        self.connection_closed().await?;

        Ok(())
    }

    async fn announce_static(&mut self, announcement: &PrefixAnnouncement) -> eyre::Result<()> {
        let mut bgp_update_msg = UpdateMessage {
            withdrawn_nlri: vec![],
            announced_nlri: vec![],
            path_attributes: vec![],
        };

        // Origin, TODO: configure this based on i/eBGP
        bgp_update_msg
            .path_attributes
            .push(PathAttribute::OriginPathAttribute(OriginPathAttribute::EGP));

        bgp_update_msg
            .path_attributes
            .push(ASPathAttribute::from_asns(vec![self.server_config.asn]));

        match self.config.afi {
            AddressFamilyIdentifier::Ipv4 => {
                match announcement.nexthop {
                    IpAddr::V4(nh) => {
                        bgp_update_msg
                            .path_attributes
                            .push(PathAttribute::NextHopPathAttribute(NextHopPathAttribute(
                                nh,
                            )))
                    }
                    _ => bail!("Found non IPv4 nexthop in announcement"),
                }

                let nlri = NLRI::try_from(announcement.prefix.as_str())
                    .map_err(|e| eyre!(e.to_string()))?;
                bgp_update_msg.announced_nlri.push(nlri);
            }
            AddressFamilyIdentifier::Ipv6 => {
                let nexthop_octets = match announcement.nexthop {
                    IpAddr::V6(nh) => nh.octets().to_vec(),
                    _ => {
                        bail!("Found non IPv6 nexthop in announcement");
                    }
                };
                let nlri = NLRI::try_from(announcement.prefix.as_str())
                    .map_err(|e| eyre!(e.to_string()))?;
                let mp_reach = MPReachNLRIPathAttribute {
                    afi: AddressFamilyIdentifier::Ipv6,
                    safi: SubsequentAddressFamilyIdentifier::Unicast,
                    nexthop: nexthop_octets,
                    nlris: vec![nlri],
                };
                bgp_update_msg
                    .path_attributes
                    .push(PathAttribute::MPReachNLRIPathAttribute(mp_reach));
            }
        }

        if let Some(large_communities) = &announcement.large_communities {
            let mut large_communities_attr = LargeCommunitiesPathAttribute { values: vec![] };
            for large_community in large_communities {
                let parts: Vec<u32> = large_community
                    .split(':')
                    .flat_map(|x| x.parse::<u32>())
                    .collect();
                if parts.len() != 3 {
                    warn!("Failed to parse large community: {}", large_community);
                }
                let payload = LargeCommunitiesPayload {
                    global_admin: parts[0],
                    ld1: parts[1],
                    ld2: parts[2],
                };
                large_communities_attr.values.push(payload);
            }
            bgp_update_msg
                .path_attributes
                .push(PathAttribute::LargeCommunitiesPathAttribute(
                    large_communities_attr,
                ));
        }

        let bgp_message = BGPMessage {
            msg_type: UPDATE_MESSAGE,
            payload: BGPSubmessage::UpdateMessage(bgp_update_msg),
        };

        info!("Sending static announcement to peer: {:?}", bgp_message);

        let mut buf = BytesMut::new();
        self.codec
            .lock()
            .await
            .encode(bgp_message, &mut buf)
            .map_err(|e| eyre!("failed to encode BGP message: {}", e))?;

        if let Some(stream) = self.tcp_stream.as_mut() {
            stream
                .write(&buf)
                .await
                .map_err(|e| eyre!("Failed to write msg to peer: {}", e))?;
        }
        Ok(())
    }

    // In the established state we accept Update, Keepalive and Notification messages.
    async fn handle_established_msg(&mut self, msg: BGPSubmessage) -> eyre::Result<()> {
        match msg {
            BGPSubmessage::UpdateMessage(u) => {
                if !self.decide_accept_message(&u.path_attributes) {
                    info!(
                        "Rejected message due to path attributes: {:?}",
                        u.path_attributes
                    );
                }

                // Have a seperate path for calling Multiprotocol NLRI processing.
                for attr in &u.path_attributes {
                    match attr {
                        PathAttribute::MPReachNLRIPathAttribute(nlri) => {
                            // TODO: Determine which AFI/SAFI this update corresponds to.
                            let nexthop_res = nlri.clone().nexthop_to_v6();

                            if let Some((global, _llnh_opt)) = nexthop_res {
                                self.process_announcements(
                                    global.octets().to_vec(),
                                    nlri.nlris.clone(),
                                    u.path_attributes.clone(),
                                )?;
                            }
                        }
                        PathAttribute::MPUnreachNLRIPathAttribute(nlri) => {
                            // TODO: Determine which AFI/SAFI this update corresponds to.
                            self.process_withdrawals(nlri.nlris.clone())?;
                        }
                        _ => {}
                    }
                }

                if !u.withdrawn_nlri.is_empty() {
                    self.process_withdrawals(u.withdrawn_nlri)?;
                }
                if !u.announced_nlri.is_empty() {
                    let mut nexthop_option: Option<NextHopPathAttribute> = None;
                    for attr in &u.path_attributes {
                        if let PathAttribute::NextHopPathAttribute(nh_attr) = attr {
                            nexthop_option = Some(nh_attr.clone());
                        }
                    }
                    match nexthop_option {
                        Some(nexthop) => {
                            self.process_announcements(
                                nexthop.0.octets().to_vec(),
                                u.announced_nlri,
                                u.path_attributes,
                            )?;
                        }
                        None => {
                            warn!(
                                "Got announced NLRI from peer {} without any nexthop",
                                self.config.name
                            );
                            // TODO: Send a notification to the peer in this case.
                        }
                    }
                }

                Ok(())
            }
            BGPSubmessage::NotificationMessage(n) => {
                info!(
                    "Got notification message from peer {}: {}",
                    self.config.name, n
                );
                Ok(())
            }

            BGPSubmessage::KeepaliveMessage(_) => Ok(()),
            _ => bail!("Got unexpected message from peer: {:?}", msg),
        }
    }
}

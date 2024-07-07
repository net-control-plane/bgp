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

use crate::config::PeerConfig;
use crate::data_structures::RouteAnnounce;
use crate::data_structures::RouteUpdate;
use crate::peer::PeerCommands;

use std::cmp::Eq;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Mutex;

use bgp_packet::nlri::NLRI;
use bgp_packet::path_attributes::PathAttribute;
use ip_network_table_deps_treebitmap::address::Address;
use serde::Serialize;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::{info, trace, warn};

use super::data_structures::RouteWithdraw;

type PeerInterface = mpsc::UnboundedSender<PeerCommands>;

/// Path is a structure to contain a specific route via one nexthop.
/// Note that currently there is an assumption that there is only
/// one route per peer per prefix, but when ADD-PATH support is added
/// this will no longer hold true.
#[derive(Debug, Clone, Serialize)]
pub struct Path {
    pub nexthop: Vec<u8>,
    pub peer_name: String,
    pub local_pref: u32,
    pub med: u32,
    pub as_path: Vec<u32>,
    pub path_attributes: Vec<PathAttribute>,
}

impl PartialEq for Path {
    fn eq(&self, other: &Path) -> bool {
        // Local pref
        if self.local_pref > other.local_pref {
            return true;
        }
        // AS path length
        if self.as_path.len() < other.as_path.len() {
            return true;
        }

        // TODO: Origin

        // MED lower is better
        if self.med < other.med {
            return true;
        }

        // Use peer name as discriminator of last resort
        self.peer_name < other.peer_name
    }
}

impl Eq for Path {}

#[derive(Debug, Clone, Serialize)]
pub struct PathSet<A> {
    pub addr: A,
    pub prefixlen: u8,
    pub nlri: NLRI,
    // paths is stored in a BTreeMap which is sorted and allows us to efficiently
    // find the best path.
    pub paths: BTreeMap<String, Path>,
}

/// RibSnapshot contians a version number and the dump of all the routes.
#[derive(Debug, Serialize)]
pub struct RibSnapshot<A> {
    pub epoch: u64,
    pub routes: Vec<PathSet<A>>,
}

pub enum RouteManagerCommands<A> {
    Update(RouteUpdate),
    /// DumpRib returns the view of the RIB at the current epoch.
    DumpRib(oneshot::Sender<RibSnapshot<A>>),
    /// StreamRib will send all the routes currently in the RIB then stream updates.
    StreamRib(
        mpsc::UnboundedSender<(u64, PathSet<A>)>,
        oneshot::Sender<broadcast::Receiver<(u64, PathSet<A>)>>,
    ),
}

pub struct RibManager<A: Address> {
    mgr_rx: mpsc::UnboundedReceiver<RouteManagerCommands<A>>,
    peers: HashMap<String, (PeerConfig, PeerInterface)>,

    // We need to use a mutex for PathSet because IpLookupTable does not return a mut ptr.
    rib: ip_network_table_deps_treebitmap::IpLookupTable<A, Mutex<PathSet<A>>>,
    epoch: u64,

    // Handle for streaming updates to PathSets in the RIB.
    pathset_streaming_handle: broadcast::Sender<(u64, PathSet<A>)>,

    shutdown: broadcast::Receiver<()>,
}

impl<A: Address> RibManager<A>
where
    NLRI: TryInto<A>,
    <NLRI as TryInto<A>>::Error: ToString,
    A: std::fmt::Debug + std::fmt::Display,
{
    pub fn new(
        chan: mpsc::UnboundedReceiver<RouteManagerCommands<A>>,
        shutdown: broadcast::Receiver<()>,
    ) -> Result<Self, std::io::Error> {
        // TODO: Make this a flag that can be configured.
        let (pathset_tx, _) = broadcast::channel(10_000_000);
        Ok(RibManager::<A> {
            mgr_rx: chan,
            peers: HashMap::new(),
            rib: ip_network_table_deps_treebitmap::IpLookupTable::new(),
            epoch: 0,
            pathset_streaming_handle: pathset_tx,
            shutdown,
        })
    }

    pub async fn run(&mut self) -> Result<(), String> {
        loop {
            let next = tokio::select! {
                cmd = self.mgr_rx.recv() => cmd,
                _ = self.shutdown.recv() => {
                    warn!("RIB manager shutting down due to shutdown signal.");
                    return Ok(());
                }
            };
            match next {
                Some(mgr_cmd) => match mgr_cmd {
                    RouteManagerCommands::Update(update) => self.handle_update(update)?,
                    RouteManagerCommands::DumpRib(sender) => {
                        self.dump_rib(sender);
                    }
                    RouteManagerCommands::StreamRib(dump_sender, stream_sender) => {
                        self.stream_rib(dump_sender, stream_sender);
                    }
                },
                None => {
                    warn!("All senders of the manager channel have been dropped, manager exiting!");
                    return Err("Manager exited due to channel closure".to_string());
                }
            }
        }
    }

    // dump_rib returns an atomic snapshot of the RIB at the current epoch.
    fn dump_rib(&mut self, sender: tokio::sync::oneshot::Sender<RibSnapshot<A>>) {
        info!("Starting RIB dump");
        let mut snapshot = RibSnapshot::<A> {
            epoch: self.epoch,
            routes: vec![],
        };
        for pathset in self.rib.iter() {
            snapshot.routes.push(pathset.2.lock().unwrap().clone());
        }
        // TODO: handle an error here.
        if let Err(e) = sender.send(snapshot) {
            warn!("Failed to send snapshot of RIB: {:?}", e);
        }
        info!("Done RIB dump");
    }

    /// stream_rib sends the current routes in the RIB back via dump_chan then closes it,
    /// and subsequently returns a broadcast::Receiver for streaming updates.
    fn stream_rib(
        &mut self,
        dump_sender: mpsc::UnboundedSender<(u64, PathSet<A>)>,
        stream_sender: oneshot::Sender<broadcast::Receiver<(u64, PathSet<A>)>>,
    ) {
        // Send all the routes currently in the RIB.
        for pathset in self.rib.iter() {
            if let Err(e) = dump_sender.send((self.epoch, pathset.2.lock().unwrap().clone())) {
                warn!("Failed to send dump to client: {}", e);
            }
        }
        drop(dump_sender);
        // Create a new subscriber and return that to the caller to be notified of updates.
        let subscriber = self.pathset_streaming_handle.subscribe();
        if let Err(e) = stream_sender.send(subscriber) {
            warn!("Failed to send subscriber in stream_rib: {:?}", e);
        }
    }

    fn handle_update(&mut self, update: RouteUpdate) -> Result<(), String> {
        match update {
            RouteUpdate::Announce(announce) => self.handle_announce(announce),
            RouteUpdate::Withdraw(withdraw) => self.handle_withdraw(withdraw),
        }
    }

    fn handle_announce(&mut self, update: RouteAnnounce) -> Result<(), String> {
        let peer_name = update.peer.clone();
        let nexthop = update.nexthop;
        for nlri in update.prefixes {
            // Increment the epoch on every NLRI processed.
            self.epoch += 1;
            let addr: A = nlri.clone().try_into().map_err(|e| e.to_string())?;
            let prefixlen = nlri.prefixlen;
            if let Some(path_set_wrapped) = self.rib.exact_match(addr, prefixlen.into()) {
                let mut path_set = path_set_wrapped.lock().unwrap();
                // There is already this prefix in the RIB, check if this is a
                // reannouncement or fresh announcement.
                match path_set.paths.get_mut(&update.peer) {
                    // Peer already announced this route before.
                    Some(existing) => {
                        trace!(
                            "Updating existing path attributes for NLRI: {}/{}",
                            addr,
                            prefixlen
                        );
                        existing.nexthop = nexthop.clone();
                        existing.path_attributes = update.path_attributes.clone();
                    }
                    // First time that this peer is announcing the route.
                    None => {
                        let path = Path {
                            nexthop: nexthop.clone(),
                            peer_name: peer_name.clone(),
                            local_pref: update.local_pref,
                            med: update.med,
                            as_path: update.as_path.clone(),
                            path_attributes: update.path_attributes.clone(),
                        };
                        path_set.paths.insert(update.peer.clone(), path);
                    }
                }

                // There is no explicit sorting and marking of the best path since
                // BTreeMap is already sorted.

                // Ignore errors sending due to no active receivers on the channel.
                let _ = self
                    .pathset_streaming_handle
                    .send((self.epoch, path_set.clone()));
            } else {
                // This prefix has never been seen before, so add a new PathSet for it.
                let mut path_set = PathSet::<A> {
                    addr,
                    prefixlen: nlri.prefixlen,
                    nlri,
                    paths: BTreeMap::new(),
                };
                let path = Path {
                    nexthop: nexthop.clone(),
                    peer_name: peer_name.clone(),
                    local_pref: update.local_pref,
                    med: update.med,
                    as_path: update.as_path.clone(),
                    path_attributes: update.path_attributes.clone(),
                };
                path_set.paths.insert(peer_name.clone(), path);
                self.rib
                    .insert(addr, prefixlen.into(), Mutex::new(path_set.clone()));

                // Ignore errors sending due to no active receivers on the channel.
                let _ = self.pathset_streaming_handle.send((self.epoch, path_set));
            }
        }

        Ok(())
    }

    fn handle_withdraw(&mut self, update: RouteWithdraw) -> Result<(), String> {
        for nlri in update.prefixes {
            self.epoch += 1;
            let addr: A = nlri.clone().try_into().map_err(|e| e.to_string())?;
            let mut pathset_empty = false;
            if let Some(path_set_wrapped) = self.rib.exact_match(addr, nlri.prefixlen.into()) {
                let mut path_set = path_set_wrapped.lock().unwrap();
                let removed = path_set.paths.remove(&update.peer);
                if removed.is_none() {
                    warn!(
                        "Got a withdrawal for route {} from {}, which was not in RIB",
                        nlri, update.peer
                    );
                }
                // Ignore errors sending due to no active receivers on the channel.
                let _ = self
                    .pathset_streaming_handle
                    .send((self.epoch, path_set.clone()));
                if path_set.paths.is_empty() {
                    pathset_empty = true;
                }
            } else {
                warn!(
                    "Got a withdrawal for route {} from {}, which was not in RIB",
                    nlri, update.peer
                );
            }
            if pathset_empty {
                self.rib.remove(addr, nlri.prefixlen.into());
            }
        }

        Ok(())
    }

    pub fn lookup_path_exact(&self, addr: A, prefixlen: u32) -> Option<PathSet<A>> {
        self.rib
            .exact_match(addr, prefixlen)
            .map(|path| path.lock().unwrap().clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::rib_manager::RibManager;
    use crate::rib_manager::RouteAnnounce;
    use crate::rib_manager::RouteManagerCommands;
    use crate::rib_manager::RouteUpdate;

    use bgp_packet::constants::AddressFamilyIdentifier;
    use bgp_packet::nlri::NLRI;

    use std::net::Ipv6Addr;
    use std::str::FromStr;
    use tokio::sync::mpsc;

    #[test]
    fn test_manager_process_single() {
        let (_, rp_rx) = mpsc::unbounded_channel::<RouteManagerCommands<Ipv6Addr>>();
        // Nothing spaawned here so no need to send the shutdown signal.
        let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let mut rib_manager: RibManager<Ipv6Addr> =
            RibManager::<Ipv6Addr>::new(rp_rx, shutdown_rx).unwrap();

        let nexthop = Ipv6Addr::new(0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0x1);

        // Send an update to the manager and check that it adds it to the RIB.
        let announce = RouteAnnounce {
            peer: "Some peer".to_string(),
            prefixes: vec![NLRI {
                afi: AddressFamilyIdentifier::Ipv6,
                prefixlen: 32,
                prefix: vec![0x20, 0x01, 0xd, 0xb8],
            }],
            as_path: vec![65536],
            local_pref: 0,
            med: 0,
            nexthop: nexthop.octets().to_vec(),
            path_attributes: vec![],
        };

        // Manually drive the manager instead of calling run to not deal with async in tests.
        assert_eq!(
            rib_manager.handle_update(RouteUpdate::Announce(announce)),
            Ok(())
        );

        let addr = Ipv6Addr::from_str("2001:db8::").unwrap();
        let prefixlen: u32 = 32;

        let lookup_result = rib_manager.lookup_path_exact(addr, prefixlen).unwrap();
        assert_eq!(lookup_result.paths.len(), 1);
        let path_result = lookup_result.paths.get("Some peer").unwrap();
        assert_eq!(path_result.nexthop, nexthop.octets().to_vec());
    }
}

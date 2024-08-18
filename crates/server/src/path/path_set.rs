use std::{
    collections::{btree_set, BTreeMap, BTreeSet},
    net::Ipv4Addr,
    sync::Arc,
};

use bgp_packet::nlri::NLRI;
use eyre::{bail, Result};
use serde::Serialize;

use super::path_data::PathData;

#[derive(Debug, Clone, Serialize)]
pub enum PathSource {
    LocallyConfigured,
    /// BGPPeer represents a path that has been learned from a BGP peer,
    /// and contains the Router ID of the peer.
    BGPPeer(Ipv4Addr),
}

impl PartialEq for PathSource {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::BGPPeer(l0), Self::BGPPeer(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PathSet<A> {
    addr: A,
    prefixlen: u8,
    nlri: NLRI,
    /// Sorted map keyed by the BGP Identifier of the peer that sent the route.
    peer_paths: BTreeMap<Ipv4Addr, Arc<PathData>>,
    paths: BTreeSet<Arc<PathData>>,
}

impl<A> PathSet<A> {
    pub fn new(addr: A, prefixlen: u8, nlri: NLRI) -> Self {
        Self {
            addr,
            prefixlen,
            nlri,
            peer_paths: Default::default(),
            paths: Default::default(),
        }
    }

    pub fn addr<'a>(&'a self) -> &'a A {
        &self.addr
    }

    pub fn prefixlen(&self) -> u8 {
        self.prefixlen
    }

    pub fn nlri<'a>(&'a self) -> &'a NLRI {
        &self.nlri
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn get_by_announcer(&self, announcer: &Ipv4Addr) -> Option<Arc<PathData>> {
        self.peer_paths.get(announcer).cloned()
    }

    /// Inserts a PathData from a given announcer, returning a PathData if the best
    /// route has been updated.
    pub fn insert_pathdata(
        &mut self,
        announcer: &Ipv4Addr,
        path_data: &Arc<PathData>,
    ) -> Option<Arc<PathData>> {
        let previous_best = self.paths.first().cloned();
        if let Some(existing) = self.peer_paths.get_mut(announcer) {
            // Path exists already so we must first remove it from self.paths.
            self.paths.remove(existing);
            // Add the new path to self.paths.
            self.paths.insert(path_data.clone());
            // Update it in the peer_paths map.
            *existing = path_data.clone();
        } else {
            // Path does not yet exist so we just add it in both structures.
            self.paths.insert(path_data.clone());
            self.peer_paths.insert(*announcer, path_data.clone());
        }
        let next_best = self.paths.first().cloned();
        // If the best path has changed, return the new best.
        if previous_best != next_best {
            return next_best;
        }
        // Update has not changed the best path.
        return None;
    }

    /// Removes a path from the PathSet.
    pub fn remove_pathdata(
        &mut self,
        announcer: &Ipv4Addr,
        nlri: &NLRI,
    ) -> Result<Option<Arc<PathData>>> {
        let previous_best = self.paths.first().cloned();
        if self.peer_paths.contains_key(&announcer) {
            self.peer_paths.remove(&announcer);
            self.paths
                .retain(|e| e.path_source != PathSource::BGPPeer(*announcer));
        } else {
            bail!("cannot remove pathdata for NLRI {} from {}, as it is not present in PathSet.peer_paths",
                nlri, announcer);
        }
        let next_best = self.paths.first().cloned();
        // If the best path has changed, return the new best.
        if previous_best != next_best {
            return Ok(next_best);
        }
        // Update has not changed the best path.
        return Ok(None);
    }

    /// Iterator over the paths contained in this PathSet.
    pub fn path_iter<'a>(&'a self) -> btree_set::Iter<'a, Arc<PathData>> {
        self.paths.iter()
    }
}

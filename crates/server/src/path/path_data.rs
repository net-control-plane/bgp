use std::cmp::Ordering;

use chrono::{DateTime, Utc};
use serde::Serialize;

use bgp_packet::path_attributes::{OriginPathAttribute, PathAttribute};

use super::path_set::PathSource;

/// PathData is a structure to contain a specific route via one nexthop.
/// Note that currently there is an assumption that there is only
/// one route per peer per prefix, but when ADD-PATH support is added
/// this will no longer hold true.
#[derive(Debug, Clone, Serialize)]
pub struct PathData {
    /// The origin through which this path was learned. This is set to EGP when learned from
    /// another peer, set to IGP when statically configured or from another control plane.
    pub origin: OriginPathAttribute,
    /// The nexthop that traffic can be sent to.
    pub nexthop: Vec<u8>,
    /// Where this path was learned from.
    pub path_source: PathSource,
    /// The local pref of this path.
    pub local_pref: u32,
    /// The multi exit discriminator of this path.
    pub med: u32,
    /// The path of autonomous systems to the destination along this path.
    pub as_path: Vec<u32>,
    /// Path attributes received from the peer.
    pub path_attributes: Vec<PathAttribute>,
    /// When the path was learned.
    pub learn_time: DateTime<Utc>,
}

impl PartialOrd for PathData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PathData {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare local_pref.
        match self.local_pref.cmp(&other.local_pref) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Prefer paths that are locally configured.
        if matches!(self.path_source, PathSource::LocallyConfigured)
            && !matches!(other.path_source, PathSource::LocallyConfigured)
        {
            return Ordering::Less;
        }

        // Compare path length.
        match self.as_path.len().cmp(&other.as_path.len()) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // IGP < EGP < INCOMPLETE
        match (self.origin as u8).cmp(&(other.origin as u8)) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // MED lower is better, only checked if the announcing ASN is the same.
        if let (Some(announcing_as_self), Some(announcing_as_other)) =
            (self.as_path.last(), other.as_path.last())
        {
            if announcing_as_self == announcing_as_other && self.med < other.med {
                return Ordering::Less;
            }
        }

        // As a discriminator of last resort, prefer older routes.
        self.learn_time.cmp(&other.learn_time)
    }
}

impl PartialEq for PathData {
    fn eq(&self, other: &Self) -> bool {
        self.origin == other.origin
            && self.nexthop == other.nexthop
            && self.path_source == other.path_source
            && self.local_pref == other.local_pref
            && self.med == other.med
            && self.as_path == other.as_path
            && self.path_attributes == other.path_attributes
            && self.learn_time == other.learn_time
    }
}

impl Eq for PathData {}

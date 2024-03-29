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

use crate::bgp_packet::nlri::NLRI;
use crate::bgp_packet::path_attributes::PathAttribute;
use std::time::SystemTime;

/// RouteInfo encapsulates information received about a particular BGP route.
#[derive(Clone, Debug)]
pub struct RouteInfo<A> {
    pub prefix: A,
    pub prefixlen: u8,
    pub nlri: NLRI,

    /// accepted is true if the route was accepted.
    pub accepted: bool,

    /// rejection_reason contains the reason why a particular route was dropped.
    pub rejection_reason: Option<String>,

    /// Time at which this path was learned from the peer.
    pub learned: SystemTime,
    /// Time at which this path was last updated by the peer.
    pub updated: SystemTime,

    /// The current path attributes from the UPDATE message where this path
    /// was learned.
    pub path_attributes: Vec<PathAttribute>,
}

/// RouteUpdate is a type which encapsulates a newly learned, modified, or removed set of prefixes.
#[derive(Debug)]
pub enum RouteUpdate {
    Announce(RouteAnnounce),
    Withdraw(RouteWithdraw),
}

#[derive(Debug)]
pub struct RouteAnnounce {
    pub peer: String,
    pub prefixes: Vec<NLRI>,

    pub local_pref: u32,
    pub med: u32,
    pub as_path: Vec<u32>,
    pub nexthop: Vec<u8>,

    pub path_attributes: Vec<PathAttribute>,
}

#[derive(Debug)]
pub struct RouteWithdraw {
    pub peer: String,
    pub prefixes: Vec<NLRI>,
}

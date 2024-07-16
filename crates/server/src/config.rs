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

use bgp_packet::constants::{AddressFamilyIdentifier, SubsequentAddressFamilyIdentifier};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub identifier: Ipv4Addr,
    pub asn: u32,
    pub hold_time: u16,

    // The address to listen on for control plane gRPC connections.
    // If unset the gRPC server is not started.
    pub grpc_addr: Option<String>,

    // The address to listen on for the debugging HTTP server.
    // If unset the HTTP server is not started.
    pub http_addr: Option<String>,

    // The addresses to listen on for BGP peers.
    pub listen_addrs: Vec<String>,

    pub peers: Vec<PeerConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerConfig {
    /// A unique name for this peer.
    pub name: String,

    pub ip: IpAddr,
    /// Optional port number to communicate with this peer.
    pub port: Option<u16>,
    /// Autonomous system number of the peer.
    pub asn: u32,

    pub afi: AddressFamilyIdentifier,
    pub safi: SubsequentAddressFamilyIdentifier,

    pub local_pref: u32,

    // Announcements is a hardcoded list of BGP updates to send
    // to the peer.
    pub announcements: Vec<PrefixAnnouncement>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrefixAnnouncement {
    pub prefix: String,
    /// Nexthop to be announced for this prefix.
    pub nexthop: IpAddr,
    /// Linklocal nexthop to be used for IPv6 announcements.
    pub llnh: Option<Ipv6Addr>,

    /// Path attributes
    pub local_pref: Option<u32>,
    /// Multi exit discriminator
    pub med: Option<u32>,
    /// Legacy communities [RFC 1997]
    pub communities: Option<Vec<String>>,
    /// Large communities [RFC 8092]
    pub large_communities: Option<Vec<String>>,
}

impl Default for PrefixAnnouncement {
    fn default() -> Self {
        Self {
            prefix: "::/0".to_owned(),
            nexthop: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            llnh: Default::default(),
            local_pref: Default::default(),
            med: Default::default(),
            communities: Default::default(),
            large_communities: Default::default(),
        }
    }
}

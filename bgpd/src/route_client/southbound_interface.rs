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

use std::{collections::HashMap, net::IpAddr};

use crate::bgp_packet::{constants::AddressFamilyIdentifier, nlri::NLRI};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::info;

/// SouthboundInterface provides a uniform API to network forwarding elements
/// These are devices or targets that perform packet routing and are the end
/// consumers of packet routing data.

#[async_trait]
pub trait SouthboundInterface {
    async fn route_add(
        &mut self,
        address_family: AddressFamilyIdentifier,
        prefix: NLRI,
        nexthop: IpAddr,
    ) -> Result<()>;
    async fn route_del(&mut self, prefix: NLRI, nexthop: IpAddr) -> Result<()>;
}

/// DummyVerifier is a SouthboundInterface that checks that routes are not added more than
/// once and not removed when there are none.
pub struct DummyVerifier {
    route_state: HashMap<NLRI, IpAddr>,
}

impl std::default::Default for DummyVerifier {
    fn default() -> DummyVerifier {
        DummyVerifier {
            route_state: HashMap::default(),
        }
    }
}

#[async_trait]
impl SouthboundInterface for DummyVerifier {
    async fn route_add(
        &mut self,
        _: AddressFamilyIdentifier,
        prefix: NLRI,
        nexthop: IpAddr,
    ) -> Result<()> {
        // Check that the route is not already present.
        match self.route_state.get(&prefix) {
            Some(value) => {
                return Err(anyhow!(
                    "Prefix {} with nexthop {} already contained in route_state! when trying to add {} -> {}",
                    prefix, value, prefix, nexthop,
                ));
            }
            _ => {}
        }
        if self.route_state.get(&prefix).is_some() {}
        // Insert route into in memory state.
        self.route_state.insert(prefix, nexthop);

        info!("Route add ok in verifier ({})", self.route_state.len());

        Ok(())
    }

    async fn route_del(&mut self, prefix: NLRI, nexthop: IpAddr) -> Result<()> {
        match self.route_state.remove(&prefix) {
            Some(entry) => {
                if entry != nexthop {
                    return Err(anyhow!(
                        "Removed entry's nexthop did not match: {} vs requested {}",
                        entry,
                        nexthop
                    ));
                }
            }
            None => {
                return Err(anyhow!(
                    "Requested removal of route {} that was not in route_state",
                    prefix
                ));
            }
        }

        info!("Route del ok in verifier ({})", self.route_state.len());
        Ok(())
    }
}

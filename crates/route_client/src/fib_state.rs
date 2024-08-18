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

use eyre::Result;
use ip_network_table_deps_treebitmap::address::Address;
use ip_network_table_deps_treebitmap::IpLookupTable;
use std::convert::{TryFrom, TryInto};
use std::fmt::Formatter;
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, trace, warn};

use bgp_packet::constants::AddressFamilyIdentifier;
use bgp_packet::nlri::NLRI;

use crate::southbound_interface::SouthboundInterface;

/// fib_state implements the logic to maintain forwarding routes in the FIB.
/// This for now means the Linux Kernel via Netlink, but in the future can
/// be extended to include other targets such as OpenFlow or even program
/// a router using BGP.

#[derive(Debug)]
pub struct FibEntry {
    nexthop: IpAddr,
}

pub struct FibState<A: Address, S: SouthboundInterface> {
    pub fib: IpLookupTable<A, Arc<Mutex<FibEntry>>>,
    pub southbound: S,
    pub af: AddressFamilyIdentifier,
}

impl<A: Address, S: SouthboundInterface> std::fmt::Debug for FibState<A, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "FibState af: {:?}", self.af)
    }
}

/// to_octets provides an interface for accessing an address as a vector of bytes.
/// This is implemented for IPv4Addr and IPv6Addr to be able to use them interchangably
/// to send updates to the kernel.
pub trait ToOctets {
    fn octets(&self) -> Vec<u8>;
}

impl ToOctets for Ipv4Addr {
    fn octets(&self) -> Vec<u8> {
        self.octets().into()
    }
}

impl ToOctets for Ipv6Addr {
    fn octets(&self) -> Vec<u8> {
        self.octets().into()
    }
}

impl<
        A: Address
            + std::convert::TryFrom<NLRI>
            + ToOctets
            + std::cmp::PartialEq
            + std::fmt::Display
            + std::fmt::Debug,
        S: SouthboundInterface,
    > FibState<A, S>
where
    String: From<<A as TryFrom<NLRI>>::Error>,
{
    pub async fn get_routing_table(&mut self) -> Result<()> {
        todo!();
    }

    /// route_add requests updating the nexthop to a particular path if it is not already
    /// the best path.
    pub async fn route_add(&mut self, nlri: &NLRI, nexthop: IpAddr) -> Result<(), String> {
        info!(af = ?self.af, %nlri, %nexthop);
        // Lookup the path in the Fib, there are three possible outcomes:
        // 1. The route is not yet known, we add it to the FibState and inject it into the kernel,
        // 2. The route is known and has a prior nexthop that needs to be updated
        // 3. The route is known and has the same nexthop: no-op.
        let prefix_addr: A = nlri.clone().try_into()?;
        match self
            .fib
            .exact_match(prefix_addr, nlri.prefixlen.into())
            .as_mut()
        {
            Some(entry_wrapped) => {
                let mut entry = entry_wrapped.lock().await;
                if entry.nexthop == nexthop {
                    // Nothing to do, route already in kernel.
                    trace!("Skipping route that already exists in kernel");
                } else {
                    // Remove old route
                    trace!("Remove old route: {:?}", entry);
                    if let Err(e) = self.southbound.route_del(nlri.clone(), entry.nexthop).await {
                        warn!(
                                "Southbound interface returned error when trying to remove route: {} via {}, error: {}",
                                nlri, entry.nexthop, e
                            );
                        return Err("Netlink remove error".to_string());
                    }

                    // Add new route
                    trace!(
                        "Add new route: prefix: {:?}, nexthop: {}",
                        nlri.prefix,
                        nexthop
                    );
                    if let Err(e) = self
                        .southbound
                        .route_add(self.af, nlri.clone(), nexthop)
                        .await
                    {
                        warn!(
                            "Netlink returned error when trying to add route: {} via {}, error: {}",
                            nlri, nexthop, e
                        );
                        return Err("Netlink add error".to_string());
                    }

                    entry.nexthop = nexthop;
                }
            }
            None => {
                // Need to insert a new entry for this route
                let entry = FibEntry {
                    nexthop: nexthop.clone(),
                };

                if let Err(e) = self
                    .southbound
                    .route_add(self.af, nlri.clone(), nexthop)
                    .await
                {
                    warn!(
                        "Netlink returned error when trying to add route: {} via {}, error: {}",
                        nlri, nexthop, e
                    );
                    return Err("Netlink add error".to_string());
                }

                let addr: A = nlri.clone().try_into()?;
                self.fib
                    .insert(addr, nlri.prefixlen.into(), Arc::new(Mutex::new(entry)));
                trace!(af = ?self.af, nlri = %nlri, nexthop = %nexthop, "Added to kernel");
            }
        };
        Ok(())
    }

    /// route_del removes a route from the FibState and kernel.
    pub async fn route_del(&mut self, nlri: NLRI) -> Result<(), String> {
        let prefix_addr: A = nlri.clone().try_into()?;
        if let Some(entry_wrapped) = self.fib.exact_match(prefix_addr, nlri.prefixlen.into()) {
            {
                let entry = entry_wrapped.lock().await;
                info!(%nlri, %prefix_addr, %entry.nexthop, "route_del");
                if let Err(e) = self.southbound.route_del(nlri.clone(), entry.nexthop).await {
                    warn!(
                        "Failed to apply route mutation to remove NLRI: {}, error: {}",
                        nlri, e
                    );
                }
            }
            self.fib.remove(prefix_addr, nlri.prefixlen.into());
        } else {
            warn!("Failed to find prefix to remove from FIB: {}", nlri);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv6Addr},
        str::FromStr,
    };

    use bgp_packet::nlri::NLRI;
    use eyre::{eyre, Result};
    use ip_network_table_deps_treebitmap::IpLookupTable;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    use crate::southbound_interface::DummyVerifier;

    use super::FibState;

    #[tokio::test]
    async fn test_double_add() -> Result<()> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(EnvFilter::from_default_env())
            .init();

        let southbound = DummyVerifier::default();
        let mut fib_state: FibState<Ipv6Addr, DummyVerifier> = FibState {
            fib: IpLookupTable::default(),
            southbound,
            af: bgp_packet::constants::AddressFamilyIdentifier::Ipv6,
        };

        let nlri = NLRI::try_from("2602:feda:b8d::/48").map_err(|e| eyre!(e))?;
        let nexthop = IpAddr::V6(Ipv6Addr::from_str("2001:db8:cafe::1")?);

        fib_state
            .route_add(&nlri, nexthop)
            .await
            .map_err(|e| eyre!(e))?;

        let nexthop_2 = IpAddr::V6(Ipv6Addr::from_str("2001:db8:babe::1")?);

        fib_state
            .route_add(&nlri, nexthop_2)
            .await
            .map_err(|e| eyre!(e))?;

        Ok(())
    }
}

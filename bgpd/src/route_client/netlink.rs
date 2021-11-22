use crate::bgp_packet::{constants::AddressFamilyIdentifier, nlri::NLRI};
use anyhow::Result;
use async_trait::async_trait;
use futures::TryStreamExt;
use netlink::constants::RTN_UNICAST;
use netlink_packet_route::{rtnl::route::nlas::Nla, RouteHeader};
use netlink_packet_route::{RouteMessage, RTPROT_STATIC};
use rtnetlink::IpVersion;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{convert::TryInto, io::ErrorKind};

use super::southbound_interface::SouthboundInterface;

/// NetlinkConnector implements methods to read/update Linux networking stuff including
/// routes and link level info.
pub struct NetlinkConnector {
    handle: rtnetlink::Handle,
    table: Option<u32>,
}

#[async_trait]
impl SouthboundInterface for NetlinkConnector {
    async fn route_add(
        &mut self,
        address_family: AddressFamilyIdentifier,
        prefix: NLRI,
        nexthop: IpAddr,
    ) -> Result<()> {
        let route = self.handle.route();
        match address_family {
            AddressFamilyIdentifier::Ipv6 => {
                let addr: Ipv6Addr = match prefix.clone().try_into()? {
                    IpAddr::V6(addr) => addr,
                    _ => {
                        return Err(anyhow::Error::from(std::io::Error::new(
                            ErrorKind::InvalidInput,
                            "Got non-IPv6 address from NLRI",
                        )))
                    }
                };
                let gw_addr: Ipv6Addr = match nexthop.clone().try_into()? {
                    IpAddr::V6(addr) => addr,
                    _ => {
                        return Err(anyhow::Error::from(std::io::Error::new(
                            ErrorKind::InvalidInput,
                            "Got non-IPv6 gateway for IPv6 NLRI",
                        )))
                    }
                };
                let mut mutation = route
                    .add()
                    .v6()
                    .destination_prefix(addr, prefix.prefixlen)
                    .gateway(gw_addr);
                if let Some(table_id) = self.table {
                    mutation = mutation.table(table_id.try_into().unwrap());
                }
                mutation.execute().await.map_err(|e| anyhow::Error::from(e))
            }
            AddressFamilyIdentifier::Ipv4 => {
                let addr: Ipv4Addr = match prefix.clone().try_into()? {
                    IpAddr::V4(addr) => addr,
                    _ => {
                        return Err(anyhow::Error::from(std::io::Error::new(
                            ErrorKind::InvalidInput,
                            "Got non-IPv4 address from NLRI",
                        )))
                    }
                };
                let gw_addr = match nexthop.clone().try_into()? {
                    IpAddr::V4(addr) => addr,
                    _ => {
                        return Err(anyhow::Error::from(std::io::Error::new(
                            ErrorKind::InvalidInput,
                            "Got non-IPv4 gateway for IPv4 NLRI",
                        )))
                    }
                };
                let mut mutation = route
                    .add()
                    .v4()
                    .destination_prefix(addr, prefix.prefixlen)
                    .gateway(gw_addr);
                if let Some(table_id) = self.table {
                    mutation = mutation.table(table_id.try_into().unwrap());
                }
                mutation.execute().await.map_err(|e| anyhow::Error::from(e))
            }
        }
    }

    async fn route_del(&mut self, prefix: NLRI, nexthop: IpAddr) -> Result<()> {
        let nh_octets = match nexthop {
            IpAddr::V6(addr) => addr.octets().to_vec(),
            IpAddr::V4(addr) => addr.octets().to_vec(),
        };
        let rt_handle = self.handle.route();
        let address_family = match prefix.afi {
            AddressFamilyIdentifier::Ipv4 => netlink_packet_route::rtnl::constants::AF_INET as u8,
            AddressFamilyIdentifier::Ipv6 => netlink_packet_route::rtnl::constants::AF_INET6 as u8,
        };
        let header = RouteHeader {
            address_family,
            destination_prefix_length: prefix.prefixlen,
            table: self.table.unwrap_or(0) as u8,
            protocol: RTPROT_STATIC,
            kind: RTN_UNICAST,
            ..Default::default()
        };
        let mut rt_msg = RouteMessage {
            header,
            ..Default::default()
        };
        let prefix_octets = match prefix.afi {
            AddressFamilyIdentifier::Ipv4 => {
                let addr: Ipv4Addr = match prefix.clone().try_into()? {
                    IpAddr::V4(addr) => addr,
                    _ => {
                        return Err(anyhow::Error::from(std::io::Error::new(
                            ErrorKind::InvalidInput,
                            "Got non-IPv4 address from NLRI",
                        )))
                    }
                };
                addr.octets().to_vec()
            }
            AddressFamilyIdentifier::Ipv6 => {
                let addr: Ipv6Addr = match prefix.clone().try_into()? {
                    IpAddr::V6(addr) => addr,
                    _ => {
                        return Err(anyhow::Error::from(std::io::Error::new(
                            ErrorKind::InvalidInput,
                            "Got non-IPv6 address from NLRI",
                        )))
                    }
                };
                addr.octets().to_vec()
            }
        };
        rt_msg.nlas.push(Nla::Destination(prefix_octets));
        rt_msg.nlas.push(Nla::Gateway(nh_octets));
        rt_handle
            .del(rt_msg)
            .execute()
            .await
            .map_err(|e| anyhow::Error::from(e))
    }
}

impl NetlinkConnector {
    pub async fn new(table: Option<u32>) -> Result<Self> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        Ok(NetlinkConnector { handle, table })
    }

    pub async fn dump_routes(
        &mut self,
        address_family: AddressFamilyIdentifier,
        table: Option<u32>,
    ) -> Result<Vec<RouteMessage>, rtnetlink::Error> {
        let mut req = self.handle.route().get(match address_family {
            AddressFamilyIdentifier::Ipv4 => IpVersion::V4,
            AddressFamilyIdentifier::Ipv6 => IpVersion::V6,
        });
        if let Some(table_id) = table {
            req.message_mut()
                .nlas
                .push(Nla::Table(table_id.try_into().unwrap()));
        }
        req.execute().try_collect().await
    }
}

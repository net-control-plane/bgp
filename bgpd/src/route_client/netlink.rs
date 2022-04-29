use crate::{
    bgp_packet::{constants::AddressFamilyIdentifier, nlri::NLRI},
    server::route_server::route_server::AddressFamily,
};
use futures::{StreamExt, TryStreamExt};
use netlink_packet_route::rtnl::route::nlas::Nla;
use netlink_packet_route::RouteMessage;
use rtnetlink::IpVersion;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// NetlinkConnector implements methods to read/update Linux networking stuff including
/// routes and link level info.
pub struct NetlinkConnector {
    handle: rtnetlink::Handle,
}

impl NetlinkConnector {
    pub async fn new() -> Result<Self, std::io::Error> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        Ok(NetlinkConnector { handle })
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

    pub async fn add_route(
        &mut self,
        address_family: AddressFamilyIdentifier,
        dst: NLRI,
        gateway: IpAddr,
        table: Option<u32>,
    ) -> Result<(), anyhow::Error> {
        let route = self.handle.route();
        match address_family {
            AddressFamilyIdentifier::Ipv6 => {
                let addr: Ipv6Addr = match dst.clone().try_into()? {
                    IpAddr::V6(addr) => addr,
                    _ => {
                        return Err(anyhow::Error::from(std::io::Error::new(
                            ErrorKind::InvalidInput,
                            "Got non-IPv6 address from NLRI",
                        )))
                    }
                };
                let gw_addr: Ipv6Addr = match gateway.clone().try_into()? {
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
                    .destination_prefix(addr, dst.prefixlen)
                    .gateway(gw_addr);
                if let Some(table_id) = table {
                    mutation = mutation.table(table_id.try_into().unwrap());
                }
                mutation.execute().await.map_err(|e| anyhow::Error::from(e))
            }
            AddressFamilyIdentifier::Ipv4 => {
                let addr: Ipv4Addr = match dst.clone().try_into()? {
                    IpAddr::V4(addr) => addr,
                    _ => {
                        return Err(anyhow::Error::from(std::io::Error::new(
                            ErrorKind::InvalidInput,
                            "Got non-IPv4 address from NLRI",
                        )))
                    }
                };
                let gw_addr = match gateway.clone().try_into()? {
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
                    .destination_prefix(addr, dst.prefixlen)
                    .gateway(gw_addr);
                if let Some(table_id) = table {
                    mutation = mutation.table(table_id.try_into().unwrap());
                }
                mutation.execute().await.map_err(|e| anyhow::Error::from(e))
            }
        }
    }

    fn remove_route(
        &mut self,
        address_family: AddressFamily,
        dst: NLRI,
        gateway: IpAddr,
        table: Option<u32>,
    ) -> Result<(), rtnetlink::Error> {
        todo!()
    }
}

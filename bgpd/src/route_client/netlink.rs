/// netlink.rs uses the netlink crates by little_dude to try and install routes to
/// the kernel. This is an experiment to replace the homemade netlink logic in //netlink
/// that didn't go according to plan.
use rtnetlink::RouteHandle;
use std::net::IpAddr;
use treebitmap::address;

use crate::{
    bgp_packet::{constants::AddressFamilyIdentifier, nlri::NLRI},
    server::route_server::route_server::AddressFamily,
};

/// NetlinkConnector implements methods to read/update Linux networking stuff including
/// routes and link level info.
pub struct NetlinkConnector {
    handle: rtnetlink::Handle,
}

impl NetlinkConnector {
    fn new() -> Result<Self, std::io::Error> {
        let (_, handle, _) = rtnetlink::new_connection()?;
        Ok(NetlinkConnector { handle })
    }

    async fn add_route(
        &mut self,
        address_family: AddressFamilyIdentifier,
        dst: NLRI,
        gateway: IpAddr,
        table: Option<u32>,
    ) -> Result<(), rtnetlink::Error> {
        let route = self.handle.route();
        match address_family {
            AddressFamilyIdentifier::Ipv6 => route.add().v6().execute().await,
            AddressFamilyIdentifier::Ipv4 => route.add().v4().execute().await,
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

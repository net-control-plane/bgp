use bgpd::bgp_packet::constants::AddressFamilyIdentifier;
use bgpd::bgp_packet::nlri::NLRI;
use bgpd::route_client::netlink::NetlinkConnector;
use std::io::ErrorKind;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    println!("Dumping all routes from netlink");

    let mut connector = NetlinkConnector::new().await.unwrap();
    let dump = connector
        .dump_routes(AddressFamilyIdentifier::Ipv6, None)
        .await
        .unwrap();

    for entry in dump {
        let dest_attr: Vec<u8> = entry
            .nlas
            .iter()
            .filter_map(|attr| match attr {
                netlink_packet_route::route::Nla::Destination(dst) => Some(dst.clone()),
                _ => None,
            })
            .next()
            .ok_or(anyhow::Error::new(std::io::Error::new(
                ErrorKind::InvalidData,
                "Did not find a destination attribute in RouteMessage",
            )))?;
        let nlri = NLRI::from_bytes(
            AddressFamilyIdentifier::Ipv6,
            dest_attr,
            entry.header.destination_prefix_length,
        )
        .unwrap();
        println!("NLRI: {}", nlri);
    }

    Ok(())
}

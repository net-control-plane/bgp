use std::str::FromStr;
use std::time::Duration;

use bgp_packet::nlri::NLRI;
use eyre::Result;
use tonic::transport::{Channel, Endpoint, Uri};

use crate::proto::bgp_server_admin_service_client::BgpServerAdminServiceClient;
use crate::proto::{AnnouncementRequest, Prefix};

pub struct Connector {
    client: BgpServerAdminServiceClient<Channel>,
}

impl Connector {
    pub async fn new(addr: String) -> Result<Self> {
        let uri = Uri::from_str(addr.as_str()).unwrap();
        let endpoint = Endpoint::from(uri).keep_alive_timeout(Duration::from_secs(10));
        let client = BgpServerAdminServiceClient::connect(endpoint).await?;
        Ok(Self { client })
    }

    pub async fn send_announce(&mut self, peer_name: String, prefix: NLRI) -> Result<()> {
        let request = AnnouncementRequest {
            peer_name,
            prefix: Some(Prefix {
                ip_prefix: prefix.prefix,
                prefix_len: prefix.prefixlen as i32,
                address_family: match prefix.afi {
                    bgp_packet::constants::AddressFamilyIdentifier::Ipv4 => {
                        crate::proto::AddressFamily::IPv4.into()
                    }
                    bgp_packet::constants::AddressFamilyIdentifier::Ipv6 => {
                        crate::proto::AddressFamily::IPv6.into()
                    }
                },
            }),
            large_communities: vec![],
            add: true,
        };
        self.client.announce_to_peer(request).await?;
        Ok(())
    }

    pub async fn send_withdraw(&mut self, peer_name: String, prefix: NLRI) -> Result<()> {
        let request = AnnouncementRequest {
            peer_name,
            prefix: Some(Prefix {
                ip_prefix: prefix.prefix,
                prefix_len: prefix.prefixlen as i32,
                address_family: match prefix.afi {
                    bgp_packet::constants::AddressFamilyIdentifier::Ipv4 => {
                        crate::proto::AddressFamily::IPv4.into()
                    }
                    bgp_packet::constants::AddressFamilyIdentifier::Ipv6 => {
                        crate::proto::AddressFamily::IPv6.into()
                    }
                },
            }),
            large_communities: vec![],
            add: false,
        };
        self.client.announce_to_peer(request).await?;
        Ok(())
    }
}

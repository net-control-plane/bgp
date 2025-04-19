use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use bytes::{Buf, BufMut, BytesMut};
use eyre::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::constants::AddressFamilyId;
use crate::parser::{ParserContext, ToWireError};

/// IpPrefix represents some IP address prefix, for a specific AddressFamilyId.
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize)]
pub struct IpPrefix {
    pub address_family: AddressFamilyId,
    pub prefix: Vec<u8>,
    pub length: u8,
}

impl IpPrefix {
    pub fn new(address_family: AddressFamilyId, prefix: Vec<u8>, length: u8) -> Result<Self> {
        // Ensure that the prefix we are given contains the right number of bytes corresponding to the prefix length.
        if prefix.len() < ((length + 7) / 8).into() {
            bail!(
                "Mismatched prefix {:?} for given prefix length: {}",
                prefix,
                length
            );
        }
        Ok(Self {
            address_family,
            prefix,
            length,
        })
    }

    pub fn to_wire(&self, _: &ParserContext, out: &mut BytesMut) -> Result<(), ToWireError> {
        // Verify that there is enough space to write the IpPrefix.
        if out.remaining() < (self.prefix.len() + 1) {
            Err(ToWireError::OutBufferOverflow)?;
        }

        // Write length and prefix.
        out.put_u8(self.length);
        out.put(self.prefix.as_slice());

        Ok(())
    }
}

impl TryFrom<&str> for IpPrefix {
    type Error = eyre::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split("/").collect();

        if parts.len() != 2 {
            bail!(
                "Expected IpPrefix in format prefix/length but got: {}",
                value
            );
        }

        let length: u8 = u8::from_str_radix(parts[1], 10).map_err(eyre::Error::from)?;
        let mut octets;
        let afi: AddressFamilyId;

        if parts[0].contains(":") {
            afi = AddressFamilyId::Ipv6;
            let addr: Ipv6Addr = Ipv6Addr::from_str(parts[0]).map_err(eyre::Error::from)?;
            octets = addr.octets().to_vec();
        } else if parts[0].contains(".") {
            afi = AddressFamilyId::Ipv4;
            let addr: Ipv4Addr = Ipv4Addr::from_str(parts[0]).map_err(eyre::Error::from)?;
            octets = addr.octets().to_vec();
        } else {
            bail!("Could not figure out address type")
        }

        // Truncate the octets we have to the right number of bytes to match the prefix length..
        if length % 8 == 0 {
            // We can cleanly truncate the number of bytes since we are at a byte boundary.
            octets.truncate((length / 8).into());
        } else {
            // We need to keep length % 8 bits of the last byte.
            let num_bytes = (length / 8) + 1;
            let mask = u8::MAX << (8 - (length % 8));
            octets.truncate(num_bytes.into());
            // Fix up the last byte.
            let last_pos = octets.len() - 1;
            octets[last_pos] &= mask;
        }

        Ok(IpPrefix {
            address_family: afi,
            prefix: octets,
            length,
        })
    }
}

impl Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.address_family {
            AddressFamilyId::Ipv4 => {
                // Pad the prefix with 0 bytes if it's less than 4 bytes long.
                let bytes = &mut self.prefix.clone();
                if bytes.len() < 4 {
                    bytes.extend(std::iter::repeat(0).take(4 - bytes.len()));
                }
                let four_bytes: [u8; 4] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| std::fmt::Error {})?;
                let ipv4_addr = Ipv4Addr::from(four_bytes);
                write!(f, "{}/{}", ipv4_addr, self.length)
            }
            AddressFamilyId::Ipv6 => {
                let bytes = &mut self.prefix.clone();
                if bytes.len() < 16 {
                    bytes.extend(std::iter::repeat(0).take(16 - bytes.len()));
                }
                let sixteen_bytes: [u8; 16] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| std::fmt::Error {})?;
                let ipv6_addr = Ipv6Addr::from(sixteen_bytes);
                write!(f, "{}/{}", ipv6_addr, self.length)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::AddressFamilyId;

    use super::IpPrefix;

    macro_rules! verify_roundtrip {
        ($name:ident, $prefix_str:expr, $afi:expr, $bytes:expr, $length:expr) => {
            #[test]
            fn $name() {
                let ip_prefix = IpPrefix::try_from($prefix_str).unwrap();

                assert_eq!(ip_prefix.address_family, $afi);
                assert_eq!(ip_prefix.prefix, $bytes);
                assert_eq!(ip_prefix.length, $length);

                let to_str: &str = &ip_prefix.to_string();
                assert_eq!(IpPrefix::try_from(to_str).unwrap(), ip_prefix);
            }
        };
    }

    verify_roundtrip!(
        verify_roundtrip_ipv4_24,
        "10.1.2.0/24",
        AddressFamilyId::Ipv4,
        vec![10, 1, 2],
        24
    );

    // Verify truncation.
    verify_roundtrip!(
        verify_roundtrip_ipv4_19,
        "10.245.123.0/19",
        AddressFamilyId::Ipv4,
        vec![10, 245, 96],
        19
    );

    // Verify truncation.
    verify_roundtrip!(
        verify_roundtrip_ipv4_3,
        "192.168.1.0/3",
        AddressFamilyId::Ipv4,
        vec![192],
        3
    );

    // Verify default address.
    verify_roundtrip!(
        verify_roundtrip_ipv4_0,
        "0.0.0.0/0",
        AddressFamilyId::Ipv4,
        vec![],
        0
    );

    verify_roundtrip!(
        verify_roundtrip_ipv6_48,
        "2001:db8:cafe::/48",
        AddressFamilyId::Ipv6,
        vec![32, 1, 13, 184, 202, 254],
        48
    );

    // Verify truncation.
    verify_roundtrip!(
        verify_roundtrip_ipv6_32,
        "2001:db8:cafe::/32",
        AddressFamilyId::Ipv6,
        vec![32, 1, 13, 184],
        32
    );

    verify_roundtrip!(
        verify_roundtrip_ipv6_0,
        "::/0",
        AddressFamilyId::Ipv6,
        vec![],
        0
    );
}

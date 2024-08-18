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

use crate::constants::AddressFamilyIdentifier;
use crate::traits::BGPParserError;
use crate::traits::ParserContext;
use crate::traits::ReadablePacket;
use crate::traits::WritablePacket;

use eyre::{bail, eyre};
use nom::bytes::complete::take;
use nom::number::complete::be_u8;
use nom::Err::Failure;
use nom::IResult;
use serde::de;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// NLRI here is the Neighbor Link Reachability Information from RFC 4271.
// Other NLRIs such as MP Reach NLRI are implemented as path attributes.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct NLRI {
    pub afi: AddressFamilyIdentifier,
    pub prefixlen: u8,
    pub prefix: Vec<u8>,
}

impl NLRI {
    pub fn from_bytes(
        afi: AddressFamilyIdentifier,
        prefix: Vec<u8>,
        prefixlen: u8,
    ) -> Result<Self, String> {
        // Check that the vector has enough bytes to represent the prefix.
        if prefix.len() < ((prefixlen + 7) / 8).into() {
            return Err(format!(
                "Prefix: {:?}/{} does not have enough bytes in prefix for given prefixlen",
                prefix, prefixlen
            ));
        }
        Ok(NLRI {
            afi,
            prefixlen,
            prefix,
        })
    }
}

impl ReadablePacket for NLRI {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        // plen is the length in bits of the address.
        let (buf, prefixlen) = be_u8(buf)?;
        let octet_len = (prefixlen + 7) / 8;
        let (buf, prefix) = take(octet_len)(buf)?;

        match ctx.nlri_mode {
            None => {
                return Err(Failure(BGPParserError::CustomText(
                    "nlri_mode not set in the context for NLRI::from_wire".to_string(),
                )));
            }
            Some(afi) => Ok((
                buf,
                NLRI {
                    afi,
                    prefixlen,
                    prefix: prefix.to_vec(),
                },
            )),
        }
    }
}

impl WritablePacket for NLRI {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = Vec::new();
        buf.push(self.prefixlen);
        buf.extend(self.prefix.as_slice());
        Ok(buf)
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(1 + self.prefix.len() as u16)
    }
}

impl Serialize for NLRI {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NLRI {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::try_from(String::deserialize(deserializer)?.as_str())
            .map_err(|e| de::Error::custom(e))
    }
}

impl TryFrom<NLRI> for Ipv6Addr {
    type Error = eyre::ErrReport;

    fn try_from(value: NLRI) -> Result<Self, Self::Error> {
        match value.afi {
            AddressFamilyIdentifier::Ipv6 => {
                let mut v: [u8; 16] = [0u8; 16];
                if value.prefix.len() > v.len() {
                    bail!(
                        "prefix length {} greater than IPv6 address length 16",
                        value.prefix.len()
                    );
                }
                for (pos, e) in value.prefix.iter().enumerate() {
                    v[pos] = *e;
                }
                let ip6: Ipv6Addr = v.into();
                Ok(ip6)
            }
            other => bail!("Unsupported AddressFamily type {}", other),
        }
    }
}

impl TryFrom<NLRI> for Ipv4Addr {
    type Error = eyre::Report;

    fn try_from(value: NLRI) -> Result<Self, Self::Error> {
        match value.afi {
            AddressFamilyIdentifier::Ipv4 => {
                let mut v: [u8; 4] = [0u8; 4];
                if value.prefix.len() > v.len() {
                    bail!(
                        "prefix length {} greater than IPv4 address length 4",
                        value.prefix.len()
                    );
                }
                for (pos, e) in value.prefix.iter().enumerate() {
                    v[pos] = *e;
                }
                let ip4 = Ipv4Addr::new(v[0], v[1], v[2], v[3]);
                Ok(ip4)
            }
            other => bail!("Unsupported AddressFamily type: {}", other),
        }
    }
}

impl TryInto<IpAddr> for NLRI {
    type Error = eyre::ErrReport;
    fn try_into(self) -> Result<IpAddr, Self::Error> {
        match self.afi {
            AddressFamilyIdentifier::Ipv4 => {
                let mut v: [u8; 4] = [0u8; 4];
                if self.prefix.len() > v.len() {
                    bail!(
                        "prefix length {} greater than IPv4 address length 4",
                        self.prefix.len()
                    );
                }
                for (pos, e) in self.prefix.iter().enumerate() {
                    v[pos] = *e;
                }
                let ip4 = Ipv4Addr::new(v[0], v[1], v[2], v[3]);
                Ok(IpAddr::V4(ip4))
            }
            AddressFamilyIdentifier::Ipv6 => {
                let mut v: [u8; 16] = [0u8; 16];
                if self.prefix.len() > v.len() {
                    bail!(
                        "prefix length {} greater than IPv6 address length 16",
                        self.prefix.len()
                    );
                }
                for (pos, e) in self.prefix.iter().enumerate() {
                    v[pos] = *e;
                }
                let ip6: Ipv6Addr = v.into();
                Ok(IpAddr::V6(ip6))
            }
        }
    }
}

impl TryFrom<&str> for NLRI {
    type Error = eyre::Report;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split("/").collect();
        if parts.len() != 2 {
            bail!("Expected ip_addr/prefixlen but got: {}", value);
        }

        let prefixlen: u8 =
            u8::from_str(parts[1]).map_err(|_| eyre!("failed to parse prefixlen"))?;
        let mut octets: Vec<u8>;
        let afi: AddressFamilyIdentifier;

        if parts[0].contains(":") {
            afi = AddressFamilyIdentifier::Ipv6;
            let addr: Ipv6Addr = Ipv6Addr::from_str(parts[0]).map_err(|e| eyre!(e))?;
            octets = addr.octets().to_vec();
        } else if parts[0].contains(".") {
            afi = AddressFamilyIdentifier::Ipv4;
            let addr: Ipv4Addr = Ipv4Addr::from_str(parts[0]).map_err(|e| eyre!(e))?;
            octets = addr.octets().to_vec();
        } else {
            bail!("Could not detect IP address type: {}", parts[0]);
        }

        // Truncate octets to prefixlen
        if prefixlen % 8 == 0 {
            // Cleanly truncate.
            octets.truncate((prefixlen / 8).into());
        } else {
            let num_bytes = (prefixlen / 8) + 1;
            let mask = u8::MAX << (8 - (prefixlen % 8));
            octets.truncate(num_bytes.into());
            if octets.len() > 0 {
                let last_pos = octets.len() - 1;
                octets[last_pos] &= mask;
            }
        }

        Ok(NLRI {
            afi,
            prefixlen,
            prefix: octets,
        })
    }
}

impl fmt::Display for NLRI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.afi {
            AddressFamilyIdentifier::Ipv4 => {
                let bytes = &mut self.prefix.clone();
                if bytes.len() < 4 {
                    bytes.extend(std::iter::repeat(0).take(4 - bytes.len()));
                }
                let four_bytes: [u8; 4] = bytes.as_slice().try_into().map_err(|_| fmt::Error {})?;
                let ipv4_addr = Ipv4Addr::from(four_bytes);
                write!(f, "{}/{}", ipv4_addr, self.prefixlen)
            }
            AddressFamilyIdentifier::Ipv6 => {
                let bytes = &mut self.prefix.clone();
                if bytes.len() < 16 {
                    bytes.extend(std::iter::repeat(0).take(16 - bytes.len()));
                }
                let sixteen_bytes: [u8; 16] =
                    bytes.as_slice().try_into().map_err(|_| fmt::Error {})?;
                let ipv6_addr = Ipv6Addr::from(sixteen_bytes);
                write!(f, "{}/{}", ipv6_addr, self.prefixlen)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::NLRI;
    use crate::constants::AddressFamilyIdentifier::{Ipv4, Ipv6};
    use crate::traits::ParserContext;
    use crate::traits::ReadablePacket;
    use crate::traits::WritablePacket;

    #[test]
    fn test_basic_nlri_v6() {
        let nlri_bytes: &[u8] = &[0x20, 0x20, 0x01, 0xdb, 0x8];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let nlri_res: (&[u8], NLRI) = NLRI::from_wire(ctx, nlri_bytes).unwrap();
        assert_eq!(nlri_res.1.afi, Ipv6);
        assert_eq!(nlri_res.1.prefixlen, 32);
        assert_eq!(nlri_res.1.prefix, vec![0x20, 0x01, 0xdb, 0x8]);
        assert_eq!(nlri_res.0.len(), 0);

        let wire: Vec<u8> = nlri_res.1.to_wire(ctx).unwrap();
        assert_eq!(wire.as_slice(), nlri_bytes);
        assert_eq!(nlri_res.1.wire_len(ctx).unwrap() as usize, wire.len());
    }

    #[test]
    fn test_basic_nlri_v4() {
        let nlri_bytes: &[u8] = &[0x18, 192, 168, 1];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv4);
        let nlri_res: (&[u8], NLRI) = NLRI::from_wire(ctx, nlri_bytes).unwrap();
        assert_eq!(nlri_res.1.afi, Ipv4);
        assert_eq!(nlri_res.1.prefixlen, 24);
        assert_eq!(nlri_res.1.prefix, vec![192, 168, 1]);
        assert_eq!(nlri_res.0.len(), 0);

        let wire: Vec<u8> = nlri_res.1.to_wire(ctx).unwrap();
        assert_eq!(wire.as_slice(), nlri_bytes);
        assert_eq!(nlri_res.1.wire_len(ctx).unwrap() as usize, wire.len());
    }

    #[test]
    fn test_string_roundtrip() {
        let cases: Vec<(String, Vec<u8>, u8, String)> = vec![
            (
                "2001:db8::/32".into(),
                vec![0x20, 0x01, 0xd, 0xb8],
                32,
                "2001:db8::/32".into(),
            ),
            (
                "2001:db8::1/16".into(),
                vec![0x20, 0x01],
                16,
                "2001::/16".into(),
            ),
            (
                "2001:db8::/64".into(),
                vec![0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0],
                64,
                "2001:db8::/64".into(),
            ),
            (
                "2001:db8::/24".into(),
                vec![0x20, 0x01, 0xd],
                24,
                "2001:d00::/24".into(),
            ),
            ("2001:db8::/0".into(), vec![], 0, "::/0".into()),
            ("::/0".into(), vec![], 0, "::/0".into()),
            ("10.0.0.0/8".into(), vec![10], 8, "10.0.0.0/8".into()),
        ];

        for (i, case) in cases.iter().enumerate() {
            let parsed_nlri = NLRI::try_from(case.0.as_str()).unwrap();
            assert_eq!(parsed_nlri.prefix, case.1, "Check prefix match ({})", i);
            assert_eq!(
                parsed_nlri.prefixlen, case.2,
                "Check prefixlen match ({})",
                i
            );
            assert_eq!(
                case.3,
                format!("{}", parsed_nlri),
                "Check std::fmt::Display match ({})",
                i
            );

            // Check that roundtripping via JSON serialize / deserialize is correct.
            let json_encoded = serde_json::to_string(&parsed_nlri).unwrap();
            assert_eq!(json_encoded[1..json_encoded.len() - 1], case.3);

            let reparsed: NLRI = serde_json::from_str(&json_encoded).unwrap();
            assert_eq!(reparsed, parsed_nlri);
        }
    }

    // #[test]
    // fn test_to_string_invalids() {
    //     let invalid_v4 = NLRI {
    //         afi: AddressFamilyIdentifier::Ipv4,
    //         prefix: vec![1, 2, 3, 4, 5],
    //         prefixlen: 16,
    //     };
    //     assert_eq!(
    //         "a formatting trait implementation returned an error: Error",
    //         format!("{}", invalid_v4)
    //     );
    // }
}

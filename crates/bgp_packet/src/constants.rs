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

use nom::IResult;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::ErrorKind;

use super::traits::{BGPParserError, ParserContext, ReadablePacket};

// Address Family Identifiers as per
// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
#[derive(Eq, PartialEq, Debug, Copy, Clone, Serialize, Deserialize, Hash, clap::ValueEnum)]
pub enum AddressFamilyIdentifier {
    Ipv4,
    Ipv6,
}

impl From<AddressFamilyIdentifier> for u16 {
    fn from(val: AddressFamilyIdentifier) -> Self {
        match val {
            AddressFamilyIdentifier::Ipv4 => 1,
            AddressFamilyIdentifier::Ipv6 => 2,
        }
    }
}

impl TryFrom<u16> for AddressFamilyIdentifier {
    type Error = std::io::Error;
    fn try_from(i: u16) -> Result<Self, Self::Error> {
        match i {
            1 => Ok(Self::Ipv4),
            2 => Ok(Self::Ipv6),
            _ => Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("Unknown AFI: {}", i),
            )),
        }
    }
}

impl From<AddressFamilyIdentifier> for Vec<u8> {
    fn from(val: AddressFamilyIdentifier) -> Self {
        match val {
            AddressFamilyIdentifier::Ipv4 => 1_u16.to_be_bytes().to_vec(),
            AddressFamilyIdentifier::Ipv6 => 2_u16.to_be_bytes().to_vec(),
        }
    }
}

/// Convenience functions to convert AddressFamilyIdentifier into those used by netlink.
impl From<AddressFamilyIdentifier> for netlink_packet_route::AddressFamily {
    fn from(val: AddressFamilyIdentifier) -> Self {
        match val {
            AddressFamilyIdentifier::Ipv4 => netlink_packet_route::AddressFamily::Inet,
            AddressFamilyIdentifier::Ipv6 => netlink_packet_route::AddressFamily::Inet6,
        }
    }
}

impl From<AddressFamilyIdentifier> for rtnetlink::IpVersion {
    fn from(val: AddressFamilyIdentifier) -> Self {
        match val {
            AddressFamilyIdentifier::Ipv4 => rtnetlink::IpVersion::V4,
            AddressFamilyIdentifier::Ipv6 => rtnetlink::IpVersion::V6,
        }
    }
}

/// This parser for AFI makes it easier to write the other message parsers.
impl ReadablePacket for AddressFamilyIdentifier {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], AddressFamilyIdentifier, BGPParserError<&'a [u8]>> {
        let (buf, afi_raw) = nom::number::complete::be_u16(buf)?;

        let afi = AddressFamilyIdentifier::try_from(afi_raw)
            .map_err(|e| nom::Err::Error(BGPParserError::CustomText(e.to_string())))?;

        IResult::Ok((buf, afi))
    }
}

impl fmt::Display for AddressFamilyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 => write!(f, "Ipv4"),
            Self::Ipv6 => write!(f, "Ipv6"),
        }
    }
}

// Subsequent Address Family Identifiers as per
// https://www.iana.org/assignments/safi-namespace/safi-namespace.xhtml
#[derive(Eq, PartialEq, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum SubsequentAddressFamilyIdentifier {
    Unicast,
    Multicast,
    NlriWithMpls,
    MplsLabeledVPN,
    MulticastMplsVpn,
}

impl From<SubsequentAddressFamilyIdentifier> for u8 {
    fn from(val: SubsequentAddressFamilyIdentifier) -> Self {
        match val {
            SubsequentAddressFamilyIdentifier::Unicast => 1,
            SubsequentAddressFamilyIdentifier::Multicast => 2,
            SubsequentAddressFamilyIdentifier::NlriWithMpls => 4,
            SubsequentAddressFamilyIdentifier::MplsLabeledVPN => 128,
            SubsequentAddressFamilyIdentifier::MulticastMplsVpn => 129,
        }
    }
}

impl TryFrom<u8> for SubsequentAddressFamilyIdentifier {
    type Error = std::io::Error;
    fn try_from(i: u8) -> Result<Self, Self::Error> {
        match i {
            1 => Ok(Self::Unicast),
            2 => Ok(Self::Multicast),
            4 => Ok(Self::NlriWithMpls),
            128 => Ok(Self::MplsLabeledVPN),
            129 => Ok(Self::MulticastMplsVpn),
            _ => Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("Unknown SAFI value: {} ", i),
            )),
        }
    }
}

/// This parser for SAFI makes it easier to write the other message parsers.
impl ReadablePacket for SubsequentAddressFamilyIdentifier {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], SubsequentAddressFamilyIdentifier, BGPParserError<&'a [u8]>> {
        let (buf, safi_raw) = nom::number::complete::be_u8(buf)?;

        let safi = SubsequentAddressFamilyIdentifier::try_from(safi_raw)
            .map_err(|e| nom::Err::Error(BGPParserError::CustomText(e.to_string())))?;

        IResult::Ok((buf, safi))
    }
}

impl fmt::Display for SubsequentAddressFamilyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unicast => write!(f, "Unicast"),
            Self::Multicast => write!(f, "Multicast"),
            Self::NlriWithMpls => write!(f, "NlriWithMpls"),
            Self::MulticastMplsVpn => write!(f, "MulticastMplsVpn"),
            Self::MplsLabeledVPN => write!(f, "MplsLabeledVpn"),
        }
    }
}

pub const AS_TRANS: u16 = 23456;

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
#[derive(Eq, PartialEq, Debug, Copy, Clone, Serialize, Deserialize, Hash)]
pub enum AddressFamilyIdentifier {
    Ipv4,
    Ipv6,
}

impl Into<u16> for AddressFamilyIdentifier {
    fn into(self) -> u16 {
        match self {
            Self::Ipv4 => 1,
            Self::Ipv6 => 2,
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
}

impl Into<u8> for SubsequentAddressFamilyIdentifier {
    fn into(self) -> u8 {
        match self {
            Self::Unicast => 1,
            Self::Multicast => 2,
        }
    }
}

impl TryFrom<u8> for SubsequentAddressFamilyIdentifier {
    type Error = std::io::Error;
    fn try_from(i: u8) -> Result<Self, Self::Error> {
        match i {
            1 => Ok(Self::Unicast),
            2 => Ok(Self::Multicast),
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
        }
    }
}

pub const AS_TRANS: u16 = 23456;

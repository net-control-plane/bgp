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
use crate::constants::SubsequentAddressFamilyIdentifier;
use crate::traits::BGPParserError;
use crate::traits::ParserContext;
use crate::traits::ReadablePacket;
use crate::traits::WritablePacket;
use byteorder::{ByteOrder, NetworkEndian};
use nom::number::complete::{be_u16, be_u8};
use nom::Err::Failure;
use nom::IResult;
use std::fmt;

/// BGPOpenOptionType represents the option types in the Open message.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash)]
pub struct BGPOpenOptionType(pub u8);

impl BGPOpenOptionType {
    pub fn new(val: u8) -> BGPOpenOptionType {
        BGPOpenOptionType(val)
    }
}

impl Into<u8> for BGPOpenOptionType {
    fn into(self) -> u8 {
        self.0
    }
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod BGPOpenOptionTypeValues {
    use super::BGPOpenOptionType;

    pub const CAPABILITIES: BGPOpenOptionType = BGPOpenOptionType(2);
}

#[derive(Debug, PartialEq)]
pub struct OpenOption {
    pub option_type: BGPOpenOptionType,
    pub oval: OpenOptions,
}

impl ReadablePacket for OpenOption {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], OpenOption, BGPParserError<&'a [u8]>> {
        let (buf, typ) = nom::combinator::complete(be_u8)(buf)?;
        let (buf, val) = match BGPOpenOptionType(typ) {
            BGPOpenOptionTypeValues::CAPABILITIES => {
                let (b, cap) = OpenOptionCapabilities::from_wire(ctx, buf)?;
                (b, OpenOptions::Capabilities(cap))
            }
            _ => {
                // TODO: This should gracefully degrrrrade and not fail the parser.
                return Err(Failure(BGPParserError::CustomText(
                    "Unknown BGP OPEN option".to_string(),
                )));
            }
        };
        IResult::Ok((
            buf,
            OpenOption {
                option_type: BGPOpenOptionType(typ),
                oval: val,
            },
        ))
    }
}

impl WritablePacket for OpenOption {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf = Vec::new();
        match &self.oval {
            OpenOptions::Capabilities(c) => {
                buf.push(BGPOpenOptionTypeValues::CAPABILITIES.into());
                buf.append(&mut c.to_wire(ctx)?);
            }
        }
        Ok(buf)
    }
    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str> {
        match &self.oval {
            OpenOptions::Capabilities(c) => {
                return Ok(2 + c.wire_len(ctx)?);
            }
        }
    }
}

impl fmt::Display for OpenOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OpenOption: {}", self.oval)
    }
}

#[derive(Debug, PartialEq)]
pub enum OpenOptions {
    Capabilities(OpenOptionCapabilities),
}

impl fmt::Display for OpenOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return match &self {
            OpenOptions::Capabilities(c) => write!(f, "Capabilities: {}", c),
        };
    }
}

/// CapabilityList represents a list of capabilities which can be present in an OpenOption.
#[derive(Debug, PartialEq)]
pub struct OpenOptionCapabilities {
    pub caps: Vec<BGPCapability>,
}

impl ReadablePacket for OpenOptionCapabilities {
    // from wire reads the length and value of the TLV.
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], OpenOptionCapabilities, BGPParserError<&'a [u8]>> {
        let (buf, caps): (_, Vec<BGPCapability>) = nom::multi::length_value(
            be_u8,
            nom::multi::many0(|i| BGPCapability::from_wire(ctx, i)),
        )(buf)?;
        return IResult::Ok((buf, OpenOptionCapabilities { caps }));
    }
}

impl WritablePacket for OpenOptionCapabilities {
    // to_wire writes the length and value of the TLV.
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = Vec::new();
        buf.push(self.wire_len(ctx).unwrap() as u8);
        for cap in &self.caps {
            let mut result: Vec<u8> = (*cap).to_wire(ctx)?;
            buf.append(&mut result);
        }
        Ok(buf)
    }
    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str> {
        let mut ttl: u16 = 0;
        for cap in &self.caps {
            ttl += (*cap).wire_len(ctx)?;
        }
        Ok(ttl)
    }
}

impl fmt::Display for OpenOptionCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Capabilities: [")?;
        for cap in &self.caps {
            std::fmt::Display::fmt(cap, f)?;
        }
        write!(f, "]")
    }
}

/// BGP Capabilities.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash)]
pub struct BGPCapabilityType(pub u8);

impl BGPCapabilityType {
    pub fn new(val: u8) -> BGPCapabilityType {
        BGPCapabilityType(val)
    }
}

impl Into<u8> for BGPCapabilityType {
    fn into(self) -> u8 {
        return self.0;
    }
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod BGPCapabilityTypeValues {
    use super::BGPCapabilityType;

    /// Multiprotocol Extensions for BGP-4 [RFC2858]
    pub const MULTPROTOCOL_BGP4: BGPCapabilityType = BGPCapabilityType(1);
    /// Route Refresh Capability for BGP-4 [RFC2918]
    pub const ROUTE_REFRESH_BGP4: BGPCapabilityType = BGPCapabilityType(2);
    /// Outbound Route Filtering Capability [RFC5291]
    pub const OUTBOUND_ROUTE_FILTERING: BGPCapabilityType = BGPCapabilityType(3);
    /// Extended Next Hop Encoding [RFC8950]
    pub const EXTENDED_NEXT_HOP: BGPCapabilityType = BGPCapabilityType(5);
    /// BGP Extended Message [RFC8654]
    pub const EXTENDED_MESSAGE: BGPCapabilityType = BGPCapabilityType(6);
    /// BGPsec Capability [RFC8205]
    pub const BGPSEC: BGPCapabilityType = BGPCapabilityType(7);
    /// Multiple Labels Capability [RFC8277]
    pub const MULTILABEL_COMPAT: BGPCapabilityType = BGPCapabilityType(8);

    /// Graceful Restart Capability [RFC4724]
    pub const GRACEFUL_RESTART: BGPCapabilityType = BGPCapabilityType(64);
    /// Support for 4-octet AS number capability [RFC6793]
    pub const FOUR_BYTE_ASN: BGPCapabilityType = BGPCapabilityType(65);
    /// ADD-PATH Capability [RFC7911]
    pub const ADD_PATH: BGPCapabilityType = BGPCapabilityType(69);
    /// Enhanced Route Refresh Capability [RFC7313]
    pub const ENHANCED_ROUTE_REFRESH: BGPCapabilityType = BGPCapabilityType(70);
}

#[derive(Debug, PartialEq)]
pub struct BGPCapability {
    pub cap_type: BGPCapabilityType,
    pub val: BGPCapabilityValue,
}

impl ReadablePacket for BGPCapability {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], BGPCapability, BGPParserError<&'a [u8]>> {
        let (buf, cap_type) = nom::combinator::peek(be_u8)(buf)?; // Peek the type, if we know it, consume.
        let (buf, val): (_, BGPCapabilityValue) =
            match BGPCapabilityType(cap_type) {
                BGPCapabilityTypeValues::FOUR_BYTE_ASN => {
                    let (buf, _) = be_u8(buf)?; // Consume type
                    let (buf, cap) = nom::multi::length_value(be_u8, |i| {
                        FourByteASNCapability::from_wire(ctx, i)
                    })(buf)?;
                    (buf, BGPCapabilityValue::FourByteASN(cap))
                }
                BGPCapabilityTypeValues::MULTPROTOCOL_BGP4 => {
                    let (buf, _) = be_u8(buf)?;
                    let (buf, cap) = nom::multi::length_value(be_u8, |i| {
                        MultiprotocolCapability::from_wire(ctx, i)
                    })(buf)?;
                    (buf, BGPCapabilityValue::Multiprotocol(cap))
                }
                // TODO: Add extended next hop.
                BGPCapabilityTypeValues::ROUTE_REFRESH_BGP4 => {
                    let (buf, _) = be_u8(buf)?;
                    let (buf, cap) = nom::multi::length_value(be_u8, |i| {
                        RouteRefreshCapability::from_wire(ctx, i)
                    })(buf)?;
                    (buf, BGPCapabilityValue::RouteRefresh(cap))
                }
                BGPCapabilityTypeValues::GRACEFUL_RESTART => {
                    let (buf, _) = be_u8(buf)?;
                    let (buf, cap) = nom::multi::length_value(be_u8, |i| {
                        GracefulRestartCapability::from_wire(ctx, i)
                    })(buf)?;
                    (buf, BGPCapabilityValue::GracefulRestart(cap))
                }
                _ => {
                    // If we do not know what this is, then put the bytes in an UnknownCapability.
                    let (buf, cap) = UnknownCapability::from_wire(ctx, buf)?;
                    (buf, BGPCapabilityValue::UnknownCapability(cap))
                }
            };
        IResult::Ok((
            buf,
            BGPCapability {
                cap_type: BGPCapabilityType(cap_type),
                val,
            },
        ))
    }
}

impl WritablePacket for BGPCapability {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = vec![];
        buf.push(self.cap_type.into());
        match &self.val {
            BGPCapabilityValue::FourByteASN(v) => {
                buf.push(v.wire_len(ctx)? as u8);
                buf.extend_from_slice(&v.to_wire(ctx)?);
            }
            BGPCapabilityValue::Multiprotocol(v) => {
                buf.push(v.wire_len(ctx)? as u8);
                buf.extend_from_slice(&v.to_wire(ctx)?);
            }
            BGPCapabilityValue::RouteRefresh(v) => {
                buf.push(v.wire_len(ctx)? as u8);
                buf.extend_from_slice(&v.to_wire(ctx)?);
            }
            BGPCapabilityValue::GracefulRestart(v) => {
                buf.push(v.wire_len(ctx)? as u8);
                buf.extend_from_slice(&v.to_wire(ctx)?);
            }
            BGPCapabilityValue::UnknownCapability(v) => {
                buf.push(v.wire_len(ctx)? as u8);
                buf.extend_from_slice(&v.to_wire(ctx)?);
            }
        };
        Ok(buf)
    }
    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str> {
        // BGPCapabilityType(u8) + cap_len(u8) + val
        return match &self.val {
            BGPCapabilityValue::FourByteASN(v) => Ok(2 + v.wire_len(ctx)?),
            BGPCapabilityValue::Multiprotocol(v) => Ok(2 + v.wire_len(ctx)?),
            BGPCapabilityValue::RouteRefresh(v) => Ok(2 + v.wire_len(ctx)?),
            BGPCapabilityValue::GracefulRestart(v) => Ok(2 + v.wire_len(ctx)?),
            BGPCapabilityValue::UnknownCapability(v) => Ok(2 + v.wire_len(ctx)?),
        };
    }
}

impl fmt::Display for BGPCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        std::fmt::Display::fmt(&self.val, f)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum BGPCapabilityValue {
    FourByteASN(FourByteASNCapability),
    Multiprotocol(MultiprotocolCapability),
    RouteRefresh(RouteRefreshCapability),
    GracefulRestart(GracefulRestartCapability),
    UnknownCapability(UnknownCapability),
}

impl fmt::Display for BGPCapabilityValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            BGPCapabilityValue::FourByteASN(v) => std::fmt::Display::fmt(v, f),
            BGPCapabilityValue::Multiprotocol(v) => std::fmt::Display::fmt(v, f),
            BGPCapabilityValue::RouteRefresh(v) => std::fmt::Display::fmt(v, f),
            BGPCapabilityValue::GracefulRestart(v) => std::fmt::Display::fmt(v, f),
            BGPCapabilityValue::UnknownCapability(v) => std::fmt::Display::fmt(v, f),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct UnknownCapability {
    cap_code: u8,
    payload: Vec<u8>,
}

impl ReadablePacket for UnknownCapability {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, typ) = be_u8(buf)?;
        let (buf, len) = be_u8(buf)?;
        let (buf, payload) = nom::bytes::complete::take(len)(buf)?;
        Ok((
            buf,
            UnknownCapability {
                cap_code: typ,
                payload: payload.to_vec(),
            },
        ))
    }
}

impl WritablePacket for UnknownCapability {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf = vec![];
        // No need to push the type or length on as that's done at a higher level.
        buf.extend(self.payload.to_owned());
        Ok(buf)
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(self.payload.len() as u16)
    }
}

impl fmt::Display for UnknownCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnknownCapability type: {}", self.cap_code)
    }
}

/// FourByteASNCapability represents the four byte BGP Capability value.
#[derive(Clone, Debug, PartialEq)]
pub struct FourByteASNCapability {
    pub asn: u32,
}

impl FourByteASNCapability {
    fn new(asn: u32) -> FourByteASNCapability {
        FourByteASNCapability { asn }
    }
}

impl ReadablePacket for FourByteASNCapability {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, asn) = nom::combinator::complete(nom::number::complete::be_u32)(buf)?;
        return IResult::Ok((buf, FourByteASNCapability::new(asn)));
    }
}

impl WritablePacket for FourByteASNCapability {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = vec![0; 4];
        byteorder::NetworkEndian::write_u32(&mut buf, self.asn);
        Ok(buf)
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(4)
    }
}

impl fmt::Display for FourByteASNCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FourByteASN: asn: {}", self.asn)
    }
}

/// MultiprotocolExtCapability represents support for RFC 4760.
#[derive(Clone, Debug, PartialEq)]
pub struct MultiprotocolCapability {
    pub afi: AddressFamilyIdentifier,
    pub safi: SubsequentAddressFamilyIdentifier,
}

impl MultiprotocolCapability {
    fn new(
        afi: AddressFamilyIdentifier,
        safi: SubsequentAddressFamilyIdentifier,
    ) -> MultiprotocolCapability {
        MultiprotocolCapability { afi, safi }
    }
}

impl ReadablePacket for MultiprotocolCapability {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], MultiprotocolCapability, BGPParserError<&'a [u8]>> {
        let (buf, (afi_raw, _, safi_raw)) = nom::combinator::complete(nom::sequence::tuple((
            |i| AddressFamilyIdentifier::from_wire(ctx, i),
            nom::bytes::complete::take(1u8),
            |i| SubsequentAddressFamilyIdentifier::from_wire(ctx, i),
        )))(buf)?;

        let afi = AddressFamilyIdentifier::try_from(afi_raw)
            .map_err(|e| nom::Err::Error(BGPParserError::CustomText(e.to_string())))?;
        let safi = SubsequentAddressFamilyIdentifier::try_from(safi_raw)
            .map_err(|e| nom::Err::Error(BGPParserError::CustomText(e.to_string())))?;

        IResult::Ok((buf, MultiprotocolCapability::new(afi, safi)))
    }
}

impl WritablePacket for MultiprotocolCapability {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        // [ AFI: uint16, 0: uint8, SAFI: uint8 ]
        let mut res = [0u8; 4];
        byteorder::NetworkEndian::write_u16(&mut res[..2], self.afi.into());
        res[3] = self.safi.into();
        Ok(res.to_vec())
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(4)
    }
}

impl fmt::Display for MultiprotocolCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MultiprotocolCapbility: [ {} {} ]", self.afi, self.safi,)
    }
}

// Route refresh capability
#[derive(Clone, Debug, PartialEq)]
pub struct RouteRefreshCapability {}

impl WritablePacket for RouteRefreshCapability {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        Ok(vec![])
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(0)
    }
}

impl ReadablePacket for RouteRefreshCapability {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], RouteRefreshCapability, BGPParserError<&'a [u8]>> {
        IResult::Ok((buf, RouteRefreshCapability {}))
    }
}

impl fmt::Display for RouteRefreshCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RouteRefreshCapability")
    }
}

// Graceful restart capability
#[derive(Clone, Debug, PartialEq)]
pub struct GracefulRestartCapability {
    pub restart_state: bool,   // 4 bits total, most sig bit here, rest reserved.
    pub restart_time_sec: u16, // 12 bits.
    pub payloads: Vec<GracefulRestartPayload>,
}

// GracefulRestartPayload represents the contents of the graceful restart cap.
#[derive(Clone, Debug, PartialEq)]
pub struct GracefulRestartPayload {
    pub afi: AddressFamilyIdentifier,
    pub safi: SubsequentAddressFamilyIdentifier,
    pub af_flags: bool, // 8 bits total, most significant bit used here.
}

impl ReadablePacket for GracefulRestartPayload {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], GracefulRestartPayload, BGPParserError<&'a [u8]>> {
        let (buf, (afi, safi, flags)) = nom::combinator::complete(nom::sequence::tuple((
            |i| AddressFamilyIdentifier::from_wire(ctx, i),
            |i| SubsequentAddressFamilyIdentifier::from_wire(ctx, i),
            be_u8,
        )))(buf)?;
        IResult::Ok((
            buf,
            GracefulRestartPayload {
                afi,
                safi,
                af_flags: (0x80 & flags) != 0,
            },
        ))
    }
}

impl WritablePacket for GracefulRestartPayload {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let afi: u16 = self.afi.into();
        let mut res = vec![0u8; 2];
        byteorder::NetworkEndian::write_u16(res.as_mut(), afi.into());
        res.push(self.safi.into());
        res.push(if self.af_flags { 0x80 } else { 0 });
        Ok(res)
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(4)
    }
}

impl fmt::Display for GracefulRestartPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GracefulRestartPayload: [afi:{} safi:{} af_flags:{}]",
            self.afi, self.safi, self.af_flags
        )
    }
}

impl ReadablePacket for GracefulRestartCapability {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, state_rt) = nom::combinator::complete(be_u16)(buf)?;
        let (buf, payloads): (_, Vec<GracefulRestartPayload>) =
            nom::multi::many0(|i| GracefulRestartPayload::from_wire(ctx, i))(buf)?;
        let restart_time_sec: u16 = 0x0fff & state_rt; // Lower 14 bits.
        let restart_state: bool = (0x8000 & state_rt) != 0; // highest bit
        IResult::Ok((
            buf,
            GracefulRestartCapability {
                restart_state,
                restart_time_sec,
                payloads,
            },
        ))
    }
}

impl WritablePacket for GracefulRestartCapability {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = vec![0u8; 2];
        let state_rt: u16 = ((self.restart_state as u16) << 15) | (0xfff & self.restart_time_sec);
        NetworkEndian::write_u16(&mut buf, state_rt);
        for item in &self.payloads {
            buf.append(&mut item.to_wire(ctx)?);
        }
        Ok(buf)
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok((2 + self.payloads.len() * 4) as u16)
    }
}

impl fmt::Display for GracefulRestartCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GracefulRestartCapability: [")?;
        for value in &self.payloads {
            fmt::Display::fmt(value, f)?;
        }
        write!(f, " ]")
    }
}

// RFC8950 - Advertising IPv4 NLRI with IPv6 next hop.
// GracefulRestartPayload represents the contents of the graceful restart cap.
#[derive(Clone, Debug, PartialEq)]
pub struct ExtendedNextHopEncodingCapability {
    pub afi_safi_nhafi: Vec<(
        AddressFamilyIdentifier,
        SubsequentAddressFamilyIdentifier,
        AddressFamilyIdentifier,
    )>,
}

impl WritablePacket for ExtendedNextHopEncodingCapability {
    fn to_wire(&self, _ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        Ok(self
            .afi_safi_nhafi
            .iter()
            .map(|e| {
                Into::<Vec<u8>>::into(e.0)
                    .into_iter()
                    .chain(vec![0x00, Into::<u8>::into(e.1)].into_iter())
                    .chain(Into::<Vec<u8>>::into(e.2).into_iter())
                    .collect::<Vec<u8>>()
            })
            .flatten()
            .collect::<Vec<u8>>())
    }

    fn wire_len(&self, _ctx: &ParserContext) -> Result<u16, &'static str> {
        Ok((self.afi_safi_nhafi.len() * 6) as u16)
    }
}

impl ReadablePacket for ExtendedNextHopEncodingCapability {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>>
    where
        Self: Sized,
    {
        let (buf, tuples) = nom::combinator::complete(nom::multi::many0(nom::sequence::tuple((
            |i| AddressFamilyIdentifier::from_wire(ctx, i),
            |i| {
                let (buf, _) = be_u8(i)?; // Eat the 0 byte.
                SubsequentAddressFamilyIdentifier::from_wire(ctx, buf)
            },
            |i| AddressFamilyIdentifier::from_wire(ctx, i),
        ))))(buf)?;

        IResult::Ok((
            buf,
            Self {
                afi_safi_nhafi: tuples,
            },
        ))
    }
}

impl fmt::Display for ExtendedNextHopEncodingCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtendednextHopEncodingCapability [")?;
        for entry in &self.afi_safi_nhafi {
            write!(f, "afi: {}, safi: {}, nhafi: {}", entry.0, entry.1, entry.2)?;
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {

    use super::BGPCapability;
    use super::BGPCapabilityTypeValues;
    use super::BGPCapabilityValue;
    use super::ExtendedNextHopEncodingCapability;
    use super::FourByteASNCapability;
    use super::OpenOption;
    use crate::constants::AddressFamilyIdentifier::Ipv6;
    use crate::traits::ParserContext;
    use crate::traits::ReadablePacket;

    #[test]
    fn test_four_byte_asn_capability() {
        let bytes: &[u8] = &[0x41, 0x04, 0x00, 0x00, 0x00, 0x2a];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let (buf, result) = BGPCapability::from_wire(ctx, bytes).unwrap();
        assert_eq!(
            result,
            BGPCapability {
                cap_type: BGPCapabilityTypeValues::FOUR_BYTE_ASN,
                val: BGPCapabilityValue::FourByteASN(FourByteASNCapability { asn: 42 })
            }
        );
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_open_options<'a>() {
        let option_bytes: &[u8] = &[
            0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02,
            0x02, 0x00, 0x02, 0x02, 0x46, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x00, 0x2a,
        ];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let (_buf, result) =
            nom::multi::many0(|buf: &'a [u8]| OpenOption::from_wire(ctx, buf))(option_bytes)
                .unwrap();

        let expected_str = "[OpenOption { option_type: BGPOpenOptionType(2), oval: Capabilities(OpenOptionCapabilities { caps: [BGPCapability { cap_type: BGPCapabilityType(1), val: Multiprotocol(MultiprotocolCapability { afi: Ipv4, safi: Unicast }) }] }) }, OpenOption { option_type: BGPOpenOptionType(2), oval: Capabilities(OpenOptionCapabilities { caps: [BGPCapability { cap_type: BGPCapabilityType(128), val: UnknownCapability(UnknownCapability { cap_code: 128, payload: [] }) }] }) }, OpenOption { option_type: BGPOpenOptionType(2), oval: Capabilities(OpenOptionCapabilities { caps: [BGPCapability { cap_type: BGPCapabilityType(2), val: RouteRefresh(RouteRefreshCapability) }] }) }, OpenOption { option_type: BGPOpenOptionType(2), oval: Capabilities(OpenOptionCapabilities { caps: [BGPCapability { cap_type: BGPCapabilityType(70), val: UnknownCapability(UnknownCapability { cap_code: 70, payload: [] }) }] }) }, OpenOption { option_type: BGPOpenOptionType(2), oval: Capabilities(OpenOptionCapabilities { caps: [BGPCapability { cap_type: BGPCapabilityType(65), val: FourByteASN(FourByteASNCapability { asn: 42 }) }] }) }]";
        assert_eq!(format!("{:?}", result), expected_str);
    }

    #[test]
    fn test_extended_next_hop_encoding_capability() {
        let bytes: Vec<u8> = vec![0x00, 0x01, 0x00, 0x01, 0x00, 0x02];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let (_, cap) = ExtendedNextHopEncodingCapability::from_wire(ctx, &bytes).unwrap();

        let expected_str =
            "ExtendednextHopEncodingCapability [afi: Ipv4, safi: Unicast, nhafi: Ipv6]";
        assert_eq!(expected_str, cap.to_string());
    }
}

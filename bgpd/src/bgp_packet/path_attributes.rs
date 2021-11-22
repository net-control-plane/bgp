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

use crate::bgp_packet::constants::AddressFamilyIdentifier;
use crate::bgp_packet::constants::SubsequentAddressFamilyIdentifier;
use crate::bgp_packet::nlri::NLRI;
use crate::bgp_packet::traits::BGPParserError;
use crate::bgp_packet::traits::ParserContext;
use crate::bgp_packet::traits::ReadablePacket;
use crate::bgp_packet::traits::WritablePacket;
use byteorder::ByteOrder;
use byteorder::NetworkEndian;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::Err::Failure;
use nom::IResult;
use serde::Serialize;
use std::convert::TryInto;
use std::fmt;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

/// PathAttribute represents path attributes in a BGP Update message.
#[derive(Debug, PartialEq, Clone, Serialize)]
pub enum PathAttribute {
    OriginPathAttribute(OriginPathAttribute),
    ASPathAttribute(ASPathAttribute),
    NextHopPathAttribute(NextHopPathAttribute),
    MultiExitDiscPathAttribute(MultiExitDiscPathAttribute),
    LocalPrefPathAttribute(LocalPrefPathAttribute),
    AtomicAggregatePathAttribute(AtomicAggregatePathAttribute),
    AggregatorPathAttribute(AggregatorPathAttribute),
    CommunitiesPathAttribute(CommunitiesPathAttribute),
    ExtendedCommunitiesPathAttribute(ExtendedCommunitiesPathAttribute),
    LargeCommunitiesPathAttribute(LargeCommunitiesPathAttribute),
    MPReachNLRIPathAttribute(MPReachNLRIPathAttribute),
    MPUnreachNLRIPathAttribute(MPUnreachNLRIPathAttribute),
    UnknownPathAttribute(Vec<u8>),
}

const PATH_ATTRIBUTE_FLAG_OPTONAL: u8 = 0x80; // when set to 1: optional, well-known: 0.
const PATH_ATTRIBUTE_FLAG_TRANSITIVE: u8 = 0x40; // when set to 1: transitive, non-transitive: 0.
const _PATH_ATTRIBUTE_FLAG_PARTIAL: u8 = 0x20; // when set to 1: partial, complete: 0.
const PATH_ATTRIBUTE_EXTENDED_LENGTH: u8 = 0x10; // when set to 1: length is u16, otherwise when 0 length is u8.
                                                 // For well known attributes the transitive bit MUST be set to 1.

// Write the type, length and call the child serializer
impl WritablePacket for PathAttribute {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        Ok(match self {
            PathAttribute::OriginPathAttribute(a) => {
                let typ: u8 = 1;
                let flag: u8 = PATH_ATTRIBUTE_FLAG_TRANSITIVE;
                let len: u8 = a.wire_len(ctx)? as u8;
                [vec![flag, typ, len], a.to_wire(ctx)?].concat()
            }
            PathAttribute::ASPathAttribute(a) => {
                let typ: u8 = 2;
                let flag: u8 = PATH_ATTRIBUTE_FLAG_TRANSITIVE;
                let len: u8 = a.wire_len(ctx)? as u8;
                [vec![flag, typ, len], a.to_wire(ctx)?].concat()
            }
            PathAttribute::NextHopPathAttribute(a) => {
                let typ: u8 = 3;
                let flag: u8 = PATH_ATTRIBUTE_FLAG_TRANSITIVE;
                let len: u8 = a.wire_len(ctx)? as u8;
                [vec![flag, typ, len], a.to_wire(ctx)?].concat()
            }
            PathAttribute::MultiExitDiscPathAttribute(a) => {
                let typ: u8 = 4;
                let flag: u8 = PATH_ATTRIBUTE_FLAG_OPTONAL;
                let len: u8 = a.wire_len(ctx)? as u8;
                [vec![flag, typ, len], a.to_wire(ctx)?].concat()
            }
            PathAttribute::LocalPrefPathAttribute(a) => {
                let typ: u8 = 5;
                let flag: u8 = 0;
                let len: u8 = a.wire_len(ctx)? as u8;
                [vec![flag, typ, len], a.to_wire(ctx)?].concat()
            }
            PathAttribute::AtomicAggregatePathAttribute(a) => {
                let typ: u8 = 6;
                let flag: u8 = 0;
                let len: u8 = a.wire_len(ctx)? as u8;
                [vec![flag, typ, len], a.to_wire(ctx)?].concat()
            }
            PathAttribute::AggregatorPathAttribute(a) => {
                let typ: u8 = 7;
                let flag: u8 = PATH_ATTRIBUTE_FLAG_OPTONAL | PATH_ATTRIBUTE_FLAG_TRANSITIVE;
                let len: u8 = a.wire_len(ctx)? as u8;
                [vec![flag, typ, len], a.to_wire(ctx)?].concat()
            }
            PathAttribute::CommunitiesPathAttribute(a) => {
                let typ: u8 = 8;
                let flag: u8 = PATH_ATTRIBUTE_FLAG_OPTONAL | PATH_ATTRIBUTE_FLAG_TRANSITIVE;
                let len: u8 = a.wire_len(ctx)? as u8;
                [vec![flag, typ, len], a.to_wire(ctx)?].concat()
            }
            PathAttribute::MPReachNLRIPathAttribute(a) => {
                let typ: u8 = 14;
                let flag: u8 = PATH_ATTRIBUTE_FLAG_OPTONAL;
                let len: u8 = a.wire_len(ctx)? as u8;
                [vec![flag, typ, len], a.to_wire(ctx)?].concat()
            }
            PathAttribute::MPUnreachNLRIPathAttribute(a) => {
                let typ: u8 = 15;
                let flag: u8 = PATH_ATTRIBUTE_FLAG_OPTONAL;
                let len: u8 = a.wire_len(ctx)? as u8;
                [vec![flag, typ, len], a.to_wire(ctx)?].concat()
            }
            PathAttribute::ExtendedCommunitiesPathAttribute(a) => {
                let typ: u8 = 16;
                let flag: u8 = PATH_ATTRIBUTE_FLAG_OPTONAL | PATH_ATTRIBUTE_FLAG_TRANSITIVE;
                let len: u8 = a.wire_len(ctx)? as u8;
                [vec![flag, typ, len], a.to_wire(ctx)?].concat()
            }
            PathAttribute::LargeCommunitiesPathAttribute(a) => {
                let typ: u8 = 32;
                let flag: u8 = PATH_ATTRIBUTE_FLAG_OPTONAL | PATH_ATTRIBUTE_FLAG_TRANSITIVE;
                let len: u8 = a.wire_len(ctx)? as u8;
                [vec![flag, typ, len], a.to_wire(ctx)?].concat()
            }
            PathAttribute::UnknownPathAttribute(u) => u.to_vec(),
        })
    }

    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str> {
        Ok(match self {
            PathAttribute::OriginPathAttribute(a) => 3 + a.wire_len(ctx)?,
            PathAttribute::ASPathAttribute(a) => 3 + a.wire_len(ctx)?,
            PathAttribute::NextHopPathAttribute(a) => 3 + a.wire_len(ctx)?,
            PathAttribute::MultiExitDiscPathAttribute(a) => 3 + a.wire_len(ctx)?,
            PathAttribute::LocalPrefPathAttribute(a) => 3 + a.wire_len(ctx)?,
            PathAttribute::AtomicAggregatePathAttribute(a) => 3 + a.wire_len(ctx)?,
            PathAttribute::AggregatorPathAttribute(a) => 3 + a.wire_len(ctx)?,
            PathAttribute::CommunitiesPathAttribute(a) => 3 + a.wire_len(ctx)?,
            PathAttribute::MPReachNLRIPathAttribute(a) => 3 + a.wire_len(ctx)?,
            PathAttribute::MPUnreachNLRIPathAttribute(a) => 3 + a.wire_len(ctx)?,
            PathAttribute::ExtendedCommunitiesPathAttribute(a) => 3 + a.wire_len(ctx)?,
            PathAttribute::LargeCommunitiesPathAttribute(a) => 3 + a.wire_len(ctx)?,
            PathAttribute::UnknownPathAttribute(u) => u.len() as u16,
        })
    }
}

// Read the type, length and dispatch accordingly.
impl ReadablePacket for PathAttribute {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, flag) = be_u8(buf)?;
        let (buf, typ) = be_u8(buf)?;
        let mut len8 = 0; // to preserve the 1 octet length for the unknown option.
        let (buf, len) = match flag & PATH_ATTRIBUTE_EXTENDED_LENGTH {
            PATH_ATTRIBUTE_EXTENDED_LENGTH => be_u16(buf)?,
            _ => {
                let (b, t) = be_u8(buf)?;
                len8 = t;
                (b, t as u16)
            }
        };
        // Explicitly read the attribute here and pass the attribute only buffer to the child parser.
        let (buf, pa_buf) = nom::bytes::complete::take(len)(buf)?;
        let (_, res): (_, PathAttribute) = match typ {
            1 => {
                let (b, r) = OriginPathAttribute::from_wire(ctx, pa_buf)?;
                (b, PathAttribute::OriginPathAttribute(r))
            }
            2 => {
                let (b, r) = ASPathAttribute::from_wire(ctx, pa_buf)?;
                (b, PathAttribute::ASPathAttribute(r))
            }
            3 => {
                let (b, r) = NextHopPathAttribute::from_wire(ctx, pa_buf)?;
                (b, PathAttribute::NextHopPathAttribute(r))
            }
            4 => {
                let (b, r) = MultiExitDiscPathAttribute::from_wire(ctx, pa_buf)?;
                (b, PathAttribute::MultiExitDiscPathAttribute(r))
            }
            5 => {
                let (b, r) = LocalPrefPathAttribute::from_wire(ctx, pa_buf)?;
                (b, PathAttribute::LocalPrefPathAttribute(r))
            }
            6 => {
                let (b, r) = AtomicAggregatePathAttribute::from_wire(ctx, pa_buf)?;
                (b, PathAttribute::AtomicAggregatePathAttribute(r))
            }
            7 => {
                let (b, r) = AggregatorPathAttribute::from_wire(ctx, pa_buf)?;
                (b, PathAttribute::AggregatorPathAttribute(r))
            }
            8 => {
                let (b, r) = CommunitiesPathAttribute::from_wire(ctx, pa_buf)?;
                (b, PathAttribute::CommunitiesPathAttribute(r))
            }
            14 => {
                let (b, r) = MPReachNLRIPathAttribute::from_wire(ctx, pa_buf)?;
                (b, PathAttribute::MPReachNLRIPathAttribute(r))
            }
            15 => {
                let (b, r) = MPUnreachNLRIPathAttribute::from_wire(ctx, pa_buf)?;
                (b, PathAttribute::MPUnreachNLRIPathAttribute(r))
            }
            16 => {
                let (b, r) = ExtendedCommunitiesPathAttribute::from_wire(ctx, pa_buf)?;
                (b, PathAttribute::ExtendedCommunitiesPathAttribute(r))
            }
            32 => {
                let (b, r) = LargeCommunitiesPathAttribute::from_wire(ctx, pa_buf)?;
                (b, PathAttribute::LargeCommunitiesPathAttribute(r))
            }
            _ => {
                let mut tmp = vec![flag, typ];
                if len8 != 0 {
                    tmp.push(len8);
                } else {
                    let mut t = [0u8; 2];
                    byteorder::NetworkEndian::write_u16(&mut t, len);
                    tmp.append(&mut t.to_vec());
                }
                tmp.extend(pa_buf.to_vec());
                (&[], PathAttribute::UnknownPathAttribute(tmp))
            }
        };
        Ok((buf, res))
    }
}

impl fmt::Display for PathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathAttribute::OriginPathAttribute(a) => std::fmt::Display::fmt(&a, f),
            PathAttribute::ASPathAttribute(a) => std::fmt::Display::fmt(&a, f),
            PathAttribute::NextHopPathAttribute(a) => std::fmt::Display::fmt(&a, f),
            PathAttribute::MultiExitDiscPathAttribute(a) => std::fmt::Display::fmt(&a, f),
            PathAttribute::LocalPrefPathAttribute(a) => std::fmt::Display::fmt(&a, f),
            PathAttribute::AtomicAggregatePathAttribute(a) => std::fmt::Display::fmt(&a, f),
            PathAttribute::AggregatorPathAttribute(a) => std::fmt::Display::fmt(&a, f),
            PathAttribute::CommunitiesPathAttribute(a) => std::fmt::Display::fmt(&a, f),
            PathAttribute::MPReachNLRIPathAttribute(a) => std::fmt::Display::fmt(&a, f),
            PathAttribute::MPUnreachNLRIPathAttribute(a) => std::fmt::Display::fmt(&a, f),
            PathAttribute::ExtendedCommunitiesPathAttribute(a) => std::fmt::Display::fmt(&a, f),
            PathAttribute::LargeCommunitiesPathAttribute(a) => std::fmt::Display::fmt(&a, f),
            PathAttribute::UnknownPathAttribute(a) => {
                write!(f, "unknown PathAttribute, bytes: {:?}", a)
            }
        }
    }
}

// Path attribute implementations.

/// Origin path attribute is a mandatory attribute defined in RFC4271.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct OriginPathAttribute(pub u8);

pub mod origin_path_attribute_values {
    use super::OriginPathAttribute;

    pub const IGP: OriginPathAttribute = OriginPathAttribute(0);
    pub const EGP: OriginPathAttribute = OriginPathAttribute(1);
    pub const UNKNOWN: OriginPathAttribute = OriginPathAttribute(2);
}

impl ReadablePacket for OriginPathAttribute {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, opa) = be_u8(buf)?;
        Ok((buf, OriginPathAttribute(opa)))
    }
}

impl WritablePacket for OriginPathAttribute {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        Ok(vec![self.0])
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(1)
    }
}

impl fmt::Display for OriginPathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use origin_path_attribute_values::*;
        match self {
            &IGP => write!(f, "Origin: IGP"),
            &EGP => write!(f, "Origin: EGP"),
            &UNKNOWN => write!(f, "Origin: Unknown"),
            _ => write!(f, "Origin: invalid value"),
        }
    }
}

/// ASPathAttribute is a well-known mandatory attribute that contains a list of TLV encoded path
/// segments. Type is either 1 for AS_SET or 2 for AS_SEQUENCE, length is a 1 octet field
/// containing the number of ASNS and the value contains the ASNs. This is defined in Section 4.3
/// of RFC4271.

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct ASPathAttribute {
    pub segments: Vec<ASPathSegment>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct ASPathSegment {
    /// ordered is true when representing an AS_SEQUENCE, andd false when
    /// representing an AS_SET.
    pub ordered: bool,
    /// Path is the list of ASNs.
    pub path: Vec<u32>,
}

impl ASPathAttribute {
    pub fn from_asns(asns: Vec<u32>) -> PathAttribute {
        let segment = ASPathSegment {
            ordered: true,
            path: asns,
        };
        PathAttribute::ASPathAttribute(ASPathAttribute {
            segments: vec![segment],
        })
    }
}

impl ReadablePacket for ASPathAttribute {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let parse_segment = |ctx: &ParserContext,
                             buf: &'a [u8]|
         -> IResult<&'a [u8], ASPathSegment, BGPParserError<&'a [u8]>> {
            let (buf, typ) = be_u8(buf)?;
            let (buf, len) = be_u8(buf)?;
            let (buf, asns): (_, Vec<u32>) = match ctx.four_octet_asn {
                Some(true) => nom::multi::many_m_n(len as usize, len as usize, be_u32)(buf)?,
                Some(false) => {
                    let (buf, asn_u16) =
                        nom::multi::many_m_n(len as usize, len as usize, be_u16)(buf)?;
                    let mut asn_u32: Vec<u32> = Vec::new();
                    for asn in asn_u16 {
                        asn_u32.push(asn as u32);
                    }
                    (buf, asn_u32)
                }
                None => {
                    return Err(Failure(BGPParserError::CustomText(
                        "Can't parse ASPath without four_octet_asn being set".to_owned(),
                    )));
                }
            };

            Ok((
                buf,
                ASPathSegment {
                    ordered: (typ == 2),
                    path: asns,
                },
            ))
        };

        let (buf, segments): (_, Vec<ASPathSegment>) =
            nom::multi::many0(|buf: &'a [u8]| parse_segment(ctx, buf))(buf)?;

        Ok((buf, ASPathAttribute { segments }))
    }
}

impl WritablePacket for ASPathAttribute {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        if !ctx.four_octet_asn.unwrap_or(false) {
            return Err(
                "Can't use ASPathAttribute to communicate with legacy peer, use AS4PathAttribute",
            );
        }
        let mut wire: Vec<u8> = Vec::new();

        for segment in &self.segments {
            wire.push(if segment.ordered { 2 } else { 1 });
            wire.push(
                segment
                    .path
                    .len()
                    .try_into()
                    .map_err(|_| "ASPath segment too long")?,
            );
            for asn in &segment.path {
                let mut tmp: Vec<u8> = vec![0u8; 4];
                NetworkEndian::write_u32(&mut tmp, *asn);
                wire.append(&mut tmp);
            }
        }
        Ok(wire)
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        let mut ctr: u16 = 0;
        for segment in &self.segments {
            ctr += 2;
            ctr += (4 * segment.path.len()) as u16;
        }
        Ok(ctr)
    }
}

impl fmt::Display for ASPathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AS Path: {{ ")?;
        for segment in &self.segments {
            write!(f, "Segment [ ")?;
            if segment.ordered {
                write!(f, "Type: AS_SEGMENT ")?
            } else {
                write!(f, "Type: AS_SET ")?
            };
            for asn in &segment.path {
                write!(f, "{} ", asn)?;
            }
            write!(f, " ]")?;
        }
        write!(f, "] }}")
    }
}

// TODO: AS4 path attribute
// Per RFC 6793 the AS4 path attribute is for legacy BGP speakers to propagate
// 4 octet ASNs in update messages.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct AS4PathAttribute {
    pub ordered: bool,
    pub path: Vec<u32>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct NextHopPathAttribute(pub Ipv4Addr);

impl ReadablePacket for NextHopPathAttribute {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (_, ip_u32) = be_u32(buf)?;
        let nexthop = Ipv4Addr::from(ip_u32);
        Ok((buf, NextHopPathAttribute(nexthop)))
    }
}

impl WritablePacket for NextHopPathAttribute {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        return Ok(self.0.octets().to_vec());
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        return Ok(4);
    }
}

impl fmt::Display for NextHopPathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NextHop: {}", self.0)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct MultiExitDiscPathAttribute(pub u32);

impl ReadablePacket for MultiExitDiscPathAttribute {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, val) = be_u32(buf)?;
        Ok((buf, MultiExitDiscPathAttribute(val)))
    }
}

impl WritablePacket for MultiExitDiscPathAttribute {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = vec![0u8; 4];
        byteorder::NetworkEndian::write_u32(&mut buf, self.0);
        Ok(buf)
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(4)
    }
}

impl fmt::Display for MultiExitDiscPathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MultiExitDisc: {}", self.0)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct LocalPrefPathAttribute(pub u32);

impl ReadablePacket for LocalPrefPathAttribute {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, val) = be_u32(buf)?;
        Ok((buf, LocalPrefPathAttribute(val)))
    }
}

impl WritablePacket for LocalPrefPathAttribute {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = vec![0u8; 4];
        byteorder::NetworkEndian::write_u32(&mut buf, self.0);
        Ok(buf)
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(4)
    }
}

impl fmt::Display for LocalPrefPathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocalPref: {}", self.0)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct AtomicAggregatePathAttribute {}

impl ReadablePacket for AtomicAggregatePathAttribute {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        Ok((buf, AtomicAggregatePathAttribute {}))
    }
}

impl WritablePacket for AtomicAggregatePathAttribute {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        Ok(vec![])
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(0)
    }
}

impl fmt::Display for AtomicAggregatePathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AtomicAggregate: present")
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct AggregatorPathAttribute {
    pub asn: u32,
    pub ip: Ipv4Addr,
}

// TODO: Support non AS4 peers.
impl ReadablePacket for AggregatorPathAttribute {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        if !ctx.four_octet_asn.is_some() {
            return Err(Failure(BGPParserError::CustomText(
                "Non four byte ASN not supported (AggregatorPathAttribute from_wire)".to_string(),
            )));
        }
        let (buf, asn) = be_u32(buf)?;
        let (buf, ip) = nom::bytes::complete::take(4u8)(buf)?;
        let correct: [u8; 4] = ip.try_into().expect("wrong slice len");
        Ok((
            buf,
            AggregatorPathAttribute {
                asn,
                ip: Ipv4Addr::from(correct),
            },
        ))
    }
}

impl WritablePacket for AggregatorPathAttribute {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        if !ctx.four_octet_asn.is_some() {
            panic!("Non four byte ASN not supported (AggregatorPathAttribute from_wire)");
        }
        let mut buf: Vec<u8> = vec![0u8; 4];
        byteorder::NetworkEndian::write_u32(&mut buf, self.asn);
        buf.extend(self.ip.octets().to_vec());
        Ok(buf)
    }
    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str> {
        if !ctx.four_octet_asn.is_some() {
            panic!("Non four byte ASN not supported (AggregatorPathAttribute from_wire)");
        }
        Ok(8)
    }
}

impl fmt::Display for AggregatorPathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Aggregator: asn: {}, ip: {}", self.asn, self.ip)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct CommunitiesPathAttribute {
    pub values: Vec<CommunitiesPayload>,
}

impl ReadablePacket for CommunitiesPathAttribute {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, values): (_, Vec<CommunitiesPayload>) =
            nom::multi::many0(|i| CommunitiesPayload::from_wire(ctx, i))(buf)?;
        Ok((buf, CommunitiesPathAttribute { values }))
    }
}

impl WritablePacket for CommunitiesPathAttribute {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf = vec![];
        for val in &self.values {
            buf.extend(val.to_wire(ctx)?);
        }
        Ok(buf)
    }
    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str> {
        let mut ttl: u16 = 0;
        for val in &self.values {
            ttl += val.wire_len(ctx)?;
        }
        Ok(ttl)
    }
}

impl fmt::Display for CommunitiesPathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Communities: [ ")?;
        for c in &self.values {
            write!(f, " {}, ", c)?;
        }
        write!(f, " ] ")
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct CommunitiesPayload {
    pub asn: u16,
    pub payload: u16,
}

impl ReadablePacket for CommunitiesPayload {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, asn): (_, u16) = be_u16(buf)?;
        let (buf, payload): (_, u16) = be_u16(buf)?;
        Ok((buf, CommunitiesPayload { asn, payload }))
    }
}

impl WritablePacket for CommunitiesPayload {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf = vec![0u8; 4];
        byteorder::NetworkEndian::write_u16(&mut buf[0..2], self.asn);
        byteorder::NetworkEndian::write_u16(&mut buf[2..4], self.payload);
        Ok(buf)
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(4)
    }
}

impl fmt::Display for CommunitiesPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.asn, self.payload)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct ExtendedCommunitiesPathAttribute {
    pub t_high: u8,
    // TODO: Handle t_low and subtypes of the Extended Communities attribute as defined in rfc4360.
    pub value: Vec<u8>,
}

impl ReadablePacket for ExtendedCommunitiesPathAttribute {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, t_high) = be_u8(buf)?;
        let (buf, value) = nom::bytes::complete::take(7u8)(buf)?;
        Ok((
            buf,
            ExtendedCommunitiesPathAttribute {
                t_high,
                value: value.to_vec(),
            },
        ))
    }
}

impl WritablePacket for ExtendedCommunitiesPathAttribute {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        if !self.value.len() == 7 {
            return Err("ExtendedCommunitiesPathAttribute value length != 7");
        }
        Ok(vec![vec![self.t_high], self.value.to_owned()].concat())
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(8)
    }
}

impl fmt::Display for ExtendedCommunitiesPathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtendedCommunities: {} {:?}", self.t_high, self.value)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct LargeCommunitiesPathAttribute {
    pub values: Vec<LargeCommunitiesPayload>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct LargeCommunitiesPayload {
    pub global_admin: u32,
    pub ld1: u32,
    pub ld2: u32,
}

impl ReadablePacket for LargeCommunitiesPayload {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, global_admin) = be_u32(buf)?;
        let (buf, ld1) = be_u32(buf)?;
        let (buf, ld2) = be_u32(buf)?;
        Ok((
            buf,
            LargeCommunitiesPayload {
                global_admin,
                ld1,
                ld2,
            },
        ))
    }
}

impl WritablePacket for LargeCommunitiesPayload {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf = vec![0u8; 12];
        byteorder::NetworkEndian::write_u32(&mut buf[0..4], self.global_admin);
        byteorder::NetworkEndian::write_u32(&mut buf[4..8], self.ld1);
        byteorder::NetworkEndian::write_u32(&mut buf[8..12], self.ld2);
        Ok(buf)
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(12)
    }
}

impl fmt::Display for LargeCommunitiesPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.global_admin, self.ld1, self.ld2)
    }
}

impl ReadablePacket for LargeCommunitiesPathAttribute {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, values): (_, Vec<LargeCommunitiesPayload>) =
            nom::multi::many0(|i| LargeCommunitiesPayload::from_wire(ctx, i))(buf)?;
        Ok((buf, LargeCommunitiesPathAttribute { values }))
    }
}

impl WritablePacket for LargeCommunitiesPathAttribute {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf = vec![];
        for val in &self.values {
            buf.extend(val.to_wire(ctx)?);
        }
        Ok(buf)
    }
    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str> {
        let mut ttl: u16 = 0;
        for val in &self.values {
            ttl += val.wire_len(ctx)?;
        }
        Ok(ttl)
    }
}

impl fmt::Display for LargeCommunitiesPathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LargeCommunities: [")?;
        for c in &self.values {
            write!(f, " {}, ", c)?;
        }
        write!(f, "]")
    }
}

/// MPReachPathAattribute implements the MultiProtocol extensions to BGP (RFC4760)
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct MPReachNLRIPathAttribute {
    pub afi: AddressFamilyIdentifier,
    pub safi: SubsequentAddressFamilyIdentifier,
    pub nexthop: Vec<u8>,
    pub nlris: Vec<NLRI>,
}

impl MPReachNLRIPathAttribute {
    // https://datatracker.ietf.org/doc/html/rfc2545 describes what the nexthop
    // field can contain. Returns a tuple of (global_nh, linklocal_nh)
    pub fn nexthop_to_v6(self) -> Option<(Ipv6Addr, Option<Ipv6Addr>)> {
        return match self.nexthop.len() {
            16 => {
                let nh_bytes: [u8; 16] = self.nexthop.try_into().unwrap();
                Some((Ipv6Addr::from(nh_bytes), None))
            }
            32 => {
                let global_nh_bytes: [u8; 16] = self.nexthop[0..16].try_into().unwrap();
                let llnh_bytes: [u8; 16] = self.nexthop[16..32].try_into().unwrap();
                Some((
                    Ipv6Addr::from(global_nh_bytes),
                    Some(Ipv6Addr::from(llnh_bytes)),
                ))
            }
            _ => None,
        };
    }
}

impl ReadablePacket for MPReachNLRIPathAttribute {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, afi) = AddressFamilyIdentifier::from_wire(ctx, buf)?;
        let (buf, safi) = SubsequentAddressFamilyIdentifier::from_wire(ctx, buf)?;
        let (buf, nexthop): (_, Vec<u8>) =
            nom::multi::length_value(be_u8, nom::multi::many0(be_u8))(buf)?;
        // Reserved field set to 0.
        let (buf, _) = be_u8(buf)?;
        let (buf, nlris): (_, Vec<NLRI>) = nom::multi::many0(|i| NLRI::from_wire(ctx, i))(buf)?;

        Ok((
            buf,
            MPReachNLRIPathAttribute {
                afi,
                safi,
                nexthop,
                nlris,
            },
        ))
    }
}

impl WritablePacket for MPReachNLRIPathAttribute {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf = vec![0u8; 4];
        byteorder::NetworkEndian::write_u16(&mut buf[0..2], self.afi.into());
        buf[2] = self.safi.into();
        buf[3] = self.nexthop.len() as u8;
        buf.extend(&self.nexthop);
        // Reserved field set to 0.
        buf.push(0);
        for nlri in &self.nlris {
            buf.extend(nlri.to_wire(ctx)?);
        }
        Ok(buf)
    }
    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str> {
        let mut ctr: u16 = 0;
        ctr += 4; // afi + safi + the (len of nexthop) octet
        ctr += self.nexthop.len() as u16;
        ctr += 1; // Reserved octet.
        for nlri in &self.nlris {
            ctr += nlri.wire_len(ctx)?;
        }
        Ok(ctr)
    }
}

impl fmt::Display for MPReachNLRIPathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MPReachNLRI: afi: {} safi: {}, nexthop: {:?} nlris: [",
            self.afi, self.safi, self.nexthop
        )?;
        for nlri in &self.nlris {
            std::fmt::Display::fmt(nlri, f)?;
        }
        write!(f, "]")
    }
}

/// MPUnreachNLRIPathAttribute represents a MultiProtocol prefix withdrawal.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct MPUnreachNLRIPathAttribute {
    pub afi: AddressFamilyIdentifier,
    pub safi: SubsequentAddressFamilyIdentifier,
    pub nlris: Vec<NLRI>,
}

impl ReadablePacket for MPUnreachNLRIPathAttribute {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, afi) = AddressFamilyIdentifier::from_wire(ctx, buf)?;
        let (buf, safi) = SubsequentAddressFamilyIdentifier::from_wire(ctx, buf)?;
        let (buf, nlris): (_, Vec<NLRI>) = nom::multi::many0(|i| NLRI::from_wire(ctx, i))(buf)?;
        Ok((buf, MPUnreachNLRIPathAttribute { afi, safi, nlris }))
    }
}

impl WritablePacket for MPUnreachNLRIPathAttribute {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf = vec![0u8; 3];
        NetworkEndian::write_u16(&mut buf[0..2], self.afi.into());
        buf[2] = self.safi.into();
        for nlri in &self.nlris {
            buf.extend(nlri.to_wire(ctx)?);
        }
        Ok(buf)
    }
    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str> {
        let mut ctr: u16 = 0;
        ctr += 3;
        for nlri in &self.nlris {
            ctr += nlri.wire_len(ctx)?;
        }
        Ok(ctr)
    }
}

impl fmt::Display for MPUnreachNLRIPathAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MPUnreachNLRI: afi: {} safi: {}, nlris: [",
            self.afi, self.safi
        )?;
        for nlri in &self.nlris {
            std::fmt::Display::fmt(nlri, f)?;
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::bgp_packet::constants::AddressFamilyIdentifier::Ipv6;
    use crate::bgp_packet::constants::SubsequentAddressFamilyIdentifier::Unicast;
    use crate::bgp_packet::traits::ParserContext;
    use crate::bgp_packet::traits::ReadablePacket;
    use crate::bgp_packet::traits::WritablePacket;

    use super::ASPathAttribute;
    use super::CommunitiesPathAttribute;
    use super::LargeCommunitiesPathAttribute;
    use super::LocalPrefPathAttribute;
    use super::MPReachNLRIPathAttribute;
    use super::MPUnreachNLRIPathAttribute;
    use super::MultiExitDiscPathAttribute;
    use super::NextHopPathAttribute;
    use super::PathAttribute;

    #[test]
    fn test_as_path_segment() {
        let as_path_bytes = &[
            0x02, 0x04, 0x00, 0x00, 0x9a, 0x74, 0x00, 0x00, 0xdf, 0x1e, 0x00, 0x00, 0x20, 0x1a,
            0x00, 0x00, 0x78, 0xfc,
        ];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let result = &ASPathAttribute::from_wire(ctx, as_path_bytes).unwrap();

        let expected_aspath: Vec<u32> = vec![39540, 57118, 8218, 30972];

        assert_eq!(result.1.segments.len(), 1);
        assert!(result.1.segments[0].ordered);
        assert_eq!(result.1.segments[0].path, expected_aspath);

        let wire = result.1.to_wire(ctx).unwrap();
        assert_eq!(wire, as_path_bytes);
    }

    #[test]
    fn test_as_path_multi_segment() {
        let as_path_bytes = &[
            0x02, 0x04, 0x00, 0x00, 0x9a, 0x74, 0x00, 0x00, 0xdf, 0x1e, 0x00, 0x00, 0x20, 0x1a,
            0x00, 0x00, 0x78, 0xfc, 0x01, 0x02, 0x00, 0x00, 0x9a, 0x74, 0x00, 0x00, 0xdf, 0x1e,
        ];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let result = &ASPathAttribute::from_wire(ctx, as_path_bytes).unwrap();

        let expected_aspath: Vec<u32> = vec![39540, 57118, 8218, 30972];
        let expected_asset: Vec<u32> = vec![39540, 57118];

        assert_eq!(result.1.segments.len(), 2);
        assert!(result.1.segments[0].ordered);
        assert_eq!(result.1.segments[0].path, expected_aspath);
        assert!(!result.1.segments[1].ordered);
        assert_eq!(result.1.segments[1].path, expected_asset);

        let wire = result.1.to_wire(ctx).unwrap();
        assert_eq!(wire, as_path_bytes);
    }

    #[test]
    fn test_next_hop_path_attribute() {
        let nh_bytes: &[u8] = &[192, 168, 1, 1];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let result = NextHopPathAttribute::from_wire(ctx, nh_bytes).unwrap();

        assert_eq!(result.1 .0, "192.168.1.1".parse::<Ipv4Addr>().unwrap());
        let wire = result.1.to_wire(ctx).unwrap();
        assert_eq!(wire, nh_bytes);
        assert_eq!(result.1.wire_len(ctx).unwrap(), wire.len() as u16);
    }

    #[test]
    fn test_multi_exit_discriminator_path_attribute() {
        let med_bytes: &[u8] = &[0xca, 0x00, 0x00, 0xbe];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let result = MultiExitDiscPathAttribute::from_wire(ctx, med_bytes).unwrap();

        assert_eq!(result.1 .0, 3388997822);
        let wire = result.1.to_wire(ctx).unwrap();
        assert_eq!(wire, med_bytes);
        assert_eq!(result.1.wire_len(ctx).unwrap(), wire.len() as u16);
    }

    #[test]
    fn test_local_pref_path_attribute() {
        let local_pref_bytes: &[u8] = &[0xca, 0x00, 0x00, 0xbe];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let result = LocalPrefPathAttribute::from_wire(ctx, local_pref_bytes).unwrap();

        assert_eq!(result.1 .0, 3388997822);
        let wire = result.1.to_wire(ctx).unwrap();
        assert_eq!(wire, local_pref_bytes);
        assert_eq!(result.1.wire_len(ctx).unwrap(), wire.len() as u16);
    }

    #[test]
    fn test_communities_path_attribute() {
        let communities_bytes: &[u8] = &[
            0x00, 0x00, 0x32, 0xbd, 0x00, 0x00, 0x41, 0x5f, 0x32, 0xe6, 0x00, 0x01, 0x32, 0xe6,
            0x10, 0x73, 0x32, 0xe6, 0xca, 0xbd, 0x57, 0x54, 0x0b, 0xb8, 0x57, 0x54, 0x0b, 0xb9,
            0x57, 0x54, 0x2b, 0x5c, 0x57, 0x54, 0xff, 0xe6, 0x57, 0x54, 0xff, 0xf1, 0x6f, 0xf7,
            0xff, 0xf1, 0x73, 0xfb, 0x0f, 0xa0, 0x73, 0xfb, 0x0f, 0xc8, 0x9a, 0x74, 0x0f, 0xa0,
            0x9a, 0x74, 0x0f, 0xb4, 0xdf, 0x1e, 0x07, 0xd0, 0xdf, 0x1e, 0x07, 0xe4,
        ];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let result = CommunitiesPathAttribute::from_wire(ctx, communities_bytes).unwrap();
        let expected_communities: Vec<(u16, u16)> = vec![
            (0, 0x32bd),
            (0, 0x415f),
            (13030, 1),
            (13030, 4211),
            (13030, 51901),
            (22356, 3000),
            (22356, 3001),
            (22356, 11100),
            (22356, 65510),
            (22356, 65521),
            (28663, 65521),
            (29691, 4000),
            (29691, 4040),
            (39540, 4000),
            (39540, 4020),
            (57118, 2000),
            (57118, 2020),
        ];
        assert_eq!(result.1.values.len(), expected_communities.len());
        for (i, community) in result.1.values.iter().enumerate() {
            assert_eq!(community.asn, expected_communities[i].0);
            assert_eq!(community.payload, expected_communities[i].1);
        }
        let wire: Vec<u8> = result.1.to_wire(ctx).unwrap();
        assert_eq!(wire, communities_bytes);
        assert_eq!(wire.len() as u16, result.1.wire_len(ctx).unwrap());
    }

    #[test]
    fn test_large_communities_path_attribute() {
        let large_community_bytes: &[u8] = &[
            0x00, 0x00, 0xdf, 0x1e, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xdf, 0x1e, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x14,
        ];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let result = LargeCommunitiesPathAttribute::from_wire(ctx, large_community_bytes).unwrap();
        assert_eq!(result.1.values.len(), 2);
        assert_eq!(result.1.values[0].global_admin, 57118);
        assert_eq!(result.1.values[0].ld1, 20);
        assert_eq!(result.1.values[0].ld2, 0);
        assert_eq!(result.1.values[1].global_admin, 57118);
        assert_eq!(result.1.values[1].ld1, 20);
        assert_eq!(result.1.values[1].ld2, 20);

        let wire: Vec<u8> = result.1.to_wire(ctx).unwrap();
        assert_eq!(wire, large_community_bytes);
        assert_eq!(wire.len() as u16, result.1.wire_len(ctx).unwrap());
    }

    #[test]
    fn test_mp_reach_nlri_path_attribute() {
        let mp_reach_bytes: &[u8] = &[
            0x00, 0x02, // IPv6
            0x01, // Unicast
            0x10, // Length of IPv6 nexthop
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // nh addr part one
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, // nh addr part two
            0x00, // Reserved
            0x20, 0x20, 0x01, 0x0d, 0xb8, // NLRI 1
            0x10, 0xfe, 0x80, // NLRI 2
        ];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let result: (&[u8], MPReachNLRIPathAttribute) =
            MPReachNLRIPathAttribute::from_wire(ctx, mp_reach_bytes).unwrap();
        assert_eq!(result.1.afi, Ipv6);
        assert_eq!(result.1.safi, Unicast);
        assert_eq!(
            result.1.nexthop,
            vec![
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // nh addr part one
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, // nh addr part two
            ]
        );
        assert_eq!(result.1.nlris.len(), 2);
        assert_eq!(format!("{}", result.1.nlris[0]), "2001:db8::/32");
        assert_eq!(format!("{}", result.1.nlris[1]), "fe80::/16");
        assert_eq!(result.0.len(), 0);

        let wire: Vec<u8> = result.1.to_wire(ctx).unwrap();
        assert_eq!(wire.as_slice(), mp_reach_bytes);
        assert_eq!(result.1.wire_len(ctx).unwrap() as usize, wire.len());
    }

    #[test]
    fn test_mp_unreach_nlri_path_attribute() {
        let mp_unreach_bytes: &[u8] = &[
            0x00, 0x02, // IPv6
            0x01, // Unicast
            0x20, 0x20, 0x01, 0x0d, 0xb8, // NLRI 1
            0x10, 0xfe, 0x80, // NLRI 2
        ];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let result: (&[u8], MPUnreachNLRIPathAttribute) =
            MPUnreachNLRIPathAttribute::from_wire(ctx, mp_unreach_bytes).unwrap();
        assert_eq!(result.1.afi, Ipv6);
        assert_eq!(result.1.safi, Unicast);
        assert_eq!(result.1.nlris.len(), 2);
        assert_eq!(format!("{}", result.1.nlris[0]), "2001:db8::/32");
        assert_eq!(format!("{}", result.1.nlris[1]), "fe80::/16");
        assert_eq!(result.0.len(), 0);

        let wire: Vec<u8> = result.1.to_wire(ctx).unwrap();
        assert_eq!(wire.as_slice(), mp_unreach_bytes);
        assert_eq!(result.1.wire_len(ctx).unwrap() as usize, wire.len());
    }

    // Tests the high level dispatching of the path attribute parser
    #[test]
    fn test_path_attribute_parsing<'a>() {
        let path_attr_bytes: &[u8] = &[
            0x40, 0x01, 0x01, 0x00, 0x50, 0x02, 0x00, 0x1a, 0x02, 0x06, 0x00, 0x00, 0x9a, 0x74,
            0x00, 0x00, 0x62, 0x03, 0x00, 0x00, 0x0b, 0x62, 0x00, 0x00, 0x19, 0x35, 0x00, 0x00,
            0x20, 0x9a, 0x00, 0x00, 0x34, 0x17, 0x40, 0x03, 0x04, 0xb9, 0x5f, 0xdb, 0x24, 0xc0,
            0x08, 0x2c, 0x0b, 0x62, 0x01, 0xa4, 0x0b, 0x62, 0x04, 0xbf, 0x0b, 0x62, 0x08, 0xa6,
            0x0b, 0x62, 0x0c, 0x80, 0x19, 0x35, 0x07, 0xd0, 0x19, 0x35, 0x09, 0xc4, 0x19, 0x35,
            0x09, 0xcf, 0x62, 0x03, 0x0b, 0x62, 0x62, 0x03, 0x2f, 0x69, 0x9a, 0x74, 0x0f, 0xa0,
            0x9a, 0x74, 0x0f, 0xbe,
        ];

        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv6);
        let (buf, res): (_, Vec<PathAttribute>) =
            nom::multi::many0(|buf: &'a [u8]| PathAttribute::from_wire(ctx, buf))(path_attr_bytes)
                .unwrap();
        assert_eq!(buf.len(), 0);
        let expected_str = "[OriginPathAttribute(OriginPathAttribute(0)), \
                            ASPathAttribute(ASPathAttribute { segments: \
                                [ASPathSegment { ordered: true, path: [39540, 25091, 2914, 6453, 8346, 13335] }] }), \
                            NextHopPathAttribute(NextHopPathAttribute(185.95.219.36)), \
                            CommunitiesPathAttribute(CommunitiesPathAttribute { values: \
                                [CommunitiesPayload { asn: 2914, payload: 420 }, \
                                CommunitiesPayload { asn: 2914, payload: 1215 }, \
                                CommunitiesPayload { asn: 2914, payload: 2214 }, \
                                CommunitiesPayload { asn: 2914, payload: 3200 }, \
                                CommunitiesPayload { asn: 6453, payload: 2000 }, \
                                CommunitiesPayload { asn: 6453, payload: 2500 }, \
                                CommunitiesPayload { asn: 6453, payload: 2511 }, \
                                CommunitiesPayload { asn: 25091, payload: 2914 }, \
                                CommunitiesPayload { asn: 25091, payload: 12137 }, \
                                CommunitiesPayload { asn: 39540, payload: 4000 }, \
                                CommunitiesPayload { asn: 39540, payload: 4030 }] })]";
        assert_eq!(format!("{:?}", res), expected_str);
    }
}

use std::net::{Ipv4Addr, Ipv6Addr};

use bitfield::bitfield;
use bytes::BufMut;
use bytes::BytesMut;
use eyre::Context;
use eyre::Result;
use eyre::bail;
use eyre::eyre;
use nom::Err::Failure;
use nom::IResult;
use nom::Parser;
use nom::number::complete::be_u8;
use nom::number::complete::be_u16;
use nom::number::complete::be_u32;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use strum::EnumDiscriminants;

use crate::constants::AddressFamilyId;
use crate::constants::SubsequentAfi;
use crate::ip_prefix::IpPrefix;
use crate::notification::NotificationMessage;
use crate::parser::BgpParserError;
use crate::parser::ParserContext;

/// A sentinel AS number used to denote that the actual AS number is provided as
/// a 4 byte value in the capabilities instead.
pub const AS_TRANS: u16 = 23456;

/// Version number used in the BGP4 protocol.
pub const BGP4_VERSION: u8 = 4;

/// Message represents the top-level messages in the BGP protocol.
#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    Open(OpenMessage),
    Update(UpdateMessage),
    Notification(NotificationMessage),
    KeepAlive,
    // RouteRefresh(RouteRefreshMessage),
}

impl Message {}

#[derive(Debug, Serialize, Deserialize)]
pub enum MessageType {
    /// BGP Open message (RFC 4271).
    Open = 1,
    /// BGP Update message (RFC 4271).
    Update = 2,
    /// BGP Notification message (RFC 4275).
    Notification = 3,
    /// BGP KeepAlive message (RFC 4271).
    KeepAlive = 4,
    /// BGP Route Refresh message (RFC 2918).
    RouteRefresh = 5,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenMessage {
    /// Version of the BGP protocol in use.
    pub version: u8,
    /// AS Number of the BGP speaker, or AS_TRANS if using 4 byte ASN.
    pub asn: u16,
    /// Hold time parameter in seconds.
    pub hold_time: u16,
    /// Global identifier of the BGP speaker.
    pub identifier: Ipv4Addr,
    /// Options.
    pub options: Vec<OpenOption>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OpenOption {
    Capabilities(Vec<Capability>),
    /// BGP extended open options length (RFC 9072).
    ExtendedLength(u32),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Capability {
    /// MultiProtocol Extension (RFC 2858).
    MultiProtocol { afi: u16, safi: u8 },
    /// Route Refresh capability (RFC 2918).
    RouteRefresh {},
    /// Outbound Route Filtering (RFC 5291).
    /// https://datatracker.ietf.org/doc/html/rfc5291
    OutboundRouteFilter {},
    /// Extended Next Hop encoding (RFC 8950).
    ExtendedNextHop {},
    /// Extended Message (RFC 8654).
    ExtendedMessage {},
    /// BGPSec (RFC 8205).
    BgpSec {},
    /// Multiple labels compatibility (RFC 8277).
    MultiLabelCompat {},
    /// Graceful restart capability (RFC 4724).
    GracefulRestart {},
    /// Four Byte ASN (RFC 4274).
    FourByteAsn { asn: u32 },
    /// Additional Path (RFC 7911).
    AddPath {},
    /// Enhanced Route Refresh (RFC 7313).
    EnhancedRouteRefresh {},
}

/// Represents a BGP Update message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateMessage {
    pub withdrawn: Vec<IpPrefix>,
    pub path_attributes: Vec<PathAttribute>,
    pub announced: Vec<IpPrefix>,
}

impl UpdateMessage {
    pub fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        /*
        +-----------------------------------------------------+
        |   Withdrawn Routes Length (2 octets)                |
        +-----------------------------------------------------+
        |   Withdrawn Routes (variable)                       |
        +-----------------------------------------------------+
        |   Total Path Attribute Length (2 octets)            |
        +-----------------------------------------------------+
        |   Path Attributes (variable)                        |
        +-----------------------------------------------------+
        |   Network Layer Reachability Information (variable) |
        +-----------------------------------------------------+
        */

        let (buf, withdraw_len) = be_u16.parse(buf)?;
        let (buf, withdrawn) =
            nom::bytes::take(withdraw_len)
                .parse(buf)
                .and_then(|(buf, withdrawn_bytes)| {
                    Ok((
                        buf,
                        nom::multi::many0(|buf| IpPrefix::from_wire(ctx, buf))
                            .parse(withdrawn_bytes)?
                            .1,
                    ))
                })?;

        let (buf, path_attr_len) = be_u16.parse(buf)?;

        let (buf, path_attributes) =
            nom::bytes::take(path_attr_len)
                .parse(buf)
                .and_then(|(buf, path_attr_bytes)| {
                    Ok((
                        buf,
                        nom::multi::many0(|buf| PathAttribute::from_wire(ctx, buf))
                            .parse(path_attr_bytes)?
                            .1,
                    ))
                })?;

        let (buf, announced) = nom::multi::many0(|buf| IpPrefix::from_wire(ctx, buf)).parse(buf)?;

        Ok((
            buf,
            Self {
                withdrawn,
                path_attributes,
                announced,
            },
        ))
    }

    pub fn wire_len(&self, ctx: &ParserContext) -> Result<u16> {
        Ok(2 + self
            .withdrawn
            .iter()
            .flat_map(|w| w.wire_len(ctx))
            .sum::<u16>()
            + 2
            + self
                .path_attributes
                .iter()
                .flat_map(|pa| pa.wire_len(ctx))
                .sum::<u16>()
            + self
                .announced
                .iter()
                .flat_map(|p| p.wire_len(ctx))
                .sum::<u16>())
    }
}

bitfield! {
    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct PathAttributeFlags(u8);
    u8;
    optional, set_optional: 0;
    transitive, set_transitive: 1;
    partial, set_partial: 2;
    extended_length, set_extended_length: 3;
}

#[repr(u8)]
#[derive(Debug, Clone, EnumDiscriminants, Serialize, Deserialize)]
#[strum_discriminants(name(PathAttributeTag))]
pub enum PathAttribute {
    Origin(OriginPathAttribute) = 1,
    ASPath(AsPathAttribute) = 2,
    NextHop(NextHopPathAttribute) = 3,
    MultiExitDisc(MultiExitDiscPathAttribute) = 4,
    LocalPref(LocalPrefPathAttribute) = 5,
    AtomicAggregate(AtomicAggregatePathAttribute) = 6,
    Aggregator(AggregatorPathAttribute) = 7,
    Communitites(CommunitiesPathAttribute) = 8,
    MpReachNlri(MpReachNlriPathAttribute) = 14,
    MpUnreachNlri(MpUnreachNlriPathAttribute) = 15,
    ExtendedCommunities(ExtendedCommunitiesPathAttribute) = 16,
    LargeCommunities(LargeCommunitiesPathAttribute) = 32,
    UnknownPathAttribute {
        flags: PathAttributeFlags,
        type_code: u8,
        payload: Vec<u8>,
    },
}

impl PathAttribute {
    /// The from_wire parser for `PathAttribute` consumes type and length which it uses to
    /// determine how many bytes to take and pass down to the corresponding sub-parser.
    pub fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let (buf, attr_flags) = be_u8(buf).map(|(buf, b)| (buf, PathAttributeFlags(b)))?;
        let (buf, type_code) = be_u8(buf)?;

        // Read the length based on the flag that tells us if the length is u16 or u8.
        let (buf, length): (_, u16) = if attr_flags.extended_length() {
            be_u16(buf)?
        } else {
            be_u8(buf).map(|(buf, b)| (buf, b as u16))?
        };

        let path_attr_parser =
            |ctx: &ParserContext,
             buf: &'a [u8],
             attr_flags: &PathAttributeFlags,
             type_code: &u8|
             -> IResult<&'a [u8], PathAttribute, BgpParserError<&'a [u8]>> {
                match *type_code {
                    t if (t == PathAttributeTag::Origin as u8) => {
                        OriginPathAttribute::from_wire(ctx, buf)
                            .map(|(buf, attr)| (buf, PathAttribute::Origin(attr)))
                    }
                    t if (t == PathAttributeTag::ASPath as u8) => {
                        AsPathAttribute::from_wire(ctx, buf)
                            .map(|(buf, attr)| (buf, PathAttribute::ASPath(attr)))
                    }
                    t if (t == PathAttributeTag::NextHop as u8) => {
                        NextHopPathAttribute::from_wire(ctx, buf)
                            .map(|(buf, attr)| (buf, PathAttribute::NextHop(attr)))
                    }
                    t if (t == PathAttributeTag::MultiExitDisc as u8) => {
                        MultiExitDiscPathAttribute::from_wire(ctx, buf)
                            .map(|(buf, attr)| (buf, PathAttribute::MultiExitDisc(attr)))
                    }
                    t if (t == PathAttributeTag::LocalPref as u8) => {
                        LocalPrefPathAttribute::from_wire(ctx, buf)
                            .map(|(buf, attr)| (buf, PathAttribute::LocalPref(attr)))
                    }
                    t if (t == PathAttributeTag::AtomicAggregate as u8) => {
                        AtomicAggregatePathAttribute::from_wire(ctx, buf)
                            .map(|(buf, attr)| (buf, PathAttribute::AtomicAggregate(attr)))
                    }
                    t if (t == PathAttributeTag::Aggregator as u8) => {
                        AggregatorPathAttribute::from_wire(ctx, buf)
                            .map(|(buf, attr)| (buf, PathAttribute::Aggregator(attr)))
                    }
                    t if (t == PathAttributeTag::Communitites as u8) => {
                        CommunitiesPathAttribute::from_wire(ctx, buf)
                            .map(|(buf, attr)| (buf, PathAttribute::Communitites(attr)))
                    }
                    t if (t == PathAttributeTag::MpReachNlri as u8) => {
                        MpReachNlriPathAttribute::from_wire(ctx, buf)
                            .map(|(buf, attr)| (buf, PathAttribute::MpReachNlri(attr)))
                    }
                    t if (t == PathAttributeTag::MpUnreachNlri as u8) => {
                        MpUnreachNlriPathAttribute::from_wire(ctx, buf)
                            .map(|(buf, attr)| (buf, PathAttribute::MpUnreachNlri(attr)))
                    }
                    t if (t == PathAttributeTag::ExtendedCommunities as u8) => {
                        ExtendedCommunitiesPathAttribute::from_wire(ctx, buf)
                            .map(|(buf, attr)| (buf, PathAttribute::ExtendedCommunities(attr)))
                    }
                    t if (t == PathAttributeTag::LargeCommunities as u8) => {
                        LargeCommunitiesPathAttribute::from_wire(ctx, buf)
                            .map(|(buf, attr)| (buf, PathAttribute::LargeCommunities(attr)))
                    }
                    other => Ok((
                        &buf[..0],
                        PathAttribute::UnknownPathAttribute {
                            flags: attr_flags.clone(),
                            type_code: other,
                            payload: buf.to_vec(),
                        },
                    )),
                }
            };

        let (buf, path_attr) = nom::bytes::take(length)
            .and_then(|buf| path_attr_parser(ctx, buf, &attr_flags, &type_code))
            .parse(buf)?;

        Ok((buf, path_attr))
    }

    pub fn to_wire(&self, ctx: &ParserContext, out: &mut BytesMut) -> Result<()> {
        // We need to know how long the inner payload is going to be to determine if
        // we need extended length or not. We also use this opportunity to set the flags.
        let mut flags = PathAttributeFlags::default();

        let (type_code, inner_len) = match self {
            PathAttribute::Origin(origin_path_attribute) => {
                flags.set_transitive(true);
                (
                    PathAttributeTag::Origin,
                    origin_path_attribute.wire_len(ctx)?,
                )
            }
            PathAttribute::ASPath(as_path_attribute) => {
                flags.set_transitive(true);
                (PathAttributeTag::ASPath, as_path_attribute.wire_len(ctx)?)
            }
            PathAttribute::NextHop(next_hop_path_attribute) => {
                flags.set_transitive(true);
                (
                    PathAttributeTag::NextHop,
                    next_hop_path_attribute.wire_len(ctx)?,
                )
            }
            PathAttribute::MultiExitDisc(multi_exit_disc_path_attribute) => {
                flags.set_optional(true);
                (
                    PathAttributeTag::MultiExitDisc,
                    multi_exit_disc_path_attribute.wire_len(ctx)?,
                )
            }
            PathAttribute::LocalPref(local_pref_path_attribute) => {
                flags.set_optional(true);
                (
                    PathAttributeTag::LocalPref,
                    local_pref_path_attribute.wire_len(ctx)?,
                )
            }
            PathAttribute::AtomicAggregate(atomic_aggregate_path_attribute) => {
                flags.set_optional(true);
                (
                    PathAttributeTag::AtomicAggregate,
                    atomic_aggregate_path_attribute.wire_len(ctx)?,
                )
            }
            PathAttribute::Aggregator(aggregator_path_attribute) => {
                flags.set_optional(true);
                flags.set_transitive(true);
                (
                    PathAttributeTag::Aggregator,
                    aggregator_path_attribute.wire_len(ctx)?,
                )
            }
            PathAttribute::Communitites(communities_path_attribute) => {
                flags.set_optional(true);
                flags.set_transitive(true);
                (
                    PathAttributeTag::Communitites,
                    communities_path_attribute.wire_len(ctx)?,
                )
            }
            PathAttribute::MpReachNlri(mp_reach_nlri_path_attribute) => {
                flags.set_optional(true);
                (
                    PathAttributeTag::MpReachNlri,
                    mp_reach_nlri_path_attribute.wire_len(ctx)?,
                )
            }
            PathAttribute::MpUnreachNlri(mp_unreach_nlri_path_attribute) => {
                flags.set_optional(true);
                (
                    PathAttributeTag::MpUnreachNlri,
                    mp_unreach_nlri_path_attribute.wire_len(ctx)?,
                )
            }
            PathAttribute::ExtendedCommunities(extended_communities_path_attribute) => {
                flags.set_optional(true);
                flags.set_transitive(true);
                (
                    PathAttributeTag::ExtendedCommunities,
                    extended_communities_path_attribute.wire_len(ctx)?,
                )
            }
            PathAttribute::LargeCommunities(large_communities_path_attribute) => {
                flags.set_optional(true);
                flags.set_transitive(true);
                (
                    PathAttributeTag::LargeCommunities,
                    large_communities_path_attribute.wire_len(ctx)?,
                )
            }
            PathAttribute::UnknownPathAttribute {
                flags,
                type_code,
                payload,
            } => todo!(),
        };

        // If the length is more than 1 byte then we must set the extended length flag.
        if (inner_len + 2) > 255 {
            flags.set_extended_length(true);
        }

        // We can now write the flags, type, length.
        out.put_u8(flags.0);
        out.put_u8(type_code as u8);

        if flags.extended_length() {
            out.put_u16(inner_len);
        } else {
            out.put_u8(inner_len as u8);
        }

        // Now that the header is written we can delegate to writing the body of the Path Attribute.
        match self {
            PathAttribute::Origin(origin_path_attribute) => origin_path_attribute.to_wire(ctx, out),
            PathAttribute::ASPath(as_path_attribute) => as_path_attribute.to_wire(ctx, out),
            PathAttribute::NextHop(next_hop_path_attribute) => {
                next_hop_path_attribute.to_wire(ctx, out)
            }
            PathAttribute::MultiExitDisc(multi_exit_disc_path_attribute) => {
                multi_exit_disc_path_attribute.to_wire(ctx, out)
            }
            PathAttribute::LocalPref(local_pref_path_attribute) => {
                local_pref_path_attribute.to_wire(ctx, out)
            }
            PathAttribute::AtomicAggregate(atomic_aggregate_path_attribute) => {
                atomic_aggregate_path_attribute.to_wire(ctx, out)
            }
            PathAttribute::Aggregator(aggregator_path_attribute) => {
                aggregator_path_attribute.to_wire(ctx, out)
            }
            PathAttribute::Communitites(communities_path_attribute) => {
                communities_path_attribute.to_wire(ctx, out)
            }
            PathAttribute::MpReachNlri(mp_reach_nlri_path_attribute) => {
                mp_reach_nlri_path_attribute.to_wire(ctx, out)
            }
            PathAttribute::MpUnreachNlri(mp_unreach_nlri_path_attribute) => {
                mp_unreach_nlri_path_attribute.to_wire(ctx, out)
            }
            PathAttribute::ExtendedCommunities(extended_communities_path_attribute) => {
                extended_communities_path_attribute.to_wire(ctx, out)
            }
            PathAttribute::LargeCommunities(large_communities_path_attribute) => {
                large_communities_path_attribute.to_wire(ctx, out)
            }
            PathAttribute::UnknownPathAttribute {
                flags,
                type_code,
                payload,
            } => todo!(),
        }?;

        Ok(())
    }

    pub fn wire_len(&self, ctx: &ParserContext) -> Result<u16> {
        todo!()
    }
}

/// Origin path attribute is a mandatory attribute defined in RFC4271.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum OriginPathAttribute {
    IGP = 0,
    EGP = 1,
    INCOMPLETE = 2,
}

impl TryFrom<u8> for OriginPathAttribute {
    type Error = eyre::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::IGP),
            1 => Ok(Self::EGP),
            2 => Ok(Self::INCOMPLETE),
            other => bail!("Unexpected origin code {}", other),
        }
    }
}

impl OriginPathAttribute {
    pub fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let (buf, value) = be_u8.parse(buf)?;
        Ok((
            buf,
            OriginPathAttribute::try_from(value)
                .map_err(|e| nom::Err::Failure(BgpParserError::Eyre(e)))?,
        ))
    }

    pub fn to_wire(&self, _: &ParserContext, out: &mut BytesMut) -> Result<()> {
        out.put_u8(*self as u8);
        Ok(())
    }

    pub fn wire_len(&self, _: &ParserContext) -> Result<u16> {
        Ok(1)
    }
}

/// ASPathAttribute is a well-known mandatory attribute that contains a list of TLV encoded path
/// segments. Type is either 1 for AS_SET or 2 for AS_SEQUENCE, length is a 1 octet field
/// containing the number of ASNS and the value contains the ASNs. This is defined in Section 4.3
/// of RFC4271.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct AsPathAttribute {
    pub segments: Vec<AsPathSegment>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct AsPathSegment {
    /// ordered is true when representing an AS_SEQUENCE, andd false when
    /// representing an AS_SET.
    pub ordered: bool,
    /// Path is the list of ASNs.
    pub path: Vec<u32>,
}

impl AsPathAttribute {
    pub fn from_asns(asns: Vec<u32>) -> PathAttribute {
        let segment = AsPathSegment {
            ordered: true,
            path: asns,
        };
        PathAttribute::ASPath(AsPathAttribute {
            segments: vec![segment],
        })
    }

    pub fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let parse_segment = |ctx: &ParserContext,
                             buf: &'a [u8]|
         -> IResult<&'a [u8], AsPathSegment, BgpParserError<&'a [u8]>> {
            let (buf, typ) = be_u8(buf)?;
            let (buf, len) = be_u8(buf)?;
            let (buf, asns): (_, Vec<u32>) = match ctx.four_octet_asn {
                Some(true) => {
                    nom::multi::many_m_n(len as usize, len as usize, be_u32).parse(buf)?
                }
                Some(false) => nom::multi::many_m_n(len as usize, len as usize, be_u16)
                    .parse(buf)
                    .map(|(buf, asns)| (buf, asns.iter().map(|asn| *asn as u32).collect()))?,
                None => {
                    return Err(nom::Err::Failure(BgpParserError::CustomText(
                        "Context must set four_octet_asn before being used",
                    )));
                }
            };

            Ok((
                buf,
                AsPathSegment {
                    ordered: typ == 2,
                    path: asns,
                },
            ))
        };

        let (buf, segments) =
            nom::multi::many0(|buf: &'a [u8]| parse_segment(ctx, buf)).parse(buf)?;

        Ok((buf, Self { segments }))
    }

    pub fn to_wire(&self, ctx: &ParserContext, out: &mut BytesMut) -> Result<()> {
        if ctx.four_octet_asn.is_none_or(|val| !val) {
            bail!("AsPathAttribute can only be sent for four_octet_asn enabled peers");
        }

        for segment in &self.segments {
            // Segment type.
            out.put_u8(if segment.ordered { 2 } else { 1 });
            // Segment AS length.
            out.put_u16(
                segment
                    .path
                    .len()
                    .try_into()
                    .wrap_err("AS Path length too long")?,
            );
            // AS numbers.
            for asn in &segment.path {
                out.put_u32(*asn);
            }
        }

        Ok(())
    }

    pub fn wire_len(&self, ctx: &ParserContext) -> Result<u16> {
        let mut counter = 0;
        for segment in &self.segments {
            counter += match ctx.four_octet_asn {
                Some(true) => 2 + (4 * segment.path.len()),
                Some(false) => 2 + (2 * segment.path.len()),
                None => bail!("ParserContext needs four_octet_asn set"),
            };
            counter += 2 + (4 * segment.path.len());
        }
        Ok(counter as u16)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct NextHopPathAttribute(pub Ipv4Addr);

impl NextHopPathAttribute {
    pub fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let (buf, ip_u32) = be_u32(buf)?;
        Ok((buf, Self(Ipv4Addr::from(ip_u32))))
    }

    pub fn to_wire(&self, _: &ParserContext, out: &mut BytesMut) -> Result<()> {
        out.put_u32(self.0.into());
        Ok(())
    }

    pub fn wire_len(&self, _: &ParserContext) -> Result<u16> {
        Ok(4)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct MultiExitDiscPathAttribute(pub u32);

impl MultiExitDiscPathAttribute {
    pub fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let (buf, val) = be_u32(buf)?;
        Ok((buf, Self(val)))
    }

    pub fn to_wire(&self, _: &ParserContext, out: &mut BytesMut) -> Result<()> {
        out.put_u32(self.0);
        Ok(())
    }

    pub fn wire_len(&self, _: &ParserContext) -> Result<u16> {
        Ok(4)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct LocalPrefPathAttribute(pub u32);

impl LocalPrefPathAttribute {
    pub fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let (buf, val) = be_u32(buf)?;
        Ok((buf, Self(val)))
    }

    pub fn to_wire(&self, _: &ParserContext, out: &mut BytesMut) -> Result<()> {
        out.put_u32(self.0);
        Ok(())
    }

    pub fn wire_len(&self, _: &ParserContext) -> Result<u16> {
        Ok(4)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct AtomicAggregatePathAttribute {}

impl AtomicAggregatePathAttribute {
    pub fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        Ok((buf, Self {}))
    }

    pub fn to_wire(&self, _: &ParserContext, _: &mut BytesMut) -> Result<()> {
        Ok(())
    }

    pub fn wire_len(&self, _: &ParserContext) -> Result<u16> {
        Ok(0)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct AggregatorPathAttribute {
    pub asn: u32,
    pub ip: Ipv4Addr,
}

impl AggregatorPathAttribute {
    pub fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        if ctx.four_octet_asn.is_none_or(|val| !val) {
            return Err(nom::Err::Failure(BgpParserError::CustomText(
                "AggregatorPathAttribute can only be parsed for four_octet_asn enabled peers",
            )));
        }
        let (buf, asn) = be_u32(buf)?;
        let (buf, ip) = be_u32(buf)?;
        Ok((
            buf,
            Self {
                asn,
                ip: Ipv4Addr::from(ip),
            },
        ))
    }

    pub fn to_wire(&self, ctx: &ParserContext, out: &mut BytesMut) -> Result<()> {
        if ctx.four_octet_asn.is_none_or(|val| !val) {
            bail!("AggregatorPathAttribute can only be sent for four_octet_asn enabled peers");
        }
        out.put_u32(self.asn);
        out.put_u32(self.ip.into());
        Ok(())
    }

    pub fn wire_len(&self, _: &ParserContext) -> Result<u16> {
        Ok(8)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CommunitiesPathAttribute(Vec<(u16, u16)>);

impl CommunitiesPathAttribute {
    pub fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let (buf, values) = nom::multi::many0(|i| (be_u16, be_u16).parse(i)).parse(buf)?;
        Ok((buf, CommunitiesPathAttribute(values)))
    }

    pub fn to_wire(&self, _: &ParserContext, out: &mut BytesMut) -> Result<()> {
        for value in &self.0 {
            out.put_u16(value.0);
            out.put_u16(value.1);
        }
        Ok(())
    }

    pub fn wire_len(&self, _: &ParserContext) -> Result<u16> {
        Ok((self.0.len() * 4) as u16)
    }
}

/// Extended Communities as defined in https://www.rfc-editor.org/rfc/rfc4360.html.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct ExtendedCommunitiesPathAttribute {
    pub extended_communities: Vec<ExtendedCommunity>,
}

impl ExtendedCommunitiesPathAttribute {
    pub fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let (buf, extended_communities) =
            nom::multi::many1(|buf| ExtendedCommunity::from_wire(ctx, buf)).parse(buf)?;
        Ok((
            buf,
            Self {
                extended_communities,
            },
        ))
    }

    pub fn to_wire(&self, ctx: &ParserContext, out: &mut BytesMut) -> Result<()> {
        self.extended_communities
            .iter()
            .map(|c| c.to_wire(ctx, out))
            .collect::<Result<Vec<_>>>()?;
        Ok(())
    }

    pub fn wire_len(&self, ctx: &ParserContext) -> Result<u16> {
        Ok(self
            .extended_communities
            .iter()
            .map(|c| c.wire_len(ctx))
            .collect::<Result<Vec<_>>>()?
            .iter()
            .sum::<u16>())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum ExtendedCommunity {
    /// AS Specific Extended Community as specified in Section 3.1 of RFC4360.
    AsSpecific {
        typ: u8,
        sub_typ: u8,
        global_admin: u16,
        local_admin: u32,
    },
    /// Ipv4 Address Specific Extended Community as specified in Section 3.2 of RFC4360.
    Ipv4AddrSpecific {
        typ: u8,
        sub_typ: u8,
        global_admin: u32,
        local_admin: u16,
    },
    /// Opaque Extended Community as specified in Section 3.3 of RFC4360.
    Opaque {
        typ: u8,
        sub_typ: u8,
        value: [u8; 5],
    },
    /// Route Target Community as specified in Section 4 of RFC4360.
    RouteTarget {
        typ: u8,
        sub_typ: u8,
        global_admin: u32,
        local_admin: u16,
    },
    /// Route Origin Community as specified in Section 5 of RFC4360.
    RouteOrigin {
        typ: u8,
        sub_typ: u8,
        global_admin: u16,
        local_admin: u32,
    },
}

impl ExtendedCommunity {
    pub fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let (buf, typ) = be_u8(buf)?;
        let (buf, sub_typ) = be_u8(buf)?;
        let (buf, parsed) = match (typ, sub_typ) {
            // Route Target Extended Community.
            (0x00 | 0x01 | 0x02, 0x02) => {
                let (buf, global_admin) = be_u32(buf)?;
                let (buf, local_admin) = be_u16(buf)?;
                (
                    buf,
                    Self::RouteTarget {
                        typ,
                        sub_typ,
                        global_admin,
                        local_admin,
                    },
                )
            }
            // Route Origin Extended Community.
            (0x00 | 0x01 | 0x02, 0x03) => {
                let (buf, global_admin) = be_u16(buf)?;
                let (buf, local_admin) = be_u32(buf)?;
                (
                    buf,
                    Self::RouteOrigin {
                        typ,
                        sub_typ,
                        global_admin,
                        local_admin,
                    },
                )
            }
            // AS specific Extended Community.
            (0x00 | 0x40, _) => {
                let (buf, global_admin) = be_u16(buf)?;
                let (buf, local_admin) = be_u32(buf)?;
                (
                    buf,
                    Self::AsSpecific {
                        typ,
                        sub_typ,
                        global_admin,
                        local_admin,
                    },
                )
            }
            // IPv4 Address Specific Extended Community.
            (0x01 | 0x41, _) => {
                let (buf, global_admin) = be_u32(buf)?;
                let (buf, local_admin) = be_u16(buf)?;
                (
                    buf,
                    Self::Ipv4AddrSpecific {
                        typ,
                        sub_typ,
                        global_admin,
                        local_admin,
                    },
                )
            }
            _ => {
                let (buf, payload) = nom::bytes::take(5_usize).parse(buf)?;
                let value: [u8; 5] = payload.try_into().map_err(|_| {
                    Failure(BgpParserError::CustomText(
                        "Expected exactly 5 bytes from the parser",
                    ))
                })?;
                (
                    buf,
                    Self::Opaque {
                        typ,
                        sub_typ,
                        value,
                    },
                )
            }
        };

        return Ok((buf, parsed));
    }

    pub fn to_wire(&self, _: &ParserContext, out: &mut BytesMut) -> Result<()> {
        match self {
            ExtendedCommunity::AsSpecific {
                typ,
                sub_typ,
                global_admin,
                local_admin,
            } => {
                out.put_u8(*typ);
                out.put_u8(*sub_typ);
                out.put_u16(*global_admin);
                out.put_u32(*local_admin);
            }
            ExtendedCommunity::Ipv4AddrSpecific {
                typ,
                sub_typ,
                global_admin,
                local_admin,
            } => {
                out.put_u8(*typ);
                out.put_u8(*sub_typ);
                out.put_u32(*global_admin);
                out.put_u16(*local_admin);
            }
            ExtendedCommunity::Opaque {
                typ,
                sub_typ,
                value,
            } => {
                out.put_u8(*typ);
                out.put_u8(*sub_typ);
                out.put(&value[..]);
            }
            ExtendedCommunity::RouteTarget {
                typ,
                sub_typ,
                global_admin,
                local_admin,
            } => {
                out.put_u8(*typ);
                out.put_u8(*sub_typ);
                out.put_u32(*global_admin);
                out.put_u16(*local_admin);
            }
            ExtendedCommunity::RouteOrigin {
                typ,
                sub_typ,
                global_admin,
                local_admin,
            } => {
                out.put_u8(*typ);
                out.put_u8(*sub_typ);
                out.put_u16(*global_admin);
                out.put_u32(*local_admin);
            }
        }
        Ok(())
    }

    pub fn wire_len(&self, _: &ParserContext) -> Result<u16> {
        Ok(8)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeCommunitiesPathAttribute {
    pub communities: Vec<LargeCommunity>,
}

impl LargeCommunitiesPathAttribute {
    pub fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let (buf, communities) =
            nom::multi::many1(|buf| LargeCommunity::from_wire(ctx, buf)).parse(buf)?;
        Ok((buf, Self { communities }))
    }

    pub fn to_wire(&self, ctx: &ParserContext, out: &mut BytesMut) -> Result<()> {
        for community in &self.communities {
            community.to_wire(ctx, out)?;
        }
        Ok(())
    }

    pub fn wire_len(&self, _: &ParserContext) -> Result<u16> {
        Ok(12_u16 * self.communities.len() as u16)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeCommunity {
    pub global_admin: u32,
    pub data_1: u32,
    pub data_2: u32,
}

impl LargeCommunity {
    pub fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let (buf, global_admin) = be_u32(buf)?;
        let (buf, data_1) = be_u32(buf)?;
        let (buf, data_2) = be_u32(buf)?;
        Ok((
            buf,
            Self {
                global_admin,
                data_1,
                data_2,
            },
        ))
    }

    pub fn to_wire(&self, _: &ParserContext, out: &mut BytesMut) -> Result<()> {
        out.put_u32(self.global_admin);
        out.put_u32(self.data_1);
        out.put_u32(self.data_2);
        Ok(())
    }

    pub fn wire_len(&self, _: &ParserContext) -> Result<u16> {
        Ok(12)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NlriNextHop {
    /// Represents an IPv4 address nexthop.
    Ipv4(Ipv4Addr),
    /// Represents a global IPv6 nexthop.
    Ipv6(Ipv6Addr),
    /// Represents a IPv6 Link Local and global address pair nexthop.
    Ipv6WithLl {
        global: Ipv6Addr,
        link_local: Ipv6Addr,
    },
}

impl NlriNextHop {
    // NlriNextHop doesn't have a from_wire since that's handled inline in the parent.

    pub fn to_wire(&self, _: &ParserContext, out: &mut BytesMut) -> Result<()> {
        match self {
            NlriNextHop::Ipv4(ipv4_addr) => out.put(&ipv4_addr.octets()[..]),
            NlriNextHop::Ipv6(ipv6_addr) => out.put(&ipv6_addr.octets()[..]),
            NlriNextHop::Ipv6WithLl { global, link_local } => {
                out.put(&global.octets()[..]);
                out.put(&link_local.octets()[..])
            }
        }

        Ok(())
    }

    pub fn wire_len(&self) -> u8 {
        match self {
            NlriNextHop::Ipv4(_) => 4,
            NlriNextHop::Ipv6(_) => 16,
            NlriNextHop::Ipv6WithLl { .. } => 32,
        }
    }
}

// parse_prefix is a helper function that implements an NLRI parser for the given AFI.
fn parse_prefix<'a>(
    afi: AddressFamilyId,
    buf: &'a [u8],
) -> IResult<&'a [u8], IpPrefix, BgpParserError<&'a [u8]>> {
    let (buf, prefix_len) = be_u8(buf)?;
    let byte_len = (prefix_len + 7) / 8;
    let (buf, prefix_bytes) = nom::bytes::take(byte_len as usize).parse(buf)?;
    let prefix = IpPrefix::new(afi, prefix_bytes.to_vec(), byte_len)
        .map_err(|e| Failure(BgpParserError::Eyre(e)))?;
    Ok((buf, prefix))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpReachNlriPathAttribute {
    pub afi: AddressFamilyId,
    pub safi: SubsequentAfi,
    /// Next hop address (either IPv4 or IPv6 for now).
    pub next_hop: NlriNextHop,
    pub prefixes: Vec<IpPrefix>,
}

impl MpReachNlriPathAttribute {
    pub fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let (buf, raw_afi) = be_u16(buf)?;
        let afi =
            AddressFamilyId::try_from(raw_afi).map_err(|e| Failure(BgpParserError::Eyre(e)))?;

        let (buf, raw_safi) = be_u8(buf)?;
        let safi =
            SubsequentAfi::try_from(raw_safi).map_err(|e| Failure(BgpParserError::Eyre(e)))?;

        let (buf, nh_len) = be_u8(buf)?;

        let (buf, next_hop, prefixes) = match afi {
            AddressFamilyId::Ipv4 => {
                // Read the length of the nexthop which should equal 4.
                if nh_len != 4 {
                    return Err(Failure(BgpParserError::Eyre(eyre!(
                        "Got nexthop address length {} when expected 4 for IPv4 AFI",
                        nh_len
                    ))));
                }
                // Read the nexthop address which should now be an IPv4 address.
                let (buf, nh_bytes) = be_u32(buf)?;
                let next_hop = NlriNextHop::Ipv4(Ipv4Addr::from(nh_bytes));

                let (buf, prefixes) =
                    nom::multi::many0(|buf| parse_prefix(AddressFamilyId::Ipv4, buf)).parse(buf)?;
                (buf, next_hop, prefixes)
            }
            AddressFamilyId::Ipv6 => {
                // https://datatracker.ietf.org/doc/html/rfc2545 defines that the nexthop address may be 16 or 32 bytes long.
                let (buf, nh_bytes) = nom::bytes::take(nh_len as usize).parse(buf)?;
                let nexthop = match nh_bytes.len() {
                    16 => {
                        // unwrap should never fire since we have explicitly checked the length.
                        let slice: [u8; 16] = nh_bytes.try_into().unwrap();
                        NlriNextHop::Ipv6(Ipv6Addr::from(slice))
                    }
                    32 => {
                        // unwrap should never fire since we have explicitly checked the length.
                        let slice: [u8; 32] = nh_bytes.try_into().unwrap();
                        let link_local_bytes: [u8; 16] = slice[0..16].try_into().unwrap();
                        let link_local = Ipv6Addr::from(link_local_bytes);
                        let global_bytes: [u8; 16] = slice[16..32].try_into().unwrap();
                        let global = Ipv6Addr::from(global_bytes);
                        NlriNextHop::Ipv6WithLl { global, link_local }
                    }
                    _ => {
                        return Err(Failure(BgpParserError::Eyre(eyre!(
                            "Mismatched IPv6 nexthop length, got {}, want 16 or 32",
                            nh_bytes.len()
                        ))));
                    }
                };
                let (buf, prefixes) =
                    nom::multi::many0(|buf| parse_prefix(AddressFamilyId::Ipv6, buf)).parse(buf)?;
                (buf, nexthop, prefixes)
            }
        };

        Ok((
            buf,
            Self {
                afi,
                safi,
                next_hop,
                prefixes,
            },
        ))
    }

    pub fn to_wire(&self, ctx: &ParserContext, out: &mut BytesMut) -> Result<()> {
        out.put_u16(self.afi as u16);
        out.put_u8(self.safi as u8);
        out.put_u8(self.next_hop.wire_len());
        self.next_hop.to_wire(ctx, out)?;
        for prefix in &self.prefixes {
            out.put_u8(prefix.length);
            out.put(&prefix.prefix[..]);
        }
        Ok(())
    }

    pub fn wire_len(&self, _: &ParserContext) -> Result<u16> {
        Ok(4_u16
            + self.next_hop.wire_len() as u16
            + self
                .prefixes
                .iter()
                .map(|p| 1 + p.prefix.len() as u16)
                .sum::<u16>())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpUnreachNlriPathAttribute {
    pub afi: AddressFamilyId,
    pub safi: SubsequentAfi,
    pub prefixes: Vec<IpPrefix>,
}

impl MpUnreachNlriPathAttribute {
    pub fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let (buf, raw_afi) = be_u16(buf)?;
        let afi =
            AddressFamilyId::try_from(raw_afi).map_err(|e| Failure(BgpParserError::Eyre(e)))?;

        let (buf, raw_safi) = be_u8(buf)?;
        let safi =
            SubsequentAfi::try_from(raw_safi).map_err(|e| Failure(BgpParserError::Eyre(e)))?;

        let (buf, prefixes) = nom::multi::many0(|buf| parse_prefix(afi, buf)).parse(buf)?;

        Ok((
            buf,
            MpUnreachNlriPathAttribute {
                afi,
                safi,
                prefixes,
            },
        ))
    }

    pub fn to_wire(&self, _: &ParserContext, out: &mut BytesMut) -> Result<()> {
        out.put_u16(self.afi as u16);
        out.put_u8(self.safi as u8);
        for prefix in &self.prefixes {
            out.put_u8(prefix.length);
            out.put(&prefix.prefix[..]);
        }
        Ok(())
    }

    pub fn wire_len(&self, _: &ParserContext) -> Result<u16> {
        Ok(3 + self
            .prefixes
            .iter()
            .map(|p| 1 + p.prefix.len() as u16)
            .sum::<u16>())
    }
}

#[cfg(test)]
mod tests {
    use eyre::Result;

    #[test]
    fn test_parse_update() -> Result<()> {
        todo!()
    }
}

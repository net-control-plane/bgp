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

use crate::capabilities::OpenOption;
use crate::constants::AddressFamilyIdentifier;
use crate::constants::SubsequentAddressFamilyIdentifier;
use crate::nlri::NLRI;
use crate::path_attributes::PathAttribute;
use crate::traits::BGPParserError;
use crate::traits::ParserContext;
use crate::traits::ReadablePacket;
use crate::traits::WritablePacket;

use byteorder::{ByteOrder, NetworkEndian};
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::Err::Failure;
use nom::IResult;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;
use std::net::Ipv4Addr;
use tokio_util::codec::{Decoder, Encoder};

/// BGPMessageType represents the type of the top level BGP message.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash)]
pub struct BGPMessageType(pub u8);

impl BGPMessageType {
    pub fn new(val: u8) -> BGPMessageType {
        BGPMessageType(val)
    }
}

impl Into<u8> for BGPMessageType {
    fn into(self) -> u8 {
        self.0
    }
}
impl From<u8> for BGPMessageType {
    fn from(i: u8) -> BGPMessageType {
        BGPMessageType(i)
    }
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod BGPMessageTypeValues {
    use super::BGPMessageType;

    pub const OPEN_MESSAGE: BGPMessageType = BGPMessageType(1);
    pub const UPDATE_MESSAGE: BGPMessageType = BGPMessageType(2);
    pub const NOTIFICATION_MESSAGE: BGPMessageType = BGPMessageType(3);
    pub const KEEPALIVE_MESSAGE: BGPMessageType = BGPMessageType(4);
    pub const REFRESH_MESSAGE: BGPMessageType = BGPMessageType(5);
}

#[derive(Debug, PartialEq)]
pub enum BGPSubmessage {
    OpenMessage(OpenMessage),
    UpdateMessage(UpdateMessage),
    NotificationMessage(NotificationMessage),
    KeepaliveMessage(KeepaliveMessage),
}

impl WritablePacket for BGPSubmessage {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        match &self {
            BGPSubmessage::OpenMessage(m) => m.to_wire(ctx),
            BGPSubmessage::UpdateMessage(m) => m.to_wire(ctx),
            BGPSubmessage::NotificationMessage(m) => m.to_wire(ctx),
            BGPSubmessage::KeepaliveMessage(m) => m.to_wire(ctx),
        }
    }
    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str> {
        match &self {
            BGPSubmessage::OpenMessage(m) => m.wire_len(ctx),
            BGPSubmessage::UpdateMessage(m) => m.wire_len(ctx),
            BGPSubmessage::NotificationMessage(m) => m.wire_len(ctx),
            BGPSubmessage::KeepaliveMessage(m) => m.wire_len(ctx),
        }
    }
}

/// KeepaliveMessage implements the KEEPALIVE message as defined in RFC4271.
#[derive(Debug, PartialEq)]
pub struct KeepaliveMessage {}

impl ReadablePacket for KeepaliveMessage {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        Ok((buf, KeepaliveMessage {}))
    }
}

impl WritablePacket for KeepaliveMessage {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        Ok(vec![])
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(0)
    }
}

impl Display for KeepaliveMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeepaliveMessage")
    }
}

/// NotificationMessage implements the NOTIFICATION message type as defined in RFC4271.
#[derive(Debug, PartialEq)]
pub struct NotificationMessage {
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Vec<u8>,
}

impl ReadablePacket for NotificationMessage {
    fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, ec) = be_u8(buf)?;
        let (buf, esc) = be_u8(buf)?;
        let data = &buf;
        Ok((
            &[0u8; 0],
            NotificationMessage {
                error_code: ec,
                error_subcode: esc,
                data: data.to_vec(),
            },
        ))
    }
}

impl WritablePacket for NotificationMessage {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf = vec![];
        buf.push(self.error_code);
        buf.push(self.error_subcode);
        buf.extend(self.data.to_owned());
        Ok(buf)
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(2 + self.data.len() as u16)
    }
}

impl Display for NotificationMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NotificationMessage error_code: {}, error_subcode: {}",
            self.error_code, self.error_subcode
        )
    }
}

#[derive(Debug, PartialEq)]
pub struct RouteRefreshMessage {
    pub afi: AddressFamilyIdentifier,
    pub safi: SubsequentAddressFamilyIdentifier,
}

impl WritablePacket for RouteRefreshMessage {
    fn to_wire(&self, _: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut res = [0u8; 4];
        byteorder::NetworkEndian::write_u16(&mut res[..2], self.afi.into());
        res[3] = self.safi.into();
        Ok(res.to_vec())
    }
    fn wire_len(&self, _: &ParserContext) -> Result<u16, &'static str> {
        Ok(4)
    }
}

impl ReadablePacket for RouteRefreshMessage {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, (afi, _, safi)) = nom::combinator::complete(nom::sequence::tuple((
            |i| AddressFamilyIdentifier::from_wire(ctx, i),
            nom::bytes::complete::take(1u8),
            |i| SubsequentAddressFamilyIdentifier::from_wire(ctx, i),
        )))(buf)?;

        IResult::Ok((buf, RouteRefreshMessage { afi, safi }))
    }
}

impl Display for RouteRefreshMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RouteRefresh [afi: {}, safi: {}]", self.afi, self.safi)
    }
}

/// BGPMessage is the top level message which is transmitted over the wire.
#[derive(Debug, PartialEq)]
pub struct BGPMessage {
    pub msg_type: BGPMessageType,
    pub payload: BGPSubmessage,
}

/// Codec is a helper for serializing and deserializing BGP messages.
pub struct Codec {
    pub ctx: ParserContext,
}

impl Encoder<BGPMessage> for Codec {
    type Error = std::io::Error;
    fn encode(
        &mut self,
        msg: BGPMessage,
        buf: &mut BytesMut,
    ) -> Result<(), <Self as Encoder<BGPMessage>>::Error> {
        let result = msg.to_wire(&self.ctx);
        match result {
            Ok(bytes) => {
                // XXX: Copying here because the whole write path needs to be updated
                // to take a refrence to BytesMut and write to that directly.
                let tmp: BytesMut = bytes.as_slice().into();
                buf.put(tmp);
                Ok(())
            }
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }
}

impl Decoder for Codec {
    type Item = BGPMessage;
    type Error = std::io::Error;
    fn decode(
        &mut self,
        buf: &mut BytesMut,
    ) -> Result<std::option::Option<<Self as Decoder>::Item>, <Self as Decoder>::Error> {
        // We first check to see if the frame contains the full BGP message before invoking
        // the parser on it.
        // Expected contents: 16x 0xff, u16 of length.
        // The length contains the header length, so we just check that the buf len matches.
        if buf.len() < 19 {
            // Minimum size is 19 for header + length + type.
            return Ok(None);
        }
        // Read the length
        let len: u16 = byteorder::BigEndian::read_u16(&buf[16..18]);
        if buf.len() < len.into() {
            // Not enough data to read this frame.
            return Ok(None);
        } else if buf.len() == len as usize {
            // Exactly one message here, parse and clear buf.
            let parse_result = BGPMessage::from_wire(&self.ctx, buf.as_ref());
            match parse_result {
                Ok(msg) => {
                    let result = msg.1;
                    buf.clear();
                    Ok(Some(result))
                }
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to parse message: {:?}", e),
                )),
            }
        } else {
            // More than one message here, parse and advance buf.
            let parse_result = BGPMessage::from_wire(&self.ctx, buf.as_ref());
            match parse_result {
                Ok(msg) => {
                    let result = msg.1;
                    buf.advance(len as usize);
                    Ok(Some(result))
                }
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to parse message: {:?}", e),
                )),
            }
        }
    }
}

impl WritablePacket for BGPMessage {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = Vec::new();
        // 16 bytes of 0xff according to Section 4.1 of RFC4271.
        buf.append(&mut vec![0xff; 16]);
        // Length.
        {
            let mut tmp: [u8; 2] = [0u8; 2];
            NetworkEndian::write_u16(&mut tmp, self.wire_len(ctx)?);
            buf.extend_from_slice(&mut tmp);
        }
        // Type
        buf.push(self.msg_type.into());
        let mut result: Vec<u8> = self.payload.to_wire(ctx)?;
        buf.append(&mut result);
        Ok(buf)
    }
    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str> {
        Ok(16 + 2 + 1 + self.payload.wire_len(ctx)?)
    }
}

impl ReadablePacket for BGPMessage {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, _) = nom::combinator::complete(nom::bytes::complete::tag(&[0xff; 16]))(buf)?;
        let (buf, len) = nom::combinator::complete(be_u16)(buf)?;
        let (buf, typ) = nom::combinator::complete(be_u8)(buf)?;
        let payload_len = len - 19;
        let (buf, payload_bytes) = nom::bytes::complete::take(payload_len)(buf)?;
        let (_, payload) = match typ.into() {
            BGPMessageTypeValues::OPEN_MESSAGE => {
                let (b, omsg) = OpenMessage::from_wire(ctx, payload_bytes)?;
                (b, BGPSubmessage::OpenMessage(omsg))
            }
            BGPMessageTypeValues::UPDATE_MESSAGE => {
                let (b, umsg) = UpdateMessage::from_wire(ctx, payload_bytes)?;
                (b, BGPSubmessage::UpdateMessage(umsg))
            }
            BGPMessageTypeValues::NOTIFICATION_MESSAGE => {
                let (b, nmsg) = NotificationMessage::from_wire(ctx, payload_bytes)?;
                (b, BGPSubmessage::NotificationMessage(nmsg))
            }
            BGPMessageTypeValues::KEEPALIVE_MESSAGE => {
                let (b, kmsg) = KeepaliveMessage::from_wire(ctx, payload_bytes)?;
                (b, BGPSubmessage::KeepaliveMessage(kmsg))
            }
            _ => {
                return Err(Failure(BGPParserError::CustomText(
                    "Unknown BGP message type".to_string(),
                )));
            }
        };
        Ok((
            buf,
            BGPMessage {
                msg_type: BGPMessageType(typ),
                payload,
            },
        ))
    }
}

impl Display for BGPMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.payload {
            BGPSubmessage::OpenMessage(m) => fmt::Display::fmt(&m, f),
            BGPSubmessage::UpdateMessage(m) => fmt::Display::fmt(&m, f),
            BGPSubmessage::KeepaliveMessage(m) => fmt::Display::fmt(&m, f),
            BGPSubmessage::NotificationMessage(m) => fmt::Display::fmt(&m, f),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct OpenMessage {
    pub version: u8,
    pub asn: u16,
    pub hold_time: u16,
    pub identifier: Ipv4Addr,
    pub options: Vec<OpenOption>,
}

impl ReadablePacket for OpenMessage {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], OpenMessage, BGPParserError<&'a [u8]>> {
        let (buf, (version, asn, hold_time, identifier)) =
            nom::combinator::complete(nom::sequence::tuple((be_u8, be_u16, be_u16, be_u32)))(buf)?;
        // oplen, [ [OpenOption] ... ]
        // OpenOption = [T, L, V]
        let (buf, opts): (_, Vec<OpenOption>) = nom::multi::length_value(
            be_u8,
            nom::multi::many0(|b| OpenOption::from_wire(ctx, b)),
        )(buf)?;
        Ok((
            buf,
            OpenMessage {
                version,
                asn,
                hold_time,
                identifier: Ipv4Addr::from(identifier),
                options: opts,
            },
        ))
    }
}

impl WritablePacket for OpenMessage {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = vec![0; 10];
        buf[0] = self.version;
        NetworkEndian::write_u16(&mut buf.as_mut_slice()[1..3], self.asn);
        NetworkEndian::write_u16(&mut buf.as_mut_slice()[3..5], self.hold_time);
        buf[5..9].clone_from_slice(&self.identifier.octets());
        let mut oplen: u8 = 0;
        for opt in &self.options {
            buf.append(&mut (*opt).to_wire(ctx)?);
            oplen += ((*opt).wire_len(ctx)?) as u8;
        }
        buf[9] = oplen;
        Ok(buf)
    }
    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str> {
        let mut count: usize = 10;
        for opt in &self.options {
            count += (*opt).to_wire(ctx)?.len();
        }
        Ok(count
            .try_into()
            .map_err(|_| "overflow in wire_len in OpenMessage")?)
    }
}

impl Display for OpenMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OpenMessage: [version: {}, asn: {}, hold_time: {}, identifier: {}, options: [",
            self.version, self.asn, self.hold_time, self.identifier
        )?;
        for option in &self.options {
            fmt::Display::fmt(option, f)?;
        }
        write!(f, "]]")
    }
}

/// UPDATE message and subtypes.
#[derive(Debug, PartialEq)]
pub struct UpdateMessage {
    pub withdrawn_nlri: Vec<NLRI>,
    pub path_attributes: Vec<PathAttribute>,
    pub announced_nlri: Vec<NLRI>,
}

impl ReadablePacket for UpdateMessage {
    fn from_wire<'a>(
        ctx: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>> {
        let (buf, wd_nlris): (_, Vec<NLRI>) = nom::multi::length_value(
            be_u16,
            nom::multi::many0(|i| NLRI::from_wire(&ctx.clone(), i)),
        )(buf)?;
        let (buf, pattrs): (_, Vec<PathAttribute>) = nom::multi::length_value(
            be_u16,
            nom::multi::many0(|i| PathAttribute::from_wire(ctx, i)),
        )(buf)?;
        let (buf, ann_nlri): (_, Vec<NLRI>) =
            nom::multi::many0(|i| NLRI::from_wire(&ctx.clone(), i))(buf)?;
        Ok((
            buf,
            UpdateMessage {
                withdrawn_nlri: wd_nlris,
                path_attributes: pattrs,
                announced_nlri: ann_nlri,
            },
        ))
    }
}

impl WritablePacket for UpdateMessage {
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str> {
        let mut buf: Vec<u8> = Vec::new();
        let mut tmp: &mut [u8] = &mut [0u8; 2];
        let mut wd_len: u16 = 0;
        for wd in &self.withdrawn_nlri {
            wd_len += wd.wire_len(ctx)?;
        }
        NetworkEndian::write_u16(&mut tmp, wd_len);
        buf.append(&mut tmp.to_vec());
        for wd in &self.withdrawn_nlri {
            buf.extend(wd.to_wire(ctx)?);
        }
        let mut pattr_len: u16 = 0;
        for pattr in &self.path_attributes {
            pattr_len += pattr.wire_len(ctx)?;
        }
        NetworkEndian::write_u16(&mut tmp, pattr_len);
        buf.extend(tmp.to_vec());
        for pattr in &self.path_attributes {
            buf.extend(pattr.to_wire(ctx)?);
        }
        for ann in &self.announced_nlri {
            buf.extend(ann.to_wire(ctx)?);
        }
        Ok(buf)
    }
    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str> {
        let mut ctr: u16 = 0;
        ctr += 2;
        for wd in &self.withdrawn_nlri {
            ctr += wd.wire_len(ctx)?;
        }
        ctr += 2;
        for pa in &self.path_attributes {
            ctr += pa.wire_len(ctx)?;
        }
        for ann in &self.announced_nlri {
            ctr += ann.wire_len(ctx)?;
        }
        Ok(ctr)
    }
}

impl Display for UpdateMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UpdateMessage [ withdrawn: ")?;
        for withdrawn_nlri in &self.withdrawn_nlri {
            fmt::Display::fmt(withdrawn_nlri, f)?;
        }
        write!(f, " announced: ")?;
        for announced_nlri in &self.announced_nlri {
            fmt::Display::fmt(announced_nlri, f)?;
        }
        write!(f, " path attributes: ")?;
        for path_attr in &self.path_attributes {
            fmt::Display::fmt(path_attr, f)?;
        }
        write!(f, " ]")
    }
}

#[cfg(test)]
mod tests {
    use super::BGPMessage;
    use super::Codec;
    use crate::constants::AddressFamilyIdentifier::Ipv6;
    use crate::messages::AddressFamilyIdentifier::Ipv4;
    use crate::traits::ParserContext;
    use crate::traits::ReadablePacket;
    use crate::traits::WritablePacket;

    use bytes::BufMut;
    use tokio_util::codec::{Decoder, Encoder};

    #[test]
    fn test_open_msg() {
        let open_msg_bytes: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x39, 0x01, 0x04, 0x00, 0x2a, 0x00, 0xb4, 0xd4, 0x19, 0x16, 0x26,
            0x1c, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00, 0x02,
            0x02, 0x02, 0x00, 0x02, 0x02, 0x46, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x00,
            0x2a,
        ];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv4);
        let (buf, result) = BGPMessage::from_wire(ctx, open_msg_bytes).unwrap();
        assert_eq!(buf.len(), 0);

        let want_str = "OpenMessage: [version: 4, asn: 42, hold_time: 180, identifier: 212.25.22.38, options: [OpenOption: Capabilities: Capabilities: [MultiprotocolCapbility: [ Ipv4 Unicast ]]OpenOption: Capabilities: Capabilities: [UnknownCapability type: 128]OpenOption: Capabilities: Capabilities: [RouteRefreshCapability]OpenOption: Capabilities: Capabilities: [UnknownCapability type: 70]OpenOption: Capabilities: Capabilities: [FourByteASN: asn: 42]]]";
        assert_eq!(format!("{}", result), want_str);

        let wire: Vec<u8> = result.to_wire(ctx).unwrap();
        assert_eq!(wire, open_msg_bytes);
    }

    #[test]
    fn test_open_msg_ipv6() {
        let open_msg_bytes: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x35, 0x01, 0x04, 0x22, 0x36, 0x00, 0xb4, 0xd4, 0x19, 0x1b, 0x2d,
            0x18, 0x02, 0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x02,
            0x02, 0x80, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x22, 0x36,
        ];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv4);
        let (buf, result) = BGPMessage::from_wire(ctx, open_msg_bytes).unwrap();
        assert_eq!(buf.len(), 0);

        let want_str = "OpenMessage: [version: 4, asn: 8758, hold_time: 180, identifier: 212.25.27.45, options: [OpenOption: Capabilities: Capabilities: [MultiprotocolCapbility: [ Ipv6 Unicast ]]OpenOption: Capabilities: Capabilities: [RouteRefreshCapability]OpenOption: Capabilities: Capabilities: [UnknownCapability type: 128]OpenOption: Capabilities: Capabilities: [FourByteASN: asn: 8758]]]";
        assert_eq!(format!("{}", result), want_str);

        let wire: Vec<u8> = result.to_wire(ctx).unwrap();
        assert_eq!(wire, open_msg_bytes);
    }

    #[test]
    fn test_update_msg_simple() {
        let update_msg_bytes: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x79, 0x02, 0x00, 0x00, 0x00, 0x5e, 0x40, 0x01, 0x01, 0x02, 0x40,
            0x02, 0x16, 0x02, 0x05, 0x00, 0x00, 0x9a, 0x74, 0x00, 0x00, 0xdf, 0x1e, 0x00, 0x00,
            0x73, 0xfb, 0x00, 0x00, 0x05, 0x13, 0x00, 0x00, 0x12, 0x83, 0x40, 0x03, 0x04, 0xb9,
            0x5f, 0xdb, 0x24, 0xc0, 0x08, 0x1c, 0x05, 0x13, 0x88, 0xb8, 0x73, 0xfb, 0x0f, 0xa0,
            0x73, 0xfb, 0x0f, 0xb5, 0x9a, 0x74, 0x0f, 0xa0, 0x9a, 0x74, 0x0f, 0xaa, 0xdf, 0x1e,
            0x07, 0xd0, 0xdf, 0x1e, 0x07, 0xda, 0xc0, 0x20, 0x18, 0x00, 0x00, 0xdf, 0x1e, 0x00,
            0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdf, 0x1e, 0x00, 0x00, 0x00,
            0x14, 0x00, 0x00, 0x00, 0x0a, 0x18, 0xcb, 0x01, 0x4e,
        ];
        let ctx = &ParserContext::new().four_octet_asn(true).nlri_mode(Ipv4);
        let (buf, result) = BGPMessage::from_wire(ctx, update_msg_bytes).unwrap();
        assert_eq!(buf.len(), 0);

        let want_str = "UpdateMessage [ withdrawn:  announced: 203.1.78.0/24 path attributes: OriginPathAttribute::INCOMPLETEAS Path: { Segment [ Type: AS_SEGMENT 39540 57118 29691 1299 4739  ]] }NextHop: 185.95.219.36Communities: [  1299:35000,  29691:4000,  29691:4021,  39540:4000,  39540:4010,  57118:2000,  57118:2010,  ] LargeCommunities: [ 57118:20:0,  57118:20:10, ] ]";
        assert_eq!(format!("{}", result), want_str);

        let reencoded = result.to_wire(&ctx).unwrap();
        assert_eq!(&reencoded, update_msg_bytes);
    }

    #[test]
    fn test_insufficient_decode() {
        let update_msg_bytes: &[u8] = &[0xff, 0xff, 0xff, 0xff, 0xff];
        let codec = &mut Codec {
            ctx: ParserContext {
                four_octet_asn: Some(true),
                nlri_mode: Some(Ipv6),
            },
        };
        let mut buf = bytes::BytesMut::from(update_msg_bytes);
        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn test_exact_decode_encode() {
        let update_msg_bytes: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x79, 0x02, 0x00, 0x00, 0x00, 0x5e, 0x40, 0x01, 0x01, 0x02, 0x40,
            0x02, 0x16, 0x02, 0x05, 0x00, 0x00, 0x9a, 0x74, 0x00, 0x00, 0xdf, 0x1e, 0x00, 0x00,
            0x73, 0xfb, 0x00, 0x00, 0x05, 0x13, 0x00, 0x00, 0x12, 0x83, 0x40, 0x03, 0x04, 0xb9,
            0x5f, 0xdb, 0x24, 0xc0, 0x08, 0x1c, 0x05, 0x13, 0x88, 0xb8, 0x73, 0xfb, 0x0f, 0xa0,
            0x73, 0xfb, 0x0f, 0xb5, 0x9a, 0x74, 0x0f, 0xa0, 0x9a, 0x74, 0x0f, 0xaa, 0xdf, 0x1e,
            0x07, 0xd0, 0xdf, 0x1e, 0x07, 0xda, 0xc0, 0x20, 0x18, 0x00, 0x00, 0xdf, 0x1e, 0x00,
            0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdf, 0x1e, 0x00, 0x00, 0x00,
            0x14, 0x00, 0x00, 0x00, 0x0a, 0x18, 0xcb, 0x01, 0x4e,
        ];
        let codec = &mut Codec {
            ctx: ParserContext {
                four_octet_asn: Some(true),
                nlri_mode: Some(Ipv6),
            },
        };
        let mut buf = bytes::BytesMut::from(update_msg_bytes);
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_some());
        assert_eq!(buf.len(), 0);
        codec.encode(result.unwrap(), &mut buf).unwrap();
        print!("Output bytes: ");
        for b in &buf {
            print!("0x{:02x}, ", b);
        }
        assert_eq!(buf.as_ref(), update_msg_bytes.as_ref());
    }

    #[test]
    fn test_multi_msg_codec_decode() {
        let update_msg_bytes: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00, 0x79, 0x02, 0x00, 0x00, 0x00, 0x5e, 0x40, 0x01, 0x01, 0x02, 0x40,
            0x02, 0x16, 0x02, 0x05, 0x00, 0x00, 0x9a, 0x74, 0x00, 0x00, 0xdf, 0x1e, 0x00, 0x00,
            0x73, 0xfb, 0x00, 0x00, 0x05, 0x13, 0x00, 0x00, 0x12, 0x83, 0x40, 0x03, 0x04, 0xb9,
            0x5f, 0xdb, 0x24, 0xc0, 0x08, 0x1c, 0x05, 0x13, 0x88, 0xb8, 0x73, 0xfb, 0x0f, 0xa0,
            0x73, 0xfb, 0x0f, 0xb5, 0x9a, 0x74, 0x0f, 0xa0, 0x9a, 0x74, 0x0f, 0xaa, 0xdf, 0x1e,
            0x07, 0xd0, 0xdf, 0x1e, 0x07, 0xda, 0xc0, 0x20, 0x18, 0x00, 0x00, 0xdf, 0x1e, 0x00,
            0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdf, 0x1e, 0x00, 0x00, 0x00,
            0x14, 0x00, 0x00, 0x00, 0x0a, 0x18, 0xcb, 0x01, 0x4e,
            // Add part of a second message which is incomplete
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x00,
        ];
        let codec = &mut Codec {
            ctx: ParserContext {
                four_octet_asn: Some(true),
                nlri_mode: Some(Ipv6),
            },
        };
        let mut buf = bytes::BytesMut::from(update_msg_bytes);
        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
        assert_eq!(buf.len(), 17);
        // Add the rest of the message into buf.
        buf.put_slice(&[
            0x79, 0x02, 0x00, 0x00, 0x00, 0x5e, 0x40, 0x01, 0x01, 0x02, 0x40, 0x02, 0x16, 0x02,
            0x05, 0x00, 0x00, 0x9a, 0x74, 0x00, 0x00, 0xdf, 0x1e, 0x00, 0x00, 0x73, 0xfb, 0x00,
            0x00, 0x05, 0x13, 0x00, 0x00, 0x12, 0x83, 0x40, 0x03, 0x04, 0xb9, 0x5f, 0xdb, 0x24,
            0xc0, 0x08, 0x1c, 0x05, 0x13, 0x88, 0xb8, 0x73, 0xfb, 0x0f, 0xa0, 0x73, 0xfb, 0x0f,
            0xb5, 0x9a, 0x74, 0x0f, 0xa0, 0x9a, 0x74, 0x0f, 0xaa, 0xdf, 0x1e, 0x07, 0xd0, 0xdf,
            0x1e, 0x07, 0xda, 0xc0, 0x20, 0x18, 0x00, 0x00, 0xdf, 0x1e, 0x00, 0x00, 0x00, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdf, 0x1e, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00,
            0x00, 0x0a, 0x18, 0xcb, 0x01, 0x4e,
        ]);
        let result2 = codec.decode(&mut buf);
        assert!(result2.is_ok());
        assert!(result2.unwrap().is_some());
        assert_eq!(buf.len(), 0);
    }
}

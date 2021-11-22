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

use crate::constants;
use crate::traits::NetlinkAttribute;
use crate::traits::Serializable;
use byteorder::ByteOrder;
use byteorder::NativeEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use log::info;
use std::convert::TryInto;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Read;
use std::io::Write;

// XXX: Hack to make libc:: constants the right type.
const CONST_NETLINK_ROUTE: u16 = libc::NETLINK_ROUTE as u16;
const CONST_NETLINK_NOOP: u16 = libc::NLMSG_NOOP as u16;
const CONST_NETLINK_ERR: u16 = libc::NLMSG_ERROR as u16;

macro_rules! check_vec_len {
    ($payload:expr, $len:expr) => {
        if $payload.len() != $len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "expected {} bytes of payload, instead got {}",
                    $len,
                    $payload.len()
                ),
            ));
        }
    };
}

#[derive(Debug)]
pub enum NetlinkPayload {
    Route(RouteMessage, Vec<RouteAttribute>),
    Error(NetlinkError),
    Noop(),
    Done(),
}

pub fn parse_netlink_message(
    buf: &mut BytesMut,
) -> Result<(NetlinkHeader, NetlinkPayload), std::io::Error> {
    let header = NetlinkHeader::from_wire(buf)?;
    let payload_len = header.nlmsg_len - std::mem::size_of::<NetlinkHeader>() as u32;
    if payload_len > buf.len().try_into().unwrap() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "Requested payload_len > buffer len: {} > {}",
                payload_len,
                buf.len()
            ),
        ));
    }
    info!(
        "Calling split_to with payload_len={}, buf.len()={}",
        payload_len,
        buf.len()
    );
    let payload: &mut BytesMut = &mut buf.split_to(payload_len as usize);

    match header.nlmsg_type {
        CONST_NETLINK_ERR => {
            let error = NetlinkError::from_wire(payload)?;
            Ok((header, NetlinkPayload::Error(error)))
        }
        CONST_NETLINK_NOOP => Ok((header, NetlinkPayload::Noop())),
        CONST_NETLINK_ROUTE => {
            let (rt_msg, attrs) = take_route_message(payload)?;
            Ok((header, NetlinkPayload::Route(rt_msg, attrs)))
        }
        libc::RTM_NEWROUTE | libc::RTM_GETROUTE | libc::RTM_DELROUTE => {
            let (rt_msg, attrs) = take_route_message(payload)?;
            Ok((header, NetlinkPayload::Route(rt_msg, attrs)))
        }
        unknown => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("Unknown netlink message type: {}", unknown),
        )),
    }
}

/// take_route_messaage attemts to parse a route message and attributes from the
/// provided buffer. It expects the header is already removed and the buffer is
/// trimmed of any padding.
pub fn take_route_message(
    buf: &mut BytesMut,
) -> Result<(RouteMessage, Vec<RouteAttribute>), std::io::Error> {
    let rt_msg = RouteMessage::from_wire(buf)?;
    let mut attributes = Vec::<RouteAttribute>::new();

    while buf.len() > 3 {
        let attr = RouteAttribute::from_wire(buf)?;
        attributes.push(attr);
    }

    Ok((rt_msg, attributes))
}

// NetlinkHeader is equivalent to nlmsghdr from the kernel.
// https://man7.org/linux/man-pages/man7/netlink.7.html
#[repr(C)]
#[derive(Debug)]
pub struct NetlinkHeader {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

impl Serializable<NetlinkHeader> for NetlinkHeader {
    fn to_wire(&self, buf: &mut BytesMut) -> Result<(), std::io::Error> {
        let mut writer = buf.writer();
        writer.write_u32::<NativeEndian>(self.nlmsg_len)?;
        writer.write_u16::<NativeEndian>(self.nlmsg_type)?;
        writer.write_u16::<NativeEndian>(self.nlmsg_flags)?;
        writer.write_u32::<NativeEndian>(self.nlmsg_seq)?;
        writer.write_u32::<NativeEndian>(self.nlmsg_pid)?;

        Ok(())
    }
    fn from_wire(buf: &mut BytesMut) -> Result<NetlinkHeader, std::io::Error> {
        let mut reader = buf.reader();
        let nlmsg_len = reader.read_u32::<NativeEndian>()?;
        let nlmsg_type = reader.read_u16::<NativeEndian>()?;
        let nlmsg_flags = reader.read_u16::<NativeEndian>()?;
        let nlmsg_seq = reader.read_u32::<NativeEndian>()?;
        let nlmsg_pid = reader.read_u32::<NativeEndian>()?;

        Ok(NetlinkHeader {
            nlmsg_len,
            nlmsg_type,
            nlmsg_flags,
            nlmsg_seq,
            nlmsg_pid,
        })
    }
}

impl Display for NetlinkHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NetlinkHeader [ len: {}, type: {}, flags: {}, seq: {}, pid: {} ]",
            self.nlmsg_len, self.nlmsg_type, self.nlmsg_flags, self.nlmsg_seq, self.nlmsg_pid
        )
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct NetlinkError {
    pub error: i32,
    pub msg: NetlinkHeader,
    // Other attributes that we're not parsing right now.
    pub payload: Vec<u8>,
}

impl Serializable<NetlinkError> for NetlinkError {
    fn to_wire(&self, buf: &mut BytesMut) -> Result<(), std::io::Error> {
        buf.writer().write_i32::<NativeEndian>(self.error)?;
        self.msg.to_wire(buf)?;
        buf.writer().write_all(&self.payload)?;
        Ok(())
    }
    fn from_wire(buf: &mut BytesMut) -> Result<NetlinkError, std::io::Error> {
        let mut reader = buf.reader();
        let error = reader.read_i32::<NativeEndian>()?;
        let msg = NetlinkHeader::from_wire(buf)?;
        let payload: Vec<u8> = buf.to_owned().to_vec();
        Ok(NetlinkError {
            error,
            msg,
            payload,
        })
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct RouteMessage {
    // address family
    pub af: u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub tos: u8,
    pub table: u8,
    pub protocol: u8,
    pub scope: u8,
    pub r#type: u8,
    pub flags: u32,
}

impl Serializable<RouteMessage> for RouteMessage {
    fn to_wire(&self, buf: &mut BytesMut) -> Result<(), std::io::Error> {
        let mut writer = buf.writer();
        writer.write_u8(self.af)?;
        writer.write_u8(self.dst_len)?;
        writer.write_u8(self.src_len)?;
        writer.write_u8(self.tos)?;
        writer.write_u8(self.table)?;
        writer.write_u8(self.protocol)?;
        writer.write_u8(self.scope)?;
        writer.write_u8(self.r#type)?;
        writer.write_u32::<NativeEndian>(self.flags)?;
        Ok(())
    }
    fn from_wire(buf: &mut BytesMut) -> Result<RouteMessage, std::io::Error> {
        // Check that the length is at least the size of a RouteMessage
        if buf.len() < std::mem::size_of::<RouteMessage>() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Buffer not large enough to read RouteMessage".to_string(),
            ));
        }

        let mut reader = buf.reader();
        let af = reader.read_u8()?;
        let dst_len = reader.read_u8()?;
        let src_len = reader.read_u8()?;
        let tos = reader.read_u8()?;
        let table = reader.read_u8()?;
        let protocol = reader.read_u8()?;
        let scope = reader.read_u8()?;
        let r#type = reader.read_u8()?;
        let flags = reader.read_u32::<NativeEndian>()?;

        Ok(RouteMessage {
            af,
            dst_len,
            src_len,
            tos,
            table,
            protocol,
            scope,
            r#type,
            flags,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum RouteAttribute {
    Dst(Vec<u8>),
    Src(Vec<u8>),
    Iif(u32),
    Oif(u32),
    Gateway(Vec<u8>),
    Priority(u32),
    Prefsrc(u32),
    Metrics(u32),
    // TODO: support multipath attribute properly
    Multipath(Vec<u8>),
    Flow(u32),
    // TODO: support cacheinfo properly
    CacheInfo(Vec<u8>),
    Table(u32),
    Mark(u32),
    // TODO: support mfc_stats properly
    MfcStats(Vec<u8>),
    // TODO: support via properly
    Via(Vec<u8>),
    NewDst(Vec<u8>),
    Pref(u8),
    EnacpType(u16),
    Encap(Vec<u8>),
}

impl NetlinkAttribute for RouteAttribute {
    fn attr_type(&self) -> u16 {
        match self {
            RouteAttribute::Dst(_) => constants::RTA_DST,
            RouteAttribute::Src(_) => constants::RTA_SRC,
            RouteAttribute::Iif(_) => constants::RTA_IIF,
            RouteAttribute::Oif(_) => constants::RTA_OIF,
            RouteAttribute::Gateway(_) => constants::RTA_GATEWAY,
            RouteAttribute::Priority(_) => constants::RTA_PRIORITY,
            RouteAttribute::Prefsrc(_) => constants::RTA_PREFSRC,
            RouteAttribute::Metrics(_) => constants::RTA_METRICS,
            RouteAttribute::Multipath(_) => constants::RTA_MULTIPATH,
            RouteAttribute::Flow(_) => constants::RTA_FLOW,
            RouteAttribute::CacheInfo(_) => constants::RTA_CACHEINFO,
            RouteAttribute::Table(_) => constants::RTA_TABLE,
            RouteAttribute::Mark(_) => constants::RTA_MARK,
            RouteAttribute::MfcStats(_) => constants::RTA_MFC_STATS,
            RouteAttribute::Via(_) => constants::RTA_VIA,
            RouteAttribute::NewDst(_) => constants::RTA_NEWDST,
            RouteAttribute::Pref(_) => constants::RTA_PREF,
            RouteAttribute::EnacpType(_) => constants::RTA_ENCAP_TYPE,
            RouteAttribute::Encap(_) => constants::RTA_ENCAP,
        }
    }
    fn payload_len(&self) -> u16 {
        match self {
            RouteAttribute::Dst(dst) => dst.len() as u16,
            RouteAttribute::Src(src) => src.len() as u16,
            RouteAttribute::Iif(_) => 4,
            RouteAttribute::Oif(_) => 4,
            RouteAttribute::Gateway(gateway) => gateway.len() as u16,
            RouteAttribute::Priority(_) => 4,
            RouteAttribute::Prefsrc(_) => 4,
            RouteAttribute::Metrics(_) => 4,
            RouteAttribute::Multipath(multipath) => multipath.len() as u16,
            RouteAttribute::Flow(_) => 4,
            RouteAttribute::CacheInfo(cacheinfo) => cacheinfo.len() as u16,
            RouteAttribute::Table(_) => 4,
            RouteAttribute::Mark(_) => 4,
            RouteAttribute::MfcStats(stats) => stats.len() as u16,
            RouteAttribute::Via(via) => via.len() as u16,
            RouteAttribute::NewDst(newdst) => newdst.len() as u16,
            RouteAttribute::Pref(_) => 1,
            RouteAttribute::EnacpType(_) => 2,
            RouteAttribute::Encap(encap) => encap.len() as u16,
        }
    }
    fn write_payload(&self, buf: &mut BytesMut) -> Result<(), std::io::Error> {
        let mut writer = buf.writer();
        match self {
            RouteAttribute::Dst(dst) => buf.put(dst.as_slice()),
            RouteAttribute::Src(src) => buf.put(src.as_slice()),
            RouteAttribute::Iif(iif) => writer.write_u32::<NativeEndian>(*iif)?,
            RouteAttribute::Oif(oif) => writer.write_u32::<NativeEndian>(*oif)?,
            RouteAttribute::Gateway(gateway) => buf.put(gateway.as_slice()),
            RouteAttribute::Priority(priority) => writer.write_u32::<NativeEndian>(*priority)?,
            RouteAttribute::Prefsrc(prefsrc) => writer.write_u32::<NativeEndian>(*prefsrc)?,
            RouteAttribute::Metrics(metrics) => writer.write_u32::<NativeEndian>(*metrics)?,
            RouteAttribute::Multipath(multipath) => buf.put(multipath.as_slice()),
            RouteAttribute::Flow(flow) => writer.write_u32::<NativeEndian>(*flow)?,
            RouteAttribute::CacheInfo(cacheinfo) => buf.put(cacheinfo.as_slice()),
            RouteAttribute::Table(table) => writer.write_u32::<NativeEndian>(*table)?,
            RouteAttribute::Mark(mark) => writer.write_u32::<NativeEndian>(*mark)?,
            RouteAttribute::MfcStats(stats) => buf.put(stats.as_slice()),
            RouteAttribute::Via(via) => buf.put(via.as_slice()),
            RouteAttribute::NewDst(newdst) => buf.put(newdst.as_slice()),
            RouteAttribute::Pref(pref) => buf.put_u8(*pref),
            RouteAttribute::EnacpType(encaptype) => writer.write_u16::<NativeEndian>(*encaptype)?,
            RouteAttribute::Encap(encap) => buf.put(encap.as_slice()),
        };
        Ok(())
    }
}

impl Serializable<RouteAttribute> for RouteAttribute {
    fn to_wire(&self, buf: &mut BytesMut) -> Result<(), std::io::Error> {
        // Write Type,  Length, Value then pad to 4 byte boundary.
        let mut writer = buf.writer();
        writer.write_u16::<NativeEndian>(self.payload_len() + 4)?;
        writer.write_u16::<NativeEndian>(self.attr_type())?;
        self.write_payload(buf)?;

        // Align the attribute to a four byte boundary.
        let padding = (4 + self.payload_len()) % 4;
        buf.put(vec![0u8; padding.into()].as_slice());

        Ok(())
    }
    fn from_wire(buf: &mut BytesMut) -> Result<RouteAttribute, std::io::Error> {
        let mut reader = buf.reader();
        let attr_len: u16 = reader.read_u16::<NativeEndian>()?;
        let attr_type: u16 = reader.read_u16::<NativeEndian>()?;
        let padding = attr_len % 4;

        if attr_len < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "route attr cannot have length < 4",
            ));
        }
        let payload_len = attr_len - 4;
        if buf.remaining() < payload_len.into() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Route attribute length was {} but buf has {} remaining",
                    payload_len,
                    buf.remaining()
                ),
            ));
        }
        let mut payload: Vec<u8> = vec![0u8; payload_len.into()];
        let bytes_read = buf.reader().read(&mut payload)?;
        if bytes_read != payload_len.into() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Failed to read {} bytes of payload, instead got {}",
                    payload_len, bytes_read
                ),
            ));
        }

        // Move buf past padding bytes.
        buf.advance(padding.into());

        match attr_type {
            constants::RTA_DST => Ok(RouteAttribute::Dst(payload)),
            constants::RTA_SRC => Ok(RouteAttribute::Src(payload)),
            constants::RTA_IIF => {
                check_vec_len!(payload, 4);
                Ok(RouteAttribute::Iif(NativeEndian::read_u32(&payload)))
            }
            constants::RTA_OIF => {
                check_vec_len!(payload, 4);
                Ok(RouteAttribute::Oif(NativeEndian::read_u32(&payload)))
            }
            constants::RTA_GATEWAY => Ok(RouteAttribute::Gateway(payload)),
            constants::RTA_PRIORITY => {
                check_vec_len!(payload, 4);
                Ok(RouteAttribute::Priority(NativeEndian::read_u32(&payload)))
            }
            constants::RTA_PREFSRC => {
                check_vec_len!(payload, 4);
                Ok(RouteAttribute::Prefsrc(NativeEndian::read_u32(&payload)))
            }
            constants::RTA_METRICS => {
                check_vec_len!(payload, 4);
                Ok(RouteAttribute::Metrics(NativeEndian::read_u32(&payload)))
            }
            constants::RTA_MULTIPATH => Ok(RouteAttribute::Multipath(payload)),
            constants::RTA_FLOW => {
                check_vec_len!(payload, 4);
                Ok(RouteAttribute::Flow(NativeEndian::read_u32(buf)))
            }
            constants::RTA_CACHEINFO => Ok(RouteAttribute::CacheInfo(payload)),
            constants::RTA_TABLE => {
                check_vec_len!(payload, 4);
                Ok(RouteAttribute::Table(NativeEndian::read_u32(&payload)))
            }
            constants::RTA_MARK => {
                check_vec_len!(payload, 4);
                Ok(RouteAttribute::Mark(NativeEndian::read_u32(&payload)))
            }
            constants::RTA_MFC_STATS => Ok(RouteAttribute::MfcStats(payload)),
            constants::RTA_VIA => Ok(RouteAttribute::CacheInfo(payload)),
            constants::RTA_NEWDST => Ok(RouteAttribute::CacheInfo(payload)),
            constants::RTA_PREF => {
                check_vec_len!(payload, 1);
                Ok(RouteAttribute::Pref(payload[0]))
            }
            constants::RTA_ENCAP_TYPE => {
                check_vec_len!(payload, 2);
                Ok(RouteAttribute::EnacpType(NativeEndian::read_u16(&payload)))
            }
            constants::RTA_ENCAP => Ok(RouteAttribute::Encap(payload)),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unknown attribute type: {}", attr_type),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RouteAttribute;
    use crate::packet::parse_netlink_message;
    use crate::traits::Serializable;
    use bytes::BytesMut;

    #[test]
    fn routemessage_roundtrip() {
        let _payload = &[
            0x74, 0x00, 0x00, 0x00, 0x18, 0x00, 0x02, 0x00, 0x35, 0x86, 0x00, 0x00, 0x31, 0x2f,
            0x05, 0x00, 0x0a, 0x80, 0x00, 0x00, 0xfe, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x0f, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x00, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x24, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x14, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
    }

    #[test]
    fn rta_table() {
        let payload: &[u8] = &[0x08, 0x00, 0x0f, 0x00, 0xff, 0x00, 0x00, 0x00];
        let attr = RouteAttribute::from_wire(&mut BytesMut::from(payload));
        assert_eq!(RouteAttribute::Table(0xff), attr.unwrap());
    }

    #[test]
    fn rta_dst() {
        let payload: &[u8] = &[
            0x14, 0x00, 0x01, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let attr = RouteAttribute::from_wire(&mut BytesMut::from(payload));
        assert_eq!(
            RouteAttribute::Dst(vec![255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]),
            attr.unwrap()
        );
    }

    #[test]
    fn parse_netlink_example_error() {
        let payload_str = "58000000020000000319000022311300edffffff410000001800050003190000000000000a280000000000000000000009000100200116b8170014000500200108e009ff2000000000000000000208000f00c90000000000";
        let payload = hex::decode(payload_str).expect("Test data hex decode failed");
        let mut buf = BytesMut::from(payload.as_slice());
        let res = parse_netlink_message(&mut buf).unwrap();
        println!("Parsed netlink message: {:?}", res);
        // assert_eq!(initial_capacity, buf.capacity());
    }

    // TODO: Clean this up to test only rtnetlink messages.
    // This blob contains link add meessages.
    // #[test]
    // fn parse_netlink_message_invariants() {
    //     let payload: &[u8] = &[
    //         /* Netlink route*/ 0xf4, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x65, 0xbf,
    //         0xe2, 0x61, 0xe8, 0x48, 0x85, 0xaa, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
    //         0x43, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x77, 0x6c,
    //         0x70, 0x30, 0x73, 0x32, 0x30, 0x66, 0x33, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00,
    //         0xe8, 0x03, 0x00, 0x00, 0x05, 0x00, 0x10, 0x00, 0x06, 0x00, 0x00, 0x00, 0x05, 0x00,
    //         0x11, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x8c, 0x05, 0x00, 0x00,
    //         0x08, 0x00, 0x32, 0x00, 0x00, 0x01, 0x00, 0x00, 0x08, 0x00, 0x33, 0x00, 0x00, 0x09,
    //         0x00, 0x00, 0x08, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x1e, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x1f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00,
    //         0x28, 0x00, 0xff, 0xff, 0x00, 0x00, 0x08, 0x00, 0x29, 0x00, 0x00, 0x00, 0x01, 0x00,
    //         0x08, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x21, 0x00, 0x01, 0x00,
    //         0x00, 0x00, 0x0c, 0x00, 0x06, 0x00, 0x6e, 0x6f, 0x71, 0x75, 0x65, 0x75, 0x65, 0x00,
    //         0x08, 0x00, 0x23, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x08, 0x00, 0x2f, 0x00, 0x2f, 0x00,
    //         0x00, 0x00, 0x08, 0x00, 0x30, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x05, 0x00, 0x27, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
    //         0x01, 0x00, 0x1c, 0x99, 0x57, 0xd9, 0x60, 0xa2, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x00,
    //         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xc4, 0x00, 0x17, 0x00, 0x9a, 0x2d,
    //         0xbd, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2, 0x62, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0xb6, 0x31, 0x63, 0x29, 0x03, 0x00, 0x00, 0x00, 0x15, 0xff, 0x5f, 0x7e, 0x01, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x07, 0x00, 0x9a, 0x2d,
    //         0xbd, 0x00, 0xc2, 0x62, 0x53, 0x00, 0xb6, 0x31, 0x63, 0x29, 0x15, 0xff, 0x5f, 0x7e,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x15, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x2b, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x0a, 0x00, 0x36, 0x00, 0x1c, 0x99, 0x57, 0xd9, 0x60, 0xa2, 0x00, 0x00,
    //         0x90, 0x01, 0x1a, 0x00, 0x88, 0x00, 0x02, 0x00, 0x84, 0x00, 0x01, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    //         0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x04, 0x01, 0x0a, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80, 0x14, 0x00,
    //         0x05, 0x00, 0xff, 0xff, 0x00, 0x00, 0xf2, 0xea, 0xf6, 0x00, 0x44, 0x66, 0x00, 0x00,
    //         0xe8, 0x03, 0x00, 0x00, 0xe4, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
    //         0x00, 0x00, 0x8c, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    //         0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xa0, 0x0f,
    //         0x00, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3a, 0x09, 0x00,
    //         0x80, 0x51, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x58, 0x02, 0x00, 0x00, 0x10, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    //         0x01, 0x00, 0x00, 0x00, 0x60, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xee,
    //         0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    //         0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x11, 0x00, 0x38, 0x00, 0x30, 0x30,
    //         0x30, 0x30, 0x3a, 0x30, 0x30, 0x3a, 0x31, 0x34, 0x2e, 0x33, 0x00, 0x00, 0x00, 0x00,
    //         0x08, 0x00, 0x39, 0x00, 0x70, 0x63, 0x69, 0x00,
    //     ];

    //     let mut buf = BytesMut::from(payload);
    //     let initial_capacity = buf.capacity();
    //     let res = parse_netlink_message(&mut buf);
    //     println!("Parsed netlink message: {:?}", res);
    //     assert_eq!(initial_capacity, buf.capacity());
    // }
}

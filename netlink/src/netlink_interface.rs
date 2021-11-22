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

use crate::packet::parse_netlink_message;
use crate::packet::NetlinkHeader;
use crate::packet::NetlinkPayload;
use crate::packet::RouteAttribute;
use crate::packet::RouteMessage;
use crate::traits::NetlinkAttribute;
use crate::traits::Serializable;
use bytes::BytesMut;
use libc::c_void;
use log::info;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Formatter;
use std::net::Ipv6Addr;

pub struct NetlinkInterface {
    nl_fd: libc::c_int,
    seqno: u32,
    buf: BytesMut,
}

#[derive(Debug, Clone)]
pub struct NetlinkError {
    reason: String,
}

impl NetlinkError {
    fn new(reason: String) -> NetlinkError {
        NetlinkError { reason }
    }
}

impl fmt::Display for NetlinkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for NetlinkError {}

impl NetlinkInterface {
    /// # Safety
    /// This function is unsafe as it manually creates a netlink socket with the socket
    /// system call.
    pub unsafe fn new() -> Result<NetlinkInterface, Box<dyn std::error::Error>> {
        let nl_fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
        if nl_fd < 0 {
            return Err(Box::new(NetlinkError::new(format!(
                "Error creating netlink socket: {}",
                nl_fd
            ))));
        }
        let sockaddr = libc::sockaddr {
            sa_family: libc::AF_NETLINK as u16,
            sa_data: [0i8; 14],
        };
        let bind_result = libc::bind(
            nl_fd,
            &sockaddr,
            std::mem::size_of::<libc::sockaddr>().try_into()?,
        );
        if bind_result < 0 {
            return Err(Box::new(NetlinkError::new(format!(
                "Failed to bind to netlink socket: {}",
                bind_result
            ))));
        }
        Ok(NetlinkInterface {
            nl_fd,
            seqno: 0,
            buf: BytesMut::with_capacity(4096),
        })
    }

    pub fn mutate_route(
        &mut self,
        add: bool,
        address_family: u8,
        dst_prefix: Vec<u8>,
        prefix_len: u8,
        gateway: Vec<u8>,
        table: Option<u32>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            "Mutate route: {:x?}/{prefix_len} via {:x?}",
            dst_prefix, gateway
        );
        // XXX: Fix this we should reuse the buffer instead of allocating a new one
        // each time. But there's some bug with how the size is being manipulated
        // below that causes the buffer to get exhausted.
        self.buf = BytesMut::with_capacity(4096);

        let msg_type = match add {
            true => libc::RTM_NEWROUTE,
            false => libc::RTM_DELROUTE,
        };
        self.seqno += 1;
        let mut nl_hdr = NetlinkHeader {
            nlmsg_type: msg_type,
            nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            nlmsg_seq: self.seqno,
            nlmsg_pid: 0,
            nlmsg_len: 0, // Filled in later.
        };

        let rt_msg = RouteMessage {
            af: address_family,
            dst_len: prefix_len,
            ..Default::default()
        };

        let dst_attr = RouteAttribute::Dst(dst_prefix);
        let gateway_addr = RouteAttribute::Gateway(gateway);

        nl_hdr.nlmsg_len = std::mem::size_of::<NetlinkHeader>() as u32
            + std::mem::size_of::<RouteMessage>() as u32
            + 4 // Attribute header
            + dst_attr.payload_len() as u32
            + 4 // Attribute header
            + gateway_addr.payload_len() as u32;

        let mut table_attr: Option<RouteAttribute> = None;
        if let Some(table_id) = table {
            table_attr = Some(RouteAttribute::Table(table_id));
            nl_hdr.nlmsg_len += 4 + table_attr.as_ref().unwrap().payload_len() as u32;
        }

        // self.buf.clear();
        nl_hdr.to_wire(&mut self.buf)?;
        rt_msg.to_wire(&mut self.buf)?;
        dst_attr.to_wire(&mut self.buf)?;
        gateway_addr.to_wire(&mut self.buf)?;
        if let Some(table_attr) = table_attr {
            table_attr.to_wire(&mut self.buf)?;
        }

        unsafe {
            let bytes_written = libc::write(
                self.nl_fd,
                self.buf.as_ptr() as *const c_void,
                self.buf.len(),
            );
            if bytes_written < 0 {
                return Err(Box::new(NetlinkError::new(format!(
                    "Failed to write to netlink: {}",
                    bytes_written
                ))));
            }
            if bytes_written != self.buf.len() as isize {
                return Err(Box::new(NetlinkError::new(
                    "Failed to write full message to netlink".to_string(),
                )));
            }
        }

        // Read the response back from netlink, should be a ACK or Error.
        self.buf.clear();

        unsafe {
            let bytes_read = libc::read(self.nl_fd, self.buf.as_mut_ptr() as *mut c_void, 4906);
            if bytes_read < 0 {
                return Err(Box::new(NetlinkError::new(format!(
                    "Failed to read from netlink: {}",
                    bytes_read
                ))));
            }
            println!(
                "bytes_read: {} (usz) {}, cap: {}",
                bytes_read,
                (bytes_read as usize),
                self.buf.capacity()
            );

            // let read_view = self.buf.clone();
            self.buf.set_len(bytes_read as usize);

            let (_header, response) = parse_netlink_message(&mut self.buf)?;
            match response {
                NetlinkPayload::Error(e) => {
                    if e.error == 0 {
                        // Successful ACK of the route add.
                        Ok(())
                    } else {
                        Err(Box::new(NetlinkError::new(format!(
                            "Got netlink error: {:?}",
                            e
                        ))))
                    }
                }
                _ => Err(Box::new(NetlinkError::new(format!(
                    "Got unexpected netlink message: {:?}",
                    response
                )))),
            }
        }
    }
}

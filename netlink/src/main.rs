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

//! This is just a small test program for testing the netlink integration.

use bytes::BytesMut;
use libc::c_void;
use netlink::packet::parse_netlink_message;
use netlink::packet::RouteAttribute;
use netlink::traits::NetlinkAttribute;
use netlink::traits::Serializable;

use netlink::packet::NetlinkHeader;
use netlink::packet::RouteMessage;
use std::convert::TryInto;

fn main() {
    println!("Starting netlink dump!");

    let nl_fd: libc::c_int;
    unsafe {
        // Establish a Netlink socket to the kernel.
        nl_fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
        if nl_fd < 0 {
            println!("Failed to create netlink socket: {}", nl_fd);
            std::process::exit(1);
        }
        let sockaddr = libc::sockaddr {
            sa_family: libc::AF_NETLINK as u16,
            sa_data: [0i8; 14],
        };
        let bind_result = libc::bind(
            nl_fd,
            &sockaddr,
            std::mem::size_of::<libc::sockaddr>().try_into().unwrap(),
        );
        if bind_result < 0 {
            println!("Failed to create netlink socket: {}", nl_fd);
            std::process::exit(1);
        }
    }

    // Build a route dump message and send it to the kernel.
    let mut nl_hdr = NetlinkHeader {
        nlmsg_type: libc::RTM_NEWROUTE,
        nlmsg_flags: (libc::NLM_F_REQUEST) as u16,
        nlmsg_seq: 0xcafe,
        nlmsg_pid: 0,
        nlmsg_len: 0,
    };

    println!("message type: {}", nl_hdr.nlmsg_type);
    let rt_msg = RouteMessage {
        af: libc::AF_INET6 as u8,
        dst_len: 32,
        ..Default::default()
    };

    let dst_attr = RouteAttribute::Dst(vec![0x20, 0x01, 0xdb, 0x8]);
    let gateway_addr = RouteAttribute::Gateway(vec![
        0x2a, 0x0d, 0xd7, 0x40, 0x1, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);

    let len = std::mem::size_of::<NetlinkHeader>()
        + std::mem::size_of::<RouteMessage>()
        + 4_usize
        + dst_attr.payload_len() as usize
        + 4_usize
        + gateway_addr.payload_len() as usize;
    nl_hdr.nlmsg_len = len as u32;
    println!("Length of netlink message: {}", len);

    let mut buf = BytesMut::with_capacity(4096);
    nl_hdr.to_wire(&mut buf).unwrap();
    rt_msg.to_wire(&mut buf).unwrap();
    dst_attr.to_wire(&mut buf).unwrap();
    gateway_addr.to_wire(&mut buf).unwrap();

    unsafe {
        let bytes_written = libc::write(nl_fd, buf.as_ptr() as *const c_void, buf.len());
        println!("bytes_written: {}", bytes_written);
    }

    let mut resp = BytesMut::with_capacity(4096);

    unsafe {
        let bytes_read = libc::read(nl_fd, resp.as_mut_ptr() as *mut c_void, 4096);
        resp.set_len(bytes_read.try_into().unwrap());
    };

    println!("Read bytes from netlink: {:?}", resp);

    while resp.len() > 3 {
        let (header, response) = parse_netlink_message(&mut resp).unwrap();
        println!("Header: {:?} response: {:?}", header, response);
    }
}

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

use std::io::{Read, Write};
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::{IpAddr, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use tokio_util::codec::Decoder;
use tracing::info;

use bgp_packet::constants::{AddressFamilyIdentifier, SubsequentAddressFamilyIdentifier};
use bgp_packet::messages::BGPSubmessage;
use bgp_packet::traits::ParserContext;
use bgp_server::bgp_server::Server;
use bgp_server::config::{PeerConfig, PrefixAnnouncement, ServerConfig};
use bgp_server::route_server::proto::bgp_server_admin_service_client::BgpServerAdminServiceClient;
use bgp_server::route_server::proto::PeerStatusRequest;

#[macro_use]
extern crate serial_test;

fn init() {
    match tracing_subscriber::fmt()
        // .with_env_filter("server=trace,tokio=trace,basic_startup=trace")
        .try_init()
    {
        Ok(()) => {}
        Err(e) => {
            eprintln!("Failed to setup tracing: {}", e);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bgp_listener_simple() {
    init();
    let sc = ServerConfig {
        asn: 65535,
        hold_time: 10,
        identifier: Ipv4Addr::new(127, 0, 0, 1),
        grpc_addr: None,
        http_addr: None,
        listen_addrs: vec!["[::]:9179".to_owned()],
        peers: vec![],
    };

    let mut bgp_server = Server::new(sc);
    bgp_server.start(true).await.unwrap();

    // Try to connect to localhost:9179 and it should connect.
    assert!(TcpStream::connect("[::1]:9179").is_ok());
    bgp_server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bgp_listener_unknown_peer() {
    init();
    let sc = ServerConfig {
        asn: 65535,
        hold_time: 10,
        identifier: Ipv4Addr::new(127, 0, 0, 1),
        grpc_addr: None,
        http_addr: None,
        listen_addrs: vec!["[::]:9179".to_owned()],
        peers: vec![],
    };

    let mut bgp_server = Server::new(sc);
    bgp_server.start(true).await.unwrap();

    // Try to connect to localhost:9179 and it should connect.
    let conn = TcpStream::connect_timeout(&"[::1]:9179".parse().unwrap(), Duration::from_secs(3));
    assert!(conn.is_ok());

    let open_msg_bytes: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x39, 0x01, 0x04, 0x00, 0x2a, 0x00, 0xb4, 0xd4, 0x19, 0x16, 0x26, 0x1c, 0x02,
        0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00,
        0x02, 0x02, 0x46, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x00, 0x2a,
    ];

    assert!(conn.as_ref().unwrap().write(open_msg_bytes).is_ok());

    let mut buf = Vec::with_capacity(256);
    assert_eq!(conn.unwrap().read(&mut buf).unwrap(), 0);
    bgp_server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bgp_listener_known_peer() {
    init();
    let v6_addr: Ipv6Addr = "::1".parse().unwrap();
    let sc = ServerConfig {
        asn: 65535,
        hold_time: 10,
        identifier: Ipv4Addr::new(127, 0, 0, 1),
        grpc_addr: None,
        http_addr: None,
        listen_addrs: vec!["[::]:9179".to_owned()],
        peers: vec![PeerConfig {
            afi: AddressFamilyIdentifier::Ipv6,
            safi: SubsequentAddressFamilyIdentifier::Unicast,
            asn: 8758,
            ip: IpAddr::V6(v6_addr),
            announcements: vec![],
            name: "local-test-peer".to_string(),
            local_pref: 100,
            port: None,
            filter_in: Vec::default(),
            filter_out: Vec::default(),
        }],
    };

    let mut bgp_server = Server::new(sc);
    bgp_server.start(true).await.unwrap();

    // Try to connect to localhost:9179 and it should connect.
    let mut conn =
        TcpStream::connect_timeout(&"[::1]:9179".parse().unwrap(), Duration::from_secs(3)).unwrap();

    // Make the stream blocking to be able to handle it easily in tests.
    conn.set_nonblocking(false).unwrap();
    conn.set_read_timeout(None).unwrap();

    let open_msg_bytes: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x35, 0x01, 0x04, 0x22, 0x36, 0x00, 0xb4, 0xd4, 0x19, 0x1b, 0x2d, 0x18, 0x02,
        0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x80, 0x00,
        0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x22, 0x36,
    ];

    assert!(conn.write_all(open_msg_bytes).is_ok());

    let mut open_buf = vec![0u8; 65536];
    let _ = conn.read(&mut open_buf).unwrap();

    let mut codec = bgp_packet::messages::Codec {
        ctx: ParserContext {
            four_octet_asn: None,
            nlri_mode: None,
        },
    };

    let response_open_msg = codec
        .decode(&mut bytes::BytesMut::from(open_buf.as_slice()))
        .unwrap();

    info!("Response message is: {:?}", response_open_msg);
    match response_open_msg.unwrap().payload {
        BGPSubmessage::OpenMessage(_open) => {}
        _ => {
            unreachable!();
        }
    }

    // Check that the server sends a keepalive after the open message.

    let mut ka_buf = vec![0u8; 65536];
    let _ = conn.read(&mut ka_buf).unwrap();
    let response_ka_message = codec
        .decode(&mut bytes::BytesMut::from(ka_buf.as_slice()))
        .unwrap();

    match response_ka_message.unwrap().payload {
        BGPSubmessage::KeepaliveMessage(_ka) => {}
        _ => {
            unreachable!();
        }
    }

    bgp_server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bgp_peer_statemachine_outbound_conn() {
    init();
    let v6_addr: Ipv6Addr = "::1".parse().unwrap();

    // Listen on some arbitrary port and put that port into the config for the server to dial out to.
    let listener = TcpListener::bind("[::1]:0".parse::<SocketAddrV6>().unwrap()).unwrap();
    info!("Listener is listening on: {:?}", listener.local_addr());
    let port: u16 = listener.local_addr().unwrap().port();

    let sc = ServerConfig {
        asn: 65535,
        hold_time: 10,
        identifier: Ipv4Addr::new(127, 0, 0, 1),
        grpc_addr: None,
        http_addr: None,
        listen_addrs: vec!["[::]:9179".to_owned()],
        peers: vec![PeerConfig {
            afi: AddressFamilyIdentifier::Ipv6,
            safi: SubsequentAddressFamilyIdentifier::Unicast,
            asn: 8758,
            ip: IpAddr::V6(v6_addr),
            port: Some(port),
            announcements: vec![],
            name: "local-test-peer".to_string(),
            local_pref: 100,
            filter_in: Vec::default(),
            filter_out: Vec::default(),
        }],
    };

    let mut bgp_server = Server::new(sc);
    bgp_server.start(true).await.unwrap();

    // Wait for the connection from the bgp_server.
    info!("Waiting for connection in test");
    let (mut conn, _) = listener.accept().unwrap();
    info!("Got a connection in test");

    let open_msg_bytes: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x35, 0x01, 0x04, 0x22, 0x36, 0x00, 0xb4, 0xd4, 0x19, 0x1b, 0x2d, 0x18, 0x02,
        0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x80, 0x00,
        0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x22, 0x36,
    ];

    assert!(conn.write_all(open_msg_bytes).is_ok());

    let mut open_buf = vec![0u8; 65536];
    let _ = conn.read(&mut open_buf).unwrap();

    let mut codec = bgp_packet::messages::Codec {
        ctx: ParserContext {
            four_octet_asn: None,
            nlri_mode: None,
        },
    };

    let response_open_msg = codec
        .decode(&mut bytes::BytesMut::from(open_buf.as_slice()))
        .unwrap();

    info!("Response message is: {:?}", response_open_msg);
    match response_open_msg.unwrap().payload {
        BGPSubmessage::OpenMessage(_open) => {}
        _ => {
            unreachable!();
        }
    }

    // Check that the server sends a keepalive after the open message.

    let mut ka_buf = vec![0u8; 65536];
    let _ = conn.read(&mut ka_buf).unwrap();
    let response_ka_message = codec
        .decode(&mut bytes::BytesMut::from(ka_buf.as_slice()))
        .unwrap();

    match response_ka_message.unwrap().payload {
        BGPSubmessage::KeepaliveMessage(_ka) => {}
        _ => {
            unreachable!();
        }
    }

    bgp_server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
// Check that reconnecting to a connection that was previously established works.
async fn test_bgp_peer_statemachine_outbound_reconnection() {
    init();
    let v6_addr: Ipv6Addr = "::1".parse().unwrap();

    // Listen on some arbitrary port and put that port into the config for the server to dial out to.
    let listener = TcpListener::bind("[::1]:0".parse::<SocketAddrV6>().unwrap()).unwrap();
    info!("Listener is listening on: {:?}", listener.local_addr());
    let port: u16 = listener.local_addr().unwrap().port();

    let sc = ServerConfig {
        asn: 65535,
        hold_time: 10,
        identifier: Ipv4Addr::new(127, 0, 0, 1),
        grpc_addr: None,
        http_addr: None,
        listen_addrs: vec!["[::]:9179".to_owned()],
        peers: vec![PeerConfig {
            afi: AddressFamilyIdentifier::Ipv6,
            safi: SubsequentAddressFamilyIdentifier::Unicast,
            asn: 8758,
            ip: IpAddr::V6(v6_addr),
            port: Some(port),
            announcements: vec![],
            name: "local-test-peer".to_string(),
            local_pref: 100,
            filter_in: Vec::default(),
            filter_out: Vec::default(),
        }],
    };

    let mut bgp_server = Server::new(sc);
    bgp_server.start(true).await.unwrap();

    // Wait for the connection from the bgp_server.
    info!("Waiting for connection in test");
    let (mut conn, _) = listener.accept().unwrap();
    info!("Got a connection in test");

    let open_msg_bytes: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x35, 0x01, 0x04, 0x22, 0x36, 0x00, 0xb4, 0xd4, 0x19, 0x1b, 0x2d, 0x18, 0x02,
        0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x80, 0x00,
        0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x22, 0x36,
    ];

    assert!(conn.write_all(open_msg_bytes).is_ok());

    let mut open_buf = vec![0u8; 65536];
    let _ = conn.read(&mut open_buf).unwrap();

    let mut codec = bgp_packet::messages::Codec {
        ctx: ParserContext {
            four_octet_asn: None,
            nlri_mode: None,
        },
    };

    let response_open_msg = codec
        .decode(&mut bytes::BytesMut::from(open_buf.as_slice()))
        .unwrap();

    info!("Response message is: {:?}", response_open_msg);
    match response_open_msg.unwrap().payload {
        BGPSubmessage::OpenMessage(_open) => {}
        _ => {
            unreachable!();
        }
    }

    // Check that the server sends a keepalive after the open message.

    let mut ka_buf = vec![0u8; 65536];
    let _ = conn.read(&mut ka_buf).unwrap();
    let response_ka_message = codec
        .decode(&mut bytes::BytesMut::from(ka_buf.as_slice()))
        .unwrap();

    match response_ka_message.unwrap().payload {
        BGPSubmessage::KeepaliveMessage(_ka) => {}
        _ => {
            unreachable!();
        }
    }

    conn.shutdown(std::net::Shutdown::Both).unwrap();

    // Expect that the other side reconnects to re-establish the connection.
    info!("Waiting for re-connection in test");
    let (mut conn, _) = listener.accept().unwrap();
    info!("Got the re-connection in test");

    let open_msg_bytes: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x35, 0x01, 0x04, 0x22, 0x36, 0x00, 0xb4, 0xd4, 0x19, 0x1b, 0x2d, 0x18, 0x02,
        0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x80, 0x00,
        0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x22, 0x36,
    ];

    assert!(conn.write_all(open_msg_bytes).is_ok());

    let mut open_buf = vec![0u8; 65536];
    let _ = conn.read(&mut open_buf).unwrap();

    let mut codec = bgp_packet::messages::Codec {
        ctx: ParserContext {
            four_octet_asn: None,
            nlri_mode: None,
        },
    };

    let response_open_msg = codec
        .decode(&mut bytes::BytesMut::from(open_buf.as_slice()))
        .unwrap();

    info!("Response message is: {:?}", response_open_msg);
    match response_open_msg.unwrap().payload {
        BGPSubmessage::OpenMessage(_open) => {}
        _ => {
            unreachable!();
        }
    }

    // Check that the server sends a keepalive after the open message.

    let mut ka_buf = vec![0u8; 65536];
    let _ = conn.read(&mut ka_buf).unwrap();
    let response_ka_message = codec
        .decode(&mut bytes::BytesMut::from(ka_buf.as_slice()))
        .unwrap();

    match response_ka_message.unwrap().payload {
        BGPSubmessage::KeepaliveMessage(_ka) => {}
        _ => {
            unreachable!();
        }
    }

    bgp_server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_bgp_listener_known_peer_inbound_reconnection() {
    init();
    let v6_addr: Ipv6Addr = "::1".parse().unwrap();
    let sc = ServerConfig {
        asn: 65535,
        hold_time: 10,
        identifier: Ipv4Addr::new(127, 0, 0, 1),
        grpc_addr: None,
        http_addr: None,
        listen_addrs: vec!["[::]:9179".to_owned()],
        peers: vec![PeerConfig {
            afi: AddressFamilyIdentifier::Ipv6,
            safi: SubsequentAddressFamilyIdentifier::Unicast,
            asn: 8758,
            ip: IpAddr::V6(v6_addr),
            announcements: vec![],
            name: "local-test-peer".to_string(),
            local_pref: 100,
            port: None,
            filter_in: Vec::default(),
            filter_out: Vec::default(),
        }],
    };

    let mut bgp_server = Server::new(sc);
    bgp_server.start(true).await.unwrap();

    // Try to connect to localhost:9179 and it should connect.
    let mut conn =
        TcpStream::connect_timeout(&"[::1]:9179".parse().unwrap(), Duration::from_secs(3)).unwrap();

    // Make the stream blocking to be able to handle it easily in tests.
    conn.set_nonblocking(false).unwrap();
    conn.set_read_timeout(None).unwrap();

    // Unsafe set linger: simulate a broken TCP stream by setting linger with a deadline of 0.
    // This causes a RST packet to be sent instead of a FIN, which means that the other side
    // will exercise the error path.
    unsafe {
        let val: libc::linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let ret_val = libc::setsockopt(
            conn.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &val as *const libc::linger as *const libc::c_void,
            size_of::<libc::linger>() as libc::socklen_t,
        );
        assert!(ret_val == 0);
    }

    let open_msg_bytes: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x35, 0x01, 0x04, 0x22, 0x36, 0x00, 0xb4, 0xd4, 0x19, 0x1b, 0x2d, 0x18, 0x02,
        0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x80, 0x00,
        0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x22, 0x36,
    ];

    assert!(conn.write_all(open_msg_bytes).is_ok());

    let mut open_buf = vec![0u8; 65536];
    let _ = conn.read(&mut open_buf).unwrap();

    let mut codec = bgp_packet::messages::Codec {
        ctx: ParserContext {
            four_octet_asn: None,
            nlri_mode: None,
        },
    };

    let response_open_msg = codec
        .decode(&mut bytes::BytesMut::from(open_buf.as_slice()))
        .unwrap();

    info!("Response message is: {:?}", response_open_msg);
    match response_open_msg.unwrap().payload {
        BGPSubmessage::OpenMessage(_open) => {}
        _ => {
            unreachable!();
        }
    }

    // Check that the server sends a keepalive after the open message.

    let mut ka_buf = vec![0u8; 65536];
    let _ = conn.read(&mut ka_buf).unwrap();
    let response_ka_message = codec
        .decode(&mut bytes::BytesMut::from(ka_buf.as_slice()))
        .unwrap();

    match response_ka_message.unwrap().payload {
        BGPSubmessage::KeepaliveMessage(_ka) => {}
        _ => {
            unreachable!();
        }
    }

    drop(conn);

    // Try to connect to localhost:9179 and it should connect and send the OPEN message.
    let mut conn =
        TcpStream::connect_timeout(&"[::1]:9179".parse().unwrap(), Duration::from_secs(3)).unwrap();

    let open_msg_bytes: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x35, 0x01, 0x04, 0x22, 0x36, 0x00, 0xb4, 0xd4, 0x19, 0x1b, 0x2d, 0x18, 0x02,
        0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x80, 0x00,
        0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x22, 0x36,
    ];

    assert!(conn.write_all(open_msg_bytes).is_ok());

    let mut open_buf = vec![0u8; 65536];
    conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let _ = conn.read(&mut open_buf).unwrap();

    let mut codec = bgp_packet::messages::Codec {
        ctx: ParserContext {
            four_octet_asn: None,
            nlri_mode: None,
        },
    };

    let response_open_msg = codec
        .decode(&mut bytes::BytesMut::from(open_buf.as_slice()))
        .unwrap();

    info!("Response message is: {:?}", response_open_msg);
    match response_open_msg.unwrap().payload {
        BGPSubmessage::OpenMessage(_open) => {}
        _ => {
            unreachable!();
        }
    }

    info!("Reconnection successful");

    bgp_server.shutdown().await;
}

// Spawn two instances of the BGP server and make them peer with each other and exchange a route.
// We then check that the route is accepted by the receiving peer.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_multi_instance_announce() {
    init();

    let v6_addr: Ipv6Addr = "::1".parse().unwrap();
    let config_a = ServerConfig {
        asn: 65535,
        hold_time: 3,
        identifier: Ipv4Addr::new(127, 0, 0, 1),
        grpc_addr: Some("[::]:9181".to_owned()),
        http_addr: None,
        listen_addrs: vec!["[::]:9179".to_owned()],
        peers: vec![PeerConfig {
            afi: AddressFamilyIdentifier::Ipv6,
            safi: SubsequentAddressFamilyIdentifier::Unicast,
            asn: 65536,
            ip: IpAddr::V6(v6_addr),
            port: Some(9180),
            announcements: vec![PrefixAnnouncement {
                prefix: "2001:db8:babe::/48".to_owned(),
                nexthop: "2001:db8::1".parse().unwrap(),
                local_pref: Some(100),
                med: Some(100),
                ..Default::default()
            }],
            name: "config-b-peer".to_string(),
            local_pref: 100,
            filter_in: Vec::default(),
            filter_out: Vec::default(),
        }],
    };

    let mut config_b = config_a.clone();
    config_b.asn = 65536;
    config_b.listen_addrs = vec!["[::]:9180".to_owned()];
    config_b.grpc_addr = Some("[::]:9182".to_owned());
    config_b.peers[0].asn = 65535;
    config_b.peers[0].port = Some(9179);
    config_b.peers[0].name = "config-a-peer".to_string();

    let mut server_a = Server::new(config_a);
    server_a.start(true).await.unwrap();

    let mut server_b = Server::new(config_b);
    server_b.start(true).await.unwrap();

    // Connect to the grpc endpoint of server_b and check until the peer is healthy.
    let mut stub = BgpServerAdminServiceClient::connect("http://[::1]:9182")
        .await
        .unwrap();

    let mut established = false;

    for _ in 1..10 {
        let response = stub
            .peer_status(PeerStatusRequest::default())
            .await
            .unwrap()
            .into_inner();
        info!(?response);

        if response.peer_status[0].state == "Established" {
            established = true;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    assert!(established);
}

# Netlink

This project was created to have an easy way to manipulate routes in the Linux kernel using the Netlink protocol.

There are some other libraries which provide similar functionality, but which were not offering the exact API which was desired to quickly modify routing state from control plane routing protocol daemons.

The API that this crate provides is (currently) specifically only for mutating routes using the following function:

```rust
// Create a handle which opens up a socket to the kernel.
let nl_iface = NetlinkInterface::new().unwrap();

// Modify a route
let af: u8 = 2; // Address family 1 is IPv6.
let dst_prefix = vec![0x20, 0x01, 0xdb, 0x8]; // 2001:db8::.
let dst_prefix_len = 32; // Specifying the prefix length is 32 bits.
let gateway_addr = vec![ // Nexthop / gateway to send packets to.
    0x2a, 0x0d, 0xd7, 0x40, 0x01, 0x05, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
let rt_table = 200; // Install this route into table 200.

self.nl_iface.mutate_route(
    true, // Add a route, false would be for removing a route.
    af,
    dst_prefix,
    dst_prefix_len,
    gateway_addr,
    Some(rt_table)).unwrap();

```

 Internally `RouteMessage` is used to represent a [rtmsg](https://man7.org/linux/man-pages/man7/rtnetlink.7.html) to the kernel, with a set of `RouteAttributes` that's attached to a particular `rtmsg`.
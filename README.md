# BGP

This project implements a Border Gateway Protocol speaker as defined in [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271) (not specification compliant yet, see status below), and provides programmatic access to the routes learned by the server.

The aim of the project is to provide a fully programatic interface for configuring, filtering, and exporting routes from the server to other peers and to the forwarding plane. 

## Design

The actual protocol interface logic (serializing bytes to objects, and objects to bytes) is contained within `bgpd/src/bgp_packet`. In there several key things are defined:

* NLRIs - A Network Layer Reachability Information object is a fancy way to say IP prefix, and represents the bytes of the prefix and the prefix length. For example 2001:db8::/32 is `0x20 0x01 0x0d 0xb8` with a prefix length of 32.
* Path Attibutes - are carried within BGP UPDATE messages and contain a wealth of metadata about a particular route, and in cases such as IPv6 announcements over MP-BGP, contains the actual prefixes and their nexthops. The parsers for path attributes are in `bgpd/src/bgp_packet/path_attributes.rs`.
* BGP Messages and the associated top-level parsing logic is contained in `bgpd/src/bgp_packet/messages.rs`.

The server logic is contained in `bgpd/src/server` and is split roughly in the following way:
* `config.rs` - Defines the configuration object which is read from the configuration file on startup. The goal is to have a fully programmatic way to configure the daemon, so this is an interim state / backup mechanism while a more scalable solution is implemented. It would be nice to be able to read the state from something like etcd on startup and provide a gRPC API to modify the server configuration.
* `peer.rs` - Contains the `PeerStateMachine` object which implements a finite state machine modelling the state of a peer, and this is where all peer related events are processed (e.g. reading messages from TCPStream, parsing them, doing things with UPDATE messages etc).
* `rib_manager.rs` - Processes routes from peers and stores them in a tree-bitmap. Also exposes an API for streaming path updates to remote receivers (e.g. over gRPC).
* `route_server.rs` - Implements a gRPC service for dumping and streaming routes.

## Project Status

The current state of the code is a barely functional proof of concept. Rayhaan uses this daemon at home for his home network, AS210036, but apart from the basic functionality of connecting to a peer, announcing a static set of routes, and streaming received routes out via gRPC, it does not do much more.

There are an abundance of opportunities to contribute to the project, to make it fully standards compliant, and achieve the goals of full programmability. If you are interested please reach out to `rayhaan (at rayhaan (with ccTLD ch))`.

### 🔥 P0

* Implementation of `route_client` to be able to properly install routes into the kernel.
* Route filters for inbound routes.
* Forwarding routes to peers.

### 🕯️ P1

* Monitoring and status of sessions with peers (to be able to detect peer down etc)
* More comprehensive integration tests (to cover route acceptance / filters / propagation to RIB / forwarding / availability in the API etc).

### RFCs

The following are the RFCs that were consulted during the writing of the daemon so far, and there are certainly parts that are not yet covered, so this list will have to be revisited to check conformance / file bugs to track where the gaps are.

* RFC4271 - https://datatracker.ietf.org/doc/html/rfc4271
	- BGP4 specification
* RFC4760 - https://datatracker.ietf.org/doc/html/rfc4760
	- Multiprotocol extensions for BGP4
* RFC4693 - https://datatracker.ietf.org/doc/html/rfc6793
	- 4 byte ASNs
	
#### RFC repository

Here's a list of interesting RFCs that we should look at eventually:

* RFC8212 - https://datatracker.ietf.org/doc/html/rfc8212
	- Default External BGP (EBGP) Route Propagation Behavior without Policies

### TODOs

A very rough sketch of some major TODOs:

* Get `route_client` into a state where it actually works
* Support forwarding routes to other peers
* Implement filters comprehensively and design an API for setting them
* Implement programatic control plane via gRPC
* RPKI integration
* Design and implement monitoring interfaces


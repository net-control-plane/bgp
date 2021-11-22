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

// This is direcly from https://docs.rs/libc/0.2.98/src/libc/unix/linux_like/linux/mod.rs.html#2449
// because when we build with musl libc some of these values are missing.

// linux/rtnetlink.h
pub const TCA_UNSPEC: libc::c_ushort = 0;
pub const TCA_KIND: libc::c_ushort = 1;
pub const TCA_OPTIONS: libc::c_ushort = 2;
pub const TCA_STATS: libc::c_ushort = 3;
pub const TCA_XSTATS: libc::c_ushort = 4;
pub const TCA_RATE: libc::c_ushort = 5;
pub const TCA_FCNT: libc::c_ushort = 6;
pub const TCA_STATS2: libc::c_ushort = 7;
pub const TCA_STAB: libc::c_ushort = 8;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;
pub const RTM_GETRULE: u16 = 34;
pub const RTM_NEWQDISC: u16 = 36;
pub const RTM_DELQDISC: u16 = 37;
pub const RTM_GETQDISC: u16 = 38;
pub const RTM_NEWTCLASS: u16 = 40;
pub const RTM_DELTCLASS: u16 = 41;
pub const RTM_GETTCLASS: u16 = 42;
pub const RTM_NEWTFILTER: u16 = 44;
pub const RTM_DELTFILTER: u16 = 45;
pub const RTM_GETTFILTER: u16 = 46;
pub const RTM_NEWACTION: u16 = 48;
pub const RTM_DELACTION: u16 = 49;
pub const RTM_GETACTION: u16 = 50;
pub const RTM_NEWPREFIX: u16 = 52;
pub const RTM_GETMULTICAST: u16 = 58;
pub const RTM_GETANYCAST: u16 = 62;
pub const RTM_NEWNEIGHTBL: u16 = 64;
pub const RTM_GETNEIGHTBL: u16 = 66;
pub const RTM_SETNEIGHTBL: u16 = 67;
pub const RTM_NEWNDUSEROPT: u16 = 68;
pub const RTM_NEWADDRLABEL: u16 = 72;
pub const RTM_DELADDRLABEL: u16 = 73;
pub const RTM_GETADDRLABEL: u16 = 74;
pub const RTM_GETDCB: u16 = 78;
pub const RTM_SETDCB: u16 = 79;
pub const RTM_NEWNETCONF: u16 = 80;
pub const RTM_GETNETCONF: u16 = 82;
pub const RTM_NEWMDB: u16 = 84;
pub const RTM_DELMDB: u16 = 85;
pub const RTM_GETMDB: u16 = 86;
pub const RTM_NEWNSID: u16 = 88;
pub const RTM_DELNSID: u16 = 89;
pub const RTM_GETNSID: u16 = 90;

pub const RTM_F_NOTIFY: libc::c_uint = 0x100;
pub const RTM_F_CLONED: libc::c_uint = 0x200;
pub const RTM_F_EQUALIZE: libc::c_uint = 0x400;
pub const RTM_F_PREFIX: libc::c_uint = 0x800;

pub const RTA_UNSPEC: libc::c_ushort = 0;
pub const RTA_DST: libc::c_ushort = 1;
pub const RTA_SRC: libc::c_ushort = 2;
pub const RTA_IIF: libc::c_ushort = 3;
pub const RTA_OIF: libc::c_ushort = 4;
pub const RTA_GATEWAY: libc::c_ushort = 5;
pub const RTA_PRIORITY: libc::c_ushort = 6;
pub const RTA_PREFSRC: libc::c_ushort = 7;
pub const RTA_METRICS: libc::c_ushort = 8;
pub const RTA_MULTIPATH: libc::c_ushort = 9;
pub const RTA_PROTOINFO: libc::c_ushort = 10; // No longer used
pub const RTA_FLOW: libc::c_ushort = 11;
pub const RTA_CACHEINFO: libc::c_ushort = 12;
pub const RTA_SESSION: libc::c_ushort = 13; // No longer used
pub const RTA_MP_ALGO: libc::c_ushort = 14; // No longer used
pub const RTA_TABLE: libc::c_ushort = 15;
pub const RTA_MARK: libc::c_ushort = 16;
pub const RTA_MFC_STATS: libc::c_ushort = 17;

pub const RTN_UNSPEC: libc::c_uchar = 0;
pub const RTN_UNICAST: libc::c_uchar = 1;
pub const RTN_LOCAL: libc::c_uchar = 2;
pub const RTN_BROADCAST: libc::c_uchar = 3;
pub const RTN_ANYCAST: libc::c_uchar = 4;
pub const RTN_MULTICAST: libc::c_uchar = 5;
pub const RTN_BLACKHOLE: libc::c_uchar = 6;
pub const RTN_UNREACHABLE: libc::c_uchar = 7;
pub const RTN_PROHIBIT: libc::c_uchar = 8;
pub const RTN_THROW: libc::c_uchar = 9;
pub const RTN_NAT: libc::c_uchar = 10;
pub const RTN_XRESOLVE: libc::c_uchar = 11;

pub const RTPROT_UNSPEC: libc::c_uchar = 0;
pub const RTPROT_REDIRECT: libc::c_uchar = 1;
pub const RTPROT_KERNEL: libc::c_uchar = 2;
pub const RTPROT_BOOT: libc::c_uchar = 3;
pub const RTPROT_STATIC: libc::c_uchar = 4;

pub const RT_SCOPE_UNIVERSE: libc::c_uchar = 0;
pub const RT_SCOPE_SITE: libc::c_uchar = 200;
pub const RT_SCOPE_LINK: libc::c_uchar = 253;
pub const RT_SCOPE_HOST: libc::c_uchar = 254;
pub const RT_SCOPE_NOWHERE: libc::c_uchar = 255;

pub const RT_TABLE_UNSPEC: libc::c_uchar = 0;
pub const RT_TABLE_COMPAT: libc::c_uchar = 252;
pub const RT_TABLE_DEFAULT: libc::c_uchar = 253;
pub const RT_TABLE_MAIN: libc::c_uchar = 254;
pub const RT_TABLE_LOCAL: libc::c_uchar = 255;

pub const RTMSG_OVERRUN: u32 = libc::NLMSG_OVERRUN as u32;
pub const RTMSG_NEWDEVICE: u32 = 0x11;
pub const RTMSG_DELDEVICE: u32 = 0x12;
pub const RTMSG_NEWROUTE: u32 = 0x21;
pub const RTMSG_DELROUTE: u32 = 0x22;
pub const RTMSG_NEWRULE: u32 = 0x31;
pub const RTMSG_DELRULE: u32 = 0x32;
pub const RTMSG_CONTROL: u32 = 0x40;
pub const RTMSG_AR_FAILED: u32 = 0x51;

pub const MAX_ADDR_LEN: usize = 7;
pub const ARPD_UPDATE: libc::c_ushort = 0x01;
pub const ARPD_LOOKUP: libc::c_ushort = 0x02;
pub const ARPD_FLUSH: libc::c_ushort = 0x03;
pub const ATF_MAGIC: libc::c_int = 0x80;

// From https://docs.rs/libc/0.2.98/src/libc/unix/linux_like/linux/gnu/mod.rs.html#938
// linux/rtnetlink.h
pub const TCA_PAD: libc::c_ushort = 9;
pub const TCA_DUMP_INVISIBLE: libc::c_ushort = 10;
pub const TCA_CHAIN: libc::c_ushort = 11;
pub const TCA_HW_OFFLOAD: libc::c_ushort = 12;

pub const RTM_DELNETCONF: u16 = 81;
pub const RTM_NEWSTATS: u16 = 92;
pub const RTM_GETSTATS: u16 = 94;
pub const RTM_NEWCACHEREPORT: u16 = 96;

pub const RTM_F_LOOKUP_TABLE: libc::c_uint = 0x1000;
pub const RTM_F_FIB_MATCH: libc::c_uint = 0x2000;

pub const RTA_VIA: libc::c_ushort = 18;
pub const RTA_NEWDST: libc::c_ushort = 19;
pub const RTA_PREF: libc::c_ushort = 20;
pub const RTA_ENCAP_TYPE: libc::c_ushort = 21;
pub const RTA_ENCAP: libc::c_ushort = 22;
pub const RTA_EXPIRES: libc::c_ushort = 23;
pub const RTA_PAD: libc::c_ushort = 24;
pub const RTA_UID: libc::c_ushort = 25;
pub const RTA_TTL_PROPAGATE: libc::c_ushort = 26;

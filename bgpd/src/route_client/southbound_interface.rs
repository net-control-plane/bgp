// Copyright 2021 Google LLC.
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

use crate::bgp_packet::nlri::NLRI;
use treebitmap::address::Address;

/// SouthboundInterface provides a uniform API to network forwarding elements
/// These are devices or targets that perform packet routing and are the end
/// consumers of packet routing data.

/// SouthboundErrorCode contains error codes to identify what went wrong with
/// programming the southbound interface.
// TODO: Actually add useful codes in here.
#[derive(Debug, Clone)]
enum SouthboundErrorCode {
    Internal,
}

/// SouthboundInterfaceError is a type that encapsulates errors talking to a
/// southbound forwarding element.
#[derive(Debug, Clone)]
struct SouthboundInterfaceError {
    code: SouthboundErrorCode,
    debug_info: String,
}

impl SouthboundInterfaceError {}

trait SouthboundInterface<A: Address> {
    fn route_add(prefix: NLRI, nexthop: A) -> Result<(), SouthboundInterfaceError>;
    fn route_del(prefix: NLRI, nexthop: A) -> Result<(), SouthboundInterfaceError>;
}

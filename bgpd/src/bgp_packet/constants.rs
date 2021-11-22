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

use serde::{Deserialize, Serialize};
use std::fmt;

// Address Family Identifiers as per
// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
#[derive(Eq, PartialEq, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct AddressFamilyIdentifier(pub u16);

impl Into<u16> for AddressFamilyIdentifier {
    fn into(self) -> u16 {
        self.0
    }
}

impl fmt::Display for AddressFamilyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return match *self {
            address_family_identifier_values::IPV4 => write!(f, "IPv4"),
            address_family_identifier_values::IPV6 => write!(f, "IPv6"),
            _ => write!(f, "Unknown AFI: {}", self.0),
        };
    }
}

pub mod address_family_identifier_values {
    use super::AddressFamilyIdentifier;

    pub const IPV4: AddressFamilyIdentifier = AddressFamilyIdentifier(1);
    pub const IPV6: AddressFamilyIdentifier = AddressFamilyIdentifier(2);
}

// Subsequent Address Family Identifiers as per
// https://www.iana.org/assignments/safi-namespace/safi-namespace.xhtml
#[derive(Eq, PartialEq, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct SubsequentAddressFamilyIdentifier(pub u8);

impl Into<u8> for SubsequentAddressFamilyIdentifier {
    fn into(self) -> u8 {
        self.0
    }
}

impl fmt::Display for SubsequentAddressFamilyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return match *self {
            subsequent_address_family_identifier_values::UNICAST => write!(f, "UNICAST"),
            subsequent_address_family_identifier_values::MULTICAST => write!(f, "MULTICAST"),
            _ => write!(f, "Unknown SAFI: {}", self.0),
        };
    }
}

pub mod subsequent_address_family_identifier_values {
    use super::SubsequentAddressFamilyIdentifier;

    pub const UNICAST: SubsequentAddressFamilyIdentifier = SubsequentAddressFamilyIdentifier(1);
    pub const MULTICAST: SubsequentAddressFamilyIdentifier = SubsequentAddressFamilyIdentifier(2);
}

pub const AS_TRANS: u16 = 23456;

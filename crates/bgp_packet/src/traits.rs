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

//! Implements high level abstractions for use in the BGP parser.

use crate::constants::AddressFamilyIdentifier;
use nom::error::ErrorKind;
use nom::error::ParseError;
use nom::IResult;

// ParserContext contains information pertinent to configurations which affect
// how message parsing is to be handled.
#[derive(Debug, PartialEq, Clone)]
pub struct ParserContext {
    // Whether the peer is RFC6793 compliant.
    pub four_octet_asn: Option<bool>,
    // nlri_mode specifies if a parsed NLRI prefix should be a IPv4 or IPv6 address.
    pub nlri_mode: Option<AddressFamilyIdentifier>,
}

impl ParserContext {
    pub fn new() -> ParserContext {
        ParserContext {
            four_octet_asn: None,
            nlri_mode: None,
        }
    }

    pub fn four_octet_asn(mut self, v: bool) -> Self {
        self.four_octet_asn = Some(v);
        self
    }

    pub fn nlri_mode(mut self, v: AddressFamilyIdentifier) -> Self {
        self.nlri_mode = Some(v);
        self
    }
}

// Custom error type for the parser.
#[derive(Debug, PartialEq)]
pub enum BGPParserError<I> {
    CustomText(String),
    Nom(I, ErrorKind),
}

impl<I> ParseError<I> for BGPParserError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        BGPParserError::Nom(input, kind)
    }
    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}

pub trait WritablePacket {
    /// to_wire serializes the packet to the wire format bytes.
    fn to_wire(&self, ctx: &ParserContext) -> Result<Vec<u8>, &'static str>;
    /// wire_len is the length of the message in bytes as would be on the wire.
    fn wire_len(&self, ctx: &ParserContext) -> Result<u16, &'static str>;
}

pub trait ReadablePacket {
    fn from_wire<'a>(
        ctx: &ParserContext,
        i: &'a [u8],
    ) -> IResult<&'a [u8], Self, BGPParserError<&'a [u8]>>
    where
        Self: Sized;
}

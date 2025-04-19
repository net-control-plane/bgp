use std::fmt::Display;

use nom::error::{ErrorKind, ParseError};

use crate::constants::AddressFamilyId;

#[derive(Debug, Default)]
pub struct ParserContext {
    /// Whether thi parser is being run with a peer that is RFC6793 compliant.
    pub four_octet_asn: Option<bool>,
    /// Which address family should be parsed by default with this parser.
    pub address_family: Option<AddressFamilyId>,
}

#[derive(Debug)]
pub enum ToWireError {
    /// There was not enough space in the output buffer to serialize the data into.
    OutBufferOverflow,
    /// Another error.
    Other(eyre::Error),
}

impl Display for ToWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToWireError::OutBufferOverflow => write!(f, "OutBufferOverflow"),
            ToWireError::Other(report) => report.fmt(f),
        }
    }
}

impl std::error::Error for ToWireError {}

// Custom error type for the parser.
#[derive(Debug)]
pub enum BgpParserError<I> {
    CustomText(&'static str),
    Eyre(eyre::ErrReport),
    Nom(I, ErrorKind),
}

impl<I> ParseError<I> for BgpParserError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        BgpParserError::Nom(input, kind)
    }
    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}

/// This module provides the required types for BGP Notification messages as defined in RFC 4271 §4.5.
use nom::number::be_u8;
use nom::{IResult, Parser};
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;
use thiserror::Error;

use crate::parser::{BgpParserError, ParserContext};

#[derive(Debug, Error, EnumDiscriminants, Serialize, Deserialize)]
#[repr(u8)]
pub enum NotificationMessage {
    #[error("Message header error")]
    MsgHeader(MsgHeaderSubcode) = 1,

    #[error("Open message error")]
    OpenMsg(OpenMsgSubcode) = 2,

    #[error("Update message error")]
    UpdateMsg(UpdateMsgSubcode) = 3,

    #[error("Hold timer expired")]
    HoldTimer = 4,

    #[error("Finite state machine error")]
    FsmError(FsmSubcode) = 5,

    #[error("Cease")]
    Cease(CeaseSubcode) = 6,

    #[error("Route refresh message error")]
    RouteRefresh(RouteRefreshSubcode) = 7,

    #[error("Send hold timer expired")]
    SendHoldTimer = 8,
}

impl NotificationMessage {
    pub fn from_wire<'a>(
        _: &ParserContext,
        buf: &'a [u8],
    ) -> IResult<&'a [u8], Self, BgpParserError<&'a [u8]>> {
        let (buf, code) = be_u8().parse(buf)?;

        match code {
            code if code == NotificationMessageDiscriminants::MsgHeader as u8 => todo!(),
            code if code == NotificationMessageDiscriminants::OpenMsg as u8 => todo!(),
            code if code == NotificationMessageDiscriminants::UpdateMsg as u8 => todo!(),
            code if code == NotificationMessageDiscriminants::HoldTimer as u8 => todo!(),
            code if code == NotificationMessageDiscriminants::FsmError as u8 => todo!(),
            code if code == NotificationMessageDiscriminants::Cease as u8 => todo!(),
            code if code == NotificationMessageDiscriminants::RouteRefresh as u8 => todo!(),
            code if code == NotificationMessageDiscriminants::SendHoldTimer as u8 => todo!(),
            _ => todo!(),
        }
    }
}

#[derive(Debug, Error, Serialize, Deserialize)]
#[repr(u8)]
pub enum MsgHeaderSubcode {
    #[error("Connection not synchronized")]
    ConnNotSynchronized = 1,

    #[error("Bad message length")]
    BadMessageLength(Vec<u8>) = 2,

    #[error("Bad message type")]
    BadMessageType(Vec<u8>) = 3,
}

#[derive(Debug, Error, Serialize, Deserialize)]
#[repr(u8)]
pub enum OpenMsgSubcode {
    /// RFC 4271 §6.2:
    /// Unsupported version number is sent when the most recent received OPEN message contains a
    /// BGP version number that is not supported. The data of this field is the largest locally-supported
    /// version number less than the version the remote BGP peer bid (i.e. sent in the last OPEN message).
    /// Or, if the smallest locally supported version number is greater than the version the remote BGP
    /// peer bid, then the smallest locally supported version number.
    #[error("Unsupported BGP version number")]
    UnsupportedVersion(u16) = 1,

    /// RFC 4271 §6.2:
    /// If the Autonomous System field of the OPEN message is unacceptable,
    /// then the Error Subcode MUST be set to Bad Peer AS.
    #[error("Bad peer AS number")]
    BadPeerAs(u32) = 2,

    /// RFC 4271 §6.2:
    /// If the BGP Identifier field of the OPEN message is syntactically
    /// incorrect, then the Error Subcode MUST be set to Bad BGP Identifier.
    /// Syntactic correctness means that the BGP Identifier field represents
    /// a valid unicast IP host address.
    #[error("Bad BGP identifier")]
    BadBgpId = 3,

    #[error("Unsupported optional parameter")]
    UnsupportedOptionalParam = 4,

    #[error("Unacceptable hold time")]
    UnacceptableHoldTime = 6,

    #[error("Unsupported capability")]
    UnsupportedCapability = 7,

    #[error("Role mismatch")]
    RoleMismatch = 8,
}

#[derive(Debug, Error, Serialize, Deserialize)]
#[repr(u8)]
pub enum UpdateMsgSubcode {
    #[error("Malformed attribute list")]
    MalforedAttrs = 1,

    #[error("Unrecognized well known attribute")]
    UnrecognizedWellKnownAttr = 2,

    #[error("Missing well known attribute")]
    MissingWellKnown = 3,

    #[error("Attribute flags error")]
    AttributeFlags = 4,

    #[error("Attribute length error")]
    AttributeLength = 5,

    #[error("Invalid origin")]
    InvalidOrigin = 6,

    #[error("Invalid next hop")]
    InvalidNextHop = 8,

    #[error("Optional attribute error")]
    OptionalAttribute = 9,

    #[error("Invalid network field")]
    InvalidNetworkField = 10,

    #[error("Malformed AS path")]
    MalformedAsPath = 11,
}

#[derive(Debug, Error, Serialize, Deserialize)]
#[repr(u8)]
pub enum FsmSubcode {
    #[error("Received an unexpected message in OpenSent state")]
    UnexpectedOpenSent = 1,

    #[error("Received an unexpected message in OpenConfirm state")]
    UnexpectedOpenConfirm = 2,

    #[error("Received an unexpected message in Established state")]
    UnexpectedEstablished = 3,
}

#[derive(Debug, Error, Serialize, Deserialize)]
#[repr(u8)]
pub enum CeaseSubcode {
    #[error("Maximum number of prefixes reached")]
    MaxPrefixes = 1,

    #[error("Administrative shutdown")]
    AdminShutdown = 2,

    #[error("Peer deconfigured")]
    PeerDeconf = 3,

    #[error("Administrative reset")]
    AdminReset = 4,

    #[error("Connection rejected")]
    ConnRejected = 5,

    #[error("Configuration change")]
    ConfChange = 6,

    #[error("Connection collision resolution")]
    ConnCollisionResolution = 7,

    #[error("Out of resources")]
    OutOfResources = 8,

    #[error("Hard reset")]
    HardReset = 9,

    #[error("BFD down")]
    BfdDown = 10,
}

#[derive(Debug, Error, Serialize, Deserialize)]
#[repr(u8)]
pub enum RouteRefreshSubcode {
    #[error("Invalid message length")]
    InvalidLength = 1,
}

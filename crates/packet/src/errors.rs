use thiserror::Error;

#[derive(Debug, Error)]
#[repr(u8)]
pub enum BgpError {
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

#[derive(Debug, Error)]
pub enum MsgHeaderSubcode {
    #[error("Connection not synchronized")]
    ConnNotSynchronized = 1,

    #[error("Bad message length")]
    BadMessageLength = 2,

    #[error("Bad message type")]
    BadMessagType = 3,
}

#[derive(Debug, Error)]
pub enum OpenMsgSubcode {
    #[error("Unsupported BGP version number")]
    UnsupportedVersion = 1,

    #[error("Bad peer AS number")]
    BadPeerAs = 2,

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

#[derive(Debug, Error)]
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

#[derive(Debug, Error)]
pub enum FsmSubcode {
    #[error("Received an unexpected message in OpenSent state")]
    UnexpectedOpenSent = 1,

    #[error("Received an unexpected message in OpenConfirm state")]
    UnexpectedOpenConfirm = 2,

    #[error("Received an unexpected message in Established state")]
    UnexpectedEstablished = 3,
}

#[derive(Debug, Error)]
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

#[derive(Debug, Error)]
pub enum RouteRefreshSubcode {
    #[error("Invalid message length")]
    InvalidLength = 1,
}

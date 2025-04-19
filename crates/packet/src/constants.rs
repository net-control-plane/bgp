use std::fmt::Display;

use eyre::bail;
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum AddressFamilyId {
    Ipv4 = 1,
    Ipv6 = 2,
}

impl TryFrom<u16> for AddressFamilyId {
    type Error = eyre::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            x if x == Self::Ipv4 as u16 => Self::Ipv4,
            x if x == Self::Ipv6 as u16 => Self::Ipv6,
            other => bail!("Unknown AddressFamily: {}", other),
        })
    }
}

impl Display for AddressFamilyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressFamilyId::Ipv4 => write!(f, "Ipv4"),
            AddressFamilyId::Ipv6 => write!(f, "Ipv6"),
        }
    }
}

/// Represents a Subsequent Address Family Identifier.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum SubsequentAfi {
    Unicast = 1,
    Multicast = 2,
    NlriWithMpls = 4,
    MplsLabelledVpn = 128,
    MulticastMplsVpn = 129,
}

impl TryFrom<u8> for SubsequentAfi {
    type Error = eyre::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            x if x == Self::Unicast as u8 => Self::Unicast,
            x if x == Self::Multicast as u8 => Self::Multicast,
            x if x == Self::NlriWithMpls as u8 => Self::NlriWithMpls,
            x if x == Self::MplsLabelledVpn as u8 => Self::MplsLabelledVpn,
            x if x == Self::MulticastMplsVpn as u8 => Self::MulticastMplsVpn,
            other => bail!("Unknown SubsequentAfi: {}", other),
        })
    }
}

impl Display for SubsequentAfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubsequentAfi::Unicast => write!(f, "Unicast"),
            SubsequentAfi::Multicast => write!(f, "Multicast"),
            SubsequentAfi::NlriWithMpls => write!(f, "NlriWithMpls"),
            SubsequentAfi::MplsLabelledVpn => write!(f, "MplsLabelledVpn"),
            SubsequentAfi::MulticastMplsVpn => write!(f, "MulticastMplsVpn"),
        }
    }
}

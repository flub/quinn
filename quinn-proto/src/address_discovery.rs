//! Address discovery types from
//! <https://datatracker.ietf.org/doc/draft-seemann-quic-address-discovery/>

use crate::VarInt;

pub(crate) const TRANSPORT_PARAMETER_CODE: u64 = 0x9f81a174;

/// The role of each participant.
///
/// When enabled, this is reported as a transport parameter.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(crate) enum Role {
    /// Is able to report observer addresses to other peers, but it's not interested in receiving
    /// reports about its own address.
    Observer,
    /// Is interested on reports about its own observed address, but will not report back to other
    /// peers.
    Observee,
    /// Will both report and receive reports of observed addresses.
    Both,
}

impl From<Role> for VarInt {
    fn from(role: Role) -> Self {
        match role {
            Role::Observer => VarInt(0),
            Role::Observee => VarInt(1),
            Role::Both => VarInt(2),
        }
    }
}

impl TryFrom<VarInt> for Role {
    type Error = crate::transport_parameters::Error;

    fn try_from(value: VarInt) -> Result<Self, Self::Error> {
        match value.0 {
            0 => Ok(Role::Observer),
            1 => Ok(Role::Observee),
            2 => Ok(Role::Both),
            _ => Err(crate::transport_parameters::Error::IllegalValue),
        }
    }
}

impl Role {
    pub(crate) fn new(is_observer: bool, is_observee: bool) -> Option<Self> {
        match (is_observer, is_observee) {
            (true, true) => Some(Role::Both),
            (true, false) => Some(Role::Observer),
            (false, true) => Some(Role::Observee),
            (false, false) => None,
        }
    }
    /// Whether this peer's role allows for address reporting to other peers.
    fn is_reporter(&self) -> bool {
        matches!(self, Role::Observer | Role::Both)
    }

    /// Whether this peer's role allows to receive observed address reports.
    fn receives_reports(&self) -> bool {
        matches!(self, Role::Observee | Role::Both)
    }

    /// Whether this peer should report observed addresses to other peer.
    pub(crate) fn should_report(&self, other: &Role) -> bool {
        self.is_reporter() && other.receives_reports()
    }
}

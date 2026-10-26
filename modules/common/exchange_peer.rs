//! The verified peer an exchange arrived with.
//!
//! A request HEAD carries a `peer` field: wave's `http` fills it with the
//! connection's verified identity — the SVID, `SHA-256` of the mTLS client
//! leaf's raw subject key — when `tls` in front of it authenticated one, and
//! leaves it empty otherwise. The SDK's `Collector` reassembles a request
//! without it, so a provider that decides on who asked notes the peer from
//! each HEAD here, by exchange id, and takes it back when the request is
//! whole.
//!
//! Only a 32-byte peer is kept: that is the one shape an SVID has, and a
//! peer of any other length is treated as no peer — never as a shorter
//! identity.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::abi::contracts::exchange::{self as x, ExchangeId};

/// An SVID's length.
pub const SVID_LEN: usize = 32;

#[derive(Clone, Copy)]
struct Slot {
    id: ExchangeId,
    svid: [u8; SVID_LEN],
    live: bool,
}

const EMPTY: Slot = Slot {
    id: ExchangeId::NONE,
    svid: [0; SVID_LEN],
    live: false,
};

/// Peers of the exchanges being collected, at most `N` at once — the
/// collector's own bound.
#[derive(Clone, Copy)]
pub struct Peers<const N: usize> {
    slots: [Slot; N],
}

impl<const N: usize> Peers<N> {
    #[must_use]
    pub const fn new() -> Self {
        Self { slots: [EMPTY; N] }
    }

    /// Note the peer of `record` when it is a request HEAD carrying an SVID.
    /// A HEAD without one clears whatever an earlier exchange with the same
    /// id left, so a reused id never inherits an identity.
    pub fn note(&mut self, record: &[u8]) {
        let Some(x::Record::Head(h)) = x::parse_request(record) else {
            return;
        };
        for slot in &mut self.slots {
            if slot.live && slot.id == h.id {
                *slot = EMPTY;
            }
        }
        if h.peer.len() != SVID_LEN {
            return;
        }
        // A full table drops the newest identity: its request is then
        // decided as unauthenticated, which is the safe direction.
        if let Some(slot) = self.slots.iter_mut().find(|s| !s.live) {
            slot.id = h.id;
            slot.svid.copy_from_slice(h.peer);
            slot.live = true;
        }
    }

    /// Take the SVID noted for `id`, if any, and forget it.
    pub fn take(&mut self, id: &ExchangeId) -> Option<[u8; SVID_LEN]> {
        let slot = self.slots.iter_mut().find(|s| s.live && s.id == *id)?;
        let svid = slot.svid;
        *slot = EMPTY;
        Some(svid)
    }
}

impl<const N: usize> Default for Peers<N> {
    fn default() -> Self {
        Self::new()
    }
}

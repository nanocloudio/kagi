//! The storage-key service's network edge, without I/O.
//!
//! A node reaches the service over HTTPS for the four operations that carry
//! their own proof: a challenge, an attach, a recovery and a renewal. Every
//! other verb is the control plane's, unauthenticated at the service, and is
//! refused here; the control plane reaches the service on an edge inside its
//! own graph.
//!
//! `POST /storage-key` carries one `storage_key_service::msg::REQUEST`
//! payload as its body, `[corr u32][op u8][resource kind u8][resource 16]
//! [body]`, and is answered with the REPLY payload. The service's replies go
//! to every party on its `replies` edge, so the endpoint rewrites a
//! request's correlation into its own space (high bit set) and keeps which
//! HTTP stream asked; a reply in that space is answered to that stream with
//! the caller's correlation restored, and any other reply is someone
//! else's.

use crate::http_app::AppId;
use crate::storage_key::op;

/// The one path served.
pub const PATH: &[u8] = b"/storage-key";
/// Correlations this endpoint gives the service: the high bit set.
pub const CORR_SPACE: u32 = 0x8000_0000;
/// Requests in flight at once.
pub const PENDING: usize = 16;

/// The operations a node may send.
pub fn admitted(opcode: u8) -> bool {
    matches!(
        opcode,
        op::CHALLENGE | op::ATTACH | op::RECOVER | op::RENEW_ATTACHMENT
    )
}

/// Why a request is answered without reaching the service.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refuse {
    /// Not `POST /storage-key`.
    NotFound,
    /// A control verb: the control plane's, not a node's.
    Forbidden,
    /// Too short to be a request.
    Malformed,
    /// Every slot is in flight.
    Busy,
}

impl Refuse {
    pub fn status(self) -> u16 {
        match self {
            Refuse::NotFound => 404,
            Refuse::Forbidden => 403,
            Refuse::Malformed => 400,
            Refuse::Busy => 503,
        }
    }
}

#[derive(Clone, Copy)]
struct Slot {
    used: bool,
    /// The exchange this request arrived on, as `http_app` identifies it.
    id: AppId,
    /// Response body bytes the server granted this exchange. Held with the
    /// id because the grant is the exchange's, and the reply that spends it
    /// is answered long after the request that was given it.
    credit: u32,
    corr: u32,
    seq: u16,
    at_ms: u64,
}

const EMPTY: Slot = Slot {
    used: false,
    id: AppId {
        origin: 0,
        conn: 0,
        stream: 0,
    },
    credit: 0,
    corr: 0,
    seq: 0,
    at_ms: 0,
};

/// The requests in flight.
pub struct Table {
    slots: [Slot; PENDING],
    seq: u16,
}

impl Table {
    pub const fn new() -> Self {
        Table {
            slots: [EMPTY; PENDING],
            seq: 0,
        }
    }

    /// Admit a request on exchange `id` whose payload is `payload`, and
    /// rewrite its correlation in place. `method` is the HTTP method byte the
    /// http module reports (POST is 3).
    pub fn admit(
        &mut self,
        method: u8,
        path: &[u8],
        id: &AppId,
        credit: u32,
        payload: &mut [u8],
        now_ms: u64,
    ) -> Result<(), Refuse> {
        if method != 3 || path != PATH {
            return Err(Refuse::NotFound);
        }
        if payload.len() < 4 + 1 + 1 + 16 {
            return Err(Refuse::Malformed);
        }
        if !admitted(payload[4]) {
            return Err(Refuse::Forbidden);
        }
        let Some(at) = self.slots.iter().position(|s| !s.used) else {
            return Err(Refuse::Busy);
        };
        self.seq = self.seq.wrapping_add(1);
        let corr = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        self.slots[at] = Slot {
            used: true,
            id: *id,
            credit,
            corr,
            seq: self.seq,
            at_ms: now_ms,
        };
        payload[..4].copy_from_slice(&Self::tag(at, self.seq).to_le_bytes());
        Ok(())
    }

    fn tag(at: usize, seq: u16) -> u32 {
        CORR_SPACE | ((at as u32) << 16) | u32::from(seq)
    }

    /// A reply payload from the service: when it answers one of this
    /// endpoint's requests, restore the caller's correlation and return the
    /// exchange to answer.
    pub fn reply(&mut self, payload: &mut [u8]) -> Option<(AppId, u32)> {
        if payload.len() < 4 {
            return None;
        }
        let tag = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if tag & CORR_SPACE == 0 {
            return None;
        }
        let at = ((tag >> 16) & 0x7FFF) as usize;
        let slot = self.slots.get_mut(at)?;
        if !slot.used || u32::from(slot.seq) != tag & 0xFFFF {
            return None;
        }
        slot.used = false;
        payload[..4].copy_from_slice(&slot.corr.to_le_bytes());
        Some((slot.id, slot.credit))
    }

    /// A request unanswered past `timeout_ms`, released: its exchange is
    /// answered 504 by the caller, which calls this until it answers `None`.
    pub fn expire(&mut self, now_ms: u64, timeout_ms: u64) -> Option<(AppId, u32)> {
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.used && now_ms.saturating_sub(s.at_ms) > timeout_ms)?;
        slot.used = false;
        Some((slot.id, slot.credit))
    }

    pub fn in_flight(&self) -> usize {
        self.slots.iter().filter(|s| s.used).count()
    }
}

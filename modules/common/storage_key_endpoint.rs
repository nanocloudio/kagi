//! The storage-key service's network edge, without I/O.
//!
//! A node reaches the service over HTTPS for the four operations that carry
//! their own proof: a challenge, an attach, a recovery and a renewal. Every
//! other verb is the control plane's, unauthenticated at the service, and is
//! refused here; the control plane reaches the service on an edge inside its
//! own graph.
//!
//! `POST /storage-key` carries one `storage_key_service::msg::REQUEST`
//! payload as its body, `[op u8][resource kind u8][resource 16][body]`, and
//! is answered with the REPLY payload. The endpoint carries each admitted
//! request to the service as an exchange of its own — the endpoint is the
//! requester, the `storage_key` module the provider — and keeps which HTTP
//! exchange asked, so the service's answer, which names only the endpoint's
//! exchange, is answered to that stream.

use crate::abi::contracts::exchange::ExchangeId;
use crate::storage_key::op;

/// The one path served.
pub const PATH: &[u8] = b"/storage-key";
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
    /// The HTTP exchange this request arrived on.
    id: ExchangeId,
    /// Response body bytes the server granted this exchange. Held with the
    /// id because the grant is the exchange's, and the answer that spends it
    /// comes long after the request that was given it.
    credit: u32,
    /// The exchange this endpoint opened with the service for it.
    call: ExchangeId,
    at_ms: u64,
}

const EMPTY: Slot = Slot {
    used: false,
    id: ExchangeId::NONE,
    credit: 0,
    call: ExchangeId::NONE,
    at_ms: 0,
};

/// The requests in flight.
pub struct Table {
    slots: [Slot; PENDING],
}

impl Table {
    pub const fn new() -> Self {
        Table {
            slots: [EMPTY; PENDING],
        }
    }

    /// Admit a request on HTTP exchange `id` whose body is `payload`, to be
    /// carried to the service on exchange `call`. `method` is the exchange
    /// contract's method byte.
    #[expect(clippy::too_many_arguments, reason = "one admission, field by field")]
    pub fn admit(
        &mut self,
        method: u8,
        path: &[u8],
        id: &ExchangeId,
        credit: u32,
        payload: &[u8],
        call: &ExchangeId,
        now_ms: u64,
    ) -> Result<(), Refuse> {
        if method != crate::abi::contracts::exchange::METHOD_POST || path != PATH {
            return Err(Refuse::NotFound);
        }
        if payload.len() < 1 + 1 + 16 {
            return Err(Refuse::Malformed);
        }
        if !admitted(payload[0]) {
            return Err(Refuse::Forbidden);
        }
        let Some(at) = self.slots.iter().position(|s| !s.used) else {
            return Err(Refuse::Busy);
        };
        self.slots[at] = Slot {
            used: true,
            id: *id,
            credit,
            call: *call,
            at_ms: now_ms,
        };
        Ok(())
    }

    /// The service answered exchange `call`: when it is one of this
    /// endpoint's, release it and return the HTTP exchange to answer and the
    /// credit it was granted.
    pub fn answer(&mut self, call: &ExchangeId) -> Option<(ExchangeId, u32)> {
        let slot = self.slots.iter_mut().find(|s| s.used && s.call == *call)?;
        slot.used = false;
        Some((slot.id, slot.credit))
    }

    /// A request unanswered past `timeout_ms`, released: its exchange is
    /// answered 504 by the caller, which calls this until it answers `None`.
    pub fn expire(&mut self, now_ms: u64, timeout_ms: u64) -> Option<(ExchangeId, u32)> {
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

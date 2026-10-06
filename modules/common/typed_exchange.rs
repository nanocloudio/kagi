//! Kagi's typed operations, carried as exchanges.
//!
//! A typed operation is a module that takes one `auth_wire` request message
//! and answers it with one `auth_wire` answer message: `token_verify`,
//! `mint_admission`, `authcode`, `token_mint`. Other projects compose them —
//! a pipeline builds the request bytes and branches on the answer — so they
//! speak the workspace's exchange contract
//! (`abi::contracts::exchange`) as PROVIDERS, on `request_in` /
//! `response_out`. This fragment is the part of that every one of them
//! shares, and the matching part for a kagi module that CALLS one.
//!
//! # The request
//!
//! A request HEAD with method `POST`. The target, headers and peer are not
//! read — a typed operation sits as happily behind wave's `http` on a route
//! as behind a pipeline, and neither the route nor the headers are an input
//! to its decision. The body is exactly ONE `auth_wire` envelope:
//!
//! ```text
//! [msg_type u8][len u16 LE][payload: len bytes]      len == body length - 3
//! ```
//!
//! The envelope stays inside the body because its type byte is what tells
//! `authorize` from `code exchange` on one port, and `admit` from `grant`.
//! Its length must agree with the body exactly: a body with bytes past the
//! envelope, or short of it, is not a message.
//!
//! The request must grant at least [`ANSWER_CREDIT`] bytes of response
//! credit. Every answer is one record, written once the decision is made; a
//! provider that had to wait for credit after deciding would be holding a
//! verdict it could not deliver.
//!
//! # The answer
//!
//! One response HEAD, no `MORE`, empty content type, no headers:
//!
//! | Status | When | Body |
//! |---|---|---|
//! | 200 | the operation produced its typed answer, a refusal verdict included | the answer envelope |
//! | 400 | the method is not `POST`; the body is not one envelope of a request type the operation takes; the response credit is below [`ANSWER_CREDIT`] | empty |
//! | 413 | the target, headers or body pass the provider's collector bounds | empty |
//! | 503 | the provider holds as many exchanges as it can | empty |
//!
//! A request whose envelope is well framed but whose payload does not decode
//! is answered 200 with the operation's own `MALFORMED` verdict: the
//! operation read it, and saying why is the operation's answer.
//!
//! # Calling one
//!
//! [`write_call`] and [`read_answer`] are the requester's half, for a kagi
//! module that drives another (an endpoint calling `mint_admission`,
//! admission calling `token_mint`). The id it chooses is [`call_id`]: a
//! counter, then the channel handle of its own request port, so two
//! requesters wired to one provider never choose the same id.
//!
//! Pure `no_std`, no syscalls: the module moves the bytes, and a host suite
//! drives the same code.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::abi::contracts::exchange::{self as x, ExchangeId, Record};
use crate::auth_wire;

/// The content type of every answer: none. The body is an `auth_wire`
/// envelope, which names its own type.
pub const CONTENT_TYPE: &[u8] = b"";

/// Where an answer's envelope starts inside its response record. An answer
/// is encoded straight into the record from here and sealed with
/// [`seal_answer`].
pub const ANSWER_AT: usize = x::response_body_at(CONTENT_TYPE.len());

/// The largest answer body: whatever one record carries after its head.
pub const ANSWER_MAX: usize = x::RECORD_MAX - ANSWER_AT;

/// The response credit a request must grant: enough for any answer.
pub const ANSWER_CREDIT: u32 = ANSWER_MAX as u32;

/// Where a call's envelope starts inside its request record: after the
/// HEAD's fixed part, with an empty target, headers and peer.
pub const CALL_AT: usize = x::HDR + x::REQ_HEAD_FIXED;

/// The largest call body: whatever one record carries after its head.
pub const CALL_MAX: usize = x::RECORD_MAX - CALL_AT;

/// Read a request body as one typed message: `(msg_type, payload)`.
///
/// `None` unless the body is exactly one envelope — a length that disagrees
/// with the body in either direction is not a message this reads around.
#[must_use]
pub fn message(body: &[u8]) -> Option<(u8, &[u8])> {
    let (msg_type, payload) = auth_wire::read_envelope(body).ok()?;
    if auth_wire::ENVELOPE + payload.len() != body.len() {
        return None;
    }
    Some((msg_type, payload))
}

/// Why a collected request is not one a typed operation reads, as the status
/// it is answered with. `None` when it is: `POST`, credit for any answer.
#[must_use]
pub fn admissible(method: u8, resp_credit: u32) -> Option<u16> {
    if method != x::METHOD_POST || resp_credit < ANSWER_CREDIT {
        return Some(x::status::BAD_REQUEST);
    }
    None
}

/// Write a 200 answer carrying `envelope` as its whole body.
pub fn write_answer(id: &ExchangeId, envelope: &[u8], out: &mut [u8]) -> Option<usize> {
    x::write_response(id, x::status::OK, CONTENT_TYPE, envelope, out)
}

/// Seal a 200 answer whose `len`-byte envelope is already at [`ANSWER_AT`].
pub fn seal_answer(id: &ExchangeId, len: usize, out: &mut [u8]) -> Option<usize> {
    x::seal_response(id, x::status::OK, CONTENT_TYPE, len, out)
}

/// Write an answer that is a status alone: a refusal before the operation
/// read the request.
pub fn write_status(id: &ExchangeId, status: u16, out: &mut [u8]) -> Option<usize> {
    x::write_response(id, status, CONTENT_TYPE, &[], out)
}

// ── calling one ───────────────────────────────────────────────────────────

/// The id a requester gives its `n`th call. `port` is the channel handle of
/// the requester's own request port: no two request ports share one, so two
/// requesters fanned into one provider never collide on an id.
#[must_use]
pub fn call_id(n: u64, port: i32) -> ExchangeId {
    let mut id = ExchangeId::from_u64(n).0;
    id[8..12].copy_from_slice(&port.to_le_bytes());
    ExchangeId(id)
}

/// Write a call: a request HEAD, `POST`, empty target, headers and peer,
/// granting [`ANSWER_CREDIT`], with `envelope` inline as its whole body.
pub fn write_call(id: &ExchangeId, envelope: &[u8], out: &mut [u8]) -> Option<usize> {
    x::write_request_head(
        &x::RequestHead {
            id: *id,
            flags: 0,
            method: x::METHOD_POST,
            target: &[],
            headers: &[],
            peer: &[],
            resp_credit: ANSWER_CREDIT,
            body: envelope,
        },
        out,
    )
}

/// Seal a call whose `len`-byte envelope is already at [`CALL_AT`].
pub fn seal_call(id: &ExchangeId, len: usize, out: &mut [u8]) -> Option<usize> {
    let end = CALL_AT.checked_add(len)?;
    if end > out.len() || end > x::RECORD_MAX {
        return None;
    }
    x::write_request_head(
        &x::RequestHead {
            id: *id,
            flags: 0,
            method: x::METHOD_POST,
            target: &[],
            headers: &[],
            peer: &[],
            resp_credit: ANSWER_CREDIT,
            body: &[],
        },
        out,
    )?;
    Some(end)
}

/// What a requester reads on its response port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer<'a> {
    /// The operation answered: a 200 carrying one envelope.
    Message {
        id: ExchangeId,
        msg_type: u8,
        payload: &'a [u8],
    },
    /// The exchange ended without a typed answer: a non-200 status, a 200
    /// whose body is not one envelope or does not fit one record, or an
    /// ABORT. `status` is the answer's own, or 502 for a body that could
    /// not be read and for an ABORT.
    Failed { id: ExchangeId, status: u16 },
    /// The provider's backend link changed. Every call open at `DOWN` is
    /// unknowable.
    Link { state: u8 },
    /// A record that ends nothing: a BODY or CREDIT of an exchange this side
    /// does not stream, a DATAGRAM, or a record that does not parse.
    Ignored,
}

/// Read one response-direction record.
#[must_use]
pub fn read_answer(record: &[u8]) -> Answer<'_> {
    match x::parse_response(record) {
        Some(Record::Head(h)) => {
            if h.status != x::status::OK {
                return Answer::Failed {
                    id: h.id,
                    status: h.status,
                };
            }
            if h.flags & x::flag::MORE != 0 {
                // Every answer this side reads is one record; one that
                // streams is not a typed answer.
                return Answer::Failed {
                    id: h.id,
                    status: x::status::BAD_GATEWAY,
                };
            }
            match message(h.body) {
                Some((msg_type, payload)) => Answer::Message {
                    id: h.id,
                    msg_type,
                    payload,
                },
                None => Answer::Failed {
                    id: h.id,
                    status: x::status::BAD_GATEWAY,
                },
            }
        }
        Some(Record::Abort { id, .. }) => Answer::Failed {
            id,
            status: x::status::BAD_GATEWAY,
        },
        Some(Record::Link { state }) => Answer::Link { state },
        _ => Answer::Ignored,
    }
}

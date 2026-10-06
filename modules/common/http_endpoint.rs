//! What kagi's HTTP endpoints hold of an exchange.
//!
//! Every endpoint sits behind wave's `http` server as a PROVIDER of the
//! workspace exchange contract (`abi::contracts::exchange`): requests arrive
//! on `request_in`, answers leave on `response_out`, and the SDK's
//! `Collector` gathers each request whole before the endpoint decides on it.
//! This fragment is the sizing every endpoint shares and the one rule the
//! contract leaves to the provider: a response body never passes the credit
//! the server granted.
//!
//! Responses are a single HEAD with the body inline. That is a deliberate
//! narrowing: every document this issuer serves is bounded well below one
//! record, and an endpoint that cannot say what it means in one record
//! answers 500 rather than streaming a partial truth. The server refuses a
//! head whose body exceeds its grant, so [`write_response`] reports the
//! overflow instead of emitting a record that would abort the exchange.
//!
//! Pure `no_std`, no syscalls.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::abi::contracts::exchange::{self as x, Collector, ExchangeId};

/// Exchanges collected at once. An endpoint answers a request as soon as it
/// is complete, so this is depth for requests arriving together rather than
/// a queue of work.
pub const MAX_EXCHANGES: usize = 8;
/// Longest request target held.
pub const MAX_TARGET: usize = 128;
/// Longest compact JWS a request may present in one header.
///
/// Mirrors `device_auth::MAX_SEGMENT`. Restated rather than imported because
/// not every endpoint authenticates devices, and a fragment that pulled
/// `device_auth` in would make the whole authentication surface a dependency
/// of plain request collection. The two are pinned together by an assertion
/// in each endpoint that mounts both, so they cannot drift apart in silence.
pub const MAX_CREDENTIAL: usize = 1024;
/// Longest request header block held.
///
/// Sized from what these endpoints actually authenticate with, not from a
/// round number. A device-authenticated request presents TWO compact JWSs —
/// the device certificate in `Authorization` and the DPoP proof in `DPoP` —
/// each of which `device_auth` admits up to [`MAX_CREDENTIAL`]. The block
/// also carries the ordinary request headers and each value's own name and
/// framing, so the two credentials are the floor rather than the whole
/// figure.
///
/// Getting this wrong is quiet: `Authorization` and `DPoP` together cross
/// 1 KiB comfortably, and a block over the limit is refused 413 at the HEAD,
/// before any handler sees a path or a method.
pub const MAX_HEADERS: usize = 2 * MAX_CREDENTIAL + 512;
/// Longest request body collected. Past this the request is refused 413
/// rather than truncated: a body this issuer cannot see all of is one it
/// must not decide on.
pub const MAX_BODY: usize = 4096;

/// The requests an endpoint is collecting.
pub type Requests = Collector<MAX_EXCHANGES, MAX_TARGET, MAX_HEADERS, MAX_BODY>;

/// The largest response body one record can carry, once the head's fixed
/// fields are accounted for.
pub const MAX_RESPONSE_BODY: usize = x::RECORD_MAX - x::HDR - x::RESP_HEAD_FIXED;

/// Write one response: a HEAD carrying the whole body.
///
/// `None` when the body does not fit one record or the credit granted, which
/// is the caller's cue to answer something it can say in one.
pub fn write_response(
    id: &ExchangeId,
    status: u16,
    content_type: &[u8],
    body: &[u8],
    resp_credit: u32,
    out: &mut [u8],
) -> Option<usize> {
    if u64::from(resp_credit) < body.len() as u64 {
        return None;
    }
    x::write_response(id, status, content_type, body, out)
}

/// Where a response body sits when it is built in place, for a content type
/// of `ct_len` bytes and no extra headers.
#[must_use]
pub const fn response_body_at(ct_len: usize) -> usize {
    x::response_body_at(ct_len)
}

/// Seal a response whose body is already at [`response_body_at`].
///
/// For the documents this issuer renders straight into the outgoing record:
/// a JWKS or a revocation bitmap is built where it will be sent, and copying
/// it through a second buffer would double the largest allocation in the
/// module for nothing.
pub fn seal_response(
    id: &ExchangeId,
    status: u16,
    content_type: &[u8],
    body_len: usize,
    resp_credit: u32,
    out: &mut [u8],
) -> Option<usize> {
    if u64::from(resp_credit) < body_len as u64 {
        return None;
    }
    x::seal_response(id, status, content_type, body_len, out)
}

/// Answer a request the collector refused: its status, an empty body.
///
/// The status is the whole answer — 413, 503 or 400 — and an empty body is
/// the one answer that can never pass a credit this endpoint did not see.
pub fn write_refusal(id: &ExchangeId, status: u16, out: &mut [u8]) -> Option<usize> {
    x::write_response(id, status, b"", &[], out)
}

/// Write a request-body credit grant for the server.
pub fn write_grant(id: &ExchangeId, bytes: u32, out: &mut [u8]) -> Option<usize> {
    x::write_credit(id, bytes, out)
}

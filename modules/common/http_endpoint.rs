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
use crate::abi::contracts::exchange_http::{self as http, Http};

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
/// Longest request meta (the header fields) held.
///
/// Sized from what these endpoints actually authenticate with, not from a
/// round number. A device-authenticated request presents TWO compact JWSs —
/// the device certificate in `authorization` and the DPoP proof in `dpop` —
/// each of which `device_auth` admits up to [`MAX_CREDENTIAL`]. The meta
/// also carries the ordinary request header fields and each field's own key
/// and framing, so the two credentials are the floor rather than the whole
/// figure.
///
/// Getting this wrong is quiet: `authorization` and `dpop` together cross
/// 1 KiB comfortably, and meta over the limit is refused 413 at the HEAD,
/// before any handler sees a path or a method.
pub const MAX_META: usize = 2 * MAX_CREDENTIAL + 512;
/// Longest request body collected. Past this the request is refused 413
/// rather than truncated: a body this issuer cannot see all of is one it
/// must not decide on.
pub const MAX_BODY: usize = 4096;

/// The requests an endpoint is collecting.
pub type Requests = Collector<Http, MAX_EXCHANGES, MAX_TARGET, MAX_META, MAX_BODY>;

/// Longest content type a response names.
pub const MAX_CONTENT_TYPE: usize = 64;

/// The meta a response with content type `ct` carries: one `content-type`
/// field, or nothing for an empty `ct`. `None` when `ct` passes
/// [`MAX_CONTENT_TYPE`].
fn content_meta(
    ct: &[u8],
    buf: &mut [u8; x::meta_field_len(x::META_CONTENT_TYPE.len(), MAX_CONTENT_TYPE)],
) -> Option<usize> {
    if ct.is_empty() {
        return Some(0);
    }
    if ct.len() > MAX_CONTENT_TYPE {
        return None;
    }
    let mut w = x::MetaWriter::new(buf);
    w.put(x::META_CONTENT_TYPE, ct);
    w.finish()
}

/// The meta length a response with a `ct_len`-byte content type carries.
#[must_use]
pub const fn content_meta_len(ct_len: usize) -> usize {
    if ct_len == 0 {
        0
    } else {
        x::meta_field_len(x::META_CONTENT_TYPE.len(), ct_len)
    }
}

/// The largest response body one record can carry, once the head's fixed
/// fields are accounted for.
pub const MAX_RESPONSE_BODY: usize = x::RECORD_MAX - x::HDR - x::RESP_HEAD_FIXED;

/// Write one response: a HEAD with status `status` carrying the whole body,
/// its content type the one meta field.
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
    let mut meta = [0u8; x::meta_field_len(x::META_CONTENT_TYPE.len(), MAX_CONTENT_TYPE)];
    let meta_len = content_meta(content_type, &mut meta)?;
    http::write_response(id, status, &meta[..meta_len], body, out)
}

/// Where a response body sits when it is built in place, for a content type
/// of `ct_len` bytes.
#[must_use]
pub const fn response_body_at(ct_len: usize) -> usize {
    x::response_body_at(content_meta_len(ct_len))
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
    let mut meta = [0u8; x::meta_field_len(x::META_CONTENT_TYPE.len(), MAX_CONTENT_TYPE)];
    let meta_len = content_meta(content_type, &mut meta)?;
    let head = http::head(*id, status, &meta[..meta_len], &[])?;
    x::seal_response_head::<Http>(&head, body_len, out)
}

/// Answer a request the collector refused: its outcome, an empty body.
///
/// The outcome is the whole answer — too large, busy or refused — and an
/// empty body is the one answer that can never pass a credit this endpoint
/// did not see.
pub fn write_refusal(id: &ExchangeId, outcome: u8, out: &mut [u8]) -> Option<usize> {
    x::write_response_head::<Http>(&x::ResponseHead::answer(*id, outcome, &[], &[]), out)
}

/// Write a request-body credit grant for the server.
pub fn write_grant(id: &ExchangeId, bytes: u32, out: &mut [u8]) -> Option<usize> {
    x::write_credit(id, bytes, out)
}

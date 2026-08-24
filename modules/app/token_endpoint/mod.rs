//! Token endpoint — the HTTP shape of a token request.
//!
//! Sits behind wave's `foundation/http` as an application, in front of
//! `token_mint`. An `HttpRequest` arrives on `request_in`; the endpoint reads
//! the form-encoded body, sends a `MSG_MINT_REQ` on `mint_out`, and when the
//! matching `MSG_MINT_RESP` comes back on `mint_in` it answers the connection
//! that asked with the OAuth token response.
//!
//! **It does not mint.** The claims, the signing key and the algorithm stay in
//! `token_mint`, which is the module that already owns them. What is here is
//! only the translation: form fields in, JSON out, and the bookkeeping that
//! remembers which HTTP connection a mint reply belongs to.
//!
//! That bookkeeping is the whole substance of the module. A mint reply
//! carries a correlation id and nothing else about its origin, so the pending
//! table is what turns it back into a response on the right connection. The
//! table is fixed-size and a request that arrives with it full is refused with
//! 503 rather than queued: a queue with no bound is a queue that answers the
//! wrong connection once the ids wrap.
//!
//! Requests are `application/x-www-form-urlencoded`, as RFC 6749 requires:
//!
//! ```text
//! POST /token
//! grant_type=client_credentials&scope=read&sub=device:alice&jkt=<43 chars>
//! ```
//!
//! `sub` and `jkt` are named by the caller here because this module is the
//! seam, not the authority: which subject a caller may ask for, and which key
//! may be bound, is a decision the enrollment path makes and hands over. A
//! deployment that lets an unauthenticated caller reach this port has made
//! that mistake in its graph, not in this module.

#![no_std]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in target/fluxor/fluxor-abi/sdk/"
)]
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the fluxor module ABI entry points (module_init/module_new/module_step): the \
              runtime owns these pointers and their validity is the ABI's contract, and the \
              signature is fixed by that contract rather than chosen here. The same allow \
              wave's and lattice's PIC modules carry."
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "see file-level allow: SDK surface is shared across modules"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/chan.rs"]
mod chan;

use auth_wire::{ExtraClaims, MintRequest, PayloadReader};

/// `module_step` return code for "did work, step me again".
const STEP_DID_WORK: i32 = 2;

/// `HttpRequest`  `[conn u16][stream u16][method u8][flags u8][path_len u16][hdr_len u16][body_len u16]`
const REQ_HDR: usize = 12;
/// `HttpResponse` `[conn u16][stream u16][status u16][flags u8][ct_len u8][hdr_len u16][body_len u16]`
const RESP_HDR: usize = 12;

/// wave's `wire::method::METHOD_POST`.
const METHOD_POST: u8 = 3;

/// Requests awaiting a mint reply.
///
/// Small on purpose. Each entry is one HTTP connection blocked on one
/// signature, and a device that has more than this many in flight is not
/// keeping up — refusing is a truer answer than a queue that grows.
const MAX_IN_FLIGHT: usize = 8;

/// Longest value read from a form field.
const MAX_FIELD: usize = 256;
/// Longest token a reply may carry back.
const MAX_TOKEN: usize = 4096;
/// WCET bound: requests translated per step.
const MAX_REQS_PER_STEP: usize = 4;
/// WCET bound: mint replies rendered per step.
const MAX_REPLIES_PER_STEP: usize = 4;

/// Default lifetime, in seconds, when a request names none.
const DEFAULT_TTL_SECS: u32 = 300;

/// One request waiting for its token.
#[derive(Clone, Copy)]
struct Pending {
    corr: u32,
    conn: u16,
    stream: u16,
    ttl: u32,
    /// `false` marks the slot free. A generation counter would be better
    /// against reuse, but the correlation id already is one: it only
    /// increments, so a stale reply finds no slot rather than the wrong one.
    live: bool,
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,   // in[0]:  HttpRequest
    out_responses: i32, // out[0]: HttpResponse
    out_mint: i32,      // out[1]: MSG_MINT_REQ
    in_mint: i32,       // in[1]:  MSG_MINT_RESP

    /// Monotonic; the correlation id a mint reply is matched by.
    next_corr: u32,
    pending: [Pending; MAX_IN_FLIGHT],

    /// The issuer and algorithm every minted token carries. Graph
    /// parameters, because they describe this deployment rather than this
    /// request — a caller that could name its own issuer could mint a token
    /// claiming to come from somebody else.
    iss: [u8; MAX_FIELD],
    iss_len: u16,
    alg: u8,

    token_issued: u32,
    token_refused: u32,
    token_malformed: u32,
    token_in_flight_full: u32,
    token_unmatched_reply: u32,

    buf: [u8; abi::CHANNEL_BUFFER_SIZE],
    out: [u8; abi::CHANNEL_BUFFER_SIZE],
}

define_params! {
    ModuleState;

    1, iss, str, 0 => |s, d, len| {
        let n = if len > MAX_FIELD { MAX_FIELD } else { len };
        let mut i = 0usize;
        while i < n {
            s.iss[i] = *d.add(i);
            i += 1;
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "clamped to MAX_FIELD (256) above"
        )]
        {
            s.iss_len = n as u16;
        }
    };

    // `auth_wire::MINT_ALG_*`. Defaults to Ed25519.
    2, alg, u32, 2 => |s, d, len| {
        if len >= 1 {
            s.alg = *d;
        }
    };
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs), the
    // kernel passes a valid, exclusively-borrowed `state` of at least
    // `module_state_size()` bytes, and a `syscalls` table whose function
    // pointers reach live kernel routines.
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<ModuleState>() {
            return -2;
        }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;

        s.in_requests = in_chan;
        s.out_responses = out_chan;
        s.out_mint = dev_channel_port(sys, 1, 1);
        s.in_mint = dev_channel_port(sys, 0, 1);

        s.next_corr = 1;
        s.pending = [Pending {
            corr: 0,
            conn: 0,
            stream: 0,
            ttl: 0,
            live: false,
        }; MAX_IN_FLIGHT];
        s.iss = [0; MAX_FIELD];
        s.iss_len = 0;
        s.alg = auth_wire::MINT_ALG_ED25519;
        s.token_issued = 0;
        s.token_refused = 0;
        s.token_malformed = 0;
        s.token_in_flight_full = 0;
        s.token_unmatched_reply = 0;

        parse_tlv(s, params, params_len);

        dev_log(sys, 3, b"[token-ep] init".as_ptr(), 15);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: as `module_new`.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // Replies first: they free a pending slot, so a request arriving in
        // the same step may take it rather than being refused for a seat
        // that was about to be vacated.
        let mut worked = drain_mint_replies(s, sys);

        for _ in 0..MAX_REQS_PER_STEP {
            if !chan::can_read(sys, s.in_requests) {
                break;
            }
            if !chan::can_write(sys, s.out_responses) {
                break;
            }
            // A raw envelope, not a typed message: wave's `http` writes the
            // HttpRequest with `channel_write`.
            let n = (sys.channel_read)(s.in_requests, s.buf.as_mut_ptr(), s.buf.len());
            if n < REQ_HDR as i32 {
                break;
            }
            handle_request(s, sys, n as usize);
            worked = true;
        }

        if worked {
            STEP_DID_WORK
        } else {
            0
        }
    }
}

/// Render every mint reply that has arrived. Returns whether any did.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn drain_mint_replies(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    let mut worked = false;
    if s.in_mint < 0 {
        return worked;
    }
    for _ in 0..MAX_REPLIES_PER_STEP {
        if !chan::can_read(sys, s.in_mint) {
            break;
        }
        if !chan::can_write(sys, s.out_responses) {
            break;
        }
        let mut buf = [0u8; MAX_TOKEN + 64];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_mint, &mut buf);
        if msg_type != auth_wire::MSG_MINT_RESP {
            continue;
        }
        worked = true;

        let mut r = PayloadReader::new(&buf[..plen as usize]);
        let (Ok(corr), Ok(status), Ok(token)) = (r.u32(), r.u8(), r.field16()) else {
            s.token_malformed = s.token_malformed.saturating_add(1);
            continue;
        };

        let Some(slot) = take_pending(s, corr) else {
            // A reply for a request nobody is waiting on: a duplicate, or one
            // whose connection went away. Dropping it is right — answering a
            // reused connection with somebody else's token would be worse
            // than answering nothing.
            s.token_unmatched_reply = s.token_unmatched_reply.saturating_add(1);
            continue;
        };

        if status == auth_wire::ST_OK && !token.is_empty() && token.len() <= MAX_TOKEN {
            s.token_issued = s.token_issued.saturating_add(1);
            let mut body = [0u8; MAX_TOKEN + 128];
            let len = write_token_json(&mut body, token, slot.ttl);
            respond(
                s,
                sys,
                slot.conn,
                slot.stream,
                200,
                b"application/json",
                &body[..len],
            );
        } else {
            s.token_refused = s.token_refused.saturating_add(1);
            respond(
                s,
                sys,
                slot.conn,
                slot.stream,
                400,
                b"application/json",
                br#"{"error":"invalid_request"}"#,
            );
        }
    }
    worked
}

/// Translate one `HttpRequest` into a `MSG_MINT_REQ`.
///
/// # Safety
///
/// As `drain_mint_replies`.
unsafe fn handle_request(s: &mut ModuleState, sys: &SyscallTable, plen: usize) {
    if plen < REQ_HDR {
        return;
    }
    let conn = u16::from_le_bytes([s.buf[0], s.buf[1]]);
    let stream = u16::from_le_bytes([s.buf[2], s.buf[3]]);
    let method = s.buf[4];
    let path_len = u16::from_le_bytes([s.buf[6], s.buf[7]]) as usize;
    let hdr_len = u16::from_le_bytes([s.buf[8], s.buf[9]]) as usize;
    let body_len = u16::from_le_bytes([s.buf[10], s.buf[11]]) as usize;

    let Some(body_at) = REQ_HDR
        .checked_add(path_len)
        .and_then(|at| at.checked_add(hdr_len))
    else {
        return;
    };
    let Some(body_end) = body_at.checked_add(body_len) else {
        return;
    };
    if body_end > plen {
        s.token_malformed = s.token_malformed.saturating_add(1);
        refuse(s, sys, conn, stream, 400, br#"{"error":"invalid_request"}"#);
        return;
    }

    if method != METHOD_POST {
        // RFC 6749 §3.2: the token endpoint takes POST. A GET carrying
        // credentials in a query string would put them in every log between
        // here and the caller.
        refuse(s, sys, conn, stream, 405, br#"{"error":"invalid_request"}"#);
        return;
    }

    // Copy the fields out before the pending table or the outbound buffer
    // borrows anything of `s`.
    let mut sub = [0u8; MAX_FIELD];
    let mut aud = [0u8; MAX_FIELD];
    let mut scope = [0u8; MAX_FIELD];
    let mut jkt = [0u8; 43];
    let (sub_len, aud_len, scope_len, jkt_len, ttl) = {
        let body = &s.buf[body_at..body_end];
        (
            form_value(body, b"sub", &mut sub),
            form_value(body, b"aud", &mut aud),
            form_value(body, b"scope", &mut scope),
            form_value(body, b"jkt", &mut jkt),
            form_u32(body, b"expires_in").unwrap_or(DEFAULT_TTL_SECS),
        )
    };

    if sub_len == 0 {
        s.token_malformed = s.token_malformed.saturating_add(1);
        refuse(s, sys, conn, stream, 400, br#"{"error":"invalid_request"}"#);
        return;
    }

    // A mint that cannot be written to is a mint that will not answer, and
    // an unanswered request is a connection that hangs until it times out.
    // Refuse now, while there is still someone to tell.
    if !chan::can_write(sys, s.out_mint) {
        s.token_in_flight_full = s.token_in_flight_full.saturating_add(1);
        refuse(
            s,
            sys,
            conn,
            stream,
            503,
            br#"{"error":"temporarily_unavailable"}"#,
        );
        return;
    }

    let corr = s.next_corr;
    let Some(index) = free_slot(s) else {
        s.token_in_flight_full = s.token_in_flight_full.saturating_add(1);
        refuse(
            s,
            sys,
            conn,
            stream,
            503,
            br#"{"error":"temporarily_unavailable"}"#,
        );
        return;
    };

    // `MintRequest::encode` writes the whole envelope — `[type][len][payload]`
    // — not the payload alone, so this goes out with the raw channel write.
    // Handing it to `channel_write_msg` would wrap an envelope in a second
    // one, and the mint would read its correlation id out of the framing.
    let mut framed = [0u8; 4096];
    let request = MintRequest {
        correlation: corr,
        alg: s.alg,
        ttl_seconds: ttl,
        iss: &s.iss[..usize::from(s.iss_len)],
        sub: &sub[..sub_len],
        aud: &aud[..aud_len],
        scope: &scope[..scope_len],
        // A `cnf` only when the caller gave a whole thumbprint. A short one
        // is a mistake, and binding a token to part of a key would bind it to
        // nothing.
        jkt: if jkt_len == jkt.len() {
            Some(&jkt)
        } else {
            None
        },
        extra: ExtraClaims::none(),
    };
    let Ok(n) = request.encode(&mut framed) else {
        s.token_malformed = s.token_malformed.saturating_add(1);
        refuse(s, sys, conn, stream, 400, br#"{"error":"invalid_request"}"#);
        return;
    };

    // The slot is claimed only once the request is actually on its way. A
    // slot held for a write that failed is a slot nothing will ever free.
    if (sys.channel_write)(s.out_mint, framed.as_ptr(), n) < n as i32 {
        s.token_in_flight_full = s.token_in_flight_full.saturating_add(1);
        refuse(
            s,
            sys,
            conn,
            stream,
            503,
            br#"{"error":"temporarily_unavailable"}"#,
        );
        return;
    }
    s.pending[index] = Pending {
        corr,
        conn,
        stream,
        ttl,
        live: true,
    };
    s.next_corr = s.next_corr.wrapping_add(1);
}

/// The first free pending slot.
fn free_slot(s: &ModuleState) -> Option<usize> {
    s.pending.iter().position(|slot| !slot.live)
}

/// Take the slot waiting on `corr`, freeing it.
fn take_pending(s: &mut ModuleState, corr: u32) -> Option<Pending> {
    let index = s
        .pending
        .iter()
        .position(|slot| slot.live && slot.corr == corr)?;
    let slot = s.pending[index];
    s.pending[index].live = false;
    Some(slot)
}

/// `{"access_token":"…","token_type":"DPoP","expires_in":N}`.
///
/// `DPoP` rather than `Bearer` whenever a token is bound: telling a client
/// `Bearer` for a token that will be refused without a proof sends it to
/// fail somewhere it cannot diagnose.
fn write_token_json(out: &mut [u8], token: &[u8], ttl: u32) -> usize {
    let mut at = 0usize;
    let mut put = |bytes: &[u8], at: &mut usize| {
        let end = (*at + bytes.len()).min(out.len());
        let n = end - *at;
        out[*at..end].copy_from_slice(&bytes[..n]);
        *at = end;
    };
    put(br#"{"access_token":""#, &mut at);
    put(token, &mut at);
    put(br#"","token_type":"DPoP","expires_in":"#, &mut at);
    let mut digits = [0u8; 10];
    let n = write_u32(&mut digits, ttl);
    put(&digits[..n], &mut at);
    put(b"}", &mut at);
    at
}

/// Decimal, without an allocator or a formatter.
fn write_u32(out: &mut [u8; 10], mut value: u32) -> usize {
    if value == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut digits = [0u8; 10];
    let mut n = 0usize;
    while value > 0 && n < digits.len() {
        digits[n] = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
        n += 1;
    }
    for i in 0..n {
        out[i] = digits[n - 1 - i];
    }
    n
}

/// The value of `name` in an `application/x-www-form-urlencoded` body,
/// percent-decoded, written into `out`. Returns how many bytes were written;
/// `0` for an absent, empty, or over-long value.
///
/// `+` is a space here, as the form encoding says — not the same rule as a
/// URI path, and getting it wrong would silently corrupt any scope with a
/// space in it.
fn form_value(body: &[u8], name: &[u8], out: &mut [u8]) -> usize {
    let mut rest = body;
    while !rest.is_empty() {
        let pair_end = rest.iter().position(|&b| b == b'&').unwrap_or(rest.len());
        let pair = &rest[..pair_end];
        if let Some(eq) = pair.iter().position(|&b| b == b'=') {
            if &pair[..eq] == name {
                return percent_decode(&pair[eq + 1..], out);
            }
        }
        rest = if pair_end >= rest.len() {
            &[]
        } else {
            &rest[pair_end + 1..]
        };
    }
    0
}

/// A form field read as a decimal `u32`.
fn form_u32(body: &[u8], name: &[u8]) -> Option<u32> {
    let mut raw = [0u8; 16];
    let n = form_value(body, name, &mut raw);
    if n == 0 {
        return None;
    }
    let mut value: u32 = 0;
    for &byte in &raw[..n] {
        let digit = byte.checked_sub(b'0')?;
        if digit > 9 {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(digit))?;
    }
    Some(value)
}

/// Percent-decode into `out`, returning the length. A truncated or invalid
/// escape ends the value: a decoder that passed `%4` through as literal text
/// would accept two spellings of the same field.
fn percent_decode(input: &[u8], out: &mut [u8]) -> usize {
    let mut at = 0usize;
    let mut i = 0usize;
    while i < input.len() {
        if at >= out.len() {
            return 0; // Over-long: refuse rather than answer about a prefix.
        }
        match input[i] {
            b'+' => {
                out[at] = b' ';
                i += 1;
            }
            b'%' => {
                let (Some(hi), Some(lo)) = (
                    input.get(i + 1).copied().and_then(hex_nibble),
                    input.get(i + 2).copied().and_then(hex_nibble),
                ) else {
                    return 0;
                };
                out[at] = (hi << 4) | lo;
                i += 3;
            }
            byte => {
                out[at] = byte;
                i += 1;
            }
        }
        at += 1;
    }
    at
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Answer without having sent anything to `token_mint`.
///
/// # Safety
///
/// As `drain_mint_replies`.
unsafe fn refuse(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    status: u16,
    body: &[u8],
) {
    respond(s, sys, conn, stream, status, b"application/json", body);
}

/// Emit one `HttpResponse`.
///
/// # Safety
///
/// As `drain_mint_replies`.
unsafe fn respond(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    status: u16,
    content_type: &[u8],
    body: &[u8],
) {
    let total = RESP_HDR + content_type.len() + body.len();
    if total > s.out.len() {
        return;
    }
    s.out[0..2].copy_from_slice(&conn.to_le_bytes());
    s.out[2..4].copy_from_slice(&stream.to_le_bytes());
    s.out[4..6].copy_from_slice(&status.to_le_bytes());
    s.out[6] = 0; // flags: a complete body in one envelope
    #[expect(
        clippy::cast_possible_truncation,
        reason = "content types here are short literals"
    )]
    {
        s.out[7] = content_type.len() as u8;
    }
    s.out[8..10].copy_from_slice(&0u16.to_le_bytes());
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by the `total > s.out.len()` check above"
    )]
    {
        s.out[10..12].copy_from_slice(&(body.len() as u16).to_le_bytes());
    }
    s.out[RESP_HDR..RESP_HDR + content_type.len()].copy_from_slice(content_type);
    s.out[RESP_HDR + content_type.len()..total].copy_from_slice(body);

    (sys.channel_write)(s.out_responses, s.out.as_ptr(), total);
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

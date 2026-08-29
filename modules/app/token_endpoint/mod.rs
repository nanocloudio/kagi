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
//! Authorization: DPoP <device certificate>
//! DPoP: <proof>
//!
//! grant_type=client_credentials&scope=read
//! ```
//!
//! **The caller does not name the subject or the key binding.** Both are read
//! out of the device certificate it presented, and a request that tries to
//! name either is refused rather than quietly overruled — a client that
//! learns its `sub=` was ignored fixes its code, where one that is silently
//! corrected never finds out.
//!
//! Admission is three facts, in this order:
//!
//! 1. The presenter holds a device certificate this issuer signed, it is
//!    inside its window, and the DPoP proof is bound to this request and
//!    signed by the key the certificate names (`device_auth`).
//! 2. The ledger holds that device.
//! 3. The ledger does not hold it as revoked.
//!
//! The third is why minting talks to the ledger at all. The short-lived
//! credential model only bounds exposure after a revocation if the mint
//! refuses to keep issuing — a relying party validating locally cannot know
//! what the issuer has since been told.

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

// ed25519 references Sha512 (sha384.rs) and helpers from p256.rs, and p256
// pulls in hmac + both hash widths, so the include set is the full chain.
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha384.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/hmac.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/p256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/ed25519.rs");

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/b64.rs"]
mod b64;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/dpop.rs"]
mod dpop;
#[path = "../../common/jose.rs"]
mod jose;
#[path = "../../common/jwk.rs"]
mod jwk;
#[path = "../../common/time_policy.rs"]
mod time_policy;

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
/// Longest credential or DPoP proof lifted out of a header and forwarded.
///
/// It has to hold a real compact JWS, or the presentation is truncated on
/// its way to admission — which fails to verify, for a reason nothing on the
/// wire would show.
const MAX_PRESENTED: usize = 2048;
/// Longest token a reply may carry back.
const MAX_TOKEN: usize = 4096;
/// WCET bound: requests translated per step.
const MAX_REQS_PER_STEP: usize = 4;
/// WCET bound: mint replies rendered per step.
const MAX_REPLIES_PER_STEP: usize = 4;

/// Default lifetime, in seconds, when a request names none.
const DEFAULT_TTL_SECS: u32 = 300;

/// Longest one-time code accepted from the form.
///
/// Bounded here as well as at the authenticator: a field this module copies
/// into a fixed buffer is one it has to bound, whatever the thing that
/// eventually reads it decides.
const MAX_OTP: usize = 8;

/// One request waiting for its token.
#[derive(Clone, Copy)]
struct Pending {
    corr: u32,
    conn: u16,
    stream: u16,
    /// `STAGE_ADMIT` while admission is deciding, `STAGE_MINT` once the
    /// mint has the request.
    stage: u8,
    /// The facts the certificate authorised, carried across the ledger round
    /// trip so the mint request is built from what was verified rather than
    /// from anything re-read afterwards.
    sub: [u8; MAX_FIELD],
    sub_len: u16,
    jkt: [u8; 43],
    jkt_len: u8,
    /// What admission established the presenter proved, carried to the mint
    /// so the token says how it was obtained. This module does not derive
    /// it: admission is the stage that saw both the enrolment record and the
    /// proof, and a second derivation here could disagree with it.
    evidence: auth_wire::assurance::EvidenceWire,
    aud: [u8; MAX_FIELD],
    aud_len: u16,
    scope: [u8; MAX_FIELD],
    scope_len: u16,
    ttl: u32,
    device_id: [u8; MAX_FIELD],
    device_id_len: u16,
    /// `false` marks the slot free. A generation counter would be better
    /// against reuse, but the correlation id already is one: it only
    /// increments, so a stale reply finds no slot rather than the wrong one.
    live: bool,
}

impl Pending {
    const fn zero() -> Self {
        Self {
            corr: 0,
            conn: 0,
            stream: 0,
            stage: STAGE_ADMIT,
            sub: [0u8; MAX_FIELD],
            sub_len: 0,
            jkt: [0u8; 43],
            jkt_len: 0,
            evidence: auth_wire::assurance::EvidenceWire {
                methods: 0,
                key_binding: 0,
                flags: 0,
                auth_time: 0,
            },
            aud: [0u8; MAX_FIELD],
            aud_len: 0,
            scope: [0u8; MAX_FIELD],
            scope_len: 0,
            ttl: 0,
            device_id: [0u8; MAX_FIELD],
            device_id_len: 0,
            live: false,
        }
    }
}

/// Waiting on admission's verdict.
const STAGE_ADMIT: u8 = 0;
/// Waiting on the mint.
const STAGE_MINT: u8 = 1;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,   // in[0]:  HttpRequest
    out_responses: i32, // out[0]: HttpResponse
    out_mint: i32,      // out[1]: MSG_MINT_REQ
    in_mint: i32,       // in[1]:  MSG_MINT_RESP

    /// Monotonic; the correlation id a mint reply is matched by.
    next_corr: u32,
    out_admit: i32,
    in_admit: i32,

    pending: [Pending; MAX_IN_FLIGHT],

    /// The issuer and algorithm every minted token carries. Graph
    /// parameters, because they describe this deployment rather than this
    /// request — a caller that could name its own issuer could mint a token
    /// claiming to come from somebody else.
    iss: [u8; MAX_FIELD],
    iss_len: u16,
    /// The credential suite minted tokens are signed under, from
    /// `auth_wire::suite`.
    suite: u16,

    token_issued: u32,
    token_refused: u32,
    token_malformed: u32,
    token_in_flight_full: u32,
    token_unauthenticated: u32,
    token_unknown_device: u32,
    token_revoked: u32,
    token_caller_authority: u32,
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

    // A credential suite id (`auth_wire::suite`). Defaults to Ed25519,
    // which is what the `alg` parameter this replaced defaulted to — a
    // changed default would silently re-point every graph that never set
    // it, and the mint would then refuse every request as an unpermitted
    // suite.
    2, suite, u32, 2 => |s, d, len| {
        if len >= 1 {
            s.suite = u16::from(*d);
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
        s.pending = [Pending::zero(); MAX_IN_FLIGHT];
        s.out_admit = dev_channel_port(sys, 1, 2);
        s.in_admit = dev_channel_port(sys, 0, 3);
        s.iss = [0; MAX_FIELD];
        s.iss_len = 0;
        s.suite = auth_wire::suite::ED25519;
        s.token_issued = 0;
        s.token_refused = 0;
        s.token_malformed = 0;
        s.token_in_flight_full = 0;
        s.token_unauthenticated = 0;
        s.token_unknown_device = 0;
        s.token_revoked = 0;
        s.token_caller_authority = 0;
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
        // Ledger replies before mint replies before new requests, so a
        // request that can advance a stage this step does.
        let mut worked = drain_admit(s, sys);
        worked |= drain_mint_replies(s, sys);

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

        let Ok(resp) = auth_wire::MintResponse::decode(&buf[..plen as usize]) else {
            s.token_malformed = s.token_malformed.saturating_add(1);
            continue;
        };
        let (corr, status, token) = (resp.correlation, resp.status, resp.body);
        // Only an inline credential is a token this endpoint can hand back.
        // A handle would need a fetch, which this endpoint has no store port
        // for — so it refuses rather than returning an object key to a
        // client that would treat it as a bearer token.
        let status =
            if status == auth_wire::mint_err::OK && resp.delivery != auth_wire::delivery::INLINE {
                auth_wire::mint_err::TOO_LARGE
            } else {
                status
            };

        let Some(slot) = take_pending(s, corr) else {
            // A reply for a request nobody is waiting on: a duplicate, or one
            // whose connection went away. Dropping it is right — answering a
            // reused connection with somebody else's token would be worse
            // than answering nothing.
            s.token_unmatched_reply = s.token_unmatched_reply.saturating_add(1);
            continue;
        };

        if status == auth_wire::mint_err::OK && !token.is_empty() && token.len() <= MAX_TOKEN {
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

    // ── the caller does not get to name the authority ────────────────────
    //
    // Refused, not ignored. A request carrying `sub=` used to be honoured;
    // silently dropping it now would leave a client believing it still chose
    // the subject, and the next person to read the code would have to guess
    // which behaviour was intended.
    {
        let body = &s.buf[body_at..body_end];
        let mut scratch = [0u8; MAX_FIELD];
        if form_value(body, b"sub", &mut scratch) != 0
            || form_value(body, b"jkt", &mut scratch) != 0
        {
            s.token_caller_authority = s.token_caller_authority.saturating_add(1);
            refuse(
                s,
                sys,
                conn,
                stream,
                400,
                br#"{"error":"invalid_request","detail":"authority_not_caller_selected"}"#,
            );
            return;
        }
    }

    let mut aud = [0u8; MAX_FIELD];
    let mut scope = [0u8; MAX_FIELD];
    // A one-time code, when the caller has a second factor to present. It is
    // carried across untouched: this module does not know what an
    // authenticator is, and admission — which reads the device record — is
    // the only thing that could check one.
    let mut otp = [0u8; MAX_OTP];
    let (aud_len, scope_len, ttl, otp_len) = {
        let body = &s.buf[body_at..body_end];
        (
            form_value(body, b"aud", &mut aud),
            form_value(body, b"scope", &mut scope),
            form_u32(body, b"expires_in").unwrap_or(DEFAULT_TTL_SECS),
            form_value(body, b"otp", &mut otp),
        )
    };

    // ── who is asking ────────────────────────────────────────────────────
    //
    // Not decided here. The credential and the DPoP proof are lifted out of
    // the headers — this module's job, because they arrived over HTTP — and
    // handed to `mint_admission`, which owns the three facts that decide
    // whether anyone may mint and for whom.
    //
    // **Nothing this module reads from the request can influence that
    // answer.** The subject, device and key binding come back from
    // admission, derived from the certificate; the form's `aud`, `scope` and
    // `ttl` travel across untouched and are only ever narrowed by the mint.
    // A request naming its own `sub` or `jkt` was refused above, before any
    // of this.
    let mut credential = [0u8; MAX_PRESENTED];
    let mut proof = [0u8; MAX_PRESENTED];
    let (credential_len, proof_len) = {
        let headers = &s.buf[REQ_HDR + path_len..body_at];
        (
            header_value(headers, b"authorization")
                .and_then(strip_dpop_scheme)
                .map_or(0, |v| copy_into(v, &mut credential)),
            header_value(headers, b"dpop").map_or(0, |v| copy_into(v, &mut proof)),
        )
    };
    if credential_len == 0 || proof_len == 0 {
        // Refused here rather than sent on as an empty presentation:
        // `AdmitRequest` refuses one at decode, so forwarding would spend a
        // round trip to be told what is already known.
        s.token_unauthenticated = s.token_unauthenticated.saturating_add(1);
        refuse(s, sys, conn, stream, 401, UNAUTHORIZED_BODY);
        return;
    }

    if s.out_admit < 0 {
        // No admission, no mint. Issuing here would mean issuing without
        // anyone having decided who the caller is.
        refuse(s, sys, conn, stream, 503, UNAVAILABLE_BODY);
        return;
    }

    let uri_len = path_len.min(MAX_FIELD);
    let mut uri = [0u8; MAX_FIELD];
    uri[..uri_len].copy_from_slice(&s.buf[REQ_HDR..REQ_HDR + uri_len]);

    let mut entry = Pending::zero();
    entry.conn = conn;
    entry.stream = stream;
    entry.stage = STAGE_ADMIT;
    entry.ttl = ttl;
    entry.aud[..aud_len].copy_from_slice(&aud[..aud_len]);
    entry.scope[..scope_len].copy_from_slice(&scope[..scope_len]);
    #[expect(clippy::cast_possible_truncation, reason = "each bounded by MAX_FIELD")]
    {
        entry.aud_len = aud_len as u16;
        entry.scope_len = scope_len as u16;
    }

    let corr = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);
    entry.corr = corr;

    let ask = auth_wire::AdmitRequest {
        corr,
        method: b"POST",
        uri: &uri[..uri_len],
        credential: &credential[..credential_len],
        proof: &proof[..proof_len],
        otp: &otp[..otp_len],
    };
    let mut framed = [0u8; 4096];
    let Ok(n) = ask.encode(&mut framed) else {
        refuse(s, sys, conn, stream, 503, UNAVAILABLE_BODY);
        return;
    };
    let Ok((wire_type, payload)) = auth_wire::read_envelope(&framed[..n]) else {
        refuse(s, sys, conn, stream, 503, UNAVAILABLE_BODY);
        return;
    };
    let Some(index) = free_slot(s) else {
        s.token_in_flight_full = s.token_in_flight_full.saturating_add(1);
        refuse(s, sys, conn, stream, 503, UNAVAILABLE_BODY);
        return;
    };
    if chan::channel_write_msg(sys, s.out_admit, wire_type, payload) <= 0 {
        refuse(s, sys, conn, stream, 503, UNAVAILABLE_BODY);
        return;
    }
    entry.live = true;
    s.pending[index] = entry;
}

/// Drain ledger replies: decide whether the device may still be minted for,
/// and if so send the mint request.
///
/// # Safety
///
/// Take admission's verdicts and either mint or answer.
///
/// **The status mapping lives here and not in `mint_admission`**, and that
/// is the point of a typed verdict: admission says what it refused, and each
/// caller says what that means in its own protocol. An HTTP endpoint turns
/// "the ledger is unreachable" into 503 and "this proof was replayed" into
/// 401; something speaking a different protocol would map the same verdicts
/// differently, and neither has to teach admission about the other.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn drain_admit(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    let mut worked = false;
    if s.in_admit < 0 {
        return worked;
    }
    while chan::can_read(sys, s.in_admit) {
        let mut buf = [0u8; 1024];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_admit, &mut buf);
        if msg_type == 0 {
            break;
        }
        if msg_type != auth_wire::MSG_ADMIT_RESP {
            continue;
        }
        let Ok(verdict) = auth_wire::AdmitResponse::decode(&buf[..plen as usize]) else {
            continue;
        };
        let Some(index) = s
            .pending
            .iter()
            .position(|p| p.live && p.stage == STAGE_ADMIT && p.corr == verdict.corr)
        else {
            s.token_unmatched_reply = s.token_unmatched_reply.saturating_add(1);
            continue;
        };
        worked = true;
        let mut entry = s.pending[index];
        s.pending[index] = Pending::zero();

        if verdict.status != auth_wire::admit_err::OK {
            let (status, body) = match verdict.status {
                // Refusals OF the presenter. 401 in every case, deliberately
                // undifferentiated on the wire: telling a caller whether it
                // failed authentication, is unknown, or is revoked answers a
                // question it has not earned the right to ask. The counters
                // keep them apart for an operator.
                auth_wire::admit_err::UNAUTHENTICATED
                | auth_wire::admit_err::STALE_PROOF
                | auth_wire::admit_err::REPLAY => {
                    s.token_unauthenticated = s.token_unauthenticated.saturating_add(1);
                    (401, UNAUTHORIZED_BODY)
                }
                auth_wire::admit_err::UNKNOWN_DEVICE => {
                    s.token_unknown_device = s.token_unknown_device.saturating_add(1);
                    (401, UNAUTHORIZED_BODY)
                }
                auth_wire::admit_err::REVOKED => {
                    s.token_revoked = s.token_revoked.saturating_add(1);
                    (401, UNAUTHORIZED_BODY)
                }
                auth_wire::admit_err::NOT_PERMITTED => {
                    s.token_refused = s.token_refused.saturating_add(1);
                    (403, UNAUTHORIZED_BODY)
                }
                // NOT refusals of the presenter: nothing looked at them.
                // Reporting these as 401 would tell a caller its credential
                // was rejected when the deployment simply could not decide.
                _ => {
                    s.token_refused = s.token_refused.saturating_add(1);
                    (503, UNAVAILABLE_BODY)
                }
            };
            refuse(s, sys, entry.conn, entry.stream, status, body);
            continue;
        }

        // Admitted. The subject and key binding are admission's, copied
        // verbatim — this module has no way to reach them otherwise, which
        // is what makes "the caller cannot name its own subject" structural
        // rather than a check someone has to remember.
        let sub_len = verdict.sub.len().min(MAX_FIELD);
        entry.sub[..sub_len].copy_from_slice(&verdict.sub[..sub_len]);
        let device_len = verdict.device_id.len().min(MAX_FIELD);
        entry.device_id[..device_len].copy_from_slice(&verdict.device_id[..device_len]);
        let jkt_len = verdict.jkt.len().min(entry.jkt.len());
        entry.jkt[..jkt_len].copy_from_slice(&verdict.jkt[..jkt_len]);
        entry.evidence = verdict.evidence;
        #[expect(clippy::cast_possible_truncation, reason = "each bounded above")]
        {
            entry.sub_len = sub_len as u16;
            entry.device_id_len = device_len as u16;
            entry.jkt_len = jkt_len as u8;
        }
        dispatch_mint(s, sys, &entry);
    }
    worked
}

/// Send the mint request for an admitted device.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn dispatch_mint(s: &mut ModuleState, sys: &SyscallTable, entry: &Pending) {
    if !chan::can_write(sys, s.out_mint) {
        s.token_in_flight_full = s.token_in_flight_full.saturating_add(1);
        refuse(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        return;
    }
    let corr = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);

    // `MintRequest::encode` writes the whole envelope, so this goes out with
    // the raw channel write: handing it to `channel_write_msg` would wrap an
    // envelope in a second one and the mint would read its correlation id out
    // of the framing.
    // The assurance claims, rendered by the shared fragment so this path and
    // the grant path emit the same three claims from the same scoring.
    let evidence = auth_wire::assurance::Evidence::decode(entry.evidence);
    let mut amr = [0u8; auth_wire::assurance::Evidence::MAX_AMR_JSON];
    let amr_len = evidence.write_amr(&mut amr).unwrap_or(0);
    let extra = [
        auth_wire::MintClaim {
            key: b"amr",
            value: auth_wire::MintClaimValue::Raw(&amr[..amr_len]),
        },
        auth_wire::MintClaim {
            key: b"acr",
            value: auth_wire::MintClaimValue::Str(evidence.acr().as_bytes()),
        },
        auth_wire::MintClaim {
            key: b"auth_time",
            value: auth_wire::MintClaimValue::U64(evidence.auth_time()),
        },
    ];

    let mut framed = [0u8; 4096];
    let request = MintRequest {
        correlation: corr,
        request_type: auth_wire::request_type::MINT,
        suite: s.suite,
        profile_id: auth_wire::suite::profile::ACCESS_TOKEN,
        // Empty: mint the profile's ACTIVE key. A caller pinning a kid here
        // would defeat rotation for every token this endpoint issues.
        kid: b"",
        ttl_seconds: entry.ttl,
        iss: &s.iss[..usize::from(s.iss_len)],
        sub: &entry.sub[..usize::from(entry.sub_len)],
        aud: &entry.aud[..usize::from(entry.aud_len)],
        scope: &entry.scope[..usize::from(entry.scope_len)],
        // Always bound: the thumbprint came from the certificate, and a token
        // minted here without a `cnf` would be a bearer token.
        thumbprint_alg: auth_wire::suite::thumbprint::JWK_SHA256,
        jkt: Some(&entry.jkt),
        extra: ExtraClaims::Slice(&extra),
    };
    let Ok(n) = request.encode(&mut framed) else {
        refuse(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        return;
    };
    let Some(index) = free_slot(s) else {
        s.token_in_flight_full = s.token_in_flight_full.saturating_add(1);
        refuse(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        return;
    };
    if (sys.channel_write)(s.out_mint, framed.as_ptr(), n) < n as i32 {
        s.token_in_flight_full = s.token_in_flight_full.saturating_add(1);
        refuse(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        return;
    }
    let mut next = *entry;
    next.stage = STAGE_MINT;
    next.corr = corr;
    next.live = true;
    s.pending[index] = next;
}

/// The `Sha256Fn` shape the fragments take, over the SDK's hasher.
fn sha256_into(data: &[u8], out: &mut [u8; 32]) {
    *out = sha256(data);
}

/// A header value by lowercase name.
fn header_value<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut at = 0usize;
    while at < headers.len() {
        let end = headers[at..]
            .iter()
            .position(|b| *b == b'\n')
            .map_or(headers.len(), |p| at + p);
        let line = &headers[at..end];
        if let Some(colon) = line.iter().position(|b| *b == b':') {
            let (key, value) = line.split_at(colon);
            if key.len() == name.len()
                && key
                    .iter()
                    .zip(name)
                    .all(|(a, b)| a.to_ascii_lowercase() == *b)
            {
                return Some(trim(&value[1..]));
            }
        }
        at = end + 1;
    }
    None
}

/// Strip the `DPoP ` scheme from an `Authorization` value.
fn strip_dpop_scheme(value: &[u8]) -> Option<&[u8]> {
    let scheme = b"DPoP ";
    if value.len() > scheme.len() && value[..scheme.len()].eq_ignore_ascii_case(scheme) {
        Some(trim(&value[scheme.len()..]))
    } else {
        None
    }
}

fn copy_into(value: &[u8], out: &mut [u8]) -> usize {
    let n = value.len().min(out.len());
    out[..n].copy_from_slice(&value[..n]);
    if value.len() > out.len() {
        0
    } else {
        n
    }
}

fn trim(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = bytes.split_last() {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

/// The bodies the refusals above carry.
const UNAUTHORIZED_BODY: &[u8] = br#"{"error":"invalid_client"}"#;
const UNAVAILABLE_BODY: &[u8] = br#"{"error":"temporarily_unavailable"}"#;

/// The first free pending slot.
fn free_slot(s: &ModuleState) -> Option<usize> {
    s.pending.iter().position(|slot| !slot.live)
}

/// Take the slot waiting on `corr`, freeing it.
fn take_pending(s: &mut ModuleState, corr: u32) -> Option<Pending> {
    let index = s
        .pending
        .iter()
        // Stage-matched: a ledger round trip and a mint round trip draw from
        // the same correlation counter, and matching on the id alone would let
        // a mint reply claim a slot that is still waiting on the ledger.
        .position(|slot| slot.live && slot.stage == STAGE_MINT && slot.corr == corr)?;
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

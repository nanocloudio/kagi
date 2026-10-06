//! Token endpoint — the HTTP shape of a token request.
//!
//! Sits behind wave's `foundation/http` as an application, in front of
//! `mint_admission` and `token_mint`. It is a PROVIDER of the workspace
//! exchange contract toward the server — a request arrives on `request_in`,
//! its answer leaves on `response_out` — and a REQUESTER of the two typed
//! operations it drives: the presentation goes to admission on `admit_out`
//! (`MSG_ADMIT_REQ`, answered on `admit_in`), and an admitted request goes to
//! the mint on `mint_out` (`MSG_MINT_REQ`, answered on `mint_in`). When the
//! token comes back the endpoint answers the connection that asked with the
//! OAuth token response.
//!
//! **It does not mint.** The claims, the signing key and the algorithm stay in
//! `token_mint`, which is the module that already owns them. What is here is
//! only the translation: form fields in, JSON out, and the bookkeeping that
//! remembers which HTTP connection a mint reply belongs to.
//!
//! That bookkeeping is the whole substance of the module. An answer from
//! admission or the mint names only the exchange this endpoint opened for it,
//! so the pending table is what turns it back into a response on the right
//! connection. The table is fixed-size and a request that arrives with it
//! full is refused with 503 rather than queued: a queue with no bound is a
//! queue that answers the wrong connection once the ids wrap.
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

#[path = "../../common/http_endpoint.rs"]
mod http_endpoint;

use abi::contracts::exchange::{self as x, ExchangeId};

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
#[path = "../../common/typed_exchange.rs"]
mod typed_exchange;

use typed_exchange::Answer;

use auth_wire::{ExtraClaims, MintRequest, PayloadReader};

/// `module_step` return code for "did work, step me again".
const STEP_DID_WORK: i32 = 2;

/// The exchange contract's method byte for `POST`.
const METHOD_POST: u8 = x::METHOD_POST;

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
    /// The exchange this endpoint opened with admission or the mint, which
    /// the answer names.
    call: ExchangeId,
    /// The server's exchange, which the response is written on.
    id: ExchangeId,
    credit: u32,
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
    /// `false` marks the slot free. The call id is the generation: it only
    /// increments, so a stale answer finds no slot rather than the wrong one.
    live: bool,
}

impl Pending {
    const fn zero() -> Self {
        Self {
            call: ExchangeId::NONE,
            id: ExchangeId::NONE,
            credit: 0,
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
    in_requests: i32,   // in[0]:  ExchangeRequest from the server
    out_responses: i32, // out[0]: ExchangeResponse to the server
    out_mint: i32,      // out[1]: ExchangeRequest to token_mint
    in_mint: i32,       // in[1]:  ExchangeResponse from token_mint

    /// Monotonic; numbers the exchanges this endpoint opens with admission
    /// and the mint.
    next_call: u64,
    out_admit: i32, // out[2]: ExchangeRequest to mint_admission
    in_admit: i32,  // in[3]:  ExchangeResponse from mint_admission
    /// Admission or the mint reported its link DOWN and has not reported it
    /// UP. Every request waiting on it is answered 503, and new ones are
    /// refused until UP.
    admit_down: bool,
    mint_down: bool,

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

    /// Requests being collected: an exchange's body may be streamed, so a
    /// request is answered once its body is whole.
    exch: http_endpoint::Requests,
    /// One response or body-credit record owed to `out_responses`.
    ///
    /// The step loop places what is owed before it reads anything new, so a
    /// refused write holds the answer instead of losing it. See
    /// [`ExchangeOutbox`] for why silence is the worst way to fail.
    outbox: ExchangeOutbox,
    /// The one call owed to admission, and the one owed to the mint.
    admit_outbox: ExchangeOutbox,
    mint_outbox: ExchangeOutbox,

    buf: [u8; x::RECORD_MAX],
    out: [u8; x::RECORD_MAX],
    admit_buf: [u8; x::RECORD_MAX],
    mint_buf: [u8; x::RECORD_MAX],
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

#[expect(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "fluxor module ABI entry point: the runtime owns these pointers \
              and the signature is fixed by the contract"
)]
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
        s.exch = http_endpoint::Requests::new();
        s.outbox = ExchangeOutbox::new();
        s.out_mint = dev_channel_port(sys, 1, 1);
        s.in_mint = dev_channel_port(sys, 0, 1);

        s.next_call = 1;
        s.admit_down = false;
        s.mint_down = false;
        s.admit_outbox = ExchangeOutbox::new();
        s.mint_outbox = ExchangeOutbox::new();
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

        // What is already owed goes out first, and nothing new is read until
        // it has gone: every record read below ends in at most one answer or
        // one call, and one dropped on a refused write answers its request
        // with silence.
        if !clear(s, sys) {
            return 0;
        }
        fail_downed(s, sys);

        // Answers first: they free a pending slot, so a request arriving in
        // the same step may take it rather than being refused for a seat
        // that was about to be vacated. Admission before the mint before new
        // requests, so a request that can advance a stage this step does.
        let mut worked = drain_admit(s, sys);
        worked |= drain_mint_replies(s, sys);

        for _ in 0..MAX_REQS_PER_STEP {
            if !clear(s, sys) {
                break;
            }
            if !chan::can_read(sys, s.in_requests) {
                break;
            }
            // One exchange record per read: the edge is a mailbox.
            let n = (sys.channel_read)(s.in_requests, s.buf.as_mut_ptr(), s.buf.len());
            if n < x::HDR as i32 {
                break;
            }
            worked = true;
            // Disjoint fields: the collector and the read buffer are borrowed
            // separately so the record needs no copy.
            let outcome = {
                let ModuleState { exch, buf, .. } = &mut *s;
                exch.accept(buf.get(..n as usize).unwrap_or(&[]))
            };
            // Request-body credit the collector owes: the server forwards a
            // body only up to what this endpoint has granted.
            if let Some((gid, bytes)) = s.exch.take_grant() {
                if let Some(n) = http_endpoint::write_grant(&gid, bytes, &mut s.out) {
                    s.outbox.send(sys, s.out_responses, &s.out, n);
                }
            }
            // A refusal is still a decision, and the caller is owed it: an
            // endpoint that drops one answers with silence, which a client
            // cannot tell from a server that hung.
            if let Some((rid, why)) = s.exch.take_refusal() {
                respond(s, sys, &rid, 0, why.status(), b"", &[]);
            }
            if let Ok(Some(at)) = outcome {
                handle_request(s, sys, at);
            }
        }

        if worked {
            STEP_DID_WORK
        } else {
            0
        }
    }
}

/// Place what is owed on all three exchange ports. True when nothing is held.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn clear(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    let answers = s.outbox.flush(sys, s.out_responses, &s.out);
    let admits = s.admit_outbox.flush(sys, s.out_admit, &s.admit_buf);
    let mints = s.mint_outbox.flush(sys, s.out_mint, &s.mint_buf);
    answers && admits && mints
}

/// Open a call: the next id on `port`.
fn next_call(s: &mut ModuleState, port: i32) -> ExchangeId {
    let id = typed_exchange::call_id(s.next_call, port);
    s.next_call = s.next_call.wrapping_add(1);
    id
}

/// Answer 503 to every request waiting on a provider whose link went DOWN,
/// one at a time: the rest stay pending until a later step.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn fail_downed(s: &mut ModuleState, sys: &SyscallTable) {
    for index in 0..MAX_IN_FLIGHT {
        let slot = s.pending[index];
        let downed = (slot.stage == STAGE_ADMIT && s.admit_down)
            || (slot.stage == STAGE_MINT && s.mint_down);
        if !slot.live || !downed {
            continue;
        }
        if !clear(s, sys) {
            return;
        }
        s.pending[index] = Pending::zero();
        s.token_refused = s.token_refused.saturating_add(1);
        refuse(s, sys, &slot.id, slot.credit, 503, UNAVAILABLE_BODY);
    }
}

/// Render every mint answer that has arrived. Returns whether any did.
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
        if !clear(s, sys) {
            break;
        }
        if !chan::can_read(sys, s.in_mint) {
            break;
        }
        let n = (sys.channel_read)(s.in_mint, s.buf.as_mut_ptr(), s.buf.len());
        if n <= 0 {
            break;
        }
        worked = true;
        let record = s.buf;
        let (call, minted) = match typed_exchange::read_answer(&record[..n as usize]) {
            Answer::Message {
                id,
                msg_type: auth_wire::MSG_MINT_RESP,
                payload,
            } => (id, auth_wire::MintResponse::decode(payload).ok()),
            Answer::Message { id, .. } => (id, None),
            Answer::Failed { id, .. } => {
                // The mint ended the exchange without a verdict: nothing was
                // decided about the caller, so this is the deployment's 503.
                if let Some(slot) = take_pending(s, &id) {
                    s.token_refused = s.token_refused.saturating_add(1);
                    refuse(s, sys, &slot.id, slot.credit, 503, UNAVAILABLE_BODY);
                }
                continue;
            }
            Answer::Link { state } => {
                s.mint_down = state == x::link::DOWN;
                continue;
            }
            Answer::Ignored => continue,
        };
        let Some(slot) = take_pending(s, &call) else {
            // An answer for a request nobody is waiting on: a duplicate, or
            // one whose connection went away. Dropping it is right —
            // answering a reused connection with somebody else's token would
            // be worse than answering nothing.
            s.token_unmatched_reply = s.token_unmatched_reply.saturating_add(1);
            continue;
        };
        let Some(resp) = minted else {
            s.token_malformed = s.token_malformed.saturating_add(1);
            refuse(s, sys, &slot.id, slot.credit, 503, UNAVAILABLE_BODY);
            continue;
        };
        let (status, token) = (resp.status, resp.body);
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

        if status == auth_wire::mint_err::OK && !token.is_empty() && token.len() <= MAX_TOKEN {
            s.token_issued = s.token_issued.saturating_add(1);
            let mut body = [0u8; MAX_TOKEN + 128];
            let len = write_token_json(&mut body, token, slot.ttl);
            respond(
                s,
                sys,
                &slot.id,
                slot.credit,
                200,
                b"application/json",
                &body[..len],
            );
        } else {
            s.token_refused = s.token_refused.saturating_add(1);
            respond(
                s,
                sys,
                &slot.id,
                slot.credit,
                400,
                b"application/json",
                br#"{"error":"invalid_request"}"#,
            );
        }
    }
    worked
}

/// Take one collected request and send its presentation to admission.
///
/// # Safety
///
/// As `drain_mint_replies`.
unsafe fn handle_request(s: &mut ModuleState, sys: &SyscallTable, at: usize) {
    let Some(req) = s.exch.request(at) else {
        return;
    };
    let (id, credit, method) = (req.id, req.resp_credit, req.method);
    // Copied out of the collector so the handler can still take `&mut s`:
    // the request borrows the table, and answering borrows the module.
    let mut target_buf = [0u8; http_endpoint::MAX_TARGET];
    let path_len = req.target.len().min(target_buf.len());
    target_buf[..path_len].copy_from_slice(&req.target[..path_len]);
    let mut header_buf = [0u8; http_endpoint::MAX_HEADERS];
    let hdr_len = req.headers.len().min(header_buf.len());
    header_buf[..hdr_len].copy_from_slice(&req.headers[..hdr_len]);
    let mut body_buf = [0u8; http_endpoint::MAX_BODY];
    let body_len = req.body.len().min(body_buf.len());
    body_buf[..body_len].copy_from_slice(&req.body[..body_len]);
    s.exch.release(at);
    let path = &target_buf[..path_len];
    let headers = &header_buf[..hdr_len];
    let body = &body_buf[..body_len];

    if method != METHOD_POST {
        // RFC 6749 §3.2: the token endpoint takes POST. A GET carrying
        // credentials in a query string would put them in every log between
        // here and the caller.
        refuse(s, sys, &id, credit, 405, br#"{"error":"invalid_request"}"#);
        return;
    }

    // ── the caller does not get to name the authority ────────────────────
    //
    // Refused, not ignored. A request carrying `sub=` used to be honoured;
    // silently dropping it now would leave a client believing it still chose
    // the subject, and the next person to read the code would have to guess
    // which behaviour was intended.
    {
        let mut scratch = [0u8; MAX_FIELD];
        if form_value(body, b"sub", &mut scratch) != 0
            || form_value(body, b"jkt", &mut scratch) != 0
        {
            s.token_caller_authority = s.token_caller_authority.saturating_add(1);
            refuse(
                s,
                sys,
                &id,
                credit,
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
        refuse(s, sys, &id, credit, 401, UNAUTHORIZED_BODY);
        return;
    }

    if s.out_admit < 0 || s.in_admit < 0 || s.admit_down {
        // No admission, no mint. Issuing here would mean issuing without
        // anyone having decided who the caller is.
        refuse(s, sys, &id, credit, 503, UNAVAILABLE_BODY);
        return;
    }

    let uri_len = path_len.min(MAX_FIELD);
    let mut uri = [0u8; MAX_FIELD];
    uri[..uri_len].copy_from_slice(&path[..uri_len]);

    let mut entry = Pending::zero();
    entry.id = id;
    entry.credit = credit;
    entry.stage = STAGE_ADMIT;
    entry.ttl = ttl;
    entry.aud[..aud_len].copy_from_slice(&aud[..aud_len]);
    entry.scope[..scope_len].copy_from_slice(&scope[..scope_len]);
    #[expect(clippy::cast_possible_truncation, reason = "each bounded by MAX_FIELD")]
    {
        entry.aud_len = aud_len as u16;
        entry.scope_len = scope_len as u16;
    }

    let Some(index) = free_slot(s) else {
        s.token_in_flight_full = s.token_in_flight_full.saturating_add(1);
        refuse(s, sys, &id, credit, 503, UNAVAILABLE_BODY);
        return;
    };
    let call = next_call(s, s.out_admit);
    entry.call = call;

    let ask = auth_wire::AdmitRequest {
        method: b"POST",
        uri: &uri[..uri_len],
        credential: &credential[..credential_len],
        proof: &proof[..proof_len],
        otp: &otp[..otp_len],
    };
    let sealed = ask
        .encode(&mut s.admit_buf[typed_exchange::CALL_AT..])
        .ok()
        .and_then(|n| typed_exchange::seal_call(&call, n, &mut s.admit_buf));
    let Some(n) = sealed else {
        refuse(s, sys, &id, credit, 503, UNAVAILABLE_BODY);
        return;
    };
    // Placed now or held for the next step: the call is owed either way.
    s.admit_outbox.send(sys, s.out_admit, &s.admit_buf, n);
    entry.live = true;
    s.pending[index] = entry;
}

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
    while clear(s, sys) && chan::can_read(sys, s.in_admit) {
        let n = (sys.channel_read)(s.in_admit, s.buf.as_mut_ptr(), s.buf.len());
        if n <= 0 {
            break;
        }
        let record = s.buf;
        let (call, verdict) = match typed_exchange::read_answer(&record[..n as usize]) {
            Answer::Message {
                id,
                msg_type: auth_wire::MSG_ADMIT_RESP,
                payload,
            } => (id, auth_wire::AdmitResponse::decode(payload).ok()),
            Answer::Message { id, .. } | Answer::Failed { id, .. } => (id, None),
            Answer::Link { state } => {
                s.admit_down = state == x::link::DOWN;
                continue;
            }
            Answer::Ignored => continue,
        };
        let Some(index) = s
            .pending
            .iter()
            .position(|p| p.live && p.stage == STAGE_ADMIT && p.call == call)
        else {
            s.token_unmatched_reply = s.token_unmatched_reply.saturating_add(1);
            continue;
        };
        worked = true;
        let mut entry = s.pending[index];
        s.pending[index] = Pending::zero();

        // Admission ended the exchange without a verdict: nothing decided
        // anything about the presenter, so this is the deployment's 503.
        let Some(verdict) = verdict else {
            s.token_refused = s.token_refused.saturating_add(1);
            refuse(s, sys, &entry.id, entry.credit, 503, UNAVAILABLE_BODY);
            continue;
        };

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
            refuse(s, sys, &entry.id, entry.credit, status, body);
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
    if s.out_mint < 0 || s.in_mint < 0 || s.mint_down {
        s.token_in_flight_full = s.token_in_flight_full.saturating_add(1);
        refuse(s, sys, &entry.id, entry.credit, 503, UNAVAILABLE_BODY);
        return;
    }
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

    let iss = s.iss;
    let request = MintRequest {
        request_type: auth_wire::request_type::MINT,
        suite: s.suite,
        profile_id: auth_wire::suite::profile::ACCESS_TOKEN,
        // Empty: mint the profile's ACTIVE key. A caller pinning a kid here
        // would defeat rotation for every token this endpoint issues.
        kid: b"",
        ttl_seconds: entry.ttl,
        iss: &iss[..usize::from(s.iss_len)],
        sub: &entry.sub[..usize::from(entry.sub_len)],
        aud: &entry.aud[..usize::from(entry.aud_len)],
        scope: &entry.scope[..usize::from(entry.scope_len)],
        // Always bound: the thumbprint came from the certificate, and a token
        // minted here without a `cnf` would be a bearer token.
        thumbprint_alg: auth_wire::suite::thumbprint::JWK_SHA256,
        jkt: Some(&entry.jkt),
        extra: ExtraClaims::Slice(&extra),
    };
    let Some(index) = free_slot(s) else {
        s.token_in_flight_full = s.token_in_flight_full.saturating_add(1);
        refuse(s, sys, &entry.id, entry.credit, 503, UNAVAILABLE_BODY);
        return;
    };
    let call = next_call(s, s.out_mint);
    let sealed = request
        .encode(&mut s.mint_buf[typed_exchange::CALL_AT..])
        .ok()
        .and_then(|n| typed_exchange::seal_call(&call, n, &mut s.mint_buf));
    let Some(n) = sealed else {
        refuse(s, sys, &entry.id, entry.credit, 503, UNAVAILABLE_BODY);
        return;
    };
    // Placed now or held for the next step: the call is owed either way.
    s.mint_outbox.send(sys, s.out_mint, &s.mint_buf, n);
    let mut next = *entry;
    next.stage = STAGE_MINT;
    next.call = call;
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

/// Take the slot waiting on mint call `call`, freeing it.
fn take_pending(s: &mut ModuleState, call: &ExchangeId) -> Option<Pending> {
    let index = s
        .pending
        .iter()
        // Stage-matched: an admission call and a mint call draw from the same
        // counter, and matching on the id alone would let a mint answer claim
        // a slot that is still waiting on admission.
        .position(|slot| slot.live && slot.stage == STAGE_MINT && slot.call == *call)?;
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
    id: &ExchangeId,
    credit: u32,
    status: u16,
    body: &[u8],
) {
    respond(s, sys, id, credit, status, b"application/json", body);
}

/// Answer one request: a single response HEAD carrying the whole body.
///
/// # Safety
///
/// As `drain_mint_replies`.
unsafe fn respond(
    s: &mut ModuleState,
    sys: &SyscallTable,
    id: &ExchangeId,
    credit: u32,
    status: u16,
    content_type: &[u8],
    body: &[u8],
) {
    let Some(total) =
        http_endpoint::write_response(id, status, content_type, body, credit, &mut s.out)
    else {
        return;
    };
    s.outbox.send(sys, s.out_responses, &s.out, total);
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

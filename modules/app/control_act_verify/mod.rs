//! Control-act verify — offline verification of a signed control act
//! (`KCAC`) against the issuer's published keyset.
//!
//! A typed operation: a PROVIDER of the workspace exchange contract on
//! `request_in` / `response_out`. Each request body is one
//! `control_act::msg::VERIFY_REQ` envelope (`[record f16][declaration f16]`)
//! and each answer body one `VERIFY_RESP` envelope carrying the typed
//! verdict (`control_act::Verdict`): the act's actor, scope, target,
//! operation id, expected epoch and the record digest the traffic fabric stores as its
//! `provenance_digest`. Every verdict, refusals included, is a 200 exchange.
//!
//! Verifying keys arrive on `verify_key` as `MSG_KEY_ADD` records of the
//! `CONTROL_ACT` profile, the same lifecycle `token_verify` follows; until
//! one lands every request is answered `NoIssuerKey`. Nothing is fetched and
//! nothing is stored: the act is checked against the keys this module holds
//! and the clock it trusts, and the verdict is the whole of its output.

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

include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha384.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/hmac.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/p256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/ed25519.rs");

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/control_act.rs"]
mod control_act;
#[path = "../../common/time_policy.rs"]
mod time_policy;
#[path = "../../common/typed_exchange.rs"]
mod typed_exchange;
#[path = "../../common/verify_keyset.rs"]
mod verify_keyset;

use abi::contracts::exchange::{self as x, Collector, ExchangeId};
use control_act as ca;

/// WCET bound: request records taken per step (at most one signature each).
const MAX_REQS_PER_STEP: usize = 4;
/// Exchanges collected at once.
const MAX_EXCHANGES: usize = 4;
/// Longest target and header block held. Neither is read; they are bounded
/// so the module can sit behind an HTTP route as well as a pipeline.
const MAX_TARGET: usize = 256;
const MAX_HEADERS: usize = 1024;
/// Longest request body: one `VERIFY_REQ` envelope — a record and the
/// declaring payload it covers, which may be a whole `WHR1` route record.
const MAX_REQUEST: usize = x::PAYLOAD_MAX;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,   // in[0]:  ExchangeRequest, VERIFY_REQ bodies
    out_responses: i32, // out[0]: ExchangeResponse, VERIFY_RESP bodies
    in_key: i32,        // in[1]:  MSG_KEY_ADD and the rest of the lifecycle

    /// The keyset, indexed by `(issuer, profile_id, kid)`. More than one
    /// key, so a rotation keeps verifying acts signed under the outgoing
    /// key until its removal deadline.
    keys: verify_keyset::Keyset,

    // Metrics (names mirror manifest [observability])
    act_ok: u32,
    act_refused: u32,
    act_malformed: u32,
    no_key_errors: u32,

    requests: Collector<MAX_EXCHANGES, MAX_TARGET, MAX_HEADERS, MAX_REQUEST>,
    outbox: ExchangeOutbox,
    buf: [u8; x::RECORD_MAX],
    out: [u8; x::RECORD_MAX],
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
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of at least
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
        s.in_key = dev_channel_port(sys, 0, 1);
        s.requests = Collector::new();
        s.outbox = ExchangeOutbox::new();
        s.keys = verify_keyset::Keyset::new();
        s.act_ok = 0;
        s.act_refused = 0;
        s.act_malformed = 0;
        s.no_key_errors = 0;
        dev_log(sys, 3, b"[act-verify] init".as_ptr(), 17);
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

        drain_key_material(s, sys);

        for _ in 0..MAX_REQS_PER_STEP {
            if !s.outbox.flush(sys, s.out_responses, &s.out) {
                break;
            }
            if !chan::can_read(sys, s.in_requests) {
                break;
            }
            let n = (sys.channel_read)(s.in_requests, s.buf.as_mut_ptr(), s.buf.len());
            if n <= 0 {
                break;
            }
            let outcome = {
                let ModuleState { requests, buf, .. } = &mut *s;
                requests.accept(buf.get(..n as usize).unwrap_or(&[]))
            };
            if let Some((id, bytes)) = s.requests.take_grant() {
                if let Some(len) = x::write_credit(&id, bytes, &mut s.out) {
                    s.outbox.send(sys, s.out_responses, &s.out, len);
                }
            }
            if let Some((id, why)) = s.requests.take_refusal() {
                answer_status(s, sys, &id, why.status());
            }
            if let Ok(Some(at)) = outcome {
                handle_verify(s, sys, at);
            }
        }
        0
    }
}

/// Drain `verify_key`, keeping the key lifecycle into the keyset.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live syscall table.
unsafe fn drain_key_material(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_key < 0 {
        return;
    }
    for _ in 0..8 {
        if !chan::can_read(sys, s.in_key) {
            break;
        }
        let mut buf = [0u8; 4096];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_key, &mut buf);
        if msg_type == 0 {
            break;
        }
        let payload = &buf[..usize::from(plen)];
        s.keys.apply(msg_type, payload);
    }
}

/// The SDK's curves, by the credential suites' convention.
fn verify_suite(suite: u16, public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match suite {
        auth_wire::suite::ED25519 => match (public.try_into(), signature.try_into()) {
            (Ok(pk), Ok(sig)) => ed25519_verify(pk, message, sig),
            _ => false,
        },
        auth_wire::suite::ES256 => {
            public.len() == 65
                && signature.len() == 64
                && ecdsa_verify(public, &sha256(message), signature)
        }
        _ => false,
    }
}

fn sha256_into(data: &[u8], out: &mut [u8; 32]) {
    *out = sha256(data);
}

/// Verify the request the collector completed in slot `at`.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live syscall table.
unsafe fn handle_verify(s: &mut ModuleState, sys: &SyscallTable, at: usize) {
    let Some(request) = s.requests.request(at) else {
        return;
    };
    let id = request.id;
    let refused = typed_exchange::admissible(request.method, request.resp_credit);
    let body_len = request.body.len();
    let mut req_bytes = [0u8; MAX_REQUEST];
    req_bytes[..body_len].copy_from_slice(request.body);
    s.requests.release(at);
    if let Some(status) = refused {
        answer_status(s, sys, &id, status);
        return;
    }
    let Some((ca::msg::VERIFY_REQ, payload)) = typed_exchange::message(&req_bytes[..body_len])
    else {
        answer_status(s, sys, &id, x::status::BAD_REQUEST);
        return;
    };

    if s.keys.is_empty() {
        s.no_key_errors = s.no_key_errors.saturating_add(1);
        emit(s, sys, &id, &ca::Verdict::refused(ca::Refusal::NoIssuerKey));
        return;
    }

    // A window check against a clock that reads 0 concludes "not yet
    // expired" for every act ever signed, so no clock is a refusal.
    let obs = dev_trusted_unix(sys);
    let now_ms = if time_policy::now_for(time_policy::Decision::CredentialWindow, &obs).is_some() {
        dev_unix_millis(sys)
    } else {
        0
    };
    let now_secs = now_ms / 1000;
    let keys = &s.keys;
    let verdict = ca::decide_verify(
        sha256_into,
        verify_suite,
        |issuer, kid| lookup(keys, issuer, kid, now_secs),
        payload,
        now_ms,
    );
    match verdict.status {
        ca::STATUS_OK => s.act_ok = s.act_ok.saturating_add(1),
        c if c == ca::Refusal::Malformed.code() => {
            s.act_malformed = s.act_malformed.saturating_add(1);
        }
        _ => s.act_refused = s.act_refused.saturating_add(1),
    }
    emit(s, sys, &id, &verdict);
}

/// The `CONTROL_ACT` key `(issuer, kid)` names, if the keyset holds one
/// that is not past its removal deadline. An unknown kid is `None` and the
/// act is refused; it is never checked against some other key.
fn lookup<'k>(
    keys: &'k verify_keyset::Keyset,
    issuer: &[u8],
    kid: &[u8],
    now_secs: u64,
) -> Option<(u16, &'k [u8])> {
    keys.keys
        .iter()
        .find(|k| {
            k.live
                && k.profile_id == auth_wire::suite::profile::CONTROL_ACT
                && &k.issuer[..usize::from(k.issuer_len)] == issuer
                && k.kid_bytes() == kid
                && !(k.remove_after_unix != 0 && now_secs >= k.remove_after_unix)
        })
        .map(|k| (k.suite, k.pubkey_bytes()))
}

/// Answer with a `VERIFY_RESP`: a 200 whose body is the verdict envelope.
///
/// # Safety
///
/// As `handle_verify`.
unsafe fn emit(s: &mut ModuleState, sys: &SyscallTable, id: &ExchangeId, verdict: &ca::Verdict) {
    let mut payload = [0u8; ca::VERDICT_LEN];
    let Some(n) = verdict.encode(&mut payload) else {
        answer_status(s, sys, id, x::status::FAILED);
        return;
    };
    let Ok(len) = auth_wire::write_envelope(
        ca::msg::VERIFY_RESP,
        &payload[..n],
        &mut s.out[typed_exchange::ANSWER_AT..],
    ) else {
        answer_status(s, sys, id, x::status::FAILED);
        return;
    };
    if let Some(total) = typed_exchange::seal_answer(id, len, &mut s.out) {
        s.outbox.send(sys, s.out_responses, &s.out, total);
    }
}

/// Answer with a status alone: a request this operation did not read.
///
/// # Safety
///
/// As `handle_verify`.
unsafe fn answer_status(s: &mut ModuleState, sys: &SyscallTable, id: &ExchangeId, status: u16) {
    if let Some(n) = typed_exchange::write_status(id, status, &mut s.out) {
        s.outbox.send(sys, s.out_responses, &s.out, n);
    }
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

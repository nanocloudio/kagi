//! RSC verify — BYOIP ownership evidence: whether a tenant holds the prefix
//! it asks to import, proven with an RPKI Signed Checklist (RFC 9323) under
//! its resource holder's CA chain, every link against its issuer's CRL.
//!
//! A typed operation: a PROVIDER of the workspace exchange contract on
//! `request_in` / `response_out`. Each request body is one
//! `rsc_verify::msg::REQUEST` envelope and each answer body one `REPLY`
//! envelope; every verdict is a 200 exchange. One record carries less than
//! an anchor, a chain, its CRLs and a checklist together, so certificates
//! and CRLs are first put in a bounded cache (`CACHE`, answered with their
//! SHA-256) and a `VERIFY` names them by digest. The cache decides nothing:
//! the relying party names the anchor it pins in every `VERIFY`.
//!
//! The decision is `rsc_verify.rs` over `rpki.rs`, on the SDK's SHA-256 and
//! RSA. Validity is checked against the trusted wall clock
//! (`time_policy::Decision::CertificateValidity`); with none, every VERIFY
//! answers `NO_CLOCK`. No params, no keys: this module signs nothing.

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
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/rsa.rs");

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/rpki.rs"]
mod rpki;
#[path = "../../common/rsc_verify.rs"]
mod rsc_verify;
#[path = "../../common/time_policy.rs"]
mod time_policy;
#[path = "../../common/typed_exchange.rs"]
mod typed_exchange;

use abi::contracts::exchange::{self as x, Collector, ExchangeId};
use rsc_verify as rv;

const STEP_DID_WORK: i32 = 2;
/// A VERIFY runs up to a dozen RSA verifications: one request a step.
const MAX_REQS_PER_STEP: usize = 1;
const MAX_EXCHANGES: usize = 2;
const MAX_TARGET: usize = 256;
const MAX_HEADERS: usize = 1024;
/// Longest request body: a certificate, a CRL or a checklist.
const MAX_REQUEST: usize = x::PAYLOAD_MAX;

/// The SDK's crypto, its RSA job held in the module's state.
struct SdkCrypto<'a> {
    job: &'a mut RsaVerifyJob,
}

impl rpki::Crypto for SdkCrypto<'_> {
    fn sha256(&mut self, msg: &[u8]) -> [u8; 32] {
        sha256(msg)
    }

    fn rsa_ok(&mut self, rsa_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let Some(k) = rsa_public_key_parse(rsa_key) else {
            return false;
        };
        rsa_pkcs1_v15_verify(self.job, &k, RsaHash::Sha256, &sha256(msg), sig)
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    out_responses: i32,

    rsc_verified: u32,
    rsc_refused: u32,
    rsc_cached: u32,
    rsc_not_cached: u32,

    job: RsaVerifyJob,
    cache: rv::Cache,
    requests: Collector<MAX_EXCHANGES, MAX_TARGET, MAX_HEADERS, MAX_REQUEST>,
    outbox: ExchangeOutbox,
    body: [u8; MAX_REQUEST],
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
    // `module_state_size()` bytes and a `syscalls` table whose function
    // pointers reach live kernel routines. All-zero is the empty cache.
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
        s.rsc_verified = 0;
        s.rsc_refused = 0;
        s.rsc_cached = 0;
        s.rsc_not_cached = 0;
        core::ptr::write(&mut s.job, RsaVerifyJob::new());
        core::ptr::write_bytes(&mut s.cache, 0, 1);
        s.requests = Collector::new();
        s.outbox = ExchangeOutbox::new();
        dev_log(sys, 3, b"[rsc-verify] init".as_ptr(), 17);
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
        let mut worked = false;
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
            worked = true;
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
                handle(s, sys, at);
            }
        }
        if worked {
            STEP_DID_WORK
        } else {
            0
        }
    }
}

/// Answer one request.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live syscall table.
unsafe fn handle(s: &mut ModuleState, sys: &SyscallTable, at: usize) {
    let Some(request) = s.requests.request(at) else {
        return;
    };
    let id = request.id;
    let refused = typed_exchange::admissible(request.method, request.resp_credit);
    let body_len = request.body.len();
    s.body[..body_len].copy_from_slice(request.body);
    s.requests.release(at);
    if let Some(status) = refused {
        answer_status(s, sys, &id, status);
        return;
    }
    let mut reply = [0u8; rv::REPLY_MAX];
    let Some(n) = decide(s, sys, body_len, &mut reply) else {
        answer_status(s, sys, &id, x::status::BAD_REQUEST);
        return;
    };
    let Ok(len) = auth_wire::write_envelope(
        rv::msg::REPLY,
        &reply[..n],
        &mut s.out[typed_exchange::ANSWER_AT..],
    ) else {
        answer_status(s, sys, &id, x::status::FAILED);
        return;
    };
    if let Some(total) = typed_exchange::seal_answer(&id, len, &mut s.out) {
        s.outbox.send(sys, s.out_responses, &s.out, total);
    }
}

/// The reply to the request in `s.body[..body_len]`; `None` when the body
/// is not one REQUEST envelope.
///
/// # Safety
///
/// As `handle`.
unsafe fn decide(
    s: &mut ModuleState,
    sys: &SyscallTable,
    body_len: usize,
    reply: &mut [u8; rv::REPLY_MAX],
) -> Option<usize> {
    let ModuleState {
        body,
        cache,
        job,
        rsc_verified,
        rsc_refused,
        rsc_cached,
        rsc_not_cached,
        ..
    } = s;
    let Some((rv::msg::REQUEST, payload)) = typed_exchange::message(&body[..body_len]) else {
        return None;
    };
    Some(match rv::Request::decode(payload) {
        None => {
            reply[0] = payload.first().copied().unwrap_or(0);
            reply[1] = rv::status::MALFORMED;
            3
        }
        Some(rv::Request::Cache(der)) => {
            let digest = sha256(der);
            let st = if rv::cacheable(der) && cache.put(&digest, der) {
                *rsc_cached = rsc_cached.saturating_add(1);
                rv::status::OK
            } else {
                rv::status::NOT_CACHEABLE
            };
            rv::reply_cache(st, &digest, reply)
        }
        Some(rv::Request::Verify(v)) => {
            let obs = dev_trusted_unix(sys);
            let now_s = if time_policy::now_for(time_policy::Decision::CertificateValidity, &obs)
                .is_some()
            {
                dev_unix_millis(sys) / 1000
            } else {
                0
            };
            let mut c = SdkCrypto { job };
            let (st, refusal, e) = rv::answer_verify(&mut c, cache, &v, now_s);
            match st {
                rv::status::OK => *rsc_verified = rsc_verified.saturating_add(1),
                rv::status::NOT_CACHED => *rsc_not_cached = rsc_not_cached.saturating_add(1),
                _ => *rsc_refused = rsc_refused.saturating_add(1),
            }
            rv::reply_verify(st, refusal, &e, reply)
        }
    })
}

/// Answer with a status alone: a request this operation did not read.
///
/// # Safety
///
/// As `handle`.
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

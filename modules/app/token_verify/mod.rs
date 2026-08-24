//! Token Verify — ES256 / EdDSA JWS access-token verification.
//!
//! The on-target counterpart to `token_mint`: consumes MSG_VERIFY_REQ on
//! `verify_requests` and replies MSG_VERIFY_RESP on `results`. The
//! verifying key arrives on `verify_key` as MSG_VERIFY_KEY
//! (`[alg u8][kid_len u8][kid][pubkey_len u8][pubkey]` — the SEC1 public
//! point for ES256, the 32-byte RFC 8032 public key for Ed25519); until
//! one lands every request replies ST_NO_KEY. Tokens are split with the
//! shared `jose` fragment and checked with the SDK's deterministic
//! verifiers, so no runtime entropy is needed. A valid signature is then
//! range-checked against its `iat`/`exp` claims (60s skew) before ST_OK.

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

// Crypto primitives (crate-root include, mirroring token_mint). ed25519
// references Sha512 (sha384.rs) and helpers from p256.rs, and p256 pulls
// in hmac + both hash widths, so the include set is the full chain.
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
#[path = "../../common/jose.rs"]
mod jose;

use auth_wire::{PayloadReader, PayloadWriter};

/// SEC1 uncompressed P-256 points are 65 bytes — the widest key we store.
const MAX_PUBKEY_LEN: usize = 65;
/// Clock skew (seconds) tolerated on `iat` when range-checking claims.
const CLOCK_SKEW_SECS: u64 = 60;
/// Max decoded-claims payload returned on `ST_OK`. Bounds the `results`
/// port record (manifest `max_record`); a larger token payload fails
/// closed (`ST_EXPIRED`).
const MAX_CLAIMS_BYTES: usize = 1024;
/// WCET bound: verify requests handled per step (one signature each).
const MAX_REQS_PER_STEP: usize = 4;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32, // in[0]: MSG_VERIFY_REQ
    out_results: i32, // out[0]: MSG_VERIFY_RESP
    in_key: i32,      // in[1]: MSG_VERIFY_KEY

    /// SEC1 public point (ES256) or 32-byte public key (Ed25519).
    /// Valid iff `has_key`; interpreted per `key_alg`.
    pubkey: [u8; MAX_PUBKEY_LEN],
    pubkey_len: u8,
    /// `auth_wire::MINT_ALG_*` of the loaded key.
    key_alg: u8,
    has_key: bool,

    // Metrics (names mirror manifest [observability])
    verify_ok: u32,
    verify_bad_sig: u32,
    verify_expired: u32,
    verify_malformed: u32,
    no_key_errors: u32,

    msg_buf: [u8; 2048],
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
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
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
        s.out_results = out_chan;
        s.in_key = dev_channel_port(sys, 0, 1);

        s.pubkey = [0; MAX_PUBKEY_LEN];
        s.pubkey_len = 0;
        s.key_alg = 0;
        s.has_key = false;
        s.verify_ok = 0;
        s.verify_bad_sig = 0;
        s.verify_expired = 0;
        s.verify_malformed = 0;
        s.no_key_errors = 0;

        dev_log(sys, 3, b"[verify] init".as_ptr(), 13);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // Verifying-key updates first, so a same-step request uses the
        // latest key.
        drain_key_material(s, sys);

        for _ in 0..MAX_REQS_PER_STEP {
            if !chan::can_read(sys, s.in_requests) {
                break;
            }
            // Every request produces exactly one reply; don't consume a
            // request we cannot answer.
            if !chan::can_write(sys, s.out_results) {
                break;
            }
            let (msg_type, plen) = chan::channel_read_msg(sys, s.in_requests, &mut s.msg_buf);
            if msg_type != auth_wire::MSG_VERIFY_REQ {
                continue;
            }
            handle_verify(s, sys, plen as usize);
        }

        0
    }
}

/// Drain `verify_key`, keeping the latest valid MSG_VERIFY_KEY
/// (`[alg u8][kid_len u8][kid][pubkey_len u8][pubkey]`).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_key_material(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_key < 0 {
        return;
    }
    for _ in 0..4 {
        if !chan::can_read(sys, s.in_key) {
            break;
        }
        let mut buf = [0u8; 256];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_key, &mut buf);
        if msg_type != auth_wire::MSG_VERIFY_KEY {
            continue;
        }
        let mut r = PayloadReader::new(&buf[..plen as usize]);
        let (Ok(alg), Ok(_kid), Ok(pubkey)) = (r.u8(), r.field8(), r.field8()) else {
            continue;
        };
        // ES256 accepts a SEC1 point (33 compressed / 65 uncompressed);
        // Ed25519 wants exactly the 32-byte public key.
        let valid = match alg {
            auth_wire::MINT_ALG_ES256 => pubkey.len() == 33 || pubkey.len() == 65,
            auth_wire::MINT_ALG_ED25519 => pubkey.len() == 32,
            _ => false,
        };
        if !valid || pubkey.len() > MAX_PUBKEY_LEN {
            continue;
        }
        s.pubkey = [0; MAX_PUBKEY_LEN];
        s.pubkey[..pubkey.len()].copy_from_slice(pubkey);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "bounded by MAX_PUBKEY_LEN (65)"
        )]
        {
            s.pubkey_len = pubkey.len() as u8;
        }
        s.key_alg = alg;
        s.has_key = true;
    }
}

/// Handle one MSG_VERIFY_REQ payload sitting in `s.msg_buf[..plen]`:
/// `[corr u32][token f16]`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_verify(s: &mut ModuleState, sys: &SyscallTable, plen: usize) {
    if plen < 4 {
        // No correlation id — nowhere to address a reply.
        return;
    }
    let corr = u32::from_le_bytes([s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3]]);

    // A missing key is recoverable — the key may still arrive later — so
    // it is reported before any parse of the request body.
    if !s.has_key {
        s.no_key_errors = s.no_key_errors.saturating_add(1);
        reply(s, sys, corr, auth_wire::ST_NO_KEY, &[]);
        return;
    }

    let mut r = PayloadReader::new(&s.msg_buf[..plen]);
    let (Ok(_corr), Ok(token)) = (r.u32(), r.field16()) else {
        s.verify_malformed = s.verify_malformed.saturating_add(1);
        reply(s, sys, corr, auth_wire::ST_MALFORMED, &[]);
        return;
    };

    let Some(jws) = jose::Jws::split(token) else {
        s.verify_malformed = s.verify_malformed.saturating_add(1);
        reply(s, sys, corr, auth_wire::ST_MALFORMED, &[]);
        return;
    };

    // Raw 64-byte JWS signature (r||s for ES256, R||S for EdDSA).
    let mut sig = [0u8; 64];
    let sig_ok = b64::decode(jws.signature_b64, &mut sig) == Some(64);

    let alg = s.key_alg;
    let pubkey = &s.pubkey[..usize::from(s.pubkey_len)];
    let verified = sig_ok
        && match alg {
            auth_wire::MINT_ALG_ES256 => {
                let hash = sha256(jws.signing_input);
                ecdsa_verify(pubkey, &hash, &sig)
            }
            auth_wire::MINT_ALG_ED25519 => match pubkey.try_into() {
                Ok(pk32) => ed25519_verify(pk32, jws.signing_input, &sig),
                Err(_) => false,
            },
            _ => false,
        };
    if !verified {
        s.verify_bad_sig = s.verify_bad_sig.saturating_add(1);
        reply(s, sys, corr, auth_wire::ST_BAD_SIGNATURE, &[]);
        return;
    }

    // Signature is valid; now the token must be live. Decode the payload
    // segment and range-check its iat/exp. A missing claim reads as 0,
    // which `within_window` treats as out-of-window (fail closed). A
    // payload larger than the decode buffer (`b64::decode` → None) also
    // fails closed. On success the decoded claims are returned so the
    // caller can authorize on iss/aud/scope/custom claims.
    let mut payload_json = [0u8; MAX_CLAIMS_BYTES];
    let Some(payload_len) = b64::decode(jws.payload_b64, &mut payload_json) else {
        s.verify_expired = s.verify_expired.saturating_add(1);
        reply(s, sys, corr, auth_wire::ST_EXPIRED, &[]);
        return;
    };
    let json = &payload_json[..payload_len];
    let iat = jose::claim_u64(json, b"iat").unwrap_or(0);
    let exp = jose::claim_u64(json, b"exp").unwrap_or(0);
    let now = dev_unix_millis(sys) / 1000;
    if !jose::within_window(now, iat, exp, CLOCK_SKEW_SECS) {
        s.verify_expired = s.verify_expired.saturating_add(1);
        reply(s, sys, corr, auth_wire::ST_EXPIRED, &[]);
        return;
    }

    s.verify_ok = s.verify_ok.saturating_add(1);
    // `json` borrows `payload_json` (a local), disjoint from `s`.
    reply(s, sys, corr, auth_wire::ST_OK, json);
}

/// Emit MSG_VERIFY_RESP = `[corr u32][status u8][claims f16]`. `claims` is
/// the decoded JWS payload JSON on `ST_OK`, empty otherwise.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn reply(s: &mut ModuleState, sys: &SyscallTable, corr: u32, status: u8, claims: &[u8]) {
    // corr(4) + status(1) + f16 length(2) + claims.
    let mut payload = [0u8; 7 + MAX_CLAIMS_BYTES];
    let mut w = PayloadWriter::new(&mut payload);
    let _ = w.u32(corr);
    let _ = w.u8(status);
    let _ = w.field16(claims);
    let n = w.len();
    chan::channel_write_msg(
        sys,
        s.out_results,
        auth_wire::MSG_VERIFY_RESP,
        &payload[..n],
    );
}

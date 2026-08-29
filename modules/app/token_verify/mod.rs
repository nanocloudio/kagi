//! Token Verify — ES256 / EdDSA JWS access-token verification.
//!
//! The on-target counterpart to `token_mint`: consumes MSG_VERIFY_REQ on
//! `verify_requests` and replies MSG_VERIFY_RESP on `results`. The
//! verifying key arrives on `verify_key` as MSG_KEY_ADD
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
#[path = "../../common/time_policy.rs"]
mod time_policy;

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

const MAX_KID_LEN: usize = 64;
const MAX_ISSUER_LEN: usize = 64;
/// Verification keys held at once. Sized to match the mint's keyset: a
/// verifier that can hold fewer keys than the issuer can sign under would
/// reject live credentials and report an unknown kid.
const MAX_KEYS: usize = 8;

/// One verification key.
#[repr(C)]
#[derive(Clone, Copy)]
struct VerifyKey {
    live: bool,
    issuer: [u8; MAX_ISSUER_LEN],
    issuer_len: u8,
    profile_id: u16,
    kid: [u8; MAX_KID_LEN],
    kid_len: u8,
    suite: u16,
    state: u8,
    generation: u32,
    remove_after_unix: u64,
    pubkey: [u8; MAX_PUBKEY_LEN],
    pubkey_len: u8,
}

impl VerifyKey {
    const fn empty() -> Self {
        Self {
            live: false,
            issuer: [0; MAX_ISSUER_LEN],
            issuer_len: 0,
            profile_id: 0,
            kid: [0; MAX_KID_LEN],
            kid_len: 0,
            suite: 0,
            state: auth_wire::key_state::ADDED,
            generation: 0,
            remove_after_unix: 0,
            pubkey: [0; MAX_PUBKEY_LEN],
            pubkey_len: 0,
        }
    }
}

/// Copy a decoded record into a verification-key slot.
fn fill_key(slot: &mut VerifyKey, rec: &auth_wire::KeyRecord<'_>) -> bool {
    if rec.key_use != auth_wire::key_use::VERIFY {
        return false;
    }
    if !auth_wire::suite::is_implemented(rec.suite) {
        return false;
    }
    // ES256 accepts a SEC1 point (33 compressed / 65 uncompressed).
    let ok_len = match rec.suite {
        auth_wire::suite::ES256 => rec.key_ref.len() == 33 || rec.key_ref.len() == 65,
        auth_wire::suite::ED25519 => rec.key_ref.len() == 32,
        _ => false,
    };
    if !ok_len
        || rec.key_ref.len() > MAX_PUBKEY_LEN
        || rec.issuer.is_empty()
        || rec.issuer.len() > MAX_ISSUER_LEN
        || rec.kid.is_empty()
        || rec.kid.len() > MAX_KID_LEN
    {
        return false;
    }
    *slot = VerifyKey::empty();
    slot.live = true;
    slot.issuer[..rec.issuer.len()].copy_from_slice(rec.issuer);
    slot.kid[..rec.kid.len()].copy_from_slice(rec.kid);
    slot.pubkey[..rec.key_ref.len()].copy_from_slice(rec.key_ref);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "all three lengths bounded immediately above"
    )]
    {
        slot.issuer_len = rec.issuer.len() as u8;
        slot.kid_len = rec.kid.len() as u8;
        slot.pubkey_len = rec.key_ref.len() as u8;
    }
    slot.profile_id = rec.profile_id;
    slot.suite = rec.suite;
    slot.state = rec.state;
    slot.generation = rec.generation;
    slot.remove_after_unix = rec.remove_after_unix;
    true
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32, // in[0]: MSG_VERIFY_REQ
    out_results: i32, // out[0]: MSG_VERIFY_RESP
    in_key: i32,      // in[1]: MSG_KEY_ADD

    /// SEC1 public point (ES256) or 32-byte public key (Ed25519).
    /// The keyset, indexed by `(issuer, profile_id, kid)`.
    ///
    /// More than one key, which is what makes rotation possible: a token
    /// signed under a retired key keeps verifying until that key's removal
    /// deadline, so credentials already in flight are not invalidated the
    /// moment a new key is activated. The predecessor held exactly one
    /// public key and overwrote it, and discarded the `kid` it was
    /// delivered with — so nothing could be indexed and every token was
    /// checked against whichever key happened to have arrived last.
    keys: [VerifyKey; MAX_KEYS],

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

        s.keys = [VerifyKey::empty(); MAX_KEYS];
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

/// Drain `verify_key`, keeping the key lifecycle into the keyset
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
    for _ in 0..8 {
        if !chan::can_read(sys, s.in_key) {
            break;
        }
        let mut buf = [0u8; 8192];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_key, &mut buf);
        let payload = &buf[..plen as usize];
        match msg_type {
            auth_wire::MSG_KEY_ADD => {
                if let Ok(rec) = auth_wire::KeyRecord::decode_add(payload) {
                    // Re-adding the same (issuer, profile, kid) replaces it
                    // rather than consuming a second slot.
                    let idx = find_key(s, rec.issuer, rec.profile_id, rec.kid)
                        .or_else(|| s.keys.iter().position(|k| !k.live));
                    if let Some(i) = idx {
                        let mut slot = VerifyKey::empty();
                        if fill_key(&mut slot, &rec) {
                            s.keys[i] = slot;
                        }
                    }
                }
            }
            auth_wire::MSG_KEYSET_SNAPSHOT => {
                let mut r = PayloadReader::new(payload);
                let Ok(count) = r.u16() else { continue };
                if usize::from(count) > MAX_KEYS {
                    continue;
                }
                let mut fresh = [VerifyKey::empty(); MAX_KEYS];
                let mut ok = true;
                for slot in fresh.iter_mut().take(usize::from(count)) {
                    match auth_wire::KeyRecord::read(&mut r) {
                        Ok(rec) if fill_key(slot, &rec) => {}
                        _ => {
                            ok = false;
                            break;
                        }
                    }
                }
                // All or nothing. A half-applied snapshot would leave the
                // verifier holding a set neither end believes in — and the
                // keys it dropped are the ones live tokens need.
                if ok {
                    s.keys = fresh;
                }
            }
            auth_wire::MSG_KEY_ACTIVATE => {
                if let Ok(kr) = auth_wire::KeyRef::decode(payload) {
                    if let Some(i) = find_key(s, kr.issuer, kr.profile_id, kr.kid) {
                        s.keys[i].state = auth_wire::key_state::ACTIVE;
                    }
                }
            }
            auth_wire::MSG_KEY_RETIRE => {
                if let Ok(kr) = auth_wire::KeyRef::decode(payload) {
                    if let Some(i) = find_key(s, kr.issuer, kr.profile_id, kr.kid) {
                        // A retired key keeps VERIFYING. That is the whole
                        // point of the state: it stops signing new tokens
                        // while the ones it already signed age out.
                        s.keys[i].state = auth_wire::key_state::RETIRED;
                        s.keys[i].remove_after_unix = kr.arg;
                    }
                }
            }
            auth_wire::MSG_KEY_REMOVE => {
                if let Ok(kr) = auth_wire::KeyRef::decode(payload) {
                    if let Some(i) = find_key(s, kr.issuer, kr.profile_id, kr.kid) {
                        s.keys[i] = VerifyKey::empty();
                    }
                }
            }
            _ => {}
        }
    }
}

fn find_key(s: &ModuleState, issuer: &[u8], profile_id: u16, kid: &[u8]) -> Option<usize> {
    for (i, k) in s.keys.iter().enumerate() {
        if k.live
            && k.profile_id == profile_id
            && &k.issuer[..usize::from(k.issuer_len)] == issuer
            && &k.kid[..usize::from(k.kid_len)] == kid
        {
            return Some(i);
        }
    }
    None
}

/// Select the key a token names, by the `kid` in its JOSE header.
///
/// An unknown kid returns `None` and the token is refused. It is NOT
/// checked against some other key: falling back to "whatever key we have"
/// is what makes a kid decorative, and it means a token signed by a key
/// the verifier never trusted can still be accepted if the header is
/// ignored.
///
/// A key past its removal deadline is not selectable even while it is
/// still in the table, so an operator that set a deadline gets it.
fn select_key(s: &ModuleState, kid: &[u8], now: u64) -> Option<usize> {
    for (i, k) in s.keys.iter().enumerate() {
        if !k.live {
            continue;
        }
        if k.remove_after_unix != 0 && now >= k.remove_after_unix {
            continue;
        }
        if &k.kid[..usize::from(k.kid_len)] == kid {
            return Some(i);
        }
    }
    None
}

/// Handle one `MSG_VERIFY_REQ` payload sitting in `s.msg_buf[..plen]`.
///
/// Returns a typed `VerifiedIdentity`, never claims JSON. The policy the
/// credential must satisfy — audience, issuer, profile, assurance —
/// travels in the request and is checked here, once, rather than by each
/// caller afterwards in its own way.
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

    // An empty keyset is recoverable — keys may still arrive — so it is
    // reported before any parse of the request body.
    if !s.keys.iter().any(|k| k.live) {
        s.no_key_errors = s.no_key_errors.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::NO_KEY);
        return;
    }

    let mut req_buf = [0u8; MAX_CLAIMS_BYTES];
    let req_len = plen.min(req_buf.len());
    req_buf[..req_len].copy_from_slice(&s.msg_buf[..req_len]);
    let Ok(req) = auth_wire::VerifyRequest::decode(&req_buf[..req_len]) else {
        s.verify_malformed = s.verify_malformed.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::MALFORMED);
        return;
    };
    let token = req.credential;

    let Some(jws) = jose::Jws::split(token) else {
        s.verify_malformed = s.verify_malformed.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::MALFORMED);
        return;
    };

    // Raw 64-byte JWS signature (r||s for ES256, R||S for EdDSA).
    let mut sig = [0u8; 64];
    let sig_ok = b64::decode(jws.signature_b64, &mut sig) == Some(64);

    // Which key signed this is the token's own claim, in its header. It is
    // looked up, never guessed: an unknown kid fails closed rather than
    // falling through to whatever key is loaded.
    let mut header_json = [0u8; 512];
    let hdr_len = b64::decode(jws.header_b64, &mut header_json).unwrap_or(0);
    let kid = jose::claim_str(&header_json[..hdr_len], b"kid").unwrap_or(b"");
    // See `resource_gate`: a window check against a clock that reads 0
    // concludes "not yet expired" for every credential ever issued.
    let obs = dev_trusted_unix(sys);
    let Some(now) = time_policy::now_for(time_policy::Decision::CredentialWindow, &obs) else {
        s.verify_expired = s.verify_expired.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::NO_CLOCK);
        return;
    };
    let Some(slot) = select_key(s, kid, now) else {
        s.verify_bad_sig = s.verify_bad_sig.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::UNKNOWN_KID);
        return;
    };

    // The header's `alg` must agree with the suite the key was delivered
    // under. A token is otherwise free to name an algorithm the key was
    // never intended for, which is the algorithm-confusion class of bug.
    let hdr_alg = jose::claim_str(&header_json[..hdr_len], b"alg").unwrap_or(b"");
    let suite = s.keys[slot].suite;
    if auth_wire::suite::from_jose_alg(hdr_alg) != suite {
        s.verify_bad_sig = s.verify_bad_sig.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::SUITE_MISMATCH);
        return;
    }

    let pubkey_bytes = s.keys[slot].pubkey;
    let pubkey = &pubkey_bytes[..usize::from(s.keys[slot].pubkey_len)];
    let verified = sig_ok
        && match suite {
            auth_wire::suite::ES256 => {
                let hash = sha256(jws.signing_input);
                ecdsa_verify(pubkey, &hash, &sig)
            }
            auth_wire::suite::ED25519 => match pubkey.try_into() {
                Ok(pk32) => ed25519_verify(pk32, jws.signing_input, &sig),
                Err(_) => false,
            },
            _ => false,
        };
    if !verified {
        s.verify_bad_sig = s.verify_bad_sig.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::BAD_SIGNATURE);
        return;
    }

    // Signature is valid; now the token must be live and must satisfy the
    // policy the request named. Decoding the payload is this module's job
    // because it already had to: doing it here once, and handing back typed
    // fields, is what stops every consumer re-parsing attacker-controlled
    // JSON to decide who somebody is.
    let mut payload_json = [0u8; MAX_CLAIMS_BYTES];
    let Some(payload_len) = b64::decode(jws.payload_b64, &mut payload_json) else {
        s.verify_malformed = s.verify_malformed.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::MALFORMED);
        return;
    };
    let json = &payload_json[..payload_len];
    let iat = jose::claim_u64(json, b"iat").unwrap_or(0);
    let exp = jose::claim_u64(json, b"exp").unwrap_or(0);
    if !jose::within_window(now, iat, exp, CLOCK_SKEW_SECS) {
        s.verify_expired = s.verify_expired.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::EXPIRED);
        return;
    }

    let issuer = jose::claim_str(json, b"iss").unwrap_or(b"");
    let subject = jose::claim_str(json, b"sub").unwrap_or(b"");
    let audience = jose::claim_str(json, b"aud").unwrap_or(b"");
    let scope = jose::claim_str(json, b"scope").unwrap_or(b"");
    let credential_id = jose::claim_str(json, b"jti").unwrap_or(b"");

    // The policy checks, in one place. Each was previously the caller's
    // job, and an audience check written five times is an audience check
    // that is subtly different five times.
    //
    // An empty expectation means "no rule", which a caller states by
    // writing it — not by forgetting a field.
    if !req.expected_issuer.is_empty() && issuer != req.expected_issuer {
        s.verify_bad_sig = s.verify_bad_sig.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::WRONG_ISSUER);
        return;
    }
    if !req.expected_audience.is_empty() && audience != req.expected_audience {
        s.verify_bad_sig = s.verify_bad_sig.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::WRONG_AUDIENCE);
        return;
    }
    if req.expected_profile != auth_wire::suite::profile::NONE
        && req.expected_profile != s.keys[slot].profile_id
    {
        s.verify_bad_sig = s.verify_bad_sig.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::WRONG_PROFILE);
        return;
    }

    // The key binding, still read: it is what makes the credential
    // non-bearer, and the identity reports it as its own fact rather than as
    // an assurance level.
    let jkt = jose::claim_str(json, b"jkt").unwrap_or(b"");

    // What the credential SAYS was proved, from its own `acr`/`amr` claims —
    // not inferred from its shape. A `cnf` binding says a credential is
    // non-bearer, which is one fact among the several a level is scored
    // from; reading a level out of it would report an answer the credential
    // never made, and would ignore the `amr` of one that did.
    //
    // A credential carrying neither claim scores as the floor, which is the
    // safe direction: an unknown level is never treated as a high one.
    let evidence = read_evidence(json);
    let presented = evidence.level();
    // A credential may not claim a level its own `amr` does not reach.
    // Refused whatever the policy asked for: the contradiction is the
    // credential's, and a caller demanding nothing should still not be
    // handed one that argues with itself.
    if let Some(claimed) =
        jose::claim_str(json, b"acr").and_then(auth_wire::assurance::AssuranceLevel::parse_bytes)
    {
        if !evidence.supports(claimed) {
            s.verify_bad_sig = s.verify_bad_sig.saturating_add(1);
            refuse(s, sys, corr, auth_wire::verify_err::INSUFFICIENT_ASSURANCE);
            return;
        }
    }
    let Some(required) = level_from_discriminant(req.min_assurance) else {
        s.verify_bad_sig = s.verify_bad_sig.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::INSUFFICIENT_ASSURANCE);
        return;
    };
    if presented < required {
        s.verify_bad_sig = s.verify_bad_sig.saturating_add(1);
        refuse(s, sys, corr, auth_wire::verify_err::INSUFFICIENT_ASSURANCE);
        return;
    }

    let kid_bytes = s.keys[slot].kid;
    let kid_out = &kid_bytes[..usize::from(s.keys[slot].kid_len)];
    let identity = auth_wire::VerifiedIdentity {
        correlation: corr,
        status: auth_wire::verify_err::OK,
        profile_id: s.keys[slot].profile_id,
        issuer,
        kid: kid_out,
        suite,
        subject,
        thumbprint_alg: if jkt.is_empty() {
            auth_wire::suite::thumbprint::NONE
        } else {
            auth_wire::suite::thumbprint::JWK_SHA256
        },
        key_thumbprint: jkt,
        audience,
        scope,
        issued_at: iat,
        expires_at: exp,
        // Absent `auth_time` falls back to `iat`. A re-issue that carries
        // one gets the real authentication instant; one that does not is
        // reported as authenticated when it was issued, which is the most
        // a credential that says nothing else can support.
        auth_time: jose::claim_u64(json, b"auth_time").unwrap_or(iat),
        evidence: evidence.encode(),
        credential_id,
        // Empty: this module does not record replays. `device_auth` does,
        // for the credentials presented with a proof, and reporting an id
        // here that nothing had recorded would be a claim about state this
        // module does not hold.
        replay_id: &[],
        // The raw payload, for a consumer that needs an application claim.
        // NOT an authorization input — everything a decision is made on is
        // above, typed.
        application: json,
    };

    s.verify_ok = s.verify_ok.saturating_add(1);
    emit(s, sys, &identity);
}

/// Read a credential's assurance claims into the shared evidence type.
///
/// `amr` is a JSON array of RFC 8176 method names. An unrecognised name is
/// dropped rather than carried, so a method this build does not understand
/// can never contribute to a level it computes — the rule
/// `auth_wire::assurance::AuthMethod::parse` already states, applied here.
///
/// The `acr` claim is NOT read back as the level. A level is scored from the
/// methods, and taking the issuer's word for it would let a credential name
/// a level its own `amr` does not support.
fn read_evidence(json: &[u8]) -> auth_wire::assurance::Evidence {
    let auth_time = jose::claim_u64(json, b"auth_time").unwrap_or(0);
    let mut evidence = auth_wire::assurance::Evidence::at(auth_time);
    let Some(amr) = jose::claim_array(json, b"amr") else {
        return evidence;
    };
    for name in amr {
        if let Some(method) = auth_wire::assurance::AuthMethod::parse_bytes(name) {
            evidence = evidence.with(method);
        }
    }
    if amr_contains(json, auth_wire::assurance::AuthMethod::Hwk) {
        evidence = evidence.key_binding(auth_wire::assurance::KeyBinding::Hardware);
    } else if amr_contains(json, auth_wire::assurance::AuthMethod::Swk) {
        evidence = evidence.key_binding(auth_wire::assurance::KeyBinding::Software);
    }
    if amr_contains(json, auth_wire::assurance::AuthMethod::User) {
        evidence = evidence.user_verified(true);
    }
    if amr_contains(json, auth_wire::assurance::AuthMethod::Webauthn) {
        evidence = evidence.phishing_resistant(true);
    }
    evidence
}

/// Whether the credential's `amr` names `method`.
fn amr_contains(json: &[u8], method: auth_wire::assurance::AuthMethod) -> bool {
    jose::claim_array(json, b"amr")
        .is_some_and(|mut names| names.any(|name| name == method.as_str().as_bytes()))
}

/// The level a policy floor discriminant names.
///
/// `None` for a value this build does not know: a floor it cannot interpret
/// is refused rather than treated as the lowest one, because the caller
/// asking for it meant something.
fn level_from_discriminant(value: u8) -> Option<auth_wire::assurance::AssuranceLevel> {
    match value {
        0 => Some(auth_wire::assurance::AssuranceLevel::Aal1),
        1 => Some(auth_wire::assurance::AssuranceLevel::Aal2),
        2 => Some(auth_wire::assurance::AssuranceLevel::Aal3),
        _ => None,
    }
}

/// Emit a `MSG_VERIFY_RESP`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit(s: &mut ModuleState, sys: &SyscallTable, id: &auth_wire::VerifiedIdentity<'_>) {
    let mut framed = [0u8; MAX_CLAIMS_BYTES + 512];
    let Ok(n) = id.encode(&mut framed) else {
        return;
    };
    // `encode` writes the whole envelope; hand the channel the payload so
    // it is not wrapped in a second one.
    let Ok((_, payload)) = auth_wire::read_envelope(&framed[..n]) else {
        return;
    };
    chan::channel_write_msg(sys, s.out_results, auth_wire::MSG_VERIFY_RESP, payload);
}

/// Emit a refusal, which carries no identity.
///
/// # Safety
///
/// As [`emit`].
unsafe fn refuse(s: &mut ModuleState, sys: &SyscallTable, corr: u32, status: u8) {
    emit(s, sys, &auth_wire::VerifiedIdentity::refused(corr, status));
}

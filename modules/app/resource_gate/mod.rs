//! Resource gate — admit a DPoP-bound request, or say why not.
//!
//! The middleware a resource server would run, as a module instead. It
//! sits behind wave's `foundation/http` as an application: an `HttpRequest`
//! envelope arrives on `request_in`, and exactly one `HttpResponse` goes back
//! on `response_out`.
//!
//! Five things must hold before a request is admitted, and each is decided by
//! the shared fragment that owns it rather than here:
//!
//! 1. The access token's signature verifies under the loaded issuer key, and
//!    the token is inside its own `iat`/`exp` window (`jose`, and the SDK's
//!    deterministic ES256 / Ed25519 verifiers).
//! 2. The DPoP proof's signature verifies under the key its own header
//!    carries — not under the issuer key, and not under an algorithm the
//!    header names.
//! 3. `typ`, the `htm`/`htu` binding and `iat` freshness hold, and the proof
//!    has not been seen before (`dpop::check_proof` and `dpop::ReplayWindow`).
//! 4. The proof key's thumbprint equals the token's `cnf.jkt`
//!    (`jwk::thumbprint_from_canonical`). Steps 2 and 3 prove the presenter
//!    holds *a* key; this is what proves it is *the* key the token was issued
//!    against.
//! 5. The token's `acr` and `auth_time` meet the configured floor
//!    (`assurance::AssurancePolicy`).
//!
//! Order matters and is not an accident. The signature checks come before the
//! claim checks so a forged proof never reaches the binding comparison, and
//! the replay record is written only after the proof has verified — recording
//! a `jti` from an unverified proof would let anyone burn an honest client's
//! identifiers.
//!
//! **The assurance floor here is a level and an age, never a required
//! method.** `amr` is a JSON array, and the shared claim reader deliberately
//! reads flat scalars only; a policy naming a method needs a reader this
//! module does not have, so asking for one is refused at configuration rather
//! than silently ignored at admission.

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
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha3.rs");
// ml_dsa.rs needs sha3.rs's SHAKE in scope; sdk_bridge.rs needs both, plus
// ed25519.rs. Order matters for all four.
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/ml_dsa.rs");
include!("../../common/sdk_bridge.rs");

/// The assurance ladder, reached through `auth_wire` so this module and the
/// wire it reads cannot mount two copies of one vocabulary.
use auth_wire::assurance;
#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/b64.rs"]
mod b64;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/device_auth.rs"]
mod device_auth;
#[path = "../../common/dpop.rs"]
mod dpop;
#[path = "../../common/jose.rs"]
mod jose;
#[path = "../../common/jwk.rs"]
mod jwk;
#[path = "../../common/state_wire.rs"]
mod state_wire;
#[path = "../../common/time_policy.rs"]
mod time_policy;
#[path = "../../common/verify_keyset.rs"]
mod verify_keyset;

use assurance::AssuranceLevel;
use auth_wire::PayloadReader;

/// `module_step` return code for "did work, step me again".
///
/// `1` would retire the module for the life of the process after its first
/// answer, so a module that serves many requests reports `Burst`.
const STEP_DID_WORK: i32 = 2;

/// `HttpRequest`  `[conn u16][stream u16][method u8][flags u8][path_len u16][hdr_len u16][body_len u16]`
const REQ_HDR: usize = 12;
/// `HttpResponse` `[conn u16][stream u16][status u16][flags u8][ct_len u8][hdr_len u16][body_len u16]`
const RESP_HDR: usize = 12;

/// SEC1 uncompressed P-256 points are 65 bytes — the widest key we store.
const MAX_PUBKEY_LEN: usize = 65;
/// Clock skew (seconds) tolerated on the access token's `iat`.
const CLOCK_SKEW_SECS: u64 = 60;
/// Freshness window (seconds) for a DPoP proof's `iat`.
const PROOF_MAX_AGE_SECS: u64 = 300;
/// Alias tying the replay window to the freshness policy: they are one
/// number, and remembering a proof for less than its window leaves a
/// replayable gap.
const PROOF_WINDOW_SECS: u64 = PROOF_MAX_AGE_SECS;
/// Decoded JOSE segment ceiling. A token or proof whose header or payload
/// exceeds it fails closed rather than being parsed from a truncated copy.
const MAX_SEGMENT: usize = 1024;
/// Replay ring depth.
///
/// At one proof per request, 128 covers a burst comfortably. What makes the
/// depth safe rather than merely large is that a proof older than
/// `PROOF_MAX_AGE_SECS` is refused by `check_proof` regardless, so an
/// attacker cannot outrun the ring by waiting.
const REPLAY_DEPTH: usize = 128;
/// Ledger client id on the shared `security_state` reply fan-out. Unique
/// across the modules that speak to one ledger (enrolment 1, e2ee-cred 2,
/// wellknown 4, admission 6, authcode 7).
const STATE_CLIENT: u8 = 8;
/// Admissions parked on a durable replay claim at once. Small on purpose:
/// the gate serves at most `MAX_REQS_PER_STEP` new requests a step, and a
/// full table refuses (503) rather than queueing unboundedly.
const MAX_PENDING_CLAIMS: usize = 8;
/// WCET bound: requests admitted or refused per step. Each costs two
/// signature verifications, which is the expensive part.
const MAX_REQS_PER_STEP: usize = 2;
/// Longest subject echoed back on admission.
const MAX_SUBJECT: usize = 128;

/// The primitives the shared authentication fragment is given. On target
/// these are the SDK's; the host suites inject their own.
const VERIFIERS: device_auth::Verifiers = device_auth::Verifiers {
    sha256: sha256_into,
    ecdsa_verify,
    ed25519_verify: ed25519_verify_slice,
    ml_dsa_verify: ml_dsa_verify_suite,
};

/// The windows this gate admits under. A resource server's access token
/// names no `cty`, so none is required of it.
const POLICY: device_auth::Policy = device_auth::Policy {
    proof_max_age_secs: PROOF_MAX_AGE_SECS,
    clock_skew_secs: CLOCK_SKEW_SECS,
    expected_cty: None,
};

#[repr(C)]
/// One admission parked on the ledger's replay answer.
#[derive(Clone, Copy)]
struct PendingClaim {
    live: bool,
    conn: u16,
    stream: u16,
    subject: [u8; MAX_SUBJECT],
    subject_len: u16,
    state_corr: u32,
}

impl PendingClaim {
    const fn zero() -> Self {
        Self {
            live: false,
            conn: 0,
            stream: 0,
            subject: [0; MAX_SUBJECT],
            subject_len: 0,
            state_corr: 0,
        }
    }
}

struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,   // in[0]:  HttpRequest
    out_responses: i32, // out[0]: HttpResponse
    in_key: i32,        // in[1]:  MSG_KEY_ADD
    /// out[1]/in[2]: the OPTIONAL durable replay lane to `security_state`.
    ///
    /// Wired, every admitted proof is also claimed in the shared ledger, so
    /// a proof spent at one gate instance is spent at all of them — the
    /// shared-TTL-state shape a replicated deployment needs.
    /// Unwired (-1), the process-local window stands alone and the
    /// deployment has DECLARED that scope by leaving the lane out: right
    /// for a gate fronting one process's state, wrong for one fronting a
    /// replicated backend, and visible either way in the graph file.
    out_state: i32,
    in_state: i32,
    pending: [PendingClaim; MAX_PENDING_CLAIMS],
    next_corr: u32,

    /// The issuer keyset. More than one key, indexed by the `kid` the
    /// presented token names — see `verify_keyset.rs`.
    keyset: verify_keyset::Keyset,

    /// The assurance floor every admitted request must meet.
    ///
    /// Defaults to `aal1` with no age limit, which admits any token the other
    /// four checks accept — the same "demands nothing beyond a valid
    /// credential" default the host validator has, so wiring the module into
    /// a graph changes what is enforced only when the graph says so.
    min_level: AssuranceLevel,
    /// Seconds. `0` means no limit.
    ///
    /// A sentinel rather than a companion flag, because the SDK's parameter
    /// reader applies every declared default through the same dispatch a real
    /// value takes: a flag would be set by the default that means "unset".
    /// Zero is safe to spend on the sentinel — a freshness demand of no
    /// seconds would refuse a token minted this instant, so it is not a
    /// policy anyone can mean.
    max_auth_age: u32,
    /// Proof identifiers already spent.
    replay: dpop::ReplayWindow<REPLAY_DEPTH>,

    // Metrics (names mirror manifest [observability])
    gate_admitted: u32,
    gate_no_key: u32,
    gate_bad_token: u32,
    gate_bad_proof: u32,
    gate_not_bound: u32,
    gate_assurance: u32,
    gate_replayed_ledger: u32,
    gate_state_unavailable: u32,

    buf: [u8; abi::CHANNEL_BUFFER_SIZE],
    out: [u8; abi::CHANNEL_BUFFER_SIZE],
}

/// Why a request was refused, as the reason phrase the response carries.
///
/// Deliberately coarse. A gate that told a caller which of the five checks
/// failed would be answering questions an attacker asked — whether this token
/// exists, whether that key is the bound one — so the wire says only which
/// half of the credential was at fault, and the counters carry the detail to
/// the operator instead.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Refusal {
    NoKey,
    Token,
    Proof,
    Assurance,
}

impl Refusal {
    const fn status(self) -> u16 {
        match self {
            // No key yet is the gate's own fault, not the caller's, and a
            // caller told 401 would go and fetch a fresh token that would
            // fail in exactly the same way.
            Self::NoKey => 503,
            Self::Token | Self::Proof => 401,
            Self::Assurance => 403,
        }
    }

    const fn reason(self) -> &'static [u8] {
        match self {
            Self::NoKey => b"no verifying key",
            Self::Token => b"invalid access token",
            Self::Proof => b"invalid dpop proof",
            Self::Assurance => b"insufficient authentication assurance",
        }
    }
}

define_params! {
    ModuleState;

    // The floor as its `acr` word, so a graph reads the way a token does.
    1, min_acr, str, 0 => |s, d, len| {
        let mut word = [0u8; 4];
        if len == word.len() {
            let mut i = 0usize;
            while i < len {
                word[i] = *d.add(i);
                i += 1;
            }
            if let Some(level) = level_from(&word) {
                s.min_level = level;
            }
        }
    };

    // Seconds; 0 (the default) means no limit.
    2, max_auth_age, u32, 0 => |s, d, len| {
        if len == 4 {
            s.max_auth_age = u32::from_le_bytes([*d, *d.add(1), *d.add(2), *d.add(3)]);
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
    // pointers reach live kernel routines. The dereferences and syscall
    // invocations below rely on those guarantees.
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
        s.out_state = dev_channel_port(sys, 1, 1);
        s.in_state = dev_channel_port(sys, 0, 2);
        s.pending = [PendingClaim::zero(); MAX_PENDING_CLAIMS];
        s.next_corr = 1;

        s.keyset = verify_keyset::Keyset::new();
        s.replay = dpop::ReplayWindow::new();
        s.gate_admitted = 0;
        s.gate_no_key = 0;
        s.gate_bad_token = 0;
        s.gate_bad_proof = 0;
        s.gate_not_bound = 0;
        s.gate_assurance = 0;
        s.gate_replayed_ledger = 0;
        s.gate_state_unavailable = 0;

        s.min_level = AssuranceLevel::Aal1;
        s.max_auth_age = 0;
        parse_tlv(s, params, params_len);

        dev_log(sys, 3, b"[gate] init".as_ptr(), 11);
        0
    }
}

/// `AssuranceLevel::parse` takes `&str`; a module links no UTF-8 validator,
/// and the three level words are ASCII, so the bytes are matched directly.
fn level_from(text: &[u8]) -> Option<AssuranceLevel> {
    match text {
        b"aal1" => Some(AssuranceLevel::Aal1),
        b"aal2" => Some(AssuranceLevel::Aal2),
        b"aal3" => Some(AssuranceLevel::Aal3),
        _ => None,
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: as `module_new` — the kernel's `state` pointer is valid and
    // exclusively borrowed for the duration of the call.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // Key updates first, so a same-step request uses the latest key.
        drain_key_material(s, sys);

        let mut worked = drain_claims(s, sys);
        for _ in 0..MAX_REQS_PER_STEP {
            if !chan::can_read(sys, s.in_requests) {
                break;
            }
            // Every request produces exactly one response; don't consume a
            // request we cannot answer.
            if !chan::can_write(sys, s.out_responses) {
                break;
            }
            // A raw envelope, not a typed message: wave's `http` writes the
            // HttpRequest with `channel_write`, so reading it through the
            // message framing would consume a type byte the envelope does
            // not carry and misread every field after it.
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

/// Drain `verify_key`, keeping the key lifecycle into the keyset
/// (`[alg u8][kid_len u8][kid][pubkey_len u8][pubkey]`).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines per the
/// module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
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
        let payload = &buf[..plen as usize];
        // The whole key lifecycle, not a single overwriting delivery. See
        // `verify_keyset.rs`: a keyset holding one key and discarding the
        // kid makes every rotation invalidate every live credential, and
        // leaves an unknown kid checked against whatever arrived last.
        s.keyset.apply(msg_type, payload);
    }
}

/// Decide one `HttpRequest` sitting in `s.buf[..plen]` and answer it.
///
/// # Safety
///
/// As `drain_key_material`.
unsafe fn handle_request(s: &mut ModuleState, sys: &SyscallTable, plen: usize) {
    if plen < REQ_HDR {
        return; // No connection or stream id — nowhere to address a response.
    }
    let conn = u16::from_le_bytes([s.buf[0], s.buf[1]]);
    let stream = u16::from_le_bytes([s.buf[2], s.buf[3]]);

    let mut proof_id = [0u8; 32];
    match admit(s, sys, plen, &mut proof_id) {
        Ok(subject_len) => {
            // `subject` lives in `s.out`'s tail, disjoint from the response
            // this writes into its head.
            let mut subject = [0u8; MAX_SUBJECT];
            subject[..subject_len].copy_from_slice(&s.out[..subject_len]);
            if s.out_state >= 0 {
                // The durable lane is wired: the local window has answered,
                // and the ledger answers for every process before anything
                // is admitted. Fail closed — a claim that cannot be made is
                // a proof whose freshness nothing established, and letting
                // the ledger's absence admit would make losing the ledger a
                // way to replay.
                claim_and_pend(s, sys, conn, stream, &subject[..subject_len], &proof_id);
            } else {
                s.gate_admitted = s.gate_admitted.saturating_add(1);
                respond(s, sys, conn, stream, 200, &subject[..subject_len]);
            }
        }
        Err(refusal) => {
            match refusal {
                Refusal::NoKey => s.gate_no_key = s.gate_no_key.saturating_add(1),
                Refusal::Token => s.gate_bad_token = s.gate_bad_token.saturating_add(1),
                Refusal::Proof => s.gate_bad_proof = s.gate_bad_proof.saturating_add(1),
                Refusal::Assurance => s.gate_assurance = s.gate_assurance.saturating_add(1),
            }
            respond(s, sys, conn, stream, refusal.status(), refusal.reason());
        }
    }
}

/// The five checks, in the order the module doc states.
///
/// On admission the token's `sub` is left at the front of `s.out` and its
/// length returned, so the caller can copy it out before the response is
/// written over the same buffer.
///
/// # Safety
///
/// As `drain_key_material`.
unsafe fn admit(
    s: &mut ModuleState,
    sys: &SyscallTable,
    plen: usize,
    proof_id: &mut [u8; 32],
) -> Result<usize, Refusal> {
    if s.keyset.is_empty() {
        return Err(Refusal::NoKey);
    }

    let method = s.buf[4];
    let path_len = u16::from_le_bytes([s.buf[6], s.buf[7]]) as usize;
    let hdr_len = u16::from_le_bytes([s.buf[8], s.buf[9]]) as usize;
    let path_at = REQ_HDR;
    let hdr_at = path_at.checked_add(path_len).ok_or(Refusal::Token)?;
    let body_at = hdr_at.checked_add(hdr_len).ok_or(Refusal::Token)?;
    if body_at > plen {
        return Err(Refusal::Token);
    }

    // Copy the two credentials out of `s.buf` before anything else borrows
    // it: the decode scratch below writes into buffers of its own, but the
    // header block is about to be re-read for the second of them.
    let mut token = [0u8; MAX_SEGMENT];
    let mut proof = [0u8; MAX_SEGMENT];
    let headers = &s.buf[hdr_at..body_at];
    let token_len = header_value(headers, b"authorization")
        .and_then(strip_dpop_scheme)
        .and_then(|value| copy_into(value, &mut token))
        .ok_or(Refusal::Token)?;
    let proof_len = header_value(headers, b"dpop")
        .and_then(|value| copy_into(value, &mut proof))
        .ok_or(Refusal::Proof)?;
    let token = &token[..token_len];
    let proof = &proof[..proof_len];

    // A credential's validity window is a statement about a date, so it
    // needs a clock worth believing. Without one this refuses.
    //
    // Reading the raw clock is not enough: `dev_unix_millis` returns 0 on
    // a platform with no RTC, and 0 is a NUMBER, so it flows into the
    // window comparison and the comparison answers. Every `exp` exceeds 0,
    // so a missing clock would read as "not yet expired" and admit every
    // expired credential. `time_policy` returns absence as absence.
    let obs = dev_trusted_unix(sys);
    let Some(now) = time_policy::now_for(time_policy::Decision::CredentialWindow, &obs) else {
        return Err(Refusal::Proof);
    };

    // ── 1 to 4: the shared device-authentication fragment ─────────────────
    //
    // The order, the failure directions and the position of the replay record
    // are the fragment's contract, so every module that authenticates a
    // presented credential performs them identically.
    // Which key signed the token is the token's own claim, in its header.
    // Looked up, never guessed: an unknown kid is refused rather than
    // checked against whatever key is loaded.
    let mut kid = [0u8; verify_keyset::MAX_KID_LEN];
    let mut pubkey = [0u8; verify_keyset::MAX_PUBKEY_LEN];
    let mut pubkey_len = 0usize;
    let mut key_suite = 0u16;
    if let Some(kid_len) = device_auth::credential_kid(token, &mut kid) {
        if let Some(k) = s.keyset.select(&kid[..kid_len], now) {
            pubkey_len = k.pubkey_bytes().len();
            pubkey[..pubkey_len].copy_from_slice(k.pubkey_bytes());
            key_suite = k.suite;
        }
    }

    let mut token_payload = [0u8; MAX_SEGMENT];
    // The window fails closed: a saturated one refuses rather than
    // evicting a live entry, because an eviction under load is an
    // admission under load. Both refusals reach `device_auth` as
    // `false`; the counters below keep them apart for an operator,
    // since "somebody replayed a proof" and "the window is saturated"
    // are different problems.
    let mut replay = |jti: &[u8; 32]| {
        // Kept for the durable claim, when the ledger lane is wired.
        *proof_id = *jti;
        match s.replay.offer(jti, now, now + PROOF_WINDOW_SECS) {
            dpop::Replay::Recorded => true,
            dpop::Replay::Seen => false,
            dpop::Replay::Full => false,
        }
    };
    let authenticated = device_auth::authenticate(
        &VERIFIERS,
        &device_auth::IssuerKey {
            suite: key_suite,
            public: &pubkey[..pubkey_len],
        },
        &device_auth::Presentation {
            credential: token,
            proof,
        },
        &device_auth::Request {
            method: method_name(method),
            uri: &s.buf[path_at..hdr_at],
            now,
        },
        &POLICY,
        &mut token_payload,
        &mut replay,
    );
    let token_json = match authenticated {
        Ok(ref ok) => ok.claims,
        Err(device_auth::AuthError::NotBound) => {
            s.gate_not_bound = s.gate_not_bound.saturating_add(1);
            return Err(Refusal::Proof);
        }
        Err(device_auth::AuthError::Proof | device_auth::AuthError::Replay) => {
            return Err(Refusal::Proof);
        }
        Err(device_auth::AuthError::Credential | device_auth::AuthError::Overflow) => {
            return Err(Refusal::Token);
        }
    };

    // ── 5. the token meets the assurance floor ────────────────────────────
    let acr = jose::claim_str(token_json, b"acr");
    let auth_time = jose::claim_u64(token_json, b"auth_time");
    check_assurance(s, token_json, acr, auth_time, now).map_err(|()| Refusal::Assurance)?;

    // Leave `sub` at the front of `s.out` for the caller.
    let subject = jose::claim_str(token_json, b"sub").unwrap_or(b"");
    let len = subject.len().min(MAX_SUBJECT);
    s.out[..len].copy_from_slice(&subject[..len]);
    Ok(len)
}

/// The assurance floor, in the order and with the failure directions the
/// shared ladder's `check` uses.
///
/// The ladder itself takes `&str` and an `amr` slice, neither of which a
/// module has: it links no UTF-8 validator, and `amr` is a JSON array the
/// shared claim reader deliberately does not parse. What is shared is
/// therefore the rule, not the call — an unknown `acr` is refused rather than
/// treated as a floor, and a freshness demand a token cannot answer fails.
fn check_assurance(
    s: &ModuleState,
    token_json: &[u8],
    acr: Option<&[u8]>,
    auth_time: Option<u64>,
    now: u64,
) -> Result<(), ()> {
    // A credential may not claim more than its own `amr` reaches. Checked
    // whatever the floor, because the contradiction is the credential's and
    // not this deployment's to weigh — and checked here as well as in
    // `token_verify` so a surface fronted by only one of them is not the
    // weaker one.
    if let Some(claimed) = acr.and_then(level_from) {
        if !evidence_from(token_json, auth_time).supports(claimed) {
            return Err(());
        }
    }
    if s.min_level > AssuranceLevel::Aal1 {
        let level = acr.and_then(level_from).ok_or(())?;
        if level < s.min_level {
            return Err(());
        }
    }
    if s.max_auth_age > 0 {
        let proved_at = auth_time.ok_or(())?;
        if now.saturating_sub(proved_at) > u64::from(s.max_auth_age) {
            return Err(());
        }
    }
    Ok(())
}

/// The evidence a token's own `amr` carries.
///
/// Each name carries whatever it implies about the key and the ceremony;
/// `Evidence::with_amr_name` draws those, so this gate and the issuer that
/// wrote the claim score one credential the same way.
fn evidence_from(token_json: &[u8], auth_time: Option<u64>) -> assurance::Evidence {
    let mut evidence = assurance::Evidence::at(auth_time.unwrap_or(0));
    if let Some(amr) = jose::claim_array(token_json, b"amr") {
        for name in amr {
            evidence = evidence.with_amr_name(name);
        }
    }
    evidence
}

/// The `Sha256Fn` shape the fragments take, over the SDK's hasher.
fn sha256_into(data: &[u8], out: &mut [u8; 32]) {
    *out = sha256(data);
}

/// The method word wave's envelope encodes as a byte.
///
/// The codes are wave's `wire::method::METHOD_*`, not a numbering of our own:
/// this is one half of a comparison against the proof's `htm`, and a table
/// that drifted from the encoder would refuse every honest request with the
/// method it got wrong.
const fn method_name(method: u8) -> &'static [u8] {
    match method {
        1 => b"GET",
        2 => b"CONNECT",
        3 => b"POST",
        4 => b"HEAD",
        5 => b"PUT",
        6 => b"PATCH",
        7 => b"DELETE",
        8 => b"OPTIONS",
        // METHOD_NONE (0) and anything unknown: no word to bind against, so
        // the comparison fails and the request is refused.
        _ => b"",
    }
}

/// The value of `name` in a CRLF header block, ASCII-case-insensitively.
fn header_value<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut rest = headers;
    while !rest.is_empty() {
        let line_end = find(rest, b"\r\n").unwrap_or(rest.len());
        let line = &rest[..line_end];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let (field, value) = line.split_at(colon);
            if field.eq_ignore_ascii_case(name) {
                return Some(trim(&value[1..]));
            }
        }
        rest = rest.get(line_end + 2..)?;
    }
    None
}

/// `DPoP <token>` → `<token>`. A `Bearer` token is not a DPoP-bound one and
/// is refused here rather than admitted unbound.
fn strip_dpop_scheme(value: &[u8]) -> Option<&[u8]> {
    let space = value.iter().position(|&b| b == b' ')?;
    if !value[..space].eq_ignore_ascii_case(b"dpop") {
        return None;
    }
    Some(trim(&value[space + 1..]))
}

fn copy_into(value: &[u8], out: &mut [u8]) -> Option<usize> {
    if value.is_empty() || value.len() > out.len() {
        return None;
    }
    out[..value.len()].copy_from_slice(value);
    Some(value.len())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn trim(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = bytes {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

/// Emit one `HttpResponse` carrying `body` as `text/plain`.
///
/// # Safety
///
/// As `drain_key_material`.
/// Send the durable replay claim and park the admission on its answer.
///
/// # Safety
///
/// As `drain_key_material`.
unsafe fn claim_and_pend(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    subject: &[u8],
    proof_id: &[u8; 32],
) {
    let Some(index) = s.pending.iter().position(|p| !p.live) else {
        // Full is a refusal, not a queue: unbounded parked admissions is
        // the eviction-under-load shape with extra steps.
        s.gate_state_unavailable = s.gate_state_unavailable.saturating_add(1);
        respond(s, sys, conn, stream, 503, b"state_unavailable");
        return;
    };
    // The proof's digest in the keyspace's alphabet — the digest, not the
    // client's own `jti`, for admission's reason: a key built from the
    // caller's bytes is a key the caller chooses.
    let mut replay_key = [0u8; 43];
    let Some(replay_key_len) = b64::encode(proof_id, &mut replay_key) else {
        s.gate_state_unavailable = s.gate_state_unavailable.saturating_add(1);
        respond(s, sys, conn, stream, 503, b"state_unavailable");
        return;
    };
    let obs = dev_trusted_unix(sys);
    let Some(now) = time_policy::now_for(time_policy::Decision::CredentialWindow, &obs) else {
        s.gate_state_unavailable = s.gate_state_unavailable.saturating_add(1);
        respond(s, sys, conn, stream, 503, b"state_unavailable");
        return;
    };

    let state_corr = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);
    let request = state_wire::claim_replay(
        state_corr,
        STATE_CLIENT,
        &replay_key[..replay_key_len],
        now + PROOF_WINDOW_SECS,
    );
    let mut frame = [0u8; 512];
    let sent = state_wire::encode_request(&mut frame, state_wire::MSG_STATE_PUT_ABS, &request)
        .ok()
        .and_then(|n| auth_wire::read_envelope(&frame[..n]).ok())
        .is_some_and(|(wire_type, payload)| {
            chan::channel_write_msg(sys, s.out_state, wire_type, payload) > 0
        });
    if !sent {
        s.gate_state_unavailable = s.gate_state_unavailable.saturating_add(1);
        respond(s, sys, conn, stream, 503, b"state_unavailable");
        return;
    }

    let mut entry = PendingClaim::zero();
    entry.live = true;
    entry.conn = conn;
    entry.stream = stream;
    let len = subject.len().min(MAX_SUBJECT);
    entry.subject[..len].copy_from_slice(&subject[..len]);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_SUBJECT")]
    {
        entry.subject_len = len as u16;
    }
    entry.state_corr = state_corr;
    s.pending[index] = entry;
}

/// Answer parked admissions from the ledger's replies.
///
/// # Safety
///
/// As `drain_key_material`.
unsafe fn drain_claims(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    if s.in_state < 0 {
        return false;
    }
    let mut worked = false;
    while chan::can_read(sys, s.in_state) {
        let mut buf = [0u8; 1024];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_state, &mut buf);
        if msg_type == 0 {
            break;
        }
        let Ok(rep) = state_wire::StateReply::decode(msg_type, &buf[..plen as usize]) else {
            continue;
        };
        // The ledger's reply port fans out to every consumer.
        if rep.client != STATE_CLIENT {
            continue;
        }
        let Some(index) = s
            .pending
            .iter()
            .position(|p| p.live && p.state_corr == rep.correlation)
        else {
            continue;
        };
        let entry = s.pending[index];
        s.pending[index] = PendingClaim::zero();
        worked = true;
        match state_wire::replay_claim_result(rep.status) {
            state_wire::ReplayClaim::Fresh => {
                s.gate_admitted = s.gate_admitted.saturating_add(1);
                let subject = entry.subject;
                respond(
                    s,
                    sys,
                    entry.conn,
                    entry.stream,
                    200,
                    &subject[..usize::from(entry.subject_len)],
                );
            }
            state_wire::ReplayClaim::Replayed => {
                // Spent at SOME gate sharing this ledger — this one or
                // another replica. The local window said fresh; the shared
                // state outranks it.
                s.gate_replayed_ledger = s.gate_replayed_ledger.saturating_add(1);
                respond(s, sys, entry.conn, entry.stream, 401, b"proof_replayed");
            }
            state_wire::ReplayClaim::Unavailable => {
                s.gate_state_unavailable = s.gate_state_unavailable.saturating_add(1);
                respond(s, sys, entry.conn, entry.stream, 503, b"state_unavailable");
            }
        }
    }
    worked
}

unsafe fn respond(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    status: u16,
    body: &[u8],
) {
    const CT: &[u8] = b"text/plain";
    let total = RESP_HDR + CT.len() + body.len();
    if total > s.out.len() {
        return;
    }
    s.out[0..2].copy_from_slice(&conn.to_le_bytes());
    s.out[2..4].copy_from_slice(&stream.to_le_bytes());
    s.out[4..6].copy_from_slice(&status.to_le_bytes());
    s.out[6] = 0; // flags: a complete body in one envelope
    #[expect(
        clippy::cast_possible_truncation,
        reason = "CT is a 10-byte literal, so the length fits a u8"
    )]
    {
        s.out[7] = CT.len() as u8;
    }
    s.out[8..10].copy_from_slice(&0u16.to_le_bytes()); // no extra headers
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by the `total > s.out.len()` check above"
    )]
    {
        s.out[10..12].copy_from_slice(&(body.len() as u16).to_le_bytes());
    }
    s.out[RESP_HDR..RESP_HDR + CT.len()].copy_from_slice(CT);
    s.out[RESP_HDR + CT.len()..total].copy_from_slice(body);

    (sys.channel_write)(s.out_responses, s.out.as_ptr(), total);
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

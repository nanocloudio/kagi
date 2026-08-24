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

#[path = "../../common/assurance.rs"]
mod assurance;
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
/// WCET bound: requests admitted or refused per step. Each costs two
/// signature verifications, which is the expensive part.
const MAX_REQS_PER_STEP: usize = 2;
/// Longest subject echoed back on admission.
const MAX_SUBJECT: usize = 128;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,   // in[0]:  HttpRequest
    out_responses: i32, // out[0]: HttpResponse
    in_key: i32,        // in[1]:  MSG_VERIFY_KEY

    /// SEC1 public point (ES256) or 32-byte public key (Ed25519).
    /// Valid iff `has_key`; interpreted per `key_alg`.
    pubkey: [u8; MAX_PUBKEY_LEN],
    pubkey_len: u8,
    /// `auth_wire::MINT_ALG_*` of the loaded key.
    key_alg: u8,
    has_key: bool,

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

        s.pubkey = [0; MAX_PUBKEY_LEN];
        s.pubkey_len = 0;
        s.key_alg = 0;
        s.has_key = false;
        s.replay = dpop::ReplayWindow::new();
        s.gate_admitted = 0;
        s.gate_no_key = 0;
        s.gate_bad_token = 0;
        s.gate_bad_proof = 0;
        s.gate_not_bound = 0;
        s.gate_assurance = 0;

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

        let mut worked = false;
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

/// Drain `verify_key`, keeping the latest valid MSG_VERIFY_KEY
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

    match admit(s, sys, plen) {
        Ok(subject_len) => {
            s.gate_admitted = s.gate_admitted.saturating_add(1);
            // `subject` lives in `s.out`'s tail, disjoint from the response
            // this writes into its head.
            let mut subject = [0u8; MAX_SUBJECT];
            subject[..subject_len].copy_from_slice(&s.out[..subject_len]);
            respond(s, sys, conn, stream, 200, &subject[..subject_len]);
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
unsafe fn admit(s: &mut ModuleState, sys: &SyscallTable, plen: usize) -> Result<usize, Refusal> {
    if !s.has_key {
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

    let now = dev_unix_millis(sys) / 1000;

    // ── 1. the access token verifies and is live ──────────────────────────
    let token_jws = jose::Jws::split(token).ok_or(Refusal::Token)?;
    if !verify_with_issuer_key(s, &token_jws) {
        return Err(Refusal::Token);
    }
    let mut token_payload = [0u8; MAX_SEGMENT];
    let token_payload_len =
        b64::decode(token_jws.payload_b64, &mut token_payload).ok_or(Refusal::Token)?;
    let token_json = &token_payload[..token_payload_len];
    let iat = jose::claim_u64(token_json, b"iat").unwrap_or(0);
    let exp = jose::claim_u64(token_json, b"exp").unwrap_or(0);
    if !jose::within_window(now, iat, exp, CLOCK_SKEW_SECS) {
        return Err(Refusal::Token);
    }

    // ── 2. the proof verifies under the key its own header carries ────────
    let proof_jws = jose::Jws::split(proof).ok_or(Refusal::Proof)?;
    let mut proof_header = [0u8; MAX_SEGMENT];
    let proof_header_len =
        b64::decode(proof_jws.header_b64, &mut proof_header).ok_or(Refusal::Proof)?;
    let proof_header = &proof_header[..proof_header_len];
    let mut canonical = [0u8; jwk::MAX_CANONICAL];
    let canonical_len = canonical_header_jwk(proof_header, &mut canonical).ok_or(Refusal::Proof)?;
    if !verify_with_header_jwk(proof_header, &canonical[..canonical_len], &proof_jws) {
        return Err(Refusal::Proof);
    }

    // ── 3. the proof's claims bind it to this request, and it is fresh ────
    let mut proof_payload = [0u8; MAX_SEGMENT];
    let proof_payload_len =
        b64::decode(proof_jws.payload_b64, &mut proof_payload).ok_or(Refusal::Proof)?;
    let facts = dpop::check_proof(
        sha256_into,
        proof_header,
        &proof_payload[..proof_payload_len],
        method_name(method),
        &s.buf[path_at..hdr_at],
        now,
        PROOF_MAX_AGE_SECS,
    )
    .map_err(|_| Refusal::Proof)?;
    // Recorded only now: a `jti` taken from an unverified proof would let
    // anyone burn an honest client's identifiers.
    if !s.replay.check_and_record(&facts.jti_digest) {
        return Err(Refusal::Proof);
    }

    // ── 4. the proof key is the key the token was issued against ──────────
    let thumbprint = jwk::thumbprint_from_canonical(sha256_into, &canonical[..canonical_len]);
    let bound = jose::claim_str(token_json, b"jkt").ok_or(Refusal::Token)?;
    if bound != thumbprint {
        s.gate_not_bound = s.gate_not_bound.saturating_add(1);
        return Err(Refusal::Proof);
    }

    // ── 5. the token meets the assurance floor ────────────────────────────
    let acr = jose::claim_str(token_json, b"acr");
    let auth_time = jose::claim_u64(token_json, b"auth_time");
    check_assurance(s, acr, auth_time, now).map_err(|()| Refusal::Assurance)?;

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
    acr: Option<&[u8]>,
    auth_time: Option<u64>,
    now: u64,
) -> Result<(), ()> {
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

/// Verify a JWS under the loaded issuer key.
fn verify_with_issuer_key(s: &ModuleState, jws: &jose::Jws<'_>) -> bool {
    let mut sig = [0u8; 64];
    if b64::decode(jws.signature_b64, &mut sig) != Some(64) {
        return false;
    }
    let pubkey = &s.pubkey[..usize::from(s.pubkey_len)];
    match s.key_alg {
        auth_wire::MINT_ALG_ES256 => {
            let hash = sha256(jws.signing_input);
            ecdsa_verify(pubkey, &hash, &sig)
        }
        auth_wire::MINT_ALG_ED25519 => match pubkey.try_into() {
            Ok(pk32) => ed25519_verify(pk32, jws.signing_input, &sig),
            Err(_) => false,
        },
        _ => false,
    }
}

/// Verify a DPoP proof under the public key its own header carries.
///
/// The algorithm comes from the header jwk's `kty`, never from the header's
/// `alg`: `alg` is written by whoever made the proof, and letting it choose
/// the verifier is the algorithm-confusion path.
fn verify_with_header_jwk(header_json: &[u8], canonical: &[u8], jws: &jose::Jws<'_>) -> bool {
    let mut sig = [0u8; 64];
    if b64::decode(jws.signature_b64, &mut sig) != Some(64) {
        return false;
    }
    let _ = canonical;
    let Some(kty) = jose::claim_str(header_json, b"kty") else {
        return false;
    };
    match kty {
        b"OKP" => {
            let Some(x) = jose::claim_str(header_json, b"x") else {
                return false;
            };
            let mut pk = [0u8; 32];
            if b64::decode(x, &mut pk) != Some(32) {
                return false;
            }
            ed25519_verify(&pk, jws.signing_input, &sig)
        }
        b"EC" => {
            let (Some(x), Some(y)) = (
                jose::claim_str(header_json, b"x"),
                jose::claim_str(header_json, b"y"),
            ) else {
                return false;
            };
            // SEC1 uncompressed: 0x04 ‖ X ‖ Y.
            let mut point = [0u8; 65];
            point[0] = 0x04;
            if b64::decode(x, &mut point[1..33]) != Some(32) {
                return false;
            }
            if b64::decode(y, &mut point[33..65]) != Some(32) {
                return false;
            }
            let hash = sha256(jws.signing_input);
            ecdsa_verify(&point, &hash, &sig)
        }
        _ => false,
    }
}

/// Rebuild the header's `jwk` in the canonical member order a thumbprint is
/// taken over.
///
/// The proof's own spelling of the JWK is not used: RFC 7638 thumbprints are
/// defined over a canonical form, and hashing whatever order the presenter
/// happened to write would let the same key produce two thumbprints.
fn canonical_header_jwk(header_json: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut record = jwk::JwkRecord::new();
    if let Some(v) = jose::claim_str(header_json, b"crv") {
        record.crv = jwk::Field::set(v).ok()?;
    }
    if let Some(v) = jose::claim_str(header_json, b"kty") {
        record.kty = jwk::Field::set(v).ok()?;
    }
    if let Some(v) = jose::claim_str(header_json, b"x") {
        record.x = jwk::Field::set(v).ok()?;
    }
    if let Some(v) = jose::claim_str(header_json, b"y") {
        record.y = jwk::Field::set(v).ok()?;
    }
    record.canonical_json(out).ok()
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

//! Enrolment endpoint — the issuer's front door, as a module.
//!
//! Two paths behind wave's `foundation/http`:
//!
//! * `POST /start` takes an email, a device public key and a PKCE code
//!   challenge, and answers with a **challenge token**: a JWS this endpoint
//!   signed, binding those three together with a nonce and a short life.
//! * `POST /redeem` takes that token back with the PKCE verifier and a
//!   possession proof over it, and answers with a **device certificate** —
//!   the durable enrolment anchor every later token rests on.
//!
//! The two halves are one module because they are two halves of one
//! agreement. `/redeem` verifies exactly what `/start` signed, over the same
//! canonicalisation and under the same key; splitting them across modules
//! would put a wire format between two functions that must never disagree,
//! and give the format nowhere to live.
//!
//! **What the challenge token is for.** Not secrecy — it is handed to the
//! caller. It exists so `/redeem` needs no server-side session: everything
//! `/redeem` must know was signed at `/start` and comes back with the
//! request. A device cannot alter it without breaking the signature, and
//! cannot replay it past its expiry.
//!
//! **What is proved by the end.** That whoever redeemed holds the private
//! half of the device key named at `/start` (the possession proof), and that
//! they are the same party that started (PKCE). Neither proves the email was
//! controlled — that is the mail gate's job, upstream of here, and the
//! certificate records what it was told rather than what it checked.

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
#[path = "../../common/ids.rs"]
mod ids;
#[path = "../../common/jose.rs"]
mod jose;
#[path = "../../common/jwk.rs"]
mod jwk;
#[path = "../../common/pkce.rs"]
mod pkce;

use auth_wire::PayloadReader;

const STEP_DID_WORK: i32 = 2;

/// `HttpRequest`  `[conn u16][stream u16][method u8][flags u8][path_len u16][hdr_len u16][body_len u16]`
const REQ_HDR: usize = 12;
/// `HttpResponse` `[conn u16][stream u16][status u16][flags u8][ct_len u8][hdr_len u16][body_len u16]`
const RESP_HDR: usize = 12;

/// wave's `wire::method::METHOD_POST`.
const METHOD_POST: u8 = 3;

/// The `cty` a challenge token carries.
///
/// Pinned on both sides. Another artefact this same key signed — an access
/// token, a device certificate — must not be redeemable as a challenge, and
/// the type is what stops it.
const CHALLENGE_CTY: &[u8] = b"challenge+jwt";

/// The `cty` a device certificate carries.
const CERTIFICATE_CTY: &[u8] = b"dc+jwt";

/// How long a challenge stays redeemable, in seconds.
///
/// Short. It exists to carry one exchange across one round trip, and a
/// long-lived one is a bearer artefact sitting in a caller's logs.
const CHALLENGE_TTL_SECS: u64 = 600;

/// How long a device certificate lives, in seconds.
const CERTIFICATE_TTL_SECS: u64 = 30 * 24 * 3600;

/// Tolerated clock skew, in seconds.
const CLOCK_SKEW_SECS: u64 = 60;

/// Longest value read out of a JSON body.
const MAX_FIELD: usize = 256;
/// Longest token this endpoint composes or reads.
const MAX_TOKEN: usize = 2048;
/// The PKCE challenge is a base64url SHA-256: 43 characters.
const CODE_CHALLENGE_LEN: usize = 43;
/// RFC 7636 §4.1 bounds on a verifier.
const MIN_VERIFIER: usize = 43;
const MAX_VERIFIER: usize = 128;
/// Nonce bytes, rendered as base64url in the claims.
const NONCE_BYTES: usize = 16;

const MAX_REQS_PER_STEP: usize = 2;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    out_responses: i32,
    in_key: i32,
    out_directory: i32,

    /// The Ed25519 seed. Signing and verifying are the same key here because
    /// this endpoint is the only party on either end of a challenge token.
    seed: [u8; 32],
    kid: [u8; 32],
    kid_len: u8,
    has_key: bool,

    /// The deployment's issuer identity, and the secret tenant ids derive
    /// from. Graph parameters: a caller that could name its own issuer could
    /// mint an enrolment claiming to come from somebody else, and one that
    /// could name the tenant seed could collide two tenants deliberately.
    iss: [u8; MAX_FIELD],
    iss_len: u16,
    tenant_seed: [u8; 64],
    tenant_seed_len: u16,

    enrol_started: u32,
    enrol_redeemed: u32,
    enrol_no_key: u32,
    enrol_malformed: u32,
    enrol_bad_challenge: u32,
    enrol_pkce_mismatch: u32,
    enrol_bad_possession: u32,
    enrol_recorded: u32,

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
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_FIELD above")]
        {
            s.iss_len = n as u16;
        }
    };

    2, tenant_seed, str, 0 => |s, d, len| {
        let n = if len > 64 { 64 } else { len };
        let mut i = 0usize;
        while i < n {
            s.tenant_seed[i] = *d.add(i);
            i += 1;
        }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to 64 above")]
        {
            s.tenant_seed_len = n as u16;
        }
    };
}

/// Why a request was refused.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Refusal {
    NoKey,
    NoEntropy,
    Malformed,
    BadChallenge,
    PkceMismatch,
    BadPossession,
}

impl Refusal {
    const fn status(self) -> u16 {
        match self {
            // The endpoint's own fault, not the caller's.
            Self::NoKey => 503,
            // Distinct from a missing key: both are the endpoint's own
            // fault, but one is a graph that has not been fed yet and the
            // other is a platform that cannot produce randomness — and an
            // operator seeing them merged would chase the wrong one.
            Self::NoEntropy => 500,
            Self::Malformed => 400,
            // Everything else is a credential that did not hold up.
            Self::BadChallenge | Self::PkceMismatch | Self::BadPossession => 401,
        }
    }

    /// The body a refusal answers with.
    ///
    /// PKCE and possession failures are told apart here because a legitimate
    /// client debugging its own integration cannot make progress otherwise,
    /// and neither reveals anything an attacker did not already supply: both
    /// are statements about material the caller itself sent.
    const fn body(self) -> &'static [u8] {
        match self {
            Self::NoKey => br#"{"error":"temporarily_unavailable"}"#,
            Self::NoEntropy => br#"{"error":"server_error","detail":"entropy"}"#,
            Self::Malformed => br#"{"error":"invalid_request"}"#,
            Self::BadChallenge => br#"{"error":"invalid_grant","detail":"challenge"}"#,
            Self::PkceMismatch => br#"{"error":"invalid_grant","detail":"pkce"}"#,
            Self::BadPossession => br#"{"error":"invalid_grant","detail":"possession"}"#,
        }
    }
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
        s.in_key = dev_channel_port(sys, 0, 1);
        s.out_directory = dev_channel_port(sys, 1, 1);

        s.seed = [0; 32];
        s.kid = [0; 32];
        s.kid_len = 0;
        s.has_key = false;
        s.iss = [0; MAX_FIELD];
        s.iss_len = 0;
        s.tenant_seed = [0; 64];
        s.tenant_seed_len = 0;
        s.enrol_started = 0;
        s.enrol_redeemed = 0;
        s.enrol_no_key = 0;
        s.enrol_malformed = 0;
        s.enrol_bad_challenge = 0;
        s.enrol_pkce_mismatch = 0;
        s.enrol_bad_possession = 0;
        s.enrol_recorded = 0;

        parse_tlv(s, params, params_len);

        dev_log(sys, 3, b"[enrol] init".as_ptr(), 12);
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

        drain_key(s, sys);

        let mut worked = false;
        for _ in 0..MAX_REQS_PER_STEP {
            if !chan::can_read(sys, s.in_requests) || !chan::can_write(sys, s.out_responses) {
                break;
            }
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

/// Take the latest MSG_MINT_KEY (`[alg u8][kid f8][seed 32]`).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn drain_key(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_key < 0 {
        return;
    }
    for _ in 0..4 {
        if !chan::can_read(sys, s.in_key) {
            break;
        }
        let mut buf = [0u8; 256];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_key, &mut buf);
        if msg_type != auth_wire::MSG_MINT_KEY {
            continue;
        }
        let mut r = PayloadReader::new(&buf[..plen as usize]);
        let (Ok(alg), Ok(kid)) = (r.u8(), r.field8()) else {
            continue;
        };
        // Ed25519 only. An enrolment endpoint signs one shape of artefact and
        // there is no reason for it to carry two algorithms; a graph that
        // hands it a P-256 key has made a mistake worth failing on rather
        // than quietly not signing.
        let seed = r.rest();
        if alg != auth_wire::MINT_ALG_ED25519 || seed.len() < 32 || kid.len() > s.kid.len() {
            continue;
        }
        s.seed.copy_from_slice(&seed[..32]);
        s.kid = [0; 32];
        s.kid[..kid.len()].copy_from_slice(kid);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "bounded by kid.len() check"
        )]
        {
            s.kid_len = kid.len() as u8;
        }
        s.has_key = true;
    }
}

/// Route one request.
///
/// # Safety
///
/// As `drain_key`.
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
        refuse(s, sys, conn, stream, Refusal::Malformed);
        return;
    }

    let path_start = if s.buf[REQ_HDR..body_at.min(plen)].starts_with(b"/start") {
        Some(true)
    } else if s.buf[REQ_HDR..body_at.min(plen)].starts_with(b"/redeem") {
        Some(false)
    } else {
        None
    };
    let Some(is_start) = path_start else {
        respond(s, sys, conn, stream, 404, br#"{"error":"not_found"}"#);
        return;
    };
    if method != METHOD_POST {
        respond(s, sys, conn, stream, 405, br#"{"error":"invalid_request"}"#);
        return;
    }
    if !s.has_key {
        s.enrol_no_key = s.enrol_no_key.saturating_add(1);
        refuse(s, sys, conn, stream, Refusal::NoKey);
        return;
    }

    let outcome = if is_start {
        start(s, sys, body_at, body_end)
    } else {
        redeem(s, sys, body_at, body_end)
    };

    match outcome {
        Ok(len) => {
            if is_start {
                s.enrol_started = s.enrol_started.saturating_add(1);
            } else {
                s.enrol_redeemed = s.enrol_redeemed.saturating_add(1);
            }
            // The token was left at the front of `s.out`; copy it clear
            // before the response is written over the same buffer.
            let mut token = [0u8; MAX_TOKEN];
            token[..len].copy_from_slice(&s.out[..len]);
            let mut body = [0u8; MAX_TOKEN + 64];
            let field: &[u8] = if is_start {
                b"challenge_token"
            } else {
                b"device_certificate"
            };
            let n = write_json_field(&mut body, field, &token[..len]);
            respond(s, sys, conn, stream, 200, &body[..n]);
        }
        Err(refusal) => {
            match refusal {
                Refusal::Malformed => s.enrol_malformed = s.enrol_malformed.saturating_add(1),
                Refusal::BadChallenge => {
                    s.enrol_bad_challenge = s.enrol_bad_challenge.saturating_add(1);
                }
                Refusal::PkceMismatch => {
                    s.enrol_pkce_mismatch = s.enrol_pkce_mismatch.saturating_add(1);
                }
                Refusal::BadPossession => {
                    s.enrol_bad_possession = s.enrol_bad_possession.saturating_add(1);
                }
                Refusal::NoKey | Refusal::NoEntropy => {
                    s.enrol_no_key = s.enrol_no_key.saturating_add(1);
                }
            }
            refuse(s, sys, conn, stream, refusal);
        }
    }
}

/// `/start`: bind an email, a device key and a PKCE challenge into a token.
///
/// Leaves the token at the front of `s.out` and returns its length.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn start(
    s: &mut ModuleState,
    sys: &SyscallTable,
    body_at: usize,
    body_end: usize,
) -> Result<usize, Refusal> {
    let mut email = [0u8; MAX_FIELD];
    let mut challenge = [0u8; MAX_FIELD];
    let mut canonical = [0u8; jwk::MAX_CANONICAL];
    let (email_len, challenge_len, canonical_len) = {
        let body = &s.buf[body_at..body_end];
        let email_len = json_string(body, b"email", &mut email);
        let challenge_len = json_string(body, b"code_challenge", &mut challenge);
        let canonical_len = canonical_device_jwk(body, &mut canonical).unwrap_or(0);
        (email_len, challenge_len, canonical_len)
    };
    if email_len == 0 || canonical_len == 0 || challenge_len != CODE_CHALLENGE_LEN {
        return Err(Refusal::Malformed);
    }

    // Hashes, not the values: the token is handed to the caller, and an
    // email address in it would travel through every log the caller keeps.
    let email_hash = b64::encode_digest32(&sha256(&email[..email_len]));
    let pubkey_hash = b64::encode_digest32(&sha256(&canonical[..canonical_len]));

    let mut nonce_bytes = [0u8; NONCE_BYTES];
    // Only a negative result is a failure. The SDK's two descriptions of
    // `RANDOM_FILL` disagree — `kernel_abi.rs` says it returns the byte count
    // and `runtime/net.rs`'s own wrapper says it returns zero — so this
    // accepts either and refuses only the errno both agree on. A predictable
    // nonce is worse than no answer, so the refusal is real when it comes.
    if (sys.provider_call)(-1, 0x0C3C, nonce_bytes.as_mut_ptr(), NONCE_BYTES) < 0 {
        return Err(Refusal::NoEntropy);
    }
    let mut nonce = [0u8; 32];
    let nonce_len = b64::encode(&nonce_bytes, &mut nonce).ok_or(Refusal::Malformed)?;

    let now = dev_unix_millis(sys) / 1000;

    let mut claims = [0u8; 1024];
    let mut at = 0usize;
    put(&mut claims, &mut at, br#"{"aud":"#)?;
    put_json_string(&mut claims, &mut at, &s.iss[..usize::from(s.iss_len)])?;
    put(&mut claims, &mut at, br#","code_challenge":"#)?;
    put_json_string(&mut claims, &mut at, &challenge[..challenge_len])?;
    put(
        &mut claims,
        &mut at,
        br#","code_challenge_method":"S256","email_hash":"#,
    )?;
    put_json_string(&mut claims, &mut at, &email_hash)?;
    put(&mut claims, &mut at, br#","exp":"#)?;
    put_u64(&mut claims, &mut at, now + CHALLENGE_TTL_SECS)?;
    put(&mut claims, &mut at, br#","iat":"#)?;
    put_u64(&mut claims, &mut at, now)?;
    put(&mut claims, &mut at, br#","iss":"#)?;
    put_json_string(&mut claims, &mut at, &s.iss[..usize::from(s.iss_len)])?;
    put(&mut claims, &mut at, br#","nbf":"#)?;
    put_u64(&mut claims, &mut at, now)?;
    put(&mut claims, &mut at, br#","nonce":"#)?;
    put_json_string(&mut claims, &mut at, &nonce[..nonce_len])?;
    put(&mut claims, &mut at, br#","pubkey_hash":"#)?;
    put_json_string(&mut claims, &mut at, &pubkey_hash)?;
    put(&mut claims, &mut at, b"}")?;

    sign_jws(s, CHALLENGE_CTY, &claims[..at])
}

/// `/redeem`: check what `/start` signed, then issue the certificate.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn redeem(
    s: &mut ModuleState,
    sys: &SyscallTable,
    body_at: usize,
    body_end: usize,
) -> Result<usize, Refusal> {
    let mut token = [0u8; MAX_TOKEN];
    let mut verifier = [0u8; MAX_VERIFIER];
    let mut signature_b64 = [0u8; 128];
    let mut canonical = [0u8; jwk::MAX_CANONICAL];
    let (token_len, verifier_len, sig_len, canonical_len) = {
        let body = &s.buf[body_at..body_end];
        (
            json_string(body, b"challenge_token", &mut token),
            json_string(body, b"code_verifier", &mut verifier),
            json_string(body, b"pop_sig", &mut signature_b64),
            canonical_device_jwk(body, &mut canonical).unwrap_or(0),
        )
    };
    if token_len == 0 || canonical_len == 0 || sig_len == 0 {
        return Err(Refusal::Malformed);
    }
    if !(MIN_VERIFIER..=MAX_VERIFIER).contains(&verifier_len) {
        return Err(Refusal::Malformed);
    }
    let token = &token[..token_len];

    // ── the challenge is ours, is a challenge, and is live ───────────────
    let jws = jose::Jws::split(token).ok_or(Refusal::BadChallenge)?;
    let mut header = [0u8; 256];
    let header_len = b64::decode(jws.header_b64, &mut header).ok_or(Refusal::BadChallenge)?;
    match jose::claim_str(&header[..header_len], b"cty") {
        Some(cty) if cty == CHALLENGE_CTY => {}
        _ => return Err(Refusal::BadChallenge),
    }
    let mut sig = [0u8; 64];
    if b64::decode(jws.signature_b64, &mut sig) != Some(64) {
        return Err(Refusal::BadChallenge);
    }
    if !ed25519_verify(&ed25519_public_key(&s.seed), jws.signing_input, &sig) {
        return Err(Refusal::BadChallenge);
    }
    let mut claims = [0u8; 1024];
    let claims_len = b64::decode(jws.payload_b64, &mut claims).ok_or(Refusal::BadChallenge)?;
    let claims = &claims[..claims_len];

    let now = dev_unix_millis(sys) / 1000;
    let exp = jose::claim_u64(claims, b"exp").ok_or(Refusal::BadChallenge)?;
    let nbf = jose::claim_u64(claims, b"nbf").ok_or(Refusal::BadChallenge)?;
    if now >= exp || nbf > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(Refusal::BadChallenge);
    }

    // ── the same party that started is redeeming ─────────────────────────
    let stored_challenge =
        jose::claim_str(claims, b"code_challenge").ok_or(Refusal::BadChallenge)?;
    match jose::claim_str(claims, b"code_challenge_method") {
        Some(method) if method == b"S256" => {}
        _ => return Err(Refusal::BadChallenge),
    }
    if !pkce::verify_s256(sha256_into, &verifier[..verifier_len], stored_challenge) {
        return Err(Refusal::PkceMismatch);
    }

    // ── the key redeeming is the key that started ────────────────────────
    let presented_hash = b64::encode_digest32(&sha256(&canonical[..canonical_len]));
    let bound_hash = jose::claim_str(claims, b"pubkey_hash").ok_or(Refusal::BadChallenge)?;
    if bound_hash != presented_hash {
        return Err(Refusal::BadPossession);
    }

    // ── and whoever redeems holds its private half ───────────────────────
    // The proof covers the whole challenge token, so it cannot be lifted onto
    // another exchange: a signature over a nonce alone would verify against
    // any challenge that happened to carry the same nonce.
    let mut pop = [0u8; 64];
    if b64::decode(&signature_b64[..sig_len], &mut pop) != Some(64) {
        return Err(Refusal::BadPossession);
    }
    if !verify_device_possession(&canonical[..canonical_len], token, &pop) {
        return Err(Refusal::BadPossession);
    }

    // ── the certificate ──────────────────────────────────────────────────
    let email_hash = jose::claim_str(claims, b"email_hash").ok_or(Refusal::BadChallenge)?;
    let mut device_id = [0u8; ids::DEVICE_ID_LENGTH];
    ids::device_id_from_canonical(sha256_into, &canonical[..canonical_len], &mut device_id);

    let mut tenant = [0u8; ids::TENANT_ID_LENGTH];
    ids::tenant_id(
        hkdf_into,
        &s.tenant_seed[..usize::from(s.tenant_seed_len)],
        email_hash,
        &mut tenant,
    )
    .map_err(|_| Refusal::Malformed)?;

    let mut out = [0u8; 1024];
    let mut at = 0usize;
    put(&mut out, &mut at, br#"{"cnf":{"jkt":"#)?;
    let thumbprint = jwk::thumbprint_from_canonical(sha256_into, &canonical[..canonical_len]);
    put_json_string(&mut out, &mut at, &thumbprint)?;
    put(&mut out, &mut at, br#"},"device_id":"#)?;
    put(&mut out, &mut at, b"\"dev_")?;
    put(&mut out, &mut at, &device_id)?;
    put(&mut out, &mut at, b"\"")?;
    put(&mut out, &mut at, br#","email_hash":"#)?;
    put_json_string(&mut out, &mut at, email_hash)?;
    put(&mut out, &mut at, br#","exp":"#)?;
    put_u64(&mut out, &mut at, now + CERTIFICATE_TTL_SECS)?;
    put(&mut out, &mut at, br#","iat":"#)?;
    put_u64(&mut out, &mut at, now)?;
    put(&mut out, &mut at, br#","iss":"#)?;
    put_json_string(&mut out, &mut at, &s.iss[..usize::from(s.iss_len)])?;
    put(&mut out, &mut at, br#","sub":"#)?;
    put(&mut out, &mut at, b"\"tenant_")?;
    put(&mut out, &mut at, &tenant)?;
    put(&mut out, &mut at, b"\"}")?;

    let certificate_len = sign_jws(s, CERTIFICATE_CTY, &out[..at])?;

    // Record the device before answering. A certificate handed out for a
    // device the directory never learned about is a certificate nothing can
    // later revoke — and revocation is the only thing that makes a long-lived
    // enrolment anchor safe to issue at all.
    //
    // The record is the certificate's own claims: what was enrolled is
    // exactly what was attested, with no second rendering to disagree.
    record_device(s, sys, &device_id, &out[..at]);

    Ok(certificate_len)
}

/// Write the enrolled device through `secret_store`.
///
/// Best effort by design. The store may be absent from a graph that has no
/// durable tier, and a deployment that wired one has a `directory_out` edge;
/// refusing the enrolment because a write queue was momentarily full would
/// turn a storage hiccup into a device that cannot enrol at all.
/// `enrol_recorded` is what tells an operator the two are keeping pace.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn record_device(s: &mut ModuleState, sys: &SyscallTable, device_id: &[u8], claims: &[u8]) {
    if s.out_directory < 0 || !chan::can_write(sys, s.out_directory) {
        return;
    }
    let mut payload = [0u8; 1024 + 64];
    let mut at = 0usize;
    // `[corr u32][id f8][version f8][value f16]`
    if put_u32_le(&mut payload, &mut at, 0).is_err() {
        return;
    }
    let mut id = [0u8; 4 + ids::DEVICE_ID_LENGTH];
    id[..4].copy_from_slice(b"dev_");
    id[4..].copy_from_slice(device_id);
    if put_field8(&mut payload, &mut at, &id).is_err()
        || put_field8(&mut payload, &mut at, b"1").is_err()
        || put_field16(&mut payload, &mut at, claims).is_err()
    {
        return;
    }
    if chan::channel_write_msg(
        sys,
        s.out_directory,
        auth_wire::MSG_SECRET_PUT,
        &payload[..at],
    ) > 0
    {
        s.enrol_recorded = s.enrol_recorded.saturating_add(1);
    }
}

fn put_u32_le(out: &mut [u8], at: &mut usize, value: u32) -> Result<(), Refusal> {
    put(out, at, &value.to_le_bytes())
}

fn put_field8(out: &mut [u8], at: &mut usize, value: &[u8]) -> Result<(), Refusal> {
    let len = u8::try_from(value.len()).map_err(|_| Refusal::Malformed)?;
    put(out, at, &[len])?;
    put(out, at, value)
}

fn put_field16(out: &mut [u8], at: &mut usize, value: &[u8]) -> Result<(), Refusal> {
    let len = u16::try_from(value.len()).map_err(|_| Refusal::Malformed)?;
    put(out, at, &len.to_le_bytes())?;
    put(out, at, value)
}

/// Verify a possession proof under the device's own key.
///
/// The algorithm comes from the key's `kty`, never from anything the caller
/// wrote: letting a caller name the verifier is the algorithm-confusion path.
fn verify_device_possession(canonical_jwk: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
    let Some(kty) = jose::claim_str(canonical_jwk, b"kty") else {
        return false;
    };
    match kty {
        b"OKP" => {
            let Some(x) = jose::claim_str(canonical_jwk, b"x") else {
                return false;
            };
            let mut key = [0u8; 32];
            if b64::decode(x, &mut key) != Some(32) {
                return false;
            }
            ed25519_verify(&key, message, signature)
        }
        b"EC" => {
            let (Some(x), Some(y)) = (
                jose::claim_str(canonical_jwk, b"x"),
                jose::claim_str(canonical_jwk, b"y"),
            ) else {
                return false;
            };
            let mut point = [0u8; 65];
            point[0] = 0x04;
            if b64::decode(x, &mut point[1..33]) != Some(32)
                || b64::decode(y, &mut point[33..65]) != Some(32)
            {
                return false;
            }
            ecdsa_verify(&point, &sha256(message), signature)
        }
        _ => false,
    }
}

/// Sign `claims` as a JWS typed `cty`, leaving it at the front of `s.out`.
fn sign_jws(s: &mut ModuleState, cty: &[u8], claims: &[u8]) -> Result<usize, Refusal> {
    let mut header = [0u8; 192];
    let mut at = 0usize;
    put(&mut header, &mut at, br#"{"alg":"EdDSA","cty":"#)?;
    put_json_string(&mut header, &mut at, cty)?;
    put(&mut header, &mut at, br#","kid":"#)?;
    put_json_string(&mut header, &mut at, &s.kid[..usize::from(s.kid_len)])?;
    put(&mut header, &mut at, br#","typ":"JWT"}"#)?;

    let mut token = [0u8; MAX_TOKEN];
    let mut n = 0usize;
    let header_len = b64::encode(&header[..at], &mut token).ok_or(Refusal::Malformed)?;
    n += header_len;
    put(&mut token, &mut n, b".")?;
    let claims_len = b64::encode(claims, &mut token[n..]).ok_or(Refusal::Malformed)?;
    n += claims_len;

    let signature = ed25519_sign(&s.seed, &token[..n]);
    put(&mut token, &mut n, b".")?;
    let sig_len = b64::encode(&signature, &mut token[n..]).ok_or(Refusal::Malformed)?;
    n += sig_len;

    if n > s.out.len() {
        return Err(Refusal::Malformed);
    }
    s.out[..n].copy_from_slice(&token[..n]);
    Ok(n)
}

/// The device key from a request body, in canonical member order.
///
/// Canonical because two spellings of one key must produce one hash: the
/// `pubkey_hash` written at `/start` is compared against the one computed at
/// `/redeem`, and a caller that reordered its JSON between the two would
/// otherwise be told its key had changed.
fn canonical_device_jwk(body: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut record = jwk::JwkRecord::new();
    let mut found = false;
    for (name, field) in [
        (&b"crv"[..], 0u8),
        (&b"kty"[..], 1),
        (&b"x"[..], 2),
        (&b"y"[..], 3),
    ] {
        if let Some(value) = jose::claim_str(body, name) {
            let set = jwk::Field::set(value).ok()?;
            match field {
                0 => record.crv = set,
                1 => {
                    record.kty = set;
                    found = true;
                }
                2 => record.x = set,
                _ => record.y = set,
            }
        }
    }
    if !found {
        return None;
    }
    record.canonical_json(out).ok()
}

/// A JSON string member's value, into `out`. `0` when absent or over-long.
///
/// The same flat scan the shared claim reader uses: it finds `"<key>"` as a
/// member and reads the quoted value after it. Escapes are not interpreted,
/// which is why every field this endpoint reads is one whose alphabet has no
/// escapable character — base64url, an email address, a compact JWS.
fn json_string(body: &[u8], key: &[u8], out: &mut [u8]) -> usize {
    let Some(value) = jose::claim_str(body, key) else {
        return 0;
    };
    if value.is_empty() || value.len() > out.len() {
        return 0;
    }
    out[..value.len()].copy_from_slice(value);
    value.len()
}

/// `{"<field>":"<value>"}`.
fn write_json_field(out: &mut [u8], field: &[u8], value: &[u8]) -> usize {
    let mut at = 0usize;
    let _ = put(out, &mut at, b"{");
    let _ = put_json_string(out, &mut at, field);
    let _ = put(out, &mut at, b":");
    let _ = put_json_string(out, &mut at, value);
    let _ = put(out, &mut at, b"}");
    at
}

fn put(out: &mut [u8], at: &mut usize, bytes: &[u8]) -> Result<(), Refusal> {
    let end = at.checked_add(bytes.len()).ok_or(Refusal::Malformed)?;
    out.get_mut(*at..end)
        .ok_or(Refusal::Malformed)?
        .copy_from_slice(bytes);
    *at = end;
    Ok(())
}

fn put_json_string(out: &mut [u8], at: &mut usize, value: &[u8]) -> Result<(), Refusal> {
    put(out, at, b"\"")?;
    put(out, at, value)?;
    put(out, at, b"\"")
}

fn put_u64(out: &mut [u8], at: &mut usize, mut value: u64) -> Result<(), Refusal> {
    if value == 0 {
        return put(out, at, b"0");
    }
    let mut digits = [0u8; 20];
    let mut n = 0usize;
    while value > 0 && n < digits.len() {
        digits[n] = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
        n += 1;
    }
    let mut ordered = [0u8; 20];
    for i in 0..n {
        ordered[i] = digits[n - 1 - i];
    }
    put(out, at, &ordered[..n])
}

/// The `Sha256Fn` shape the fragments take.
fn sha256_into(data: &[u8], out: &mut [u8; 32]) {
    *out = sha256(data);
}

/// The `HkdfSha256Fn` shape `ids` takes.
fn hkdf_into(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8; 32]) {
    let mut prk = [0u8; 32];
    hkdf_extract(HashAlg::Sha256, salt, ikm, &mut prk);
    hkdf_expand(HashAlg::Sha256, &prk, info, okm);
}

/// Answer a refusal.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn refuse(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    refusal: Refusal,
) {
    respond(s, sys, conn, stream, refusal.status(), refusal.body());
}

/// Emit one `HttpResponse` carrying `body` as JSON.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn respond(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    status: u16,
    body: &[u8],
) {
    const CT: &[u8] = b"application/json";
    let total = RESP_HDR + CT.len() + body.len();
    if total > s.out.len() {
        return;
    }
    s.out[0..2].copy_from_slice(&conn.to_le_bytes());
    s.out[2..4].copy_from_slice(&stream.to_le_bytes());
    s.out[4..6].copy_from_slice(&status.to_le_bytes());
    s.out[6] = 0;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "CT is a 16-byte literal, so the length fits a u8"
    )]
    {
        s.out[7] = CT.len() as u8;
    }
    s.out[8..10].copy_from_slice(&0u16.to_le_bytes());
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

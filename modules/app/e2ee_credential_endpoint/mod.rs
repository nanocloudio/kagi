//! E2EE credential endpoint — binding a device's messaging keys to its
//! enrolled identity.
//!
//! `POST /e2ee/credential` takes a device's E2EE public keys, a possession
//! proof over them, and the issuer's nonce; it answers with a credential this
//! issuer signed, saying which keys belong to which enrolled device.
//!
//! **Why the keys are not the enrolment key.** Some authenticators cannot
//! sign an arbitrary message at all, an Ed25519 signing key is not an HPKE
//! key and cannot do key agreement, and reusing one key across authentication
//! and messaging creates cross-protocol and correlation risks that separate
//! keys do not have. So a device generates messaging keys locally, proves it
//! holds them and holds its enrolled identity, and this signs the binding.
//! The private keys never leave the device and this issuer never sees a group
//! secret.
//!
//! **The proof is checked against the DIRECTORY's key, never a supplied one.**
//! The request carries the device's enrolment JWK so the module can verify a
//! signature with it, but the JWK is only accepted after its thumbprint
//! matches the `cnf.jkt` the directory recorded at enrolment. Verifying
//! against a key that arrived with the request would let anything that can
//! reach this port mint a credential for any device id.
//!
//! What a credential does not prove is that the issuer is honest. It stops a
//! delivery or storage service substituting a device key; it does not stop a
//! compromised issuer introducing a device that was never enrolled.

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
#[path = "../../common/e2ee_credential.rs"]
mod credential;
#[path = "../../common/issuer_key.rs"]
mod issuer_key;
#[path = "../../common/jose.rs"]
mod jose;
#[path = "../../common/jwk.rs"]
mod jwk;
#[path = "../../../target/fluxor/fluxor-abi/sdk/contracts/key_vault.rs"]
mod key_vault;
#[path = "../../common/state_wire.rs"]
mod state_wire;

use auth_wire::PayloadReader;
use credential::Ciphersuite;

const STEP_DID_WORK: i32 = 2;

const REQ_HDR: usize = 12;
const RESP_HDR: usize = 12;
const METHOD_POST: u8 = 3;

/// The `cty` a credential carries. The contract owns the value; this is the
/// spelling a JOSE header needs.
const CREDENTIAL_CTY: &[u8] = b"ke+jwt";

/// How long a credential lives, in seconds.
const CREDENTIAL_TTL_SECS: u64 = 24 * 3600;

const MAX_FIELD: usize = 256;
/// This module's client id on the ledger's shared reply port. Distinct
/// from every other consumer's, so a fan-out reply reaches exactly one.
const STATE_CLIENT: u8 = 2;

const MAX_TOKEN: usize = 2048;
/// Requests awaiting a directory answer.
const MAX_IN_FLIGHT: usize = 4;
const MAX_REQS_PER_STEP: usize = 2;
const MAX_REPLIES_PER_STEP: usize = 4;

/// One request waiting on the directory.
///
/// The whole request is held, not a reference to it: the HTTP buffer is
/// reused by the next request, and a pending entry pointing into it would
/// answer the second caller with the first one's keys.
#[derive(Clone, Copy)]
struct Pending {
    corr: u32,
    conn: u16,
    stream: u16,
    device_id: [u8; MAX_FIELD],
    device_id_len: u16,
    canonical: [u8; jwk::MAX_CANONICAL],
    canonical_len: u16,
    sig_thumbprint: [u8; 43],
    hpke_thumbprint: [u8; 43],
    generation: u32,
    signature: [u8; 64],
    nonce: [u8; 64],
    nonce_len: u16,
    live: bool,
}

impl Pending {
    const fn empty() -> Self {
        Self {
            corr: 0,
            conn: 0,
            stream: 0,
            device_id: [0; MAX_FIELD],
            device_id_len: 0,
            canonical: [0; jwk::MAX_CANONICAL],
            canonical_len: 0,
            sig_thumbprint: [0; 43],
            hpke_thumbprint: [0; 43],
            generation: 0,
            signature: [0; 64],
            nonce: [0; 64],
            nonce_len: 0,
            live: false,
        }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    out_responses: i32,
    in_key: i32,
    out_directory: i32,
    in_directory: i32,

    /// The signing key, held in the vault under the label the keyset record
    /// names. This module never holds a private key.
    key: issuer_key::IssuerKey,
    kid: [u8; 32],
    kid_len: u8,
    /// Scratch for one vault SIGN. Sized for the largest signing input this
    /// module produces plus the request header, and kept in module state
    /// rather than on the PIC stack.
    sign_scratch: [u8; MAX_TOKEN + issuer_key::SIGN_SCRATCH_OVERHEAD],

    iss: [u8; MAX_FIELD],
    iss_len: u16,

    next_corr: u32,
    pending: [Pending; MAX_IN_FLIGHT],

    credential_issued: u32,
    credential_no_key: u32,
    credential_malformed: u32,
    credential_unknown_device: u32,
    credential_bad_possession: u32,
    credential_in_flight_full: u32,

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
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Refusal {
    NoKey,
    Malformed,
    UnknownDevice,
    BadPossession,
    Busy,
}

impl Refusal {
    const fn status(self) -> u16 {
        match self {
            Self::NoKey | Self::Busy => 503,
            Self::Malformed => 400,
            // One status for "no such device" and "that proof does not hold".
            // Telling them apart would answer whether a device id exists to
            // anyone willing to ask, which is a question this endpoint has no
            // reason to answer.
            Self::UnknownDevice | Self::BadPossession => 401,
        }
    }

    const fn body(self) -> &'static [u8] {
        match self {
            Self::NoKey | Self::Busy => br#"{"error":"temporarily_unavailable"}"#,
            Self::Malformed => br#"{"error":"invalid_request"}"#,
            Self::UnknownDevice | Self::BadPossession => br#"{"error":"invalid_grant"}"#,
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
    // SAFETY: per the module ABI, the kernel passes a valid, exclusively
    // borrowed `state` of at least `module_state_size()` bytes and a live
    // syscall table.
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
        s.in_directory = dev_channel_port(sys, 0, 2);

        s.key = issuer_key::IssuerKey::empty();
        s.kid = [0; 32];
        s.kid_len = 0;
        s.iss = [0; MAX_FIELD];
        s.iss_len = 0;
        s.next_corr = 1;
        s.pending = [Pending::empty(); MAX_IN_FLIGHT];
        s.credential_issued = 0;
        s.credential_no_key = 0;
        s.credential_malformed = 0;
        s.credential_unknown_device = 0;
        s.credential_bad_possession = 0;
        s.credential_in_flight_full = 0;

        parse_tlv(s, params, params_len);

        dev_log(sys, 3, b"[e2ee-cred] init".as_ptr(), 16);
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
        // Directory answers first: they free a pending slot, so a request in
        // the same step may take it rather than being refused a seat that was
        // about to be vacated.
        let mut worked = drain_directory(s, sys);

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

/// Take this profile's signing key from a `MSG_KEY_ADD`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a live syscall table.
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
        // The key lifecycle, not a single raw-key delivery. This endpoint
        // signs one artefact shape and holds one key for it, so it takes
        // the ADD for its own profile and ignores everything else on the
        // channel — the channel carries the whole issuer keyset.
        let payload = &buf[..plen as usize];
        if msg_type != auth_wire::MSG_KEY_ADD {
            continue;
        }
        let Ok(rec) = auth_wire::KeyRecord::decode_add(payload) else {
            continue;
        };
        if rec.key_use != auth_wire::key_use::SIGN
            || rec.profile_id != auth_wire::suite::profile::E2EE_CREDENTIAL
        {
            continue;
        }

        let (kid, label) = (rec.kid, rec.key_ref);
        if rec.suite != auth_wire::suite::ED25519
            || label.is_empty()
            || label.len() > auth_wire::MAX_KEY_LABEL
            || kid.is_empty()
            || kid.len() > s.kid.len()
        {
            continue;
        }
        // The record names a LABEL; the key is generated inside the vault on
        // first open and never travels. A label that will not open leaves
        // the module without a key, which is the same state it was in
        // before the record arrived — and `has_key` is now simply whether
        // the vault holds one, so there is no flag to get out of step.
        s.key.close(sys);
        if !s.key.open(sys, rec.suite, label) {
            continue;
        }
        s.kid = [0; 32];
        s.kid[..kid.len()].copy_from_slice(kid);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "bounded by the kid.len() check"
        )]
        {
            s.kid_len = kid.len() as u8;
        }
    }
}

/// Finish every request whose directory answer has arrived.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn drain_directory(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    if s.in_directory < 0 {
        return false;
    }
    let mut worked = false;
    for _ in 0..MAX_REPLIES_PER_STEP {
        if !chan::can_read(sys, s.in_directory) || !chan::can_write(sys, s.out_responses) {
            break;
        }
        let mut buf = [0u8; abi::CHANNEL_BUFFER_SIZE];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_directory, &mut buf);
        if msg_type != state_wire::MSG_STATE_VALUE {
            continue;
        }
        worked = true;

        let Ok(reply) = state_wire::StateReply::decode(msg_type, &buf[..plen as usize]) else {
            continue;
        };
        // The ledger's reply port fans out to every consumer; a reply
        // addressed to another module is not this module's to act on.
        if reply.client != STATE_CLIENT {
            continue;
        }
        let (corr, status, record) = (reply.correlation, reply.status, reply.value);
        let Some(slot) = take_pending(s, corr) else {
            continue;
        };

        if status != auth_wire::ST_OK {
            s.credential_unknown_device = s.credential_unknown_device.saturating_add(1);
            refuse(s, sys, slot.conn, slot.stream, Refusal::UnknownDevice);
            continue;
        }

        match issue(s, &slot, record) {
            Ok(len) => {
                s.credential_issued = s.credential_issued.saturating_add(1);
                let mut token = [0u8; MAX_TOKEN];
                token[..len].copy_from_slice(&s.out[..len]);
                let mut body = [0u8; MAX_TOKEN + 64];
                let n = write_json_field(&mut body, b"credential", &token[..len]);
                respond(s, sys, slot.conn, slot.stream, 200, &body[..n]);
            }
            Err(refusal) => {
                if refusal == Refusal::BadPossession {
                    s.credential_bad_possession = s.credential_bad_possession.saturating_add(1);
                }
                refuse(s, sys, slot.conn, slot.stream, refusal);
            }
        }
    }
    worked
}

/// Read one request and ask the directory about its device.
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
    if &s.buf[REQ_HDR..body_at.min(plen)][..path_len.min(16)] != b"/e2ee/credential" {
        respond(s, sys, conn, stream, 404, br#"{"error":"not_found"}"#);
        return;
    }
    if method != METHOD_POST {
        respond(s, sys, conn, stream, 405, br#"{"error":"invalid_request"}"#);
        return;
    }
    if !s.key.is_open() {
        s.credential_no_key = s.credential_no_key.saturating_add(1);
        refuse(s, sys, conn, stream, Refusal::NoKey);
        return;
    }

    match accept(s, sys, conn, stream, body_at, body_end) {
        Ok(()) => {}
        Err(refusal) => {
            if refusal == Refusal::Malformed {
                s.credential_malformed = s.credential_malformed.saturating_add(1);
            }
            if refusal == Refusal::Busy {
                s.credential_in_flight_full = s.credential_in_flight_full.saturating_add(1);
            }
            refuse(s, sys, conn, stream, refusal);
        }
    }
}

/// Parse the request, claim a slot, and ask the directory.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn accept(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    body_at: usize,
    body_end: usize,
) -> Result<(), Refusal> {
    let mut slot = Pending::empty();

    let (device_len, canonical_len, sig_len, hpke_len, nonce_len, generation, signature_len) = {
        let body = &s.buf[body_at..body_end];
        let device_len = json_string(body, b"device_id", &mut slot.device_id);
        let canonical_len = canonical_jwk_of(body, b"device_pubkey", &mut slot.canonical);
        let mut sig_jwk = [0u8; jwk::MAX_CANONICAL];
        let mut hpke_jwk = [0u8; jwk::MAX_CANONICAL];
        let sig_len = canonical_jwk_of(body, b"sig_jwk", &mut sig_jwk);
        let hpke_len = canonical_jwk_of(body, b"hpke_jwk", &mut hpke_jwk);
        if sig_len > 0 {
            slot.sig_thumbprint = jwk::thumbprint_from_canonical(sha256_into, &sig_jwk[..sig_len]);
        }
        if hpke_len > 0 {
            slot.hpke_thumbprint =
                jwk::thumbprint_from_canonical(sha256_into, &hpke_jwk[..hpke_len]);
        }
        let nonce_len = json_string(body, b"nonce", &mut slot.nonce);
        let generation = jose::claim_u64(body, b"generation").unwrap_or(0);
        let mut signature_b64 = [0u8; 128];
        let sig_b64_len = json_string(body, b"pop_sig", &mut signature_b64);
        let signature_len = if sig_b64_len == 0 {
            0
        } else {
            b64::decode(&signature_b64[..sig_b64_len], &mut slot.signature).unwrap_or(0)
        };
        (
            device_len,
            canonical_len,
            sig_len,
            hpke_len,
            nonce_len,
            generation,
            signature_len,
        )
    };

    if device_len == 0
        || canonical_len == 0
        || sig_len == 0
        || hpke_len == 0
        || nonce_len == 0
        || signature_len != 64
        || generation == 0
    {
        return Err(Refusal::Malformed);
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "each length is bounded above"
    )]
    {
        slot.device_id_len = device_len as u16;
        slot.canonical_len = canonical_len as u16;
        slot.nonce_len = nonce_len as u16;
    }
    slot.generation = u32::try_from(generation).map_err(|_| Refusal::Malformed)?;
    slot.conn = conn;
    slot.stream = stream;
    slot.corr = s.next_corr;
    slot.live = true;

    if s.out_directory < 0 || !chan::can_write(sys, s.out_directory) {
        return Err(Refusal::Busy);
    }
    let index = s
        .pending
        .iter()
        .position(|p| !p.live)
        .ok_or(Refusal::Busy)?;

    // The device directory is the security-state ledger, read through the
    // same namespace `enrollment_endpoint` writes. Reading a different store
    // than the one enrolment commits to would let this endpoint issue for a
    // device the ledger does not hold, or refuse one it does.
    let request = state_wire::get(
        slot.corr,
        STATE_CLIENT,
        state_wire::NS_DEVICE,
        &slot.device_id[..device_len],
    );
    let mut frame = [0u8; MAX_FIELD + 32];
    let n = state_wire::encode_request(&mut frame, state_wire::MSG_STATE_GET, &request)
        .map_err(|_| Refusal::Malformed)?;
    let (msg_type, payload) =
        auth_wire::read_envelope(&frame[..n]).map_err(|_| Refusal::Malformed)?;
    if chan::channel_write_msg(sys, s.out_directory, msg_type, payload) <= 0 {
        return Err(Refusal::Busy);
    }

    s.pending[index] = slot;
    s.next_corr = s.next_corr.wrapping_add(1);
    Ok(())
}

/// The directory answered: check possession against what it recorded, then
/// sign.
///
/// Leaves the credential at the front of `s.out`.
fn issue(s: &mut ModuleState, slot: &Pending, record: &[u8]) -> Result<usize, Refusal> {
    // The enrolment recorded a thumbprint, not a key. The request supplies
    // the key; it is accepted only because its thumbprint is the one the
    // directory holds.
    let bound = jose::claim_str(record, b"jkt").ok_or(Refusal::UnknownDevice)?;
    let canonical = &slot.canonical[..usize::from(slot.canonical_len)];
    let presented = jwk::thumbprint_from_canonical(sha256_into, canonical);
    if bound != presented {
        return Err(Refusal::BadPossession);
    }

    // What the device signed: the contract's bytes, so a device composing a
    // proof and this issuer checking one cannot disagree about what it covers.
    let mut input = [0u8; credential::MAX_PROOF_INPUT];
    let input_len = credential::write_proof_input(
        &slot.device_id[..usize::from(slot.device_id_len)],
        &slot.sig_thumbprint,
        &slot.hpke_thumbprint,
        Ciphersuite::MlsP256Aes128GcmSha256,
        &slot.nonce[..usize::from(slot.nonce_len)],
        &mut input,
    )
    .map_err(|_| Refusal::Malformed)?;

    if !verify_with_jwk(canonical, &input[..input_len], &slot.signature) {
        return Err(Refusal::BadPossession);
    }

    let issued_at = current_seconds(s);

    let mut claims = [0u8; 1024];
    let mut at = 0usize;
    put(&mut claims, &mut at, br#"{"exp":"#)?;
    put_u64(&mut claims, &mut at, issued_at + CREDENTIAL_TTL_SECS)?;
    put(&mut claims, &mut at, br#","gen":"#)?;
    put_u64(&mut claims, &mut at, u64::from(slot.generation))?;
    put(&mut claims, &mut at, br#","hpke_jwk_thumbprint":"#)?;
    put_json_string(&mut claims, &mut at, &slot.hpke_thumbprint)?;
    put(&mut claims, &mut at, br#","iat":"#)?;
    put_u64(&mut claims, &mut at, issued_at)?;
    put(&mut claims, &mut at, br#","iss":"#)?;
    put_json_string(&mut claims, &mut at, &s.iss[..usize::from(s.iss_len)])?;
    put(&mut claims, &mut at, br#","sig_jwk_thumbprint":"#)?;
    put_json_string(&mut claims, &mut at, &slot.sig_thumbprint)?;
    put(&mut claims, &mut at, br#","sub":"#)?;
    put_json_string(
        &mut claims,
        &mut at,
        &slot.device_id[..usize::from(slot.device_id_len)],
    )?;
    put(&mut claims, &mut at, br#","suite":"#)?;
    put_u64(
        &mut claims,
        &mut at,
        u64::from(Ciphersuite::MlsP256Aes128GcmSha256.code()),
    )?;
    put(&mut claims, &mut at, br#","tid":"#)?;
    let tenant = jose::claim_str(record, b"sub").unwrap_or(b"");
    put_json_string(&mut claims, &mut at, tenant)?;
    put(&mut claims, &mut at, b"}")?;

    sign_jws(s, CREDENTIAL_CTY, &claims[..at])
}

/// Seconds since the epoch, from the kernel clock.
fn current_seconds(s: &ModuleState) -> u64 {
    // SAFETY: `s.syscalls` was validated in `module_new` and the table's
    // function pointers reach live kernel routines for the module's lifetime.
    unsafe { dev_unix_millis(&*s.syscalls) / 1000 }
}

/// Verify a signature under a canonical JWK.
///
/// The algorithm comes from the key's own `kty`, never from anything the
/// caller wrote.
fn verify_with_jwk(canonical: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
    let Some(kty) = jose::claim_str(canonical, b"kty") else {
        return false;
    };
    match kty {
        b"OKP" => {
            let Some(x) = jose::claim_str(canonical, b"x") else {
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
                jose::claim_str(canonical, b"x"),
                jose::claim_str(canonical, b"y"),
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
    // SAFETY: `s.syscalls` is the table handed to `module_new` and lives as
    // long as the module.
    let sys = unsafe { &*s.syscalls };
    let mut header = [0u8; 192];
    let mut at = 0usize;
    put(&mut header, &mut at, br#"{"alg":"EdDSA","cty":"#)?;
    put_json_string(&mut header, &mut at, cty)?;
    put(&mut header, &mut at, br#","kid":"#)?;
    put_json_string(&mut header, &mut at, &s.kid[..usize::from(s.kid_len)])?;
    put(&mut header, &mut at, br#","typ":"JWT"}"#)?;

    let mut token = [0u8; MAX_TOKEN];
    let mut n = b64::encode(&header[..at], &mut token).ok_or(Refusal::Malformed)?;
    put(&mut token, &mut n, b".")?;
    let claims_len = b64::encode(claims, &mut token[n..]).ok_or(Refusal::Malformed)?;
    n += claims_len;

    // Ed25519 signs the signing input itself (RFC 8037), and the fragment
    // reads RAW from the key's own suite.
    let key = s.key;
    // SAFETY: as `sys` above; `sign_scratch` does not alias `token`.
    // Sized from the registry rather than from ES256's 64 bytes: what the
    // issuer key's suite signs in is what this has to hold.
    let mut signature = [0u8; auth_wire::suite::MAX_IMPLEMENTED_SIGNATURE_LEN];
    let signature_len = unsafe { key.sign(sys, &mut s.sign_scratch, &token[..n], &mut signature) }
        .ok_or(Refusal::Malformed)?;
    put(&mut token, &mut n, b".")?;
    let sig_len =
        b64::encode(&signature[..signature_len], &mut token[n..]).ok_or(Refusal::Malformed)?;
    n += sig_len;

    if n > s.out.len() {
        return Err(Refusal::Malformed);
    }
    s.out[..n].copy_from_slice(&token[..n]);
    Ok(n)
}

/// Take the slot waiting on `corr`, freeing it.
fn take_pending(s: &mut ModuleState, corr: u32) -> Option<Pending> {
    let index = s.pending.iter().position(|p| p.live && p.corr == corr)?;
    let slot = s.pending[index];
    s.pending[index].live = false;
    Some(slot)
}

/// A named JWK member of the body, in canonical order.
///
/// The flat claim reader finds a key anywhere, so the three JWKs in one body
/// would be indistinguishable to it. This narrows to the object that follows
/// `"<name>":` before reading the members out of it.
fn canonical_jwk_of(body: &[u8], name: &[u8], out: &mut [u8]) -> usize {
    let Some(start) = find_member(body, name) else {
        return 0;
    };
    let region = &body[start..];
    let Some(end) = region.iter().position(|&b| b == b'}') else {
        return 0;
    };
    let object = &region[..=end];

    let mut record = jwk::JwkRecord::new();
    let mut has_kty = false;
    for (member, which) in [
        (&b"crv"[..], 0u8),
        (&b"kty"[..], 1),
        (&b"x"[..], 2),
        (&b"y"[..], 3),
    ] {
        if let Some(value) = jose::claim_str(object, member) {
            let Ok(field) = jwk::Field::set(value) else {
                return 0;
            };
            match which {
                0 => record.crv = field,
                1 => {
                    record.kty = field;
                    has_kty = true;
                }
                2 => record.x = field,
                _ => record.y = field,
            }
        }
    }
    if !has_kty {
        return 0;
    }
    record.canonical_json(out).unwrap_or(0)
}

/// Where the object after `"<name>":` begins.
fn find_member(body: &[u8], name: &[u8]) -> Option<usize> {
    let mut needle = [0u8; MAX_FIELD];
    let mut at = 0usize;
    needle[at] = b'"';
    at += 1;
    needle[at..at + name.len()].copy_from_slice(name);
    at += name.len();
    needle[at] = b'"';
    at += 1;
    needle[at] = b':';
    at += 1;
    let needle = &needle[..at];
    body.windows(needle.len())
        .position(|w| w == needle)
        .map(|found| found + needle.len())
}

/// A JSON string member's value, into `out`. `0` when absent or over-long.
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
    // A value that could end its own string could introduce a key, and the
    // reader takes the FIRST match anywhere in the record — see
    // `jose::is_record_safe`. Every value written here is a thumbprint, a
    // hash or a deployment parameter today, and the guard is what keeps that
    // a fact rather than a habit.
    if !jose::is_record_safe(value) {
        return Err(Refusal::Malformed);
    }
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

fn sha256_into(data: &[u8], out: &mut [u8; 32]) {
    *out = sha256(data);
}

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

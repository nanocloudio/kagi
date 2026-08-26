//! The OIDC authorization-code flow: /authorize issues a single-use code,
//! and the token code-exchange redeems it for an access token + an ID token.
//!
//! kagi authenticates DEVICES/WORKLOADS by a dc+jwt certificate and a DPoP
//! proof, so the subject who "logs in" at /authorize IS the device presenting
//! its certificate. The code binds that established subject to a client and a
//! PKCE challenge; the exchange verifies PKCE and mints. The subject is
//! established inside kagi and never named by the caller — the C14 line.
//!
//! Two flows, one module, because they are two halves of one stateful
//! exchange sharing a code store and a client registry:
//!
//!   /authorize   device_auth → GET client registry → verify redirect_uri
//!                (exact) + require PKCE, CLAMP scope to the client's
//!                registered scope (token_mint signs scope verbatim, so the
//!                clamp is here or nowhere) → PUT a single-use code bound to
//!                {sub, device_id, jkt, client_id, redirect_uri,
//!                code_challenge, nonce, scope, auth_time} → return the code.
//!
//!   exchange     GET the code → verify redirect_uri/client_id match and PKCE
//!                (S256) → GET the device record and refuse a REVOKED device
//!                (mint-time revocation, where mint_admission enforces it too)
//!                → CAS-consume the code (single-use; verify BEFORE consume,
//!                as enrolment does) → mint the access token (bound to the
//!                stored jkt — the DPoP sender-constraint survives the code)
//!                → mint the ID token (aud=client_id, nonce, auth_time) →
//!                return both.

#![no_std]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in target/fluxor/fluxor-abi/sdk/"
)]
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the fluxor module ABI entry points: the runtime owns these pointers and their validity is the ABI's contract. Same allow the other PIC modules carry."
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "shared SDK surface across modules"
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

const STEP_DID_WORK: i32 = 2;
const MAX_IN_FLIGHT: usize = 8;
const MAX_FIELD: usize = 256;
const CODE_ID_BYTES: usize = 16; // 16 random bytes → 22 base64url chars
const CODE_ID_CHARS: usize = 22;
const CODE_TTL_SECS: u64 = 60;
const PROOF_WINDOW_SECS: u64 = 300;
/// This module's identity to the state ledger. Not an OAuth client id, and
/// not a namespace — those are `state_wire::NS_OAUTH_*`.
const STATE_CLIENT: u8 = 7;
const CSPRNG_OP: u32 = 0x0C3C;

/// PKCE: only S256 is offered — `plain` is a downgrade a client can force.
const PKCE_CHALLENGE_LEN: usize = 43; // base64url(SHA256) is 43 chars

fn sha256_into(data: &[u8], out: &mut [u8; 32]) {
    *out = sha256(data);
}

const VERIFIERS: device_auth::Verifiers = device_auth::Verifiers {
    sha256: sha256_into,
    ecdsa_verify,
    ed25519_verify,
};

/// A dc+jwt device certificate presented at /authorize, and nothing else.
const POLICY: device_auth::Policy = device_auth::Policy {
    proof_max_age_secs: PROOF_WINDOW_SECS,
    clock_skew_secs: 60,
    expected_cty: Some(b"dc+jwt"),
};

/// Which flow a Pending entry is running.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// /authorize: awaiting the client-registry GET.
    AuthzClient,
    /// exchange: awaiting the code GET.
    XchgCode,
    /// exchange: awaiting the device-record GET (revocation check).
    XchgDevice,
    /// exchange: awaiting the CAS-consume ack for the code.
    XchgConsume,
    /// exchange: awaiting the access-token mint.
    XchgMintAt,
    /// exchange: awaiting the ID-token mint.
    XchgMintId,
}

#[derive(Clone, Copy)]
struct Pending {
    live: bool,
    flow: Flow,
    caller_corr: u32,
    state_corr: u32,
    mint_corr: u32,
    sub: [u8; MAX_FIELD],
    sub_len: u16,
    device_id: [u8; MAX_FIELD],
    device_id_len: u16,
    jkt: [u8; 43],
    client_id: [u8; MAX_FIELD],
    client_id_len: u16,
    redirect_uri: [u8; MAX_FIELD],
    redirect_uri_len: u16,
    scope: [u8; MAX_FIELD],
    scope_len: u16,
    nonce: [u8; MAX_FIELD],
    nonce_len: u16,
    state: [u8; MAX_FIELD],
    state_len: u16,
    code: [u8; CODE_ID_CHARS],
    code_len: u16,
    code_etag: [u8; 64],
    code_etag_len: u16,
    auth_time: u64,
    access_token: [u8; 4096],
    access_len: u16,
}

impl Pending {
    const fn zero() -> Self {
        Self {
            live: false,
            flow: Flow::AuthzClient,
            caller_corr: 0,
            state_corr: 0,
            mint_corr: 0,
            sub: [0; MAX_FIELD],
            sub_len: 0,
            device_id: [0; MAX_FIELD],
            device_id_len: 0,
            jkt: [0; 43],
            client_id: [0; MAX_FIELD],
            client_id_len: 0,
            redirect_uri: [0; MAX_FIELD],
            redirect_uri_len: 0,
            scope: [0; MAX_FIELD],
            scope_len: 0,
            nonce: [0; MAX_FIELD],
            nonce_len: 0,
            state: [0; MAX_FIELD],
            state_len: 0,
            code: [0; CODE_ID_CHARS],
            code_len: 0,
            code_etag: [0; 64],
            code_etag_len: 0,
            auth_time: 0,
            access_token: [0; 4096],
            access_len: 0,
        }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    out_replies: i32,
    in_verify_key: i32,
    out_state: i32,
    in_state: i32,
    out_mint: i32,
    in_mint: i32,
    next_corr: u32,
    keyset: verify_keyset::Keyset,
    replay: dpop::ReplayWindow<128>,
    pending: [Pending; MAX_IN_FLIGHT],
    // Deployment policy for the ACCESS token, never client-supplied.
    iss: [u8; MAX_FIELD],
    iss_len: u16,
    aud: [u8; MAX_FIELD],
    aud_len: u16,
    ttl_seconds: u32,
    id_ttl_seconds: u32,
    token_suite: u16,
    authz_ok: u32,
    authz_refused: u32,
    xchg_ok: u32,
    xchg_refused: u32,
    buf: [u8; abi::CHANNEL_BUFFER_SIZE],
}

define_params! {
    ModuleState;

    1, iss, str, 0 => |s, d, len| {
        let n = if len > MAX_FIELD { MAX_FIELD } else { len };
        let mut i = 0usize;
        while i < n { s.iss[i] = *d.add(i); i += 1; }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_FIELD")]
        { s.iss_len = n as u16; }
    };
    2, aud, str, 0 => |s, d, len| {
        let n = if len > MAX_FIELD { MAX_FIELD } else { len };
        let mut i = 0usize;
        while i < n { s.aud[i] = *d.add(i); i += 1; }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_FIELD")]
        { s.aud_len = n as u16; }
    };
    3, ttl_seconds, u32, 0 => |s, d, len| {
        if len >= 4 { s.ttl_seconds = u32::from_le_bytes([*d, *d.add(1), *d.add(2), *d.add(3)]); }
    };
    4, id_ttl_seconds, u32, 0 => |s, d, len| {
        if len >= 4 { s.id_ttl_seconds = u32::from_le_bytes([*d, *d.add(1), *d.add(2), *d.add(3)]); }
    };
    5, suite, u32, 2 => |s, d, len| {
        if len >= 1 { s.token_suite = u16::from(*d); }
    };
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "state is far below u32::MAX"
    )]
    {
        core::mem::size_of::<ModuleState>() as u32
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
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
    // SAFETY: per the module ABI.
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
        parse_tlv(s, params, params_len);

        s.in_requests = in_chan;
        s.out_replies = out_chan;
        s.in_verify_key = dev_channel_port(sys, 0, 1);
        s.out_state = dev_channel_port(sys, 1, 1);
        s.in_state = dev_channel_port(sys, 0, 2);
        s.out_mint = dev_channel_port(sys, 1, 2);
        s.in_mint = dev_channel_port(sys, 0, 3);

        s.next_corr = 1;
        s.keyset = verify_keyset::Keyset::new();
        s.replay = dpop::ReplayWindow::new();
        s.pending = [Pending::zero(); MAX_IN_FLIGHT];
        s.authz_ok = 0;
        s.authz_refused = 0;
        s.xchg_ok = 0;
        s.xchg_refused = 0;

        // No ledger, no flow: the code store, the client registry and the
        // revocation check all live there. Refused at construction.
        if s.out_state < 0 || s.in_state < 0 || s.out_mint < 0 || s.in_mint < 0 {
            dev_log(
                sys,
                1,
                b"[authcode] refusing: ledger/mint not wired".as_ptr(),
                43,
            );
            return -1;
        }
        dev_log(sys, 3, b"[authcode] init".as_ptr(), 15);
        0
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: as module_new.
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut ModuleState);
        if s.syscalls.is_null() {
            return -1;
        }
        let sys = &*s.syscalls;
        let mut worked = drain_keys(s, sys);
        worked |= drain_state(s, sys);
        worked |= drain_mint(s, sys);
        worked |= drain_requests(s, sys);
        if worked {
            STEP_DID_WORK
        } else {
            0
        }
    }
}

/// # Safety
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn drain_keys(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    if s.in_verify_key < 0 {
        return false;
    }
    let mut worked = false;
    while chan::can_read(sys, s.in_verify_key) {
        let mut buf = [0u8; 1024];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_verify_key, &mut buf);
        if msg_type == 0 {
            break;
        }
        worked = true;
        s.keyset.apply(msg_type, &buf[..plen as usize]);
    }
    worked
}

fn free_slot(s: &ModuleState) -> Option<usize> {
    s.pending.iter().position(|p| !p.live)
}

/// Refuse an /authorize caller (no code, no redirect, no state).
///
/// # Safety
/// As `drain_keys`.
unsafe fn refuse_authz(s: &mut ModuleState, sys: &SyscallTable, corr: u32, status: u8) {
    s.authz_refused = s.authz_refused.saturating_add(1);
    let resp = auth_wire::AuthorizeResponse {
        corr,
        status,
        code: b"",
        redirect_uri: b"",
        state: b"",
    };
    let mut framed = [0u8; 512];
    if let Ok(n) = resp.encode(&mut framed) {
        if let Ok((t, p)) = auth_wire::read_envelope(&framed[..n]) {
            chan::channel_write_msg(sys, s.out_replies, t, p);
        }
    }
}

/// Refuse an exchange caller (no tokens).
///
/// # Safety
/// As `drain_keys`.
unsafe fn refuse_xchg(s: &mut ModuleState, sys: &SyscallTable, corr: u32, status: u8) {
    s.xchg_refused = s.xchg_refused.saturating_add(1);
    let resp = auth_wire::CodeExchangeResponse {
        corr,
        status,
        access_token: b"",
        id_token: b"",
    };
    let mut framed = [0u8; 512];
    if let Ok(n) = resp.encode(&mut framed) {
        if let Ok((t, p)) = auth_wire::read_envelope(&framed[..n]) {
            chan::channel_write_msg(sys, s.out_replies, t, p);
        }
    }
}

/// # Safety
/// As `drain_keys`.
unsafe fn drain_requests(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    if s.in_requests < 0 {
        return false;
    }
    let mut worked = false;
    while chan::can_read(sys, s.in_requests) {
        let buf_ptr = s.buf.as_mut_ptr();
        let (msg_type, plen) = {
            let buf = core::slice::from_raw_parts_mut(buf_ptr, abi::CHANNEL_BUFFER_SIZE);
            chan::channel_read_msg(sys, s.in_requests, buf)
        };
        if msg_type == 0 {
            break;
        }
        worked = true;
        let payload = core::slice::from_raw_parts(buf_ptr, plen as usize);
        if msg_type == auth_wire::MSG_AUTHORIZE_REQ {
            if let Ok(req) = auth_wire::AuthorizeRequest::decode(payload) {
                handle_authorize(s, sys, &req);
            } else {
                dev_log(sys, 1, b"[authcode] authorize decode failed".as_ptr(), 33);
            }
        } else if msg_type == auth_wire::MSG_CODE_EXCHANGE_REQ {
            if let Ok(req) = auth_wire::CodeExchangeRequest::decode(payload) {
                handle_exchange(s, sys, &req);
            } else {
                dev_log(sys, 1, b"[authcode] exchange decode failed".as_ptr(), 32);
            }
        }
    }
    worked
}

/// /authorize fact 1: authenticate the subject, then start the client lookup.
///
/// # Safety
/// As `drain_keys`.
unsafe fn handle_authorize(
    s: &mut ModuleState,
    sys: &SyscallTable,
    req: &auth_wire::AuthorizeRequest<'_>,
) {
    let corr = req.corr;
    if s.keyset.is_empty() {
        refuse_authz(s, sys, corr, auth_wire::authz_err::NO_KEY);
        return;
    }
    if req.credential.is_empty() || req.proof.is_empty() {
        refuse_authz(s, sys, corr, auth_wire::authz_err::UNAUTHENTICATED);
        return;
    }
    // PKCE S256 is mandatory: a code with no challenge is a code with no
    // client binding.
    if req.code_challenge.len() != PKCE_CHALLENGE_LEN {
        refuse_authz(s, sys, corr, auth_wire::authz_err::NO_PKCE);
        return;
    }
    // Everything the code record will carry from the client is refused here
    // if it could not survive being a JSON string value. See `json_safe`.
    if !json_safe(req.client_id)
        || !json_safe(req.redirect_uri)
        || !json_safe(req.nonce)
        || !json_safe(req.code_challenge)
    {
        refuse_authz(s, sys, corr, auth_wire::authz_err::MALFORMED);
        return;
    }
    let obs = dev_trusted_unix(sys);
    let Some(now) = time_policy::now_for(time_policy::Decision::CredentialWindow, &obs) else {
        refuse_authz(s, sys, corr, auth_wire::authz_err::NO_CLOCK);
        return;
    };

    // Look the credential's key up by the kid it names.
    let mut pubkey = [0u8; 65];
    let mut pubkey_len = 0usize;
    let mut key_suite = 0u16;
    let mut kid = [0u8; verify_keyset::MAX_KID_LEN];
    if let Some(kl) = device_auth::credential_kid(req.credential, &mut kid) {
        if let Some(k) = s.keyset.select(&kid[..kl], now) {
            pubkey_len = k.pubkey_bytes().len();
            pubkey[..pubkey_len].copy_from_slice(k.pubkey_bytes());
            key_suite = k.suite;
        }
    }

    let mut claims_buf = [0u8; device_auth::MAX_SEGMENT];
    let mut replayed = false;
    let admitted = {
        let seen = &mut replayed;
        let mut offer = |jti: &[u8; 32]| match s.replay.offer(jti, now, now + PROOF_WINDOW_SECS) {
            dpop::Replay::Recorded => true,
            dpop::Replay::Seen | dpop::Replay::Full => {
                *seen = true;
                false
            }
        };
        device_auth::authenticate(
            &VERIFIERS,
            &device_auth::IssuerKey {
                suite: key_suite,
                public: &pubkey[..pubkey_len],
            },
            &device_auth::Presentation {
                credential: req.credential,
                proof: req.proof,
            },
            &device_auth::Request {
                method: req.method,
                uri: req.uri,
                now,
            },
            &POLICY,
            &mut claims_buf,
            &mut offer,
        )
    };
    let Ok(admitted) = admitted else {
        // A replayed proof is its own refusal: an operator holding one
        // failing request should not have to guess whether the credential
        // was bad or the proof was a repeat.
        let why = if replayed {
            auth_wire::authz_err::REPLAY
        } else {
            auth_wire::authz_err::UNAUTHENTICATED
        };
        refuse_authz(s, sys, corr, why);
        return;
    };
    let (Some(sub), Some(device_id)) = (
        jose::claim_str(admitted.claims, b"sub"),
        jose::claim_str(admitted.claims, b"device_id"),
    ) else {
        refuse_authz(s, sys, corr, auth_wire::authz_err::UNAUTHENTICATED);
        return;
    };

    let Some(index) = free_slot(s) else {
        refuse_authz(s, sys, corr, auth_wire::authz_err::STATE_UNAVAILABLE);
        return;
    };
    // Stash everything the code will bind. redirect_uri, nonce, state and the
    // code_challenge come from the client's request; sub/device_id/jkt from
    // the certificate; scope is deferred to the client-registry reply, where
    // it is CLAMPED.
    let mut e = Pending::zero();
    e.flow = Flow::AuthzClient;
    e.caller_corr = corr;
    e.auth_time = now;
    copy_field(&mut e.sub, &mut e.sub_len, sub);
    copy_field(&mut e.device_id, &mut e.device_id_len, device_id);
    e.jkt = admitted.thumbprint;
    copy_field(&mut e.client_id, &mut e.client_id_len, req.client_id);
    copy_field(
        &mut e.redirect_uri,
        &mut e.redirect_uri_len,
        req.redirect_uri,
    );
    copy_field(&mut e.nonce, &mut e.nonce_len, req.nonce);
    copy_field(&mut e.state, &mut e.state_len, req.state);
    // Reuse `scope` to carry the code_challenge across the client RTT; it is
    // overwritten with the clamped scope once the client is known.
    copy_field(&mut e.scope, &mut e.scope_len, req.code_challenge);

    let sc = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);
    e.state_corr = sc;
    if !state_get(s, sys, sc, state_wire::NS_OAUTH_CLIENT, req.client_id) {
        refuse_authz(s, sys, corr, auth_wire::authz_err::STATE_UNAVAILABLE);
        return;
    }
    e.live = true;
    s.pending[index] = e;
}

/// exchange step 1: start the code lookup.
///
/// # Safety
/// As `drain_keys`.
unsafe fn handle_exchange(
    s: &mut ModuleState,
    sys: &SyscallTable,
    req: &auth_wire::CodeExchangeRequest<'_>,
) {
    let corr = req.corr;
    if s.keyset.is_empty() {
        refuse_xchg(s, sys, corr, auth_wire::authz_err::NO_KEY);
        return;
    }
    if req.code.is_empty() || req.code_verifier.is_empty() {
        refuse_xchg(s, sys, corr, auth_wire::authz_err::MALFORMED);
        return;
    }
    let Some(index) = free_slot(s) else {
        refuse_xchg(s, sys, corr, auth_wire::authz_err::STATE_UNAVAILABLE);
        return;
    };
    let mut e = Pending::zero();
    e.flow = Flow::XchgCode;
    e.caller_corr = corr;
    copy_field(&mut e.code, &mut e.code_len, req.code);
    copy_field(&mut e.client_id, &mut e.client_id_len, req.client_id);
    copy_field(
        &mut e.redirect_uri,
        &mut e.redirect_uri_len,
        req.redirect_uri,
    );
    // Carry the verifier in `scope` (unused until the AT mint) across the RTT.
    copy_field(&mut e.scope, &mut e.scope_len, req.code_verifier);

    let sc = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);
    e.state_corr = sc;
    if !state_get(s, sys, sc, state_wire::NS_OAUTH_CODE, req.code) {
        refuse_xchg(s, sys, corr, auth_wire::authz_err::STATE_UNAVAILABLE);
        return;
    }
    e.live = true;
    s.pending[index] = e;
}

fn copy_field(dst: &mut [u8], dst_len: &mut u16, src: &[u8]) {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "n bounded by dst.len() (<= MAX_FIELD)"
    )]
    {
        *dst_len = n as u16;
    }
}

/// Encode + send a state GET; false if the frame could not be built/written.
///
/// # Safety
/// As `drain_keys`.
unsafe fn state_get(s: &ModuleState, sys: &SyscallTable, corr: u32, ns: u8, key: &[u8]) -> bool {
    let req = state_wire::get(corr, STATE_CLIENT, ns, key);
    let mut frame = [0u8; 512];
    let Ok(n) = state_wire::encode_request(&mut frame, state_wire::MSG_STATE_GET, &req) else {
        return false;
    };
    let Ok((t, p)) = auth_wire::read_envelope(&frame[..n]) else {
        return false;
    };
    chan::channel_write_msg(sys, s.out_state, t, p) > 0
}

/// Whether a byte string can be a JSON string value without escaping.
///
/// A quote or a backslash would end the value early, and `jose::claim_str`
/// scans for the FIRST `"key":"..."` anywhere in the record — so a value
/// carrying `","scope":"admin` puts an attacker's scope AHEAD of the real
/// one and wins the read. The clamp at /authorize would then bound a scope
/// nothing signs. Control bytes go too: they cannot appear raw in JSON.
///
/// Refused rather than escaped. `claim_str` returns the raw bytes between
/// the quotes, so an escaped value would read back with its backslashes
/// still in it — a nonce that is not the nonce the client sent.
fn json_safe(v: &[u8]) -> bool {
    !v.iter().any(|&b| b == b'"' || b == b'\\' || b < 0x20)
}

/// Build the compact code record authcode owns both ends of. JSON, so the
/// existing `jose::claim_str` reader parses it back — no second codec.
///
/// Every value is checked here as well as at ingress: this is the one place
/// the record is assembled, so it is the one place that cannot be bypassed
/// by a later caller.
fn build_code_record(e: &Pending, cc: &[u8], out: &mut [u8]) -> Option<usize> {
    // {"sub":..,"did":..,"jkt":..,"cid":..,"ruri":..,"cc":..,"nonce":..,
    //  "scope":..,"at":<auth_time>}
    let mut at = 0usize;
    let put = |out: &mut [u8], at: &mut usize, b: &[u8]| -> bool {
        if *at + b.len() > out.len() {
            return false;
        }
        out[*at..*at + b.len()].copy_from_slice(b);
        *at += b.len();
        true
    };
    macro_rules! w {
        ($b:expr) => {
            if !put(out, &mut at, $b) {
                return None;
            }
        };
    }
    for field in [
        &e.sub[..usize::from(e.sub_len)],
        &e.device_id[..usize::from(e.device_id_len)],
        &e.jkt[..],
        &e.client_id[..usize::from(e.client_id_len)],
        &e.redirect_uri[..usize::from(e.redirect_uri_len)],
        cc,
        &e.nonce[..usize::from(e.nonce_len)],
        &e.scope[..usize::from(e.scope_len)],
    ] {
        if !json_safe(field) {
            return None;
        }
    }
    w!(b"{\"sub\":\"");
    w!(&e.sub[..usize::from(e.sub_len)]);
    w!(b"\",\"did\":\"");
    w!(&e.device_id[..usize::from(e.device_id_len)]);
    w!(b"\",\"jkt\":\"");
    w!(&e.jkt);
    w!(b"\",\"cid\":\"");
    w!(&e.client_id[..usize::from(e.client_id_len)]);
    w!(b"\",\"ruri\":\"");
    w!(&e.redirect_uri[..usize::from(e.redirect_uri_len)]);
    w!(b"\",\"cc\":\"");
    w!(cc);
    w!(b"\",\"nonce\":\"");
    w!(&e.nonce[..usize::from(e.nonce_len)]);
    w!(b"\",\"scope\":\"");
    w!(&e.scope[..usize::from(e.scope_len)]);
    w!(b"\",\"at\":\"");
    let mut nb = [0u8; 20];
    let nl = u64_dec(e.auth_time, &mut nb);
    w!(&nb[..nl]);
    w!(b"\"}");
    Some(at)
}

fn u64_dec(mut v: u64, out: &mut [u8; 20]) -> usize {
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in 0..n {
        out[i] = tmp[n - 1 - i];
    }
    n
}

/// Draw a 22-char base64url code id from the CSPRNG.
///
/// # Safety
/// As `drain_keys`.
unsafe fn draw_code(sys: &SyscallTable, out: &mut [u8; CODE_ID_CHARS]) -> bool {
    let mut raw = [0u8; CODE_ID_BYTES];
    if (sys.provider_call)(-1, CSPRNG_OP, raw.as_mut_ptr(), raw.len()) < 0 {
        return false;
    }
    let mut enc = [0u8; 24];
    let Some(n) = b64::encode(&raw, &mut enc) else {
        return false;
    };
    if n < CODE_ID_CHARS {
        return false;
    }
    out.copy_from_slice(&enc[..CODE_ID_CHARS]);
    true
}

/// The ledger has answered. Three cases by `flow`.
///
/// # Safety
/// As `drain_keys`.
unsafe fn drain_state(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    if s.in_state < 0 {
        return false;
    }
    let mut worked = false;
    while chan::can_read(sys, s.in_state) {
        let mut buf = [0u8; 2048];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_state, &mut buf);
        if msg_type == 0 {
            break;
        }
        let Ok(rep) = state_wire::StateReply::decode(msg_type, &buf[..plen as usize]) else {
            continue;
        };
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
        worked = true;
        let e = s.pending[index];
        match e.flow {
            Flow::AuthzClient => authz_on_client(s, sys, index, &e, &rep),
            Flow::XchgCode => xchg_on_code(s, sys, index, &e, &rep),
            Flow::XchgDevice => xchg_on_device(s, sys, index, &e, &rep),
            Flow::XchgConsume => xchg_on_consume(s, sys, index, &e, &rep),
            // Mint stages are answered on in_mint, not here.
            Flow::XchgMintAt | Flow::XchgMintId => {}
        }
    }
    worked
}

/// /authorize: the client registry answered. Verify redirect_uri (exact),
/// clamp scope to the client's registered scope, then create the code.
///
/// # Safety
/// As `drain_keys`.
unsafe fn authz_on_client(
    s: &mut ModuleState,
    sys: &SyscallTable,
    index: usize,
    e: &Pending,
    rep: &state_wire::StateReply<'_>,
) {
    if rep.status != auth_wire::ST_OK {
        s.pending[index] = Pending::zero();
        refuse_authz(s, sys, e.caller_corr, auth_wire::authz_err::UNKNOWN_CLIENT);
        return;
    }
    let reg_ruri = jose::claim_str(rep.value, b"redirect_uri").unwrap_or(b"");
    let reg_scope = jose::claim_str(rep.value, b"scope").unwrap_or(b"");
    // Exact match — no wildcard, no normalisation, byte-for-byte.
    if reg_ruri.is_empty() || reg_ruri != &e.redirect_uri[..usize::from(e.redirect_uri_len)] {
        s.pending[index] = Pending::zero();
        refuse_authz(s, sys, e.caller_corr, auth_wire::authz_err::BAD_REDIRECT);
        return;
    }
    // The code_challenge was parked in `scope`; capture it before scope is
    // overwritten with the CLAMPED (registered) scope.
    let mut cc = [0u8; PKCE_CHALLENGE_LEN];
    let cclen = usize::from(e.scope_len).min(PKCE_CHALLENGE_LEN);
    cc[..cclen].copy_from_slice(&e.scope[..cclen]);

    let mut draw = [0u8; CODE_ID_CHARS];
    if !draw_code(sys, &mut draw) {
        s.pending[index] = Pending::zero();
        refuse_authz(
            s,
            sys,
            e.caller_corr,
            auth_wire::authz_err::STATE_UNAVAILABLE,
        );
        return;
    }

    // Rebuild the entry with the clamped scope, then serialise the record.
    let mut ne = *e;
    copy_field(&mut ne.scope, &mut ne.scope_len, reg_scope);
    ne.code = draw;
    #[expect(clippy::cast_possible_truncation, reason = "constant CODE_ID_CHARS")]
    {
        ne.code_len = CODE_ID_CHARS as u16;
    }
    let mut record = [0u8; 1024];
    let Some(rn) = build_code_record(&ne, &cc[..cclen], &mut record) else {
        s.pending[index] = Pending::zero();
        refuse_authz(
            s,
            sys,
            e.caller_corr,
            auth_wire::authz_err::STATE_UNAVAILABLE,
        );
        return;
    };

    // PUT the single-use code (create-only), TTL bounded.
    let sc = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);
    let put = state_wire::put_if_absent(
        sc,
        STATE_CLIENT,
        state_wire::NS_OAUTH_CODE,
        &draw,
        &record[..rn],
        ne.auth_time + CODE_TTL_SECS,
    );
    let mut frame = [0u8; 2048];
    let ok = state_wire::encode_request(&mut frame, state_wire::MSG_STATE_PUT_ABS, &put)
        .ok()
        .and_then(|n| auth_wire::read_envelope(&frame[..n]).ok())
        .map(|(t, p)| chan::channel_write_msg(sys, s.out_state, t, p) > 0)
        .unwrap_or(false);
    if !ok {
        s.pending[index] = Pending::zero();
        refuse_authz(
            s,
            sys,
            e.caller_corr,
            auth_wire::authz_err::STATE_UNAVAILABLE,
        );
        return;
    }
    // The PUT ack is not awaited on a stage: put_if_absent is create-only, and
    // the code is returned to the client now. A collision (same 22-byte id) is
    // astronomically unlikely and would surface as a failed redemption. Answer
    // the caller immediately.
    s.pending[index] = Pending::zero();
    let resp = auth_wire::AuthorizeResponse {
        corr: e.caller_corr,
        status: auth_wire::authz_err::OK,
        code: &draw,
        redirect_uri: reg_ruri,
        state: &e.state[..usize::from(e.state_len)],
    };
    let mut framed = [0u8; 512];
    if let Ok(n) = resp.encode(&mut framed) {
        if let Ok((t, p)) = auth_wire::read_envelope(&framed[..n]) {
            chan::channel_write_msg(sys, s.out_replies, t, p);
            s.authz_ok = s.authz_ok.saturating_add(1);
        }
    }
}

/// exchange: the code record came back. Verify redirect_uri, client_id and
/// PKCE on the READ value (before consuming it, as enrolment does), capture
/// the code's authoritative bindings, then GET the device for the revocation
/// check.
///
/// # Safety
/// As `drain_keys`.
unsafe fn xchg_on_code(
    s: &mut ModuleState,
    sys: &SyscallTable,
    index: usize,
    e: &Pending,
    rep: &state_wire::StateReply<'_>,
) {
    // Unknown / expired code (the store answers NOT_FOUND once the TTL lapses).
    if rep.status != auth_wire::ST_OK {
        s.pending[index] = Pending::zero();
        refuse_xchg(s, sys, e.caller_corr, auth_wire::authz_err::INVALID_GRANT);
        return;
    }
    let rec = rep.value;
    // A code that has already been redeemed is CAS-consumed to a
    // `{"status":"consumed"}` marker, which the TTL keeps around until it
    // lapses. A replay reads that marker rather than NOT_FOUND, and must be
    // refused as an invalid grant — not mistaken for a client/redirect
    // mismatch just because the marker carries no bindings. RFC 6749 §4.1.2:
    // an authorization code MUST NOT be used more than once.
    if matches!(jose::claim_str(rec, b"status"), Some(b"consumed")) {
        s.pending[index] = Pending::zero();
        refuse_xchg(s, sys, e.caller_corr, auth_wire::authz_err::INVALID_GRANT);
        return;
    }
    let cid = jose::claim_str(rec, b"cid").unwrap_or(b"");
    let ruri = jose::claim_str(rec, b"ruri").unwrap_or(b"");
    let cc = jose::claim_str(rec, b"cc").unwrap_or(b"");
    // client_id and redirect_uri must match the code's binding — the
    // confused-deputy guard.
    if cid != &e.client_id[..usize::from(e.client_id_len)]
        || ruri != &e.redirect_uri[..usize::from(e.redirect_uri_len)]
    {
        s.pending[index] = Pending::zero();
        refuse_xchg(s, sys, e.caller_corr, auth_wire::authz_err::MISMATCH);
        return;
    }
    // PKCE S256: base64url(SHA256(verifier)) == the stored challenge. The
    // verifier was parked in `e.scope`.
    let verifier = &e.scope[..usize::from(e.scope_len)];
    let digest = sha256(verifier);
    let computed = b64::encode_digest32(&digest);
    if cc.len() != computed.len() || cc != &computed[..] {
        s.pending[index] = Pending::zero();
        refuse_xchg(s, sys, e.caller_corr, auth_wire::authz_err::PKCE_FAILED);
        return;
    }

    // Capture the code's AUTHORITATIVE bindings into the pending, replacing the
    // caller-supplied fields. From here the caller influences nothing.
    let mut ne = *e;
    capture(&mut ne.sub, &mut ne.sub_len, jose::claim_str(rec, b"sub"));
    capture(
        &mut ne.device_id,
        &mut ne.device_id_len,
        jose::claim_str(rec, b"did"),
    );
    capture(
        &mut ne.nonce,
        &mut ne.nonce_len,
        jose::claim_str(rec, b"nonce"),
    );
    capture(
        &mut ne.scope,
        &mut ne.scope_len,
        jose::claim_str(rec, b"scope"),
    );
    if let Some(jkt) = jose::claim_str(rec, b"jkt") {
        if jkt.len() == 43 {
            ne.jkt.copy_from_slice(jkt);
        }
    }
    ne.auth_time = jose::claim_str(rec, b"at").map(parse_u64).unwrap_or(0);
    // Keep the code's etag for the CAS-consume.
    copy_field(&mut ne.code_etag, &mut ne.code_etag_len, rep.etag);

    // GET the device record: a revoked device gets no token, even with a valid
    // code — mint-time revocation, where mint_admission enforces it too.
    let sc = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);
    ne.state_corr = sc;
    ne.flow = Flow::XchgDevice;
    if !state_get(
        s,
        sys,
        sc,
        state_wire::NS_DEVICE,
        &ne.device_id[..usize::from(ne.device_id_len)],
    ) {
        s.pending[index] = Pending::zero();
        refuse_xchg(
            s,
            sys,
            e.caller_corr,
            auth_wire::authz_err::STATE_UNAVAILABLE,
        );
        return;
    }
    s.pending[index] = ne;
}

fn capture(dst: &mut [u8], dst_len: &mut u16, v: Option<&[u8]>) {
    if let Some(b) = v {
        let n = b.len().min(dst.len());
        dst[..n].copy_from_slice(&b[..n]);
        #[expect(clippy::cast_possible_truncation, reason = "n bounded by dst.len()")]
        {
            *dst_len = n as u16;
        }
    } else {
        *dst_len = 0;
    }
}

fn parse_u64(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for &c in b {
        if c.is_ascii_digit() {
            v = v.wrapping_mul(10).wrapping_add(u64::from(c - b'0'));
        }
    }
    v
}

/// exchange: the device record came back. Refuse a revoked device, then
/// CAS-consume the code (single-use) using the etag from the code GET.
///
/// # Safety
/// As `drain_keys`.
unsafe fn xchg_on_device(
    s: &mut ModuleState,
    sys: &SyscallTable,
    index: usize,
    e: &Pending,
    rep: &state_wire::StateReply<'_>,
) {
    match rep.status {
        auth_wire::ST_OK => {}
        auth_wire::ST_NOT_FOUND => {
            // Certificate valid, but the device is not (or no longer) in the
            // ledger — the same refusal grant gives.
            s.pending[index] = Pending::zero();
            refuse_xchg(s, sys, e.caller_corr, auth_wire::authz_err::INVALID_GRANT);
            return;
        }
        _ => {
            s.pending[index] = Pending::zero();
            refuse_xchg(
                s,
                sys,
                e.caller_corr,
                auth_wire::authz_err::STATE_UNAVAILABLE,
            );
            return;
        }
    }
    if matches!(jose::claim_str(rep.value, b"status"), Some(b"revoked")) {
        s.pending[index] = Pending::zero();
        refuse_xchg(s, sys, e.caller_corr, auth_wire::authz_err::INVALID_GRANT);
        return;
    }

    // Consume the code exactly once: CAS pending→consumed on the etag read at
    // the code GET. A second exchange loses the race → INVALID_GRANT.
    let sc = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);
    let cas = state_wire::StateRequest {
        correlation: sc,
        client: STATE_CLIENT,
        namespace: state_wire::NS_OAUTH_CODE,
        key: &e.code[..usize::from(e.code_len)],
        etag: &e.code_etag[..usize::from(e.code_etag_len)],
        value: b"{\"status\":\"consumed\"}",
        expiry_unix: e.auth_time + CODE_TTL_SECS,
    };
    let mut frame = [0u8; 512];
    let ok = state_wire::encode_request(&mut frame, state_wire::MSG_STATE_CAS, &cas)
        .ok()
        .and_then(|n| auth_wire::read_envelope(&frame[..n]).ok())
        .map(|(t, p)| chan::channel_write_msg(sys, s.out_state, t, p) > 0)
        .unwrap_or(false);
    if !ok {
        s.pending[index] = Pending::zero();
        refuse_xchg(
            s,
            sys,
            e.caller_corr,
            auth_wire::authz_err::STATE_UNAVAILABLE,
        );
        return;
    }
    let mut ne = *e;
    ne.state_corr = sc;
    ne.flow = Flow::XchgConsume;
    s.pending[index] = ne;
}

/// exchange: the CAS-consume answered. On success, mint the access token
/// (bound to the stored jkt).
///
/// # Safety
/// As `drain_keys`.
unsafe fn xchg_on_consume(
    s: &mut ModuleState,
    sys: &SyscallTable,
    index: usize,
    e: &Pending,
    rep: &state_wire::StateReply<'_>,
) {
    if rep.status != auth_wire::ST_OK {
        // Lost the single-use race, or the code changed under us.
        s.pending[index] = Pending::zero();
        refuse_xchg(s, sys, e.caller_corr, auth_wire::authz_err::INVALID_GRANT);
        return;
    }
    // Mint the access token: aud = the deployment RS, scope = the CLAMPED
    // scope from the code, cnf.jkt = the device's key. Profile ACCESS_TOKEN.
    let mc = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);
    let spec = MintSpec {
        profile: auth_wire::suite::profile::ACCESS_TOKEN,
        aud: &s.aud[..usize::from(s.aud_len)],
        scope: &e.scope[..usize::from(e.scope_len)],
        ttl: s.ttl_seconds,
        sub: &e.sub[..usize::from(e.sub_len)],
        jkt: Some(&e.jkt),
        extra: &[],
    };
    if !emit_mint(s, sys, mc, &spec) {
        s.pending[index] = Pending::zero();
        refuse_xchg(s, sys, e.caller_corr, auth_wire::authz_err::MINT_FAILED);
        return;
    }
    let mut ne = *e;
    ne.mint_corr = mc;
    ne.flow = Flow::XchgMintAt;
    s.pending[index] = ne;
}

/// The policy inputs to one mint. Bundled so `emit_mint` takes a fixed four
/// arguments rather than the profile/aud/scope/ttl/sub/jkt/extra spread —
/// the two call sites (access token, ID token) differ only in these fields.
struct MintSpec<'a> {
    profile: u16,
    aud: &'a [u8],
    scope: &'a [u8],
    ttl: u32,
    sub: &'a [u8],
    jkt: Option<&'a [u8]>,
    extra: &'a [auth_wire::MintClaim<'a>],
}

/// Build and send a MintRequest to token_mint. Shared by both token mints.
///
/// The request shape (policy params + jkt) is the one `mint_admission`
/// builds for the grant path; the two are held in step by the harness, which
/// drives both against the same `token_mint`.
///
/// # Safety
/// As `drain_keys`. `spec`'s slices (including the `extra` claims —
/// nonce/auth_time for the ID token) borrow caller memory that must outlive
/// the call.
unsafe fn emit_mint(s: &ModuleState, sys: &SyscallTable, corr: u32, spec: &MintSpec<'_>) -> bool {
    let req = auth_wire::MintRequest {
        correlation: corr,
        request_type: auth_wire::request_type::MINT,
        suite: s.token_suite,
        profile_id: spec.profile,
        kid: b"",
        ttl_seconds: spec.ttl,
        iss: &s.iss[..usize::from(s.iss_len)],
        sub: spec.sub,
        aud: spec.aud,
        scope: spec.scope,
        thumbprint_alg: if spec.jkt.is_some() {
            auth_wire::suite::thumbprint::JWK_SHA256
        } else {
            auth_wire::suite::thumbprint::NONE
        },
        jkt: spec.jkt,
        extra: auth_wire::ExtraClaims::Slice(spec.extra),
    };
    let mut framed = [0u8; 4096];
    req.encode(&mut framed)
        .ok()
        .and_then(|n| auth_wire::read_envelope(&framed[..n]).ok())
        .map(|(t, p)| chan::channel_write_msg(sys, s.out_mint, t, p) > 0)
        .unwrap_or(false)
}

/// A token mint answered. Two stages: the access token, then the ID token.
///
/// # Safety
/// As `drain_keys`.
unsafe fn drain_mint(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    if s.in_mint < 0 {
        return false;
    }
    let mut worked = false;
    while chan::can_read(sys, s.in_mint) {
        let mut buf = [0u8; 8192];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_mint, &mut buf);
        if msg_type == 0 {
            break;
        }
        if msg_type != auth_wire::MSG_MINT_RESP {
            continue;
        }
        let Ok(rep) = auth_wire::MintResponse::decode(&buf[..plen as usize]) else {
            continue;
        };
        let Some(index) = s.pending.iter().position(|p| {
            p.live
                && p.mint_corr == rep.correlation
                && matches!(p.flow, Flow::XchgMintAt | Flow::XchgMintId)
        }) else {
            continue;
        };
        worked = true;
        let e = s.pending[index];
        let minted_ok =
            rep.status == auth_wire::mint_err::OK && rep.delivery == auth_wire::delivery::INLINE;
        match e.flow {
            Flow::XchgMintAt => {
                if !minted_ok {
                    s.pending[index] = Pending::zero();
                    refuse_xchg(s, sys, e.caller_corr, auth_wire::authz_err::MINT_FAILED);
                    continue;
                }
                // Hold the access token, then mint the ID token: aud=client_id,
                // profile ID_TOKEN, with nonce + auth_time as claims (omitted
                // when absent, per OIDC).
                let mut ne = e;
                if rep.body.len() > ne.access_token.len() {
                    // Truncating here would hand the client a token-shaped
                    // string that verifies as nothing. The mint produced
                    // something this module cannot carry: a 5xx.
                    s.pending[index] = Pending::zero();
                    refuse_xchg(s, sys, e.caller_corr, auth_wire::authz_err::MINT_FAILED);
                    continue;
                }
                let n = rep.body.len();
                ne.access_token[..n].copy_from_slice(&rep.body[..n]);
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "n bounded by access_token.len() (4096)"
                )]
                {
                    ne.access_len = n as u16;
                }
                let mut extra = [auth_wire::MintClaim {
                    key: b"",
                    value: auth_wire::MintClaimValue::Bool(false),
                }; 2];
                let mut ex = 0usize;
                if ne.nonce_len > 0 {
                    extra[ex] = auth_wire::MintClaim {
                        key: b"nonce",
                        value: auth_wire::MintClaimValue::Str(
                            &ne.nonce[..usize::from(ne.nonce_len)],
                        ),
                    };
                    ex += 1;
                }
                if ne.auth_time > 0 {
                    extra[ex] = auth_wire::MintClaim {
                        key: b"auth_time",
                        value: auth_wire::MintClaimValue::U64(ne.auth_time),
                    };
                    ex += 1;
                }
                let mc = s.next_corr;
                s.next_corr = s.next_corr.wrapping_add(1).max(1);
                let spec = MintSpec {
                    profile: auth_wire::suite::profile::ID_TOKEN,
                    aud: &ne.client_id[..usize::from(ne.client_id_len)], // aud = client
                    scope: b"", // ID token carries no scope
                    ttl: s.id_ttl_seconds,
                    sub: &ne.sub[..usize::from(ne.sub_len)],
                    jkt: None, // ID token is not sender-constrained
                    extra: &extra[..ex],
                };
                let ok = emit_mint(s, sys, mc, &spec);
                if !ok {
                    s.pending[index] = Pending::zero();
                    refuse_xchg(s, sys, e.caller_corr, auth_wire::authz_err::MINT_FAILED);
                    continue;
                }
                ne.mint_corr = mc;
                ne.flow = Flow::XchgMintId;
                s.pending[index] = ne;
            }
            Flow::XchgMintId => {
                s.pending[index] = Pending::zero();
                if !minted_ok {
                    refuse_xchg(s, sys, e.caller_corr, auth_wire::authz_err::MINT_FAILED);
                    continue;
                }
                let resp = auth_wire::CodeExchangeResponse {
                    corr: e.caller_corr,
                    status: auth_wire::authz_err::OK,
                    access_token: &e.access_token[..usize::from(e.access_len)],
                    id_token: rep.body,
                };
                let mut framed = [0u8; 8192];
                if let Ok(n) = resp.encode(&mut framed) {
                    if let Ok((t, p)) = auth_wire::read_envelope(&framed[..n]) {
                        chan::channel_write_msg(sys, s.out_replies, t, p);
                        s.xchg_ok = s.xchg_ok.saturating_add(1);
                    }
                }
            }
            _ => {}
        }
    }
    worked
}

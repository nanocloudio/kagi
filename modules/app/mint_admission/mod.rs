//! Admission: may this presenter mint, and for whom?
//!
//! One question, answered once, for whoever asks. A caller sends
//! `MSG_ADMIT_REQ` with the credential and DPoP proof it received and the
//! request they are bound to; this answers `MSG_ADMIT_RESP` with either a
//! typed refusal or the subject, device and key binding the credential
//! ESTABLISHED.
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
//! credential model only bounds exposure after a revocation if the issuer
//! refuses to keep issuing — a relying party validating locally cannot know
//! what the issuer has since been told.
//!
//! # Why this is a module and not a function inside the endpoint
//!
//! These three facts were implemented inline in `token_endpoint`, where
//! they were correct and tested. Separating them is not a correctness fix;
//! it is a scope fix. Admission is a POLICY about who may hold a
//! credential, and it was living inside an HTTP transport — so it could
//! only ever be asked over HTTP, could only be tested through HTTP, and a
//! second thing needing the same decision would have had to reimplement it
//! or route through a web server to reach it.
//!
//! **Nothing in the request names a subject, an audience or a key
//! binding.** A caller that could suggest them would be choosing what it is
//! asking permission for; the answer is derived from the credential and the
//! ledger, and the wire has no field to suggest it in.
//!
//! # Why the refusals are typed
//!
//! `admit_err` says what was actually refused. A caller maps those to
//! whatever its own protocol says, and the REASON is not something it
//! should have to infer from a boolean. `STATE_UNAVAILABLE` and `NO_CLOCK`
//! in particular are not refusals of the presenter at all — nothing looked
//! at them — and a caller reporting those as "your credential was rejected"
//! would send an operator hunting a credential that was fine.

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

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/b64.rs"]
mod b64;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/device_auth.rs"]
mod device_auth;
#[path = "../../common/totp.rs"]
mod totp;
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

/// `module_step` return code for "did work, step me again".
const STEP_DID_WORK: i32 = 2;

/// Requests awaiting a ledger answer.
///
/// Small on purpose. Each entry is one caller blocked on one ledger round
/// trip, and a deployment with more than this many in flight is not keeping
/// up — refusing is a truer answer than a queue that grows.
const MAX_IN_FLIGHT: usize = 8;

/// Longest subject or device id carried back.
const MAX_FIELD: usize = 256;

/// This module's client id on the ledger's shared reply port.
const STATE_CLIENT: u8 = 6;

/// How long a DPoP proof stays fresh, and therefore how long its `jti` must
/// be remembered.
///
/// One constant for both, because they are one number: remembering a proof
/// for less than its freshness window leaves a replayable gap, and
/// remembering it for longer wastes a slot on a proof `check_proof` would
/// refuse anyway.
const PROOF_WINDOW_SECS: u64 = 300;

/// The `Sha256Fn` shape the fragments take, over the SDK's hasher.
fn sha256_into(data: &[u8], out: &mut [u8; 32]) {
    *out = sha256(data);
}

const VERIFIERS: device_auth::Verifiers = device_auth::Verifiers {
    sha256: sha256_into,
    ecdsa_verify,
    ed25519_verify,
};

/// The windows a device certificate is admitted under, and the credential
/// kind this module accepts. `dc+jwt` and nothing else: an access token
/// presented here would be a token minting a token.
const POLICY: device_auth::Policy = device_auth::Policy {
    proof_max_age_secs: PROOF_WINDOW_SECS,
    clock_skew_secs: 60,
    expected_cty: Some(b"dc+jwt"),
};

/// One request waiting on the ledger.
#[derive(Clone, Copy)]
struct Pending {
    live: bool,
    /// The CALLER's correlation, echoed back on the reply. Distinct from the
    /// ledger correlation below — conflating them is how a reply gets
    /// matched to the wrong request.
    caller_corr: u32,
    /// The correlation the ledger will answer with.
    state_corr: u32,
    /// True for a GRANT (admit-and-mint); false for a bare admit. Decides
    /// whether a success mints or answers, and whether refusals frame as
    /// GrantResponse or AdmitResponse.
    grant: bool,
    /// The correlation the MINT will answer with — a THIRD correlation space
    /// (caller / ledger / mint), matched only while `awaiting_mint`, because
    /// conflating any two is how a reply lands on the wrong request.
    mint_corr: u32,
    /// Set once the MintRequest is out; the entry now awaits `in_mint`.
    awaiting_mint: bool,
    sub: [u8; MAX_FIELD],
    sub_len: u16,
    device_id: [u8; MAX_FIELD],
    device_id_len: u16,
    jkt: [u8; 43],
    /// What the presenter proved, assembled here because this is the only
    /// stage that sees both halves: the enrolment facts the ledger record
    /// carries, and the possession proof in the request in front of it.
    evidence: auth_wire::assurance::EvidenceWire,
    /// Which round trip this entry is waiting on.
    stage: u8,
    /// The proof's replay identifier, base64url, as the ledger files it.
    replay_key: [u8; 43],
    replay_key_len: u8,
    /// The one-time code presented, if any. Checked against the device
    /// record when it comes back, because that is where the authenticator
    /// lives.
    otp: [u8; MAX_OTP],
    otp_len: u8,
    /// When the possession proof was verified — the token's `auth_time`.
    ///
    /// Taken at verification rather than when the ledger answers: the round
    /// trip is not part of the authentication, and a busy ledger must not
    /// make a token look freshly authenticated later than it was.
    proved_at: u64,
}

impl Pending {
    const fn zero() -> Self {
        Self {
            live: false,
            caller_corr: 0,
            state_corr: 0,
            grant: false,
            mint_corr: 0,
            awaiting_mint: false,
            sub: [0; MAX_FIELD],
            sub_len: 0,
            device_id: [0; MAX_FIELD],
            device_id_len: 0,
            jkt: [0; 43],
            evidence: auth_wire::assurance::EvidenceWire {
                methods: 0,
                key_binding: 0,
                flags: 0,
                auth_time: 0,
            },
            stage: STAGE_CLAIM_PROOF,
            replay_key: [0; 43],
            replay_key_len: 0,
            otp: [0; MAX_OTP],
            otp_len: 0,
            proved_at: 0,
        }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,   // in[0]:  MSG_ADMIT_REQ
    out_replies: i32,   // out[0]: MSG_ADMIT_RESP
    in_verify_key: i32, // in[1]:  MSG_KEY_ADD
    out_state: i32,     // out[1]: state requests
    in_state: i32,      // in[2]:  state replies
    out_mint: i32,      // out[2]: MSG_MINT_REQ (grant mode)
    in_mint: i32,       // in[3]:  MSG_MINT_RESP (grant mode)

    /// Monotonic; the correlation the ledger — and, in grant mode, the mint
    /// — answer with. Distinct ports, so one counter is safe.
    next_corr: u32,

    /// Grant-mode policy, all deployment params never client-supplied — a
    /// client presents only its credential, so it can widen nothing.
    /// `token_mint` signs `aud`/`scope`/`ttl` VERBATIM (it is the signer,
    /// not the authority), so the ONLY safe place for them is here.
    iss: [u8; MAX_FIELD],
    iss_len: u16,
    aud: [u8; MAX_FIELD],
    aud_len: u16,
    scope: [u8; MAX_FIELD],
    scope_len: u16,
    ttl_seconds: u32,
    /// Credential suite the minted token is signed under (`auth_wire::suite`).
    grant_suite: u16,

    /// The issuer keyset. More than one key, indexed by the `kid` a
    /// credential names — see `verify_keyset.rs` for why a single
    /// overwritten key made rotation destructive.
    keyset: verify_keyset::Keyset,

    /// DPoP identifiers already spent.
    replay: dpop::ReplayWindow<128>,

    pending: [Pending; MAX_IN_FLIGHT],

    admit_ok: u32,
    admit_unauthenticated: u32,
    admit_unknown_device: u32,
    admit_revoked: u32,
    admit_replay: u32,
    admit_unavailable: u32,
    admit_in_flight_full: u32,
    admit_unmatched_reply: u32,
    /// A one-time code was presented and did not hold.
    admit_bad_otp: u32,
    grant_ok: u32,
    grant_mint_failed: u32,

    buf: [u8; abi::CHANNEL_BUFFER_SIZE],
}

define_params! {
    ModuleState;

    // Grant-mode policy. All optional: a graph using admission for bare
    // admit (as token_endpoint does) sets none, and `grant_suite` then
    // defaults to Ed25519 — harmless, because a bare-admit graph never
    // reaches the mint path.
    1, iss, str, 0 => |s, d, len| {
        let n = if len > MAX_FIELD { MAX_FIELD } else { len };
        let mut i = 0usize;
        while i < n { s.iss[i] = *d.add(i); i += 1; }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_FIELD above")]
        { s.iss_len = n as u16; }
    };
    2, aud, str, 0 => |s, d, len| {
        let n = if len > MAX_FIELD { MAX_FIELD } else { len };
        let mut i = 0usize;
        while i < n { s.aud[i] = *d.add(i); i += 1; }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_FIELD above")]
        { s.aud_len = n as u16; }
    };
    3, scope, str, 0 => |s, d, len| {
        let n = if len > MAX_FIELD { MAX_FIELD } else { len };
        let mut i = 0usize;
        while i < n { s.scope[i] = *d.add(i); i += 1; }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_FIELD above")]
        { s.scope_len = n as u16; }
    };
    4, ttl_seconds, u32, 0 => |s, d, len| {
        if len >= 4 {
            s.ttl_seconds = u32::from_le_bytes([*d, *d.add(1), *d.add(2), *d.add(3)]);
        }
    };
    5, suite, u32, 2 => |s, d, len| {
        if len >= 1 { s.grant_suite = u16::from(*d); }
    };
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "module state is far below u32::MAX"
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
        // Grant-mode policy (iss/aud/scope/ttl/suite). Applies defaults even
        // when the graph passes none, so `grant_suite` is Ed25519 rather
        // than the 0 an uninitialised field would hold.
        parse_tlv(s, params, params_len);

        s.in_requests = in_chan;
        s.out_replies = out_chan;
        s.in_verify_key = dev_channel_port(sys, 0, 1);
        s.out_state = dev_channel_port(sys, 1, 1);
        s.in_state = dev_channel_port(sys, 0, 2);
        s.out_mint = dev_channel_port(sys, 1, 2);
        s.in_mint = dev_channel_port(sys, 0, 3);

        s.next_corr = 1;
        s.grant_ok = 0;
        s.grant_mint_failed = 0;
        s.keyset = verify_keyset::Keyset::new();
        s.replay = dpop::ReplayWindow::new();
        s.pending = [Pending::zero(); MAX_IN_FLIGHT];
        s.admit_ok = 0;
        s.admit_unauthenticated = 0;
        s.admit_unknown_device = 0;
        s.admit_revoked = 0;
        s.admit_replay = 0;
        s.admit_unavailable = 0;
        s.admit_in_flight_full = 0;
        s.admit_unmatched_reply = 0;
        s.admit_bad_otp = 0;

        // No ledger, no admission. Refused at CONSTRUCTION rather than at
        // the first request: without it, enrolment and revocation are both
        // unknown, and a module that starts and then refuses everything
        // looks like a runtime fault instead of a graph missing an edge.
        if s.out_state < 0 || s.in_state < 0 {
            dev_log(
                sys,
                1,
                b"[admit] refusing to construct: no ledger wired".as_ptr(),
                45,
            );
            return -1;
        }
        dev_log(sys, 3, b"[admit] init".as_ptr(), 12);
        0
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: as `module_new`.
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

/// Take verification keys off the control edge.
///
/// # Safety
///
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

/// Answer one caller with a refusal.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn reply(s: &mut ModuleState, sys: &SyscallTable, corr: u32, status: u8, grant: bool) {
    // Every refusal says which one it was. The counters aggregate; this is
    // for the operator holding one failing request, who otherwise sees a
    // status their caller mapped and has no way back to the reason.
    let why: &[u8] = match status {
        auth_wire::admit_err::UNAUTHENTICATED => b"[admit] refused: unauthenticated",
        auth_wire::admit_err::UNKNOWN_DEVICE => b"[admit] refused: unknown device",
        auth_wire::admit_err::REVOKED => b"[admit] refused: revoked",
        auth_wire::admit_err::NOT_PERMITTED => b"[admit] refused: not permitted",
        auth_wire::admit_err::STALE_PROOF => b"[admit] refused: stale proof",
        auth_wire::admit_err::REPLAY => b"[admit] refused: replayed proof",
        auth_wire::admit_err::STATE_UNAVAILABLE => b"[admit] refused: ledger unavailable",
        auth_wire::admit_err::NO_CLOCK => b"[admit] refused: no trusted clock",
        auth_wire::admit_err::NO_KEY => b"[admit] refused: no verification key",
        // Grant mode only, and the one reason that is not the presenter's
        // fault: admitted, then the signing failed. Without an arm of its
        // own it would log as `malformed` and send the operator looking at
        // the request.
        auth_wire::grant_err::MINT_FAILED => b"[grant] refused: mint failed",
        _ => b"[admit] refused: malformed",
    };
    dev_log(sys, 2, why.as_ptr(), why.len());
    let mut framed = [0u8; 1024];
    // A grant caller reads MSG_GRANT_RESP; an admit caller reads
    // MSG_ADMIT_RESP. Both refusals carry no identity and no token — the
    // rule each reply type enforces at decode.
    let encoded = if grant {
        auth_wire::GrantResponse {
            corr,
            status,
            token: b"",
        }
        .encode(&mut framed)
    } else {
        auth_wire::AdmitResponse {
            corr,
            status,
            sub: b"",
            device_id: b"",
            thumbprint_alg: auth_wire::suite::thumbprint::NONE,
            jkt: b"",
            // A refusal establishes nothing, so it carries no evidence — the
            // same rule as the identity fields beside it.
            evidence: auth_wire::assurance::EvidenceWire {
                methods: 0,
                key_binding: 0,
                flags: 0,
                auth_time: 0,
            },
        }
        .encode(&mut framed)
    };
    if let Ok(n) = encoded {
        if let Ok((wire_type, payload)) = auth_wire::read_envelope(&framed[..n]) {
            chan::channel_write_msg(sys, s.out_replies, wire_type, payload);
        }
    }
}

/// Answer one caller with the identity the credential established.
///
/// # Safety
///
/// As `reply`.
unsafe fn admit(s: &mut ModuleState, sys: &SyscallTable, entry: &Pending) {
    let resp = auth_wire::AdmitResponse {
        corr: entry.caller_corr,
        status: auth_wire::admit_err::OK,
        sub: &entry.sub[..usize::from(entry.sub_len)],
        device_id: &entry.device_id[..usize::from(entry.device_id_len)],
        thumbprint_alg: auth_wire::suite::thumbprint::JWK_SHA256,
        jkt: &entry.jkt,
        evidence: entry.evidence,
    };
    let mut framed = [0u8; 1024];
    if let Ok(n) = resp.encode(&mut framed) {
        if let Ok((wire_type, payload)) = auth_wire::read_envelope(&framed[..n]) {
            chan::channel_write_msg(sys, s.out_replies, wire_type, payload);
            s.admit_ok = s.admit_ok.saturating_add(1);
        }
    }
}

fn free_slot(s: &ModuleState) -> Option<usize> {
    s.pending.iter().position(|p| !p.live)
}

/// Take admission requests and start each one's ledger round trip.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
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
        // A GrantRequest is admit-and-mint; an AdmitRequest is admit only.
        // A GrantRequest decodes even with an empty credential (its corr must
        // be answered), and is refused in `handle`; an AdmitRequest that
        // fails to decode is dropped, because it carries no trustworthy corr.
        if msg_type == auth_wire::MSG_GRANT_REQ {
            if let Ok(g) = auth_wire::GrantRequest::decode(payload) {
                handle(
                    s,
                    sys,
                    &Ask {
                        corr: g.corr,
                        method: g.method,
                        uri: g.uri,
                        credential: g.credential,
                        proof: g.proof,
                        otp: g.otp,
                        grant: true,
                    },
                );
            }
        } else if let Ok(req) = auth_wire::AdmitRequest::decode(payload) {
            handle(
                s,
                sys,
                &Ask {
                    corr: req.corr,
                    method: req.method,
                    uri: req.uri,
                    credential: req.credential,
                    proof: req.proof,
                    otp: req.otp,
                    grant: false,
                },
            );
        } else {
            // No correlation to answer under. Dropped rather than answered
            // at a guessed correlation, which would resolve some other
            // caller's request. Logged, because the caller sees nothing.
            dev_log(
                sys,
                1,
                b"[admit] dropped: request did not decode".as_ptr(),
                39,
            );
        }
    }
    worked
}

/// Claiming the proof's replay identifier, so one proof admits once across
/// every replica sharing the ledger.
const STAGE_CLAIM_PROOF: u8 = 0;
/// Reading the device record.
const STAGE_DEVICE: u8 = 1;

/// Longest one-time code a presenter may offer.
const MAX_OTP: usize = 8;

/// One presentation, whichever request shape carried it.
///
/// The two differ in what they ask for and not in what they present, so the
/// admission path takes this and neither of them.
struct Ask<'a> {
    corr: u32,
    method: &'a [u8],
    uri: &'a [u8],
    credential: &'a [u8],
    proof: &'a [u8],
    otp: &'a [u8],
    grant: bool,
}

/// Fact 1, and the start of facts 2-3.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn handle(s: &mut ModuleState, sys: &SyscallTable, ask: &Ask<'_>) {
    let Ask {
        corr,
        method,
        uri,
        credential,
        proof,
        otp,
        grant,
    } = *ask;
    // A GrantRequest decodes with an empty credential so its corr survives to
    // be answered here — a GET /oauth/token, a wrong path, or an empty body
    // must get a refusal, not vanish. (An AdmitRequest never reaches this
    // with an empty credential: its decode rejects one.)
    if credential.is_empty() || proof.is_empty() {
        s.admit_unauthenticated = s.admit_unauthenticated.saturating_add(1);
        reply(s, sys, corr, auth_wire::admit_err::UNAUTHENTICATED, grant);
        return;
    }
    if s.keyset.is_empty() {
        s.admit_unavailable = s.admit_unavailable.saturating_add(1);
        reply(s, sys, corr, auth_wire::admit_err::NO_KEY, grant);
        return;
    }

    // The presented certificate's window. Without a trustworthy clock this
    // refuses as NO_CLOCK, which is not a refusal of the presenter: nothing
    // looked at them.
    let obs = dev_trusted_unix(sys);
    let Some(now) = time_policy::now_for(time_policy::Decision::CredentialWindow, &obs) else {
        s.admit_unavailable = s.admit_unavailable.saturating_add(1);
        reply(s, sys, corr, auth_wire::admit_err::NO_CLOCK, grant);
        return;
    };

    // Which key signed the credential is the credential's own claim, in its
    // JOSE header. It is looked up, never guessed: an unknown kid is refused
    // rather than checked against whatever key is loaded.
    let mut pubkey = [0u8; 65];
    let mut pubkey_len = 0usize;
    let mut key_suite = 0u16;
    let mut kid = [0u8; verify_keyset::MAX_KID_LEN];
    if let Some(kid_len) = device_auth::credential_kid(credential, &mut kid) {
        if let Some(k) = s.keyset.select(&kid[..kid_len], now) {
            pubkey_len = k.pubkey_bytes().len();
            pubkey[..pubkey_len].copy_from_slice(k.pubkey_bytes());
            key_suite = k.suite;
        }
    }

    let mut claims_buf = [0u8; device_auth::MAX_SEGMENT];
    let mut replayed = false;
    let mut proof_id = [0u8; 32];
    let admitted = {
        // The window fails closed: a saturated one refuses rather than
        // evicting a live entry, because an eviction under load is an
        // admission under load. Both outcomes reach `device_auth` as
        // `false`; `replayed` keeps them apart for the reply, since
        // "somebody replayed a proof" and "the window is saturated" are
        // different operator problems.
        let seen = &mut replayed;
        let claimed = &mut proof_id;
        let mut offer = |jti: &[u8; 32]| {
            // Kept for the durable claim below. The local window answers
            // first because it is free and catches a replay inside this
            // process immediately; the ledger answers for every process.
            *claimed = *jti;
            match s.replay.offer(jti, now, now + PROOF_WINDOW_SECS) {
                dpop::Replay::Recorded => true,
                dpop::Replay::Seen | dpop::Replay::Full => {
                    *seen = true;
                    false
                }
            }
        };
        device_auth::authenticate(
            &VERIFIERS,
            &device_auth::IssuerKey {
                suite: key_suite,
                public: &pubkey[..pubkey_len],
            },
            &device_auth::Presentation { credential, proof },
            &device_auth::Request { method, uri, now },
            &POLICY,
            &mut claims_buf,
            &mut offer,
        )
    };
    let Ok(admitted) = admitted else {
        if replayed {
            s.admit_replay = s.admit_replay.saturating_add(1);
            reply(s, sys, corr, auth_wire::admit_err::REPLAY, grant);
        } else {
            s.admit_unauthenticated = s.admit_unauthenticated.saturating_add(1);
            reply(s, sys, corr, auth_wire::admit_err::UNAUTHENTICATED, grant);
        }
        return;
    };

    // What the certificate authorises, read FROM the certificate. `sub` is
    // the tenant the enrolment bound, and the thumbprint is the one the
    // certificate was issued against — which `device_auth` has already shown
    // belongs to the key that signed the proof.
    let (Some(cert_sub), Some(device_id)) = (
        jose::claim_str(admitted.claims, b"sub"),
        jose::claim_str(admitted.claims, b"device_id"),
    ) else {
        s.admit_unauthenticated = s.admit_unauthenticated.saturating_add(1);
        reply(s, sys, corr, auth_wire::admit_err::UNAUTHENTICATED, grant);
        return;
    };

    let Some(index) = free_slot(s) else {
        s.admit_in_flight_full = s.admit_in_flight_full.saturating_add(1);
        reply(s, sys, corr, auth_wire::admit_err::STATE_UNAVAILABLE, grant);
        return;
    };

    let mut entry = Pending::zero();
    entry.caller_corr = corr;
    entry.grant = grant;
    let sub_len = cert_sub.len().min(MAX_FIELD);
    entry.sub[..sub_len].copy_from_slice(&cert_sub[..sub_len]);
    let device_len = device_id.len().min(MAX_FIELD);
    entry.device_id[..device_len].copy_from_slice(&device_id[..device_len]);
    entry.jkt = admitted.thumbprint;
    entry.proved_at = now;
    let otp_len = otp.len().min(MAX_OTP);
    entry.otp[..otp_len].copy_from_slice(&otp[..otp_len]);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_OTP")]
    {
        entry.otp_len = otp_len as u8;
    }
    #[expect(clippy::cast_possible_truncation, reason = "each bounded by MAX_FIELD")]
    {
        entry.sub_len = sub_len as u16;
        entry.device_id_len = device_len as u16;
    }

    // The proof's replay id, in the keyspace's alphabet. The digest rather
    // than the client's own `jti`: a `jti` is whatever the client wrote, and
    // a key built from it would be a key the client chooses.
    let mut replay_key = [0u8; 43];
    let Some(replay_key_len) = b64::encode(&proof_id, &mut replay_key) else {
        s.admit_unavailable = s.admit_unavailable.saturating_add(1);
        reply(s, sys, corr, auth_wire::admit_err::STATE_UNAVAILABLE, grant);
        return;
    };
    entry.replay_key = replay_key;
    #[expect(clippy::cast_possible_truncation, reason = "base64url of 32 bytes is 43")]
    {
        entry.replay_key_len = replay_key_len as u8;
    }

    let state_corr = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);
    entry.state_corr = state_corr;
    entry.stage = STAGE_CLAIM_PROOF;

    // The replay claim goes FIRST, before the device is even looked up. A
    // proof this authority has already answered is not a request; spending a
    // ledger round trip on the device record before finding that out would
    // be doing work for a replay.
    let request = state_wire::claim_replay(
        state_corr,
        STATE_CLIENT,
        &replay_key[..replay_key_len],
        now + PROOF_WINDOW_SECS,
    );
    let mut frame = [0u8; 512];
    let Ok(n) = state_wire::encode_request(&mut frame, state_wire::MSG_STATE_PUT_ABS, &request)
    else {
        s.admit_unavailable = s.admit_unavailable.saturating_add(1);
        reply(s, sys, corr, auth_wire::admit_err::STATE_UNAVAILABLE, grant);
        return;
    };
    let Ok((wire_type, payload)) = auth_wire::read_envelope(&frame[..n]) else {
        s.admit_unavailable = s.admit_unavailable.saturating_add(1);
        reply(s, sys, corr, auth_wire::admit_err::STATE_UNAVAILABLE, grant);
        return;
    };
    if chan::channel_write_msg(sys, s.out_state, wire_type, payload) <= 0 {
        s.admit_unavailable = s.admit_unavailable.saturating_add(1);
        reply(s, sys, corr, auth_wire::admit_err::STATE_UNAVAILABLE, grant);
        return;
    }
    entry.live = true;
    s.pending[index] = entry;
}

/// Facts 2 and 3, once the ledger has answered.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn drain_state(s: &mut ModuleState, sys: &SyscallTable) -> bool {
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
            s.admit_unmatched_reply = s.admit_unmatched_reply.saturating_add(1);
            continue;
        };
        worked = true;
        let entry = s.pending[index];
        s.pending[index] = Pending::zero();

        // The replay claim's answer, before anything about the device.
        if entry.stage == STAGE_CLAIM_PROOF {
            match state_wire::replay_claim_result(rep.status) {
                state_wire::ReplayClaim::Fresh => {}
                state_wire::ReplayClaim::Replayed => {
                    // Seen by this process or another sharing the ledger.
                    // The local window catches the first case for free; this
                    // is the one it cannot see.
                    s.admit_replay = s.admit_replay.saturating_add(1);
                    reply(
                        s,
                        sys,
                        entry.caller_corr,
                        auth_wire::admit_err::REPLAY,
                        entry.grant,
                    );
                    continue;
                }
                state_wire::ReplayClaim::Unavailable => {
                    // A claim that could not be made is a proof whose
                    // freshness nothing established. Admitting anyway would
                    // make the ledger's absence a way to replay.
                    s.admit_unavailable = s.admit_unavailable.saturating_add(1);
                    reply(
                        s,
                        sys,
                        entry.caller_corr,
                        auth_wire::admit_err::STATE_UNAVAILABLE,
                        entry.grant,
                    );
                    continue;
                }
            }
            if !stage_device_read(s, sys, index, &entry) {
                s.admit_unavailable = s.admit_unavailable.saturating_add(1);
                reply(
                    s,
                    sys,
                    entry.caller_corr,
                    auth_wire::admit_err::STATE_UNAVAILABLE,
                    entry.grant,
                );
            }
            continue;
        }

        match rep.status {
            auth_wire::ST_OK => {}
            auth_wire::ST_NOT_FOUND => {
                // The certificate verifies but the ledger does not hold the
                // device. That is a certificate outliving its enrolment, and
                // it must not mint.
                s.admit_unknown_device = s.admit_unknown_device.saturating_add(1);
                reply(
                    s,
                    sys,
                    entry.caller_corr,
                    auth_wire::admit_err::UNKNOWN_DEVICE,
                    entry.grant,
                );
                continue;
            }
            _ => {
                s.admit_unavailable = s.admit_unavailable.saturating_add(1);
                reply(
                    s,
                    sys,
                    entry.caller_corr,
                    auth_wire::admit_err::STATE_UNAVAILABLE,
                    entry.grant,
                );
                continue;
            }
        }

        // Revocation is checked HERE, at admission, which is the whole point
        // of the short-lived model: a relying party validating a credential
        // locally cannot know what the issuer has since been told, so the
        // issuer has to stop issuing.
        if matches!(jose::claim_str(rep.value, b"status"), Some(b"revoked")) {
            s.admit_revoked = s.admit_revoked.saturating_add(1);
            reply(
                s,
                sys,
                entry.caller_corr,
                auth_wire::admit_err::REVOKED,
                entry.grant,
            );
            continue;
        }

        // A presented code is checked against the authenticator the record
        // holds. A code that does not hold refuses the request outright:
        // admitting at the lower level instead would make a wrong code worth
        // exactly as much as no code, which is how a second factor becomes
        // optional in practice while looking mandatory in policy.
        let mut entry = entry;
        let otp_verified = match verify_presented_otp(&entry, rep.value) {
            OtpOutcome::NonePresented => false,
            OtpOutcome::Verified => true,
            OtpOutcome::Refused => {
                s.admit_bad_otp = s.admit_bad_otp.saturating_add(1);
                reply(
                    s,
                    sys,
                    entry.caller_corr,
                    auth_wire::admit_err::UNAUTHENTICATED,
                    entry.grant,
                );
                continue;
            }
        };

        // Assemble what the presenter proved, now that both halves are in
        // hand: the enrolment facts the ledger record carries, and the
        // possession proof this request just made. Scoring is the shared
        // fragment's, so what admission establishes and what a relying party
        // later checks are the same ladder.
        entry.evidence = establish_evidence(rep.value, entry.proved_at, otp_verified);

        if entry.grant {
            emit_mint(s, sys, index, &entry);
        } else {
            admit(s, sys, &entry);
        }
    }
    worked
}

/// What the presenter proved, from the enrolment record and this request.
///
/// Two sources, and neither alone is the answer. The record says how the
/// device was ENROLLED — which channel proved control, where its key lives —
/// and the request in front of us says the device holds that key NOW. A
/// token's `amr` has to carry both or it describes an authentication that
/// did not happen.
///
/// `auth_time` is this proof, not the enrolment: the device authenticated
/// just now by signing, and reporting the enrolment instant would make every
/// token look as old as the device.
///
/// Unrecognised methods in the record are dropped rather than carried, so a
/// record written by a newer build cannot inflate a level this one computes.
fn establish_evidence(
    record: &[u8],
    now: u64,
    otp_verified: bool,
) -> auth_wire::assurance::EvidenceWire {
    use auth_wire::assurance::{AuthMethod, Evidence, KeyBinding};

    // The proof this request made. Always present: admission does not reach
    // here without a verified possession proof.
    let mut evidence = Evidence::at(now).with(AuthMethod::Pop);
    if otp_verified {
        // Knowledge, against the device key's possession — the second
        // category, and the whole reason a code was asked for.
        evidence = evidence.with(AuthMethod::Otp);
    }

    if let Some(amr) = jose::claim_array(record, b"amr") {
        for name in amr {
            evidence = evidence.with_amr_name(name);
        }
    }
    evidence = match jose::claim_str(record, b"key_binding") {
        Some(b"hardware") => evidence.key_binding(KeyBinding::Hardware),
        // Software unless the enrolment recorded otherwise. A device key this
        // issuer never saw generated is a software key as far as it knows,
        // and guessing upward is the one direction that must not happen.
        _ => evidence.key_binding(KeyBinding::Software),
    };
    if matches!(jose::claim_str(record, b"user_verified"), Some(b"true")) {
        evidence = evidence.user_verified(true);
    }
    evidence.encode()
}

/// What checking a presented code concluded.
enum OtpOutcome {
    /// No code was offered. Not a failure: a second factor is optional, and
    /// a request without one is admitted at whatever its other proofs reach.
    NonePresented,
    /// The code matched a live step this authenticator has not used.
    Verified,
    /// A code was offered and did not hold, or there was no confirmed
    /// authenticator to check it against.
    Refused,
}

/// Check a presented code against the authenticator in the device record.
///
/// An UNCONFIRMED authenticator verifies nothing. Registration draws a secret
/// and confirmation proves the device can compute its codes; between the two
/// there is a secret nobody has demonstrated they hold, and treating it as a
/// factor would let a registration that never worked raise an assurance
/// level.
///
/// The counter is NOT advanced here. This module reads the record and does
/// not own it — advancing a counter it cannot conditionally write would be a
/// claim it cannot keep, and the freshness this check needs comes from the
/// step window, which is 90 seconds wide. Single use across that window is
/// the authenticator's own property, enforced where the record is written.
fn verify_presented_otp(entry: &Pending, record: &[u8]) -> OtpOutcome {
    let code_bytes = &entry.otp[..usize::from(entry.otp_len)];
    if code_bytes.is_empty() {
        return OtpOutcome::NonePresented;
    }
    if !matches!(jose::claim_str(record, b"totp_confirmed"), Some(b"true")) {
        return OtpOutcome::Refused;
    }
    let Some(held) = jose::claim_str(record, b"totp_secret") else {
        return OtpOutcome::Refused;
    };
    let Ok(code) = totp::parse_code(code_bytes) else {
        return OtpOutcome::Refused;
    };
    let mut secret = [0u8; totp::MAX_SECRET];
    let Ok(secret_len) = totp::base32_decode(held, &mut secret) else {
        return OtpOutcome::Refused;
    };
    let last = jose::claim_u64(record, b"totp_counter");
    match totp::verify_totp(
        hmac_sha256_into,
        &secret[..secret_len],
        code,
        entry.proved_at,
        0,
        TOTP_PERIOD,
        TOTP_DIGITS,
        TOTP_SKEW,
        last,
    ) {
        Ok(Some(_)) => OtpOutcome::Verified,
        _ => OtpOutcome::Refused,
    }
}

/// HMAC-SHA256 in the shape the TOTP fragment takes.
fn hmac_sha256_into(key: &[u8], message: &[u8], out: &mut [u8]) -> usize {
    let n = out.len().min(32);
    hmac(HashAlg::Sha256, key, message, &mut out[..n]);
    n
}

/// The TOTP profile this issuer verifies under, matching the one
/// `enrollment_endpoint` registers. Two copies of these numbers would be two
/// authenticators, one of which works.
const TOTP_DIGITS: u8 = 6;
const TOTP_PERIOD: u64 = 30;
const TOTP_SKEW: u64 = 1;

/// Ask the ledger for the device record, once the proof is claimed.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn stage_device_read(
    s: &mut ModuleState,
    sys: &SyscallTable,
    index: usize,
    entry: &Pending,
) -> bool {
    let state_corr = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);
    let request = state_wire::get(
        state_corr,
        STATE_CLIENT,
        state_wire::NS_DEVICE,
        &entry.device_id[..usize::from(entry.device_id_len)],
    );
    let mut frame = [0u8; 512];
    let sent = state_wire::encode_request(&mut frame, state_wire::MSG_STATE_GET, &request)
        .ok()
        .and_then(|n| auth_wire::read_envelope(&frame[..n]).ok())
        .is_some_and(|(t, p)| chan::channel_write_msg(sys, s.out_state, t, p) > 0);
    if !sent {
        return false;
    }
    let mut next = *entry;
    next.stage = STAGE_DEVICE;
    next.state_corr = state_corr;
    next.live = true;
    s.pending[index] = next;
    true
}

/// The presenter is admitted; MINT under the deployment's policy.
///
/// The `MintRequest` is built HERE, in kagi, from the subject and key
/// binding admission ESTABLISHED — the pipeline never sees them, which is
/// what keeps `/oauth/token` inside C14. `aud`/`scope`/`ttl`/`iss`/`suite`
/// are deployment PARAMS, never client-supplied: `token_mint` signs them
/// verbatim, so this is the only place they can be bounded.
///
/// The Pending entry is REUSED (not freed) and re-staged to await the mint
/// reply on a THIRD correlation. Every failure frees it and answers
/// MINT_FAILED — a leaked STAGE_GRANT_MINT slot would eventually refuse
/// every admit-only caller too.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn emit_mint(s: &mut ModuleState, sys: &SyscallTable, index: usize, entry: &Pending) {
    if s.out_mint < 0 {
        // Grant mode was asked of a graph that wired no mint. Fail closed,
        // as a refusal the caller can see.
        s.grant_mint_failed = s.grant_mint_failed.saturating_add(1);
        reply(
            s,
            sys,
            entry.caller_corr,
            auth_wire::grant_err::MINT_FAILED,
            true,
        );
        return;
    }
    let mint_corr = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);

    // What the presenter proved, as the three claims a relying party reads.
    // Rendered by the shared fragment: the level in `acr` and the methods in
    // `amr` are scored from one place, so a token cannot claim a level its
    // own method list does not support.
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

    let req = auth_wire::MintRequest {
        correlation: mint_corr,
        request_type: auth_wire::request_type::MINT,
        suite: s.grant_suite,
        profile_id: auth_wire::suite::profile::ACCESS_TOKEN,
        kid: b"",
        ttl_seconds: s.ttl_seconds,
        iss: &s.iss[..usize::from(s.iss_len)],
        sub: &entry.sub[..usize::from(entry.sub_len)],
        aud: &s.aud[..usize::from(s.aud_len)],
        scope: &s.scope[..usize::from(s.scope_len)],
        thumbprint_alg: auth_wire::suite::thumbprint::JWK_SHA256,
        jkt: Some(&entry.jkt),
        extra: auth_wire::ExtraClaims::Slice(&extra),
    };
    let mut framed = [0u8; 4096];
    let ok = req
        .encode(&mut framed)
        .ok()
        .and_then(|n| auth_wire::read_envelope(&framed[..n]).ok())
        .map(|(t, p)| chan::channel_write_msg(sys, s.out_mint, t, p) > 0)
        .unwrap_or(false);
    if !ok {
        s.grant_mint_failed = s.grant_mint_failed.saturating_add(1);
        reply(
            s,
            sys,
            entry.caller_corr,
            auth_wire::grant_err::MINT_FAILED,
            true,
        );
        return;
    }
    // Re-stage the SAME entry to await the mint reply. sub/jkt are no longer
    // needed (the request is out) but the caller_corr is, to answer with.
    let mut staged = *entry;
    staged.live = true;
    staged.awaiting_mint = true;
    staged.mint_corr = mint_corr;
    s.pending[index] = staged;
}

/// The mint has answered; relay it as the grant response.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn drain_mint(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    if s.in_mint < 0 {
        return false;
    }
    let mut worked = false;
    while chan::can_read(sys, s.in_mint) {
        // A token-bearing MintResponse can approach TOKEN_BUF_LEN; size for
        // the whole envelope so a real JWT is never truncated.
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
        let Some(index) = s
            .pending
            .iter()
            .position(|p| p.live && p.awaiting_mint && p.mint_corr == rep.correlation)
        else {
            s.admit_unmatched_reply = s.admit_unmatched_reply.saturating_add(1);
            continue;
        };
        worked = true;
        let entry = s.pending[index];
        s.pending[index] = Pending::zero();

        // A non-OK mint, or one delivered as an object handle rather than an
        // inline token, is a 5xx: the presenter was fine, the SIGNING was
        // not. An object handle would mean the token was too large to inline
        // — for an access token that is a misconfiguration, not something to
        // hand a client half of.
        if rep.status != auth_wire::mint_err::OK || rep.delivery != auth_wire::delivery::INLINE {
            s.grant_mint_failed = s.grant_mint_failed.saturating_add(1);
            reply(
                s,
                sys,
                entry.caller_corr,
                auth_wire::grant_err::MINT_FAILED,
                true,
            );
            continue;
        }
        grant_ok(s, sys, entry.caller_corr, rep.body);
    }
    worked
}

/// Answer a grant caller with the minted token.
///
/// # Safety
///
/// As `drain_mint`.
unsafe fn grant_ok(s: &mut ModuleState, sys: &SyscallTable, corr: u32, token: &[u8]) {
    let resp = auth_wire::GrantResponse {
        corr,
        status: auth_wire::grant_err::OK,
        token,
    };
    let mut framed = [0u8; 8192];
    if let Ok(n) = resp.encode(&mut framed) {
        if let Ok((wire_type, payload)) = auth_wire::read_envelope(&framed[..n]) {
            chan::channel_write_msg(sys, s.out_replies, wire_type, payload);
            s.grant_ok = s.grant_ok.saturating_add(1);
        }
    }
}

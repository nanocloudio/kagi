//! Control-act mint — sign a control act (`KCAC`) for an actor this issuer
//! has authenticated.
//!
//! A typed operation: a PROVIDER of the workspace exchange contract on
//! `request_in` / `response_out`. Each request body is one
//! `control_act::msg::MINT_REQ` envelope (`control_act::MintRequest`) and
//! each answer body one `MINT_RESP` envelope: the signed record, or a typed
//! refusal. Every verdict is a 200 exchange.
//!
//! **The actor is never a field of the request.** It is established from
//! the cert-bound identity carrier the request carries
//! (`cert_bound_identity.rs`): a short-lived JWS the actor signed with the
//! leaf key its SPIFFE certificate names, carrying the leaf in `x5c`. The
//! leaf is checked against the authority's key on `ca_key` (a chain of one,
//! which is the only chain `certificate_endpoint` issues), the signature
//! against the leaf's key, and the SPIFFE name in the leaf gives the actor's
//! class and 16-byte id (`spiffe::parse`). `SHA-256(leaf public key)` — the
//! SVID the mTLS control link would have reported for the same leaf — is
//! what the audit entry records. A caller holding an operator credential
//! can therefore obtain an act for that operator and for nobody else. When
//! the exchange arrives over mTLS (`tls` in front of wave's `http`), its
//! verified SVID is the exchange's `peer`, and the carrier must name the
//! same key: a carrier lifted onto another operator's connection is
//! refused.
//!
//! The act is signed in the vault under the `CONTROL_ACT` profile's key,
//! named by label on `signing_key`; its public half is announced on
//! `key_announce` for every `control_act_verify` in the deployment. One
//! audit entry (`KCAA`) per decision leaves on `audit_out`; this module
//! keeps nothing — not the act, not the audit — because Kagi is never the
//! state store for the acts it signs.

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
#[path = "../../common/b64.rs"]
mod b64;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/control_act.rs"]
mod control_act;
#[path = "../../common/exchange_peer.rs"]
mod exchange_peer;
#[path = "../../common/issuer_key.rs"]
mod issuer_key;
#[path = "../../common/jose.rs"]
mod jose;
#[path = "../../../target/fluxor/fluxor-abi/sdk/contracts/key_vault.rs"]
mod key_vault;
#[path = "../../common/spiffe.rs"]
mod spiffe;
#[path = "../../common/time_policy.rs"]
mod time_policy;
#[path = "../../common/typed_exchange.rs"]
mod typed_exchange;
#[path = "../../common/x509_leaf.rs"]
mod x509_leaf;

/// The carrier verifier. `include!`-style: it reads JOSE through the `b64`
/// and `jose` fragments mounted above, so it is wrapped in a module that
/// puts them in scope, as the harness wraps the same file.
mod cert_bound_identity {
    use crate::{b64, jose};
    include!("../../common/cert_bound_identity.rs");
}

use abi::contracts::exchange::{self as x, Collector, ExchangeId};
use control_act as ca;

const STEP_DID_WORK: i32 = 2;
const MAX_REQS_PER_STEP: usize = 2;
const MAX_EXCHANGES: usize = 4;
const MAX_TARGET: usize = 256;
const MAX_HEADERS: usize = 1024;
/// Longest request body: a mint request whose carrier holds a leaf.
const MAX_REQUEST: usize = x::PAYLOAD_MAX;
/// Longest issuer, trust domain or audience the graph names.
const MAX_FIELD: usize = 128;
/// The kid every act names. One key per profile at a time; rotation is
/// ADD/ACTIVATE on `signing_key` under a new label, announced under the
/// generation the record carries.
const KID: &[u8] = b"control-act";
/// Carriers remembered against replay, and how long. A carrier lives at
/// most five minutes (`cert_bound_identity`), so an entry older than that
/// can be forgotten.
const REPLAY_SLOTS: usize = 64;
const REPLAY_ID_MAX: usize = cert_bound_identity::CARRIER_JTI_MAX;

#[repr(C)]
#[derive(Clone, Copy)]
struct Seen {
    id: [u8; REPLAY_ID_MAX],
    len: u8,
    expires_at: u64,
}

impl Seen {
    const EMPTY: Self = Self {
        id: [0; REPLAY_ID_MAX],
        len: 0,
        expires_at: 0,
    };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    out_responses: i32,
    in_key: i32,
    in_ca_key: i32,
    out_key_announce: i32,
    out_audit: i32,
    announce: u8,

    /// The CONTROL_ACT signing key, as a vault label.
    key: issuer_key::IssuerKey,
    key_pending: issuer_key::PendingRecord,
    sign_scratch: [u8; ca::MAX_RECORD + issuer_key::SIGN_SCRATCH_OVERHEAD],

    /// The authority's key, as `x509_leaf::anchor` reads it:
    /// `[suite u16][public]`. Empty until `ca_key` delivers one.
    anchor: [u8; 2 + 65],
    anchor_len: u8,

    issuer: [u8; MAX_FIELD],
    issuer_len: u8,
    trust_domain: [u8; MAX_FIELD],
    trust_domain_len: u8,
    audience: [u8; MAX_FIELD],
    audience_len: u8,

    seen: [Seen; REPLAY_SLOTS],

    act_minted: u32,
    act_refused: u32,
    act_unauthenticated: u32,
    act_no_key: u32,

    requests: Collector<MAX_EXCHANGES, MAX_TARGET, MAX_HEADERS, MAX_REQUEST>,
    /// The verified peer each collecting exchange arrived with.
    peers: exchange_peer::Peers<MAX_EXCHANGES>,
    outbox: ExchangeOutbox,
    buf: [u8; x::RECORD_MAX],
    out: [u8; x::RECORD_MAX],
}

define_params! {
    ModuleState;

    1, iss, str, 0 => |s, d, len| {
        let n = if len > MAX_FIELD { MAX_FIELD } else { len };
        let mut i = 0usize;
        while i < n {
            s.issuer[i] = *d.add(i);
            i += 1;
        }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_FIELD above")]
        {
            s.issuer_len = n as u8;
        }
    };

    2, trust_domain, str, 0 => |s, d, len| {
        let n = if len > MAX_FIELD { MAX_FIELD } else { len };
        let mut i = 0usize;
        while i < n {
            s.trust_domain[i] = *d.add(i);
            i += 1;
        }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_FIELD above")]
        {
            s.trust_domain_len = n as u8;
        }
    };

    3, audience, str, 0 => |s, d, len| {
        let n = if len > MAX_FIELD { MAX_FIELD } else { len };
        let mut i = 0usize;
        while i < n {
            s.audience[i] = *d.add(i);
            i += 1;
        }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_FIELD above")]
        {
            s.audience_len = n as u8;
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

#[expect(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "fluxor module ABI entry point: the runtime owns these pointers \
              and the signature is fixed by the contract"
)]
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
        s.in_ca_key = dev_channel_port(sys, 0, 2);
        s.out_key_announce = dev_channel_port(sys, 1, 1);
        s.out_audit = dev_channel_port(sys, 1, 2);
        s.announce = 0;
        s.key = issuer_key::IssuerKey::empty();
        s.key_pending = issuer_key::PendingRecord::empty();
        s.anchor = [0; 2 + 65];
        s.anchor_len = 0;
        s.issuer = [0; MAX_FIELD];
        s.issuer_len = 0;
        s.trust_domain = [0; MAX_FIELD];
        s.trust_domain_len = 0;
        s.audience = [0; MAX_FIELD];
        s.audience_len = 0;
        s.seen = [Seen::EMPTY; REPLAY_SLOTS];
        s.act_minted = 0;
        s.act_refused = 0;
        s.act_unauthenticated = 0;
        s.act_no_key = 0;
        s.requests = Collector::new();
        s.peers = exchange_peer::Peers::new();
        s.outbox = ExchangeOutbox::new();

        parse_tlv(s, params, params_len);

        if s.issuer_len == 0 || s.trust_domain_len == 0 || s.audience_len == 0 {
            // An issuer with no name signs for nobody; a trust domain it
            // does not know admits every name; an audience it did not
            // declare is one every carrier matches.
            dev_log(
                sys,
                1,
                b"[act-mint] iss, trust_domain and audience are required".as_ptr(),
                55,
            );
            return -3;
        }
        dev_log(sys, 3, b"[act-mint] init".as_ptr(), 15);
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
        drain_ca_key(s, sys);
        announce_key(s, sys);

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
                let ModuleState {
                    requests,
                    peers,
                    buf,
                    ..
                } = &mut *s;
                let record = buf.get(..n as usize).unwrap_or(&[]);
                peers.note(record);
                requests.accept(record)
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
                handle_mint(s, sys, at);
            }
        }
        if worked {
            STEP_DID_WORK
        } else {
            0
        }
    }
}

/// Take the CONTROL_ACT signing key from a `MSG_KEY_ADD`.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live syscall table.
unsafe fn drain_key(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_key < 0 {
        return;
    }
    if s.key_pending.is_held() {
        let mut held = [0u8; issuer_key::KEY_RECORD_MAX];
        let n = s.key_pending.take(&mut held);
        if take_key_record(s, sys, &held[..n]) {
            s.key_pending.hold(&held[..n]);
            return;
        }
    }
    for _ in 0..4 {
        if !chan::can_read(sys, s.in_key) {
            break;
        }
        let mut buf = [0u8; 256];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_key, &mut buf);
        if msg_type != auth_wire::MSG_KEY_ADD {
            continue;
        }
        let payload = &buf[..usize::from(plen)];
        if take_key_record(s, sys, payload) {
            s.key_pending.hold(payload);
            return;
        }
    }
}

/// Act on one key ADD record. True when the vault could not open its key
/// yet (`E_AGAIN`).
///
/// # Safety
///
/// As `drain_key`.
unsafe fn take_key_record(s: &mut ModuleState, sys: &SyscallTable, payload: &[u8]) -> bool {
    let Ok(rec) = auth_wire::KeyRecord::decode_add(payload) else {
        return false;
    };
    if rec.key_use != auth_wire::key_use::SIGN
        || rec.profile_id != auth_wire::suite::profile::CONTROL_ACT
    {
        return false;
    }
    if !matches!(
        rec.suite,
        auth_wire::suite::ED25519 | auth_wire::suite::ES256
    ) || rec.key_ref.is_empty()
        || rec.key_ref.len() > auth_wire::MAX_KEY_LABEL
    {
        return false;
    }
    s.key.close(sys);
    match s.key.open_status(sys, rec.suite, rec.key_ref) {
        0 => s.announce = 1,
        E_AGAIN => return true,
        _ => {}
    }
    false
}

/// Take the authority's public key from a VERIFY `MSG_KEY_ADD` on `ca_key`:
/// what `certificate_endpoint` announces on its `key_announce`. The latest
/// one delivered is the anchor; a rotation of the CA is a new record.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn drain_ca_key(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_ca_key < 0 {
        return;
    }
    for _ in 0..4 {
        if !chan::can_read(sys, s.in_ca_key) {
            break;
        }
        let mut buf = [0u8; 512];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_ca_key, &mut buf);
        if msg_type != auth_wire::MSG_KEY_ADD {
            continue;
        }
        let Ok(rec) = auth_wire::KeyRecord::decode_add(&buf[..usize::from(plen)]) else {
            continue;
        };
        if rec.key_use != auth_wire::key_use::VERIFY {
            continue;
        }
        let mut anchor = [0u8; 2 + 65];
        let Some(n) = x509_leaf::write_anchor(rec.suite, rec.key_ref, &mut anchor) else {
            continue;
        };
        if x509_leaf::anchor(&anchor[..n]).is_none() {
            continue;
        }
        s.anchor = anchor;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "at most 67 bytes, the buffer's length"
        )]
        {
            s.anchor_len = n as u8;
        }
    }
}

/// Announce the open key's public half as a VERIFY `MSG_KEY_ADD`.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn announce_key(s: &mut ModuleState, sys: &SyscallTable) {
    if s.announce == 0 || s.out_key_announce < 0 || !s.key.is_open() {
        return;
    }
    let rec = auth_wire::KeyRecord {
        issuer: &s.issuer[..usize::from(s.issuer_len)],
        profile_id: auth_wire::suite::profile::CONTROL_ACT,
        kid: KID,
        suite: s.key.suite(),
        state: auth_wire::key_state::ACTIVE,
        key_use: auth_wire::key_use::VERIFY,
        generation: 0,
        activate_after_unix: 0,
        remove_after_unix: 0,
        key_ref: s.key.public_key(),
    };
    let mut payload = [0u8; 512];
    let mut w = auth_wire::PayloadWriter::new(&mut payload);
    if rec.write(&mut w).is_err() {
        s.announce = 0;
        return;
    }
    let n = w.len();
    if chan::channel_write_msg(
        sys,
        s.out_key_announce,
        auth_wire::MSG_KEY_ADD,
        &payload[..n],
    ) > 0
    {
        s.announce = 0;
    }
}

// ── The carrier's primitives ───────────────────────────────────────────

fn sha256_into(data: &[u8], out: &mut [u8; 32]) {
    *out = sha256(data);
}

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

fn carrier_ecdsa(public: &[u8], hash: &[u8; 32], signature: &[u8; 64]) -> bool {
    public.len() == 65 && ecdsa_verify(public, hash, signature)
}

fn carrier_chain(
    cert_msg: &[u8],
    anchor: &[u8],
    expected_uri: &[u8],
    now: u64,
    require_clock: bool,
) -> u32 {
    x509_leaf::verify_chain(
        verify_suite,
        cert_msg,
        anchor,
        expected_uri,
        now,
        require_clock,
    )
}

const VERIFIERS: cert_bound_identity::CarrierVerifiers = cert_bound_identity::CarrierVerifiers {
    sha256: sha256_into,
    ecdsa_verify: carrier_ecdsa,
    verify_chain: carrier_chain,
    leaf_public_key: x509_leaf::leaf_public_key,
};

/// Whether `id` was presented inside its window before; records it if not.
fn replayed(seen: &mut [Seen; REPLAY_SLOTS], id: &[u8], expires_at: u64, now_secs: u64) -> bool {
    if id.is_empty() || id.len() > REPLAY_ID_MAX {
        return true;
    }
    for slot in seen.iter_mut() {
        if slot.len != 0 && slot.expires_at <= now_secs {
            *slot = Seen::EMPTY;
        }
    }
    if seen
        .iter()
        .any(|slot| slot.len != 0 && &slot.id[..usize::from(slot.len)] == id)
    {
        return true;
    }
    // A full table evicts the soonest to expire: the entry with the least
    // window left is the one a replay has the least time to exploit.
    let slot = seen
        .iter_mut()
        .min_by_key(|slot| if slot.len == 0 { 0 } else { slot.expires_at });
    if let Some(slot) = slot {
        *slot = Seen::EMPTY;
        for (d, s) in slot.id.iter_mut().zip(id) {
            *d = *s;
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "bounded by REPLAY_ID_MAX above"
        )]
        {
            slot.len = id.len() as u8;
        }
        slot.expires_at = expires_at;
    }
    false
}

/// The one decision: who asked, and the act they get.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live syscall table.
unsafe fn handle_mint(s: &mut ModuleState, sys: &SyscallTable, at: usize) {
    let Some(request) = s.requests.request(at) else {
        return;
    };
    let id = request.id;
    let refused = typed_exchange::admissible(request.method, request.resp_credit);
    let body_len = request.body.len();
    let mut req_bytes = [0u8; MAX_REQUEST];
    req_bytes[..body_len].copy_from_slice(request.body);
    s.requests.release(at);
    let peer = s.peers.take(&id);
    if let Some(status) = refused {
        answer_status(s, sys, &id, status);
        return;
    }
    let Some((ca::msg::MINT_REQ, payload)) = typed_exchange::message(&req_bytes[..body_len]) else {
        answer_status(s, sys, &id, x::status::BAD_REQUEST);
        return;
    };

    let obs = dev_trusted_unix(sys);
    let now_ms = if time_policy::now_for(time_policy::Decision::CredentialWindow, &obs).is_some() {
        dev_unix_millis(sys)
    } else {
        0
    };
    let mut audit = ca::Audit::new(0, now_ms);
    let outcome = decide(s, payload, peer.as_ref(), now_ms, &mut audit);
    let (status, record_len) = match outcome {
        Ok(len) => {
            s.act_minted = s.act_minted.saturating_add(1);
            audit.record = ca::record_digest(sha256_into, &s.sign_scratch[..len]);
            (ca::STATUS_OK, len)
        }
        Err(refusal) => {
            match refusal {
                ca::Refusal::NoIssuerKey => s.act_no_key = s.act_no_key.saturating_add(1),
                ca::Refusal::NotAuthenticated | ca::Refusal::Replayed => {
                    s.act_unauthenticated = s.act_unauthenticated.saturating_add(1);
                }
                _ => s.act_refused = s.act_refused.saturating_add(1),
            }
            audit.refusal = refusal.code();
            (refusal.code(), 0)
        }
    };
    emit_audit(s, sys, &audit);
    let mut resp = [0u8; 3 + ca::MAX_RECORD];
    let Some(n) = ca::write_mint_response(status, &s.sign_scratch[..record_len], &mut resp) else {
        answer_status(s, sys, &id, x::status::FAILED);
        return;
    };
    let Ok(len) = auth_wire::write_envelope(
        ca::msg::MINT_RESP,
        &resp[..n],
        &mut s.out[typed_exchange::ANSWER_AT..],
    ) else {
        answer_status(s, sys, &id, x::status::FAILED);
        return;
    };
    if let Some(total) = typed_exchange::seal_answer(&id, len, &mut s.out) {
        s.outbox.send(sys, s.out_responses, &s.out, total);
    }
}

/// Decide a mint. On success the signed record is in
/// `s.sign_scratch[..len]`; the audit is filled either way.
///
/// # Safety
///
/// As `handle_mint`.
unsafe fn decide(
    s: &mut ModuleState,
    payload: &[u8],
    peer: Option<&[u8; exchange_peer::SVID_LEN]>,
    now_ms: u64,
    audit: &mut ca::Audit,
) -> Result<usize, ca::Refusal> {
    let req = ca::MintRequest::decode(payload)?;
    audit.kind = req.kind;
    audit.tenant = req.tenant;
    audit.service = req.service;
    audit.operation = req.operation;
    if !s.key.is_open() {
        return Err(ca::Refusal::NoIssuerKey);
    }
    if now_ms == 0 {
        return Err(ca::Refusal::NoClock);
    }
    if s.anchor_len == 0 {
        // No authority key: nothing could have authenticated the caller.
        return Err(ca::Refusal::NotAuthenticated);
    }
    let now_secs = now_ms / 1000;
    let policy = cert_bound_identity::CarrierPolicy {
        anchor_der: &s.anchor[..usize::from(s.anchor_len)],
        audience: &s.audience[..usize::from(s.audience_len)],
        now_unix_secs: now_secs,
        require_clock: true,
    };
    let identity = cert_bound_identity::verify(&VERIFIERS, req.carrier, &policy)
        .map_err(|_| ca::Refusal::NotAuthenticated)?;
    audit.svid = identity.svid;
    // The link's own identity, when it has one, outranks the carrier: the
    // carrier must be the same key the connection authenticated.
    if peer.is_some_and(|svid| *svid != identity.svid) {
        return Err(ca::Refusal::NotAuthenticated);
    }
    let who = spiffe::parse(
        sha256_into,
        identity.spiffe(),
        &s.trust_domain[..usize::from(s.trust_domain_len)],
    )
    .ok_or(ca::Refusal::NotAuthenticated)?;
    if !ca::actor::may_act(who.class.code()) {
        return Err(ca::Refusal::ActorNotPermitted);
    }
    if replayed(
        &mut s.seen,
        identity.replay_id(),
        identity.expires_at,
        now_secs,
    ) {
        return Err(ca::Refusal::Replayed);
    }
    let act = req.act(who.class.code(), who.id, now_ms);
    audit.record_act(&act);
    act.check()?;

    let signer = ca::Signer {
        issuer: &s.issuer[..usize::from(s.issuer_len)],
        kid: KID,
    };
    let mut record = [0u8; ca::MAX_RECORD];
    let unsigned = ca::write_unsigned(&mut record, &act, &signer, s.key.suite())
        .ok_or(ca::Refusal::Malformed)?;
    // ES256 signs a digest, Ed25519 the message itself: what the vault is
    // handed is what the suite signs.
    let digest;
    let input: &[u8] = if s.key.suite() == auth_wire::suite::ES256 {
        digest = sha256(&record[..unsigned]);
        &digest
    } else {
        &record[..unsigned]
    };
    let mut signature = [0u8; ca::MAX_SIGNATURE];
    let sys = &*s.syscalls;
    let ModuleState {
        key, sign_scratch, ..
    } = s;
    let sig_len = key
        .sign(sys, &mut sign_scratch[..], input, &mut signature)
        .ok_or(ca::Refusal::NoIssuerKey)?;
    let len = ca::append_signature(&mut record, unsigned, &signature[..sig_len])
        .ok_or(ca::Refusal::Malformed)?;
    for (d, s) in sign_scratch.iter_mut().zip(record.iter().take(len)) {
        *d = *s;
    }
    Ok(len)
}

/// Write one audit entry to `audit_out`. Best effort: a full audit channel
/// loses the entry rather than the answer, and says so in the counter.
///
/// # Safety
///
/// As `handle_mint`.
unsafe fn emit_audit(s: &mut ModuleState, sys: &SyscallTable, audit: &ca::Audit) {
    if s.out_audit < 0 {
        return;
    }
    let mut entry = [0u8; ca::AUDIT_LEN];
    if let Some(n) = audit.encode(&mut entry) {
        chan::channel_write_msg(sys, s.out_audit, ca::msg::AUDIT, &entry[..n]);
    }
}

/// Answer with a status alone: a request this operation did not read.
///
/// # Safety
///
/// As `handle_mint`.
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

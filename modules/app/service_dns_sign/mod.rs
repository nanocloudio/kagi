//! Service DNS sign — sign a traffic-fabric `service_dns` projection (`KSDN`) for
//! the publisher the graph pins to its service.
//!
//! A typed operation: a PROVIDER of the workspace exchange contract on
//! `request_in` / `response_out`. Each request body is one
//! `service_dns::msg::REQUEST` envelope — the region controller's unsigned
//! 224-byte projection and its cert-bound identity carrier — and each answer
//! body one `REPLY` envelope: the signed record, or a typed refusal. Every
//! verdict is a 200 exchange.
//!
//! **The publisher is never a field of the request.** It is established from
//! the carrier (`cert_bound_identity.rs`): the leaf chains to the authority's
//! key on `ca_key`, the carrier is signed by the leaf's key, and the leaf's
//! SPIFFE name gives the class and id. Over mTLS the exchange's verified
//! SVID must be the carrier's key. A projection is signed only when that
//! `(class, id)` is pinned to the projection's service by a `publisher`
//! param — a region controller signs for its own service and no other — and
//! only for a window a resolver may act on (`service_dns::decide_sign`).
//!
//! The projection is signed in the vault under the `SERVICE_DNS` profile's
//! key, named by label on `signing_key`; its public half is announced on
//! `key_announce` for the deployment's `service_dns` consumers, which verify
//! offline with `service_dns.rs` alone. The key's custody floor is
//! issuer-grade (`KeyRole::Issuer`) under the declared `posture`: a stolen
//! key steers every resolver of every service the deployment answers for.
//! This module keeps nothing.
//!
//! Params: `iss` (1), `trust_domain` (2), `audience` (3), `posture` (6:
//! development | production; undeclared refuses to construct), `publisher_1`
//! … `publisher_8` (7–14): `service:<id>:<service>` or `host:<id>:<service>`,
//! each id 32 lowercase hex digits. A graph pinning no publisher signs for
//! nobody.

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
#[path = "../../common/exchange_peer.rs"]
mod exchange_peer;
#[path = "../../common/issuer_key.rs"]
mod issuer_key;
#[path = "../../common/jose.rs"]
mod jose;
#[path = "../../common/key_custody.rs"]
mod key_custody;
#[path = "../../../target/fluxor/fluxor-abi/sdk/contracts/key_vault.rs"]
mod key_vault;
#[path = "../../common/service_dns.rs"]
mod service_dns;
#[path = "../../common/spiffe.rs"]
mod spiffe;
#[path = "../../common/time_policy.rs"]
mod time_policy;
#[path = "../../common/typed_exchange.rs"]
mod typed_exchange;
#[path = "../../common/x509_leaf.rs"]
mod x509_leaf;

/// The carrier verifier, with the JOSE fragments it reads in scope.
mod cert_bound_identity {
    use crate::{b64, jose};
    include!("../../common/cert_bound_identity.rs");
}

use abi::contracts::exchange::{self as x, Collector, ExchangeId};
use service_dns as sd;

const STEP_DID_WORK: i32 = 2;
const MAX_REQS_PER_STEP: usize = 2;
const MAX_EXCHANGES: usize = 4;
const MAX_TARGET: usize = 256;
const MAX_HEADERS: usize = 1024;
/// Longest request body: a projection and a carrier holding a leaf.
const MAX_REQUEST: usize = x::PAYLOAD_MAX;
/// Longest issuer, trust domain or audience the graph names.
const MAX_FIELD: usize = 128;
/// The kid every record names. One key per profile at a time.
const KID: &[u8] = b"service-dns";
/// Carriers remembered against replay. A carrier lives at most five minutes
/// (`cert_bound_identity`), so an entry older than that can be forgotten.
const REPLAY_SLOTS: usize = 64;
const REPLAY_ID_MAX: usize = cert_bound_identity::CARRIER_JTI_MAX;

const POSTURE_UNDECLARED: u8 = 0;
const POSTURE_DEVELOPMENT: u8 = 1;
const POSTURE_PRODUCTION: u8 = 2;

/// `service:` and `host:`, then `<32 hex>:<32 hex>`.
const PUBLISHER_MAX: usize = 8 + 32 + 1 + 32;

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
    announce: u8,

    /// The SERVICE_DNS signing key, as a vault label.
    key: issuer_key::IssuerKey,
    key_pending: issuer_key::PendingRecord,
    sign_scratch: [u8; sd::MAX_RECORD + issuer_key::SIGN_SCRATCH_OVERHEAD],

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
    posture: u8,
    /// Publisher params as given, parsed once the TLV walk is done.
    publisher_raw: [[u8; PUBLISHER_MAX]; sd::MAX_PUBLISHERS],
    publisher_raw_len: [u8; sd::MAX_PUBLISHERS],
    policy: sd::Policy,

    seen: [Seen; REPLAY_SLOTS],

    dns_signed: u32,
    dns_refused: u32,
    dns_unauthenticated: u32,
    dns_no_key: u32,

    requests: Collector<MAX_EXCHANGES, MAX_TARGET, MAX_HEADERS, MAX_REQUEST>,
    /// The verified peer each collecting exchange arrived with.
    peers: exchange_peer::Peers<MAX_EXCHANGES>,
    outbox: ExchangeOutbox,
    buf: [u8; x::RECORD_MAX],
    out: [u8; x::RECORD_MAX],
}

/// Copy a string param into a fixed field, clamped.
///
/// # Safety
///
/// `d` is valid for reads of `len` bytes (the TLV walk's guarantee).
unsafe fn take_field(field: &mut [u8], d: *const u8, len: usize) -> u8 {
    let n = len.min(field.len()).min(usize::from(u8::MAX));
    let mut i = 0usize;
    while i < n {
        field[i] = *d.add(i);
        i += 1;
    }
    #[expect(clippy::cast_possible_truncation, reason = "clamped to u8::MAX above")]
    {
        n as u8
    }
}

/// Hold publisher param `slot` until the walk ends.
///
/// # Safety
///
/// As [`take_field`].
unsafe fn take_publisher(s: &mut ModuleState, slot: usize, d: *const u8, len: usize) {
    if let (Some(raw), Some(raw_len)) = (
        s.publisher_raw.get_mut(slot),
        s.publisher_raw_len.get_mut(slot),
    ) {
        *raw_len = take_field(raw, d, len);
    }
}

define_params! {
    ModuleState;

    1, iss, str, 0 => |s, d, len| { s.issuer_len = take_field(&mut s.issuer, d, len); };
    2, trust_domain, str, 0 => |s, d, len| {
        s.trust_domain_len = take_field(&mut s.trust_domain, d, len);
    };
    3, audience, str, 0 => |s, d, len| { s.audience_len = take_field(&mut s.audience, d, len); };
    6, posture, u8, 0, enum { undeclared=0, development=1, production=2 }
        => |s, d, len| { s.posture = p_u8(d, len, 0, POSTURE_UNDECLARED); };
    7, publisher_1, str, 0 => |s, d, len| { take_publisher(s, 0, d, len); };
    8, publisher_2, str, 0 => |s, d, len| { take_publisher(s, 1, d, len); };
    9, publisher_3, str, 0 => |s, d, len| { take_publisher(s, 2, d, len); };
    10, publisher_4, str, 0 => |s, d, len| { take_publisher(s, 3, d, len); };
    11, publisher_5, str, 0 => |s, d, len| { take_publisher(s, 4, d, len); };
    12, publisher_6, str, 0 => |s, d, len| { take_publisher(s, 5, d, len); };
    13, publisher_7, str, 0 => |s, d, len| { take_publisher(s, 6, d, len); };
    14, publisher_8, str, 0 => |s, d, len| { take_publisher(s, 7, d, len); };
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn hex16(s: &[u8]) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (o, pair) in out.iter_mut().zip(s.chunks_exact(2)) {
        *o = (hex_nibble(*pair.first()?)? << 4) | hex_nibble(*pair.get(1)?)?;
    }
    Some(out)
}

/// `service:<id>:<service>` or `host:<id>:<service>`.
fn parse_publisher(raw: &[u8]) -> Option<sd::Publisher> {
    let (class, rest) = if let Some(rest) = raw.strip_prefix(b"service:") {
        (sd::class::SERVICE, rest)
    } else {
        (sd::class::HOST, raw.strip_prefix(b"host:")?)
    };
    if rest.len() != 65 || rest.get(32) != Some(&b':') {
        return None;
    }
    Some(sd::Publisher {
        class,
        id: hex16(rest.get(..32)?)?,
        service: hex16(rest.get(33..)?)?,
    })
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
        s.posture = POSTURE_UNDECLARED;
        s.publisher_raw = [[0; PUBLISHER_MAX]; sd::MAX_PUBLISHERS];
        s.publisher_raw_len = [0; sd::MAX_PUBLISHERS];
        s.policy = sd::Policy::new();
        s.seen = [Seen::EMPTY; REPLAY_SLOTS];
        s.dns_signed = 0;
        s.dns_refused = 0;
        s.dns_unauthenticated = 0;
        s.dns_no_key = 0;
        s.requests = Collector::new();
        s.peers = exchange_peer::Peers::new();
        s.outbox = ExchangeOutbox::new();

        parse_tlv(s, params, params_len);

        if s.issuer_len == 0 || s.trust_domain_len == 0 || s.audience_len == 0 {
            let line = b"[service-dns] iss, trust_domain and audience are required";
            dev_log(sys, 1, line.as_ptr(), line.len());
            return -3;
        }
        for slot in 0..sd::MAX_PUBLISHERS {
            let n = usize::from(s.publisher_raw_len[slot]);
            if n == 0 {
                continue;
            }
            let pinned =
                parse_publisher(&s.publisher_raw[slot][..n]).is_some_and(|p| s.policy.pin(p));
            if !pinned {
                // A pin that does not parse is a deployment that meant to
                // admit someone and admits nobody instead: refuse to start
                // rather than discover it at the first projection.
                let line = b"[service-dns] refusing to construct: a publisher param does not parse";
                dev_log(sys, 1, line.as_ptr(), line.len());
                return -3;
            }
        }
        let posture = match s.posture {
            POSTURE_DEVELOPMENT => key_custody::Posture::Development,
            POSTURE_PRODUCTION => key_custody::Posture::Production,
            _ => {
                let line = b"[service-dns] refusing to construct: posture undeclared";
                dev_log(sys, 1, line.as_ptr(), line.len());
                return -1;
            }
        };
        // The signing key's custody floor, refused at construction: a
        // projection steers every resolver of a service, so the key is
        // issuer-grade.
        let tier = if (sys.provider_call)(-1, key_vault::PROBE, core::ptr::null_mut(), 0) == 1 {
            let mut tier_buf = [0u8; 4];
            if (sys.provider_call)(-1, key_vault::TIER, tier_buf.as_mut_ptr(), tier_buf.len()) >= 0
            {
                tier_buf[0]
            } else {
                key_custody::TIER_NONE
            }
        } else {
            key_custody::TIER_NONE
        };
        if !key_custody::permits(key_custody::KeyRole::Issuer, posture, tier) {
            let why = key_custody::refusal_text(tier);
            let line = b"[service-dns] refusing to construct:";
            dev_log(sys, 1, line.as_ptr(), line.len());
            dev_log(sys, 1, why.as_ptr(), why.len());
            return -1;
        }
        if s.policy.count == 0 {
            let line = b"[service-dns] no publisher pinned: every projection will be refused";
            dev_log(sys, 2, line.as_ptr(), line.len());
        }
        dev_log(sys, 3, b"[service-dns] init".as_ptr(), 18);
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
                handle_sign(s, sys, at);
            }
        }
        if worked {
            STEP_DID_WORK
        } else {
            0
        }
    }
}

/// Take the SERVICE_DNS signing key from a `MSG_KEY_ADD`.
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
        || rec.profile_id != auth_wire::suite::profile::SERVICE_DNS
        || !matches!(
            rec.suite,
            auth_wire::suite::ED25519 | auth_wire::suite::ES256
        )
        || rec.key_ref.is_empty()
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

/// Take the authority's public key from a VERIFY `MSG_KEY_ADD` on `ca_key`.
/// The latest one delivered is the anchor.
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
        profile_id: auth_wire::suite::profile::SERVICE_DNS,
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

/// The one decision: who asked, and whether they publish for this service.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live syscall table.
unsafe fn handle_sign(s: &mut ModuleState, sys: &SyscallTable, at: usize) {
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
    let Some((sd::msg::REQUEST, payload)) = typed_exchange::message(&req_bytes[..body_len]) else {
        answer_status(s, sys, &id, x::status::BAD_REQUEST);
        return;
    };

    let obs = dev_trusted_unix(sys);
    let now_ms = if time_policy::now_for(time_policy::Decision::CredentialWindow, &obs).is_some() {
        dev_unix_millis(sys)
    } else {
        0
    };
    let outcome = decide(s, payload, peer.as_ref(), now_ms);
    let (refusal, record_len) = match outcome {
        Ok(len) => {
            s.dns_signed = s.dns_signed.saturating_add(1);
            (None, len)
        }
        Err(refusal) => {
            match refusal {
                sd::Refusal::NoIssuerKey => s.dns_no_key = s.dns_no_key.saturating_add(1),
                sd::Refusal::NotAuthenticated | sd::Refusal::Replayed => {
                    s.dns_unauthenticated = s.dns_unauthenticated.saturating_add(1);
                }
                _ => s.dns_refused = s.dns_refused.saturating_add(1),
            }
            (Some(refusal), 0)
        }
    };
    let mut resp = [0u8; 3 + sd::MAX_RECORD];
    let Some(n) = sd::write_reply(refusal, &s.sign_scratch[..record_len], &mut resp) else {
        answer_status(s, sys, &id, x::status::FAILED);
        return;
    };
    let Ok(len) = auth_wire::write_envelope(
        sd::msg::REPLY,
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

/// Decide a signature. On success the signed record is in
/// `s.sign_scratch[..len]`.
///
/// # Safety
///
/// As `handle_sign`.
unsafe fn decide(
    s: &mut ModuleState,
    payload: &[u8],
    peer: Option<&[u8; exchange_peer::SVID_LEN]>,
    now_ms: u64,
) -> Result<usize, sd::Refusal> {
    let req = sd::SignRequest::decode(payload)?;
    if !s.key.is_open() {
        return Err(sd::Refusal::NoIssuerKey);
    }
    if now_ms == 0 {
        return Err(sd::Refusal::NoClock);
    }
    if s.anchor_len == 0 {
        // No authority key: nothing could have authenticated the caller.
        return Err(sd::Refusal::NotAuthenticated);
    }
    let now_secs = now_ms / 1000;
    let policy = cert_bound_identity::CarrierPolicy {
        anchor_der: &s.anchor[..usize::from(s.anchor_len)],
        audience: &s.audience[..usize::from(s.audience_len)],
        now_unix_secs: now_secs,
        require_clock: true,
    };
    let identity = cert_bound_identity::verify(&VERIFIERS, req.carrier, &policy)
        .map_err(|_| sd::Refusal::NotAuthenticated)?;
    // The link's own identity, when it has one, outranks the carrier: the
    // carrier must be the same key the connection authenticated.
    if peer.is_some_and(|svid| *svid != identity.svid) {
        return Err(sd::Refusal::NotAuthenticated);
    }
    let who = spiffe::parse(
        sha256_into,
        identity.spiffe(),
        &s.trust_domain[..usize::from(s.trust_domain_len)],
    )
    .ok_or(sd::Refusal::NotAuthenticated)?;
    if replayed(
        &mut s.seen,
        identity.replay_id(),
        identity.expires_at,
        now_secs,
    ) {
        return Err(sd::Refusal::Replayed);
    }
    sd::decide_sign(
        &s.policy,
        req.projection,
        Some((who.class.code(), who.id)),
        now_ms,
    )?;

    let signer = sd::Signer {
        issuer: &s.issuer[..usize::from(s.issuer_len)],
        kid: KID,
    };
    let mut record = [0u8; sd::MAX_RECORD];
    let unsigned = sd::write_unsigned(&mut record, req.projection, &signer, s.key.suite())
        .ok_or(sd::Refusal::Malformed)?;
    // ES256 signs a digest, Ed25519 the message itself: what the vault is
    // handed is what the suite signs.
    let digest;
    let input: &[u8] = if s.key.suite() == auth_wire::suite::ES256 {
        digest = sha256(&record[..unsigned]);
        &digest
    } else {
        &record[..unsigned]
    };
    let mut signature = [0u8; sd::MAX_SIGNATURE];
    let sys = &*s.syscalls;
    let ModuleState {
        key, sign_scratch, ..
    } = s;
    let sig_len = key
        .sign(sys, &mut sign_scratch[..], input, &mut signature)
        .ok_or(sd::Refusal::NoIssuerKey)?;
    let len = sd::append_signature(&mut record, unsigned, &signature[..sig_len])
        .ok_or(sd::Refusal::Malformed)?;
    for (d, s) in sign_scratch.iter_mut().zip(record.iter().take(len)) {
        *d = *s;
    }
    Ok(len)
}

/// Answer with a status alone: a request this operation did not read.
///
/// # Safety
///
/// As `handle_sign`.
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

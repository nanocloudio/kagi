//! Transfer grant — key-custody transfer grants (`KTGR`) for the traffic fabric's
//! paired-anchor TLS continuity (RFC §12.5.5, §15.4).
//!
//! The decisions are `modules/common/transfer_grant_service.rs`; this module
//! is its host. It is a PROVIDER of the workspace exchange contract on
//! `request_in` / `response_out`: each request body is one
//! `transfer_grant::msg::REQUEST` envelope (issue, consume, invalidate) and
//! each answer one `REPLY` envelope.
//!
//! - **Callers** authenticate with a cert-bound identity carrier from their
//!   `host` or `operator` leaf (`carrier_auth.rs`), chained to the
//!   authority's key on `ca_key`; over mTLS the carrier must name the
//!   exchange's verified SVID.
//! - **The ledger** (`security_state`, namespace `kagi/transfer-grants/`) on
//!   `ledger_out` / `ledger_in` holds each grant's single-use state and the
//!   recovery generation.
//! - **The grant key** arrives on `signing_key` as a vault label; its public
//!   half is announced on `key_announce` for the vault hosts that check a
//!   grant before wrapping. Its custody floor is
//!   `key_custody::KeyRole::TransferGrant` under the declared `posture`:
//!   `PROCESS_HW` in production, checked at construction.
//!
//! Params: `iss` (1), `trust_domain` (2), `audience` (3), `allow_possession`
//! (4, u8, default 0 — a possession-bound standby is refused), `min_tier`
//! (5, u8, default 1 = `PROCESS_HW`), `posture` (6: development | production;
//! undeclared refuses to construct).

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
#[path = "../../common/carrier_auth.rs"]
mod carrier_auth;
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
#[path = "../../common/spiffe.rs"]
mod spiffe;
#[path = "../../common/state_wire.rs"]
mod state_wire;
#[path = "../../common/storage_key.rs"]
mod storage_key;
#[path = "../../common/time_policy.rs"]
mod time_policy;
#[path = "../../common/transfer_grant.rs"]
mod transfer_grant;
#[path = "../../common/transfer_grant_service.rs"]
mod transfer_grant_service;
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
use transfer_grant as tg;
use transfer_grant_service::{self as svc};

const STEP_DID_WORK: i32 = 2;
const MAX_REQUESTS_PER_STEP: usize = 2;
const MAX_LEDGER_PER_STEP: usize = 4;
const MSG_BUF: usize = 4096;
const MAX_EXCHANGES: usize = 4;
const MAX_TARGET: usize = 256;
const MAX_HEADERS: usize = 1024;
const MAX_REQUEST: usize = x::PAYLOAD_MAX;
const MAX_FIELD: usize = 64;
const REPLAY_SLOTS: usize = 64;

const POSTURE_UNDECLARED: u8 = 0;
const POSTURE_DEVELOPMENT: u8 = 1;
const POSTURE_PRODUCTION: u8 = 2;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    out_responses: i32,
    in_key: i32,
    in_ca_key: i32,
    in_ledger: i32,
    out_ledger: i32,
    out_key_announce: i32,
    announce: u8,

    key: issuer_key::IssuerKey,
    key_pending: issuer_key::PendingRecord,
    sign_scratch: [u8; tg::MAX_RECORD + issuer_key::SIGN_SCRATCH_OVERHEAD],

    anchor: [u8; 2 + 65],
    anchor_len: u8,
    issuer: [u8; MAX_FIELD],
    issuer_len: u8,
    trust_domain: [u8; MAX_FIELD],
    trust_domain_len: u8,
    audience: [u8; MAX_FIELD],
    audience_len: u8,
    allow_possession: u8,
    min_tier: u8,
    posture: u8,

    auth: carrier_auth::Authenticator<REPLAY_SLOTS>,
    service: svc::Service,
    requests: Collector<MAX_EXCHANGES, MAX_TARGET, MAX_HEADERS, MAX_REQUEST>,
    peers: exchange_peer::Peers<MAX_EXCHANGES>,
    outbox: ExchangeOutbox,
    buf: [u8; MSG_BUF],
    body: [u8; MAX_REQUEST],
    record: [u8; x::RECORD_MAX],
    out: [u8; x::RECORD_MAX],
}

macro_rules! str_param {
    ($s:ident, $d:ident, $len:ident, $field:ident, $len_field:ident) => {{
        let n = if $len > MAX_FIELD { MAX_FIELD } else { $len };
        let mut i = 0usize;
        while i < n {
            $s.$field[i] = *$d.add(i);
            i += 1;
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "clamped to MAX_FIELD above"
        )]
        {
            $s.$len_field = n as u8;
        }
    }};
}

define_params! {
    ModuleState;

    1, iss, str, 0 => |s, d, len| { str_param!(s, d, len, issuer, issuer_len); };
    2, trust_domain, str, 0 => |s, d, len| { str_param!(s, d, len, trust_domain, trust_domain_len); };
    3, audience, str, 0 => |s, d, len| { str_param!(s, d, len, audience, audience_len); };
    4, allow_possession, u8, 0 => |s, d, len| { s.allow_possession = p_u8(d, len, 0, 0); };
    5, min_tier, u8, 1 => |s, d, len| { s.min_tier = p_u8(d, len, 0, 1); };
    6, posture, u8, 0, enum { undeclared=0, development=1, production=2 }
        => |s, d, len| { s.posture = p_u8(d, len, 0, POSTURE_UNDECLARED); };
}

/// The service's view of this module.
struct ModuleHost<'a> {
    sys: &'a SyscallTable,
    key: &'a issuer_key::IssuerKey,
    scratch: &'a mut [u8],
    auth: &'a mut carrier_auth::Authenticator<REPLAY_SLOTS>,
    anchor: &'a [u8],
    audience: &'a [u8],
    trust_domain: &'a [u8],
    out_responses: i32,
    out_ledger: i32,
    outbox: &'a mut ExchangeOutbox,
    out: &'a mut [u8; x::RECORD_MAX],
}

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

fn carrier_chain(cert_msg: &[u8], anchor: &[u8], uri: &[u8], now: u64, clock: bool) -> u32 {
    x509_leaf::verify_chain(verify_suite, cert_msg, anchor, uri, now, clock)
}

const VERIFIERS: cert_bound_identity::CarrierVerifiers = cert_bound_identity::CarrierVerifiers {
    sha256: sha256_into,
    ecdsa_verify: carrier_ecdsa,
    verify_chain: carrier_chain,
    leaf_public_key: x509_leaf::leaf_public_key,
};

impl ModuleHost<'_> {
    fn trust(&self) -> carrier_auth::Trust<'_> {
        carrier_auth::Trust {
            anchor: self.anchor,
            audience: self.audience,
            trust_domain: self.trust_domain,
        }
    }
}

impl svc::Host for ModuleHost<'_> {
    fn now_ms(&mut self) -> u64 {
        // SAFETY: `sys` is the live syscall table handed to `module_new`.
        let obs = unsafe { dev_trusted_unix(self.sys) };
        if time_policy::now_for(time_policy::Decision::CredentialWindow, &obs).is_none() {
            return 0;
        }
        // SAFETY: as above.
        unsafe { dev_unix_millis(self.sys) }
    }

    fn random(&mut self, out: &mut [u8]) -> bool {
        // SAFETY: `out` is a live, exclusively borrowed buffer of its length.
        unsafe { dev_csprng_fill(self.sys, out.as_mut_ptr(), out.len()) >= 0 }
    }

    fn sha256(&self) -> tg::Sha256Fn {
        sha256_into
    }

    fn verify(&self) -> tg::VerifyFn {
        verify_suite
    }

    fn issuer_suite(&self) -> u16 {
        if self.key.is_open() {
            self.key.suite()
        } else {
            0
        }
    }

    fn issuer_public(&self) -> &[u8] {
        self.key.public_key()
    }

    fn sign(&mut self, message: &[u8], signature: &mut [u8]) -> Option<usize> {
        let digest;
        let input: &[u8] = if self.key.suite() == auth_wire::suite::ES256 {
            digest = sha256(message);
            &digest
        } else {
            message
        };
        // SAFETY: `sys` is live; `scratch` is module state and does not
        // alias `input`.
        unsafe { self.key.sign(self.sys, self.scratch, input, signature) }
    }

    fn authenticate(
        &mut self,
        carrier: &[u8],
        peer: Option<&[u8; svc::PEER_LEN]>,
    ) -> Option<(u8, [u8; 16])> {
        let now_secs = self.now_ms() / 1000;
        if now_secs == 0 {
            return None;
        }
        let trust = carrier_auth::Trust {
            anchor: self.anchor,
            audience: self.audience,
            trust_domain: self.trust_domain,
        };
        self.auth
            .authenticate(&VERIFIERS, &trust, carrier, peer, now_secs)
            .ok()
            .map(|c| (c.class, c.id))
    }

    fn host_leaf_key(
        &self,
        leaf: &[u8],
        host_id: &[u8; 16],
        out: &mut [u8; 65],
    ) -> Option<(u16, usize)> {
        // SAFETY: `sys` is the live syscall table.
        let now_secs = unsafe { dev_unix_millis(self.sys) } / 1000;
        carrier_auth::identity_leaf_key(
            verify_suite,
            sha256_into,
            &self.trust(),
            leaf,
            svc::CLASS_HOST,
            host_id,
            now_secs,
            out,
        )
    }

    fn send_ledger(&mut self, frame: &[u8]) -> bool {
        if self.out_ledger < 0 || frame.len() > i32::MAX as usize {
            return false;
        }
        // SAFETY: `sys` is live and `frame` is a borrowed buffer of its
        // length.
        unsafe {
            if !chan::can_write(self.sys, self.out_ledger) {
                return false;
            }
            #[expect(
                clippy::cast_possible_truncation,
                reason = "bounded against i32::MAX above"
            )]
            let want = frame.len() as i32;
            (self.sys.channel_write)(self.out_ledger, frame.as_ptr(), frame.len()) == want
        }
    }

    fn answer(&mut self, caller: &svc::Caller, frame: &[u8]) -> bool {
        // SAFETY: `sys` is the live syscall table this host was built with.
        if self.out_responses < 0
            || !unsafe {
                self.outbox
                    .flush(self.sys, self.out_responses, &self.out[..])
            }
        {
            return false;
        }
        let id = ExchangeId(*caller);
        let Some(n) = typed_exchange::write_answer(&id, frame, &mut self.out[..])
            .or_else(|| typed_exchange::write_status(&id, x::status::FAILED, &mut self.out[..]))
        else {
            return false;
        };
        // SAFETY: as above.
        unsafe {
            self.outbox
                .send(self.sys, self.out_responses, &self.out[..], n)
        };
        true
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
        s.in_ledger = dev_channel_port(sys, 0, 3);
        s.out_ledger = dev_channel_port(sys, 1, 1);
        s.out_key_announce = dev_channel_port(sys, 1, 2);
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
        s.allow_possession = 0;
        s.min_tier = 1;
        s.posture = POSTURE_UNDECLARED;
        s.auth = carrier_auth::Authenticator::new();
        s.requests = Collector::new();
        s.peers = exchange_peer::Peers::new();
        s.outbox = ExchangeOutbox::new();

        parse_tlv(s, params, params_len);

        if s.issuer_len == 0 || s.trust_domain_len == 0 || s.audience_len == 0 {
            let line = b"[transfer-grant] iss, trust_domain and audience are required";
            dev_log(sys, 1, line.as_ptr(), line.len());
            return -3;
        }
        let posture = match s.posture {
            POSTURE_DEVELOPMENT => key_custody::Posture::Development,
            POSTURE_PRODUCTION => key_custody::Posture::Production,
            _ => {
                let line = b"[transfer-grant] refusing to construct: posture undeclared";
                dev_log(sys, 1, line.as_ptr(), line.len());
                return -1;
            }
        };
        // The grant key's custody floor, refused at construction like
        // token_mint's: a grant moves live TLS secrets, so its key is
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
        if !key_custody::permits(key_custody::KeyRole::TransferGrant, posture, tier) {
            let why = key_custody::refusal_text(tier);
            let line = b"[transfer-grant] refusing to construct:";
            dev_log(sys, 1, line.as_ptr(), line.len());
            dev_log(sys, 1, why.as_ptr(), why.len());
            return -1;
        }

        let issuer_len = usize::from(s.issuer_len);
        let policy = tg::Policy {
            allow_possession: s.allow_possession != 0,
            min_tier: s.min_tier,
        };
        let ModuleState {
            service, issuer, ..
        } = s;
        *service = svc::Service::new();
        service.init(&issuer[..issuer_len], policy);
        let line = b"[transfer-grant] init";
        dev_log(sys, 3, line.as_ptr(), line.len());
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

        if !s.outbox.flush(sys, s.out_responses, &s.out) {
            return 0;
        }

        let ModuleState {
            in_requests,
            out_responses,
            in_ledger,
            out_ledger,
            key,
            sign_scratch,
            anchor,
            anchor_len,
            audience,
            audience_len,
            trust_domain,
            trust_domain_len,
            auth,
            buf,
            body,
            service,
            requests,
            peers,
            outbox,
            record,
            out,
            ..
        } = s;
        let mut host = ModuleHost {
            sys,
            key,
            scratch: sign_scratch,
            auth,
            anchor: &anchor[..usize::from(*anchor_len)],
            audience: &audience[..usize::from(*audience_len)],
            trust_domain: &trust_domain[..usize::from(*trust_domain_len)],
            out_responses: *out_responses,
            out_ledger: *out_ledger,
            outbox,
            out,
        };
        let mut worked = false;

        for _ in 0..MAX_LEDGER_PER_STEP {
            if host.outbox.holding() || !chan::can_read(sys, *in_ledger) {
                break;
            }
            let (t, n) = chan::channel_read_msg(sys, *in_ledger, buf);
            if t == 0 {
                break;
            }
            worked = true;
            service.on_ledger(&mut host, t, buf.get(..usize::from(n)).unwrap_or(&[]));
        }
        for _ in 0..MAX_REQUESTS_PER_STEP {
            if host.outbox.holding() || !chan::can_read(sys, *in_requests) {
                break;
            }
            let n = (sys.channel_read)(*in_requests, record.as_mut_ptr(), record.len());
            if n <= 0 {
                break;
            }
            worked = true;
            let bytes = record.get(..n as usize).unwrap_or(&[]);
            peers.note(bytes);
            let outcome = requests.accept(bytes);
            if let Some((id, grant)) = requests.take_grant() {
                if let Some(len) = x::write_credit(&id, grant, &mut host.out[..]) {
                    host.outbox.send(sys, *out_responses, &host.out[..], len);
                }
            }
            if let Some((id, why)) = requests.take_refusal() {
                answer_status(&mut host, &id, why.status());
            }
            let Ok(Some(at)) = outcome else {
                continue;
            };
            let Some(request) = requests.request(at) else {
                continue;
            };
            let id = request.id;
            let refused = typed_exchange::admissible(request.method, request.resp_credit);
            let body_len = request.body.len().min(body.len());
            for (d, s) in body.iter_mut().zip(request.body.iter().take(body_len)) {
                *d = *s;
            }
            requests.release(at);
            let peer = peers.take(&id);
            if let Some(status) = refused {
                answer_status(&mut host, &id, status);
                continue;
            }
            match typed_exchange::message(&body[..body_len]) {
                Some((tg::msg::REQUEST, payload)) => {
                    let svid: &[u8] = match &peer {
                        Some(svid) => svid,
                        None => &[],
                    };
                    service.on_request(&mut host, &id.0, svid, payload);
                }
                _ => answer_status(&mut host, &id, x::status::BAD_REQUEST),
            }
        }
        if !host.outbox.holding() {
            service.tick(&mut host);
        }
        if worked {
            STEP_DID_WORK
        } else {
            0
        }
    }
}

/// # Safety
///
/// `host.sys` is the live syscall table.
unsafe fn answer_status(host: &mut ModuleHost<'_>, id: &ExchangeId, status: u16) {
    if let Some(n) = typed_exchange::write_status(id, status, &mut host.out[..]) {
        host.outbox
            .send(host.sys, host.out_responses, &host.out[..], n);
    }
}

/// Take the TRANSFER_GRANT signing key from a `MSG_KEY_ADD`.
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

/// # Safety
///
/// As `drain_key`.
unsafe fn take_key_record(s: &mut ModuleState, sys: &SyscallTable, payload: &[u8]) -> bool {
    let Ok(rec) = auth_wire::KeyRecord::decode_add(payload) else {
        return false;
    };
    if rec.key_use != auth_wire::key_use::SIGN
        || rec.profile_id != auth_wire::suite::profile::TRANSFER_GRANT
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

/// The authority's key, from the VERIFY `MSG_KEY_ADD` its CA announces.
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
        s.anchor_len = u8::try_from(n).unwrap_or(0);
    }
}

/// # Safety
///
/// As `drain_key`.
unsafe fn announce_key(s: &mut ModuleState, sys: &SyscallTable) {
    if s.announce == 0 || s.out_key_announce < 0 || !s.key.is_open() {
        return;
    }
    let rec = auth_wire::KeyRecord {
        issuer: &s.issuer[..usize::from(s.issuer_len)],
        profile_id: auth_wire::suite::profile::TRANSFER_GRANT,
        kid: svc::KID,
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

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

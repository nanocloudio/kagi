//! custody_authority — the continuity authority a Fluxor
//! `TRANSPORT_CONTINUITY` provider asks, in the provider's own graph.
//!
//! The decisions are `modules/common/custody_authority_service.rs`; this
//! module is its host. Wired to the provider's `auth_req` / `auth_rsp`:
//!
//! - a **custody check** (`0xC4 [flow][epoch][challenge][evidence]`) — may
//!   this standby's attested recipient receive the flow's continuity key?
//!   — is decided by `transfer_grant::decide_custody_check` (the standby an
//!   enrolled host, its identity key the evidence's signer, hardware custody
//!   as the policy demands), the transfer's `KTGR` signed by the grant key
//!   (`signing_key`, a vault label) and written CONSUMED, create-if-absent,
//!   in the ledger under its nonce; only then is it answered `0xC5`
//!   accepting. A replayed transfer, an unknown signer, missing custody, no
//!   clock, no key or a silent ledger refuse.
//! - a **token check** (`0xC2 [token]`) goes to Clustor's session directory
//!   on `token_out` and its verdict (`0xC3`) back from `token_in`.
//! - **`CUSTODY_READY`** (`custody_authority_service::ready`, REQUEST 0xA0 /
//!   REPLY 0xA1) is a typed operation on `request_in` / `response_out`: for
//!   up to 32 hosts, whether each is enrolled here, the custody tier its
//!   attested evidence last proved, whether a grant could be issued to it
//!   now — the grant key open, a trusted clock, the ledger answering a read
//!   made for the question within two seconds, the posture admitting the
//!   grant key's vault — and whether it holds a live identity certificate
//!   the CA on `ca_key` signed, delivered on `cert_in` (the enrolment path's
//!   `[0x5C][len][leaf ‖ issuer]` frames), with its notAfter.
//!
//! Params: `host` (1, 32 hex: this host, the source of every transfer
//! checked here), `iss` (2), `allow_possession` (3, default 0), `min_tier`
//! (4, default 1 = `PROCESS_HW`), `posture` (5: development | production;
//! undeclared refuses to construct), `ttl_ms` (6, default 30000),
//! `dest0`..`dest7` (7..14: `<host id 32 hex>:<identity key 130 hex>`, the
//! standby hosts a key may move to), `trust_domain` (15: the SPIFFE trust
//! domain host certificates name; required when `cert_in` is wired).

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
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/custody_authority_service.rs"]
mod custody_authority_service;
#[path = "../../common/issuer_key.rs"]
mod issuer_key;
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
#[path = "../../common/typed_exchange.rs"]
mod typed_exchange;
#[path = "../../common/x509_leaf.rs"]
mod x509_leaf;

use abi::contracts::exchange::{self as x, Collector, ExchangeId};
use custody_authority_service::{self as ca, ready, Authority};
use transfer_grant as tg;

const STEP_DID_WORK: i32 = 2;
const MAX_FIELD: usize = 64;
const MSG_BUF: usize = 2048;
/// Exchanges being collected at once.
const MAX_EXCHANGES: usize = 2;
const MAX_TARGET: usize = 256;
const MAX_HEADERS: usize = 1024;
/// Longest `CUSTODY_READY` request body: its envelope and 32 hosts fit.
const MAX_REQUEST: usize = 1024;
/// One `cert_in` frame: a leaf and its issuer.
const CERT_INBOX: usize = 4096;

const POSTURE_UNDECLARED: u8 = 0;
const POSTURE_DEVELOPMENT: u8 = 1;
const POSTURE_PRODUCTION: u8 = 2;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_auth: i32,
    in_key: i32,
    in_ledger: i32,
    in_token: i32,
    out_auth: i32,
    out_ledger: i32,
    out_token: i32,
    out_grant: i32,
    in_ca_key: i32,
    in_cert: i32,
    in_requests: i32,
    out_responses: i32,

    key: issuer_key::IssuerKey,
    key_pending: issuer_key::PendingRecord,
    sign_scratch: [u8; tg::MAX_RECORD + issuer_key::SIGN_SCRATCH_OVERHEAD],

    issuer: [u8; MAX_FIELD],
    issuer_len: u8,
    host: [u8; 16],
    host_ok: u8,
    allow_possession: u8,
    min_tier: u8,
    posture: u8,
    ttl_ms: u32,
    /// Enrolment params that did not parse: refused at construction.
    bad_dest: u8,
    trust_domain: [u8; ca::TRUST_DOMAIN_MAX],
    trust_domain_len: u8,
    bad_trust_domain: u8,

    authority: Authority,
    buf: [u8; MSG_BUF],

    /// `CUSTODY_READY` exchanges: the id each question slot answers, and
    /// the reply waiting to go out in it.
    ready_ids: [Option<ExchangeId>; ready::PROBES],
    ready_reply: [[u8; ready::REPLY_MAX]; ready::PROBES],
    ready_len: [u16; ready::PROBES],
    requests: Collector<MAX_EXCHANGES, MAX_TARGET, MAX_HEADERS, MAX_REQUEST>,
    outbox: ExchangeOutbox,
    req_buf: [u8; x::RECORD_MAX],
    out: [u8; x::RECORD_MAX],
    cert_inbox: [u8; 3 + CERT_INBOX],
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_into(src: &[u8], out: &mut [u8]) -> bool {
    if src.len() != out.len() * 2 {
        return false;
    }
    for (i, o) in out.iter_mut().enumerate() {
        match (hex_nibble(src[2 * i]), hex_nibble(src[2 * i + 1])) {
            (Some(h), Some(l)) => *o = (h << 4) | l,
            _ => return false,
        }
    }
    true
}

/// The string param at `d` of `len` bytes, up to its first NUL.
unsafe fn str_param<'a>(d: *const u8, len: usize) -> &'a [u8] {
    let t = core::slice::from_raw_parts(d, len);
    t.split(|&b| b == 0).next().unwrap_or(&[])
}

/// `<id 32 hex>:<key 130 hex>`: one enrolled standby host.
unsafe fn enroll(s: &mut ModuleState, d: *const u8, len: usize) {
    let t = str_param(d, len);
    if t.is_empty() {
        return;
    }
    let mut id = [0u8; 16];
    let mut public = [0u8; 65];
    let ok = t.len() == 32 + 1 + 130
        && t[32] == b':'
        && hex_into(&t[..32], &mut id)
        && hex_into(&t[33..], &mut public)
        && public[0] == 0x04
        && s.authority.config.enroll(id, public);
    if !ok {
        s.bad_dest = 1;
    }
}

define_params! {
    ModuleState;

    1, host, str, 0 => |s, d, len| {
        let t = str_param(d, len);
        s.host_ok = u8::from(hex_into(t, &mut s.host));
    };
    2, iss, str, 0 => |s, d, len| {
        let t = str_param(d, len);
        let n = t.len().min(MAX_FIELD);
        s.issuer[..n].copy_from_slice(&t[..n]);
        s.issuer_len = n as u8;
    };
    3, allow_possession, u8, 0 => |s, d, len| { s.allow_possession = p_u8(d, len, 0, 0); };
    4, min_tier, u8, 1 => |s, d, len| { s.min_tier = p_u8(d, len, 0, 1); };
    5, posture, u8, 0, enum { undeclared=0, development=1, production=2 }
        => |s, d, len| { s.posture = p_u8(d, len, 0, POSTURE_UNDECLARED); };
    6, ttl_ms, u32, 30000 => |s, d, len| { s.ttl_ms = p_u32(d, len, 0, 30000); };
    7, dest0, str, 0 => |s, d, len| { enroll(s, d, len); };
    8, dest1, str, 0 => |s, d, len| { enroll(s, d, len); };
    9, dest2, str, 0 => |s, d, len| { enroll(s, d, len); };
    10, dest3, str, 0 => |s, d, len| { enroll(s, d, len); };
    11, dest4, str, 0 => |s, d, len| { enroll(s, d, len); };
    12, dest5, str, 0 => |s, d, len| { enroll(s, d, len); };
    13, dest6, str, 0 => |s, d, len| { enroll(s, d, len); };
    14, dest7, str, 0 => |s, d, len| { enroll(s, d, len); };
    15, trust_domain, str, 0 => |s, d, len| {
        let t = str_param(d, len);
        if t.len() > ca::TRUST_DOMAIN_MAX || t.len() > usize::from(u8::MAX) {
            s.bad_trust_domain = 1;
        } else {
            s.trust_domain[..t.len()].copy_from_slice(t);
            s.trust_domain_len = t.len() as u8;
        }
    };
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

/// The authority's view of this module.
struct ModuleHost<'a> {
    sys: &'a SyscallTable,
    key: &'a issuer_key::IssuerKey,
    scratch: &'a mut [u8],
    out_auth: i32,
    out_ledger: i32,
    out_token: i32,
    out_grant: i32,
    ready_reply: &'a mut [[u8; ready::REPLY_MAX]; ready::PROBES],
    ready_len: &'a mut [u16; ready::PROBES],
}

/// One whole `[type][len][payload]` frame onto `ch`.
unsafe fn write_frame(sys: &SyscallTable, ch: i32, frame: &[u8]) -> bool {
    if ch < 0 || frame.len() < 3 {
        return false;
    }
    chan::channel_write_msg(sys, ch, frame[0], &frame[3..]) > 0
}

impl ca::Host for ModuleHost<'_> {
    fn now_ms(&mut self) -> u64 {
        // SAFETY: `sys` is the live syscall table handed to `module_new`.
        let obs = unsafe { dev_trusted_unix(self.sys) };
        if time_policy::now_for(time_policy::Decision::CredentialWindow, &obs).is_none() {
            return 0;
        }
        // SAFETY: as above.
        unsafe { dev_unix_millis(self.sys) }
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

    fn send_ledger(&mut self, frame: &[u8]) -> bool {
        // SAFETY: `sys` is live.
        unsafe { write_frame(self.sys, self.out_ledger, frame) }
    }

    fn send_provider(&mut self, frame: &[u8]) -> bool {
        // SAFETY: `sys` is live.
        unsafe { write_frame(self.sys, self.out_auth, frame) }
    }

    fn send_token(&mut self, frame: &[u8]) -> bool {
        // SAFETY: `sys` is live.
        unsafe { write_frame(self.sys, self.out_token, frame) }
    }

    fn send_grant(&mut self, record: &[u8]) -> bool {
        // SAFETY: `sys` is live.
        unsafe {
            self.out_grant >= 0
                && chan::channel_write_msg(self.sys, self.out_grant, ca::MSG_KTGR_RECORD, record)
                    > 0
        }
    }

    fn send_ready(&mut self, slot: usize, reply: &[u8]) -> bool {
        // Held in the slot until the step loop can place it: an exchange
        // answer is never dropped for want of room on the port.
        let (Some(buf), Some(len)) = (self.ready_reply.get_mut(slot), self.ready_len.get_mut(slot))
        else {
            return false;
        };
        let Some(dst) = buf.get_mut(..reply.len()) else {
            return false;
        };
        dst.copy_from_slice(reply);
        #[expect(clippy::cast_possible_truncation, reason = "at most REPLY_MAX")]
        {
            *len = reply.len() as u16;
        }
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

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI the kernel passes a valid, exclusively
    // borrowed `state` and a live syscall table.
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
        s.in_auth = in_chan;
        s.in_key = dev_channel_port(sys, 0, 1);
        s.in_ledger = dev_channel_port(sys, 0, 2);
        s.in_token = dev_channel_port(sys, 0, 3);
        s.out_auth = out_chan;
        s.out_ledger = dev_channel_port(sys, 1, 1);
        s.out_token = dev_channel_port(sys, 1, 2);
        s.out_grant = dev_channel_port(sys, 1, 3);
        s.in_ca_key = dev_channel_port(sys, 0, 4);
        s.in_cert = dev_channel_port(sys, 0, 5);
        s.in_requests = dev_channel_port(sys, 0, 6);
        s.out_responses = dev_channel_port(sys, 1, 4);
        s.trust_domain_len = 0;
        s.bad_trust_domain = 0;
        s.ready_ids = [None; ready::PROBES];
        s.ready_len = [0; ready::PROBES];
        s.requests = Collector::new();
        s.outbox = ExchangeOutbox::new();
        s.key = issuer_key::IssuerKey::empty();
        s.key_pending = issuer_key::PendingRecord::empty();
        s.issuer_len = 0;
        s.host_ok = 0;
        s.allow_possession = 0;
        s.min_tier = 1;
        s.posture = POSTURE_UNDECLARED;
        s.ttl_ms = 30_000;
        s.bad_dest = 0;
        s.authority = Authority::new();

        parse_tlv(s, params, params_len);

        if s.host_ok == 0 || s.issuer_len == 0 || s.bad_dest != 0 {
            let line =
                b"[custody-authority] host (32 hex), iss and well-formed dest<n> are required";
            dev_log(sys, 1, line.as_ptr(), line.len());
            return -3;
        }
        if s.bad_trust_domain != 0
            || (s.in_cert >= 0 && (s.trust_domain_len == 0 || s.in_ca_key < 0))
        {
            let line = b"[custody-authority] cert_in takes host certificates: it needs trust_domain (<= 128 bytes) and ca_key";
            dev_log(sys, 1, line.as_ptr(), line.len());
            return -3;
        }
        let posture = match s.posture {
            POSTURE_DEVELOPMENT => key_custody::Posture::Development,
            POSTURE_PRODUCTION => key_custody::Posture::Production,
            _ => {
                let line = b"[custody-authority] refusing to construct: posture undeclared";
                dev_log(sys, 1, line.as_ptr(), line.len());
                return -1;
            }
        };
        // The grant key's custody floor, as the transfer-grant service's:
        // a grant moves live TLS secrets.
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
            let line = b"[custody-authority] refusing to construct:";
            dev_log(sys, 1, line.as_ptr(), line.len());
            dev_log(sys, 1, why.as_ptr(), why.len());
            return -1;
        }
        let cfg = &mut s.authority.config;
        cfg.source = s.host;
        cfg.policy = tg::Policy {
            allow_possession: s.allow_possession != 0,
            min_tier: s.min_tier,
        };
        cfg.ttl_ms = u64::from(s.ttl_ms);
        // Construction is refused above unless the posture admits the
        // grant key's vault, so a running authority states it.
        cfg.posture_admits = true;
        let _ = cfg.set_trust_domain(&s.trust_domain[..usize::from(s.trust_domain_len)]);
        let n = usize::from(s.issuer_len);
        cfg.issuer[..n].copy_from_slice(&s.issuer[..n]);
        cfg.issuer_len = n;
        let line = b"[custody-authority] init";
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
        let mut worked = drain_certs(s, sys);
        let ModuleState {
            in_auth,
            in_ledger,
            in_token,
            out_auth,
            out_ledger,
            out_token,
            out_grant,
            key,
            sign_scratch,
            authority,
            buf,
            ready_reply,
            ready_len,
            ..
        } = &mut *s;
        let mut host = ModuleHost {
            sys,
            key,
            scratch: sign_scratch,
            out_auth: *out_auth,
            out_ledger: *out_ledger,
            out_token: *out_token,
            out_grant: *out_grant,
            ready_reply,
            ready_len,
        };
        for _ in 0..4 {
            if *in_ledger < 0 || !chan::can_read(sys, *in_ledger) {
                break;
            }
            let (t, n) = chan::channel_read_msg(sys, *in_ledger, buf);
            if t == 0 {
                break;
            }
            worked = true;
            authority.on_ledger(&mut host, t, buf.get(..usize::from(n)).unwrap_or(&[]));
        }
        for _ in 0..4 {
            if *in_token < 0 || !chan::can_read(sys, *in_token) {
                break;
            }
            let (t, n) = chan::channel_read_msg(sys, *in_token, buf);
            if t == 0 {
                break;
            }
            worked = true;
            authority.on_token(&mut host, t, buf.get(..usize::from(n)).unwrap_or(&[]));
        }
        for _ in 0..2 {
            if *in_auth < 0 || !chan::can_read(sys, *in_auth) {
                break;
            }
            let (t, n) = chan::channel_read_msg(sys, *in_auth, buf);
            if t == 0 {
                break;
            }
            worked = true;
            authority.on_provider(&mut host, t, buf.get(..usize::from(n)).unwrap_or(&[]));
        }
        authority.tick(&mut host);
        worked |= serve_ready(s, sys);
        if worked {
            STEP_DID_WORK
        } else {
            0
        }
    }
}

/// The `CUSTODY_READY` exchanges: place answers that are ready, then take
/// new questions while the port has room. True when anything moved.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live syscall table.
unsafe fn serve_ready(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    if s.in_requests < 0 || s.out_responses < 0 {
        return false;
    }
    let mut worked = false;
    // Answers first: a question is taken only when its answer could leave.
    for slot in 0..ready::PROBES {
        if !s.outbox.flush(sys, s.out_responses, &s.out) {
            return worked;
        }
        let n = usize::from(s.ready_len[slot]);
        if n == 0 {
            continue;
        }
        s.ready_len[slot] = 0;
        if let Some(id) = s.ready_ids[slot].take() {
            worked = true;
            answer_ready(s, sys, &id, slot, n);
        }
    }
    for _ in 0..2 {
        if !s.outbox.flush(sys, s.out_responses, &s.out) || !chan::can_read(sys, s.in_requests) {
            break;
        }
        let n = (sys.channel_read)(s.in_requests, s.req_buf.as_mut_ptr(), s.req_buf.len());
        if n <= 0 {
            break;
        }
        worked = true;
        let outcome = {
            let record = s.req_buf.get(..n as usize).unwrap_or(&[]);
            s.requests.accept(record)
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
            take_question(s, sys, at);
        }
    }
    worked
}

/// One collected `CUSTODY_READY` request.
///
/// # Safety
///
/// As `serve_ready`.
unsafe fn take_question(s: &mut ModuleState, sys: &SyscallTable, at: usize) {
    let Some(request) = s.requests.request(at) else {
        return;
    };
    let id = request.id;
    let refused = typed_exchange::admissible(request.method, request.resp_credit);
    let body_len = request.body.len();
    let mut body = [0u8; MAX_REQUEST];
    body[..body_len].copy_from_slice(request.body);
    s.requests.release(at);
    if let Some(status) = refused {
        answer_status(s, sys, &id, status);
        return;
    }
    let Some((ready::REQUEST, payload)) = typed_exchange::message(&body[..body_len]) else {
        answer_status(s, sys, &id, x::status::BAD_REQUEST);
        return;
    };
    let Some(slot) = s.ready_ids.iter().position(Option::is_none) else {
        // Both slots wait on the ledger: BUSY, at once.
        let mut env = [0u8; 3 + 2];
        env[0] = ready::REPLY;
        env[1..3].copy_from_slice(&2u16.to_le_bytes());
        env[3..].copy_from_slice(&[ready::status::BUSY, 0]);
        if let Some(n) = typed_exchange::write_answer(&id, &env, &mut s.out) {
            s.outbox.send(sys, s.out_responses, &s.out, n);
        }
        return;
    };
    s.ready_ids[slot] = Some(id);
    let ModuleState {
        out_auth,
        out_ledger,
        out_token,
        out_grant,
        key,
        sign_scratch,
        authority,
        ready_reply,
        ready_len,
        ..
    } = &mut *s;
    let mut host = ModuleHost {
        sys,
        key,
        scratch: sign_scratch,
        out_auth: *out_auth,
        out_ledger: *out_ledger,
        out_token: *out_token,
        out_grant: *out_grant,
        ready_reply,
        ready_len,
    };
    authority.ready_request(&mut host, slot, payload);
}

/// Write the reply held in `slot` (`n` bytes) as `id`'s answer.
///
/// # Safety
///
/// As `serve_ready`; the outbox is clear.
unsafe fn answer_ready(
    s: &mut ModuleState,
    sys: &SyscallTable,
    id: &ExchangeId,
    slot: usize,
    n: usize,
) {
    let reply = &s.ready_reply[slot][..n];
    let Ok(len) =
        auth_wire::write_envelope(ready::REPLY, reply, &mut s.out[typed_exchange::ANSWER_AT..])
    else {
        answer_status(s, sys, id, x::status::FAILED);
        return;
    };
    if let Some(total) = typed_exchange::seal_answer(id, len, &mut s.out) {
        s.outbox.send(sys, s.out_responses, &s.out, total);
    }
}

/// Answer with a status alone.
///
/// # Safety
///
/// As `serve_ready`.
unsafe fn answer_status(s: &mut ModuleState, sys: &SyscallTable, id: &ExchangeId, status: u16) {
    if let Some(n) = typed_exchange::write_status(id, status, &mut s.out) {
        s.outbox.send(sys, s.out_responses, &s.out, n);
    }
}

/// Take the CA's public key from a VERIFY `MSG_KEY_ADD` on `ca_key`: the
/// anchor a host certificate must chain to. The latest one is the anchor.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live syscall table.
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
        if let Some(n) = x509_leaf::write_anchor(rec.suite, rec.key_ref, &mut anchor) {
            let _ = s.authority.config.set_anchor(&anchor[..n]);
        }
    }
}

/// Take host certificates off `cert_in`. True when a frame was read.
///
/// # Safety
///
/// As `drain_ca_key`.
unsafe fn drain_certs(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    if s.in_cert < 0 {
        return false;
    }
    let mut worked = false;
    for _ in 0..2 {
        let (msg_type, copied, pl) = net_read_frame_sized(
            sys,
            s.in_cert,
            s.cert_inbox.as_mut_ptr(),
            s.cert_inbox.len(),
        );
        if msg_type == 0 {
            break;
        }
        worked = true;
        if msg_type != 0x5C || copied != pl {
            s.authority.stats.certs_refused = s.authority.stats.certs_refused.saturating_add(1);
            continue;
        }
        let chain = &s.cert_inbox[3..3 + pl];
        let _ = s.authority.on_cert(verify_suite, sha256_into, chain);
    }
    worked
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
    // E_AGAIN: the vault is not ready; the record is held and retried.
    s.key.open_status(sys, rec.suite, rec.key_ref) == E_AGAIN
}

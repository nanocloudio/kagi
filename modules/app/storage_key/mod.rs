//! Storage-key service — grants, fresh attachment bundles, rotation and
//! recovery for encrypted volumes, decided by this issuer and never holding
//! a volume key.
//!
//! The decisions are `modules/common/storage_key_service.rs`, a state
//! machine that does no I/O of its own; this module is its host. It moves
//! frames between the service and four parties:
//!
//! - **requesters** on `request_in` / `response_out`, where this module is
//!   a PROVIDER of the workspace exchange contract: the control plane asking
//!   to create, grant, revoke, rotate, retire, erase or authorise recovery,
//!   and attaching nodes asking for a challenge and then for a bundle, or
//!   for a renewal of an attachment they hold. A request body is one
//!   `msg::REQUEST` envelope and its answer body one `msg::REPLY` envelope
//!   (`typed_exchange.rs`; byte layouts in
//!   `docs/architecture/typed-operations.md`); the exchange id is the
//!   correlation;
//! - **the ledger** (`security_state`) on `ledger_out` / `ledger_in`, which
//!   holds every grant, recovery set, ticket, anti-replay claim and audit
//!   entry;
//! - **the custodians** (`storage_custodian`) on `custodian_out` /
//!   `custodian_in`, each of which releases its share only against an order
//!   this issuer signed, and refuses a resource for good once ordered to
//!   erase it;
//! - **the key lifecycle** on `signing_key`, which names the vault label of
//!   the storage-grant signing key. The key is generated in the vault and
//!   only signatures leave it; its public half is announced on
//!   `key_announce` as a VERIFY `MSG_KEY_ADD`, for the custodians'
//!   `verify_key`. Only this module can: a vault label is this module's
//!   own, and nothing else opens the key to read its public half.
//!
//! The control verbs on `request_in` carry no authentication of their own:
//! the port is a control-plane port and belongs behind the same admission
//! as the rest of the control surface. Attach, recover and renew requests
//! authenticate themselves, with a proof by the enrolled device key.

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
#[path = "../../common/storage_key.rs"]
mod storage_key;
#[path = "../../common/storage_key_service.rs"]
mod storage_key_service;
#[path = "../../common/time_policy.rs"]
mod time_policy;
#[path = "../../common/typed_exchange.rs"]
mod typed_exchange;

use abi::contracts::exchange::{self as x, Collector, ExchangeId};

use auth_wire::assurance::{AssuranceLevel, AuthMethod, Evidence};
use storage_key as sk;
use storage_key_service::{self as svc, Port};

const STEP_DID_WORK: i32 = 2;

/// Messages taken per port per step. A ledger answer can cost a signature
/// verification and a sign, a request a proof and an evidence check; four
/// answers and two requests keep an attach moving through its round trips
/// while bounding a step to a handful of curve operations.
const MAX_REQUESTS_PER_STEP: usize = 2;
const MAX_LEDGER_PER_STEP: usize = 4;
const MAX_CUSTODIAN_PER_STEP: usize = 2;

/// Longest message this module reads: a request, a ledger value carrying a
/// record, or a custodian result.
const MSG_BUF: usize = 4096;
/// Exchanges collected at once.
const MAX_EXCHANGES: usize = 4;
/// Longest target and header block held. Neither is read; they are bounded
/// so the module can sit behind an HTTP route as well as a requester.
const MAX_TARGET: usize = 256;
const MAX_HEADERS: usize = 1024;
/// Longest request body: one `msg::REQUEST` envelope.
const MAX_REQUEST: usize = auth_wire::ENVELOPE + 1 + svc::MAX_REQUEST;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,   // in[0]:  ExchangeRequest, msg::REQUEST bodies
    out_responses: i32, // out[0]: ExchangeResponse, msg::REPLY bodies
    in_key: i32,
    out_ledger: i32,
    in_ledger: i32,
    out_custodian: i32,
    in_custodian: i32,
    out_key_announce: i32,
    /// The open key's public half is still to be announced.
    announce: u8,

    /// The storage-grant signing key, as a vault label.
    key: issuer_key::IssuerKey,
    /// Scratch for one vault SIGN over a record's signed prefix.
    sign_scratch: [u8; sk::MAX_RECORD + issuer_key::SIGN_SCRATCH_OVERHEAD],

    issuer: [u8; sk::MAX_ID],
    issuer_len: u16,

    buf: [u8; MSG_BUF],
    service: svc::Service,

    /// Requests being collected until their body is whole.
    requests: Collector<MAX_EXCHANGES, MAX_TARGET, MAX_HEADERS, MAX_REQUEST>,
    /// The one answer, credit or refusal owed to `response_out`. Nothing new
    /// is read while it is held.
    outbox: ExchangeOutbox,
    /// The record being read from `request_in`.
    record: [u8; x::RECORD_MAX],
    /// The record being written to `response_out`.
    out: [u8; x::RECORD_MAX],
}

define_params! {
    ModuleState;

    // The issuer identity every record names and every device proof is
    // addressed to.
    1, iss, str, 0 => |s, d, len| {
        let n = if len > sk::MAX_ID { sk::MAX_ID } else { len };
        let mut i = 0usize;
        while i < n {
            s.issuer[i] = *d.add(i);
            i += 1;
        }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_ID above")]
        {
            s.issuer_len = n as u16;
        }
    };
}

/// The service's view of this module: its clock, CSPRNG, vault key and
/// output ports.
struct ModuleHost<'a> {
    sys: &'a SyscallTable,
    key: &'a issuer_key::IssuerKey,
    scratch: &'a mut [u8],
    out_responses: i32,
    outbox: &'a mut ExchangeOutbox,
    out: &'a mut [u8; x::RECORD_MAX],
    out_ledger: i32,
    out_custodian: i32,
}

impl svc::Host for ModuleHost<'_> {
    fn now_ms(&mut self) -> u64 {
        // A decision dated by a clock the platform does not vouch for is not
        // dated: no trustworthy clock reads as 0, which the service refuses.
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

    fn sha256(&self) -> sk::Sha256Fn {
        sha256_into
    }

    fn verify(&self) -> sk::VerifyFn {
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
        // ES256 signs a digest, Ed25519 the message itself: what the vault
        // is handed is what the suite signs.
        let digest;
        let input: &[u8] = if self.key.suite() == auth_wire::suite::ES256 {
            digest = sha256(message);
            &digest
        } else {
            message
        };
        // SAFETY: `sys` is live; `scratch` is module state and does not
        // alias `input`, which is either a local or a service buffer.
        unsafe { self.key.sign(self.sys, self.scratch, input, signature) }
    }

    fn device_facts(
        &self,
        record: &[u8],
        tenant: &[u8],
        suite: u16,
        public: &[u8],
    ) -> sk::DeviceFacts {
        let revoked = matches!(jose::claim_str(record, b"status"), Some(b"revoked"));
        let in_tenant = jose::claim_str(record, b"sub") == Some(tenant);
        let key_bound = match (
            jose::claim_str(record, b"jkt"),
            jwk_thumbprint(suite, public),
        ) {
            (Some(bound), Some(presented)) => bound == presented.as_slice(),
            _ => false,
        };
        sk::DeviceFacts {
            active: !revoked,
            in_tenant,
            key_bound,
            assurance: enrolment_assurance(record),
        }
    }

    fn answer(&mut self, caller: &svc::Caller, frame: &[u8]) -> bool {
        // One answer is placed or held at a time. An answer that finds one
        // still held, after a last attempt to place it, is not written over
        // it: the service counts it unanswered rather than this losing two.
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
        // An answer that does not fit one record is this module's failure,
        // answered as one rather than left unanswered.
        let Some(n) = typed_exchange::write_answer(&id, frame, &mut self.out[..])
            .or_else(|| typed_exchange::write_status(&id, x::status::FAILED, &mut self.out[..]))
        else {
            return false;
        };
        // SAFETY: as above; `out` holds the record until it is placed.
        unsafe {
            self.outbox
                .send(self.sys, self.out_responses, &self.out[..], n)
        };
        true
    }

    fn send(&mut self, port: Port, frame: &[u8]) -> bool {
        let chan = match port {
            Port::Ledger => self.out_ledger,
            Port::Custodian => self.out_custodian,
        };
        if chan < 0 || frame.len() > i32::MAX as usize {
            return false;
        }
        // SAFETY: `sys` is live and `frame` is a borrowed buffer of its
        // length.
        unsafe {
            if !chan::can_write(self.sys, chan) {
                return false;
            }
            #[expect(
                clippy::cast_possible_truncation,
                reason = "bounded against i32::MAX above"
            )]
            let want = frame.len() as i32;
            (self.sys.channel_write)(chan, frame.as_ptr(), frame.len()) == want
        }
    }
}

/// Answer `id` with a status alone: a request this service did not read.
///
/// # Safety
///
/// `host.sys` is the live syscall table.
unsafe fn answer_status(host: &mut ModuleHost<'_>, id: &ExchangeId, status: u16) {
    if let Some(n) = typed_exchange::write_status(id, status, &mut host.out[..]) {
        host.outbox
            .send(host.sys, host.out_responses, &host.out[..], n);
    }
}

fn sha256_into(data: &[u8], out: &mut [u8; 32]) {
    *out = sha256(data);
}

/// The profile's `VerifyFn` over the SDK's curves.
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

/// The RFC 7638 thumbprint of a device key, as the directory's `cnf.jkt`
/// spells it.
fn jwk_thumbprint(suite: u16, public: &[u8]) -> Option<[u8; 43]> {
    let mut x = [0u8; 48];
    let mut y = [0u8; 48];
    let record = match suite {
        auth_wire::suite::ED25519 if public.len() == 32 => {
            let n = b64::encode(public, &mut x)?;
            jwk::JwkRecord::okp_ed25519(x.get(..n)?).ok()?
        }
        auth_wire::suite::ES256 if public.len() == 65 && public.first() == Some(&0x04) => {
            let nx = b64::encode(public.get(1..33)?, &mut x)?;
            let ny = b64::encode(public.get(33..65)?, &mut y)?;
            jwk::JwkRecord::ec_p256(x.get(..nx)?, y.get(..ny)?).ok()?
        }
        _ => return None,
    };
    record.thumbprint(sha256_into).ok()
}

/// The NIST assurance level of a device's enrolment, from the `amr` the
/// directory recorded: 0 when it recorded no method this issuer knows.
fn enrolment_assurance(record: &[u8]) -> u8 {
    let Some(amr) = jose::claim_array(record, b"amr") else {
        return 0;
    };
    let mut evidence = Evidence::at(0);
    let mut recognised = false;
    for name in amr {
        // A name this issuer does not know carries no evidence, and must not
        // stand in for one that does: an `amr` of nothing recognised is no
        // assurance rather than the floor of the ladder.
        if AuthMethod::parse_bytes(name).is_some() {
            evidence = evidence.with_amr_name(name);
            recognised = true;
        }
    }
    if !recognised {
        return 0;
    }
    match evidence.level() {
        AssuranceLevel::Aal1 => 1,
        AssuranceLevel::Aal2 => 2,
        AssuranceLevel::Aal3 => 3,
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
        s.requests = Collector::new();
        s.outbox = ExchangeOutbox::new();
        s.in_key = dev_channel_port(sys, 0, 1);
        s.out_ledger = dev_channel_port(sys, 1, 1);
        s.in_ledger = dev_channel_port(sys, 0, 2);
        s.out_custodian = dev_channel_port(sys, 1, 2);
        s.in_custodian = dev_channel_port(sys, 0, 3);
        s.out_key_announce = dev_channel_port(sys, 1, 3);

        s.key = issuer_key::IssuerKey::empty();
        s.issuer = [0; sk::MAX_ID];
        s.issuer_len = 0;

        parse_tlv(s, params, params_len);

        let n = usize::from(s.issuer_len);
        let ModuleState {
            issuer, service, ..
        } = s;
        service.init(issuer.get(..n).unwrap_or(&[]));

        dev_log(sys, 3, b"[storage-key] init".as_ptr(), 18);
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
        announce_key(s, sys);

        // What is owed goes out first, and nothing new is read until it has:
        // a record taken and then answered into a full channel would be
        // answered with silence.
        if !s.outbox.flush(sys, s.out_responses, &s.out) {
            return 0;
        }

        let ModuleState {
            in_requests,
            out_responses,
            in_ledger,
            out_ledger,
            in_custodian,
            out_custodian,
            key,
            sign_scratch,
            buf,
            service,
            requests,
            outbox,
            record,
            out,
            ..
        } = s;
        let mut host = ModuleHost {
            sys,
            key,
            scratch: sign_scratch,
            out_responses: *out_responses,
            outbox,
            out,
            out_ledger: *out_ledger,
            out_custodian: *out_custodian,
        };
        let mut worked = false;

        // Answers first: each frees or advances an operation, so a request
        // in the same step may take the slot it vacated.
        // Every record read below ends in at most one answer, and one is
        // placed or held at a time: nothing is read while one is held.
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
        for _ in 0..MAX_CUSTODIAN_PER_STEP {
            if host.outbox.holding() || !chan::can_read(sys, *in_custodian) {
                break;
            }
            let (t, n) = chan::channel_read_msg(sys, *in_custodian, buf);
            if t == 0 {
                break;
            }
            worked = true;
            if t == svc::msg::REWRAP_RESULT || t == svc::msg::ERASE_RESULT {
                service.on_custodian(&mut host, buf.get(..usize::from(n)).unwrap_or(&[]));
            }
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
            let outcome = requests.accept(record.get(..n as usize).unwrap_or(&[]));
            // One record owes at most one thing: a body grant, a refusal, or
            // (once whole) an answer.
            if let Some((id, bytes)) = requests.take_grant() {
                if let Some(len) = x::write_credit(&id, bytes, &mut host.out[..]) {
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
            let body_len = request.body.len();
            buf[..body_len].copy_from_slice(request.body);
            requests.release(at);
            if let Some(status) = refused {
                answer_status(&mut host, &id, status);
                continue;
            }
            match typed_exchange::message(&buf[..body_len]) {
                Some((svc::msg::REQUEST, payload)) => service.on_request(&mut host, &id.0, payload),
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

/// Take the storage-grant signing key from a `MSG_KEY_ADD`.
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
        // The channel carries the whole issuer keyset; this module signs one
        // profile and takes only that profile's signing record.
        if msg_type != auth_wire::MSG_KEY_ADD {
            continue;
        }
        let Ok(rec) = auth_wire::KeyRecord::decode_add(&buf[..usize::from(plen)]) else {
            continue;
        };
        if rec.key_use != auth_wire::key_use::SIGN
            || rec.profile_id != auth_wire::suite::profile::STORAGE_GRANT
        {
            continue;
        }
        // Records are held in the ledger beside three envelopes, and a
        // signature that would not fit there is not a record suite.
        if !matches!(
            rec.suite,
            auth_wire::suite::ED25519 | auth_wire::suite::ES256
        ) || rec.key_ref.is_empty()
            || rec.key_ref.len() > auth_wire::MAX_KEY_LABEL
        {
            continue;
        }
        s.key.close(sys);
        if s.key.open(sys, rec.suite, rec.key_ref) {
            s.announce = 1;
        }
    }
}

/// Announce the open key's public half as a VERIFY `MSG_KEY_ADD`: what each
/// custodian verifies this issuer's orders under. Asked again each step until
/// the channel takes it.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a live syscall table.
unsafe fn announce_key(s: &mut ModuleState, sys: &SyscallTable) {
    if s.announce == 0 || s.out_key_announce < 0 || !s.key.is_open() {
        return;
    }
    let rec = auth_wire::KeyRecord {
        issuer: s.issuer.get(..usize::from(s.issuer_len)).unwrap_or(&[]),
        profile_id: auth_wire::suite::profile::STORAGE_GRANT,
        kid: b"storage-grant",
        suite: s.key.suite(),
        state: auth_wire::key_state::ACTIVE,
        key_use: auth_wire::key_use::VERIFY,
        generation: 0,
        activate_after_unix: 0,
        remove_after_unix: 0,
        key_ref: s.key.public_key(),
    };
    let mut payload = [0u8; ANNOUNCE_BUF];
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

/// A storage-grant key announcement: the issuer, the kid, the record's
/// field overhead, and the public key at its widest — 65 bytes for ES256,
/// where Ed25519 takes 32. Within the `key_announce` port's `max_record`.
const ANNOUNCE_BUF: usize = sk::MAX_ID + 65 + 192;
const ANNOUNCE_MAX_RECORD: usize = 512;
const _: () = assert!(
    ANNOUNCE_BUF <= ANNOUNCE_MAX_RECORD,
    "a key announcement must fit the key_announce port's max_record"
);

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

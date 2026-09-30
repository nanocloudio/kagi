//! Storage-key recovery custodian — one of the three independent holders of
//! a volume's recovery shares.
//!
//! The custodian's recovery key is a labelled P-256 agreement key in this
//! node's vault. `SHARE_SPLIT` in a provisioning vault seals one share of
//! every volume key to it; nothing but this vault can open that envelope.
//! A share leaves only through `SHARE_REWRAP`, sealed to the fresh recipient
//! an attach or recovery names, and only against a release the storage-key
//! issuer signed: the order carries the signed authorisation, the
//! recipient's public key and this custodian's custody envelope, and
//! `storage_key::admit_order` decides it.
//!
//! What the custodian adds is independence, not policy of its own: it holds
//! one share, releases it only to what the issuer's key authorised, remembers
//! the releases it made so one authorisation cannot draw a second envelope,
//! and never sees a share in the clear — the vault opens and reseals inside
//! one operation.
//!
//! An `ERASE_ORDER` carries the issuer's signed erasure of a resource
//! (`storage_key::admit_erase`). The custodian's recovery key is one key for
//! every resource, so there is no per-resource key to destroy here: the
//! custody envelopes themselves are the issuer's ledger records, deleted by
//! the erasure. What the custodian does is refuse, from then on, to rewrap
//! any envelope of the erased resource, so a copy of a deleted envelope
//! opens nothing through it.
//!
//! Ports: `orders` / `results` to the issuer's `custodian_out` /
//! `custodian_in`; `verify_key` takes the issuer's storage-grant
//! verification key as a `MSG_KEY_ADD` VERIFY record. `CUSTODIAN_KEY_REQ`
//! on `orders` answers this custodian's recovery public key, which a
//! creation names.

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

use storage_key as sk;
use storage_key::Refusal;
use storage_key_service as svc;

const STEP_DID_WORK: i32 = 2;
/// One order per step: an order is a signature verification and a vault
/// rewrap, two P-256 agreements.
const MAX_ORDERS_PER_STEP: usize = 1;
/// Releases remembered, so one authorisation cannot draw a second envelope
/// from this custodian. It is the custodian's own check and not the only
/// one: the issuer claims a release's anti-replay id in the ledger before it
/// orders anything. Past this many the oldest is forgotten, and an
/// authorisation still inside its `ENVELOPE_TTL_MS` could be offered again.
const MAX_SEEN: usize = 32;
const MSG_BUF: usize = 4096;
/// Longest verification key: an uncompressed P-256 point.
const MAX_VERIFY_KEY: usize = 65;
/// Erased resources remembered. The list is held in memory: past this many,
/// the oldest is forgotten, and a restart forgets them all.
const MAX_ERASED: usize = 64;
/// The index of a module configured as a custodian it cannot be. No order
/// names it, so the module answers nothing rather than standing in for one
/// of the three.
const NOT_A_CUSTODIAN: u8 = 0xFF;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_orders: i32,
    out_results: i32,
    in_key: i32,

    /// Which of the three custodians this is: 0, 1 or 2. The share index of
    /// its custody envelope is this plus one, and [`NOT_A_CUSTODIAN`] is a
    /// configuration that names none of the three.
    index: u8,
    label: [u8; key_vault::MAX_LABEL],
    label_len: u8,
    /// The recovery key's vault handle, or -1.
    handle: i32,
    public: [u8; sk::PUBLIC_LEN],
    thumbprint: [u8; 32],

    issuer_suite: u16,
    issuer_key: [u8; MAX_VERIFY_KEY],
    issuer_key_len: u8,

    seen: [[u8; 16]; MAX_SEEN],
    seen_live: u8,
    seen_next: u8,

    erased: [[u8; 16]; MAX_ERASED],
    erased_live: u8,
    erased_next: u8,

    released: u32,
    refused: u32,

    buf: [u8; MSG_BUF],
}

define_params! {
    ModuleState;

    // Which custodian: 0, 1 or 2. The issuer addresses orders by it, and a
    // custody envelope's share index is it plus one.
    1, index, u8, 0 => |s, d, len| {
        s.index = p_u8(d, len, 0, 0);
    };

    // The vault label of this custodian's recovery key. The key is generated
    // in the vault on first open and survives restarts under this label.
    2, label, str, 0 => |s, d, len| {
        let n = if len > key_vault::MAX_LABEL { key_vault::MAX_LABEL } else { len };
        let mut i = 0usize;
        while i < n {
            s.label[i] = *d.add(i);
            i += 1;
        }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_LABEL above")]
        {
            s.label_len = n as u8;
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
        s.in_orders = in_chan;
        s.out_results = out_chan;
        s.in_key = dev_channel_port(sys, 0, 1);
        s.index = 0;
        s.label = [0; key_vault::MAX_LABEL];
        s.label_len = 0;
        s.handle = -1;
        s.public = [0; sk::PUBLIC_LEN];
        s.thumbprint = [0; 32];
        s.issuer_suite = 0;
        s.issuer_key = [0; MAX_VERIFY_KEY];
        s.issuer_key_len = 0;
        s.seen = [[0; 16]; MAX_SEEN];
        s.seen_live = 0;
        s.seen_next = 0;
        s.erased = [[0; 16]; MAX_ERASED];
        s.erased_live = 0;
        s.erased_next = 0;
        s.released = 0;
        s.refused = 0;

        parse_tlv(s, params, params_len);
        if s.index > 2 {
            // A fourth custodian is not a custodian of a 2-of-3 set.
            s.index = NOT_A_CUSTODIAN;
        }
        open_recovery_key(s, sys);

        dev_log(sys, 3, b"[custodian] init".as_ptr(), 16);
        0
    }
}

/// Open (or on first start, generate) the recovery key under its label.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live syscall table.
unsafe fn open_recovery_key(s: &mut ModuleState, sys: &SyscallTable) {
    let n = usize::from(s.label_len);
    if n == 0 {
        return;
    }
    // AGREE to open custody envelopes, EXPORT_PUBLIC because an envelope
    // names its recipient by public key, PERSIST because the shares sealed
    // to it outlive any one run. Nothing else: this key never signs and
    // never leaves.
    const USAGE: u32 =
        key_vault::usage::AGREE | key_vault::usage::EXPORT_PUBLIC | key_vault::usage::PERSIST;
    // [suite u16][usage u32][flags u8][label_len u8][label]
    // [pub_out_ptr u64][pub_out_cap u16][pub_len_out u16]
    let mut arg = [0u8; 8 + key_vault::MAX_LABEL + 12];
    arg[0..2].copy_from_slice(&key_vault::suite::P256.to_le_bytes());
    arg[2..6].copy_from_slice(&USAGE.to_le_bytes());
    arg[6] = 0;
    arg[7] = s.label_len;
    arg[8..8 + n].copy_from_slice(&s.label[..n]);
    let tail = 8 + n;
    let ptr = s.public.as_mut_ptr() as u64;
    arg[tail..tail + 8].copy_from_slice(&ptr.to_le_bytes());
    #[expect(clippy::cast_possible_truncation, reason = "PUBLIC_LEN is 65")]
    arg[tail + 8..tail + 10].copy_from_slice(&(sk::PUBLIC_LEN as u16).to_le_bytes());
    let h = (sys.provider_call)(-1, key_vault::OPEN_OR_GENERATE, arg.as_mut_ptr(), tail + 12);
    if h < 0 {
        return;
    }
    let got = usize::from(u16::from_le_bytes([arg[tail + 10], arg[tail + 11]]));
    if got != sk::PUBLIC_LEN {
        let _ = (sys.provider_call)(h, key_vault::DESTROY, core::ptr::null_mut(), 0);
        return;
    }
    s.handle = h;
    s.thumbprint = sha256(&s.public);
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
        for _ in 0..MAX_ORDERS_PER_STEP {
            if !chan::can_read(sys, s.in_orders) || !chan::can_write(sys, s.out_results) {
                break;
            }
            let mut buf = [0u8; MSG_BUF];
            let (t, n) = chan::channel_read_msg(sys, s.in_orders, &mut buf);
            if t == 0 {
                break;
            }
            worked = true;
            let payload = buf.get(..usize::from(n)).unwrap_or(&[]);
            match t {
                svc::msg::REWRAP_ORDER => handle_order(s, sys, payload),
                svc::msg::ERASE_ORDER => handle_erase(s, sys, payload),
                svc::msg::CUSTODIAN_KEY_REQ => answer_key(s, sys, payload),
                _ => {}
            }
        }
        if worked {
            STEP_DID_WORK
        } else {
            0
        }
    }
}

/// Take the issuer's storage-grant verification key.
///
/// # Safety
///
/// As `open_recovery_key`.
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
        if msg_type != auth_wire::MSG_KEY_ADD {
            continue;
        }
        let Ok(rec) = auth_wire::KeyRecord::decode_add(&buf[..usize::from(plen)]) else {
            continue;
        };
        if rec.key_use != auth_wire::key_use::VERIFY
            || rec.profile_id != auth_wire::suite::profile::STORAGE_GRANT
        {
            continue;
        }
        let want = match rec.suite {
            auth_wire::suite::ED25519 => 32,
            auth_wire::suite::ES256 => 65,
            _ => continue,
        };
        if rec.key_ref.len() != want {
            continue;
        }
        s.issuer_key[..want].copy_from_slice(rec.key_ref);
        #[expect(clippy::cast_possible_truncation, reason = "32 or 65")]
        {
            s.issuer_key_len = want as u8;
        }
        s.issuer_suite = rec.suite;
    }
}

/// Wall-clock milliseconds, or 0 when the platform does not vouch for its
/// clock — which `admit_order` refuses as expired.
///
/// # Safety
///
/// `sys` is live.
unsafe fn now_ms(sys: &SyscallTable) -> u64 {
    let obs = dev_trusted_unix(sys);
    if time_policy::now_for(time_policy::Decision::CredentialWindow, &obs).is_none() {
        return 0;
    }
    dev_unix_millis(sys)
}

/// Release this custodian's share to the recipient an order names, if the
/// issuer's signed authorisation admits it.
///
/// # Safety
///
/// As `open_recovery_key`.
unsafe fn handle_order(s: &mut ModuleState, sys: &SyscallTable, payload: &[u8]) {
    let Some(order) = svc::read_order(payload) else {
        return;
    };
    // Orders fan out to all three custodians; each answers only its own.
    if order.custodian != s.index {
        return;
    }
    let mut envelope = [0u8; sk::ENVELOPE_LEN];
    let outcome = release(s, sys, &order, &mut envelope);
    let mut frame = [0u8; 64 + sk::ENVELOPE_LEN];
    let n = match outcome {
        Ok(()) => {
            s.released = s.released.saturating_add(1);
            svc::write_result(order.corr, s.index, None, &envelope, &mut frame)
        }
        Err(refusal) => {
            s.refused = s.refused.saturating_add(1);
            svc::write_result(order.corr, s.index, Some(refusal), &[], &mut frame)
        }
    };
    envelope.fill(0);
    if let Some(n) = n {
        // The frame carries its own envelope: a raw write, not a typed one.
        // A short write loses the result and the issuer times the custodian
        // out, which is the same outcome as silence.
        let _ = (sys.channel_write)(s.out_results, frame.as_ptr(), n);
    }
}

/// # Safety
///
/// As `open_recovery_key`.
unsafe fn release(
    s: &mut ModuleState,
    sys: &SyscallTable,
    order: &svc::Order<'_>,
    envelope: &mut [u8; sk::ENVELOPE_LEN],
) -> Result<(), Refusal> {
    if s.handle < 0 || s.issuer_key_len == 0 {
        return Err(Refusal::NoIssuerKey);
    }
    let live = usize::from(s.seen_live);
    let auth = sk::admit_order(
        sha256_into,
        verify_suite,
        s.issuer_suite,
        s.issuer_key
            .get(..usize::from(s.issuer_key_len))
            .unwrap_or(&[]),
        &s.thumbprint,
        order.record,
        order.recipient,
        order.envelope,
        now_ms(sys),
        s.seen.get(..live).unwrap_or(&[]),
    )?;
    sk::refuse_erased(
        order.envelope,
        s.erased.get(..usize::from(s.erased_live)).unwrap_or(&[]),
    )?;
    let mut arg = [0u8; sk::REWRAP_ARG_LEN];
    #[expect(clippy::cast_possible_truncation, reason = "ENVELOPE_LEN is 260")]
    sk::write_rewrap_arg(
        &auth,
        order.recipient,
        order.envelope,
        envelope.as_mut_ptr() as u64,
        sk::ENVELOPE_LEN as u32,
        &mut arg,
    )?;
    let rc = (sys.provider_call)(
        s.handle,
        key_vault::SHARE_REWRAP,
        arg.as_mut_ptr(),
        arg.len(),
    );
    let at = key_vault::share::rewrap::OUT_LEN;
    let written = u32::from_le_bytes([arg[at], arg[at + 1], arg[at + 2], arg[at + 3]]);
    if rc < 0 || written as usize != sk::ENVELOPE_LEN {
        return Err(Refusal::CustodianRefused);
    }
    // Remembered only once released: a refused order drew nothing.
    let slot = usize::from(s.seen_next);
    if let Some(entry) = s.seen.get_mut(slot) {
        *entry = auth.anti_replay;
    }
    s.seen_next = if slot + 1 >= MAX_SEEN {
        0
    } else {
        s.seen_next + 1
    };
    if live < MAX_SEEN {
        s.seen_live += 1;
    }
    Ok(())
}

/// Record an erasure the issuer signed, and confirm it.
///
/// # Safety
///
/// As `open_recovery_key`.
unsafe fn handle_erase(s: &mut ModuleState, sys: &SyscallTable, payload: &[u8]) {
    let Some(order) = svc::read_erase_order(payload) else {
        return;
    };
    if order.custodian != s.index {
        return;
    }
    let outcome = if s.issuer_key_len == 0 {
        Err(Refusal::NoIssuerKey)
    } else {
        sk::admit_erase(
            verify_suite,
            s.issuer_suite,
            s.issuer_key
                .get(..usize::from(s.issuer_key_len))
                .unwrap_or(&[]),
            order.record,
        )
        .map(|b| remember_erased(s, b.resource))
    };
    if outcome.is_err() {
        s.refused = s.refused.saturating_add(1);
    }
    let mut frame = [0u8; 32];
    if let Some(n) = svc::write_erase_result(order.corr, s.index, outcome.err(), &mut frame) {
        // As `handle_order`: an already-enveloped frame, written raw.
        let _ = (sys.channel_write)(s.out_results, frame.as_ptr(), n);
    }
}

/// Add a resource to the erased list, once.
fn remember_erased(s: &mut ModuleState, resource: [u8; 16]) {
    let live = usize::from(s.erased_live);
    if s.erased.get(..live).unwrap_or(&[]).contains(&resource) {
        return;
    }
    let slot = usize::from(s.erased_next);
    if let Some(entry) = s.erased.get_mut(slot) {
        *entry = resource;
    }
    s.erased_next = if slot + 1 >= MAX_ERASED {
        0
    } else {
        s.erased_next + 1
    };
    if live < MAX_ERASED {
        s.erased_live += 1;
    }
}

/// Answer this custodian's recovery public key: `[corr u32][custodian u8]`
/// in, `[corr][custodian][status][public f8]` out.
///
/// # Safety
///
/// As `open_recovery_key`.
unsafe fn answer_key(s: &mut ModuleState, sys: &SyscallTable, payload: &[u8]) {
    let mut r = sk::Reader::new(payload);
    let (Some(corr), Some(custodian)) = (r.u32(), r.u8()) else {
        return;
    };
    if custodian != s.index {
        return;
    }
    let mut body = [0u8; 8 + sk::PUBLIC_LEN];
    let mut w = sk::Writer::new(&mut body);
    let open = s.handle >= 0;
    let ok = w.u32(corr).is_some()
        && w.u8(s.index).is_some()
        && w.u8(if open {
            svc::STATUS_OK
        } else {
            svc::STATUS_REFUSED
        })
        .is_some()
        && w.f8(if open { &s.public[..] } else { &[] }).is_some();
    if !ok {
        return;
    }
    let len = w.len();
    let _ = chan::channel_write_msg(sys, s.out_results, svc::msg::CUSTODIAN_KEY, &body[..len]);
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

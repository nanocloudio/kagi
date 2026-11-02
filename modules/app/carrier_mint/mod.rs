//! carrier_mint — mint the certificate-bound identity carriers a holder of a
//! vault-born identity presents to a Kagi relying party.
//!
//! A relying party that cannot see the caller's TLS identity — Kagi's
//! `service_dns_sign` behind Wormhole's `dns_sign_relay`, for one — admits a
//! caller on a carrier (`cert_bound_identity.rs`): an ES256 compact JWS the
//! caller signed with its leaf's own key, the leaf in `x5c`, naming that
//! relying party for at most five minutes. This module is the caller's half.
//! It writes carriers `cert_bound_identity::verify` accepts
//! (`modules/common/carrier_mint.rs` writes them; the verifier's bounds are
//! restated there) and keeps its consumer stocked.
//!
//! **Its own key, certified the way Fluxor's `tls` is.** Vault keys are
//! namespaced by module type and owner-only, so a minter cannot sign with
//! another module's key. It holds its own: `identity_label` names a P-256 key
//! the vault opens, or generates the first time (`OPEN_OR_GENERATE`,
//! `SIGN | EXPORT_PUBLIC | PERSIST`), whose private half never leaves it. The
//! certificate cannot be in the graph, because the key did not exist when
//! the graph was built, so the module asks for one on the same seam `tls`
//! uses:
//!
//! ```text
//! identity_req  out[1]  [0x5B][len u16 LE = 65][SEC1 point]
//!                       every second until a chain is taken, then again
//!                       once two thirds of its lifetime have passed
//! identity_cert in[0]   [0x5C][len u16 LE][leaf DER ‖ issuer DER ‖ …]
//! ```
//!
//! A chain is taken only when its leaf parses, is a P-256 leaf that
//! certifies THIS key, and names a SPIFFE URI within the verifier's bounds
//! (and, with `spiffe` set, that one); any other is dropped and counted. The
//! leaf's issuer is not checked here — the relying party checks the leaf
//! against its own anchor, and the minter presents nothing it could not
//! prove possession of.
//!
//! **Supply.** One carrier as soon as a chain is taken, then one every
//! `period_ms` while certified, each on `carrier_out` as `[len u16 LE]
//! [compact JWS]` (at most 4608 bytes). Each is single use (the relying
//! party remembers its `jti`), lives `lifetime_s` (never past the leaf's
//! notAfter) and is never re-sent: a carrier the channel would not take is
//! retried until half its life is gone, then dropped and replaced. With
//! the defaults (60 s, 15 s) four live carriers are in flight, which is what
//! `dns_sign_relay` holds.
//!
//! **Time.** `iat` and `exp` are statements about wall-clock time, so a
//! carrier is minted only under a trusted clock (`dev_trusted_unix`,
//! `time_policy::Decision::CredentialWindow`) and only inside the leaf's
//! window. Without one, nothing is minted (`no_clock`), never a carrier
//! stamped 1970.
//!
//! Params: `identity_label` (1, required, ≤ 64 bytes), `audience` (2,
//! required: the relying party's `audience`), `lifetime_s` (3, 1..=300,
//! default 60), `period_ms` (4, 1000..=300000, default 15000), `spiffe` (5,
//! optional: the one SAN a taken leaf must name).

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

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/b64.rs"]
mod b64;
#[path = "../../common/carrier_mint.rs"]
mod carrier_mint;
#[path = "../../common/issuer_key.rs"]
mod issuer_key;
#[path = "../../../target/fluxor/fluxor-abi/sdk/contracts/key_vault.rs"]
mod key_vault;
#[path = "../../common/time_policy.rs"]
mod time_policy;
#[path = "../../common/x509_leaf.rs"]
mod x509_leaf;

use carrier_mint as cm;

const STEP_DID_WORK: i32 = 2;
/// Between certificate requests, and between vault retries after a refusal.
const REQ_PERIOD_MS: u64 = 1000;
/// Between vault retries while its store is not yet readable.
const OPEN_RETRY_MS: u64 = 100;
/// Between mint attempts while no trusted clock answers.
const CLOCK_RETRY_MS: u64 = 1000;
const LABEL_MAX: usize = 64;
/// One `identity_cert` frame: a leaf and its issuer, as `tls` takes them.
const INBOX: usize = 4096;

const ST_OPENING: u8 = 0;
const ST_UNCERTIFIED: u8 = 1;
const ST_CERTIFIED: u8 = 2;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_cert: i32,
    out_carrier: i32,
    out_req: i32,

    label: [u8; LABEL_MAX],
    label_len: u8,
    label_overflow: u8,
    audience: [u8; cm::AUDIENCE_MAX],
    audience_len: u8,
    audience_bad: u8,
    expect: [u8; cm::SPIFFE_MAX],
    expect_len: u8,
    expect_bad: u8,
    lifetime_s: u32,
    period_ms: u32,

    state: u8,
    /// The vault refusal was said once.
    said_refused: u8,
    /// The missing clock was said once.
    said_clock: u8,
    key: issuer_key::IssuerKey,
    point: [u8; cm::POINT_LEN],
    /// `dev_millis` at which the next open / request is due.
    next_at: u64,
    /// `dev_millis` after which the held certificate is renewed.
    renew_at: u64,
    /// `dev_millis` at which the next carrier is due.
    mint_at: u64,

    leaf: [u8; cm::LEAF_MAX],
    leaf_len: u16,
    spiffe: [u8; cm::SPIFFE_MAX],
    spiffe_len: u8,
    not_before: u64,
    not_after: u64,

    /// One carrier waiting for `carrier_out`: `[len u16 LE][JWS]`.
    pending: [u8; 2 + cm::CARRIER_MAX],
    pending_len: u16,
    /// `dev_millis` after which a waiting carrier is stale.
    pending_stale_at: u64,

    json: [u8; cm::SCRATCH],
    sign_scratch: [u8; 32 + issuer_key::SIGN_SCRATCH_OVERHEAD],
    inbox: [u8; 3 + INBOX],

    minted: u32,
    chains_taken: u32,
    chains_refused: u32,
    no_clock: u32,
    outside_window: u32,
    stale: u32,
    sign_failed: u32,
}

/// Copy a string param into `field`; true when it did not fit.
///
/// # Safety
///
/// `d` is valid for reads of `len` bytes (the TLV walk's guarantee).
unsafe fn take_str(field: &mut [u8], d: *const u8, len: usize, out_len: &mut u8) -> bool {
    let t = core::slice::from_raw_parts(d, len);
    let t = t.split(|&b| b == 0).next().unwrap_or(&[]);
    if t.len() > field.len() || t.len() > usize::from(u8::MAX) {
        return true;
    }
    field[..t.len()].copy_from_slice(t);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by u8::MAX above")]
    {
        *out_len = t.len() as u8;
    }
    false
}

define_params! {
    ModuleState;

    1, identity_label, str, 0 => |s, d, len| {
        s.label_overflow = u8::from(take_str(&mut s.label, d, len, &mut s.label_len));
    };
    2, audience, str, 0 => |s, d, len| {
        s.audience_bad = u8::from(take_str(&mut s.audience, d, len, &mut s.audience_len));
    };
    3, lifetime_s, u32, 60 => |s, d, len| { s.lifetime_s = p_u32(d, len, 0, 60); };
    4, period_ms, u32, 15000 => |s, d, len| { s.period_ms = p_u32(d, len, 0, 15000); };
    5, spiffe, str, 0 => |s, d, len| {
        s.expect_bad = u8::from(take_str(&mut s.expect, d, len, &mut s.expect_len));
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

/// Refuse construction with `line`.
///
/// # Safety
///
/// `sys` is the live syscall table handed to `module_new`.
unsafe fn refuse(sys: &SyscallTable, line: &[u8]) -> i32 {
    dev_log(sys, 1, line.as_ptr(), line.len());
    -3
}

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
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs), the
    // kernel passes a valid, exclusively-borrowed `state` of at least
    // `module_state_size()` bytes and a live syscall table.
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
        s.in_cert = in_chan;
        s.out_carrier = out_chan;
        s.out_req = dev_channel_port(sys, 1, 1);
        s.label = [0; LABEL_MAX];
        s.label_len = 0;
        s.label_overflow = 0;
        s.audience = [0; cm::AUDIENCE_MAX];
        s.audience_len = 0;
        s.audience_bad = 0;
        s.expect = [0; cm::SPIFFE_MAX];
        s.expect_len = 0;
        s.expect_bad = 0;
        s.lifetime_s = 60;
        s.period_ms = 15_000;
        s.state = ST_OPENING;
        s.said_refused = 0;
        s.said_clock = 0;
        s.key = issuer_key::IssuerKey::empty();
        s.point = [0; cm::POINT_LEN];
        s.next_at = 0;
        s.renew_at = 0;
        s.mint_at = 0;
        s.leaf_len = 0;
        s.spiffe_len = 0;
        s.not_before = 0;
        s.not_after = 0;
        s.pending_len = 0;
        s.pending_stale_at = 0;
        s.minted = 0;
        s.chains_taken = 0;
        s.chains_refused = 0;
        s.no_clock = 0;
        s.outside_window = 0;
        s.stale = 0;
        s.sign_failed = 0;

        parse_tlv(s, params, params_len);

        if s.label_len == 0 || s.label_overflow != 0 {
            return refuse(
                sys,
                b"[carrier-mint] identity_label (1..=64 bytes) is required",
            );
        }
        let audience = &s.audience[..usize::from(s.audience_len)];
        if s.audience_bad != 0 || !cm::audience_ok(audience) {
            return refuse(
                sys,
                b"[carrier-mint] audience (printable, no quote or backslash, <= 128 bytes) is required",
            );
        }
        if s.expect_bad != 0 {
            return refuse(
                sys,
                b"[carrier-mint] spiffe exceeds the carrier's 96-byte bound",
            );
        }
        if s.lifetime_s == 0 || u64::from(s.lifetime_s) > cm::LIFETIME_MAX_SECS {
            return refuse(sys, b"[carrier-mint] lifetime_s must be 1..=300");
        }
        if !(1000..=300_000).contains(&s.period_ms) {
            return refuse(sys, b"[carrier-mint] period_ms must be 1000..=300000");
        }
        if (sys.provider_call)(-1, key_vault::PROBE, core::ptr::null_mut(), 0) != 1 {
            return refuse(
                sys,
                b"[carrier-mint] refusing to construct: the identity needs a key vault, and this target has none",
            );
        }
        if s.in_cert < 0 || s.out_req < 0 || s.out_carrier < 0 {
            return refuse(
                sys,
                b"[carrier-mint] refusing to construct: identity_cert, identity_req and carrier_out must be wired",
            );
        }
        let line = b"[carrier-mint] init";
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
        let now = dev_millis(sys);
        let mut did = false;
        if s.state == ST_OPENING {
            if now < s.next_at || !open(s, sys, now) {
                return 0;
            }
            did = true;
        }
        did |= take_chain(s, sys, now);
        did |= request(s, sys, now);
        did |= mint(s, sys, now);
        did |= flush(s, sys, now);
        if did {
            STEP_DID_WORK
        } else {
            0
        }
    }
}

/// `OPEN_OR_GENERATE` the label's P-256 key. True once open.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live syscall table.
unsafe fn open(s: &mut ModuleState, sys: &SyscallTable, now: u64) -> bool {
    let label = &s.label[..usize::from(s.label_len)];
    let rc = s.key.open_status(sys, auth_wire::suite::ES256, label);
    if rc == E_AGAIN {
        // The vault's store is not readable yet. Nothing is generated in
        // the meantime: a key generated now would be replaced by the
        // persisted one, and every certificate for it lost.
        s.next_at = now + OPEN_RETRY_MS;
        return false;
    }
    let public = s.key.public_key();
    if rc != 0 || public.len() != cm::POINT_LEN || public.first() != Some(&0x04) {
        s.key.close(sys);
        if s.said_refused == 0 {
            s.said_refused = 1;
            let msg = b"[carrier-mint] the vault refused the label's P-256 key";
            dev_log(sys, 1, msg.as_ptr(), msg.len());
        }
        s.next_at = now + REQ_PERIOD_MS;
        return false;
    }
    s.point.copy_from_slice(public);
    s.state = ST_UNCERTIFIED;
    s.next_at = now;
    let msg = b"[carrier-mint] identity key open; requesting a certificate";
    dev_log(sys, 3, msg.as_ptr(), msg.len());
    true
}

/// Take a chain off `identity_cert` when it certifies this key.
///
/// # Safety
///
/// As `open`.
unsafe fn take_chain(s: &mut ModuleState, sys: &SyscallTable, now: u64) -> bool {
    let (msg_type, copied, pl) =
        net_read_frame_sized(sys, s.in_cert, s.inbox.as_mut_ptr(), s.inbox.len());
    if msg_type == 0 {
        return false;
    }
    if msg_type != cm::MSG_IDENTITY_CERT || copied != pl || pl == 0 || s.state == ST_OPENING {
        s.chains_refused = s.chains_refused.wrapping_add(1);
        return true;
    }
    let taken = cm::take_chain(
        &s.inbox[3..3 + pl],
        &s.point,
        &s.expect[..usize::from(s.expect_len)],
    );
    let Ok(taken) = taken else {
        s.chains_refused = s.chains_refused.wrapping_add(1);
        let msg = b"[carrier-mint] dropped a chain that does not certify this key's identity";
        dev_log(sys, 1, msg.as_ptr(), msg.len());
        return true;
    };
    let (not_before, not_after) = (taken.not_before, taken.not_after);
    let leaf_len = taken.leaf.len();
    let spiffe_len = taken.spiffe.len();
    let mut leaf = [0u8; cm::LEAF_MAX];
    leaf[..leaf_len].copy_from_slice(taken.leaf);
    let mut spiffe = [0u8; cm::SPIFFE_MAX];
    spiffe[..spiffe_len].copy_from_slice(taken.spiffe);
    s.leaf = leaf;
    s.spiffe = spiffe;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by LEAF_MAX and SPIFFE_MAX"
    )]
    {
        s.leaf_len = leaf_len as u16;
        s.spiffe_len = spiffe_len as u8;
    }
    s.not_before = not_before;
    s.not_after = not_after;
    s.state = ST_CERTIFIED;
    // Two thirds of its lifetime, measured from now on the monotonic clock:
    // the renewal needs no trusted clock to be asked for.
    s.renew_at = now.saturating_add(cm::renew_after_ms(not_before, not_after));
    s.next_at = now;
    // The first carrier under it goes out at once.
    s.mint_at = now;
    s.chains_taken = s.chains_taken.wrapping_add(1);
    let msg = b"[carrier-mint] identity certified";
    dev_log(sys, 3, msg.as_ptr(), msg.len());
    true
}

/// Ask for a certificate when one is due.
///
/// # Safety
///
/// As `open`.
unsafe fn request(s: &mut ModuleState, sys: &SyscallTable, now: u64) -> bool {
    let due = match s.state {
        ST_UNCERTIFIED => true,
        ST_CERTIFIED => now >= s.renew_at,
        _ => false,
    };
    if !due || now < s.next_at {
        return false;
    }
    let frame = cm::identity_req(&s.point);
    #[expect(clippy::cast_possible_wrap, reason = "68 bytes")]
    let whole = frame.len() as i32;
    if (sys.channel_write)(s.out_req, frame.as_ptr(), frame.len()) == whole {
        s.next_at = now + REQ_PERIOD_MS;
        return true;
    }
    false
}

/// Mint the next carrier into `pending` when one is due.
///
/// # Safety
///
/// As `open`.
unsafe fn mint(s: &mut ModuleState, sys: &SyscallTable, now: u64) -> bool {
    if s.state != ST_CERTIFIED || s.pending_len != 0 || now < s.mint_at {
        return false;
    }
    let obs = dev_trusted_unix(sys);
    let Some(unix) = time_policy::now_for(time_policy::Decision::CredentialWindow, &obs) else {
        s.no_clock = s.no_clock.wrapping_add(1);
        if s.said_clock == 0 {
            s.said_clock = 1;
            let msg = b"[carrier-mint] no trusted clock: nothing is minted until one answers";
            dev_log(sys, 2, msg.as_ptr(), msg.len());
        }
        s.mint_at = now + CLOCK_RETRY_MS;
        return false;
    };
    s.said_clock = 0;
    let exp = unix
        .saturating_add(u64::from(s.lifetime_s))
        .min(s.not_after);
    if unix < s.not_before || exp <= unix {
        // The leaf is not live: a carrier under it would be refused. A
        // renewal is asked for at once.
        s.outside_window = s.outside_window.wrapping_add(1);
        s.renew_at = now;
        s.mint_at = now + REQ_PERIOD_MS;
        return false;
    }
    let mut jti = [0u8; cm::JTI_LEN];
    if dev_csprng_fill(sys, jti.as_mut_ptr(), jti.len()) < 0 {
        s.sign_failed = s.sign_failed.wrapping_add(1);
        s.mint_at = now + REQ_PERIOD_MS;
        return false;
    }
    let claims = cm::Claims {
        spiffe: &s.spiffe[..usize::from(s.spiffe_len)],
        audience: &s.audience[..usize::from(s.audience_len)],
        iat: unix,
        exp,
        jti: &jti,
    };
    let input = cm::write_signing_input(
        &s.leaf[..usize::from(s.leaf_len)],
        &claims,
        &mut s.json,
        &mut s.pending[2..],
    );
    let Some(input_len) = input else {
        s.sign_failed = s.sign_failed.wrapping_add(1);
        s.mint_at = now + u64::from(s.period_ms);
        return false;
    };
    // ES256: the vault signs the SHA-256 of the signing input (DIGEST
    // mode), and its 64-byte low-S r‖s is the JWS segment as it stands.
    let digest = sha256(&s.pending[2..2 + input_len]);
    let mut signature = [0u8; 64];
    let signed = s
        .key
        .sign(sys, &mut s.sign_scratch, &digest, &mut signature)
        == Some(64);
    let total = if signed {
        cm::append_signature(&mut s.pending[2..], input_len, &signature)
    } else {
        None
    };
    let Some(n) = total else {
        s.sign_failed = s.sign_failed.wrapping_add(1);
        s.mint_at = now + u64::from(s.period_ms);
        return false;
    };
    #[expect(clippy::cast_possible_truncation, reason = "bounded by CARRIER_MAX")]
    {
        s.pending[..2].copy_from_slice(&(n as u16).to_le_bytes());
        s.pending_len = (2 + n) as u16;
    }
    s.pending_stale_at = now.saturating_add(u64::from(s.lifetime_s) * 500);
    s.mint_at = now + u64::from(s.period_ms);
    true
}

/// Hand the waiting carrier to `carrier_out`, or drop it once stale.
///
/// # Safety
///
/// As `open`.
unsafe fn flush(s: &mut ModuleState, sys: &SyscallTable, now: u64) -> bool {
    if s.pending_len == 0 {
        return false;
    }
    let n = usize::from(s.pending_len);
    #[expect(clippy::cast_possible_wrap, reason = "at most 4610 bytes")]
    let whole = n as i32;
    if (sys.channel_write)(s.out_carrier, s.pending.as_ptr(), n) == whole {
        s.pending_len = 0;
        s.minted = s.minted.wrapping_add(1);
        return true;
    }
    if now >= s.pending_stale_at {
        // Half its life gone waiting: a fresh one serves the consumer
        // longer than this one would.
        s.pending_len = 0;
        s.stale = s.stale.wrapping_add(1);
        s.mint_at = now;
        return true;
    }
    false
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

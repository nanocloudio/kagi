//! Token Mint — ES256 / EdDSA JWS access-token minting.
//!
//! Consumes MSG_MINT_REQ on `mint_requests` and replies MSG_MINT_RESP
//! on `tokens`. The signing key arrives on `key_material` as
//! MSG_KEY_ADD (`[alg u8][kid f8][key 32B]` — P-256 private scalar
//! big-endian for ES256, RFC 8032 seed for Ed25519); until one lands
//! every mint replies ST_NO_KEY, and requests whose `alg` doesn't match
//! the loaded key reply ST_NO_KEY too. Tokens are compact JWS built
//! from the shared `jose` fragment (byte-compatible with the host
//! issuer); both signature schemes are deterministic (RFC 6979 ECDSA /
//! RFC 8032 EdDSA), so no runtime entropy is needed.

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

// Crypto primitives (crate-root include, mirroring fluxor's tls module).
// p256's RFC 6979 nonce derivation needs hmac, which needs both hash
// widths, so the include set is sha256 + sha384 + hmac + p256.
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha384.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/hmac.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/p256.rs");
// ed25519 references Sha512 (sha384.rs) and helpers from p256.rs.
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
#[path = "../../common/key_custody.rs"]
mod key_custody;
#[path = "../../common/time_policy.rs"]
mod time_policy;

// The fluxor key_vault capability surface (opcodes / key_types). When a
// backend is present the signing key lives in it (kernel static slots on the
// software backend, a PKCS#11 token on a hardware backend) and never in this
// module; SIGN runs in the backend. See rfc_crypto_extensions.md.
#[path = "../../../target/fluxor/fluxor-abi/sdk/contracts/key_vault.rs"]
mod key_vault;

use auth_wire::{MintClaimValue, MintRequest, PayloadWriter};

/// key_vault `key_type` for a credential suite.
fn kv_key_type(suite: u16) -> u8 {
    if suite == auth_wire::suite::ED25519 {
        2 // Ed25519 seed
    } else {
        1 // P-256 scalar
    }
}

/// This deployment's posture, for the key-custody floor.
///
/// `Development` today, and that is the honest setting: kagi's own e2e
/// graphs run on a host with no HSM, and a production floor here would
/// refuse every one of them. A production deployment flips this — in the
/// same commit as wiring the vault that satisfies it, which is the point
/// at which someone is thinking about custody rather than about getting a
/// test to pass.
///
/// A constant rather than a parameter, because the permissive direction is
/// silent: a production graph that left it at `Development` would issue
/// under a software key and look exactly like one that had not.
const KEY_CUSTODY_POSTURE: key_custody::Posture = key_custody::Posture::Development;

const MAX_KID_LEN: usize = 64;
const MAX_ISSUER_LEN: usize = 64;
/// Keys held at once, across every profile.
///
/// More than one, which is the point: a rotation ADDs before it ACTIVATEs
/// and RETIREs the old key rather than removing it, so three entries for a
/// single profile is the ordinary mid-rotation state. The predecessor held
/// exactly one key and overwrote it, which made rotation an atomic swap
/// with no overlap — every credential signed under the old key stopped
/// verifying the instant the new one arrived.
const MAX_KEYS: usize = 8;

/// One key in the mint's keyset.
#[repr(C)]
#[derive(Clone, Copy)]
struct KeySlot {
    live: bool,
    issuer: [u8; MAX_ISSUER_LEN],
    issuer_len: u8,
    profile_id: u16,
    kid: [u8; MAX_KID_LEN],
    kid_len: u8,
    suite: u16,
    /// `auth_wire::key_state::*`.
    state: u8,
    generation: u32,
    activate_after_unix: u64,
    remove_after_unix: u64,
    /// The vault label this key is opened under. **Not key material** —
    /// this module never holds a private key, and there is deliberately no
    /// field it could be put in.
    label: [u8; auth_wire::MAX_KEY_LABEL],
    label_len: u8,
    /// The vault-held key itself, once opened — including the public half
    /// it exported, which this module is the only component able to learn.
    key: issuer_key::IssuerKey,
}

impl KeySlot {
    const fn empty() -> Self {
        Self {
            live: false,
            issuer: [0; MAX_ISSUER_LEN],
            issuer_len: 0,
            profile_id: 0,
            kid: [0; MAX_KID_LEN],
            kid_len: 0,
            suite: 0,
            state: auth_wire::key_state::ADDED,
            generation: 0,
            activate_after_unix: 0,
            remove_after_unix: 0,
            label: [0; auth_wire::MAX_KEY_LABEL],
            label_len: 0,
            key: issuer_key::IssuerKey::empty(),
        }
    }

    fn matches(&self, issuer: &[u8], profile_id: u16, kid: &[u8]) -> bool {
        self.live
            && self.profile_id == profile_id
            && &self.issuer[..usize::from(self.issuer_len)] == issuer
            && &self.kid[..usize::from(self.kid_len)] == kid
    }
}
/// Compact JWS output cap; also bounds the `tokens` port max_record. Sized
/// to hold a token carrying a realistic set of custom claims (W1/P1), not
/// just the fixed reserved-claim set.
const TOKEN_BUF_LEN: usize = 4096;
/// WCET bound: mint requests handled per step (one ECDSA sign each).
const MAX_REQS_PER_STEP: usize = 4;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32, // in[0]: MSG_MINT_REQ
    out_tokens: i32,  // out[0]: MSG_MINT_RESP
    in_key: i32,      // in[1]: MSG_KEY_ADD
    /// out[1]: the public half of each signing key, as a VERIFY KEY_ADD.
    out_key_announce: i32,

    /// The keyset, indexed by `(issuer, profile_id, kid)`.
    keys: [KeySlot; MAX_KEYS],

    /// True iff a key_vault backend answered `PROBE` at init — signing then
    /// goes through the vault (key never held long-term in this module).
    /// The backend's isolation tier from `key_vault::TIER`, or
    /// `TIER_NONE`. What `C5` is actually checked against: `PROBE` says a
    /// backend exists, this says what it protects against.
    vault_tier: u8,
    /// Scratch for the key_vault SIGN arg: `[len u16][pad u16][msg][sig 64]`.
    kv_arg: [u8; 4 + TOKEN_BUF_LEN + 64],

    // Metrics (names mirror manifest [observability])
    mint_ok: u32,
    mint_err: u32,
    no_key_errors: u32,
    sign_ops: u32,

    msg_buf: [u8; 4096],
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
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
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
        s.out_tokens = out_chan;
        s.in_key = dev_channel_port(sys, 0, 1);
        s.out_key_announce = dev_channel_port(sys, 1, 1);

        s.keys = [KeySlot::empty(); MAX_KEYS];
        s.mint_ok = 0;
        s.mint_err = 0;
        s.no_key_errors = 0;
        s.sign_ops = 0;

        // Probe the key_vault, and read its TIER — not just whether one
        // answered.
        //
        // `PROBE` says a backend exists. It says nothing about what that
        // backend isolates against, and this module used to stop there:
        // any backend, including the in-process software one, satisfied it.
        // `C5` is a statement about isolation, so it has to be checked
        // against the ordinal that carries isolation.
        let probe = (sys.provider_call)(-1, key_vault::PROBE, core::ptr::null_mut(), 0);
        // No backend, no mint. This used to be a soft signal selecting
        // between a vault and an in-module scalar; with the scalar gone
        // there is nothing on the other side of the branch, and a module
        // that constructs without a vault would be one that starts cleanly
        // and refuses every request — the shape that reads as a runtime
        // fault rather than a misconfiguration.
        if probe != 1 {
            dev_log(
                sys,
                1,
                b"[mint] refusing to construct: no key_vault backend".as_ptr(),
                50,
            );
            return -1;
        }
        s.vault_tier = {
            let mut tier_buf = [0u8; 4];
            let rc =
                (sys.provider_call)(-1, key_vault::TIER, tier_buf.as_mut_ptr(), tier_buf.len());
            if rc >= 0 {
                tier_buf[0]
            } else {
                // A backend that will not say what it is gets no credit for
                // being one. Reading a refusal as `SOFTWARE` would be
                // inventing the answer.
                key_custody::TIER_NONE
            }
        };

        // The custody floor for the keys this module holds.
        //
        // Refused at CONSTRUCTION, not at the first mint. A module that
        // starts and then refuses every request looks like a runtime fault;
        // one that will not start says what is wrong at the moment someone
        // can still fix it. And the failure this prevents is silent in the
        // other direction: a deployment issuing under a software key
        // believes its issuer key is protected, and nothing downstream can
        // tell — the credentials verify either way.
        if !key_custody::permits(
            key_custody::KeyRole::Issuer,
            KEY_CUSTODY_POSTURE,
            s.vault_tier,
        ) {
            let why = key_custody::refusal_text(s.vault_tier);
            dev_log(sys, 1, b"[mint] refusing to construct:".as_ptr(), 29);
            dev_log(sys, 1, why.as_ptr(), why.len());
            return -1;
        }

        let t = key_custody::tier_text(s.vault_tier);
        dev_log(sys, 3, b"[mint] init (key_vault tier=)".as_ptr(), 28);
        dev_log(sys, 3, t.as_ptr(), t.len());
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // Signing-key updates first, so a same-step mint uses the
        // latest kid/scalar.
        drain_key_material(s, sys);

        for _ in 0..MAX_REQS_PER_STEP {
            if !chan::can_read(sys, s.in_requests) {
                break;
            }
            // Every request produces exactly one reply; don't consume a
            // request we cannot answer.
            if !chan::can_write(sys, s.out_tokens) {
                break;
            }
            let (msg_type, plen) = chan::channel_read_msg(sys, s.in_requests, &mut s.msg_buf);
            if msg_type != auth_wire::MSG_MINT_REQ {
                continue;
            }
            handle_mint(s, sys, plen as usize);
        }

        0
    }
}

/// Drain `key_material`, keeping the key lifecycle into the keyset
/// (`[alg u8][kid f8][key 32B]`).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_key_material(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_key < 0 {
        return;
    }
    for _ in 0..8 {
        if !chan::can_read(sys, s.in_key) {
            break;
        }
        let mut buf = [0u8; 8192];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_key, &mut buf);
        let payload = &buf[..plen as usize];
        match msg_type {
            auth_wire::MSG_KEY_ADD => {
                if let Ok(rec) = auth_wire::KeyRecord::decode_add(payload) {
                    apply_key_add(s, sys, &rec);
                }
            }
            auth_wire::MSG_KEYSET_SNAPSHOT => {
                // A restarting mint reaches current state here. The whole
                // set replaces the whole set: applying a snapshot on top of
                // stale entries would leave a key the snapshot no longer
                // names still able to sign.
                let mut r = auth_wire::PayloadReader::new(payload);
                let Ok(count) = r.u16() else { continue };
                if usize::from(count) > MAX_KEYS {
                    continue;
                }
                let mut fresh = [KeySlot::empty(); MAX_KEYS];
                let mut ok = true;
                for slot in fresh.iter_mut().take(usize::from(count)) {
                    match auth_wire::KeyRecord::read(&mut r) {
                        Ok(rec) => {
                            if !fill_slot(slot, &rec) {
                                ok = false;
                                break;
                            }
                        }
                        Err(_) => {
                            ok = false;
                            break;
                        }
                    }
                }
                // All or nothing: a snapshot that half-decoded would leave
                // the keyset in a state neither the sender nor this module
                // believes in.
                if !ok {
                    continue;
                }
                for i in 0..MAX_KEYS {
                    destroy_slot_key(s, sys, i);
                }
                s.keys = fresh;
                // Opening runs after the table is settled, so a key that
                // will not open clears its own slot rather than leaving the
                // snapshot half-applied. The all-or-nothing rule above is
                // about DECODING: a record that decoded and then failed to
                // open is a real key the vault refused, and dropping the
                // whole snapshot for it would take out its live siblings
                // too.
                for i in 0..MAX_KEYS {
                    if s.keys[i].live && !open_slot_key(s, sys, i) {
                        s.keys[i] = KeySlot::empty();
                    }
                }
            }
            auth_wire::MSG_KEY_ACTIVATE => {
                if let Ok(kr) = auth_wire::KeyRef::decode(payload) {
                    if let Some(i) = find_slot(s, kr.issuer, kr.profile_id, kr.kid) {
                        // Exactly one active key per (issuer, profile): the
                        // previous one is retired rather than left active,
                        // or two keys would both claim to be the one new
                        // credentials are signed under.
                        for j in 0..MAX_KEYS {
                            if j != i
                                && s.keys[j].live
                                && s.keys[j].profile_id == s.keys[i].profile_id
                                && s.keys[j].state == auth_wire::key_state::ACTIVE
                            {
                                s.keys[j].state = auth_wire::key_state::RETIRED;
                            }
                        }
                        s.keys[i].state = auth_wire::key_state::ACTIVE;
                        #[expect(
                            clippy::cast_possible_truncation,
                            reason = "a lifecycle generation is a u32 on the wire"
                        )]
                        {
                            s.keys[i].generation = kr.arg as u32;
                        }
                    }
                }
            }
            auth_wire::MSG_KEY_RETIRE => {
                if let Ok(kr) = auth_wire::KeyRef::decode(payload) {
                    if let Some(i) = find_slot(s, kr.issuer, kr.profile_id, kr.kid) {
                        s.keys[i].state = auth_wire::key_state::RETIRED;
                        s.keys[i].remove_after_unix = kr.arg;
                    }
                }
            }
            auth_wire::MSG_KEY_REMOVE => {
                if let Ok(kr) = auth_wire::KeyRef::decode(payload) {
                    if let Some(i) = find_slot(s, kr.issuer, kr.profile_id, kr.kid) {
                        // This is the compromise path, so the vault slot
                        // goes too — leaving it would keep the key signable
                        // by anything still holding the handle.
                        destroy_slot_key(s, sys, i);
                        s.keys[i] = KeySlot::empty();
                    }
                }
            }
            _ => {}
        }
    }
}

fn find_slot(s: &ModuleState, issuer: &[u8], profile_id: u16, kid: &[u8]) -> Option<usize> {
    for (i, k) in s.keys.iter().enumerate() {
        if k.matches(issuer, profile_id, kid) {
            return Some(i);
        }
    }
    None
}

/// Copy a decoded record into a slot. Returns false if it does not fit or
/// names something this build cannot sign with.
fn fill_slot(slot: &mut KeySlot, rec: &auth_wire::KeyRecord<'_>) -> bool {
    if rec.key_use != auth_wire::key_use::SIGN {
        return false;
    }
    // A suite this build cannot sign in is refused at load rather than at
    // the first mint: a key that is present but unusable looks like a
    // configured issuer right up until someone asks it for a credential.
    if !auth_wire::suite::is_implemented(rec.suite) {
        return false;
    }
    if rec.issuer.is_empty()
        || rec.issuer.len() > MAX_ISSUER_LEN
        || rec.kid.is_empty()
        || rec.kid.len() > MAX_KID_LEN
        || rec.key_ref.is_empty()
        || rec.key_ref.len() > auth_wire::MAX_KEY_LABEL
    {
        return false;
    }
    *slot = KeySlot::empty();
    slot.live = true;
    slot.issuer[..rec.issuer.len()].copy_from_slice(rec.issuer);
    slot.kid[..rec.kid.len()].copy_from_slice(rec.kid);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "both lengths bounded immediately above"
    )]
    {
        slot.issuer_len = rec.issuer.len() as u8;
        slot.kid_len = rec.kid.len() as u8;
    }
    slot.profile_id = rec.profile_id;
    slot.suite = rec.suite;
    slot.state = rec.state;
    slot.generation = rec.generation;
    slot.activate_after_unix = rec.activate_after_unix;
    slot.remove_after_unix = rec.remove_after_unix;
    slot.label[..rec.key_ref.len()].copy_from_slice(rec.key_ref);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "label length bounded by MAX_KEY_LABEL immediately above"
    )]
    {
        slot.label_len = rec.key_ref.len() as u8;
    }
    slot.key = issuer_key::IssuerKey::empty();
    true
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a valid
/// `&SyscallTable` per the module ABI.
unsafe fn apply_key_add(s: &mut ModuleState, sys: &SyscallTable, rec: &auth_wire::KeyRecord<'_>) {
    // Re-adding an existing (issuer, profile, kid) replaces it in place, so
    // a redelivered record is idempotent rather than consuming a second slot.
    let idx = find_slot(s, rec.issuer, rec.profile_id, rec.kid)
        .or_else(|| s.keys.iter().position(|k| !k.live));
    let Some(i) = idx else {
        // A full keyset refuses the add rather than evicting: whichever key
        // it evicted would be one some live credential still needs.
        return;
    };
    destroy_slot_key(s, sys, i);
    let mut slot = KeySlot::empty();
    if !fill_slot(&mut slot, rec) {
        return;
    }
    s.keys[i] = slot;
    if !open_slot_key(s, sys, i) {
        // A key that cannot be opened is not a key. Left un-live rather
        // than kept as a configured-looking slot that refuses every mint.
        s.keys[i] = KeySlot::empty();
    }
}

/// Open slot `i`'s key in the vault under its label, generating it on the
/// first open, and announce the public half to verifiers.
///
/// `OPEN_OR_GENERATE` rather than "exists?" then "create": those two are a
/// race, and two mints starting together would both see absence, both
/// generate, and one would sign under a key nothing else trusts.
///
/// The mask is `SIGN | EXPORT_PUBLIC | PERSIST` and nothing more. An issuer
/// key signs credentials and exports its public half; it does not agree
/// keys, and its private half has no operation that returns it. Asking for
/// exactly what is used is what makes the vault's per-operation check mean
/// something — a mask of everything is a mask that refuses nothing.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a valid
/// `&SyscallTable` per the module ABI.
unsafe fn open_slot_key(s: &mut ModuleState, sys: &SyscallTable, i: usize) -> bool {
    let label_len = usize::from(s.keys[i].label_len);
    let mut label = [0u8; auth_wire::MAX_KEY_LABEL];
    label[..label_len].copy_from_slice(&s.keys[i].label[..label_len]);
    let suite = s.keys[i].suite;
    if !s.keys[i].key.open(sys, suite, &label[..label_len]) {
        return false;
    }
    announce_public_key(s, sys, i);
    true
}

/// Emit the slot's public half as a VERIFY [`auth_wire::MSG_KEY_ADD`].
///
/// **This edge exists because the operator can no longer supply it.** While
/// a signing record carried a raw private key, whoever distributed it could
/// derive the public half and hand it to the verifiers itself. A key
/// generated inside the vault has no such moment: the mint is the only
/// component that ever sees the public half, so publishing it is the mint's
/// job. One output port and an edge, rather than a second distribution
/// channel to secure — the announcement carries nothing secret, which is
/// exactly why it can travel on an ordinary lane.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a valid
/// `&SyscallTable` per the module ABI.
unsafe fn announce_public_key(s: &mut ModuleState, sys: &SyscallTable, i: usize) {
    if s.out_key_announce < 0 || !s.keys[i].key.is_open() {
        return;
    }
    let issuer_len = usize::from(s.keys[i].issuer_len);
    let kid_len = usize::from(s.keys[i].kid_len);
    let rec = auth_wire::KeyRecord {
        issuer: &s.keys[i].issuer[..issuer_len],
        profile_id: s.keys[i].profile_id,
        kid: &s.keys[i].kid[..kid_len],
        suite: s.keys[i].suite,
        state: s.keys[i].state,
        key_use: auth_wire::key_use::VERIFY,
        generation: s.keys[i].generation,
        activate_after_unix: s.keys[i].activate_after_unix,
        remove_after_unix: s.keys[i].remove_after_unix,
        key_ref: s.keys[i].key.public_key(),
    };
    let mut payload = [0u8; 512];
    let mut w = auth_wire::PayloadWriter::new(&mut payload);
    if rec.write(&mut w).is_err() {
        return;
    }
    let n = w.len();
    chan::channel_write_msg(
        sys,
        s.out_key_announce,
        auth_wire::MSG_KEY_ADD,
        &payload[..n],
    );
}

/// Release a slot's vault handle, if it has one.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a valid
/// `&SyscallTable` per the module ABI.
unsafe fn destroy_slot_key(s: &mut ModuleState, sys: &SyscallTable, i: usize) {
    s.keys[i].key.close(sys);
}

/// Handle one MSG_MINT_REQ payload sitting in `s.msg_buf[..plen]`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_mint(s: &mut ModuleState, sys: &SyscallTable, plen: usize) {
    // Layout is `[corr u32]…`; the correlation id we echo on a reply is the
    // first field, so a request too short to hold one cannot be answered.
    if plen < 4 {
        // No correlation id — nowhere to address a reply.
        return;
    }
    let corr = u32::from_le_bytes([s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3]]);

    let Ok(req) = MintRequest::decode(&s.msg_buf[..plen]) else {
        s.mint_err = s.mint_err.saturating_add(1);
        refuse(s, sys, corr, auth_wire::mint_err::MALFORMED);
        return;
    };
    if !auth_wire::suite::is_implemented(req.suite) {
        s.mint_err = s.mint_err.saturating_add(1);
        refuse(s, sys, corr, auth_wire::mint_err::UNSUPPORTED_SUITE);
        return;
    }

    // Key selection, and the reason the keyset exists. An empty `kid` asks
    // for the profile's ACTIVE key — the ordinary case, and the one that
    // lets rotation happen without every caller learning a new kid. A named
    // `kid` selects that key whatever its state, so a caller re-signing
    // under a specific key can, and so a RETIRED key is still reachable
    // until its removal deadline.
    // The `iat`/`exp` this mint stamps. A credential dated from a clock
    // that reads 0 is one no verifier will accept, and minting it anyway
    // turns a clock problem into a mystery at the relying party.
    let obs = dev_trusted_unix(sys);
    let Some(now) = time_policy::now_for(time_policy::Decision::CredentialWindow, &obs) else {
        s.mint_err = s.mint_err.saturating_add(1);
        refuse(s, sys, corr, auth_wire::mint_err::SIGN_FAILED);
        return;
    };
    let Some(slot) = select_key(s, &req, now) else {
        s.no_key_errors = s.no_key_errors.saturating_add(1);
        // "This kid is not in the keyset" and "this profile has no key at
        // all" are different operator problems, and the old ST_NO_KEY said
        // neither.
        let why = if req.kid.is_empty() {
            auth_wire::mint_err::NO_KEY
        } else {
            auth_wire::mint_err::UNKNOWN_KID
        };
        refuse(s, sys, corr, why);
        return;
    };
    if s.keys[slot].suite != req.suite {
        s.mint_err = s.mint_err.saturating_add(1);
        refuse(s, sys, corr, auth_wire::mint_err::SUITE_NOT_PERMITTED);
        return;
    }

    let iat = now;
    let exp = iat + u64::from(req.ttl_seconds);

    let mut header = [0u8; 192];
    let mut claims = [0u8; TOKEN_BUF_LEN];
    let mut token = [0u8; TOKEN_BUF_LEN];

    // Translate the request's custom claims into jose claims, borrowing the
    // value bytes straight from the decoded payload. Bounded by
    // MAX_EXTRA_CLAIMS (the wire decode already rejects a larger count).
    let mut extra = [jose::Claim {
        key: b"",
        value: jose::ClaimValue::Bool(false),
    }; jose::MAX_EXTRA_CLAIMS];
    let mut extra_len = 0usize;
    for claim in req.extra.iter() {
        if extra_len >= jose::MAX_EXTRA_CLAIMS {
            s.mint_err = s.mint_err.saturating_add(1);
            refuse(s, sys, corr, auth_wire::mint_err::MALFORMED);
            return;
        }
        extra[extra_len] = jose::Claim {
            key: claim.key,
            value: match claim.value {
                MintClaimValue::Str(v) => jose::ClaimValue::Str(v),
                MintClaimValue::U64(v) => jose::ClaimValue::U64(v),
                MintClaimValue::Bool(v) => jose::ClaimValue::Bool(v),
                MintClaimValue::Raw(v) => jose::ClaimValue::Raw(v),
            },
        };
        extra_len += 1;
    }

    let kid_bytes = s.keys[slot].kid;
    let kid = &kid_bytes[..usize::from(s.keys[slot].kid_len)];
    // The JOSE `alg` is derived from the suite, not chosen alongside it —
    // a header naming an algorithm the signature was not made with is the
    // whole class of algorithm-confusion bug.
    let jws_alg = auth_wire::suite::jose_alg(req.suite);
    let built = (|| -> Result<usize, jose::JoseError> {
        let h_len = jose::write_header(jws_alg, kid, &mut header)?;
        let access = jose::AccessClaims {
            iss: req.iss,
            sub: req.sub,
            aud: req.aud,
            scope: req.scope,
            jkt: req.jkt,
            iat,
            exp,
        };
        let c_len = jose::write_access_claims_ext(&access, &extra[..extra_len], &mut claims)?;
        jose::signing_input(&header[..h_len], &claims[..c_len], &mut token)
    })();
    let Ok(input_len) = built else {
        s.mint_err = s.mint_err.saturating_add(1);
        refuse(s, sys, corr, auth_wire::mint_err::MALFORMED);
        return;
    };

    // Raw 64-byte signatures are exactly the JWS segment form (no DER).
    // ES256 signs the SHA-256 of the signing input per JOSE; EdDSA signs the
    // input itself (RFC 8037). SIGN runs in the backend: the private key is
    // generated there and never enters this module at all.
    s.sign_ops = s.sign_ops.saturating_add(1);
    let is_eddsa = req.suite == auth_wire::suite::ED25519;
    // `IssuerKey` is `Copy`, so the key is taken out of `s.keys` before
    // `s.kv_arg` is borrowed mutably: two disjoint fields of one state.
    let key = s.keys[slot].key;
    // There is ONE signing path, and it is the vault. The predecessor kept
    // an in-module scalar as a fallback for graphs with no backend; with the
    // private key generated inside the vault there is no scalar to fall back
    // to, and a second path would have been a second place for the key to
    // be. `module_new` refuses to construct without a backend, so a handle
    // below zero here means the key failed to open, not that the platform
    // cannot sign.
    // The fragment picks RAW or DIGEST from the key's own suite; what this
    // module chooses is WHAT gets signed, which is the JOSE rule: EdDSA
    // signs the signing input itself (RFC 8037), ES256 signs its SHA-256.
    let signed: Option<[u8; 64]> = if is_eddsa {
        key.sign(sys, &mut s.kv_arg, &token[..input_len])
    } else {
        let hash = sha256(&token[..input_len]);
        key.sign(sys, &mut s.kv_arg, &hash)
    };
    let Some(sig) = signed else {
        s.mint_err = s.mint_err.saturating_add(1);
        // Signing failed with a key that IS loaded — the vault refused, or
        // the slot never opened. Reported as itself: calling it malformed
        // would send an operator to inspect a request that was fine.
        refuse(s, sys, corr, auth_wire::mint_err::SIGN_FAILED);
        return;
    };

    let Ok(total) = jose::append_signature(&mut token, input_len, &sig) else {
        s.mint_err = s.mint_err.saturating_add(1);
        refuse(s, sys, corr, auth_wire::mint_err::MALFORMED);
        return;
    };

    s.mint_ok = s.mint_ok.saturating_add(1);
    emit(
        s,
        sys,
        &auth_wire::MintResponse::inline(corr, &token[..total]),
    );
}

/// Pick the key a request will be signed under, or `None`.
///
/// An empty `kid` selects the profile's ACTIVE key; a named one selects
/// exactly that key whatever its lifecycle state. `now` is checked against
/// both deadlines, so a key that has not reached its activation time or is
/// past its removal deadline is not selectable even though it is loaded.
fn select_key(s: &ModuleState, req: &MintRequest<'_>, now: u64) -> Option<usize> {
    for (i, k) in s.keys.iter().enumerate() {
        if !k.live || k.profile_id != req.profile_id {
            continue;
        }
        if !req.iss.is_empty() && &k.issuer[..usize::from(k.issuer_len)] != req.iss {
            continue;
        }
        if k.activate_after_unix != 0 && now < k.activate_after_unix {
            continue;
        }
        if k.remove_after_unix != 0 && now >= k.remove_after_unix {
            continue;
        }
        if req.kid.is_empty() {
            if k.state == auth_wire::key_state::ACTIVE {
                return Some(i);
            }
        } else if &k.kid[..usize::from(k.kid_len)] == req.kid {
            return Some(i);
        }
    }
    None
}

/// Emit a `MSG_MINT_RESP`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit(s: &mut ModuleState, sys: &SyscallTable, resp: &auth_wire::MintResponse<'_>) {
    let mut payload = [0u8; TOKEN_BUF_LEN + 64];
    let mut w = PayloadWriter::new(&mut payload);
    let _ = w.u32(resp.correlation);
    let _ = w.u8(resp.status);
    let _ = w.u8(resp.delivery);
    let _ = w.u32(resp.required_len);
    let _ = w.field16(resp.body);
    let n = w.len();
    chan::channel_write_msg(sys, s.out_tokens, auth_wire::MSG_MINT_RESP, &payload[..n]);
}

/// Emit a refusal carrying no credential.
///
/// # Safety
///
/// As [`emit`].
unsafe fn refuse(s: &mut ModuleState, sys: &SyscallTable, corr: u32, status: u8) {
    emit(s, sys, &auth_wire::MintResponse::refused(corr, status, 0));
}

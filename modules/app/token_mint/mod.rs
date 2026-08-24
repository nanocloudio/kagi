//! Token Mint — ES256 / EdDSA JWS access-token minting.
//!
//! Consumes MSG_MINT_REQ on `mint_requests` and replies MSG_MINT_RESP
//! on `tokens`. The signing key arrives on `key_material` as
//! MSG_MINT_KEY (`[alg u8][kid f8][key 32B]` — P-256 private scalar
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
#[path = "../../common/jose.rs"]
mod jose;

// The fluxor key_vault capability surface (opcodes / key_types). When a
// backend is present the signing key lives in it (kernel static slots on the
// software backend, a PKCS#11 token on a hardware backend) and never in this
// module; SIGN runs in the backend. See rfc_crypto_extensions.md.
#[path = "../../../target/fluxor/fluxor-abi/sdk/contracts/key_vault.rs"]
mod key_vault;

use auth_wire::{MintClaimValue, MintRequest, PayloadWriter};

/// key_vault `key_type` for the loaded algorithm.
fn kv_key_type(alg: u8) -> u8 {
    if alg == auth_wire::MINT_ALG_ED25519 {
        2 // Ed25519 seed
    } else {
        1 // P-256 scalar
    }
}

const MAX_KID_LEN: usize = 64;
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
    in_key: i32,      // in[1]: MSG_MINT_KEY

    kid: [u8; MAX_KID_LEN],
    kid_len: u8,
    /// Fallback-only private key (no key_vault backend present). ES256:
    /// P-256 scalar (BE); Ed25519: RFC 8032 seed. When the vault is used
    /// this is wiped and `kv_handle >= 0` holds the isolated key instead.
    d: [u8; 32],
    /// `auth_wire::MINT_ALG_*` of the loaded key.
    key_alg: u8,
    has_key: bool,

    /// True iff a key_vault backend answered `PROBE` at init — signing then
    /// goes through the vault (key never held long-term in this module).
    use_vault: bool,
    /// Opaque key_vault slot handle for the loaded key, or -1 when none /
    /// fallback. Never decoded; passed back to SIGN/DESTROY.
    kv_handle: i32,
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

        s.kid = [0; MAX_KID_LEN];
        s.kid_len = 0;
        s.d = [0; 32];
        s.key_alg = 0;
        s.has_key = false;
        s.mint_ok = 0;
        s.mint_err = 0;
        s.no_key_errors = 0;
        s.sign_ops = 0;

        // Probe the key_vault capability surface. When present, signing keys
        // are custodial (stored in the backend, wiped from this module); when
        // absent, fall back to in-module signing with the delivered scalar.
        s.kv_handle = -1;
        let probe = (sys.provider_call)(-1, key_vault::PROBE, core::ptr::null_mut(), 0);
        s.use_vault = probe == 1;
        if s.use_vault {
            dev_log(sys, 3, b"[mint] init (key_vault)".as_ptr(), 23);
        } else {
            dev_log(sys, 3, b"[mint] init".as_ptr(), 11);
        }
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

/// Drain `key_material`, keeping the latest valid MSG_MINT_KEY
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
    for _ in 0..4 {
        if !chan::can_read(sys, s.in_key) {
            break;
        }
        let mut buf = [0u8; 512];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_key, &mut buf);
        if msg_type != auth_wire::MSG_MINT_KEY {
            continue;
        }
        let mut r = auth_wire::PayloadReader::new(&buf[..plen as usize]);
        let (Ok(alg), Ok(kid), Ok(d)) = (r.u8(), r.field8(), r.take(32)) else {
            continue;
        };
        if alg != auth_wire::MINT_ALG_ES256 && alg != auth_wire::MINT_ALG_ED25519 {
            continue;
        }
        if kid.is_empty() || kid.len() > MAX_KID_LEN {
            continue;
        }
        s.kid = [0; MAX_KID_LEN];
        s.kid[..kid.len()].copy_from_slice(kid);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "bounded by MAX_KID_LEN (64)"
        )]
        {
            s.kid_len = kid.len() as u8;
        }
        s.key_alg = alg;

        // Prefer the key_vault: STORE the delivered key, keep only the opaque
        // handle, and wipe every in-module copy of the scalar. This is an
        // import path (received-then-wiped, not never-present); a fresh
        // MSG_MINT_KEY destroys the prior slot first. If STORE fails, fall
        // back to holding the scalar in-module for this key.
        let stored = if s.use_vault {
            store_key_in_vault(s, sys, alg, d)
        } else {
            false
        };
        if stored {
            s.d = [0; 32]; // key lives in the vault now
            s.has_key = true;
        } else {
            s.kv_handle = -1;
            s.d.copy_from_slice(d);
            s.has_key = true;
        }
    }
}

/// STORE the delivered private key into the key_vault, replacing any prior
/// slot. Returns `true` and sets `s.kv_handle` on success.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a valid `&SyscallTable`
/// per the module ABI.
unsafe fn store_key_in_vault(s: &mut ModuleState, sys: &SyscallTable, alg: u8, d: &[u8]) -> bool {
    if d.len() != 32 {
        return false;
    }
    // Destroy the previous slot so a key rotation can't leak vault slots.
    if s.kv_handle >= 0 {
        let _ = (sys.provider_call)(s.kv_handle, key_vault::DESTROY, core::ptr::null_mut(), 0);
        s.kv_handle = -1;
    }
    // STORE arg: [key_type u8][len u8][pad u16][bytes[32]].
    let mut arg = [0u8; 4 + 32];
    arg[0] = kv_key_type(alg);
    arg[1] = 32;
    arg[4..4 + 32].copy_from_slice(d);
    let handle = (sys.provider_call)(-1, key_vault::STORE, arg.as_mut_ptr(), arg.len());
    // Wipe the transient copy of the key material in `arg`.
    for b in &mut arg[4..] {
        core::ptr::write_volatile(b, 0);
    }
    if handle >= 0 {
        s.kv_handle = handle;
        true
    } else {
        false
    }
}

/// Sign `msg[..msg_len]` with the loaded key_vault slot. `msg` is the SHA-256
/// digest for P-256 (ES256) or the raw message for Ed25519, per the contract.
/// Returns the raw 64-byte signature on success.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a valid `&SyscallTable`
/// per the module ABI; `msg` must be valid for `msg_len` bytes and not alias
/// `s.kv_arg`.
unsafe fn vault_sign(
    s: &mut ModuleState,
    sys: &SyscallTable,
    msg: *const u8,
    msg_len: usize,
) -> Option<[u8; 64]> {
    let total = 4 + msg_len + 64;
    if total > s.kv_arg.len() {
        return None;
    }
    // SIGN arg: [hash_len u16][pad u16][hash/msg bytes][sig_out 64].
    let len_u16 = u16::try_from(msg_len).ok()?;
    s.kv_arg[0..2].copy_from_slice(&len_u16.to_le_bytes());
    s.kv_arg[2] = 0;
    s.kv_arg[3] = 0;
    core::ptr::copy_nonoverlapping(msg, s.kv_arg.as_mut_ptr().add(4), msg_len);
    for b in &mut s.kv_arg[4 + msg_len..total] {
        *b = 0;
    }
    let rc = (sys.provider_call)(s.kv_handle, key_vault::SIGN, s.kv_arg.as_mut_ptr(), total);
    if rc != 0 {
        return None;
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&s.kv_arg[4 + msg_len..4 + msg_len + 64]);
    Some(sig)
}

/// Handle one MSG_MINT_REQ payload sitting in `s.msg_buf[..plen]`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_mint(s: &mut ModuleState, sys: &SyscallTable, plen: usize) {
    // Layout is `[version u8][corr u32]…`; the correlation id we echo on a
    // reply sits just past the version byte.
    if plen < 5 {
        // No correlation id — nowhere to address a reply.
        return;
    }
    let corr = u32::from_le_bytes([s.msg_buf[1], s.msg_buf[2], s.msg_buf[3], s.msg_buf[4]]);

    let Ok(req) = MintRequest::decode(&s.msg_buf[..plen]) else {
        s.mint_err = s.mint_err.saturating_add(1);
        reply(s, sys, corr, auth_wire::ST_MALFORMED, &[]);
        return;
    };
    if req.alg != auth_wire::MINT_ALG_ES256 && req.alg != auth_wire::MINT_ALG_ED25519 {
        s.mint_err = s.mint_err.saturating_add(1);
        reply(s, sys, corr, auth_wire::ST_MALFORMED, &[]);
        return;
    }
    // A key of the wrong algorithm is "no usable key", not a malformed
    // request — the right key may still arrive on `key_material`.
    if !s.has_key || s.key_alg != req.alg {
        s.no_key_errors = s.no_key_errors.saturating_add(1);
        reply(s, sys, corr, auth_wire::ST_NO_KEY, &[]);
        return;
    }

    let iat = dev_unix_millis(sys) / 1000;
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
            reply(s, sys, corr, auth_wire::ST_MALFORMED, &[]);
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

    let kid = &s.kid[..usize::from(s.kid_len)];
    let jws_alg = if req.alg == auth_wire::MINT_ALG_ED25519 {
        jose::ALG_EDDSA
    } else {
        jose::ALG_ES256
    };
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
        reply(s, sys, corr, auth_wire::ST_MALFORMED, &[]);
        return;
    };

    // Raw 64-byte signatures are exactly the JWS segment form (no DER).
    // ES256 signs the SHA-256 of the signing input per JOSE; EdDSA signs the
    // input itself (RFC 8037). When a key_vault handle is loaded, SIGN runs
    // in the backend (the private key never re-enters this module); else it
    // falls back to the in-module scalar.
    s.sign_ops = s.sign_ops.saturating_add(1);
    let is_eddsa = req.alg == auth_wire::MINT_ALG_ED25519;
    // Both arms are fallible: the vault SIGN can be refused, and
    // `ecdsa_sign` rejects a `d` outside [1, n-1] rather than signing
    // under `d mod n`. One `None` funnels into the malformed reply.
    let signed: Option<[u8; 64]> = if s.use_vault && s.kv_handle >= 0 {
        // key_vault SIGN takes the digest for P-256 (ES256) and the message
        // itself for Ed25519 (not prehashed, per the contract).
        if is_eddsa {
            vault_sign(s, sys, token.as_ptr(), input_len)
        } else {
            let hash = sha256(&token[..input_len]);
            vault_sign(s, sys, hash.as_ptr(), 32)
        }
    } else if is_eddsa {
        Some(ed25519_sign(&s.d, &token[..input_len]))
    } else {
        let hash = sha256(&token[..input_len]);
        ecdsa_sign(&s.d, &hash, &[0u8; 32])
    };
    let Some(sig) = signed else {
        s.mint_err = s.mint_err.saturating_add(1);
        reply(s, sys, corr, auth_wire::ST_MALFORMED, &[]);
        return;
    };

    let Ok(total) = jose::append_signature(&mut token, input_len, &sig) else {
        s.mint_err = s.mint_err.saturating_add(1);
        reply(s, sys, corr, auth_wire::ST_MALFORMED, &[]);
        return;
    };

    s.mint_ok = s.mint_ok.saturating_add(1);
    reply(s, sys, corr, auth_wire::ST_OK, &token[..total]);
}

/// Emit MSG_MINT_RESP = `[corr u32][status u8][token f16]`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn reply(s: &mut ModuleState, sys: &SyscallTable, corr: u32, status: u8, token: &[u8]) {
    let mut payload = [0u8; TOKEN_BUF_LEN + 16];
    let mut w = PayloadWriter::new(&mut payload);
    let _ = w.u32(corr);
    let _ = w.u8(status);
    let _ = w.field16(token);
    let n = w.len();
    chan::channel_write_msg(sys, s.out_tokens, auth_wire::MSG_MINT_RESP, &payload[..n]);
}

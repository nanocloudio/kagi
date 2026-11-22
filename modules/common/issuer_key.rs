//! An issuer's signing key, held as a **vault label** rather than as key
//! material.
//!
//! Every kagi module that signs with an issuer key does the same three
//! things: open a labelled key in the vault, keep the exported public half
//! so verifiers can be told what it is, and sign through the backend. This
//! is that, once, so the four signing modules share one implementation
//! rather than four that drift.
//!
//! # Why a label and not a key
//!
//! A raw private scalar on the key-distribution wire makes distribution and
//! COMPROMISE the same operation: whoever can reach the control plane hands
//! an issuer a signing key of their choosing, and whoever can observe that
//! channel holds the issuer's key.
//!
//! A label removes the material from the wire entirely. The control plane
//! can ask that a key EXIST; it cannot supply one and cannot learn one. The
//! private half is generated inside the vault on first open and leaves it
//! only as signatures.
//!
//! What makes a label sufficient is that a labelled key survives a
//! **process** restart. Without that, the same key across a restart could
//! only be had by putting it on the wire — and an issuer whose key changes
//! at every restart invalidates every credential it ever issued.
//!
//! # Why the public half is carried here
//!
//! With the key generated inside the vault, the operator distributing the
//! signing record never sees the public half either. The signing module is
//! the only component that does, so announcing it becomes the signing
//! module's job — and it needs somewhere to hold it until it can.

#![allow(
    dead_code,
    reason = "one fragment serves four modules; each uses the part it needs"
)]

/// Longest public key an implemented suite exports: an uncompressed P-256
/// point. Ed25519's is 32, so one bound covers both.
pub const MAX_ISSUER_PUBKEY: usize = auth_wire::suite::MAX_IMPLEMENTED_PUBLIC_KEY_LEN;

use crate::abi::SyscallTable;
use crate::auth_wire;
use crate::key_vault;
use crate::E_INVAL;

/// Scratch an [`IssuerKey::sign`] call needs BEYOND the signing input: the
/// vault signs in place, so the scratch holds the input and then the
/// signature written over it, and the widest signature bounds what the
/// input alone does not.
///
/// The caller supplies the buffer rather than this fragment putting one on
/// the stack: these are PIC modules, and a signing input can be a whole
/// TBSCertificate. A module that already owns a work buffer lends it.
pub const SIGN_SCRATCH_OVERHEAD: usize = auth_wire::suite::MAX_IMPLEMENTED_SIGNATURE_LEN;

/// Most identical `SIGN` calls one signature is given before it is refused:
/// far above what a resumable P-256 or ML-DSA job takes on any core, so it
/// bounds only a vault that never finishes.
const SIGN_CALLS_MAX: usize = 1024;

/// The custody the vault reads out (`key_vault::CUSTODY`), or `None`
/// when it will not say. A vault that will not say what it is gets no
/// credit for being one: reading a refusal as `CUSTODY_SOFTWARE` would be
/// inventing the answer.
///
/// # Safety
///
/// `sys` must be a valid syscall table per the module ABI.
pub unsafe fn vault_custody(sys: &SyscallTable) -> Option<u8> {
    let mut custody = [0u8; key_vault::custody_arg::ARG_LEN];
    let rc = (sys.provider_call)(
        -1,
        key_vault::CUSTODY,
        custody.as_mut_ptr(),
        custody.len(),
        core::ptr::null_mut(),
        0,
    );
    if rc == 1 {
        Some(custody[0])
    } else {
        None
    }
}

/// A signing key that lives in the vault.
///
/// There is deliberately no field a private key could be put in.
#[derive(Clone, Copy)]
pub struct IssuerKey {
    label: [u8; auth_wire::MAX_KEY_LABEL],
    label_len: u8,
    pub_key: [u8; MAX_ISSUER_PUBKEY],
    /// A `u16`: an ML-DSA-87 public key is 2592 bytes, and a `u8` would
    /// keep only its low byte of length, which reads as a short key
    /// rather than as an error.
    pub_len: u16,
    /// Opaque vault handle, or -1 when no key is open. Never decoded.
    handle: i32,
    suite: u16,
}

/// The key-vault suite a kagi CREDENTIAL suite is custodied under.
///
/// The one place the two registries meet, with both in view. They are
/// different registries — kagi's names what a JWS is signed with,
/// fluxor's what a vault slot holds — and where their ids coincide it is
/// coincidence rather than contract, so nothing else may assume it.
///
/// A suite with no custody equivalent maps to `NONE`, which the vault
/// refuses. Defaulting instead would open a key of one algorithm under
/// the label meant for another, and the label is what survives a
/// restart.
const fn vault_suite(credential_suite: u16) -> u16 {
    match credential_suite {
        auth_wire::suite::ES256 => key_vault::suite::P256,
        auth_wire::suite::ED25519 => key_vault::suite::ED25519,
        auth_wire::suite::ES384 => key_vault::suite::P384,
        auth_wire::suite::ML_DSA_44 => key_vault::suite::ML_DSA_44,
        auth_wire::suite::ML_DSA_65 => key_vault::suite::ML_DSA_65,
        auth_wire::suite::ML_DSA_87 => key_vault::suite::ML_DSA_87,
        _ => key_vault::suite::NONE,
    }
}

impl IssuerKey {
    pub const fn empty() -> Self {
        Self {
            label: [0; auth_wire::MAX_KEY_LABEL],
            label_len: 0,
            pub_key: [0; MAX_ISSUER_PUBKEY],
            pub_len: 0,
            handle: -1,
            suite: 0,
        }
    }

    pub fn is_open(&self) -> bool {
        self.handle >= 0 && self.pub_len > 0
    }

    pub fn suite(&self) -> u16 {
        self.suite
    }

    /// The exported public half, empty when no key is open.
    pub fn public_key(&self) -> &[u8] {
        &self.pub_key[..usize::from(self.pub_len)]
    }

    pub fn label(&self) -> &[u8] {
        &self.label[..usize::from(self.label_len)]
    }

    /// Open `label` in the vault, generating the key on the first open.
    ///
    /// `OPEN_OR_GENERATE` rather than "exists?" then "create": those two are
    /// a race, and two issuers starting together would both see absence,
    /// both generate, and one would sign under a key nothing else trusts.
    ///
    /// The mask is `SIGN | EXPORT_PUBLIC | PERSIST` and nothing more. An
    /// issuer key signs and exports its public half; it does not agree keys,
    /// and its private half has no operation that returns it. Asking for
    /// exactly what is used is what makes the vault's per-operation check
    /// mean something — a mask of everything refuses nothing.
    ///
    /// # Safety
    ///
    /// `sys` must be a valid syscall table per the module ABI.
    pub unsafe fn open(&mut self, sys: &SyscallTable, suite: u16, label: &[u8]) -> bool {
        self.open_status(sys, suite, label) == 0
    }

    /// As [`open`](Self::open), with the vault's answer: 0 when the key is
    /// open; `E_AGAIN` when the vault cannot answer yet — its persistent
    /// store is not ready, and a key that may already exist there must not
    /// be generated afresh — so the same open is to be asked again; any
    /// other negative errno when it is refused. A caller that opens on a
    /// record it reads once must keep what it needs to ask again on
    /// `E_AGAIN`, or the key never opens.
    ///
    /// # Safety
    ///
    /// As `open`.
    pub unsafe fn open_status(&mut self, sys: &SyscallTable, suite: u16, label: &[u8]) -> i32 {
        if label.is_empty() || label.len() > auth_wire::MAX_KEY_LABEL {
            return E_INVAL;
        }
        const USAGE: u32 =
            key_vault::usage::SIGN | key_vault::usage::EXPORT_PUBLIC | key_vault::usage::PERSIST;
        let vault = vault_suite(suite);
        if vault == key_vault::suite::NONE {
            return E_INVAL;
        }
        let mut arg = [0u8; key_vault::open::MAX_ARG];
        let Some(arg_len) = key_vault::open::encode(
            &mut arg,
            &key_vault::open::Request {
                suite: vault,
                usage: USAGE,
                flags: 0,
                label,
            },
        ) else {
            return E_INVAL;
        };
        let mut pub_out = [0u8; MAX_ISSUER_PUBKEY];
        let handle = (sys.provider_call)(
            -1,
            key_vault::OPEN_OR_GENERATE,
            arg.as_mut_ptr(),
            arg_len,
            pub_out.as_mut_ptr(),
            pub_out.len(),
        );
        if handle < 0 {
            return handle;
        }
        let pub_len = key_vault::open::len(&arg[..arg_len]).unwrap_or(0);
        if pub_len == 0 || pub_len > MAX_ISSUER_PUBKEY {
            // A key that opened but exported nothing cannot be announced,
            // and a key verifiers never learn signs credentials nobody can
            // check. Released rather than kept: a half-open key is the state
            // that looks configured and is not.
            let _ = (sys.provider_call)(
                handle,
                key_vault::DESTROY,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                0,
            );
            return E_INVAL;
        }
        self.handle = handle;
        self.suite = suite;
        self.pub_key[..pub_len].copy_from_slice(&pub_out[..pub_len]);
        self.label = [0; auth_wire::MAX_KEY_LABEL];
        self.label[..label.len()].copy_from_slice(label);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "both lengths bounded immediately above"
        )]
        {
            self.pub_len = pub_len as u16;
            self.label_len = label.len() as u8;
        }
        0
    }

    /// Sign `input` in the vault, returning the raw 64-byte signature.
    ///
    /// `input` is what the SUITE signs, which is not the same thing for
    /// both: the SHA-256 digest for ES256 and the message itself for
    /// Ed25519, per RFC 8037 and the vault contract. The mode is derived
    /// from the open key's suite rather than taken as a parameter — it used
    /// to be inferred from the key type with the wire saying nothing, and a
    /// caller handing a P-256 slot a whole message got a valid signature
    /// over the wrong thing.
    ///
    /// `scratch` must hold `input.len()` and the suite's signature:
    /// `input.len() + SIGN_SCRATCH_OVERHEAD` always does.
    ///
    /// # Safety
    ///
    /// `sys` must be a valid syscall table per the module ABI, and `scratch`
    /// must not alias `input`.
    pub unsafe fn sign(
        &self,
        sys: &SyscallTable,
        scratch: &mut [u8],
        input: &[u8],
        sig_out: &mut [u8],
    ) -> Option<usize> {
        if self.handle < 0 {
            return None;
        }
        // The length this suite signs in, from the registry. Checked
        // against what the vault actually wrote below, so a backend that
        // answered with a different length is refused rather than
        // producing a signature nothing verifies.
        let want = auth_wire::suite::max_signature_len(self.suite);
        if want == 0 || sig_out.len() < want {
            return None;
        }
        let total = input.len().max(want);
        if scratch.len() < total || input.len() > u32::MAX as usize {
            return None;
        }
        // What the bytes ARE, which is a property of the algorithm and not
        // of the caller: ECDSA signs a digest, while Ed25519 and the pure
        // FIPS 204 variant both sign the whole message.
        let mode = match self.suite {
            auth_wire::suite::ED25519
            | auth_wire::suite::ML_DSA_44
            | auth_wire::suite::ML_DSA_65
            | auth_wire::suite::ML_DSA_87 => key_vault::sign_mode::RAW,
            _ => key_vault::sign_mode::DIGEST,
        };
        #[expect(
            clippy::cast_possible_truncation,
            reason = "input length bounded against u32::MAX immediately above"
        )]
        let mut arg = key_vault::sign::encode(mode, input.len() as u32);
        // SIGN works in place: the input at the head of `scratch`, the
        // signature written over it from byte 0. A suite the vault signs as
        // a resumable job answers EAGAIN on the call that starts it and on
        // each identical call that advances it, until the one that writes
        // the signature.
        let mut rc = crate::abi::errno::EAGAIN;
        let mut calls = 0usize;
        while rc == crate::abi::errno::EAGAIN && calls < SIGN_CALLS_MAX {
            scratch[..input.len()].copy_from_slice(input);
            rc = (sys.provider_call)(
                self.handle,
                key_vault::SIGN,
                arg.as_mut_ptr(),
                arg.len(),
                scratch.as_mut_ptr(),
                total,
            );
            calls += 1;
        }
        // A signature of the wrong length is refused rather than
        // zero-padded: padding one produces a well-formed value that
        // verifies against nothing, which is the failure that gets
        // diagnosed last.
        if rc < 0 || rc as usize != want {
            return None;
        }
        sig_out[..want].copy_from_slice(&scratch[..want]);
        Some(want)
    }

    /// Release the vault handle. The key itself persists under its label —
    /// closing a handle is not destroying a key, and an issuer that erased
    /// its key on every graph reload would invalidate everything it issued.
    ///
    /// # Safety
    ///
    /// `sys` must be a valid syscall table per the module ABI.
    pub unsafe fn close(&mut self, sys: &SyscallTable) {
        if self.handle >= 0 {
            let _ = (sys.provider_call)(
                self.handle,
                key_vault::DESTROY,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                0,
            );
        }
        *self = Self::empty();
    }
}

/// The largest key record an endpoint reads off its key channel.
pub const KEY_RECORD_MAX: usize = 256;

/// One key record held for another try. An endpoint opens its key while
/// handling a record it reads once; when the vault answers `E_AGAIN` (its
/// persistent store is not ready yet) the record is kept here and handled
/// again on a later step, rather than consumed with the key never opened.
/// Later records wait behind it, so they are handled in the order sent.
#[repr(C)]
pub struct PendingRecord {
    buf: [u8; KEY_RECORD_MAX],
    len: u16,
}

impl PendingRecord {
    pub const fn empty() -> Self {
        Self {
            buf: [0; KEY_RECORD_MAX],
            len: 0,
        }
    }

    /// Is a record waiting?
    pub fn is_held(&self) -> bool {
        self.len != 0
    }

    /// Keep `payload` for another try; a record past `KEY_RECORD_MAX` is
    /// not one this endpoint reads, and is not kept.
    pub fn hold(&mut self, payload: &[u8]) {
        if payload.is_empty() || payload.len() > KEY_RECORD_MAX {
            self.len = 0;
            return;
        }
        self.buf[..payload.len()].copy_from_slice(payload);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "bounded by KEY_RECORD_MAX immediately above"
        )]
        {
            self.len = payload.len() as u16;
        }
    }

    /// Take the held record into `out`: its length, 0 when none.
    pub fn take(&mut self, out: &mut [u8; KEY_RECORD_MAX]) -> usize {
        let n = usize::from(self.len).min(KEY_RECORD_MAX);
        out[..n].copy_from_slice(&self.buf[..n]);
        self.len = 0;
        n
    }
}

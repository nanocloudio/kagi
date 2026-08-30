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

/// Scratch an [`IssuerKey::sign`] call needs BEYOND the signing input.
///
/// The caller supplies the buffer rather than this fragment putting one on
/// the stack: these are PIC modules, and a signing input can be a whole
/// TBSCertificate. A module that already owns a work buffer lends it.
pub const SIGN_SCRATCH_OVERHEAD: usize = 18;

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
        if label.is_empty() || label.len() > auth_wire::MAX_KEY_LABEL {
            return false;
        }
        const USAGE: u32 =
            key_vault::usage::SIGN | key_vault::usage::EXPORT_PUBLIC | key_vault::usage::PERSIST;
        // [suite u16][usage u32][flags u8][label_len u8][label]
        // [pub_out_ptr u64][pub_out_cap u16][pub_len_out u16]
        let mut pub_out = [0u8; MAX_ISSUER_PUBKEY];
        let mut arg = [0u8; 8 + auth_wire::MAX_KEY_LABEL + 12];
        let vault = vault_suite(suite);
        if vault == key_vault::suite::NONE {
            return false;
        }
        arg[0..2].copy_from_slice(&vault.to_le_bytes());
        arg[2..6].copy_from_slice(&USAGE.to_le_bytes());
        arg[6] = 0;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "label length bounded by MAX_KEY_LABEL immediately above"
        )]
        {
            arg[7] = label.len() as u8;
        }
        arg[8..8 + label.len()].copy_from_slice(label);
        let tail = 8 + label.len();
        let pub_ptr = pub_out.as_mut_ptr() as u64;
        arg[tail..tail + 8].copy_from_slice(&pub_ptr.to_le_bytes());
        #[expect(
            clippy::cast_possible_truncation,
            reason = "MAX_ISSUER_PUBKEY is the registry's widest key, far inside u16"
        )]
        {
            arg[tail + 8..tail + 10].copy_from_slice(&(MAX_ISSUER_PUBKEY as u16).to_le_bytes());
        }
        arg[tail + 10..tail + 12].copy_from_slice(&0u16.to_le_bytes());
        let handle =
            (sys.provider_call)(-1, key_vault::OPEN_OR_GENERATE, arg.as_mut_ptr(), tail + 12);
        if handle < 0 {
            return false;
        }
        let pub_len = usize::from(u16::from_le_bytes([arg[tail + 10], arg[tail + 11]]));
        if pub_len == 0 || pub_len > MAX_ISSUER_PUBKEY {
            // A key that opened but exported nothing cannot be announced,
            // and a key verifiers never learn signs credentials nobody can
            // check. Released rather than kept: a half-open key is the state
            // that looks configured and is not.
            let _ = (sys.provider_call)(handle, key_vault::DESTROY, core::ptr::null_mut(), 0);
            return false;
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
        true
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
    /// `scratch` must hold `input.len() + SIGN_SCRATCH_OVERHEAD`.
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
        let total = input.len().checked_add(SIGN_SCRATCH_OVERHEAD)?;
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
        let sig = &mut sig_out[..want];
        // SIGN v1: [sign_mode u8][_pad u8][input_len u32][input]
        //          [sig_out_ptr u64][sig_out_cap u16][sig_len_out u16]
        scratch[0] = mode;
        scratch[1] = 0;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "input length bounded against u32::MAX immediately above"
        )]
        {
            scratch[2..6].copy_from_slice(&(input.len() as u32).to_le_bytes());
        }
        scratch[6..6 + input.len()].copy_from_slice(input);
        let tail = 6 + input.len();
        let sig_ptr = sig.as_mut_ptr() as u64;
        scratch[tail..tail + 8].copy_from_slice(&sig_ptr.to_le_bytes());
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the registry's widest signature is 4627, far inside u16"
        )]
        {
            scratch[tail + 8..tail + 10].copy_from_slice(&(want as u16).to_le_bytes());
        }
        scratch[tail + 10..tail + 12].copy_from_slice(&0u16.to_le_bytes());
        let rc = (sys.provider_call)(self.handle, key_vault::SIGN, scratch.as_mut_ptr(), total);
        if rc < 0 {
            return None;
        }
        let sig_len = usize::from(u16::from_le_bytes([scratch[tail + 10], scratch[tail + 11]]));
        // A signature of the wrong length is refused rather than
        // zero-padded: padding one produces a well-formed value that
        // verifies against nothing, which is the failure that gets
        // diagnosed last.
        if sig_len != want {
            return None;
        }
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
            let _ = (sys.provider_call)(self.handle, key_vault::DESTROY, core::ptr::null_mut(), 0);
        }
        *self = Self::empty();
    }
}

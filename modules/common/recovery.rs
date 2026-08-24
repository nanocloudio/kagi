//! Recovery codes — the way back in when every device is gone.
//!
//! The codes are **derived, not stored**. Each is
//!
//! ```text
//! code_i = base32(HKDF-SHA256(salt = tenant_id, ikm = recovery_root,
//!                              info = "kagi-recovery-code" ‖ i)[..10])
//! ```
//!
//! so the issuer holds one root secret per tenant rather than a table of
//! hashes, and the codes for a tenant can be regenerated for display without
//! being kept anywhere.
//!
//! What *is* stored is which codes have been spent: a bitmap of consumed
//! indices, which is small, and which the caller persists alongside the
//! tenant's device set. Redeeming a code is therefore idempotent-safe — a
//! spent index never verifies again.
//!
//! Pure `no_std` fragment: HKDF is injected, every code is a fixed-width
//! buffer, and the whole redeemed-set is one `u16`. The derivation and the
//! redemption rule are the part a device and the issuer must agree on
//! exactly; how the codes are rendered for a person to read is not, and stays
//! on the host.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::ids::HkdfSha256Fn;
use crate::totp::{base32_encode, base32_encoded_len};

/// Domain separation for the derivation, so a recovery code can never
/// collide with a tenant id, a device id, or any other HKDF output kagi
/// derives from the same material.
const RECOVERY_INFO: &[u8] = b"kagi-recovery-code";

/// Raw bytes behind each code. Ten bytes is 80 bits, which base32 renders as
/// exactly 16 characters with no padding — comfortably beyond guessing, and
/// still short enough to read off paper.
pub const CODE_BYTES: usize = 10;

/// Characters in a rendered code, before any grouping is applied.
pub const CODE_LENGTH: usize = 16;

/// How many codes a tenant is issued. Ten is the common convention, and the
/// count is fixed so the bitmap that tracks them fits a `u16`.
pub const CODE_COUNT: usize = 10;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoveryError {
    EmptyRoot,
    IndexOutOfRange,
    Encoding,
}

/// Which of a tenant's recovery codes have been spent.
///
/// Persist this with the tenant's device set. It is the entire mutable state
/// of the recovery mechanism.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct RecoveryState {
    /// Bit `i` set means code `i` has been redeemed.
    spent: u16,
}

impl RecoveryState {
    /// A freshly issued set, with nothing spent.
    pub const fn new() -> Self {
        Self { spent: 0 }
    }

    /// The bitmap, for a caller that persists it.
    pub const fn bits(self) -> u16 {
        self.spent
    }

    /// A set restored from a persisted bitmap.
    pub const fn from_bits(spent: u16) -> Self {
        Self { spent }
    }

    /// Whether code `index` has been redeemed.
    pub const fn is_spent(&self, index: usize) -> bool {
        index < CODE_COUNT && (self.spent >> index) & 1 == 1
    }

    /// How many codes remain.
    pub fn remaining(&self) -> usize {
        (0..CODE_COUNT).filter(|&i| !self.is_spent(i)).count()
    }

    /// Mark a code redeemed.
    pub fn spend(&mut self, index: usize) {
        if index < CODE_COUNT {
            self.spent |= 1 << index;
        }
    }
}

/// Derive the code at `index` for a tenant, as 16 base32 characters.
pub fn derive(
    hkdf: HkdfSha256Fn,
    recovery_root: &[u8],
    tenant_id: &[u8],
    index: usize,
    out: &mut [u8; CODE_LENGTH],
) -> Result<(), RecoveryError> {
    if recovery_root.is_empty() {
        return Err(RecoveryError::EmptyRoot);
    }
    if index >= CODE_COUNT {
        return Err(RecoveryError::IndexOutOfRange);
    }

    // The index is part of the HKDF info, so each code is an independent
    // derivation: learning one reveals nothing about the others.
    let mut info = [0u8; RECOVERY_INFO.len() + 1];
    info[..RECOVERY_INFO.len()].copy_from_slice(RECOVERY_INFO);
    // `index` is bounded by CODE_COUNT, so the cast cannot truncate.
    info[RECOVERY_INFO.len()] = u8::try_from(index).unwrap_or(u8::MAX);

    let mut okm = [0u8; 32];
    hkdf(tenant_id, recovery_root, &info, &mut okm);

    let mut encoded = [0u8; 32];
    let len =
        base32_encode(&okm[..CODE_BYTES], &mut encoded).map_err(|_| RecoveryError::Encoding)?;
    if len != base32_encoded_len(CODE_BYTES) || len != CODE_LENGTH {
        return Err(RecoveryError::Encoding);
    }
    out.copy_from_slice(&encoded[..CODE_LENGTH]);
    Ok(())
}

/// Redeem a code presented by a tenant.
///
/// Returns the index that matched, with `state` updated to mark it spent, or
/// `None` when nothing matched. Every index is evaluated before returning,
/// and each comparison runs to completion, so the time taken does not reveal
/// which code was close.
///
/// `presented` is normalised first: case is folded and the grouping
/// separators and whitespace a tenant will inevitably type are removed, so a
/// correct code is never rejected for cosmetic reasons.
pub fn redeem(
    hkdf: HkdfSha256Fn,
    recovery_root: &[u8],
    tenant_id: &[u8],
    presented: &[u8],
    state: &mut RecoveryState,
) -> Result<Option<usize>, RecoveryError> {
    let mut normalised = [0u8; CODE_LENGTH];
    let Some(()) = normalise(presented, &mut normalised) else {
        return Ok(None);
    };

    let mut matched: Option<usize> = None;
    for index in 0..CODE_COUNT {
        let mut expected = [0u8; CODE_LENGTH];
        derive(hkdf, recovery_root, tenant_id, index, &mut expected)?;
        let equal = fixed_time_eq(&expected, &normalised);
        // No early exit: a match late in the list must cost the same as one
        // early in it.
        if equal && !state.is_spent(index) && matched.is_none() {
            matched = Some(index);
        }
    }

    if let Some(index) = matched {
        state.spend(index);
    }
    Ok(matched)
}

/// Fold case and strip the separators and spaces a tenant may type.
///
/// Returns `None` unless exactly `CODE_LENGTH` characters survive. ASCII
/// folding only: a code is base32, so a byte that is not ASCII could never
/// match one, and folding it would only change how it fails.
fn normalise(presented: &[u8], out: &mut [u8; CODE_LENGTH]) -> Option<()> {
    let mut at = 0usize;
    for &byte in presented {
        if byte.is_ascii_whitespace() || byte == b'-' {
            continue;
        }
        // One byte too many is already the wrong length; stopping here keeps
        // the walk bounded without changing the answer.
        *out.get_mut(at)? = byte.to_ascii_uppercase();
        at += 1;
    }
    (at == CODE_LENGTH).then_some(())
}

/// Compare without an early exit on the first differing byte.
fn fixed_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

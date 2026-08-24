//! PKCE S256 verification (RFC 7636).
//!
//! Pure `no_std` fragment mirroring the host redeem path: the challenge is
//! `b64url(sha256(verifier))` and the comparison is constant-time.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::b64;
use crate::jwk::Sha256Fn;

/// RFC 7636 §4.1 verifier length bounds.
pub const MIN_VERIFIER: usize = 43;
pub const MAX_VERIFIER: usize = 128;

/// Verify an S256 code challenge against a verifier. Returns `false` on
/// out-of-bounds verifier length or mismatch; comparison is constant-time
/// over the full challenge width.
pub fn verify_s256(sha256: Sha256Fn, verifier: &[u8], challenge: &[u8]) -> bool {
    if verifier.len() < MIN_VERIFIER || verifier.len() > MAX_VERIFIER {
        return false;
    }
    let mut digest = [0u8; 32];
    sha256(verifier, &mut digest);
    let expected = b64::encode_digest32(&digest);
    ct_eq(&expected, challenge)
}

/// Constant-time equality: runs over the full length of `a` regardless of
/// where a mismatch occurs; length mismatch still fails.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

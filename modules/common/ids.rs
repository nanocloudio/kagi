//! Deterministic kagi identifiers: tenant id, device id, workload subject.
//!
//! Pure `no_std` fragment; the derivations are:
//!   `tenant_id = b64url(HKDF-SHA256(salt = lower(trim(email)), ikm = secret,
//!                                   info = "tenant-id"))[..22]`
//!   `device_id = b64url(sha256(canonical_device_jwk_json))[..22]`
//!   `workload_subject = b64url(HKDF-SHA256(salt = trim(identity), ikm = secret,
//!                                          info = "kagi-workload-subject"))[..22]`
//! Crypto primitives are injected by the consumer.
//!
//! All three are 22 base64url characters, and the tenant id and the workload
//! subject differ only by their `info` label. That domain separation is the
//! whole reason a workload subject cannot collide with a tenant id derived
//! from the same secret, so the two derivations sit together where the label
//! is visibly the only thing between them.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::b64;
use crate::jwk::{JwkRecord, Sha256Fn};

/// Length of tenant/device identifier strings after truncation.
pub const TENANT_ID_LENGTH: usize = 22;
pub const DEVICE_ID_LENGTH: usize = 22;
pub const WORKLOAD_SUBJECT_LENGTH: usize = 22;

/// Longest normalized email accepted by the fragment path.
pub const MAX_EMAIL: usize = 256;

/// Longest workload identity accepted by the fragment path.
pub const MAX_IDENTITY: usize = 256;

/// HKDF-SHA256 primitive injected by the consumer:
/// `(salt, ikm, info, okm32)`. Host wires the `hkdf` crate; PIC modules
/// wire the SDK's `hmac.rs::{hkdf_extract, hkdf_expand}`.
pub type HkdfSha256Fn = fn(&[u8], &[u8], &[u8], &mut [u8; 32]);

const TENANT_INFO_LABEL: &[u8] = b"tenant-id";

/// HKDF `info` label — domain-separates workload subjects from tenant ids.
const WORKLOAD_INFO_LABEL: &[u8] = b"kagi-workload-subject";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IdError {
    EmptySecret,
    EmptyEmail,
    EmailTooLong,
    EmptyIdentity,
    IdentityTooLong,
    Jwk(crate::jwk::JwkError),
}

/// Derive the deterministic tenant identifier. `out` receives 22 ASCII
/// base64url chars.
pub fn tenant_id(
    hkdf: HkdfSha256Fn,
    secret: &[u8],
    email: &[u8],
    out: &mut [u8; TENANT_ID_LENGTH],
) -> Result<(), IdError> {
    if secret.is_empty() {
        return Err(IdError::EmptySecret);
    }

    // trim ASCII whitespace + lowercase, into a fixed buffer.
    let trimmed = trim_ascii(email);
    if trimmed.is_empty() {
        return Err(IdError::EmptyEmail);
    }
    if trimmed.len() > MAX_EMAIL {
        return Err(IdError::EmailTooLong);
    }
    let mut norm = [0u8; MAX_EMAIL];
    for (dst, &src) in norm.iter_mut().zip(trimmed) {
        *dst = src.to_ascii_lowercase();
    }
    let norm = &norm[..trimmed.len()];

    let mut okm = [0u8; 32];
    hkdf(norm, secret, TENANT_INFO_LABEL, &mut okm);

    let encoded = b64::encode_digest32(&okm);
    out.copy_from_slice(&encoded[..TENANT_ID_LENGTH]);
    Ok(())
}

/// Derive the opaque workload subject. `out` receives 22 ASCII base64url
/// chars.
///
/// The same HKDF shape as [`tenant_id`], with the identity in the salt and a
/// different `info` label. The identity is trimmed but NOT lowercased: a
/// workload identity is a path (`<namespace>/<serviceaccount>`), and folding
/// its case would merge two workloads a cluster keeps apart.
pub fn workload_subject(
    hkdf: HkdfSha256Fn,
    secret: &[u8],
    identity: &[u8],
    out: &mut [u8; WORKLOAD_SUBJECT_LENGTH],
) -> Result<(), IdError> {
    if secret.is_empty() {
        return Err(IdError::EmptySecret);
    }
    let trimmed = trim_ascii(identity);
    if trimmed.is_empty() {
        return Err(IdError::EmptyIdentity);
    }
    if trimmed.len() > MAX_IDENTITY {
        return Err(IdError::IdentityTooLong);
    }

    let mut okm = [0u8; 32];
    hkdf(trimmed, secret, WORKLOAD_INFO_LABEL, &mut okm);

    let encoded = b64::encode_digest32(&okm);
    out.copy_from_slice(&encoded[..WORKLOAD_SUBJECT_LENGTH]);
    Ok(())
}

/// Derive the device identifier from a fixed-shape device JWK.
pub fn device_id(
    sha256: Sha256Fn,
    jwk: &JwkRecord,
    out: &mut [u8; DEVICE_ID_LENGTH],
) -> Result<(), IdError> {
    let mut canonical = [0u8; crate::jwk::MAX_CANONICAL];
    // The thumbprint form, not the publishing one: a device that later
    // decorates its JWK with `alg` or `kid` is the same device, and an id
    // that moved would orphan every certificate issued against it.
    let n = jwk
        .canonical_thumbprint_json(&mut canonical)
        .map_err(IdError::Jwk)?;
    device_id_from_canonical(sha256, &canonical[..n], out);
    Ok(())
}

/// Derive the device identifier from pre-canonicalized JWK bytes — the
/// path for a JWK of arbitrary shape, which needs an allocator to
/// canonicalize and so is canonicalized by the caller.
pub fn device_id_from_canonical(
    sha256: Sha256Fn,
    canonical: &[u8],
    out: &mut [u8; DEVICE_ID_LENGTH],
) {
    let mut digest = [0u8; 32];
    sha256(canonical, &mut digest);
    let encoded = b64::encode_digest32(&digest);
    out.copy_from_slice(&encoded[..DEVICE_ID_LENGTH]);
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = bytes {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

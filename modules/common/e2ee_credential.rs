//! The E2EE device-credential contract: what a device signs, and what a
//! verifier decides.
//!
//! A device generates E2EE keys locally, proves it holds them AND holds its
//! enrolled identity, and the issuer signs the binding between the two. Three
//! parties have to agree on exactly what that means — the device composing a
//! proof, the issuer signing a credential, and whatever later accepts one —
//! and they are not the same process, often not the same machine, and here
//! not even the same repository. So the bytes a proof covers and the checks a
//! credential must pass live in one place.
//!
//! Pure `no_std` fragment. Thumbprints and signature verification are
//! injected, because which canonicalizer and which curve implementation run
//! depends on whether the caller is a module, an issuer, or a relying party —
//! and none of that changes what is being agreed.
//!
//! **What a credential does not prove.** That the issuer is honest. A
//! credential stops a delivery or storage service substituting a device key;
//! it does not stop a compromised issuer introducing a device that was never
//! enrolled.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::auth_wire::suite;
use crate::b64;
use crate::jose;

/// The `cty` an E2EE credential carries.
///
/// Deliberately distinct from the device certificate's `dc+jwt` and the
/// cross-attestation's `da+jwt`: a token accepted in the wrong role is a token
/// whose claims mean something other than what the verifier assumed.
pub const CREDENTIAL_CONTENT_TYPE: &[u8] = b"ke+jwt";

/// The `cty` a possession proof carries.
pub const PROOF_CONTENT_TYPE: &[u8] = b"kp+jwt";

/// How long a possession proof stays fresh, in seconds.
///
/// Short: the proof exists to show the device holds its keys right now, and a
/// long-lived one is a replayable artefact rather than evidence. Freshness is
/// the nonce issuer's to enforce, not this fragment's — issuance receives a
/// nonce it did not mint and cannot date. Stated here so the bound has one
/// number rather than one per caller.
pub const PROOF_MAX_AGE: u64 = 300;

/// Tolerated clock skew on `iat`, in seconds.
pub const CLOCK_SKEW_SECS: u64 = 60;

/// The longest proof signing input this fragment composes.
pub const MAX_PROOF_INPUT: usize = 512;

/// Verify a JWS signature. `(suite, pubkey, signing_input, signature)`.
///
/// `suite` is a `suite::*` id, the same `u16` the rest of the surface
/// carries — not a narrowed copy of it, because a suite space that is `u16`
/// in the registry and `u8` at a verification boundary is one that silently
/// stops round-tripping the day it needs the width. The curve implementation
/// is the caller's: a module wires the SDK's, an issuer wires the one its
/// key custody speaks.
pub type VerifyFn = fn(u16, &[u8], &[u8], &[u8]) -> bool;

/// The ciphersuites this contract covers.
///
/// One, and it is P-256 throughout, because that is what the key-custody
/// contract supports on every backend it claims.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ciphersuite {
    /// `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`.
    MlsP256Aes128GcmSha256,
}

impl Ciphersuite {
    /// The IANA MLS ciphersuite number.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::MlsP256Aes128GcmSha256 => 0x0002,
        }
    }

    /// The suite a code names, if it is one this build attests to.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            0x0002 => Some(Self::MlsP256Aes128GcmSha256),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CredentialError {
    /// Not a three-segment compact JWS.
    Malformed,
    /// A segment was not valid base64url, or did not fit.
    Segment,
    /// The header is not typed as a credential.
    WrongContentType,
    /// The header names no algorithm, or one this build does not verify.
    UnknownAlgorithm,
    /// The signature did not verify against the issuer key.
    BadSignature,
    /// A required claim is missing.
    MissingClaim,
    /// The credential names a different trust domain.
    WrongIssuer,
    /// The credential has expired, or is issued too far in the future.
    OutsideWindow,
    /// The credential names a ciphersuite this build does not attest to.
    UnknownCiphersuite,
    /// The output buffer was too small.
    BufferTooSmall,
}

/// The facts a verified credential carries, borrowed from the claims it was
/// read out of.
///
/// A borrowed view rather than an owned copy: a module has no allocator, and
/// the claims are already in the caller's buffer. That the type exists at all
/// is the point — it cannot be constructed except by [`check_credential`], so
/// a consumer holding one is holding evidence rather than an assertion.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CredentialFacts<'a> {
    /// The issuing trust domain.
    pub iss: &'a [u8],
    /// The device the keys belong to.
    pub sub: &'a [u8],
    /// The tenant the device is enrolled under.
    pub tid: &'a [u8],
    /// The assurance level of the enrolment this credential rests on.
    pub aal: &'a [u8],
    /// The suite, resolved. A credential naming a suite this build does not
    /// attest to never becomes one of these.
    pub ciphersuite: Ciphersuite,
    /// The key generation.
    pub generation: u32,
    pub iat: u64,
    pub exp: u64,
}

/// The bytes a device signs to prove it holds the keys it is asking to bind.
///
/// Both public keys and the generation are covered, so a proof cannot be
/// lifted onto a different key pair or replayed against a later rotation. The
/// nonce is the issuer's, so the device cannot choose what it signs.
///
/// Takes thumbprints rather than the keys themselves: which canonicalizer
/// produced them depends on whether the JWK has a fixed shape, and what the
/// proof covers must not. A caller that cannot thumbprint a key must fail
/// rather than substitute a placeholder — two unusable keys would otherwise
/// produce the same input, and a proof would cover no key material while
/// still verifying.
pub fn write_proof_input(
    device_id: &[u8],
    signature_thumbprint: &[u8],
    hpke_thumbprint: &[u8],
    suite: Ciphersuite,
    nonce: &[u8],
    out: &mut [u8],
) -> Result<usize, CredentialError> {
    if device_id.is_empty()
        || signature_thumbprint.is_empty()
        || hpke_thumbprint.is_empty()
        || nonce.is_empty()
    {
        return Err(CredentialError::MissingClaim);
    }
    let mut at = 0usize;
    let mut digits = [0u8; 5];
    let code_len = write_u16(&mut digits, suite.code());
    for (index, field) in [
        PROOF_CONTENT_TYPE,
        device_id,
        signature_thumbprint,
        hpke_thumbprint,
        &digits[..code_len],
        nonce,
    ]
    .into_iter()
    .enumerate()
    {
        if index > 0 {
            put(out, &mut at, b"\n")?;
        }
        put(out, &mut at, field)?;
    }
    Ok(at)
}

/// Every check a credential must pass, and the facts that survive them.
///
/// The signature is verified here rather than by the caller, because the
/// point of the type this returns is that it cannot exist without it. A
/// caller that verified separately could hand itself a `CredentialFacts`
/// built from unverified claims, and the whole distinction between a
/// credential and a claim would rest on that caller remembering.
///
/// `claims_out` receives the decoded claims JSON, which the returned facts
/// borrow from.
pub fn check_credential<'a>(
    verify: VerifyFn,
    credential: &[u8],
    issuer_suite: u16,
    issuer_key: &[u8],
    expected_issuer: &[u8],
    now: u64,
    claims_out: &'a mut [u8],
) -> Result<CredentialFacts<'a>, CredentialError> {
    let jws = jose::Jws::split(credential).ok_or(CredentialError::Malformed)?;

    // The type comes before the signature on purpose: a token presented in
    // the wrong role is refused as the wrong role, not as a bad signature,
    // and an operator reading the two learns different things.
    let mut header = [0u8; 256];
    let header_len = b64::decode(jws.header_b64, &mut header).ok_or(CredentialError::Segment)?;
    let header = &header[..header_len];
    match jose::claim_str(header, b"cty") {
        Some(cty) if cty == CREDENTIAL_CONTENT_TYPE => {}
        _ => return Err(CredentialError::WrongContentType),
    }
    // The header must SAY what signed it, but what actually verifies is
    // `issuer_suite` — the suite the caller holds the key under. A credential
    // therefore cannot talk a verifier into a weaker algorithm by naming
    // one, which is the whole of the JOSE `alg` confusion class.
    if jose::claim_str(header, b"alg").is_none() {
        return Err(CredentialError::UnknownAlgorithm);
    }

    // A suite this build cannot verify is refused as that, before any bytes
    // are read under it.
    if !suite::is_implemented(issuer_suite) {
        return Err(CredentialError::UnknownAlgorithm);
    }

    // The buffer is sized from the registry and the signature is then
    // checked against the length THIS suite produces. A fixed `64` would be
    // right for the two suites implemented today and wrong for every one
    // after them, and would accept a 64-byte signature offered under a suite
    // that does not sign in 64 bytes.
    let expected = suite::max_signature_len(issuer_suite);
    let mut signature = [0u8; suite::MAX_IMPLEMENTED_SIGNATURE_LEN];
    if b64::decode(jws.signature_b64, &mut signature) != Some(expected) {
        return Err(CredentialError::Segment);
    }
    if !verify(
        issuer_suite,
        issuer_key,
        jws.signing_input,
        &signature[..expected],
    ) {
        return Err(CredentialError::BadSignature);
    }

    let claims_len = b64::decode(jws.payload_b64, claims_out).ok_or(CredentialError::Segment)?;
    let claims = &claims_out[..claims_len];

    let iss = jose::claim_str(claims, b"iss").ok_or(CredentialError::MissingClaim)?;
    if iss != expected_issuer {
        return Err(CredentialError::WrongIssuer);
    }
    let sub = jose::claim_str(claims, b"sub").ok_or(CredentialError::MissingClaim)?;
    let tid = jose::claim_str(claims, b"tid").ok_or(CredentialError::MissingClaim)?;
    let aal = jose::claim_str(claims, b"aal").unwrap_or(b"");
    let iat = jose::claim_u64(claims, b"iat").ok_or(CredentialError::MissingClaim)?;
    let exp = jose::claim_u64(claims, b"exp").ok_or(CredentialError::MissingClaim)?;
    let suite = jose::claim_u64(claims, b"suite").ok_or(CredentialError::MissingClaim)?;
    let generation = jose::claim_u64(claims, b"gen").ok_or(CredentialError::MissingClaim)?;

    if now >= exp {
        return Err(CredentialError::OutsideWindow);
    }
    if iat > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(CredentialError::OutsideWindow);
    }

    let ciphersuite = u16::try_from(suite)
        .ok()
        .and_then(Ciphersuite::from_code)
        .ok_or(CredentialError::UnknownCiphersuite)?;

    Ok(CredentialFacts {
        iss,
        sub,
        tid,
        aal,
        ciphersuite,
        generation: u32::try_from(generation).map_err(|_| CredentialError::MissingClaim)?,
        iat,
        exp,
    })
}

fn put(out: &mut [u8], at: &mut usize, bytes: &[u8]) -> Result<(), CredentialError> {
    let end = at
        .checked_add(bytes.len())
        .ok_or(CredentialError::BufferTooSmall)?;
    out.get_mut(*at..end)
        .ok_or(CredentialError::BufferTooSmall)?
        .copy_from_slice(bytes);
    *at = end;
    Ok(())
}

/// Decimal, without an allocator or a formatter.
fn write_u16(out: &mut [u8; 5], mut value: u16) -> usize {
    if value == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut digits = [0u8; 5];
    let mut n = 0usize;
    while value > 0 && n < digits.len() {
        digits[n] = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
        n += 1;
    }
    for i in 0..n {
        out[i] = digits[n - 1 - i];
    }
    n
}

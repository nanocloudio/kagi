//! Kagi's credential-suite registry.
//!
//! A suite id is the one number the kagi surface carries to say what
//! cryptography a credential uses. A bare JOSE `alg` will not do: it names
//! a signature algorithm and says nothing about the sizes, key type and
//! policy a decision about that credential actually needs.
//!
//! Every size here is otherwise a literal at each call site: `64` for a
//! signature, `65` for a point, `43` for a base64url SHA-256 thumbprint,
//! `32` for a private scalar. Those are true for P-256 and wrong for
//! everything else,
//! and an ML-DSA-65 signature is 3309 bytes against ES256's 64. A module
//! that sizes a buffer from `suite::max_signature_len` keeps working when a
//! suite is added; one that writes `64` does not.
//!
//! **Naming a suite is not implementing it.** [`is_implemented`] is the only
//! thing that says this build can sign or verify one, and every issuance and
//! verification path refuses anything else. The ids exist so no interface has
//! to change when the primitives arrive.
//!
//! Distinct from fluxor's `x509::suite`, which names *certificate* suites for
//! the TLS chain validator. This one names *credential* suites — what a JWS
//! is signed with, what a key package is bound to. They overlap in the
//! classical algorithms and will not in the post-quantum ones, and a shared
//! table would have to pretend that a certificate profile and a JOSE `alg`
//! are the same registry.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

/// No suite. Never valid on a wire: a credential that does not say what
/// signed it cannot be checked, and defaulting one would pick the answer
/// for the caller.
pub const NONE: u16 = 0;
/// ECDSA on P-256 with SHA-256. JOSE `ES256`.
pub const ES256: u16 = 1;
/// Ed25519. JOSE `EdDSA` — note that `EdDSA` alone does not name a curve,
/// which is why the suite id and not the JOSE name is what kagi carries.
pub const ED25519: u16 = 2;
/// ECDSA on P-384 with SHA-384. JOSE `ES384`.
pub const ES384: u16 = 3;
/// ML-DSA-44 (FIPS 204).
pub const ML_DSA_44: u16 = 4;
/// ML-DSA-65.
pub const ML_DSA_65: u16 = 5;
/// ML-DSA-87.
pub const ML_DSA_87: u16 = 6;
/// ML-DSA-44 composed with ES256: both signatures over the same input,
/// both required.
pub const HYBRID_ES256_ML_DSA_44: u16 = 7;

/// Highest id this registry defines.
pub const MAX_ID: u16 = HYBRID_ES256_ML_DSA_44;

/// Whether this build can sign and verify in `suite`.
///
/// ES256, Ed25519 and the three ML-DSA parameter sets — the ones the
/// fluxor SDK gives kagi primitives for. ES384 and the hybrid are named
/// so sizes, policies and error reporting are already suite-shaped; they
/// are refused everywhere a credential is signed or checked, so a
/// deployment learns at configuration rather than at its first signature.
#[must_use]
pub const fn is_implemented(suite: u16) -> bool {
    matches!(suite, ES256 | ED25519 | ML_DSA_44 | ML_DSA_65 | ML_DSA_87)
}

/// This suite's bit in a suite mask. [`NONE`] and any id past [`MAX_ID`]
/// have no bit, so neither can ever be permitted.
///
/// A `u32` holds the registry with room to spare; the assertion is what
/// turns growing past it into a build failure rather than a shift that
/// wraps a new suite onto an existing one's bit.
const _: () = assert!(
    (MAX_ID as u32) < u32::BITS,
    "the suite registry has outgrown a u32 mask"
);

#[must_use]
pub const fn mask(suite: u16) -> u32 {
    if suite == NONE || suite > MAX_ID {
        0
    } else {
        1u32 << suite
    }
}

/// Every suite this build can sign and verify, as a mask.
///
/// Derived from [`is_implemented`] rather than listed beside it, because
/// two lists of the same thing drift and the direction they drift in is
/// unpredictable: a suite verifiable but not permitted refuses live
/// credentials, and one permitted but not verifiable admits them to a
/// verifier that has no primitive.
pub const IMPLEMENTED: u32 = {
    let mut allowed = 0u32;
    let mut suite = 1u16;
    while suite <= MAX_ID {
        if is_implemented(suite) {
            allowed |= mask(suite);
        }
        suite += 1;
    }
    allowed
};

/// Whether `suite` requires two signatures that must both verify.
///
/// The binding rule for a hybrid is that both proofs cover the same
/// credential, request, audience and key lifecycle generation — otherwise
/// an attacker strips the half they cannot forge and presents the half
/// they can.
#[must_use]
pub const fn is_hybrid(suite: u16) -> bool {
    matches!(suite, HYBRID_ES256_ML_DSA_44)
}

/// The classical half of a hybrid, or [`NONE`].
#[must_use]
pub const fn hybrid_classical(suite: u16) -> u16 {
    match suite {
        HYBRID_ES256_ML_DSA_44 => ES256,
        _ => NONE,
    }
}

/// The post-quantum half of a hybrid, or [`NONE`].
#[must_use]
pub const fn hybrid_pq(suite: u16) -> u16 {
    match suite {
        HYBRID_ES256_ML_DSA_44 => ML_DSA_44,
        _ => NONE,
    }
}

/// Classical-equivalent security level in bits. `0` for [`NONE`], so an
/// unresolved suite can never be the stronger side of a comparison.
#[must_use]
pub const fn security_bits(suite: u16) -> u16 {
    match suite {
        ES256 | ED25519 | ML_DSA_44 | HYBRID_ES256_ML_DSA_44 => 128,
        ES384 | ML_DSA_65 => 192,
        ML_DSA_87 => 256,
        _ => 0,
    }
}

/// The JOSE `alg` header value, or an empty slice for a suite JOSE has not
/// named.
///
/// Deliberately empty rather than invented where no standards body has
/// assigned one: a made-up `alg` string would be interoperable with nothing
/// and would have to be un-invented later.
#[must_use]
pub const fn jose_alg(suite: u16) -> &'static [u8] {
    match suite {
        ES256 => b"ES256",
        ED25519 => b"EdDSA",
        ES384 => b"ES384",
        // RFC 9964 registers the FIPS 204 parameter sets under their own
        // names; the `alg` is the parameter set, not a family name, which
        // is why there is no ML-DSA equivalent of `EdDSA`'s ambiguity.
        ML_DSA_44 => b"ML-DSA-44",
        ML_DSA_65 => b"ML-DSA-65",
        ML_DSA_87 => b"ML-DSA-87",
        // The hybrid has no name to carry: a composite ML-DSA/ECDSA `alg`
        // is an Internet-Draft (`draft-ietf-jose-pq-composite-sigs`) and
        // not a registration.
        _ => b"",
    }
}

/// Resolve a JOSE `alg` header to a suite id, or [`NONE`].
#[must_use]
pub fn from_jose_alg(alg: &[u8]) -> u16 {
    if alg == b"ES256" {
        ES256
    } else if alg == b"EdDSA" {
        ED25519
    } else if alg == b"ES384" {
        ES384
    } else if alg == b"ML-DSA-44" {
        ML_DSA_44
    } else if alg == b"ML-DSA-65" {
        ML_DSA_65
    } else if alg == b"ML-DSA-87" {
        ML_DSA_87
    } else {
        NONE
    }
}

/// The JWK `kty` a public key in `suite` is published under, or an empty
/// slice for a suite with no registered key type.
///
/// `kty` is what a relying party dispatches on, and the three key types
/// carry their algorithm in three different places: `EC` names a curve in
/// `crv`, `OKP` names one there too, and RFC 9964's `AKP` names a
/// parameter set in `alg`. Which member is authoritative follows from
/// this, so it is answered here once rather than at each emitter.
#[must_use]
pub const fn jwk_kty(suite: u16) -> &'static [u8] {
    match suite {
        ES256 | ES384 => b"EC",
        ED25519 => b"OKP",
        ML_DSA_44 | ML_DSA_65 | ML_DSA_87 => b"AKP",
        _ => b"",
    }
}

/// Longest private key, in bytes: what a `MSG_KEY_ADD` record must carry.
#[must_use]
pub const fn max_private_key_len(suite: u16) -> usize {
    match suite {
        ES256 => 32,   // the P-256 scalar, big-endian
        ED25519 => 32, // the RFC 8032 seed
        ES384 => 48,
        ML_DSA_44 => 2560,
        ML_DSA_65 => 4032,
        ML_DSA_87 => 4896,
        HYBRID_ES256_ML_DSA_44 => 32 + 2560,
        _ => 0,
    }
}

/// Longest public key, in bytes.
#[must_use]
pub const fn max_public_key_len(suite: u16) -> usize {
    match suite {
        ES256 => 65, // uncompressed SEC1 point
        ED25519 => 32,
        ES384 => 97,
        ML_DSA_44 => 1312,
        ML_DSA_65 => 1952,
        ML_DSA_87 => 2592,
        HYBRID_ES256_ML_DSA_44 => 65 + 1312,
        _ => 0,
    }
}

/// Whether `len` is a valid encoded public-key length for `suite`.
///
/// Not simply `== max_public_key_len`: ES256 keys travel as SEC1 points
/// in either form, and a 33-byte compressed point is the same key as its
/// 65-byte uncompressed spelling. Every other suite has exactly one
/// encoded length, and a key of any other length is not that suite's key.
///
/// One definition, because a keyset that admits a key shape the verifier
/// then refuses is a key that is present and unusable — which looks like
/// a configured issuer right up until someone presents a credential.
///
/// A suite the registry does not know has no length, so the explicit
/// zero check is what stops an empty key matching it.
#[must_use]
pub const fn public_key_len_ok(suite: u16, len: usize) -> bool {
    match suite {
        ES256 => len == 33 || len == 65,
        _ => len != 0 && len == max_public_key_len(suite),
    }
}

/// The longest public key this build can be asked to verify under, over
/// every implemented suite.
///
/// The bound a keyset slot, a published-key record, an exported issuer
/// key and a JWK member are all sized from. Derived here so they cannot
/// come to disagree, and so implementing a suite widens every one of them
/// at once: a SEC1 P-256 point is 65 bytes and an ML-DSA-87 key is 2592,
/// and a slot sized for the first cannot hold the second.
pub const MAX_IMPLEMENTED_PUBLIC_KEY_LEN: usize = {
    let mut longest = 0usize;
    let mut suite = 1u16;
    while suite <= MAX_ID {
        if is_implemented(suite) {
            let len = max_public_key_len(suite);
            if len > longest {
                longest = len;
            }
        }
        suite += 1;
    }
    longest
};

/// Longest signature, in bytes.
///
/// JOSE-encoded, so ECDSA is raw `r‖s` rather than the DER form an X.509
/// certificate carries — the same algorithm, a different length, which is
/// exactly why this is a lookup and not a constant.
#[must_use]
pub const fn max_signature_len(suite: u16) -> usize {
    match suite {
        ES256 => 64,
        ED25519 => 64,
        ES384 => 96,
        ML_DSA_44 => 2420,
        ML_DSA_65 => 3309,
        ML_DSA_87 => 4627,
        HYBRID_ES256_ML_DSA_44 => 64 + 2420,
        _ => 0,
    }
}

/// The longest signature among the implemented suites named in `allowed`.
///
/// A verification path sizes its decode buffer from the suites IT can be
/// offered, not from the widest the build names. With ML-DSA-87 among
/// them the two differ by 4.5 KB per path, so a call site that can only
/// ever see a device's classical proof reserves 64 bytes while one that
/// verifies whatever the issuer keyset holds passes [`IMPLEMENTED`].
///
/// Suites in `allowed` that this build cannot verify contribute nothing:
/// naming ML-DSA-87 in a policy does not make a buffer hold one if the
/// primitive is absent.
#[must_use]
pub const fn max_signature_len_over(allowed: u32) -> usize {
    let mut longest = 0usize;
    let mut suite = 1u16;
    while suite <= MAX_ID {
        if is_implemented(suite) && allowed & mask(suite) != 0 {
            let len = max_signature_len(suite);
            if len > longest {
                longest = len;
            }
        }
        suite += 1;
    }
    longest
}

/// The longest signature this build can be asked to verify, over every
/// implemented suite.
///
/// Derived rather than written down, so implementing a suite widens the
/// buffer that decodes it instead of truncating one. A fragment checks
/// the DECODED length against [`max_signature_len`] for the suite it was
/// actually told, so a signature that merely fits is not mistaken for one
/// of the right shape.
pub const MAX_IMPLEMENTED_SIGNATURE_LEN: usize = max_signature_len_over(IMPLEMENTED);

const _: () = {
    let mut suite = 0u16;
    while suite <= MAX_ID {
        if is_implemented(suite) {
            assert!(
                max_signature_len(suite) != 0,
                "an implemented suite has no signature length in the registry"
            );
            assert!(
                max_public_key_len(suite) != 0,
                "an implemented suite has no public key length in the registry"
            );
            assert!(
                !jose_alg(suite).is_empty(),
                "an implemented suite has no JOSE name; a credential cannot \
                 say what signed it"
            );
        }
        suite += 1;
    }
};

/// Thumbprint algorithms for a `cnf.jkt` key binding.
pub mod thumbprint {
    /// No key binding.
    pub const NONE: u8 = 0;
    /// RFC 7638 JWK thumbprint over SHA-256, base64url-unpadded: 43 chars.
    pub const JWK_SHA256: u8 = 1;
    /// RFC 7638 over SHA-384: 64 chars.
    pub const JWK_SHA384: u8 = 2;

    /// Exact base64url-unpadded length of a thumbprint, or 0.
    ///
    /// Exact, not a maximum: base64url of a fixed-size digest has exactly
    /// one length, and accepting a shorter one accepts a truncated digest.
    #[must_use]
    pub const fn len(alg: u8) -> usize {
        match alg {
            JWK_SHA256 => 43,
            JWK_SHA384 => 64,
            _ => 0,
        }
    }

    /// Whether this build can compute thumbprints in `alg`.
    #[must_use]
    pub const fn is_implemented(alg: u8) -> bool {
        matches!(alg, JWK_SHA256)
    }
}

/// Credential profiles: what a credential is FOR.
///
/// A profile is not a suite. The suite says how a credential is signed; the
/// profile says what it authorises and therefore which issuer key domain
/// may sign it. Keeping them apart is what stops a device certificate and a
/// workload SVID being signed by the same key because they happen to use
/// the same algorithm.
pub mod profile {
    pub const NONE: u16 = 0;
    /// An OAuth-style access token.
    pub const ACCESS_TOKEN: u16 = 1;
    /// A device certificate (`dc+jwt`) issued at enrolment.
    pub const DEVICE_CERTIFICATE: u16 = 2;
    /// A SPIFFE workload identity.
    pub const WORKLOAD_SVID: u16 = 3;
    /// A signed enrolment challenge.
    pub const ENROLMENT_CHALLENGE: u16 = 4;
    /// An E2EE device credential.
    pub const E2EE_CREDENTIAL: u16 = 5;
    /// OIDC ID token signing key.
    pub const ID_TOKEN: u16 = 6;

    /// Highest profile this registry defines. Raise it with every profile
    /// added above: a bound that trails the list silently excludes the
    /// newest profile from anything that range-checks one.
    pub const MAX_ID: u16 = ID_TOKEN;

    /// Short stable token, for an operator-facing log line.
    #[must_use]
    pub const fn text(profile: u16) -> &'static [u8] {
        match profile {
            ACCESS_TOKEN => b"access-token",
            DEVICE_CERTIFICATE => b"device-certificate",
            WORKLOAD_SVID => b"workload-svid",
            ENROLMENT_CHALLENGE => b"enrolment-challenge",
            E2EE_CREDENTIAL => b"e2ee-credential",
            ID_TOKEN => b"id-token",
            _ => b"none",
        }
    }
}

/// Short stable token for a suite, for an operator-facing log line.
#[must_use]
pub const fn text(suite: u16) -> &'static [u8] {
    match suite {
        ES256 => b"es256",
        ED25519 => b"ed25519",
        ES384 => b"es384",
        ML_DSA_44 => b"ml-dsa-44",
        ML_DSA_65 => b"ml-dsa-65",
        ML_DSA_87 => b"ml-dsa-87",
        HYBRID_ES256_ML_DSA_44 => b"es256+ml-dsa-44",
        _ => b"none",
    }
}

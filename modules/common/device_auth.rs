//! Device authentication — verify a presented credential and its DPoP proof,
//! and report the claims of whoever presented it.
//!
//! This is steps 1 to 4 of the resource gate's admission, lifted out so that
//! every module which must authenticate a device performs them in the same
//! order with the same failure directions. `resource_gate` authenticates an
//! access token; `mint_admission`, `keypackage_endpoint` and
//! `e2ee_state_endpoint` authenticate a device certificate. The credential
//! differs only in its `cty`, so the difference is a parameter rather than
//! four copies of the ordering.
//!
//! What this fragment decides:
//!
//! 1. The credential's signature verifies under the supplied issuer key, and
//!    the credential is inside its own `iat`/`exp` window.
//! 2. The DPoP proof's signature verifies under the key its own header
//!    carries — not under the issuer key, and never under the algorithm the
//!    header names, which is the algorithm-confusion path.
//! 3. `typ`, the `htm`/`htu` binding and `iat` freshness hold
//!    (`dpop::check_proof`).
//! 4. The proof key's thumbprint equals the credential's `cnf.jkt`. Steps 2
//!    and 3 prove the presenter holds *a* key; this proves it is *the* key
//!    the credential was issued against.
//!
//! What it deliberately does **not** decide:
//!
//! - **Replay.** The window is stateful and lives in module state, so the
//!   caller supplies it as `record_replay`, which this calls once — after the
//!   proof has verified in step 3 and before the binding comparison in step
//!   4. That position is the contract, not an implementation detail:
//!   recording earlier would take a `jti` from an unverified proof and let
//!   anyone burn an honest client's identifiers, and recording later would
//!   change which presentations consume one.
//! - **Assurance**, which is a policy floor rather than an authentication
//!   fact, and **authorization**, which is the calling module's whole job.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::auth_wire::suite;
use crate::b64;
use crate::dpop;
use crate::jose;
use crate::jwk;

/// The hasher shape every fragment here takes. Re-exported from `jwk` rather
/// than redeclared, so the same function pointer satisfies this fragment,
/// `dpop::check_proof` and `jwk::thumbprint_from_canonical`.
pub use crate::jwk::Sha256Fn;
/// Verify an ECDSA P-256 signature over a digest, given a SEC1 public point.
/// Slices rather than fixed arrays, matching the SDK verifier's own shape.
pub type EcdsaVerifyFn = fn(&[u8], &[u8], &[u8]) -> bool;
/// Verify an Ed25519 signature over a message, given a 32-byte public key.
pub type Ed25519VerifyFn = fn(&[u8; 32], &[u8], &[u8; 64]) -> bool;

/// The primitives this fragment is given rather than links. On target these
/// are the SDK's; on the host they are `p256` / `ed25519-dalek` / `sha2`.
#[derive(Clone, Copy)]
pub struct Verifiers {
    pub sha256: Sha256Fn,
    pub ecdsa_verify: EcdsaVerifyFn,
    pub ed25519_verify: Ed25519VerifyFn,
}

/// Credential suites this fragment can verify under.
///
/// Re-exported from the registry rather than restated. Two constants worth
/// of duplication is how a suite id comes to mean one thing here and another
/// where it was defined, and the registry is also where the sizes live.
pub use crate::auth_wire::suite::{ED25519 as SUITE_ED25519, ES256 as SUITE_ES256};

/// DPoP proof-key types, from the proof header's own JWK `kty`.
pub const ALG_ES256: u8 = 1;
pub const ALG_ED25519: u8 = 2;

/// The issuer key a credential is verified under.
pub struct IssuerKey<'a> {
    /// The credential suite, from `auth_wire::suite`. Not a JOSE `alg`
    /// string and not the old two-value `ALG_*` pair: the suite is what
    /// the key was delivered under, and it is the only thing that decides
    /// how a signature over it is checked.
    pub suite: u16,
    pub public: &'a [u8],
}

/// What a caller presented: a credential and the proof that they hold the
/// key it was issued against. The two are always supplied together, because
/// neither is worth anything without the other.
pub struct Presentation<'a> {
    pub credential: &'a [u8],
    pub proof: &'a [u8],
}

/// The request the proof must be bound to.
pub struct Request<'a> {
    /// The HTTP method name, uppercase, as `htm` spells it.
    pub method: &'a [u8],
    /// The request URI, as `htu` spells it.
    pub uri: &'a [u8],
    /// Seconds since the Unix epoch.
    ///
    /// A caller on a platform whose clock may be unavailable must decide what
    /// a zero here means *before* calling: this fragment compares windows and
    /// cannot tell a missing clock from 1970.
    pub now: u64,
}

/// The window policy, and which credential kind is acceptable.
pub struct Policy {
    /// How old a DPoP proof may be.
    pub proof_max_age_secs: u64,
    /// Clock skew allowed on the credential's own window.
    pub clock_skew_secs: u64,
    /// The `cty` the credential header must carry, or `None` to accept a
    /// credential that names none — which is what an access token does.
    pub expected_cty: Option<&'static [u8]>,
}

/// Why a presentation was refused. Each variant is a distinct direction so a
/// caller can count and answer them differently; collapsing them would lose
/// the difference between "this is not our credential" and "this is our
/// credential, presented by someone who does not hold its key".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthError {
    /// The credential is malformed, not signed by the issuer key, outside its
    /// window, or not the credential kind the policy names.
    Credential,
    /// The proof is malformed, not signed by the key its header carries, or
    /// fails the `typ` / `htm` / `htu` / `iat` checks.
    Proof,
    /// The proof verified, but its `jti` has been seen before.
    Replay,
    /// Both verified, but the proof key is not the key the credential was
    /// issued against.
    NotBound,
    /// A scratch buffer the caller supplied was too small.
    Overflow,
}

/// A verified presentation.
pub struct Authenticated<'a> {
    /// The credential's decoded claims JSON, in the caller's buffer.
    pub claims: &'a [u8],
    /// The proof's `jti` digest, already passed to `record_replay`.
    pub jti_digest: [u8; 32],
    /// The thumbprint of the key that presented the credential, which step 4
    /// has already shown equals the credential's `cnf.jkt`.
    pub thumbprint: [u8; 43],
}

/// The largest JOSE segment this fragment will decode.
pub const MAX_SEGMENT: usize = 1024;

/// Verify `credential` and `proof` against `req`, returning the credential's
/// claims on success.
///
/// `claims_out` receives the decoded credential payload and must live as long
/// as the returned claims are read.
/// `record_replay` is called once with the proof's `jti` digest, between
/// steps 3 and 4, and returns `false` if the identifier has been seen before.
pub fn authenticate<'b>(
    v: &Verifiers,
    key: &IssuerKey<'_>,
    presented: &Presentation<'_>,
    req: &Request<'_>,
    policy: &Policy,
    claims_out: &'b mut [u8],
    record_replay: &mut impl FnMut(&[u8; 32]) -> bool,
) -> Result<Authenticated<'b>, AuthError> {
    // ── 1. the credential verifies and is live ────────────────────────────
    let cred_jws = jose::Jws::split(presented.credential).ok_or(AuthError::Credential)?;

    if let Some(want) = policy.expected_cty {
        let mut header = [0u8; MAX_SEGMENT];
        let header_len =
            b64::decode(cred_jws.header_b64, &mut header).ok_or(AuthError::Credential)?;
        match jose::claim_str(&header[..header_len], b"cty") {
            Some(got) if got == want => {}
            _ => return Err(AuthError::Credential),
        }
    }

    if !verify_under_issuer(v, key, &cred_jws) {
        return Err(AuthError::Credential);
    }

    let claims_len = b64::decode(cred_jws.payload_b64, claims_out).ok_or(AuthError::Overflow)?;
    let claims = &claims_out[..claims_len];
    let iat = jose::claim_u64(claims, b"iat").unwrap_or(0);
    let exp = jose::claim_u64(claims, b"exp").unwrap_or(0);
    if !jose::within_window(req.now, iat, exp, policy.clock_skew_secs) {
        return Err(AuthError::Credential);
    }

    // ── 2. the proof verifies under the key its own header carries ────────
    let proof_jws = jose::Jws::split(presented.proof).ok_or(AuthError::Proof)?;
    let mut proof_header = [0u8; MAX_SEGMENT];
    let proof_header_len =
        b64::decode(proof_jws.header_b64, &mut proof_header).ok_or(AuthError::Proof)?;
    let proof_header = &proof_header[..proof_header_len];
    let mut canonical = [0u8; jwk::MAX_CANONICAL];
    let canonical_len =
        canonical_header_jwk(proof_header, &mut canonical).ok_or(AuthError::Proof)?;
    let canonical = &canonical[..canonical_len];
    if !verify_under_header_jwk(v, proof_header, &proof_jws) {
        return Err(AuthError::Proof);
    }

    // ── 3. the proof's claims bind it to this request, and it is fresh ────
    let mut proof_payload = [0u8; MAX_SEGMENT];
    let proof_payload_len =
        b64::decode(proof_jws.payload_b64, &mut proof_payload).ok_or(AuthError::Proof)?;
    let facts = dpop::check_proof(
        v.sha256,
        proof_header,
        &proof_payload[..proof_payload_len],
        req.method,
        req.uri,
        req.now,
        policy.proof_max_age_secs,
    )
    .map_err(|_| AuthError::Proof)?;

    // Recorded only now: a `jti` taken from an unverified proof would let
    // anyone burn an honest client's identifiers.
    if !record_replay(&facts.jti_digest) {
        return Err(AuthError::Replay);
    }

    // ── 4. the proof key is the key the credential was issued against ─────
    let thumbprint = jwk::thumbprint_from_canonical(v.sha256, canonical);
    let bound = jose::claim_str(claims, b"jkt").ok_or(AuthError::Credential)?;
    if bound != thumbprint {
        return Err(AuthError::NotBound);
    }

    Ok(Authenticated {
        claims: &claims_out[..claims_len],
        jti_digest: facts.jti_digest,
        thumbprint,
    })
}

/// The `kid` a credential names, copied into `out`; returns its length.
///
/// The credential says which key signed it, and that is a claim to be
/// looked up, not a fact to be trusted: the caller resolves it against a
/// keyset and refuses an unknown one. What this must never become is a
/// hint — "use this key if we have it, otherwise any key" — which is what a
/// `kid` that nothing indexes by amounts to.
///
/// `None` when the credential is not a compact JWS, its header does not
/// base64-decode, it carries no `kid`, or the `kid` does not fit `out`.
/// Every one of those is a credential this caller cannot resolve a key
/// for, so they collapse to one answer.
pub fn credential_kid(credential: &[u8], out: &mut [u8]) -> Option<usize> {
    let jws = jose::Jws::split(credential)?;
    let mut header_json = [0u8; 512];
    let n = b64::decode(jws.header_b64, &mut header_json)?;
    let kid = jose::claim_str(&header_json[..n], b"kid")?;
    if kid.is_empty() || kid.len() > out.len() {
        return None;
    }
    out[..kid.len()].copy_from_slice(kid);
    Some(kid.len())
}

/// Verify a JWS under a known issuer key.
///
/// The algorithm comes from the key we already trust, never from the JWS
/// header — the header is written by whoever made the token.
fn verify_under_issuer(v: &Verifiers, key: &IssuerKey<'_>, jws: &jose::Jws<'_>) -> bool {
    // Sized from the registry, then checked against the length THIS suite
    // signs in. A fixed length would be right for the two suites carried
    // today and would accept a signature of that length offered under any
    // suite added later.
    let Some((sig, len)) = decode_signature(jws.signature_b64, key.suite) else {
        return false;
    };
    let Some(sig) = as_fixed_64(&sig, len) else {
        return false;
    };
    match key.suite {
        SUITE_ES256 => {
            let mut hash = [0u8; 32];
            (v.sha256)(jws.signing_input, &mut hash);
            (v.ecdsa_verify)(key.public, &hash, sig)
        }
        SUITE_ED25519 => match key.public.try_into() {
            Ok(pk32) => (v.ed25519_verify)(pk32, jws.signing_input, sig),
            Err(_) => false,
        },
        _ => false,
    }
}

/// Decode a base64url signature and check it is the length `suite` signs in.
///
/// The buffer is the build's widest implemented signature; the check is
/// against the length THIS suite produces, so a signature that merely fits
/// is not mistaken for one of the right shape.
///
/// Returns the buffer and that length. The algorithm verifiers take a fixed
/// array because their algorithms have a fixed size — an Ed25519 signature
/// IS 64 bytes — so the caller narrows to the exact length rather than this
/// pretending every suite is the same width.
fn decode_signature(
    signature_b64: &[u8],
    suite_id: u16,
) -> Option<([u8; suite::MAX_IMPLEMENTED_SIGNATURE_LEN], usize)> {
    if !suite::is_implemented(suite_id) {
        return None;
    }
    let expected = suite::max_signature_len(suite_id);
    let mut sig = [0u8; suite::MAX_IMPLEMENTED_SIGNATURE_LEN];
    if b64::decode(signature_b64, &mut sig) != Some(expected) {
        return None;
    }
    Some((sig, expected))
}

/// Narrow a decoded signature to the 64-byte array an Ed25519 or raw-ECDSA
/// verifier takes.
///
/// `None` when the suite does not sign in 64 bytes, which is a suite this
/// pair of verifiers cannot serve however well its signature decoded.
fn as_fixed_64(sig: &[u8; suite::MAX_IMPLEMENTED_SIGNATURE_LEN], len: usize) -> Option<&[u8; 64]> {
    sig.get(..len)?.try_into().ok()
}

/// Verify a DPoP proof under the public key its own header carries.
///
/// The algorithm comes from the header jwk's `kty`, never from the header's
/// `alg`: `alg` is written by whoever made the proof, and letting it choose
/// the verifier is the algorithm-confusion path.
fn verify_under_header_jwk(v: &Verifiers, header_json: &[u8], jws: &jose::Jws<'_>) -> bool {
    let Some(kty) = jose::claim_str(header_json, b"kty") else {
        return false;
    };
    // The key type picks the suite, and the suite gives the length — so the
    // proof's own `alg` never reaches this, and a signature of the wrong
    // length for the key it names is refused before any curve sees it.
    let suite_id = match kty {
        b"OKP" => SUITE_ED25519,
        b"EC" => SUITE_ES256,
        _ => return false,
    };
    let Some((sig, len)) = decode_signature(jws.signature_b64, suite_id) else {
        return false;
    };
    let Some(sig) = as_fixed_64(&sig, len) else {
        return false;
    };
    match kty {
        b"OKP" => {
            let Some(x) = jose::claim_str(header_json, b"x") else {
                return false;
            };
            let mut pk = [0u8; 32];
            if b64::decode(x, &mut pk) != Some(32) {
                return false;
            }
            (v.ed25519_verify)(&pk, jws.signing_input, sig)
        }
        b"EC" => {
            let (Some(x), Some(y)) = (
                jose::claim_str(header_json, b"x"),
                jose::claim_str(header_json, b"y"),
            ) else {
                return false;
            };
            // SEC1 uncompressed: 0x04 ‖ X ‖ Y.
            let mut point = [0u8; 65];
            point[0] = 0x04;
            if b64::decode(x, &mut point[1..33]) != Some(32) {
                return false;
            }
            if b64::decode(y, &mut point[33..65]) != Some(32) {
                return false;
            }
            let mut hash = [0u8; 32];
            (v.sha256)(jws.signing_input, &mut hash);
            (v.ecdsa_verify)(&point, &hash, sig)
        }
        _ => false,
    }
}

/// Rebuild the header's `jwk` in the canonical member order a thumbprint is
/// taken over.
///
/// The proof's own spelling of the JWK is not used: RFC 7638 thumbprints are
/// defined over a canonical form, and hashing whatever order the presenter
/// happened to write would let the same key produce two thumbprints.
pub fn canonical_header_jwk(header_json: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut record = jwk::JwkRecord::new();
    if let Some(value) = jose::claim_str(header_json, b"crv") {
        record.crv = jwk::Field::set(value).ok()?;
    }
    if let Some(value) = jose::claim_str(header_json, b"kty") {
        record.kty = jwk::Field::set(value).ok()?;
    }
    if let Some(value) = jose::claim_str(header_json, b"x") {
        record.x = jwk::Field::set(value).ok()?;
    }
    if let Some(value) = jose::claim_str(header_json, b"y") {
        record.y = jwk::Field::set(value).ok()?;
    }
    record.canonical_json(out).ok()
}

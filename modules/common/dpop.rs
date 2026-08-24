//! `DPoP` proof-of-possession verification (RFC 9449) — the deterministic,
//! reusable parts (P6). Pure `no_std` fragment; crypto is injected.
//!
//! A `DPoP` proof is a compact JWS whose header carries the prover's public
//! `jwk` and `typ:"dpop+jwt"`, and whose claims are `htm` (HTTP method),
//! `htu` (HTTP URI), `iat`, and a unique `jti`. A resource server binds it to
//! an access token by requiring `jwk`'s thumbprint to equal the token's
//! `cnf.jkt`. The full check is: signature valid (with the header `jwk`),
//! `htm`/`htu` match the request, `iat` is fresh, `jti` is unseen (replay),
//! and the thumbprint matches `cnf.jkt`.
//!
//! This fragment owns the parts that are the same on host and on-target: the
//! header/claim extraction, the freshness/binding checks, and a bounded
//! replay window. Signature verification and public-key reconstruction are
//! caller-wired (host: `p256`/`ed25519-dalek`; module: the fluxor SDK), since
//! they depend on the algorithm and the injected verify primitive.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::jose;
use crate::jwk::Sha256Fn;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DpopError {
    /// Not a compact JWS.
    Malformed,
    /// Header `typ` is not `dpop+jwt`.
    BadType,
    /// A required claim (`htm`/`htu`/`iat`/`jti`) is missing.
    MissingClaim,
    /// `htm` or `htu` did not match the expected request binding.
    BindingMismatch,
    /// `iat` is outside the freshness window.
    Stale,
    /// `jti` was already seen (replay).
    Replay,
}

/// The validated, request-bound facts extracted from a `DPoP` proof. `jti_digest`
/// is `sha256(jti)` — a fixed-width replay key so the window need not store
/// variable-length ids.
pub struct ProofFacts {
    pub jti_digest: [u8; 32],
    pub iat: u64,
}

/// Header/claims checks on a `DPoP` proof whose signature the caller has ALREADY
/// verified with the header's `jwk`. Confirms `typ`, the `htm`/`htu` binding,
/// and `iat` freshness; extracts the `jti` digest for the replay window. The
/// caller separately checks that the header jwk's thumbprint equals the access
/// token's `cnf.jkt` (see [`crate::jwk::JwkRecord::thumbprint`]).
///
/// `header_json` / `payload_json` are the base64url-decoded segments.
pub fn check_proof(
    sha256: Sha256Fn,
    header_json: &[u8],
    payload_json: &[u8],
    bound_method: &[u8],
    bound_uri: &[u8],
    now: u64,
    max_age_secs: u64,
) -> Result<ProofFacts, DpopError> {
    // typ must be dpop+jwt (case-sensitive per RFC 9449).
    match jose::claim_str(header_json, b"typ") {
        Some(t) if t == b"dpop+jwt" => {}
        _ => return Err(DpopError::BadType),
    }

    let htm = jose::claim_str(payload_json, b"htm").ok_or(DpopError::MissingClaim)?;
    let htu = jose::claim_str(payload_json, b"htu").ok_or(DpopError::MissingClaim)?;
    if htm != bound_method || htu != bound_uri {
        return Err(DpopError::BindingMismatch);
    }

    let iat = jose::claim_u64(payload_json, b"iat").ok_or(DpopError::MissingClaim)?;
    // Fresh: iat within [now - max_age, now + skew]; reuse the token window
    // helper with a symmetric bound by treating (iat, iat+max_age) as the
    // validity span. A proof from the future (small skew) or older than
    // max_age is rejected.
    if now.saturating_sub(iat) > max_age_secs || iat > now.saturating_add(max_age_secs) {
        return Err(DpopError::Stale);
    }

    let jti = jose::claim_str(payload_json, b"jti").ok_or(DpopError::MissingClaim)?;
    if jti.is_empty() {
        return Err(DpopError::MissingClaim);
    }
    let mut jti_digest = [0u8; 32];
    sha256(jti, &mut jti_digest);

    Ok(ProofFacts { jti_digest, iat })
}

/// A bounded replay window over `jti` digests — a fixed-size ring that holds
/// the most recent `N` seen digests. `check_and_record` returns `true` if the
/// digest is new (and records it), `false` if it is a replay of one still in
/// the window. Sized so its coverage exceeds the proof freshness window: a
/// proof older than `max_age` is rejected by [`check_proof`] regardless, so an
/// attacker cannot outrun the ring with stale proofs.
pub struct ReplayWindow<const N: usize> {
    digests: [[u8; 32]; N],
    /// Number of live entries (until the ring first fills).
    len: usize,
    /// Next write position (wraps at N).
    next: usize,
}

impl<const N: usize> ReplayWindow<N> {
    pub const fn new() -> Self {
        Self {
            digests: [[0u8; 32]; N],
            len: 0,
            next: 0,
        }
    }

    /// Record `digest` if unseen; return `true` when newly recorded, `false`
    /// on replay.
    pub fn check_and_record(&mut self, digest: &[u8; 32]) -> bool {
        for existing in &self.digests[..self.len] {
            if existing == digest {
                return false;
            }
        }
        self.digests[self.next] = *digest;
        self.next = (self.next + 1) % N;
        if self.len < N {
            self.len += 1;
        }
        true
    }
}

impl<const N: usize> Default for ReplayWindow<N> {
    fn default() -> Self {
        Self::new()
    }
}

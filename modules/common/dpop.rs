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

/// The outcome of offering a proof to the replay window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Replay {
    /// New, and recorded.
    Recorded,
    /// Already seen inside its freshness window.
    Seen,
    /// The window is full of entries that are all still fresh.
    ///
    /// A refusal, and a DIFFERENT one from `Seen`: the caller refuses either
    /// way, but an operator needs to tell "somebody replayed a proof" from
    /// "the window is saturated", because the second means the deployment is
    /// under a load its window cannot cover and the first does not.
    Full,
}

/// A bounded replay window over `jti` digests.
///
/// # Why this fails closed instead of evicting
///
/// It used to be a plain ring: `next = (next + 1) % N`, overwriting the
/// oldest entry when full. The argument written here was that the ring was
/// "sized so its coverage exceeds the proof freshness window", so an evicted
/// entry's proof would already be too old to reuse.
///
/// **That argument did not hold at the sizes actually deployed.** Every
/// consumer used `N = 128` against a `proof_max_age_secs` of 300. An
/// attacker sending 129 distinct proofs inside those five minutes — fewer
/// than one per second — evicted the earliest entry, whose proof was still
/// comfortably inside its own freshness window and could then be replayed.
/// The ring could be outrun by anyone who could make a request.
///
/// A slot is now reusable only once the proof it holds has aged past its own
/// freshness window, at which point `check_proof` would refuse that proof
/// anyway and forgetting it costs nothing. When no slot has aged out, the
/// window answers [`Replay::Full`] and the caller refuses. An eviction under
/// load is an admission under load, so the load has to be what breaks.
pub struct ReplayWindow<const N: usize> {
    digests: [[u8; 32]; N],
    /// When each entry stops mattering: the proof's `iat` plus the freshness
    /// window it was checked under. `0` marks a free slot.
    ///
    /// Held per entry rather than derived, because the window a proof was
    /// checked under is a property of the policy that admitted it, and a
    /// policy change must not retroactively shorten what is remembered.
    expires_at: [u64; N],
}

impl<const N: usize> ReplayWindow<N> {
    pub const fn new() -> Self {
        Self {
            digests: [[0u8; 32]; N],
            expires_at: [0u64; N],
        }
    }

    /// Offer `digest` to the window.
    ///
    /// `expires_at` is when this proof stops being replayable — its `iat`
    /// plus the freshness window it was checked under. `now` is the current
    /// time in seconds.
    pub fn offer(&mut self, digest: &[u8; 32], now: u64, expires_at: u64) -> Replay {
        let mut free: Option<usize> = None;
        for i in 0..N {
            let live = self.expires_at[i] != 0 && now < self.expires_at[i];
            if live {
                if self.digests[i] == *digest {
                    return Replay::Seen;
                }
            } else if free.is_none() {
                // A free slot, or one whose proof has aged past the point
                // where `check_proof` would accept it anyway.
                free = Some(i);
            }
        }
        match free {
            Some(i) => {
                self.digests[i] = *digest;
                self.expires_at[i] = expires_at;
                Replay::Recorded
            }
            None => Replay::Full,
        }
    }

    /// How many entries are still live at `now`.
    ///
    /// For an operator gauge: a window sitting near `N` is one about to
    /// start refusing, which is worth knowing before it does.
    #[must_use]
    pub fn live(&self, now: u64) -> usize {
        (0..N)
            .filter(|&i| self.expires_at[i] != 0 && now < self.expires_at[i])
            .count()
    }
}

impl<const N: usize> Default for ReplayWindow<N> {
    fn default() -> Self {
        Self::new()
    }
}

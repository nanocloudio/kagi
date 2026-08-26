//! What each credential decision needs to know about the clock.
//!
//! Every expiry check, replay window, certificate lifetime and key
//! retirement is a statement about time — and on RP2350-class hardware with
//! no RTC the number those checks read is legitimately zero. Ten call sites
//! across this repo currently do `dev_unix_millis(sys) / 1000` and compare,
//! which means on such a board every `exp` is in the future and nothing ever
//! expires. That is not a rounding error; it is the absence of expiry.
//!
//! This fragment is the table that says which decisions may proceed on what.
//! It decides nothing itself: it maps a decision to a requirement, and the
//! caller refuses when the requirement is not met. The point of writing it
//! down is that "does this check need a trustworthy clock?" should be
//! answered once, in one place, rather than implicitly by whoever wrote each
//! comparison.
//!
//! ## Why refusing is the safe direction
//!
//! For every decision here, the failure mode of proceeding without trusted
//! time is that something expired is treated as live: a spent token, a
//! retired key, a revoked certificate. The failure mode of refusing is that
//! a credential cannot be issued or accepted until the clock is fixed. The
//! second is an outage; the first is a bypass. So the table's default is to
//! require, and the exceptions are individually argued.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

/// Offsets into the `timer::TRUSTED_UNIX` record. Mirrors
/// `abi::kernel_abi::trusted_time`, which a `no_std` fragment cannot reach
/// because it is not mounted here — the numbers are the contract.
const OFF_UNIX_SECONDS: usize = 0;
const OFF_UNCERTAINTY_MS: usize = 12;
const OFF_MONOTONIC_US: usize = 16;
const OFF_SOURCE_EPOCH: usize = 24;
const OFF_SOURCE_CLASS: usize = 32;
const OFF_FLAGS: usize = 33;

/// The record's encoded length.
pub const RECORD_LEN: usize = 34;

/// `source_class` values.
pub const SOURCE_UNAVAILABLE: u8 = 0;
pub const SOURCE_FREE_RUNNING: u8 = 1;
pub const SOURCE_RTC: u8 = 2;
pub const SOURCE_NETWORK_SYNC: u8 = 3;
pub const SOURCE_SIGNED_AUTHORITY: u8 = 4;

/// `flags` bits.
pub const FLAG_SYNCHRONIZED: u8 = 0x01;
pub const FLAG_TRUSTED: u8 = 0x02;
pub const FLAG_ROLLBACK_SUSPECT: u8 = 0x04;

/// A decoded observation.
#[derive(Clone, Copy)]
pub struct Observation {
    pub unix_seconds: u64,
    pub uncertainty_ms: u32,
    pub monotonic_us: u64,
    pub source_epoch: u64,
    pub source_class: u8,
    pub flags: u8,
}

impl Observation {
    /// Decode a `TRUSTED_UNIX` record.
    #[must_use]
    pub fn decode(rec: &[u8]) -> Option<Self> {
        if rec.len() < RECORD_LEN {
            return None;
        }
        Some(Self {
            unix_seconds: u64::from_le_bytes([
                rec[OFF_UNIX_SECONDS],
                rec[OFF_UNIX_SECONDS + 1],
                rec[OFF_UNIX_SECONDS + 2],
                rec[OFF_UNIX_SECONDS + 3],
                rec[OFF_UNIX_SECONDS + 4],
                rec[OFF_UNIX_SECONDS + 5],
                rec[OFF_UNIX_SECONDS + 6],
                rec[OFF_UNIX_SECONDS + 7],
            ]),
            uncertainty_ms: u32::from_le_bytes([
                rec[OFF_UNCERTAINTY_MS],
                rec[OFF_UNCERTAINTY_MS + 1],
                rec[OFF_UNCERTAINTY_MS + 2],
                rec[OFF_UNCERTAINTY_MS + 3],
            ]),
            monotonic_us: u64::from_le_bytes([
                rec[OFF_MONOTONIC_US],
                rec[OFF_MONOTONIC_US + 1],
                rec[OFF_MONOTONIC_US + 2],
                rec[OFF_MONOTONIC_US + 3],
                rec[OFF_MONOTONIC_US + 4],
                rec[OFF_MONOTONIC_US + 5],
                rec[OFF_MONOTONIC_US + 6],
                rec[OFF_MONOTONIC_US + 7],
            ]),
            source_epoch: u64::from_le_bytes([
                rec[OFF_SOURCE_EPOCH],
                rec[OFF_SOURCE_EPOCH + 1],
                rec[OFF_SOURCE_EPOCH + 2],
                rec[OFF_SOURCE_EPOCH + 3],
                rec[OFF_SOURCE_EPOCH + 4],
                rec[OFF_SOURCE_EPOCH + 5],
                rec[OFF_SOURCE_EPOCH + 6],
                rec[OFF_SOURCE_EPOCH + 7],
            ]),
            source_class: rec[OFF_SOURCE_CLASS],
            flags: rec[OFF_FLAGS],
        })
    }

    /// Whether this observation may be used for a wall-clock decision.
    ///
    /// Both conditions are required, and neither implies the other: a source
    /// can be present and unsynchronised (an RTC nobody set), and a
    /// deployment can decline to trust a source that *is* synchronised.
    /// `TRUSTED` is set by the provider from deployment policy and is never
    /// inferred here — inferring it would be this fragment deciding the thing
    /// it exists to ask about.
    #[must_use]
    pub fn is_trustworthy(&self) -> bool {
        self.source_class != SOURCE_UNAVAILABLE
            && (self.flags & FLAG_TRUSTED) != 0
            && (self.flags & FLAG_ROLLBACK_SUSPECT) == 0
    }
}

/// What a decision needs from the clock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Requirement {
    /// A trustworthy wall clock. Refuse without one.
    TrustedWallClock,
    /// A monotonic duration is enough — the decision is about elapsed time
    /// since something this process itself observed, not about a date.
    MonotonicDuration,
    /// An issuer-signed time observation carried in the request may stand in.
    SignedObservationAccepted,
}

/// The decisions this issuer makes that depend on time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    /// A credential's `iat` / `exp` window at verification.
    CredentialWindow,
    /// A DPoP proof's freshness.
    ProofFreshness,
    /// An X.509 path's validity period.
    CertificateValidity,
    /// An enrolment ceremony on a device that may have no RTC.
    EnrolmentCeremony,
    /// Retiring a verification key past its removal deadline.
    KeyRetirement,
    /// Expiring a replay or single-use record.
    ReplayRecordExpiry,
    /// A rate-limit bucket keyed by wall-clock period.
    RateLimitBucket,
}

/// What `decision` requires.
///
/// The two exceptions are argued rather than assumed:
///
/// - **`ProofFreshness`** may use a monotonic duration *only* when the proof
///   is bound to a server-issued nonce whose issuance this server timed
///   monotonically. Without that binding the proof carries a client-chosen
///   `iat` and only a real clock can bound it, so the caller that has no
///   nonce must treat this as `TrustedWallClock`.
/// - **`EnrolmentCeremony`** is the one place a device legitimately has no
///   clock: it is being enrolled precisely because it is new. An
///   issuer-signed observation carried inside the enrolment transaction,
///   bound to a locally measured monotonic deadline, is what lets the
///   ceremony complete without the device having to know the date.
///
/// **`ReplayRecordExpiry`** is monotonic because the record's own expiry is
/// authenticated data verified on read; the clock is only deciding when to
/// reclaim space, and reclaiming late is harmless where expiring early is
/// not.
#[must_use]
pub const fn requirement(decision: Decision) -> Requirement {
    match decision {
        Decision::CredentialWindow
        | Decision::CertificateValidity
        | Decision::KeyRetirement
        | Decision::RateLimitBucket => Requirement::TrustedWallClock,
        Decision::ProofFreshness | Decision::ReplayRecordExpiry => Requirement::MonotonicDuration,
        Decision::EnrolmentCeremony => Requirement::SignedObservationAccepted,
    }
}

/// Whether `observation` satisfies what `decision` needs.
///
/// A caller that gets `false` refuses; it does not fall back to a weaker
/// check. The whole reason this returns a bool rather than a "best effort
/// time" is that there is no such thing: a decision either has the evidence
/// it needs or it does not.
#[must_use]
pub fn permits(decision: Decision, observation: &Observation) -> bool {
    match requirement(decision) {
        Requirement::TrustedWallClock => observation.is_trustworthy(),
        // Monotonic time is always available: it is a counter this process
        // has been reading since it started.
        Requirement::MonotonicDuration => true,
        // The signed observation itself is verified by the caller — this
        // says only that the ceremony is allowed to accept one.
        Requirement::SignedObservationAccepted => true,
    }
}

/// Read the clock and answer whether `decision` may proceed on it.
///
/// The one call every migrated site makes. It returns `Some(seconds)` when
/// the observation satisfies what the decision needs, and `None` when it
/// does not — and `None` is a refusal, not a signal to fall back.
///
/// This shape exists because the shape it replaced could not refuse. Every
/// site was `dev_unix_millis(sys) / 1000`, which returns `0` on a platform
/// with no RTC — and `0` is a *number*, so it flowed into the comparison and
/// the comparison answered. A certificate's `not_after` is greater than 0,
/// so an expiry check against a missing clock concluded "not yet expired".
/// Thirteen sites made that mistake identically, because the API gave them
/// no way to make any other one.
///
/// `trusted_unix` is the raw 36-byte record from `dev_trusted_unix`.
#[must_use]
pub fn now_for(decision: Decision, trusted_unix: &[u8]) -> Option<u64> {
    let obs = Observation::decode(trusted_unix)?;
    if !permits(decision, &obs) {
        return None;
    }
    // A decision that needs only a monotonic duration still gets the wall
    // reading when there is one — it is the caller's own bookkeeping that
    // matters, and handing back a second time base would make two clocks
    // where the caller expects one.
    Some(obs.unix_seconds)
}

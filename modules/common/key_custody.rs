//! Key-custody policy: what isolation a signing key must have.
//!
//! `C5` — production signing requires an approved vault. This is where that
//! is enforced, and it is enforced as a **policy on the tier ordinal**
//! rather than on whether a backend answered.
//!
//! # Why the tier and not persistence
//!
//! It is tempting to treat "the key survives a restart" as the security
//! property, because that is the visible one. It is not. Where no
//! device-unique key exists, a persisted software key is sealed under
//! something the host can also read — so persistence buys confidentiality
//! against a compromised *module* and none against a compromised *host*.
//! That is exactly what [`TIER_SOFTWARE`] already says.
//!
//! So **persistence must never be read as raising the tier.** A backend that
//! learns to persist is the same backend it was; the ordinal is the truthful
//! signal and it does not move. A profile that needs isolation from the host
//! asks for the tier, gets refused when it is not there, and is never
//! consoled by durability.
//!
//! # Why refusing rather than falling back
//!
//! The alternative — issue with a software key and log a warning — produces
//! a deployment that believes its issuer key is protected when it is not.
//! Nothing downstream can tell the difference: the credentials verify
//! either way. A refusal is visible at configuration time, which is the
//! only point at which anyone can still act on it.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

/// Tier ordinals, mirroring `key_vault::tier`.
///
/// Ordered by what they isolate against, so a policy says "at least this"
/// rather than enumerating backends it would then have to be taught about.
pub const TIER_SOFTWARE: u8 = 0;
pub const TIER_PROCESS_HW: u8 = 1;
pub const TIER_DEVICE_HW: u8 = 2;

/// No backend answered at all. Distinct from `TIER_SOFTWARE`, which is a
/// backend that exists and isolates against a compromised module.
pub const TIER_NONE: u8 = 0xFF;

/// What a key is for. The requirement follows from this, not from the
/// caller's own opinion of how important it is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyRole {
    /// The issuer key every credential in the trust domain chains to.
    Issuer,
    /// A certificate authority key.
    CertificateAuthority,
    /// A workload identity key.
    Workload,
    /// A key used to sign an enrolment challenge — an artefact that
    /// authorises nothing and is only ever presented back to this issuer.
    EnrolmentChallenge,
    /// A key encrypting data at rest, where losing it loses the data and
    /// compromising it reads the data — but which authorises nobody.
    DataEncryption,
}

/// Whether this deployment is production.
///
/// A separate input from the role because the SAME role has different
/// requirements in the two: a development graph must be able to run on a
/// laptop with no HSM, and a production one must not. Conflating them
/// produces either a development environment nobody can start or a
/// production one with no floor — and the second failure is silent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Posture {
    Development,
    Production,
}

/// The minimum tier `role` requires under `posture`.
///
/// `EnrolmentChallenge` is the one role that takes `TIER_SOFTWARE` in
/// production, and it is argued rather than assumed: the artefact it signs
/// grants nothing. Someone who steals that key can forge a challenge, which
/// buys them a redemption attempt they must still pass a mailed code and a
/// proof of possession to complete. Requiring an HSM for it would price
/// enrolment out of deployments that can run everything else, for a key
/// whose compromise costs a rate-limited guess.
///
/// `DataEncryption` likewise: it protects confidentiality of stored data and
/// authorises nobody, so its floor is about the data's sensitivity rather
/// than about issuance, and that is the deployment's call.
#[must_use]
pub const fn required_tier(role: KeyRole, posture: Posture) -> u8 {
    match posture {
        // Development runs on whatever is there. The floor is `SOFTWARE`
        // rather than `NONE`, because a development graph with no vault at
        // all is one whose vault path is never exercised — and the first
        // time anyone runs it is then in production.
        Posture::Development => TIER_SOFTWARE,
        Posture::Production => match role {
            KeyRole::Issuer | KeyRole::CertificateAuthority | KeyRole::Workload => TIER_PROCESS_HW,
            KeyRole::EnrolmentChallenge | KeyRole::DataEncryption => TIER_SOFTWARE,
        },
    }
}

/// Whether a backend at `tier` may hold a key for `role`.
///
/// `TIER_NONE` satisfies nothing, including `Development`: a graph with no
/// vault has no custody at all, and the development floor exists precisely
/// so the vault path is exercised before production depends on it.
#[must_use]
pub const fn permits(role: KeyRole, posture: Posture, tier: u8) -> bool {
    if tier == TIER_NONE {
        return false;
    }
    tier >= required_tier(role, posture)
}

/// Why a key was refused, for an operator-facing log line.
///
/// Two distinct reasons, because they need different actions: one is "wire
/// a vault", the other is "wire a *better* vault", and an operator told
/// only "refused" will try the first when they need the second.
#[must_use]
pub const fn refusal_text(tier: u8) -> &'static [u8] {
    if tier == TIER_NONE {
        b"no key_vault backend is wired"
    } else {
        b"key_vault tier is below this role's production floor"
    }
}

/// Short stable token for a tier.
#[must_use]
pub const fn tier_text(tier: u8) -> &'static [u8] {
    match tier {
        TIER_SOFTWARE => b"software",
        TIER_PROCESS_HW => b"process-hw",
        TIER_DEVICE_HW => b"device-hw",
        _ => b"none",
    }
}

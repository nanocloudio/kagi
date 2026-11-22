//! Key-custody policy: what isolation a signing key must have.
//!
//! `C5` — production signing requires an approved vault. This is where that
//! is enforced, and it is enforced as a **policy on the custody ordinal**
//! rather than on whether a backend answered.
//!
//! # Why custody and not persistence
//!
//! It is tempting to treat "the key survives a restart" as the security
//! property, because that is the visible one. It is not. Where no
//! device-unique key exists, a persisted software key is sealed under
//! something the host can also read — so persistence buys confidentiality
//! against a compromised *module* and none against a compromised *host*.
//! That is exactly what [`CUSTODY_SOFTWARE`] already says.
//!
//! So **persistence must never be read as raising the custody.** A backend that
//! learns to persist is the same backend it was; the ordinal is the truthful
//! signal and it does not move. A profile that needs isolation from the host
//! asks for the custody, gets refused when it is not there, and is never
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

/// Custody ordinals, mirroring `key_vault::custody`.
///
/// Ordered by what they isolate against, so a policy says "at least this"
/// rather than enumerating backends it would then have to be taught about.
pub const CUSTODY_SOFTWARE: u8 = 0;
pub const CUSTODY_PROCESS_HW: u8 = 1;
pub const CUSTODY_DEVICE_HW: u8 = 2;

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
    /// The key signing key-custody transfer grants (`transfer_grant.rs`): a
    /// grant authorises a vault to move live TLS traffic secrets to a
    /// standby, so a stolen key moves them anywhere. Issuer-grade.
    TransferGrant,
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

/// The minimum custody `role` requires under `posture`.
///
/// `EnrolmentChallenge` is the one role that takes `CUSTODY_SOFTWARE` in
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
pub const fn required_custody(role: KeyRole, posture: Posture) -> u8 {
    match posture {
        // Development runs on whatever vault is there.
        Posture::Development => CUSTODY_SOFTWARE,
        Posture::Production => match role {
            KeyRole::Issuer
            | KeyRole::CertificateAuthority
            | KeyRole::Workload
            | KeyRole::TransferGrant => CUSTODY_PROCESS_HW,
            KeyRole::EnrolmentChallenge | KeyRole::DataEncryption => CUSTODY_SOFTWARE,
        },
    }
}

/// Whether a backend at `custody` may hold a key for `role`.
#[must_use]
pub const fn permits(role: KeyRole, posture: Posture, custody: u8) -> bool {
    custody >= required_custody(role, posture)
}

/// Why a key was refused, for an operator-facing log line: the vault every
/// signing module claims is there, and isolates less than the role needs.
pub const REFUSAL_TEXT: &[u8] = b"key_vault custody is below this role's production floor";

/// Short stable token for a custody ordinal.
#[must_use]
pub const fn custody_text(custody: u8) -> &'static [u8] {
    match custody {
        CUSTODY_SOFTWARE => b"software",
        CUSTODY_PROCESS_HW => b"process-hw",
        CUSTODY_DEVICE_HW => b"device-hw",
        _ => b"unknown",
    }
}

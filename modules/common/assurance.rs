//! Authentication assurance: what proofs backed a token, and how strong they
//! were.
//!
//! Without these claims a relying party can only ask "is this token valid",
//! which collapses every proof kagi accepts — an inbox round-trip, an
//! enclave-held device key, a passkey with user verification — onto one
//! answer. With them, sector, nanocloud and acorn can hold a cheap proof for
//! ordinary reads and demand a stronger one for a privileged operation,
//! without kagi knowing anything about the operation.
//!
//! Three claims are emitted, all standard:
//!
//! - `amr` — the authentication methods actually used (RFC 8176). Registered
//!   values are used where one exists; kagi's own values are listed in
//!   [`AuthMethod`].
//! - `acr` — the assurance level the combination reached: `aal1`, `aal2` or
//!   `aal3`, following the NIST SP 800-63B ladder.
//! - `auth_time` — when the proof was made (seconds since the Unix epoch),
//!   so a relying party can require a *recent* proof rather than merely a
//!   valid one.
//!
//! Pure `no_std` fragment: [`Evidence`] records what happened and
//! [`Evidence::level`] scores it; rendering the claims as JSON is the host's,
//! because a device has no allocator for a JSON map. Nothing here decides
//! policy — the relying party does, from the claims.
//!
//! The ladder is shared for the reason the ladder exists. kagi computes a
//! level and a relying party checks one, and those two are frequently not the
//! same process: sector evaluating an [`AssurancePolicy`] against a token
//! kagi minted must agree with kagi about what `aal2` means, or a policy
//! written to demand two factors quietly accepts one.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

/// A single authentication method, as reported in `amr`.
///
/// Values marked *(RFC 8176)* come from the IANA "Authentication Method
/// Reference Values" registry. The rest are kagi extensions, which the
/// registry explicitly permits; they are named for what they are rather than
/// bent onto an ill-fitting registered value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthMethod {
    /// Control of an email inbox was proven (kagi extension). The bootstrap
    /// factor: enough to bind a first device, never enough on its own for a
    /// privileged operation.
    Email,
    /// An operator-provisioned bootstrap token was presented (kagi
    /// extension). Node and workload admission, not human authentication.
    Bootstrap,
    /// Proof of possession of a private key (RFC 8176 `pop`) — a signed
    /// challenge or a `DPoP` proof.
    Pop,
    /// The proving key is held in software (RFC 8176 `swk`).
    Swk,
    /// The proving key is held in hardware: a secure enclave, a TPM, a FIDO2
    /// security key, or an HSM-backed slot (RFC 8176 `hwk`).
    Hwk,
    /// A one-time password from an authenticator app was verified
    /// (RFC 8176 `otp`).
    Otp,
    /// The user was verified locally by the authenticator, by PIN or
    /// biometric, before it would sign (RFC 8176 `user`).
    User,
    /// A `WebAuthn` assertion was verified (kagi extension). Implies the
    /// signature was bound to the relying-party origin, which is what makes
    /// it phishing-resistant.
    Webauthn,
    /// A recovery code was redeemed (kagi extension). Account recovery only;
    /// it never contributes to a level above [`AssuranceLevel::Aal1`].
    Recovery,
    /// More than one distinct factor was used (RFC 8176 `mfa`). Derived, not
    /// asserted by a caller: [`Evidence::claims`] adds it when the evidence
    /// warrants.
    Mfa,
}

impl AuthMethod {
    /// Every method, in the enum's own order — which is the order a set of
    /// them is reported in.
    pub const ALL: [Self; 10] = [
        Self::Email,
        Self::Bootstrap,
        Self::Pop,
        Self::Swk,
        Self::Hwk,
        Self::Otp,
        Self::User,
        Self::Webauthn,
        Self::Recovery,
        Self::Mfa,
    ];

    /// This method's place in the evidence bitset.
    const fn bit(self) -> u16 {
        1 << (self as u16)
    }

    /// The `amr` string for this method.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Bootstrap => "bootstrap",
            Self::Pop => "pop",
            Self::Swk => "swk",
            Self::Hwk => "hwk",
            Self::Otp => "otp",
            Self::User => "user",
            Self::Webauthn => "webauthn",
            Self::Recovery => "recovery",
            Self::Mfa => "mfa",
        }
    }

    /// Parse an `amr` entry. Unknown values return `None` and are dropped
    /// rather than carried forward, so a method this build does not
    /// understand can never contribute to a level it computes.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "email" => Some(Self::Email),
            "bootstrap" => Some(Self::Bootstrap),
            "pop" => Some(Self::Pop),
            "swk" => Some(Self::Swk),
            "hwk" => Some(Self::Hwk),
            "otp" => Some(Self::Otp),
            "user" => Some(Self::User),
            "webauthn" => Some(Self::Webauthn),
            "recovery" => Some(Self::Recovery),
            // Anything else — including `mfa`, which is derived from the
            // other methods rather than being a source of truth, so parsing
            // it back in would let a token inflate its own summary.
            _ => None,
        }
    }

    /// Which authentication factor category this method belongs to. Counting
    /// *distinct categories* is what separates genuine multi-factor
    /// authentication from two proofs of the same kind: a device key plus a
    /// `DPoP` proof from that same key is one factor presented twice.
    const fn factor(self) -> Option<Factor> {
        match self {
            // Something you have.
            Self::Email | Self::Pop | Self::Swk | Self::Hwk | Self::Webauthn => {
                Some(Factor::Possession)
            }
            // Something you know. A TOTP seed is a shared secret the user
            // carries, but it is entered from knowledge of the displayed
            // code, and it is an independent factor from the device key.
            Self::Otp | Self::Recovery => Some(Factor::Knowledge),
            // `user` covers both a PIN (knowledge) and a biometric
            // (inherence); it is scored through `user_verified` rather than
            // as a category of its own, so it does not double-count.
            Self::User | Self::Bootstrap | Self::Mfa => None,
        }
    }
}

/// Authentication factor categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Factor {
    /// Something you have.
    Possession,
    /// Something you know.
    Knowledge,
}

/// Where the proving key lives. The distinction is the whole basis of the
/// AAL3 claim: a key that can be exported is a key that can be stolen at a
/// distance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyBinding {
    /// No key was involved (an inbox round-trip, a bootstrap token).
    #[default]
    None,
    /// The key is held in software and could in principle be exported.
    Software,
    /// The key is non-exportable and held in hardware: a secure enclave, a
    /// TPM, a FIDO2 authenticator, or an HSM slot reached through the fluxor
    /// key vault.
    Hardware,
}

/// The assurance level a set of proofs reached, following NIST SP 800-63B.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssuranceLevel {
    /// Single factor. Enough to say who someone claims to be.
    Aal1,
    /// Two distinct factors, or one multi-factor cryptographic authenticator.
    Aal2,
    /// A hardware-bound, phishing-resistant, user-verified authenticator.
    Aal3,
}

impl AssuranceLevel {
    /// The `acr` string for this level.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aal1 => "aal1",
            Self::Aal2 => "aal2",
            Self::Aal3 => "aal3",
        }
    }

    /// Parse an `acr` claim. Unknown values are rejected rather than being
    /// treated as a floor, so a relying party can never be talked into
    /// accepting an unrecognised level.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "aal1" => Some(Self::Aal1),
            "aal2" => Some(Self::Aal2),
            "aal3" => Some(Self::Aal3),
            _ => None,
        }
    }
}

/// What actually happened during an authentication, and therefore what the
/// token may claim.
#[derive(Clone, Copy, Default, Debug)]
pub struct Evidence {
    /// Bit `n` set means the method with discriminant `n` was recorded.
    ///
    /// A bitset rather than a set: there are ten methods, a module has no
    /// allocator for a tree, and iterating the bits in order gives exactly
    /// the order a `BTreeSet<AuthMethod>` gave — the enum's own.
    methods: u16,
    key_binding: KeyBinding,
    user_verified: bool,
    phishing_resistant: bool,
    auth_time: u64,
}

impl Evidence {
    /// Start recording an authentication that completed at `auth_time`
    /// (seconds since the Unix epoch).
    pub fn at(auth_time: u64) -> Self {
        Self {
            auth_time,
            ..Self::default()
        }
    }

    /// Record that `method` was used.
    #[must_use]
    pub fn with(mut self, method: AuthMethod) -> Self {
        // `mfa` is derived in `claims`; accepting it from a caller would let
        // a miswired call site inflate the token's own summary of itself.
        if method != AuthMethod::Mfa {
            self.methods |= method.bit();
        }
        self
    }

    /// Record where the proving key lives.
    #[must_use]
    pub const fn key_binding(mut self, binding: KeyBinding) -> Self {
        self.key_binding = binding;
        self
    }

    /// Record that the authenticator verified the user locally (PIN or
    /// biometric) before it would sign. Also emits `user` in `amr`.
    #[must_use]
    pub fn user_verified(mut self, verified: bool) -> Self {
        self.user_verified = verified;
        if verified {
            self.methods |= AuthMethod::User.bit();
        }
        self
    }

    /// Record that the proof was bound to the relying party it was presented
    /// to, so it cannot be replayed against a different origin. True for a
    /// `WebAuthn` assertion (origin-bound client data) and for a
    /// channel-bound mTLS handshake.
    #[must_use]
    pub const fn phishing_resistant(mut self, resistant: bool) -> Self {
        self.phishing_resistant = resistant;
        self
    }

    /// When the proof was made.
    pub const fn auth_time(&self) -> u64 {
        self.auth_time
    }

    /// The methods recorded, in a stable order.
    pub fn methods(&self) -> impl Iterator<Item = AuthMethod> + '_ {
        AuthMethod::ALL
            .into_iter()
            .filter(|method| self.methods & method.bit() != 0)
    }

    /// Whether any method was recorded.
    pub const fn is_empty(&self) -> bool {
        self.methods == 0
    }

    /// How many distinct factor categories the evidence covers.
    fn distinct_factors(&self) -> usize {
        let mut possession = false;
        let mut knowledge = false;
        for method in self.methods() {
            match method.factor() {
                Some(Factor::Possession) => possession = true,
                Some(Factor::Knowledge) => knowledge = true,
                None => {}
            }
        }
        usize::from(possession) + usize::from(knowledge)
    }

    /// Score the evidence onto the assurance ladder.
    ///
    /// - **AAL3** needs all three of: a hardware-bound key, a proof bound to
    ///   this relying party, and local user verification. That is a FIDO2
    ///   security key or a platform passkey in an enclave — nothing softer
    ///   reaches it.
    /// - **AAL2** needs either two distinct factor categories, or a single
    ///   authenticator that is itself multi-factor: a hardware-bound key that
    ///   only signs after verifying the user.
    /// - **AAL1** is everything else, including any authentication that used
    ///   a recovery code — recovery re-establishes access, it does not
    ///   demonstrate the strength the lost authenticator had.
    pub fn level(&self) -> AssuranceLevel {
        if self.methods & AuthMethod::Recovery.bit() != 0 {
            return AssuranceLevel::Aal1;
        }

        let hardware = self.key_binding == KeyBinding::Hardware;

        if hardware && self.phishing_resistant && self.user_verified {
            return AssuranceLevel::Aal3;
        }

        let multi_factor_authenticator = hardware && self.user_verified;
        if multi_factor_authenticator || self.distinct_factors() >= 2 {
            return AssuranceLevel::Aal2;
        }

        AssuranceLevel::Aal1
    }
}

/// What a relying party demands of a token before honouring a request.
///
/// This is the resource-server half of the contract. kagi never sees it: the
/// policy is evaluated wherever the token is presented, against the claims
/// the token carries.
#[derive(Debug, Clone, Copy)]
pub struct AssurancePolicy {
    /// Lowest acceptable `acr`.
    pub min_level: AssuranceLevel,
    /// Longest tolerated age of `auth_time`, in seconds. `None` accepts any
    /// age, so long as the token itself is unexpired.
    pub max_age: Option<u64>,
    /// A method the token must report in `amr`, whatever its level. Use for
    /// operations that need one specific proof (for example a `WebAuthn`
    /// assertion) rather than a level.
    pub require_method: Option<AuthMethod>,
}

impl Default for AssurancePolicy {
    /// The default demands nothing beyond a valid token, preserving the
    /// behaviour of a relying party that has not opted in.
    fn default() -> Self {
        Self {
            min_level: AssuranceLevel::Aal1,
            max_age: None,
            require_method: None,
        }
    }
}

/// Why a token failed an [`AssurancePolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssuranceFailure {
    /// The token carried no `acr`, so its assurance is unknown. A policy
    /// above `aal1` refuses it rather than guessing.
    LevelUnknown,
    /// The token's level is below the policy's floor.
    LevelTooLow {
        required: AssuranceLevel,
        presented: AssuranceLevel,
    },
    /// The proof behind the token is older than the policy allows; the caller
    /// should re-authenticate (a step-up), not merely refresh the token.
    ProofTooOld { age: u64, max_age: u64 },
    /// A specifically required method was not among the token's `amr`.
    MethodMissing(AuthMethod),
}

impl AssurancePolicy {
    /// Require at least `level`.
    pub const fn at_least(level: AssuranceLevel) -> Self {
        Self {
            min_level: level,
            max_age: None,
            require_method: None,
        }
    }

    /// Also require the proof to be no older than `seconds`.
    #[must_use]
    pub const fn within(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// Also require a specific method.
    #[must_use]
    pub const fn requiring(mut self, method: AuthMethod) -> Self {
        self.require_method = Some(method);
        self
    }

    /// Check the policy against the assurance claims of a token that has
    /// already been verified (signature, issuer, audience, expiry).
    ///
    /// `acr` and `auth_time` are `Option` because a token minted before a
    /// deployment adopted these claims carries neither. A default policy
    /// accepts such a token; any policy above the floor refuses it, which is
    /// the safe direction — an unknown level is never treated as a high one.
    pub fn check(
        &self,
        acr: Option<&str>,
        amr: &[&str],
        auth_time: Option<u64>,
        now: u64,
    ) -> Result<(), AssuranceFailure> {
        if let Some(required) = self.require_method {
            if !amr.iter().any(|m| *m == required.as_str()) {
                return Err(AssuranceFailure::MethodMissing(required));
            }
        }

        if self.min_level > AssuranceLevel::Aal1 {
            let presented = acr
                .and_then(AssuranceLevel::parse)
                .ok_or(AssuranceFailure::LevelUnknown)?;
            if presented < self.min_level {
                return Err(AssuranceFailure::LevelTooLow {
                    required: self.min_level,
                    presented,
                });
            }
        }

        if let Some(max_age) = self.max_age {
            // A token with no `auth_time` cannot satisfy a freshness demand.
            let proved_at = auth_time.ok_or(AssuranceFailure::LevelUnknown)?;
            let age = now.saturating_sub(proved_at);
            if age > max_age {
                return Err(AssuranceFailure::ProofTooOld { age, max_age });
            }
        }

        Ok(())
    }
}

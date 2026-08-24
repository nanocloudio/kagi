//! `WebAuthn` (W3C Level 2) registration and assertion — the deterministic core.
//!
//! Pure `no_std` fragment. Everything here is parsing, structural validation
//! and binding checks; the two primitives that are not deterministic byte
//! work — SHA-256 and public-key signature verification — are injected, as in
//! [`crate::dpop`]. The same code therefore runs in a PIC module, in wasm,
//! and in the host suites that pin it.
//!
//! `WebAuthn` is structurally what kagi already does: a challenge is signed by
//! a key the client cannot export. The difference is what the browser adds on
//! top, and it is the part worth having:
//!
//! - the signature covers a hash of the client data, which names the
//!   **origin** the ceremony ran on, so an assertion produced against a
//!   phishing site does not verify here;
//! - the authenticator reports whether it checked **user presence** and
//!   **user verification** before signing;
//! - it reports a **signature counter**, which lets a relying party notice a
//!   cloned authenticator.
//!
//! Those three facts feed [`crate::assurance`] directly.
//!
//! Scope, stated plainly: attestation *statements* are parsed far enough to
//! read the credential out of them, and the `none` and `packed` formats are
//! recognised, but no attestation certificate chain is validated against a
//! metadata service. A deployment that must prove which authenticator model
//! produced a credential needs that additional step; kagi's enrollment gates
//! do not, because the credential's trust comes from the enrollment that
//! bound it, not from its manufacturer.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::cbor::{CborError, Reader};
use crate::jose;
use crate::jwk::Sha256Fn;

/// Flags byte of the authenticator data (`WebAuthn` §6.1).
pub const FLAG_USER_PRESENT: u8 = 0x01;
pub const FLAG_USER_VERIFIED: u8 = 0x04;
pub const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
pub const FLAG_BACKUP_STATE: u8 = 0x10;
pub const FLAG_ATTESTED_CREDENTIAL: u8 = 0x40;
pub const FLAG_EXTENSION_DATA: u8 = 0x80;

/// Fixed-size prefix of the authenticator data: `rpIdHash` (32) ‖ flags (1) ‖
/// `signCount` (4).
pub const AUTH_DATA_PREFIX: usize = 37;

/// COSE algorithm identifiers kagi accepts (IANA COSE Algorithms registry).
/// These are exactly the two curves the rest of kagi signs and verifies with.
pub const COSE_ALG_ES256: i64 = -7;
pub const COSE_ALG_EDDSA: i64 = -8;

/// COSE key type values.
pub const COSE_KTY_OKP: i64 = 1;
pub const COSE_KTY_EC2: i64 = 2;

/// COSE elliptic curve values.
pub const COSE_CRV_P256: i64 = 1;
pub const COSE_CRV_ED25519: i64 = 6;

/// Longest credential id accepted. The specification caps it at 1023 bytes;
/// authenticators in practice emit 16–64.
pub const MAX_CREDENTIAL_ID: usize = 1023;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WebauthnError {
    /// The attestation object or authenticator data was malformed.
    Malformed,
    /// A CBOR structure could not be read.
    Cbor(CborError),
    /// `type` in the client data was not the ceremony being performed —
    /// an assertion replayed into a registration, or the reverse.
    WrongCeremony,
    /// The client data did not echo the challenge that was issued. This is
    /// the freshness check.
    ChallengeMismatch,
    /// The ceremony ran on an origin this relying party does not serve.
    OriginMismatch,
    /// The authenticator data was not bound to this relying party's id.
    RelyingPartyMismatch,
    /// The authenticator did not report user presence.
    UserNotPresent,
    /// User verification was required and the authenticator did not report it.
    UserNotVerified,
    /// The credential carried no attested public key (registration only).
    MissingCredential,
    /// The credential's algorithm or curve is not one kagi verifies.
    UnsupportedAlgorithm,
    /// The signature did not verify under the credential's public key.
    BadSignature,
    /// The signature counter did not advance, which is what a cloned
    /// authenticator looks like.
    CounterReplay,
    /// A supplied buffer was too small.
    BufferTooSmall,
}

impl From<CborError> for WebauthnError {
    fn from(err: CborError) -> Self {
        Self::Cbor(err)
    }
}

/// Signature verification injected by the consumer:
/// `(algorithm, public_key, message, signature) -> ok`.
///
/// `algorithm` is the COSE identifier ([`COSE_ALG_ES256`] / [`COSE_ALG_EDDSA`])
/// so one function pointer covers both curves. `public_key` is the raw form
/// [`CoseKey::public_key`] produced: an uncompressed SEC1 point for P-256, or
/// the 32-byte compressed point for Ed25519. Host wires `p256`/
/// `ed25519-dalek`; a PIC module wires the fluxor SDK.
pub type VerifyFn = fn(i64, &[u8], &[u8], &[u8]) -> bool;

/// Which ceremony a piece of client data belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ceremony {
    /// `navigator.credentials.create()` — enrolling a new credential.
    Create,
    /// `navigator.credentials.get()` — authenticating with one.
    Get,
}

impl Ceremony {
    /// The `type` value the client data must carry (`WebAuthn` §5.8.1).
    pub const fn client_data_type(self) -> &'static [u8] {
        match self {
            Self::Create => b"webauthn.create",
            Self::Get => b"webauthn.get",
        }
    }
}

/// A credential's public key, read out of its COSE encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoseKey<'a> {
    /// COSE algorithm identifier.
    pub alg: i64,
    /// COSE key type.
    pub kty: i64,
    /// COSE curve identifier.
    pub crv: i64,
    /// The `x` coordinate (P-256) or the whole point (Ed25519).
    pub x: &'a [u8],
    /// The `y` coordinate; empty for Ed25519.
    pub y: &'a [u8],
}

/// Largest raw public key [`CoseKey::public_key`] emits: an uncompressed
/// SEC1 P-256 point (`0x04` ‖ x ‖ y).
pub const MAX_PUBLIC_KEY: usize = 65;

impl CoseKey<'_> {
    /// Check that this is a key kagi can verify with, and reject the
    /// mismatched combinations (an `ES256` label on an Ed25519 curve, say)
    /// that would otherwise reach the verifier as a confusing input.
    pub const fn check(&self) -> Result<(), WebauthnError> {
        match (self.alg, self.kty, self.crv) {
            (COSE_ALG_ES256, COSE_KTY_EC2, COSE_CRV_P256)
            | (COSE_ALG_EDDSA, COSE_KTY_OKP, COSE_CRV_ED25519) => Ok(()),
            _ => Err(WebauthnError::UnsupportedAlgorithm),
        }
    }

    /// Write the raw public key the [`VerifyFn`] expects into `out`, and
    /// return its length: an uncompressed SEC1 point for P-256, or the
    /// 32-byte point for Ed25519.
    pub fn public_key(&self, out: &mut [u8]) -> Result<usize, WebauthnError> {
        self.check()?;
        if self.alg == COSE_ALG_EDDSA {
            if self.x.len() != 32 {
                return Err(WebauthnError::Malformed);
            }
            if out.len() < 32 {
                return Err(WebauthnError::BufferTooSmall);
            }
            out[..32].copy_from_slice(self.x);
            return Ok(32);
        }

        if self.x.len() != 32 || self.y.len() != 32 {
            return Err(WebauthnError::Malformed);
        }
        if out.len() < MAX_PUBLIC_KEY {
            return Err(WebauthnError::BufferTooSmall);
        }
        out[0] = 0x04;
        out[1..33].copy_from_slice(self.x);
        out[33..65].copy_from_slice(self.y);
        Ok(MAX_PUBLIC_KEY)
    }
}

/// Parse a `COSE_Key` map (RFC 8152) — the form a credential public key takes
/// inside authenticator data.
pub fn parse_cose_key(bytes: &[u8]) -> Result<CoseKey<'_>, WebauthnError> {
    // Labels: 1 = kty, 3 = alg, -1 = crv, -2 = x, -3 = y.
    let mut kty = 0i64;
    let mut alg = 0i64;
    let mut crv = 0i64;
    let mut x: &[u8] = &[];
    let mut y: &[u8] = &[];

    let mut reader = Reader::new(bytes);
    let entries = reader.map_len()?;
    for _ in 0..entries {
        let label = reader.integer()?;
        match label {
            1 => kty = reader.integer()?,
            3 => alg = reader.integer()?,
            -1 => crv = reader.integer()?,
            -2 => x = reader.bytes()?,
            -3 => y = reader.bytes()?,
            _ => reader.skip_value()?,
        }
    }

    let key = CoseKey {
        alg,
        kty,
        crv,
        x,
        y,
    };
    key.check()?;
    Ok(key)
}

/// The credential an authenticator attested during registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestedCredential<'a> {
    /// The authenticator model identifier. All-zero for authenticators that
    /// decline to identify themselves, which is the common and privacy-
    /// preserving case for platform passkeys.
    pub aaguid: &'a [u8; 16],
    /// The credential id, echoed back on every later assertion.
    pub id: &'a [u8],
    /// The credential public key, still COSE-encoded.
    pub cose_key: &'a [u8],
}

/// Parsed authenticator data (`WebAuthn` §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatorData<'a> {
    /// SHA-256 of the relying party id the credential is scoped to.
    pub rp_id_hash: &'a [u8; 32],
    /// The raw flags byte.
    pub flags: u8,
    /// The authenticator's signature counter. Zero means the authenticator
    /// does not implement one.
    pub sign_count: u32,
    /// Present on registration; absent on assertion.
    pub credential: Option<AttestedCredential<'a>>,
}

impl AuthenticatorData<'_> {
    /// Whether the authenticator confirmed a human was present (a touch).
    pub const fn user_present(&self) -> bool {
        self.flags & FLAG_USER_PRESENT != 0
    }

    /// Whether the authenticator verified *which* human (PIN or biometric).
    /// This is the flag that separates a single-factor authenticator from a
    /// multi-factor one.
    pub const fn user_verified(&self) -> bool {
        self.flags & FLAG_USER_VERIFIED != 0
    }

    /// Whether the credential may be backed up (synced between the user's
    /// devices). A synced passkey is not hardware-bound to one device, so it
    /// cannot support a claim that rests on hardware binding.
    pub const fn backup_eligible(&self) -> bool {
        self.flags & FLAG_BACKUP_ELIGIBLE != 0
    }

    /// Whether the credential is currently backed up.
    pub const fn backed_up(&self) -> bool {
        self.flags & FLAG_BACKUP_STATE != 0
    }
}

/// Parse authenticator data. The attested-credential block is read only when
/// the `AT` flag says it is there.
pub fn parse_authenticator_data(data: &[u8]) -> Result<AuthenticatorData<'_>, WebauthnError> {
    if data.len() < AUTH_DATA_PREFIX {
        return Err(WebauthnError::Malformed);
    }
    let rp_id_hash: &[u8; 32] = data[..32]
        .try_into()
        .map_err(|_| WebauthnError::Malformed)?;
    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

    let mut parsed = AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        credential: None,
    };

    if flags & FLAG_ATTESTED_CREDENTIAL == 0 {
        return Ok(parsed);
    }

    // attestedCredentialData = aaguid(16) ‖ idLen(2) ‖ id ‖ COSE key.
    let rest = &data[AUTH_DATA_PREFIX..];
    if rest.len() < 18 {
        return Err(WebauthnError::Malformed);
    }
    let aaguid: &[u8; 16] = rest[..16]
        .try_into()
        .map_err(|_| WebauthnError::Malformed)?;
    let id_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
    if id_len == 0 || id_len > MAX_CREDENTIAL_ID {
        return Err(WebauthnError::Malformed);
    }
    let after_len = &rest[18..];
    if after_len.len() < id_len {
        return Err(WebauthnError::Malformed);
    }
    let id = &after_len[..id_len];
    let key_and_extensions = &after_len[id_len..];

    // The COSE key is the next complete CBOR item; anything after it is
    // extension data, which is not consumed here. Reading the item tells us
    // where it ends.
    let mut reader = Reader::new(key_and_extensions);
    reader.skip_value()?;
    let cose_key = &key_and_extensions[..reader.position()];

    parsed.credential = Some(AttestedCredential {
        aaguid,
        id,
        cose_key,
    });
    Ok(parsed)
}

/// An attestation object as returned by `navigator.credentials.create()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationObject<'a> {
    /// The attestation statement format: `none`, `packed`, and so on.
    pub fmt: &'a [u8],
    /// The authenticator data, still encoded.
    pub auth_data: &'a [u8],
}

/// Parse the CBOR attestation object down to the two fields kagi consumes.
/// The attestation statement itself is skipped: see the module note on scope.
pub fn parse_attestation_object(bytes: &[u8]) -> Result<AttestationObject<'_>, WebauthnError> {
    let mut fmt: &[u8] = &[];
    let mut auth_data: &[u8] = &[];

    let mut reader = Reader::new(bytes);
    let entries = reader.map_len()?;
    for _ in 0..entries {
        let key = reader.text()?;
        if key == b"fmt" {
            fmt = reader.text()?;
        } else if key == b"authData" {
            auth_data = reader.bytes()?;
        } else {
            reader.skip_value()?;
        }
    }

    if fmt.is_empty() || auth_data.is_empty() {
        return Err(WebauthnError::Malformed);
    }
    Ok(AttestationObject { fmt, auth_data })
}

/// Validate the client data JSON against the ceremony that was expected
/// (`WebAuthn` §7.1 steps 7–10, §7.2 steps 11–14).
///
/// `expected_challenge` is the base64url form of the challenge that was
/// issued, exactly as the browser echoes it. `origins` is the set the
/// relying party serves; a ceremony from any other origin is refused, which
/// is the property that makes `WebAuthn` phishing-resistant.
pub fn check_client_data(
    client_data_json: &[u8],
    ceremony: Ceremony,
    expected_challenge: &[u8],
    origins: &[&[u8]],
) -> Result<(), WebauthnError> {
    let found_type = jose::claim_str(client_data_json, b"type").ok_or(WebauthnError::Malformed)?;
    if found_type != ceremony.client_data_type() {
        return Err(WebauthnError::WrongCeremony);
    }

    let challenge =
        jose::claim_str(client_data_json, b"challenge").ok_or(WebauthnError::Malformed)?;
    if !fixed_time_eq(challenge, expected_challenge) {
        return Err(WebauthnError::ChallengeMismatch);
    }

    let origin = jose::claim_str(client_data_json, b"origin").ok_or(WebauthnError::Malformed)?;
    if !origins.contains(&origin) {
        return Err(WebauthnError::OriginMismatch);
    }

    Ok(())
}

/// Build the bytes a `WebAuthn` signature is computed over: the raw
/// authenticator data followed by SHA-256 of the client data JSON
/// (`WebAuthn` §6.3.3). Returns the length written into `out`.
pub fn signing_payload(
    sha256: Sha256Fn,
    auth_data: &[u8],
    client_data_json: &[u8],
    out: &mut [u8],
) -> Result<usize, WebauthnError> {
    let total = auth_data.len() + 32;
    if out.len() < total {
        return Err(WebauthnError::BufferTooSmall);
    }
    out[..auth_data.len()].copy_from_slice(auth_data);
    let mut digest = [0u8; 32];
    sha256(client_data_json, &mut digest);
    out[auth_data.len()..total].copy_from_slice(&digest);
    Ok(total)
}

/// What a relying party demands of a ceremony.
#[derive(Clone, Copy)]
pub struct CeremonyPolicy<'a> {
    /// The relying party id the credential must be scoped to (for example
    /// `id.example.com`). Checked as SHA-256 against `rpIdHash`.
    pub rp_id: &'a [u8],
    /// Origins the ceremony may have run on.
    pub origins: &'a [&'a [u8]],
    /// Whether the authenticator must report user verification. Required for
    /// any credential that is to count as more than a possession factor.
    pub require_user_verification: bool,
}

/// A verified registration, ready for the caller to persist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration<'a> {
    /// The credential id to store and to echo in later `allowCredentials`.
    pub credential_id: &'a [u8],
    /// The credential public key, COSE-encoded, to store.
    pub cose_key: &'a [u8],
    /// The authenticator model identifier, if it disclosed one.
    pub aaguid: &'a [u8; 16],
    /// The counter value to store as the baseline.
    pub sign_count: u32,
    /// Whether the authenticator verified the user.
    pub user_verified: bool,
    /// Whether this credential can sync to the user's other devices. A synced
    /// credential is not bound to one piece of hardware.
    pub backup_eligible: bool,
}

/// Verify a registration ceremony (`navigator.credentials.create()`).
///
/// No signature is checked here: with attestation format `none` — what a
/// platform passkey emits by default — there is no signature to check, and
/// the credential's trust comes from the enrollment gate that authorised the
/// ceremony. What *is* checked is that the credential is bound to this
/// relying party, answers the challenge that was issued, was created on an
/// allowed origin, and reports the user interaction the policy requires.
pub fn verify_registration<'a>(
    sha256: Sha256Fn,
    attestation_object: &'a [u8],
    client_data_json: &[u8],
    expected_challenge: &[u8],
    policy: &CeremonyPolicy<'_>,
) -> Result<Registration<'a>, WebauthnError> {
    check_client_data(
        client_data_json,
        Ceremony::Create,
        expected_challenge,
        policy.origins,
    )?;

    let attestation = parse_attestation_object(attestation_object)?;
    let auth_data = parse_authenticator_data(attestation.auth_data)?;
    check_binding(sha256, &auth_data, policy)?;

    let credential = auth_data
        .credential
        .ok_or(WebauthnError::MissingCredential)?;
    // Reject a key we could never verify an assertion with, at registration
    // rather than at first use.
    parse_cose_key(credential.cose_key)?;

    Ok(Registration {
        credential_id: credential.id,
        cose_key: credential.cose_key,
        aaguid: credential.aaguid,
        sign_count: auth_data.sign_count,
        user_verified: auth_data.user_verified(),
        backup_eligible: auth_data.backup_eligible(),
    })
}

/// A verified assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assertion {
    /// The counter the authenticator reported; store it and require the next
    /// assertion to exceed it.
    pub sign_count: u32,
    /// Whether the authenticator verified the user for this assertion.
    pub user_verified: bool,
    /// Whether the credential is currently synced.
    pub backed_up: bool,
}

/// Verify an assertion ceremony (`navigator.credentials.get()`).
///
/// `cose_key` is the stored credential public key; `stored_sign_count` is the
/// counter recorded at registration or at the previous assertion. A counter
/// that fails to advance is refused as [`WebauthnError::CounterReplay`] —
/// two authenticators sharing one credential is what that looks like. An
/// authenticator that reports a constant zero has no counter, and is exempt,
/// as the specification directs.
///
/// `payload` is scratch space for the signed bytes; it must hold
/// `auth_data.len() + 32`.
#[expect(
    clippy::too_many_arguments,
    reason = "one WebAuthn assertion check needs all of these inputs; splitting \
              them across calls would let a caller skip one"
)]
pub fn verify_assertion(
    sha256: Sha256Fn,
    verify: VerifyFn,
    auth_data_bytes: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
    cose_key: &[u8],
    expected_challenge: &[u8],
    policy: &CeremonyPolicy<'_>,
    stored_sign_count: u32,
    payload: &mut [u8],
) -> Result<Assertion, WebauthnError> {
    check_client_data(
        client_data_json,
        Ceremony::Get,
        expected_challenge,
        policy.origins,
    )?;

    let auth_data = parse_authenticator_data(auth_data_bytes)?;
    check_binding(sha256, &auth_data, policy)?;

    let key = parse_cose_key(cose_key)?;
    let mut public_key = [0u8; MAX_PUBLIC_KEY];
    let key_len = key.public_key(&mut public_key)?;

    let payload_len = signing_payload(sha256, auth_data_bytes, client_data_json, payload)?;
    if !verify(
        key.alg,
        &public_key[..key_len],
        &payload[..payload_len],
        signature,
    ) {
        return Err(WebauthnError::BadSignature);
    }

    // WebAuthn §7.2 step 21: if either counter is non-zero, the new one must
    // be strictly greater. Both zero means the authenticator keeps no
    // counter, which is permitted.
    if (auth_data.sign_count != 0 || stored_sign_count != 0)
        && auth_data.sign_count <= stored_sign_count
    {
        return Err(WebauthnError::CounterReplay);
    }

    Ok(Assertion {
        sign_count: auth_data.sign_count,
        user_verified: auth_data.user_verified(),
        backed_up: auth_data.backed_up(),
    })
}

/// The checks common to both ceremonies: the credential is scoped to this
/// relying party, and the user interaction the policy demands took place.
fn check_binding(
    sha256: Sha256Fn,
    auth_data: &AuthenticatorData<'_>,
    policy: &CeremonyPolicy<'_>,
) -> Result<(), WebauthnError> {
    let mut expected = [0u8; 32];
    sha256(policy.rp_id, &mut expected);
    if !fixed_time_eq(auth_data.rp_id_hash, &expected) {
        return Err(WebauthnError::RelyingPartyMismatch);
    }
    if !auth_data.user_present() {
        return Err(WebauthnError::UserNotPresent);
    }
    if policy.require_user_verification && !auth_data.user_verified() {
        return Err(WebauthnError::UserNotVerified);
    }
    Ok(())
}

/// Compare two byte strings without an early exit on the first difference.
/// Used for the challenge and the relying-party hash, both of which an
/// attacker would otherwise be able to probe a byte at a time.
fn fixed_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

// NOTE: `//` rather than `//!`, and no inner attributes.
//
// This fragment is `include!`d FLAT by sector's `surface_gate` — inner
// attributes and inner doc comments are illegal outside a module root, so
// a fragment that carries them can only ever be mounted one way. One
// source consumed by two repos has to mount both ways.
//
// The certificate-bound identity carrier.
//
// A short-lived JWS that a *client* signs with the private key of a
// kagi-issued SPIFFE leaf, carrying that leaf in the `x5c` header. It exists
// for a party that holds a key but cannot drive a TLS handshake with it — a
// browser using WebCrypto — so it proves the platform identity by signing
// rather than by handshaking.
//
// # This is not a JWT-SVID, and the file name is part of the fix
//
// It is deliberately NOT called `jwt_svid.rs`. A SPIFFE JWT-SVID is
// *issuer-signed*: the trust domain's authority mints it and a verifier
// checks it against that authority's JWKS. This is *subject-signed*: the
// holder mints it and a verifier checks it against a certificate chain. The
// two share a serialisation and share no trust model.
//
// Two files called `jwt_svid.rs`, one in kagi and one in sector, is how this
// came to be represented as a standard JWT-SVID in the first place — and
// then to be implemented twice, differently. The name here says what the
// thing actually is, so the next person to reach for "the SVID verifier"
// has to notice which one they mean.
//
// # What the two implementations each got wrong
//
// This fragment replaces sector's `modules/common/jwt_svid.rs`, and the
// reasons are specific rather than tidiness:
//
// - It called `verify_cert_signature(cert_der, ca_pubkey)` — a bare
//   signature check. That establishes that *something* signed the leaf. It
//   does not check the leaf's validity window, that the signer was a CA at
//   all (`basicConstraints`), that the signer was permitted to sign
//   certificates (`keyUsage`), or that the leaf was authorised for client
//   authentication (`extendedKeyUsage`). A CA that had expired, or a leaf
//   issued for TLS *serving* and presented as a client identity, both
//   passed. [`verify`] composes fluxor's `verify_chain` under
//   `PROFILE_CA_URI` instead, which checks all of it.
// - `jti` was optional. A token carrying none verified, and the caller's
//   replay cache then keyed on an empty value — so either every such token
//   collided with every other, or none did, depending on the cache. Here a
//   missing or empty `jti` is a refusal.
// - `iat` was not checked at all, only `exp`. A token stamped far in the
//   future verified.
// - `exp - iat` was unbounded. A ten-year "short-lived" token verified.
//
// # What a caller still owns
//
// Replay. This returns the `jti` and the `exp` that bounds how long it must
// be remembered; recording it is the caller's, because the store that can
// answer "seen before" across replicas is not something a pure verifier
// holds.

/// Longest SPIFFE id accepted. A trust domain plus a workload path; longer
/// than a hostname, which is why it does not borrow a DNS bound.
pub const MAX_SPIFFE: usize = 256;
/// Longest `jti`. Bounded because it is copied into a fixed record and a
/// truncated `jti` would collide with every other token sharing its prefix.
pub const MAX_JTI: usize = 64;
/// Longest `x5c` leaf certificate accepted, in DER.
pub const MAX_LEAF_DER: usize = 2048;
/// Longest decoded JOSE header.
pub const MAX_HEADER: usize = 3072;
/// Longest decoded claims segment.
pub const MAX_CLAIMS: usize = 1024;

/// Accepted clock skew on `iat`, in seconds.
///
/// A token may be stamped up to this far in the future before it is refused.
/// Applied only to `iat`: `exp` gets no grace, because extending a
/// credential's life is the direction that costs something.
pub const MAX_IAT_SKEW: u64 = 300;

/// Longest lifetime a carrier may claim, in seconds.
///
/// The point of this carrier is that it is short-lived — it is the
/// compensating control for a key a browser holds and cannot protect the way
/// a TPM does. A carrier with a long lifetime is a bearer credential with
/// extra steps, so one is refused rather than accepted and worried about.
pub const MAX_LIFETIME_SECS: u64 = 600;

/// Why a carrier was refused.
///
/// Typed, and specific, because these are operator-facing: "malformed" for
/// an expired CA sends someone to inspect a token that is fine.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CarrierError {
    /// Not a compact JWS, or a segment did not base64url-decode.
    Malformed,
    /// The header named an algorithm this carrier does not accept.
    UnsupportedAlg,
    /// No `x5c`, or its leaf did not parse as DER.
    NoCertificate,
    /// The leaf did not validate to the trust anchor under the profile.
    /// `code` is the `CERT_ERR_*` reason.
    Chain { code: u32 },
    /// The JWS signature did not verify under the leaf's key.
    BadSignature,
    /// A required claim was absent or empty.
    MissingClaim,
    /// `aud` did not match.
    WrongAudience,
    /// `iss` is not a URI SAN the leaf actually carries.
    NotInCertificate,
    /// Outside its validity window, or stamped too far ahead.
    Expired,
    /// The claimed lifetime exceeds [`MAX_LIFETIME_SECS`].
    LifetimeTooLong,
    /// A field did not fit its bound.
    Overflow,
}

/// A verified carrier.
pub struct CertBoundIdentity {
    /// `SHA-256` of the leaf's raw subject public key — the key pin, and
    /// byte-identical to the fingerprint fluxor's TLS module derives, so a
    /// caller can compare an mTLS peer and a carrier peer directly.
    pub key_fingerprint: [u8; 32],
    /// The SPIFFE id: the leaf SAN URI, which `iss` and `sub` both equal.
    pub spiffe_id: [u8; MAX_SPIFFE],
    pub spiffe_len: usize,
    /// The replay id. Never empty in a verified carrier.
    pub jti: [u8; MAX_JTI],
    pub jti_len: usize,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl CertBoundIdentity {
    #[must_use]
    pub fn spiffe(&self) -> &[u8] {
        &self.spiffe_id[..self.spiffe_len]
    }

    #[must_use]
    pub fn replay_id(&self) -> &[u8] {
        &self.jti[..self.jti_len]
    }
}

/// What the carrier must satisfy.
pub struct CarrierPolicy<'a> {
    /// DER of the trust anchor the leaf must chain to.
    pub anchor_der: &'a [u8],
    /// This service's audience. Never empty: a carrier accepted with no
    /// audience rule is a carrier any service will accept, which is the
    /// confused-deputy shape.
    pub audience: &'a [u8],
    /// Seconds since the Unix epoch.
    pub now_unix_secs: u64,
    /// Whether the leaf's own validity window must be enforced. False only
    /// where the platform has no trustworthy clock — and then the carrier's
    /// own `exp` is still checked, because that is what bounds the damage.
    pub require_clock: bool,
}

/// Crypto injected by the host module, so this fragment mounts anywhere the
/// primitives do.
pub type Sha256Fn = fn(&[u8], &mut [u8; 32]);
pub type EcdsaVerifyFn = fn(&[u8], &[u8; 32], &[u8; 64]) -> bool;
/// `verify_chain(cert_msg_body, anchor_der, expected_uri, now, require_clock)`
/// → a `CERT_ERR_*` code, `0` for OK. Wraps fluxor's `verify_chain` under
/// `PROFILE_CA_URI` so this fragment need not mount the whole TLS module.
pub type VerifyChainFn = fn(&[u8], &[u8], &[u8], u64, bool) -> u32;
/// `leaf_public_key(cert_der, out) -> Option<len>` — the subject public key
/// of a parsed certificate.
///
/// Injected, and taking a destination buffer, so this fragment never holds a
/// borrow into DER it did not validate. It is only ever called AFTER
/// `verify_chain` has returned OK.
pub type LeafPublicKeyFn = fn(&[u8], &mut [u8; 65]) -> Option<usize>;

pub struct CarrierVerifiers {
    pub sha256: Sha256Fn,
    pub ecdsa_verify: EcdsaVerifyFn,
    pub verify_chain: VerifyChainFn,
    pub leaf_public_key: LeafPublicKeyFn,
}

fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y)
}

/// Verify a certificate-bound carrier.
///
/// The order is the contract, and it is chain-before-anything-else: nothing
/// is read out of the certificate until the certificate has been validated,
/// so no value taken from it can be a value an unvalidated certificate
/// supplied.
pub fn verify(
    v: &CarrierVerifiers,
    token: &[u8],
    policy: &CarrierPolicy<'_>,
) -> Result<CertBoundIdentity, CarrierError> {
    if policy.audience.is_empty() || policy.anchor_der.is_empty() {
        // A policy with no audience or no anchor cannot be satisfied, and
        // treating either as "no rule" would accept everything.
        return Err(CarrierError::MissingClaim);
    }

    let jws = jose::Jws::split(token).ok_or(CarrierError::Malformed)?;

    // ── header ───────────────────────────────────────────────────────────
    let mut header = [0u8; MAX_HEADER];
    let hn = b64::decode(jws.header_b64, &mut header).ok_or(CarrierError::Malformed)?;
    let header = &header[..hn];
    let alg = jose::claim_str(header, b"alg").ok_or(CarrierError::MissingClaim)?;
    if !bytes_eq(alg, b"ES256") {
        return Err(CarrierError::UnsupportedAlg);
    }

    let x5c = jose::claim_array_first_str(header, b"x5c").ok_or(CarrierError::NoCertificate)?;
    let mut leaf = [0u8; MAX_LEAF_DER];
    let leaf_len = b64::decode_standard(x5c, &mut leaf).ok_or(CarrierError::NoCertificate)?;
    let leaf_der = &leaf[..leaf_len];

    // ── claims, read but not yet trusted ─────────────────────────────────
    //
    // `iss` is needed BEFORE the chain check, because it is the name the
    // chain must be validated against — the URI-SAN profile takes the
    // expected name as an input rather than reading one out afterwards. That
    // ordering is what stops a leaf being validated and then quietly
    // supplying whatever name it likes.
    let mut claims_buf = [0u8; MAX_CLAIMS];
    let cn = b64::decode(jws.payload_b64, &mut claims_buf).ok_or(CarrierError::Malformed)?;
    let claims = &claims_buf[..cn];

    let iss = jose::claim_str(claims, b"iss").ok_or(CarrierError::MissingClaim)?;
    if iss.is_empty() || iss.len() > MAX_SPIFFE {
        return Err(CarrierError::Overflow);
    }

    // ── the chain ────────────────────────────────────────────────────────
    //
    // A full path validation under `PROFILE_CA_URI`, not a bare signature
    // check. This is the whole difference between "somebody signed this
    // leaf" and "this leaf is a client identity from our trust domain,
    // inside its validity window, issued by something that was a CA".
    //
    // The certificate message is one certificate: this carrier presents a
    // leaf, never a chain, because a client that could supply intermediates
    // could supply a path the anchor was never meant to reach.
    let mut cert_msg = [0u8; 4 + MAX_LEAF_DER + 8];
    let msg_len = write_cert_message(leaf_der, &mut cert_msg).ok_or(CarrierError::Overflow)?;
    let rc = (v.verify_chain)(
        &cert_msg[..msg_len],
        policy.anchor_der,
        iss,
        policy.now_unix_secs,
        policy.require_clock,
    );
    if rc != 0 {
        return Err(CarrierError::Chain { code: rc });
    }

    // Everything below reads a certificate that has been validated.
    let mut pubkey = [0u8; 65];
    let pk_len = (v.leaf_public_key)(leaf_der, &mut pubkey).ok_or(CarrierError::NoCertificate)?;
    if pk_len == 0 || pk_len > 65 {
        return Err(CarrierError::NoCertificate);
    }
    let cert = &pubkey[..pk_len];

    // ── the signature ────────────────────────────────────────────────────
    let mut sig = [0u8; 64];
    if b64::decode(jws.signature_b64, &mut sig) != Some(64) {
        return Err(CarrierError::Malformed);
    }
    let mut hash = [0u8; 32];
    (v.sha256)(jws.signing_input, &mut hash);
    if !(v.ecdsa_verify)(cert, &hash, &sig) {
        return Err(CarrierError::BadSignature);
    }

    // ── the claims, now that the signer is established ───────────────────
    let aud = jose::claim_str(claims, b"aud").ok_or(CarrierError::MissingClaim)?;
    if !bytes_eq(aud, policy.audience) {
        return Err(CarrierError::WrongAudience);
    }

    let sub = jose::claim_str(claims, b"sub").ok_or(CarrierError::MissingClaim)?;
    if !bytes_eq(sub, iss) {
        // Subject-signed: the signer and the subject are the same party, so
        // a carrier naming a different `sub` is naming somebody else's
        // identity with its own key.
        return Err(CarrierError::NotInCertificate);
    }

    // `jti` is REQUIRED, and required non-empty. It used to be optional, so
    // a carrier without one verified and the caller's replay cache keyed on
    // an empty value — every such carrier colliding, or none, depending on
    // the cache.
    let jti = jose::claim_str(claims, b"jti").ok_or(CarrierError::MissingClaim)?;
    if jti.is_empty() {
        return Err(CarrierError::MissingClaim);
    }
    if jti.len() > MAX_JTI {
        // Refused rather than truncated: a truncated `jti` collides with
        // every other carrier sharing its prefix, which turns the replay
        // cache into a denial of service against the honest holder.
        return Err(CarrierError::Overflow);
    }

    // `iat` is REQUIRED and enforced. Only `exp` used to be checked, so a
    // carrier stamped far in the future verified — and then verified again
    // for as long as its `exp` allowed.
    let iat = jose::claim_u64(claims, b"iat").ok_or(CarrierError::MissingClaim)?;
    let exp = jose::claim_u64(claims, b"exp").ok_or(CarrierError::MissingClaim)?;
    let now = policy.now_unix_secs;
    if iat > now.saturating_add(MAX_IAT_SKEW) {
        return Err(CarrierError::Expired);
    }
    if exp <= now || exp <= iat {
        return Err(CarrierError::Expired);
    }
    if exp - iat > MAX_LIFETIME_SECS {
        return Err(CarrierError::LifetimeTooLong);
    }

    let mut out = CertBoundIdentity {
        key_fingerprint: [0u8; 32],
        spiffe_id: [0u8; MAX_SPIFFE],
        spiffe_len: iss.len(),
        jti: [0u8; MAX_JTI],
        jti_len: jti.len(),
        issued_at: iat,
        expires_at: exp,
    };
    (v.sha256)(cert, &mut out.key_fingerprint);
    out.spiffe_id[..iss.len()].copy_from_slice(iss);
    out.jti[..jti.len()].copy_from_slice(jti);
    Ok(out)
}

/// Wrap one DER certificate as a TLS Certificate message body, which is what
/// `verify_chain` takes.
///
/// `[context_len: 0][list_len: u24][cert_len: u24][cert][ext_len: u16 = 0]`.
fn write_cert_message(der: &[u8], out: &mut [u8]) -> Option<usize> {
    let entry = 3 + der.len() + 2;
    let total = 1 + 3 + entry;
    if out.len() < total || der.len() > 0x00FF_FFFF {
        return None;
    }
    out[0] = 0; // empty certificate_request_context
    out[1] = (entry >> 16) as u8;
    out[2] = (entry >> 8) as u8;
    out[3] = entry as u8;
    out[4] = (der.len() >> 16) as u8;
    out[5] = (der.len() >> 8) as u8;
    out[6] = der.len() as u8;
    out[7..7 + der.len()].copy_from_slice(der);
    out[7 + der.len()] = 0;
    out[8 + der.len()] = 0;
    Some(total)
}

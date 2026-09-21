// cert_bound_identity — verify a certificate-bound identity carrier.
//
// A browser cannot drive mTLS with a WebCrypto key, so it proves a platform
// identity the other way round: it SIGNS a short-lived JWS with the key its
// certificate names, and carries the certificate chain in the JOSE header.
// This fragment decides whether that carrier is a valid presentation of the
// identity it claims, and reports the same identity mTLS would have — the
// SPIFFE name in the leaf, and the key pin `SHA-256(leaf public key)`.
//
// kagi owns it because kagi owns what an identity claim is. Relying parties
// (sector's surface gate today) include this file rather than keeping a
// parser each, so one set of rules decides admission everywhere.
//
// `include!`-style: no inner attributes, so it flat-includes anywhere. The
// including context provides `b64` and `jose` (kagi-common) and supplies the
// crypto and chain validation by injection through `CarrierVerifiers` — this
// file links nothing and allocates nothing.
//
// What it decides, in order, refusing at the first failure:
//
//   1. The carrier is a compact JWS whose header names `ES256` and carries
//      an `x5c` chain.
//   2. The claims are complete and live: `aud` is this relying party, `jti`
//      is present (a carrier with no replay identifier cannot be replay
//      checked at all), `iat` is not in the future and `exp` is, and the
//      lifetime between them is bounded.
//   3. The chain validates to the anchor under the URI-SAN profile against
//      the SPIFFE id the claims assert — so the chain is validated against
//      the identity being claimed, never validated first and asked for a
//      name second.
//   4. The signature verifies under the leaf's public key. The key is taken
//      from the certificate, never from the header, which is the
//      key-confusion path.
//
// What it does NOT decide: replay. That window is stateful and belongs to
// the caller, which passes `replay_id()` to its own cache.

/// Hash `data` into `out`.
pub type CarrierSha256Fn = fn(&[u8], &mut [u8; 32]);
/// Verify an ECDSA P-256 signature (`r‖s`, 64 bytes) over `hash` under an
/// uncompressed public point.
pub type CarrierEcdsaVerifyFn = fn(&[u8], &[u8; 32], &[u8; 64]) -> bool;
/// Validate a TLS-framed certificate chain to `anchor_der` under the URI-SAN
/// profile, requiring `expected_uri` of the leaf. Answers 0 on success and
/// the profile's own reason code otherwise.
pub type CarrierVerifyChainFn = fn(&[u8], &[u8], &[u8], u64, bool) -> u32;
/// Copy the leaf's uncompressed public point out of a DER certificate,
/// answering its length.
pub type CarrierLeafKeyFn = fn(&[u8], &mut [u8; 65]) -> Option<usize>;

/// The primitives this fragment is given rather than links. On target these
/// are the SDK's and the TLS module's; on the host they are the same ones the
/// relying party already holds.
#[derive(Clone, Copy)]
pub struct CarrierVerifiers {
    pub sha256: CarrierSha256Fn,
    pub ecdsa_verify: CarrierEcdsaVerifyFn,
    pub verify_chain: CarrierVerifyChainFn,
    pub leaf_public_key: CarrierLeafKeyFn,
}

/// What the relying party requires of a carrier.
pub struct CarrierPolicy<'a> {
    /// The platform CA, WHOLE. A raw public point carries no validity window
    /// and no extensions, so none of the chain rules could be checked from
    /// one.
    pub anchor_der: &'a [u8],
    /// The `aud` this relying party answers to.
    pub audience: &'a [u8],
    /// Seconds since the Unix epoch.
    pub now_unix_secs: u64,
    /// Whether certificate lifetimes must be enforced. A relying party with
    /// no trusted clock says so here rather than comparing against 1970.
    pub require_clock: bool,
}

/// Why a carrier was refused. Each variant is a distinct direction, so a
/// caller can count and answer them apart: "this is not our carrier" is not
/// "this is our carrier, presented by someone who does not hold its key".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CarrierError {
    /// Not a compact JWS, not `ES256`, or no `x5c`.
    Malformed,
    /// A segment or certificate did not fit this fragment's buffers.
    Overflow,
    /// A claim is missing, this relying party is not the audience, or the
    /// window is not live.
    Claims,
    /// The chain does not validate to the anchor for the claimed identity.
    Chain,
    /// The chain is good and the signature is not the leaf key's.
    Signature,
}

/// Longest SPIFFE id carried.
pub const CARRIER_SPIFFE_MAX: usize = 96;
/// Longest `jti` carried.
pub const CARRIER_JTI_MAX: usize = 48;
/// Longest JOSE header this fragment decodes.
const HEADER_MAX: usize = 2048;
/// Longest claims set this fragment decodes.
const CLAIMS_MAX: usize = 1024;
/// Longest certificate accepted in `x5c`, in DER.
const CERT_MAX: usize = 1600;
/// Certificates read from `x5c`: a leaf and one intermediate. The anchor is
/// configured, not carried.
const CHAIN_MAX: usize = 2;
/// The chain as a TLS Certificate message body: per certificate a 3-byte
/// length and a 2-byte extensions field, plus the 1-byte context and the
/// 3-byte list length.
const CERT_MSG_MAX: usize = 4 + CHAIN_MAX * (3 + CERT_MAX + 2);
/// The longest a carrier may be valid for. A carrier is a proof of
/// possession made moments ago, not a session.
const LIFETIME_MAX_SECS: u64 = 300;

/// A verified certificate-bound identity: the same identity mTLS would have
/// produced from the same certificate.
pub struct CertBoundIdentity {
    /// `SHA-256` of the leaf's public key — the key pin.
    pub svid: [u8; 32],
    spiffe: [u8; CARRIER_SPIFFE_MAX],
    spiffe_len: usize,
    jti: [u8; CARRIER_JTI_MAX],
    jti_len: usize,
    /// The carrier's `exp`, in seconds since the Unix epoch. The caller's
    /// replay cache holds the identifier until then and no longer.
    pub expires_at: u64,
}

impl CertBoundIdentity {
    /// The SPIFFE id the chain carries and the claims assert.
    pub fn spiffe(&self) -> &[u8] {
        &self.spiffe[..self.spiffe_len]
    }

    /// The identifier a caller's replay cache is keyed on.
    pub fn replay_id(&self) -> &[u8] {
        &self.jti[..self.jti_len]
    }
}

/// Byte equality, without the slice helper's early exit on length alone
/// being the only comparison a reader has to trust.
fn carrier_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Frame `certs` as a TLS 1.3 Certificate message body, which is what a
/// chain validator reads: `[ctx_len][list_len:u24]([cert_len:u24][cert][ext_len:u16])*`.
fn frame_cert_msg(certs: &[&[u8]], out: &mut [u8; CERT_MSG_MAX]) -> Option<usize> {
    let mut body = 0usize;
    for cert in certs {
        body += 3 + cert.len() + 2;
    }
    let total = 4 + body;
    if total > out.len() || body > 0xFF_FFFF {
        return None;
    }
    out[0] = 0; // no certificate_request_context
    out[1] = (body >> 16) as u8;
    out[2] = (body >> 8) as u8;
    out[3] = body as u8;
    let mut at = 4;
    for cert in certs {
        let n = cert.len();
        out[at] = (n >> 16) as u8;
        out[at + 1] = (n >> 8) as u8;
        out[at + 2] = n as u8;
        at += 3;
        out[at..at + n].copy_from_slice(cert);
        at += n;
        out[at] = 0;
        out[at + 1] = 0;
        at += 2;
    }
    Some(at)
}

/// Verify `carrier` against `policy`, answering the identity it proves.
///
/// The caller must still refuse a replayed `replay_id()`: this fragment is
/// stateless and cannot see a second presentation of a carrier that was
/// valid the first time.
pub fn verify(
    v: &CarrierVerifiers,
    carrier: &[u8],
    policy: &CarrierPolicy<'_>,
) -> Result<CertBoundIdentity, CarrierError> {
    let jws = jose::Jws::split(carrier).ok_or(CarrierError::Malformed)?;

    // ── 1. header: the algorithm and the chain it carries ─────────────────
    let mut header = [0u8; HEADER_MAX];
    let hn = b64::decode(jws.header_b64, &mut header).ok_or(CarrierError::Overflow)?;
    let header = &header[..hn];
    let alg = jose::claim_str(header, b"alg").ok_or(CarrierError::Malformed)?;
    if !carrier_bytes_eq(alg, b"ES256") {
        return Err(CarrierError::Malformed);
    }
    let x5c = jose::claim_array(header, b"x5c").ok_or(CarrierError::Malformed)?;
    let mut der = [[0u8; CERT_MAX]; CHAIN_MAX];
    let mut der_len = [0usize; CHAIN_MAX];
    let mut chain_n = 0usize;
    for entry in x5c {
        if chain_n == CHAIN_MAX {
            return Err(CarrierError::Overflow);
        }
        // `x5c` is standard base64, not the URL-safe alphabet the segments
        // use (RFC 7515 §4.1.6).
        let n = b64::decode_standard(entry, &mut der[chain_n]).ok_or(CarrierError::Overflow)?;
        if n == 0 {
            return Err(CarrierError::Malformed);
        }
        der_len[chain_n] = n;
        chain_n += 1;
    }
    if chain_n == 0 {
        return Err(CarrierError::Malformed);
    }

    // ── 2. claims: complete, ours, and live ───────────────────────────────
    let mut claims = [0u8; CLAIMS_MAX];
    let cn = b64::decode(jws.payload_b64, &mut claims).ok_or(CarrierError::Overflow)?;
    let claims = &claims[..cn];
    let aud = jose::claim_str(claims, b"aud").ok_or(CarrierError::Claims)?;
    if !carrier_bytes_eq(aud, policy.audience) {
        return Err(CarrierError::Claims);
    }
    let iss = jose::claim_str(claims, b"iss").ok_or(CarrierError::Claims)?;
    if iss.is_empty() || iss.len() > CARRIER_SPIFFE_MAX {
        return Err(CarrierError::Claims);
    }
    // A carrier with no `jti` cannot be replay checked, so it is refused
    // here rather than admitted once and unbounded times after.
    let jti = jose::claim_str(claims, b"jti").ok_or(CarrierError::Claims)?;
    if jti.is_empty() || jti.len() > CARRIER_JTI_MAX {
        return Err(CarrierError::Claims);
    }
    let iat = jose::claim_u64(claims, b"iat").ok_or(CarrierError::Claims)?;
    let exp = jose::claim_u64(claims, b"exp").ok_or(CarrierError::Claims)?;
    let now = policy.now_unix_secs;
    if exp <= iat || exp.saturating_sub(iat) > LIFETIME_MAX_SECS {
        return Err(CarrierError::Claims);
    }
    if policy.require_clock && (exp <= now || iat > now) {
        return Err(CarrierError::Claims);
    }

    // ── 3. the chain, against the identity being claimed ──────────────────
    let mut certs: [&[u8]; CHAIN_MAX] = [&[]; CHAIN_MAX];
    for i in 0..chain_n {
        certs[i] = &der[i][..der_len[i]];
    }
    let mut cert_msg = [0u8; CERT_MSG_MAX];
    let msg_len = frame_cert_msg(&certs[..chain_n], &mut cert_msg).ok_or(CarrierError::Overflow)?;
    if (v.verify_chain)(
        &cert_msg[..msg_len],
        policy.anchor_der,
        iss,
        now,
        policy.require_clock,
    ) != 0
    {
        return Err(CarrierError::Chain);
    }

    // ── 4. the signature, under the leaf's own key ────────────────────────
    let mut public = [0u8; 65];
    let pn = (v.leaf_public_key)(certs[0], &mut public).ok_or(CarrierError::Chain)?;
    let public = &public[..pn];
    let mut raw_sig = [0u8; 64];
    let sn = b64::decode(jws.signature_b64, &mut raw_sig).ok_or(CarrierError::Overflow)?;
    if sn != raw_sig.len() {
        return Err(CarrierError::Signature);
    }
    let mut signed = [0u8; 32];
    (v.sha256)(jws.signing_input, &mut signed);
    if !(v.ecdsa_verify)(public, &signed, &raw_sig) {
        return Err(CarrierError::Signature);
    }

    let mut svid = [0u8; 32];
    (v.sha256)(public, &mut svid);
    let mut out = CertBoundIdentity {
        svid,
        spiffe: [0; CARRIER_SPIFFE_MAX],
        spiffe_len: iss.len(),
        jti: [0; CARRIER_JTI_MAX],
        jti_len: jti.len(),
        expires_at: exp,
    };
    out.spiffe[..iss.len()].copy_from_slice(iss);
    out.jti[..jti.len()].copy_from_slice(jti);
    Ok(out)
}

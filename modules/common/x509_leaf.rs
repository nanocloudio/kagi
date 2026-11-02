//! Reading an X.509 leaf that this authority issued, and checking it chains
//! to the authority — the one chain shape kagi's CA produces.
//!
//! `certificate_endpoint` issues every leaf directly under the CA: there are
//! no intermediates, so a chain is a leaf and an anchor, and validating it
//! is verifying one signature. That is what a module needs in order to
//! accept a cert-bound identity carrier (`cert_bound_identity.rs`) — whose
//! chain validation is injected — without a general X.509 path builder,
//! which no `no_std` module has and none of kagi's own chains would use.
//!
//! What is read: the `TBSCertificate` bytes (the signed input), the subject
//! public key and its algorithm, the validity window, the first URI in the
//! `subjectAltName`, and the signature. Every other field is skipped by its
//! length. What is not read is deliberately not read: a module decides
//! nothing on a subject name, a key usage or an unknown extension, so it
//! does not parse them, and an unknown extension marked critical is refused
//! rather than silently passed — a verifier that ignores a critical
//! extension is a verifier that accepts a constraint it did not check.
//!
//! The reader is strict about DER's definite short and long lengths and
//! refuses indefinite lengths, lengths past the buffer and trailing bytes.
//! It accepts leaves other issuers write too, provided they are v3, P-256 or
//! Ed25519, and carry a URI SAN; it is a reader of the certificate profile
//! `docs/identity-provisioning.md` §3 fixes, not of X.509 at large.
//!
//! Pure `no_std`; signature verification is injected as the credential
//! suites' `VerifyFn`.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

/// Verify a signature: `(suite, public_key, message, signature)`, by the
/// credential suite's convention (ES256 hashes, Ed25519 signs whole).
pub type VerifyFn = fn(u16, &[u8], &[u8], &[u8]) -> bool;

/// Credential suites, restated so this fragment mounts nothing.
pub const ES256: u16 = 1;
pub const ED25519: u16 = 2;

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_CONTEXT_0: u8 = 0xA0;
const TAG_CONTEXT_3: u8 = 0xA3;
const TAG_BOOLEAN: u8 = 0x01;
/// `GeneralName` `uniformResourceIdentifier [6]`, implicit.
const TAG_URI: u8 = 0x86;

const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_SAN: &[u8] = &[0x55, 0x1D, 0x11];
/// Extensions a relying party on this profile may leave unread even when
/// critical: basicConstraints and keyUsage (the leaf is not used as a CA
/// and signs nothing but its carrier), and the SAN itself.
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];

/// Why a chain was refused, as the reason code the injected validator
/// answers. 0 is success.
pub mod reason {
    pub const OK: u32 = 0;
    /// Not a TLS certificate message holding exactly one certificate.
    pub const CHAIN_SHAPE: u32 = 1;
    /// The leaf does not parse under this profile.
    pub const LEAF_MALFORMED: u32 = 2;
    /// The anchor is not a key this fragment can verify under.
    pub const ANCHOR_MALFORMED: u32 = 3;
    /// The leaf's signature is not the anchor's.
    pub const SIGNATURE: u32 = 4;
    /// Outside the leaf's validity window.
    pub const VALIDITY: u32 = 5;
    /// The leaf's URI SAN is not the identity expected.
    pub const IDENTITY: u32 = 6;
    /// An unknown critical extension.
    pub const CRITICAL_EXTENSION: u32 = 7;
}

/// One DER element: its tag and contents.
struct Tlv<'a> {
    tag: u8,
    contents: &'a [u8],
}

/// Read one element at the front of `b`, answering it and what follows.
fn tlv(b: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)?;
    let (len, hdr) = if first < 0x80 {
        (usize::from(first), 2usize)
    } else {
        let n = usize::from(first & 0x7F);
        // Definite long form, at most three length bytes: nothing here is
        // larger than 16 MiB, and 0x80 alone is the indefinite form DER
        // forbids.
        if n == 0 || n > 3 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*b.get(2 + i)?);
        }
        // Minimal encoding: a long form that would have fitted the short
        // form is not DER.
        if len < 0x80 {
            return None;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    let contents = b.get(hdr..end)?;
    Some((Tlv { tag, contents }, &b[end..]))
}

/// The length of the DER element at the front of `b`, header included: how
/// a concatenation of certificates (`leaf DER ‖ issuer DER ‖ …`, the
/// enrolment path's chain) is split.
#[must_use]
pub fn element_len(b: &[u8]) -> Option<usize> {
    let (_, rest) = tlv(b)?;
    Some(b.len() - rest.len())
}

/// Read one element and require its tag.
fn expect(b: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (t, rest) = tlv(b)?;
    if t.tag != tag {
        return None;
    }
    Some((t.contents, rest))
}

/// A leaf, read.
#[derive(Clone, Copy)]
pub struct Leaf<'a> {
    /// The `TBSCertificate` element whole, tag and length included: the
    /// bytes the signature is over.
    pub tbs: &'a [u8],
    /// The subject key's credential suite: [`ES256`] or [`ED25519`].
    pub suite: u16,
    /// The raw subject public key: a 65-byte SEC1 point, or 32 bytes.
    pub public: &'a [u8],
    pub not_before: u64,
    pub not_after: u64,
    /// The first URI in the `subjectAltName`, empty when none.
    pub san_uri: &'a [u8],
    /// The signature algorithm's suite, from the outer `signatureAlgorithm`.
    pub signature_suite: u16,
    /// The signature as the certificate carries it: DER `ECDSA-Sig-Value`
    /// for ES256, 64 raw bytes for Ed25519.
    pub signature: &'a [u8],
}

/// Read a certificate. `None` for anything that is not one under this
/// profile, including a certificate with trailing bytes.
#[must_use]
pub fn parse(der: &[u8]) -> Option<Leaf<'_>> {
    let (cert, rest) = expect(der, TAG_SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    // TBSCertificate, whole: the signed input is the element, not its
    // contents.
    let (tbs_tlv, after_tbs) = tlv(cert)?;
    if tbs_tlv.tag != TAG_SEQUENCE {
        return None;
    }
    let tbs_len = cert.len() - after_tbs.len();
    let tbs = cert.get(..tbs_len)?;
    let (sig_alg, after_alg) = expect(after_tbs, TAG_SEQUENCE)?;
    let signature_suite = signature_suite_of(sig_alg)?;
    let (sig_bits, after_sig) = expect(after_alg, TAG_BIT_STRING)?;
    if !after_sig.is_empty() || sig_bits.first() != Some(&0) {
        return None;
    }
    let signature = &sig_bits[1..];
    if signature_suite == ED25519 && signature.len() != 64 {
        return None;
    }

    // Inside the TBS.
    let mut t = tbs_tlv.contents;
    // version [0] EXPLICIT: v3 only, because the SAN exists only there.
    let (version, rest) = expect(t, TAG_CONTEXT_0)?;
    let (v, after_v) = expect(version, TAG_INTEGER)?;
    if v != [0x02] || !after_v.is_empty() {
        return None;
    }
    t = rest;
    let (_serial, rest) = expect(t, TAG_INTEGER)?;
    t = rest;
    let (inner_alg, rest) = expect(t, TAG_SEQUENCE)?;
    // The TBS names the signature algorithm too; a certificate whose two
    // disagree has been edited.
    if signature_suite_of(inner_alg)? != signature_suite {
        return None;
    }
    t = rest;
    let (_issuer, rest) = expect(t, TAG_SEQUENCE)?;
    t = rest;
    let (validity, rest) = expect(t, TAG_SEQUENCE)?;
    let (start, after_start) = tlv(validity)?;
    let (end, after_end) = tlv(after_start)?;
    if !after_end.is_empty() {
        return None;
    }
    let not_before = time(start.tag, start.contents)?;
    let not_after = time(end.tag, end.contents)?;
    t = rest;
    let (_subject, rest) = expect(t, TAG_SEQUENCE)?;
    t = rest;
    let (spki, rest) = expect(t, TAG_SEQUENCE)?;
    let (suite, public) = subject_key(spki)?;
    t = rest;
    // Optional issuerUniqueID [1] / subjectUniqueID [2] are not issued under
    // this profile and refused with everything else unexpected.
    let mut san_uri: &[u8] = &[];
    if !t.is_empty() {
        let (exts, rest) = expect(t, TAG_CONTEXT_3)?;
        if !rest.is_empty() {
            return None;
        }
        san_uri = extensions(exts)?;
    }
    Some(Leaf {
        tbs,
        suite,
        public,
        not_before,
        not_after,
        san_uri,
        signature_suite,
        signature,
    })
}

/// The suite an `AlgorithmIdentifier` names for a signature.
fn signature_suite_of(alg: &[u8]) -> Option<u16> {
    let (oid, params) = expect(alg, TAG_OID)?;
    if oid == OID_ED25519 && params.is_empty() {
        Some(ED25519)
    } else if oid == OID_ECDSA_SHA256 && params.is_empty() {
        Some(ES256)
    } else {
        None
    }
}

/// The suite and raw key a `SubjectPublicKeyInfo` carries.
fn subject_key(spki: &[u8]) -> Option<(u16, &[u8])> {
    let (alg, after_alg) = expect(spki, TAG_SEQUENCE)?;
    let (bits, after_bits) = expect(after_alg, TAG_BIT_STRING)?;
    if !after_bits.is_empty() || bits.first() != Some(&0) {
        return None;
    }
    let key = &bits[1..];
    let (oid, params) = expect(alg, TAG_OID)?;
    if oid == OID_ED25519 {
        if !params.is_empty() || key.len() != 32 {
            return None;
        }
        Some((ED25519, key))
    } else if oid == OID_EC_PUBLIC_KEY {
        let (curve, after_curve) = expect(params, TAG_OID)?;
        if curve != OID_P256 || !after_curve.is_empty() {
            return None;
        }
        // Uncompressed only: the SVID is the hash of these 65 bytes, and a
        // compressed point would name a different one.
        if key.len() != 65 || key[0] != 0x04 {
            return None;
        }
        Some((ES256, key))
    } else {
        None
    }
}

/// Walk the extensions: refuse an unknown critical one, and return the first
/// URI of the SAN (empty when there is no SAN or it holds no URI).
fn extensions(exts: &[u8]) -> Option<&[u8]> {
    let (mut list, rest) = expect(exts, TAG_SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let mut uri: &[u8] = &[];
    while !list.is_empty() {
        let (ext, rest) = expect(list, TAG_SEQUENCE)?;
        list = rest;
        let (oid, after_oid) = expect(ext, TAG_OID)?;
        let (critical, after_crit) = match tlv(after_oid)? {
            (
                Tlv {
                    tag: TAG_BOOLEAN,
                    contents,
                },
                rest,
            ) => (contents == [0xFF], rest),
            _ => (false, after_oid),
        };
        let (value, after_value) = expect(after_crit, TAG_OCTET_STRING)?;
        if !after_value.is_empty() {
            return None;
        }
        if oid == OID_SAN {
            uri = san_uri(value)?;
        } else if critical
            && oid != OID_BASIC_CONSTRAINTS
            && oid != OID_KEY_USAGE
            && oid != OID_EXT_KEY_USAGE
        {
            return None;
        }
    }
    Some(uri)
}

/// The first URI `GeneralName` of a `subjectAltName` value.
fn san_uri(value: &[u8]) -> Option<&[u8]> {
    let (mut names, rest) = expect(value, TAG_SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let mut uri: &[u8] = &[];
    while !names.is_empty() {
        let (name, rest) = tlv(names)?;
        names = rest;
        if name.tag == TAG_URI && uri.is_empty() {
            uri = name.contents;
        }
    }
    Some(uri)
}

/// A `UTCTime` or `GeneralizedTime` as Unix seconds. Zulu only, no
/// fractional seconds: RFC 5280's one encoding of each.
fn time(tag: u8, b: &[u8]) -> Option<u64> {
    let (year, rest) = match tag {
        TAG_UTC_TIME => {
            if b.len() != 13 {
                return None;
            }
            let yy = two(b, 0)?;
            // RFC 5280 §4.1.2.5.1: 50–99 are 1950–1999, 00–49 are 2000–2049.
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &b[2..])
        }
        TAG_GENERALIZED_TIME => {
            if b.len() != 15 {
                return None;
            }
            (two(b, 0)? * 100 + two(b, 2)?, &b[4..])
        }
        _ => return None,
    };
    if rest.len() != 11 || rest[10] != b'Z' {
        return None;
    }
    let month = two(rest, 0)?;
    let day = two(rest, 2)?;
    let hour = two(rest, 4)?;
    let minute = two(rest, 6)?;
    let second = two(rest, 8)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

fn two(b: &[u8], at: usize) -> Option<u64> {
    let hi = *b.get(at)?;
    let lo = *b.get(at + 1)?;
    if !hi.is_ascii_digit() || !lo.is_ascii_digit() {
        return None;
    }
    Some(u64::from(hi - b'0') * 10 + u64::from(lo - b'0'))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`), for years from 1970.
fn days_from_civil(y: u64, m: u64, d: u64) -> Option<u64> {
    if y < 1970 {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe).checked_sub(719_468)
}

/// An ECDSA `ECDSA-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`) as the
/// fixed `r ‖ s` the credential suites verify. `None` for anything that is
/// not one, or whose components do not fit 32 bytes.
pub fn ecdsa_raw(der: &[u8], out: &mut [u8; 64]) -> Option<()> {
    let (seq, rest) = expect(der, TAG_SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let (r, after_r) = expect(seq, TAG_INTEGER)?;
    let (s, after_s) = expect(after_r, TAG_INTEGER)?;
    if !after_s.is_empty() {
        return None;
    }
    *out = [0; 64];
    put_scalar(r, &mut out[..32])?;
    put_scalar(s, &mut out[32..])
}

/// Copy a DER INTEGER's magnitude right-aligned into a 32-byte slot.
fn put_scalar(int: &[u8], slot: &mut [u8]) -> Option<()> {
    // DER INTEGERs are two's complement: a top bit set is a negative
    // number, which no ECDSA component is, and a leading zero is the sign
    // byte of a magnitude whose own top bit is set — present exactly then,
    // because DER is minimal.
    let first = *int.first()?;
    if first & 0x80 != 0 {
        return None;
    }
    let mag = if int.len() > 1 && first == 0 {
        if int[1] & 0x80 == 0 {
            return None;
        }
        &int[1..]
    } else {
        int
    };
    if mag.len() > slot.len() {
        return None;
    }
    let at = slot.len() - mag.len();
    for (d, s) in slot.iter_mut().skip(at).zip(mag) {
        *d = *s;
    }
    Some(())
}

/// Verify that `leaf` was signed by the key `(anchor_suite, anchor_public)`.
#[must_use]
pub fn signed_by(
    leaf: &Leaf<'_>,
    verify: VerifyFn,
    anchor_suite: u16,
    anchor_public: &[u8],
) -> bool {
    if leaf.signature_suite != anchor_suite {
        return false;
    }
    match anchor_suite {
        ES256 => {
            let mut raw = [0u8; 64];
            ecdsa_raw(leaf.signature, &mut raw).is_some()
                && verify(ES256, anchor_public, leaf.tbs, &raw)
        }
        ED25519 => verify(ED25519, anchor_public, leaf.tbs, leaf.signature),
        _ => false,
    }
}

/// An anchor as this fragment takes it: `[suite u16 LE][public key]` — the
/// authority's key as it announces it (`key_announce`, a VERIFY
/// `MSG_KEY_ADD`), rather than its certificate. What a chain of one is
/// checked against is the key; a certificate around it adds nothing a
/// module could act on.
pub fn anchor(anchor: &[u8]) -> Option<(u16, &[u8])> {
    let suite = u16::from_le_bytes([*anchor.first()?, *anchor.get(1)?]);
    let public = anchor.get(2..)?;
    let ok = match suite {
        ES256 => public.len() == 65 && public[0] == 0x04,
        ED25519 => public.len() == 32,
        _ => false,
    };
    if ok {
        Some((suite, public))
    } else {
        None
    }
}

/// Write an anchor for [`anchor`] to read.
pub fn write_anchor(suite: u16, public: &[u8], out: &mut [u8]) -> Option<usize> {
    let end = 2usize.checked_add(public.len())?;
    let dst = out.get_mut(..end)?;
    for (d, s) in dst.iter_mut().zip(suite.to_le_bytes().iter().chain(public)) {
        *d = *s;
    }
    Some(end)
}

/// The leaf a TLS 1.3 `Certificate` message body carries, when it carries
/// exactly one: `[ctx_len u8][ctx][list_len u24]([cert_len u24][cert]
/// [ext_len u16][ext])*`.
pub fn chain_of_one(cert_msg: &[u8]) -> Option<&[u8]> {
    let ctx_len = usize::from(*cert_msg.first()?);
    let b = cert_msg.get(1 + ctx_len..)?;
    let list_len = u24(b)?;
    let list = b.get(3..3 + list_len)?;
    if b.len() != 3 + list_len {
        return None;
    }
    let cert_len = u24(list)?;
    let cert = list.get(3..3 + cert_len)?;
    let after = list.get(3 + cert_len..)?;
    let ext_len = usize::from(u16::from_be_bytes([*after.first()?, *after.get(1)?]));
    if after.len() != 2 + ext_len {
        return None;
    }
    Some(cert)
}

fn u24(b: &[u8]) -> Option<usize> {
    Some(
        (usize::from(*b.first()?) << 16) | (usize::from(*b.get(1)?) << 8) | usize::from(*b.get(2)?),
    )
}

/// A chain validator in the shape `cert_bound_identity::CarrierVerifyChainFn`
/// takes, over an injected `VerifyFn`: the message holds one leaf, the leaf
/// parses, the anchor (as [`anchor`] reads it) signed it, it is inside its
/// window when a clock is required, and its URI SAN is `expected_uri`.
/// Answers a [`reason`].
#[must_use]
pub fn verify_chain(
    verify: VerifyFn,
    cert_msg: &[u8],
    anchor_bytes: &[u8],
    expected_uri: &[u8],
    now_unix_secs: u64,
    require_clock: bool,
) -> u32 {
    let Some(der) = chain_of_one(cert_msg) else {
        return reason::CHAIN_SHAPE;
    };
    let Some(leaf) = parse(der) else {
        return reason::LEAF_MALFORMED;
    };
    let Some((anchor_suite, anchor_public)) = anchor(anchor_bytes) else {
        return reason::ANCHOR_MALFORMED;
    };
    if !signed_by(&leaf, verify, anchor_suite, anchor_public) {
        return reason::SIGNATURE;
    }
    if require_clock && (now_unix_secs < leaf.not_before || now_unix_secs >= leaf.not_after) {
        return reason::VALIDITY;
    }
    if leaf.san_uri.is_empty() || leaf.san_uri != expected_uri {
        return reason::IDENTITY;
    }
    reason::OK
}

/// The leaf's uncompressed P-256 point, in the shape
/// `cert_bound_identity::CarrierLeafKeyFn` takes. `None` for an Ed25519
/// leaf: a carrier is ES256-signed, and a leaf that cannot sign one proves
/// nothing by it.
pub fn leaf_public_key(der: &[u8], out: &mut [u8; 65]) -> Option<usize> {
    let leaf = parse(der)?;
    if leaf.suite != ES256 {
        return None;
    }
    if leaf.public.len() != out.len() {
        return None;
    }
    for (d, s) in out.iter_mut().zip(leaf.public) {
        *d = *s;
    }
    Some(65)
}

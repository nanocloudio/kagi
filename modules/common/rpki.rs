//! RPKI signed objects (RFC 6488) under a resource-certificate chain: the
//! relying-party core `rsc_verify` runs a Signed Checklist through
//! (`rsc_verify.rs`). Ported from Nanocloud's `_shared/rpki.rs` (anchor → EE
//! only, no CRLs) and taken further: a chain of CA certificates between the
//! trust anchor and the EE certificate — a tenant's resource holder's CA
//! under its RIR's anchor — and every link checked against its issuer's
//! current CRL.
//!
//! What is checked, in order, each a refusal by name ([`Refusal`]):
//!
//! - the trust anchor: a self-signed RSA certificate (sha256WithRSA), valid
//!   at `now`, a CA, carrying RFC 3779 IP resources (never `inherit`);
//! - each CA of the chain, in order from the anchor: issued under the
//!   certificate before it (its issuer name that one's subject, its
//!   signature under that one's key), a CA, valid at `now`, its RFC 3779 IP
//!   resources (or `inherit`, its issuer's) inside its issuer's, and not
//!   revoked by its issuer's CRL;
//! - the issuer's CRL (RFC 5280 §5), for every certificate below the anchor:
//!   one the caller handed in whose issuer is that issuer and whose
//!   signature verifies under its key, current at `now` (this update
//!   reached, next update present and not passed) — none is a refusal, not
//!   a pass;
//! - the CMS wrapper: `signedData`, the encapsulated content type the caller
//!   names, exactly one certificate (the EE) and one signer;
//! - the EE certificate: issued under the chain's last CA (the anchor's
//!   when the chain is empty), valid at `now`, its resources inside its
//!   issuer's, not revoked;
//! - the signer: signed attributes present, `content-type` the object's,
//!   `message-digest` the SHA-256 of the eContent, and the signature over
//!   those attributes verifying under the EE certificate's key.
//!
//! Not done here, each a stated limit: fetching (the caller hands in every
//! object), manifests, AS resources, address ranges that are not prefixes,
//! CRL delta and distribution-point semantics (a CRL counts for the issuer
//! that signed it, whatever it says of its scope).
//!
//! Pure `no_std`, allocation-free and mounting nothing: SHA-256 and RSA
//! (PKCS#1 v1.5 over SHA-256) are injected ([`Crypto`]); a module wires the
//! Fluxor SDK's `rsa.rs`, a host suite whatever it trusts.

#![allow(
    dead_code,
    reason = "shared via #[path] into the module and the host suite; each uses a subset of the surface"
)]

/// The crypto a check runs on: a module wires the Fluxor SDK's (its RSA
/// job its own state), a host suite whatever it trusts. Generic, not a
/// trait object, so a PIC module carries no vtable.
pub trait Crypto {
    /// SHA-256 of `msg`.
    fn sha256(&mut self, msg: &[u8]) -> [u8; 32];
    /// Whether `sig` is a PKCS#1 v1.5 RSA signature over the SHA-256 of
    /// `msg` under `rsa_key` (a DER `RSAPublicKey`).
    fn rsa_ok(&mut self, rsa_key: &[u8], msg: &[u8], sig: &[u8]) -> bool;
}

/// RFC 3779 prefixes one certificate holds.
pub const RESOURCES_MAX: usize = 16;
/// CA certificates between the anchor and the EE certificate.
pub const CHAIN_MAX: usize = 4;
/// Revoked serials a CRL may list (one past is a refusal, not a truncation).
pub const CRL_ENTRIES_MAX: usize = 512;
/// The signed attributes' largest encoding this reads.
const SIGNED_ATTRS_MAX: usize = 1024;

const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_IP_ADDR_BLOCKS: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x07];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];

/// Why an object was refused. Stable: the codes travel in replies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Refusal {
    /// Not the DER this profile reads.
    Malformed = 1,
    /// A signature algorithm other than sha256WithRSAEncryption, or a key
    /// that is not RSA.
    Algorithm = 2,
    /// The anchor's self-signature does not verify.
    AnchorSignature = 3,
    /// A certificate outside its validity at `now`.
    Expired = 4,
    /// A certificate whose issuer name is not the certificate above it, or
    /// whose signature does not verify under that one's key.
    IssuerSignature = 5,
    /// A certificate that issues another but is no CA.
    NotCa = 6,
    /// Not the object type named, or not exactly one certificate and one
    /// signer.
    Shape = 7,
    /// A signed attribute missing or disagreeing with the content.
    Attributes = 8,
    SignerSignature = 9,
    /// A resource outside its issuer's.
    Resources = 10,
    /// No CRL of a certificate's issuer, signed by it, was handed in.
    NoCrl = 11,
    /// The issuer's CRL is not current at `now`.
    StaleCrl = 12,
    /// The issuer's CRL lists the certificate.
    Revoked = 13,
    /// A chain longer than [`CHAIN_MAX`].
    Chain = 14,
}

impl Refusal {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

// ── a minimal DER reader ──────────────────────────────────────────────────

/// One TLV: tag, contents and the whole encoding.
#[derive(Clone, Copy)]
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    pub body: &'a [u8],
    pub whole: &'a [u8],
}

pub(crate) fn tlv(b: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *b.first()?;
    let l0 = *b.get(1)?;
    let (len, hdr) = if l0 < 0x80 {
        (usize::from(l0), 2)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 3 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*b.get(2 + i)?);
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    Some((
        Tlv {
            tag,
            body: b.get(hdr..end)?,
            whole: b.get(..end)?,
        },
        b.get(end..)?,
    ))
}

pub(crate) fn expect(b: &[u8], tag: u8) -> Result<(Tlv<'_>, &[u8]), Refusal> {
    match tlv(b) {
        Some((t, rest)) if t.tag == tag => Ok((t, rest)),
        _ => Err(Refusal::Malformed),
    }
}

/// Seconds since 1970 of a UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime.
pub(crate) fn der_time(t: &Tlv<'_>) -> Option<u64> {
    let d = t.body;
    let num = |s: &[u8]| -> Option<u64> {
        let mut v = 0u64;
        for c in s {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + u64::from(c - b'0');
        }
        Some(v)
    };
    let (year, rest) = match t.tag {
        0x17 if d.len() == 13 => {
            let y = num(&d[0..2])?;
            (if y >= 50 { 1900 + y } else { 2000 + y }, &d[2..])
        }
        0x18 if d.len() == 15 => (num(&d[0..4])?, &d[4..]),
        _ => return None,
    };
    if rest.last() != Some(&b'Z') {
        return None;
    }
    let (mo, da, h, mi, s) = (
        num(&rest[0..2])?,
        num(&rest[2..4])?,
        num(&rest[4..6])?,
        num(&rest[6..8])?,
        num(&rest[8..10])?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if mo <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146_097 + doe).checked_sub(719_468)?;
    Some(days * 86_400 + h * 3600 + mi * 60 + s)
}

/// A non-negative DER INTEGER of at most eight bytes (a leading zero
/// allowed).
pub(crate) fn der_uint(t: &Tlv<'_>) -> Option<u64> {
    if t.tag != 0x02 || t.body.is_empty() || t.body.len() > 9 || t.body[0] & 0x80 != 0 {
        return None;
    }
    let mut v = 0u64;
    for b in t.body {
        v = v.checked_shl(8)? | u64::from(*b);
    }
    Some(v)
}

// ── resources ─────────────────────────────────────────────────────────────

/// An IP prefix as RFC 3779 encodes it: family (4 or 6), the address bits
/// and the prefix length.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Prefix {
    pub family: u8,
    pub addr: [u8; 16],
    pub len: u8,
}

impl Prefix {
    /// Whether `other` lies inside this prefix.
    #[must_use]
    pub fn covers(&self, other: &Prefix) -> bool {
        if self.family != other.family || other.len < self.len {
            return false;
        }
        let full = usize::from(self.len / 8);
        if self.addr[..full] != other.addr[..full] {
            return false;
        }
        let rem = self.len % 8;
        if rem == 0 {
            return true;
        }
        let mask = 0xFFu8 << (8 - rem);
        self.addr[full] & mask == other.addr[full] & mask
    }
}

/// A BIT STRING address (`IPAddress`) of `family`.
pub(crate) fn bit_prefix(t: &Tlv<'_>, family: u8) -> Option<Prefix> {
    if t.tag != 0x03 || t.body.is_empty() {
        return None;
    }
    let unused = t.body[0];
    let bits = &t.body[1..];
    let width = if family == 4 { 4 } else { 16 };
    if unused > 7 || bits.len() > width || (bits.is_empty() && unused != 0) {
        return None;
    }
    let len = bits.len() * 8 - usize::from(unused);
    let mut addr = [0u8; 16];
    addr[..bits.len()].copy_from_slice(bits);
    Some(Prefix {
        family,
        addr,
        len: len as u8,
    })
}

pub(crate) fn afi_family(t: &Tlv<'_>) -> Option<u8> {
    if t.tag != 0x04 || t.body.len() < 2 {
        return None;
    }
    match (t.body[0], t.body[1]) {
        (0, 1) => Some(4),
        (0, 2) => Some(6),
        _ => None,
    }
}

/// A certificate's RFC 3779 IP resources: prefixes, or `inherit` (per
/// family; a family that inherits takes its issuer's prefixes of it).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Resources {
    pub inherit4: bool,
    pub inherit6: bool,
    pub n: usize,
    pub prefixes: [Prefix; RESOURCES_MAX],
}

impl Resources {
    #[must_use]
    pub fn prefixes(&self) -> &[Prefix] {
        &self.prefixes[..self.n]
    }

    #[must_use]
    pub fn covers(&self, p: &Prefix) -> bool {
        self.prefixes().iter().any(|r| r.covers(p))
    }

    fn inherits(&self, family: u8) -> bool {
        if family == 4 {
            self.inherit4
        } else {
            self.inherit6
        }
    }

    /// The resources in force under `issuer` (whose own are in force):
    /// each inheriting family takes the issuer's prefixes of it; every
    /// other prefix must lie inside the issuer's.
    fn under(&self, issuer: &Resources) -> Result<Resources, Refusal> {
        let mut r = Resources::default();
        for p in self.prefixes() {
            if !issuer.covers(p) {
                return Err(Refusal::Resources);
            }
            r.push(*p)?;
        }
        for p in issuer.prefixes() {
            if self.inherits(p.family) {
                r.push(*p)?;
            }
        }
        Ok(r)
    }

    fn push(&mut self, p: Prefix) -> Result<(), Refusal> {
        if self.n == RESOURCES_MAX {
            return Err(Refusal::Resources);
        }
        self.prefixes[self.n] = p;
        self.n += 1;
        Ok(())
    }
}

/// `IPAddrBlocks ::= SEQUENCE OF IPAddressFamily` (prefixes and inherit).
fn ip_resources(der: &[u8]) -> Result<Resources, Refusal> {
    let bad = Refusal::Malformed;
    let (blocks, _) = expect(der, 0x30)?;
    let mut r = Resources::default();
    let mut rest = blocks.body;
    while !rest.is_empty() {
        let (fam, next) = expect(rest, 0x30)?;
        rest = next;
        let (afi, choice) = tlv(fam.body).ok_or(bad)?;
        let family = afi_family(&afi).ok_or(bad)?;
        let (c, _) = tlv(choice).ok_or(bad)?;
        match c.tag {
            0x05 if family == 4 => r.inherit4 = true,
            0x05 => r.inherit6 = true,
            0x30 => {
                let mut items = c.body;
                while !items.is_empty() {
                    let (item, next) = tlv(items).ok_or(bad)?;
                    items = next;
                    // A prefix; a range (a SEQUENCE) is not read here.
                    let p = bit_prefix(&item, family).ok_or(Refusal::Resources)?;
                    r.push(p)?;
                }
            }
            _ => return Err(bad),
        }
    }
    Ok(r)
}

// ── certificates ──────────────────────────────────────────────────────────

/// What a resource certificate says that this profile uses.
#[derive(Clone, Copy)]
pub struct Cert<'a> {
    tbs: &'a [u8],
    signature: &'a [u8],
    /// The serial's contents (a DER INTEGER's body), as a CRL lists it.
    serial: &'a [u8],
    /// The issuer and subject names, whole DER: compared byte for byte.
    issuer: &'a [u8],
    subject: &'a [u8],
    pub not_before: u64,
    pub not_after: u64,
    /// The `RSAPublicKey` inside the subject public key info.
    rsa_key: &'a [u8],
    /// `basicConstraints` says CA.
    pub ca: bool,
    pub resources: Resources,
}

impl Cert<'_> {
    fn valid_at(&self, now_s: u64) -> bool {
        self.not_before <= now_s && now_s <= self.not_after
    }
}

/// Read a certificate.
pub fn cert_parse(der: &[u8]) -> Result<Cert<'_>, Refusal> {
    let bad = Refusal::Malformed;
    let (cert, _) = expect(der, 0x30)?;
    let (tbs, rest) = expect(cert.body, 0x30)?;
    let (alg, rest) = expect(rest, 0x30)?;
    let (sig, _) = expect(rest, 0x03)?;
    let (oid, _) = expect(alg.body, 0x06)?;
    if oid.body != OID_SHA256_RSA {
        return Err(Refusal::Algorithm);
    }
    let mut f = tbs.body;
    // [0] version, serial, signature, issuer, validity, subject, spki.
    if f.first() == Some(&0xa0) {
        f = tlv(f).ok_or(bad)?.1;
    }
    let (serial, f) = expect(f, 0x02)?;
    let (_, f) = expect(f, 0x30)?;
    let (issuer, f) = expect(f, 0x30)?;
    let (validity, f) = expect(f, 0x30)?;
    let (subject, f) = expect(f, 0x30)?;
    let (spki, mut f) = expect(f, 0x30)?;
    let (nb, rest_v) = tlv(validity.body).ok_or(bad)?;
    let (na, _) = tlv(rest_v).ok_or(bad)?;
    let (alg, key) = expect(spki.body, 0x30)?;
    let (koid, _) = expect(alg.body, 0x06)?;
    if koid.body != OID_RSA {
        return Err(Refusal::Algorithm);
    }
    let (bits, _) = expect(key, 0x03)?;
    if bits.body.first() != Some(&0) {
        return Err(bad);
    }
    let mut resources = Resources::default();
    let mut ca = false;
    while !f.is_empty() {
        let (t, next) = tlv(f).ok_or(bad)?;
        f = next;
        if t.tag != 0xa3 {
            continue;
        }
        let (exts, _) = expect(t.body, 0x30)?;
        let mut e = exts.body;
        while !e.is_empty() {
            let (ext, next) = expect(e, 0x30)?;
            e = next;
            let (eoid, mut v) = expect(ext.body, 0x06)?;
            if v.first() == Some(&0x01) {
                v = tlv(v).ok_or(bad)?.1;
            }
            let (val, _) = expect(v, 0x04)?;
            if eoid.body == OID_IP_ADDR_BLOCKS {
                resources = ip_resources(val.body)?;
            } else if eoid.body == OID_BASIC_CONSTRAINTS {
                // BasicConstraints { cA BOOLEAN DEFAULT FALSE, ... }
                let (bc, _) = expect(val.body, 0x30)?;
                if let Some((b, _)) = tlv(bc.body) {
                    ca = b.tag == 0x01 && b.body == [0xFF];
                }
            }
        }
    }
    let (unused, sig_bytes) = sig.body.split_first().ok_or(bad)?;
    if *unused != 0 {
        return Err(bad);
    }
    Ok(Cert {
        tbs: tbs.whole,
        signature: sig_bytes,
        serial: serial.body,
        issuer: issuer.whole,
        subject: subject.whole,
        not_before: der_time(&nb).ok_or(bad)?,
        not_after: der_time(&na).ok_or(bad)?,
        rsa_key: &bits.body[1..],
        ca,
        resources,
    })
}

/// A trust anchor: its self-signed certificate, checked at `now_s`.
pub fn anchor_check<'a>(
    c: &mut impl Crypto,
    der: &'a [u8],
    now_s: u64,
) -> Result<Cert<'a>, Refusal> {
    let a = cert_parse(der)?;
    if a.issuer != a.subject || !c.rsa_ok(a.rsa_key, a.tbs, a.signature) {
        return Err(Refusal::AnchorSignature);
    }
    if !a.valid_at(now_s) {
        return Err(Refusal::Expired);
    }
    if !a.ca {
        return Err(Refusal::NotCa);
    }
    if a.resources.inherit4 || a.resources.inherit6 || a.resources.n == 0 {
        return Err(Refusal::Resources);
    }
    Ok(a)
}

// ── CRLs ──────────────────────────────────────────────────────────────────

/// What a CRL says that this profile uses.
#[derive(Clone, Copy)]
pub struct Crl<'a> {
    tbs: &'a [u8],
    signature: &'a [u8],
    issuer: &'a [u8],
    pub this_update: u64,
    /// 0 when absent (such a CRL is never current).
    pub next_update: u64,
    /// The `revokedCertificates` SEQUENCE's contents (empty: none).
    revoked: &'a [u8],
}

/// Read a CRL (RFC 5280 §5).
pub fn crl_parse(der: &[u8]) -> Result<Crl<'_>, Refusal> {
    let bad = Refusal::Malformed;
    let (list, _) = expect(der, 0x30)?;
    let (tbs, rest) = expect(list.body, 0x30)?;
    let (alg, rest) = expect(rest, 0x30)?;
    let (sig, _) = expect(rest, 0x03)?;
    let (oid, _) = expect(alg.body, 0x06)?;
    if oid.body != OID_SHA256_RSA {
        return Err(Refusal::Algorithm);
    }
    let mut f = tbs.body;
    // version (an INTEGER, present in a v2 CRL), signature, issuer,
    // thisUpdate, nextUpdate?, revokedCertificates?, [0] extensions?
    if f.first() == Some(&0x02) {
        f = tlv(f).ok_or(bad)?.1;
    }
    let (_, f) = expect(f, 0x30)?;
    let (issuer, f) = expect(f, 0x30)?;
    let (this_t, mut f) = tlv(f).ok_or(bad)?;
    let this_update = der_time(&this_t).ok_or(bad)?;
    let mut next_update = 0;
    if matches!(f.first(), Some(&(0x17 | 0x18))) {
        let (t, next) = tlv(f).ok_or(bad)?;
        next_update = der_time(&t).ok_or(bad)?;
        f = next;
    }
    let mut revoked: &[u8] = &[];
    if f.first() == Some(&0x30) {
        let (r, _) = tlv(f).ok_or(bad)?;
        revoked = r.body;
    }
    let (unused, sig_bytes) = sig.body.split_first().ok_or(bad)?;
    if *unused != 0 {
        return Err(bad);
    }
    Ok(Crl {
        tbs: tbs.whole,
        signature: sig_bytes,
        issuer: issuer.whole,
        this_update,
        next_update,
        revoked,
    })
}

impl Crl<'_> {
    /// Whether the CRL lists `serial` (a DER INTEGER's contents).
    fn lists(&self, serial: &[u8]) -> Result<bool, Refusal> {
        let mut r = self.revoked;
        let mut n = 0;
        while !r.is_empty() {
            let (entry, next) = expect(r, 0x30)?;
            r = next;
            n += 1;
            if n > CRL_ENTRIES_MAX {
                return Err(Refusal::Malformed);
            }
            let (s, _) = expect(entry.body, 0x02)?;
            if s.body == serial {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// `child`, issued under `issuer` (whose resources in force are
/// `issuer_res`): the issuer is a CA, the name and signature chain, the
/// child is valid at `now_s`, its resources lie inside, and the issuer's
/// current CRL among `crls` does not list it. Its resources in force.
fn issued_under(
    c: &mut impl Crypto,
    child: &Cert<'_>,
    issuer: &Cert<'_>,
    issuer_res: &Resources,
    crls: &[&[u8]],
    now_s: u64,
) -> Result<Resources, Refusal> {
    if !issuer.ca {
        return Err(Refusal::NotCa);
    }
    if child.issuer != issuer.subject || !c.rsa_ok(issuer.rsa_key, child.tbs, child.signature) {
        return Err(Refusal::IssuerSignature);
    }
    if !child.valid_at(now_s) {
        return Err(Refusal::Expired);
    }
    let res = child.resources.under(issuer_res)?;
    // The issuer's CRL: the one it signed (another issuer of its name
    // signs nothing it vouches for). Each such CRL the caller handed in
    // counts, and any stale one refuses.
    let mut found = false;
    for der in crls {
        let crl = crl_parse(der)?;
        if crl.issuer != issuer.subject || !c.rsa_ok(issuer.rsa_key, crl.tbs, crl.signature) {
            continue;
        }
        found = true;
        if now_s < crl.this_update || crl.next_update == 0 || now_s > crl.next_update {
            return Err(Refusal::StaleCrl);
        }
        if crl.lists(child.serial)? {
            return Err(Refusal::Revoked);
        }
    }
    if !found {
        return Err(Refusal::NoCrl);
    }
    Ok(res)
}

/// An RPKI signed object (RFC 6488) of eContent type `econtent_type` under
/// the chain `anchor` → `cas` (in order) → its EE certificate, every link
/// checked against its issuer's CRL among `crls`, at `now_s` (see the file
/// comment): its eContent and the EE certificate's resources in force.
pub fn signed_object<'a>(
    c: &mut impl Crypto,
    anchor: &[u8],
    cas: &[&[u8]],
    crls: &[&[u8]],
    der: &'a [u8],
    econtent_type: &[u8],
    now_s: u64,
) -> Result<(&'a [u8], Resources), Refusal> {
    let bad = Refusal::Malformed;
    if cas.len() > CHAIN_MAX {
        return Err(Refusal::Chain);
    }
    let a = anchor_check(&mut *c, anchor, now_s)?;
    let mut issuer = a;
    let mut res = a.resources;
    for ca in cas {
        let cert = cert_parse(ca)?;
        res = issued_under(&mut *c, &cert, &issuer, &res, crls, now_s)?;
        if !cert.ca {
            return Err(Refusal::NotCa);
        }
        issuer = cert;
    }
    // ContentInfo { contentType, [0] SignedData }
    let (ci, _) = expect(der, 0x30)?;
    let (ct, rest) = expect(ci.body, 0x06)?;
    if ct.body != OID_SIGNED_DATA {
        return Err(Refusal::Shape);
    }
    let (wrap, _) = expect(rest, 0xa0)?;
    let (sd, _) = expect(wrap.body, 0x30)?;
    let (_, f) = expect(sd.body, 0x02)?;
    let (_, f) = expect(f, 0x31)?;
    let (encap, f) = expect(f, 0x30)?;
    let (ect, erest) = expect(encap.body, 0x06)?;
    if ect.body != econtent_type {
        return Err(Refusal::Shape);
    }
    let (ew, _) = expect(erest, 0xa0)?;
    let (econtent, _) = expect(ew.body, 0x04)?;
    let (certs, f) = expect(f, 0xa0)?;
    let (ee_t, more) = tlv(certs.body).ok_or(bad)?;
    if !more.is_empty() {
        return Err(Refusal::Shape);
    }
    let mut f = f;
    if f.first() == Some(&0xa1) {
        f = tlv(f).ok_or(bad)?.1;
    }
    let (signers, _) = expect(f, 0x31)?;
    let (si, more) = expect(signers.body, 0x30)?;
    if !more.is_empty() {
        return Err(Refusal::Shape);
    }
    // The EE certificate under the chain's last CA.
    let ee = cert_parse(ee_t.whole)?;
    let ee_res = issued_under(&mut *c, &ee, &issuer, &res, crls, now_s)?;
    // SignerInfo { version, sid, digestAlg, [0] signedAttrs, sigAlg, sig }
    let (_, s) = expect(si.body, 0x02)?;
    let (_, s) = tlv(s).ok_or(bad)?;
    let (_, s) = expect(s, 0x30)?;
    let (attrs, s) = expect(s, 0xa0)?;
    let (salg, s) = expect(s, 0x30)?;
    let (sig, _) = expect(s, 0x04)?;
    let (soid, _) = expect(salg.body, 0x06)?;
    if soid.body != OID_SHA256_RSA && soid.body != OID_RSA {
        return Err(Refusal::Algorithm);
    }
    let mut content_type_ok = false;
    let mut digest_ok = false;
    let mut at = attrs.body;
    while !at.is_empty() {
        let (attr, next) = expect(at, 0x30)?;
        at = next;
        let (aoid, vals) = expect(attr.body, 0x06)?;
        let (set, _) = expect(vals, 0x31)?;
        let (v, _) = tlv(set.body).ok_or(bad)?;
        if aoid.body == OID_CONTENT_TYPE {
            content_type_ok = v.tag == 0x06 && v.body == econtent_type;
        } else if aoid.body == OID_MESSAGE_DIGEST {
            digest_ok = v.tag == 0x04 && v.body == c.sha256(econtent.body);
        }
    }
    if !content_type_ok || !digest_ok {
        return Err(Refusal::Attributes);
    }
    // The signature covers the attributes as a SET (tag 0x31).
    let mut signed = [0u8; SIGNED_ATTRS_MAX];
    let n = attrs.whole.len();
    if n > signed.len() {
        return Err(bad);
    }
    signed[..n].copy_from_slice(attrs.whole);
    signed[0] = 0x31;
    if !c.rsa_ok(ee.rsa_key, &signed[..n], sig.body) {
        return Err(Refusal::SignerSignature);
    }
    Ok((econtent.body, ee_res))
}

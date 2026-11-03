//! BYOIP ownership evidence (rfc_lb_vip §11.15): whether a tenant holds an
//! address prefix it asks to import is a fact about resource certificates,
//! proven with an RPKI Signed Checklist (RSC, RFC 9323) — a CMS signed
//! object (RFC 6488) whose EE certificate the tenant's resource holder's CA
//! issued under a trust anchor (`rpki.rs`: the chain, every link against
//! its issuer's CRL), listing the IP resources it speaks for and the SHA-256
//! of the documents it signs. The document the tenant has its CA sign is the
//! import's challenge ([`challenge`]: the tenant and the prefix, so a
//! checklist proves one tenant's claim to one prefix and nothing else).
//! Ported from Nanocloud's `_shared/ownership.rs`.
//!
//! [`verify`] gives the traffic fabric's `OwnershipEvidence` (its `address_core`'s
//! import admission requires `verified`) only when, in order, each a refusal
//! by name:
//!
//! - the RSC is a valid signed object under the chain (`rpki::signed_object`);
//! - its content is an RSC: version 0, a resource block whose IP blocks are
//!   prefixes inside the EE certificate's resources, SHA-256 as the digest
//!   algorithm, a non-empty checklist;
//! - one of its IP blocks covers the prefix claimed;
//! - its checklist holds the SHA-256 of this tenant's and prefix's challenge.
//!
//! The evidence's digest is the SHA-256 of the RSC itself, so what was
//! accepted can be named. AS resources in the block are allowed and not
//! used.
//!
//! # The typed operation (`rsc_verify`)
//!
//! One exchange record carries at most 8,192 bytes, less than an anchor,
//! a CA chain, their CRLs and a checklist together. So the operation is
//! two requests: [`op::CACHE`] puts one certificate or CRL in the provider's
//! bounded cache and answers its SHA-256; [`op::VERIFY`] names the anchor,
//! the chain and the CRLs by those digests and carries the checklist itself.
//! The cache decides nothing: which anchor a relying party trusts is the
//! relying party's to pin, and it names that anchor's digest in every
//! VERIFY. An entry not cached (or evicted, oldest first) answers
//! [`status::NOT_CACHED`] and is put again.
//!
//! ```text
//! request  [op u8][body]
//!   CACHE  [der f16]
//!   VERIFY [anchor 32][n u8][ca 32]×n[m u8][crl 32]×m[tenant 16]
//!          [family u8][addr 16][len u8][rsc f16]      IPv4 in addr[12..16]
//! reply    [op u8][status u8][refusal u8][body]
//!   CACHE  [digest 32]
//!   VERIFY [holder 16][family u8][addr 16][len u8][digest 32][verified u8]
//! ```
//!
//! A refusal's reply carries the operation's whole body zeroed (`verified`
//! 0): a caller that ignored the status holds nothing that admits.
//!
//! Pure `no_std`, allocation-free; mounts `crate::rpki`.

#![allow(
    dead_code,
    reason = "shared via #[path] into the module and the host suite; each uses a subset of the surface"
)]

use crate::rpki::{
    self, afi_family, bit_prefix, der_uint, expect, tlv, Crypto, Prefix, Refusal as RpkiRefusal,
};

/// `id-ct-signedChecklist` (RFC 9323).
pub const OID_RSC: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x30,
];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// `fabric-ownership.v1` ‖ tenant ‖ family ‖ address ‖ length.
pub const CHALLENGE_LEN: usize = 19 + 16 + 1 + 16 + 1;

/// The traffic fabric's address families.
pub const AF_INET: u8 = 4;
pub const AF_INET6: u8 = 6;

/// A prefix as the traffic fabric's `BgpPrefix` carries it: its family, its address
/// in sixteen bytes (IPv4 in the last four) and its length.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Claim {
    pub family: u8,
    pub addr: [u8; 16],
    pub len: u8,
}

impl Claim {
    fn valid(&self) -> bool {
        match self.family {
            AF_INET => self.addr[..12] == [0; 12] && self.len <= 32,
            AF_INET6 => self.len <= 128,
            _ => false,
        }
    }

    /// The claim as RFC 3779 bits (IPv4 in the first four bytes).
    fn prefix(&self) -> Prefix {
        let mut addr = [0u8; 16];
        if self.family == AF_INET {
            addr[..4].copy_from_slice(&self.addr[12..16]);
        } else {
            addr = self.addr;
        }
        Prefix {
            family: self.family,
            addr,
            len: self.len,
        }
    }
}

/// The traffic fabric's `OwnershipEvidence`, field for field.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Evidence {
    pub holder: [u8; 16],
    pub covers: Claim,
    /// SHA-256 of the RSC accepted.
    pub digest: [u8; 32],
    pub verified: bool,
}

/// Why a checklist is not ownership evidence. Stable codes: they travel in
/// replies (`refusal`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The signed object did not validate (its own reason).
    Rpki(RpkiRefusal),
    /// Not an RSC this profile reads, or a claim that is not a prefix.
    Shape,
    /// The checklist's resources are not inside the EE certificate's.
    Resources,
    /// No resource of the checklist covers the prefix claimed.
    NotCovered,
    /// The checklist does not sign this tenant's claim to this prefix.
    NotChallenged,
}

impl Refusal {
    /// The reply's code: a signed object's own refusal below 0x40, the
    /// checklist's from 0x40.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Rpki(r) => r.code(),
            Self::Shape => 0x40,
            Self::Resources => 0x41,
            Self::NotCovered => 0x42,
            Self::NotChallenged => 0x43,
        }
    }
}

/// The document a tenant has its resource holder's CA list in an RSC to
/// prove it holds `claim`: `fabric-ownership.v1`, then the tenant, the
/// family, the address (sixteen bytes, IPv4 in the last four) and the
/// length — the traffic fabric's `ownership_challenge`, byte for byte.
#[must_use]
pub fn challenge(tenant: &[u8; 16], claim: &Claim) -> [u8; CHALLENGE_LEN] {
    let mut c = [0u8; CHALLENGE_LEN];
    c[..19].copy_from_slice(b"fabric-ownership.v1");
    c[19..35].copy_from_slice(tenant);
    c[35] = claim.family;
    c[36..52].copy_from_slice(&claim.addr);
    c[52] = claim.len;
    c
}

/// Verify `rsc` as `tenant`'s evidence that it holds `claim`, under the
/// chain `anchor` → `cas` with `crls`, at `now_s`.
#[allow(
    clippy::too_many_arguments,
    reason = "the chain, its CRLs, the checklist, whose claim and when: each an input of the one decision"
)]
pub fn verify(
    c: &mut impl Crypto,
    anchor: &[u8],
    cas: &[&[u8]],
    crls: &[&[u8]],
    rsc: &[u8],
    tenant: &[u8; 16],
    claim: &Claim,
    now_s: u64,
) -> Result<Evidence, Refusal> {
    let shape = Refusal::Shape;
    if !claim.valid() {
        return Err(shape);
    }
    let (content, ee_res) = rpki::signed_object(&mut *c, anchor, cas, crls, rsc, OID_RSC, now_s)
        .map_err(Refusal::Rpki)?;
    // RpkiSignedChecklist { version [0] DEFAULT 0, resources ResourceBlock,
    //   digestAlgorithm AlgorithmIdentifier, checkList SEQUENCE OF FileNameAndHash }
    let (body, _) = expect(content, 0x30).map_err(|_| shape)?;
    let mut f = body.body;
    if f.first() == Some(&0xa0) {
        let (v, next) = tlv(f).ok_or(shape)?;
        let (ver, _) = tlv(v.body).ok_or(shape)?;
        if der_uint(&ver) != Some(0) {
            return Err(shape);
        }
        f = next;
    }
    // ResourceBlock { asID [0] OPTIONAL, ipAddrBlocks [1] OPTIONAL }
    let (block, f) = expect(f, 0x30).map_err(|_| shape)?;
    let mut b = block.body;
    if b.first() == Some(&0xa0) {
        b = tlv(b).ok_or(shape)?.1;
    }
    let (ips, _) = expect(b, 0xa1).map_err(|_| shape)?;
    let want = claim.prefix();
    let mut covered = false;
    let mut any = false;
    let mut fams = ips.body;
    while !fams.is_empty() {
        let (fam, next) = expect(fams, 0x30).map_err(|_| shape)?;
        fams = next;
        let (afi, addrs) = tlv(fam.body).ok_or(shape)?;
        let family = afi_family(&afi).ok_or(shape)?;
        let (list, _) = expect(addrs, 0x30).map_err(|_| shape)?;
        let mut l = list.body;
        while !l.is_empty() {
            let (bits, next) = tlv(l).ok_or(shape)?;
            l = next;
            // Prefixes only: an address range is not read here.
            let p = bit_prefix(&bits, family).ok_or(shape)?;
            if !ee_res.covers(&p) {
                return Err(Refusal::Resources);
            }
            any = true;
            covered |= p.covers(&want);
        }
    }
    if !any {
        return Err(shape);
    }
    if !covered {
        return Err(Refusal::NotCovered);
    }
    let (alg, f) = expect(f, 0x30).map_err(|_| shape)?;
    let (oid, _) = expect(alg.body, 0x06).map_err(|_| shape)?;
    if oid.body != OID_SHA256 {
        return Err(shape);
    }
    let (checklist, _) = expect(f, 0x30).map_err(|_| shape)?;
    let want_digest = c.sha256(&challenge(tenant, claim));
    let mut found = false;
    let mut entries = checklist.body;
    while !entries.is_empty() {
        let (e, next) = expect(entries, 0x30).map_err(|_| shape)?;
        entries = next;
        let mut g = e.body;
        if g.first() == Some(&0x16) {
            g = tlv(g).ok_or(shape)?.1;
        }
        let (h, _) = expect(g, 0x04).map_err(|_| shape)?;
        found |= h.body == want_digest;
    }
    if !found {
        return Err(Refusal::NotChallenged);
    }
    let digest = c.sha256(rsc);
    Ok(Evidence {
        holder: *tenant,
        covers: *claim,
        digest,
        verified: true,
    })
}

// ── the typed operation ───────────────────────────────────────────────────

/// Envelope types (`auth_wire` framing; Kagi's typed-operation codes).
pub mod msg {
    /// `[op u8][body]`.
    pub const REQUEST: u8 = 0x9C;
    /// `[op u8][status u8][refusal u8][body]`.
    pub const REPLY: u8 = 0x9D;
}

pub mod op {
    /// Put one certificate or CRL in the cache: `[der f16]`.
    pub const CACHE: u8 = 1;
    /// Verify a checklist under cached objects (see the file comment).
    pub const VERIFY: u8 = 2;
}

pub mod status {
    pub const OK: u8 = 0;
    /// The request does not decode.
    pub const MALFORMED: u8 = 1;
    /// A digest the request names is not cached here.
    pub const NOT_CACHED: u8 = 2;
    /// The checklist is not the evidence claimed (`refusal` says why).
    pub const REFUSED: u8 = 3;
    /// No trusted clock to check validity against.
    pub const NO_CLOCK: u8 = 4;
    /// A CACHE of bytes that are neither a certificate nor a CRL this
    /// profile reads, or past [`super::CACHE_ITEM_MAX`].
    pub const NOT_CACHEABLE: u8 = 5;
}

/// The largest certificate or CRL the cache holds.
pub const CACHE_ITEM_MAX: usize = 4096;
/// Entries the cache holds; the oldest gives way.
pub const CACHE_SLOTS: usize = 12;
/// CRLs one VERIFY may name: one per issuer in the longest chain.
pub const CRLS_MAX: usize = rpki::CHAIN_MAX + 1;
/// The largest reply body: VERIFY's.
pub const REPLY_MAX: usize = 3 + 16 + 1 + 16 + 1 + 32 + 1;

/// A decoded VERIFY.
#[derive(Clone, Copy)]
pub struct VerifyRequest<'a> {
    pub anchor: [u8; 32],
    pub n_cas: usize,
    pub cas: [[u8; 32]; rpki::CHAIN_MAX],
    pub n_crls: usize,
    pub crls: [[u8; 32]; CRLS_MAX],
    pub tenant: [u8; 16],
    pub claim: Claim,
    pub rsc: &'a [u8],
}

/// A decoded request.
#[derive(Clone, Copy)]
#[allow(
    clippy::large_enum_variant,
    reason = "decoded once per request on the stack, never stored: no allocator to box into"
)]
pub enum Request<'a> {
    Cache(&'a [u8]),
    Verify(VerifyRequest<'a>),
}

fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if b.len() < n {
        return None;
    }
    let (h, t) = b.split_at(n);
    *b = t;
    Some(h)
}

fn take32(b: &mut &[u8]) -> Option<[u8; 32]> {
    let mut v = [0u8; 32];
    v.copy_from_slice(take(b, 32)?);
    Some(v)
}

fn take_f16<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = take(b, 2)?;
    take(b, usize::from(u16::from_le_bytes([n[0], n[1]])))
}

impl<'a> Request<'a> {
    /// Decode a REQUEST payload; `None` for anything else, trailing bytes
    /// included.
    #[must_use]
    pub fn decode(payload: &'a [u8]) -> Option<Self> {
        let mut b = payload;
        let o = *take(&mut b, 1)?.first()?;
        let r = match o {
            op::CACHE => Request::Cache(take_f16(&mut b)?),
            op::VERIFY => {
                let anchor = take32(&mut b)?;
                let n_cas = usize::from(*take(&mut b, 1)?.first()?);
                if n_cas > rpki::CHAIN_MAX {
                    return None;
                }
                let mut cas = [[0u8; 32]; rpki::CHAIN_MAX];
                for d in cas.iter_mut().take(n_cas) {
                    *d = take32(&mut b)?;
                }
                let n_crls = usize::from(*take(&mut b, 1)?.first()?);
                if n_crls > CRLS_MAX {
                    return None;
                }
                let mut crls = [[0u8; 32]; CRLS_MAX];
                for d in crls.iter_mut().take(n_crls) {
                    *d = take32(&mut b)?;
                }
                let mut tenant = [0u8; 16];
                tenant.copy_from_slice(take(&mut b, 16)?);
                let family = *take(&mut b, 1)?.first()?;
                let mut addr = [0u8; 16];
                addr.copy_from_slice(take(&mut b, 16)?);
                let len = *take(&mut b, 1)?.first()?;
                let rsc = take_f16(&mut b)?;
                Request::Verify(VerifyRequest {
                    anchor,
                    n_cas,
                    cas,
                    n_crls,
                    crls,
                    tenant,
                    claim: Claim { family, addr, len },
                    rsc,
                })
            }
            _ => return None,
        };
        b.is_empty().then_some(r)
    }
}

/// Encode a VERIFY request (a relying party's half).
pub fn encode_verify(
    anchor: &[u8; 32],
    cas: &[[u8; 32]],
    crls: &[[u8; 32]],
    tenant: &[u8; 16],
    claim: &Claim,
    rsc: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if cas.len() > rpki::CHAIN_MAX || crls.len() > CRLS_MAX {
        return None;
    }
    let n = 1 + 32 + 1 + 32 * cas.len() + 1 + 32 * crls.len() + 16 + 1 + 16 + 1 + 2 + rsc.len();
    let o = out.get_mut(..n)?;
    let mut at = 0;
    let mut put = |b: &[u8]| {
        o[at..at + b.len()].copy_from_slice(b);
        at += b.len();
    };
    put(&[op::VERIFY]);
    put(anchor);
    put(&[cas.len() as u8]);
    for d in cas {
        put(d);
    }
    put(&[crls.len() as u8]);
    for d in crls {
        put(d);
    }
    put(tenant);
    put(&[claim.family]);
    put(&claim.addr);
    put(&[claim.len]);
    put(&u16::try_from(rsc.len()).ok()?.to_le_bytes());
    put(rsc);
    Some(n)
}

/// Encode a CACHE request.
pub fn encode_cache(der: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = 1 + 2 + der.len();
    let o = out.get_mut(..n)?;
    o[0] = op::CACHE;
    o[1..3].copy_from_slice(&u16::try_from(der.len()).ok()?.to_le_bytes());
    o[3..].copy_from_slice(der);
    Some(n)
}

/// A CACHE reply.
pub fn reply_cache(st: u8, digest: &[u8; 32], out: &mut [u8; REPLY_MAX]) -> usize {
    out[0] = op::CACHE;
    out[1] = st;
    out[2] = 0;
    out[3..35].copy_from_slice(if st == status::OK { digest } else { &[0; 32] });
    35
}

/// A VERIFY reply: the evidence, or a refusal with the body zeroed.
pub fn reply_verify(st: u8, refusal: u8, e: &Evidence, out: &mut [u8; REPLY_MAX]) -> usize {
    *out = [0; REPLY_MAX];
    out[0] = op::VERIFY;
    out[1] = st;
    out[2] = refusal;
    if st == status::OK && e.verified {
        out[3..19].copy_from_slice(&e.holder);
        out[19] = e.covers.family;
        out[20..36].copy_from_slice(&e.covers.addr);
        out[36] = e.covers.len;
        out[37..69].copy_from_slice(&e.digest);
        out[69] = 1;
    }
    REPLY_MAX
}

/// A VERIFY reply, decoded (a relying party's half): the evidence when the
/// status is OK and it says verified, else the status and refusal.
pub fn read_verify(b: &[u8]) -> Result<Evidence, (u8, u8)> {
    if b.len() != REPLY_MAX || b[0] != op::VERIFY {
        return Err((status::MALFORMED, 0));
    }
    if b[1] != status::OK || b[69] != 1 {
        return Err((b[1], b[2]));
    }
    let mut e = Evidence {
        verified: true,
        ..Evidence::default()
    };
    e.holder.copy_from_slice(&b[3..19]);
    e.covers.family = b[19];
    e.covers.addr.copy_from_slice(&b[20..36]);
    e.covers.len = b[36];
    e.digest.copy_from_slice(&b[37..69]);
    Ok(e)
}

/// Whether `der` is a certificate or a CRL this profile reads.
#[must_use]
pub fn cacheable(der: &[u8]) -> bool {
    der.len() <= CACHE_ITEM_MAX && (rpki::cert_parse(der).is_ok() || rpki::crl_parse(der).is_ok())
}

/// The bounded cache: certificates and CRLs by SHA-256, the oldest giving
/// way. All-zero memory is the empty cache.
pub struct Cache {
    pub lens: [u16; CACHE_SLOTS],
    pub ages: [u32; CACHE_SLOTS],
    pub digests: [[u8; 32]; CACHE_SLOTS],
    pub items: [[u8; CACHE_ITEM_MAX]; CACHE_SLOTS],
    pub clock: u32,
}

impl Cache {
    pub const EMPTY: Self = Self {
        lens: [0; CACHE_SLOTS],
        ages: [0; CACHE_SLOTS],
        digests: [[0; 32]; CACHE_SLOTS],
        items: [[0; CACHE_ITEM_MAX]; CACHE_SLOTS],
        clock: 0,
    };

    /// Hold `der` under `digest` (its SHA-256); already held, it is
    /// refreshed.
    pub fn put(&mut self, digest: &[u8; 32], der: &[u8]) -> bool {
        if der.len() > CACHE_ITEM_MAX {
            return false;
        }
        self.clock = self.clock.wrapping_add(1);
        let slot = (0..CACHE_SLOTS)
            .find(|&i| self.lens[i] != 0 && self.digests[i] == *digest)
            .or_else(|| (0..CACHE_SLOTS).find(|&i| self.lens[i] == 0))
            .unwrap_or_else(|| {
                (0..CACHE_SLOTS)
                    .max_by_key(|&i| self.clock.wrapping_sub(self.ages[i]))
                    .unwrap_or(0)
            });
        self.items[slot][..der.len()].copy_from_slice(der);
        self.lens[slot] = der.len() as u16;
        self.digests[slot] = *digest;
        self.ages[slot] = self.clock;
        true
    }

    /// The object held under `digest`.
    #[must_use]
    pub fn get(&self, digest: &[u8; 32]) -> Option<&[u8]> {
        (0..CACHE_SLOTS)
            .find(|&i| self.lens[i] != 0 && self.digests[i] == *digest)
            .map(|i| &self.items[i][..usize::from(self.lens[i])])
    }
}

/// Answer one decoded VERIFY against `cache` at `now_s` (0: no clock): the
/// reply's status, refusal and evidence.
pub fn answer_verify(
    c: &mut impl Crypto,
    cache: &Cache,
    v: &VerifyRequest<'_>,
    now_s: u64,
) -> (u8, u8, Evidence) {
    let none = Evidence::default();
    if now_s == 0 {
        return (status::NO_CLOCK, 0, none);
    }
    let Some(anchor) = cache.get(&v.anchor) else {
        return (status::NOT_CACHED, 0, none);
    };
    let mut cas: [&[u8]; rpki::CHAIN_MAX] = [&[]; rpki::CHAIN_MAX];
    for (slot, d) in cas.iter_mut().zip(&v.cas[..v.n_cas]) {
        match cache.get(d) {
            Some(b) => *slot = b,
            None => return (status::NOT_CACHED, 0, none),
        }
    }
    let mut crls: [&[u8]; CRLS_MAX] = [&[]; CRLS_MAX];
    for (slot, d) in crls.iter_mut().zip(&v.crls[..v.n_crls]) {
        match cache.get(d) {
            Some(b) => *slot = b,
            None => return (status::NOT_CACHED, 0, none),
        }
    }
    match verify(
        &mut *c,
        anchor,
        &cas[..v.n_cas],
        &crls[..v.n_crls],
        v.rsc,
        &v.tenant,
        &v.claim,
        now_s,
    ) {
        Ok(e) => (status::OK, 0, e),
        Err(r) => (status::REFUSED, r.code(), none),
    }
}

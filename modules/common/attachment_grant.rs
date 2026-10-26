//! Private producer/consumer attachments (`KATT`): the producer's signed
//! publication, and the grant that admits one consumer to it.
//!
//! Wormhole's RFC §11.12 exposes one service identity across tenants without
//! connecting their networks. The attachment identity is `(producer_tenant,
//! service_id, consumer_tenant, attachment_id, attachment_generation)`, and
//! Kagi authorises both halves: the producer's declaration and the
//! consumer's request. Lattice stores the desired attachment, Clustor
//! commits its generations; Kagi stores neither. Two records carry Kagi's
//! decisions instead:
//!
//! - a **publication** ([`kind::PUBLICATION`]): the producer tenant and
//!   service, the direction, the source-identity disclosure, quota ceilings,
//!   and the exact consumer tenants and trust domains it accepts. The
//!   producer hands it to Lattice beside its declaration; a consumer's
//!   request carries it back. Wildcards are refused: no `*` domain, no zero
//!   tenant, no empty set.
//! - a **grant** ([`kind::GRANT`]): the whole attachment identity, the
//!   consumer actor and its trust domain, the quotas granted (each within the
//!   publication's ceiling), and the digest of the publication it was
//!   decided under.
//!
//! Both carry the service's **revocation generation** at signing.
//! `attachment_revoke` advances it in the ledger (`kagi/attachments/`) —
//! the one piece of attachment state Kagi keeps — and Kagi refuses to grant
//! under a publication from an older generation. Wormhole compares a
//! grant's generation with the revocation boundary Clustor commits, so new
//! connections stop at the new generation.
//!
//! # Trust domains
//!
//! A domain is accepted as the SHA-256 of its lowercase name. A consumer is
//! in an accepted domain when its leaf chains to that domain's authority
//! and its SPIFFE name is in it: this instance's own domain (its CA key),
//! or a federated domain **pinned** by a control-plane keyset record naming
//! the domain and its CA key (`federation_key`). Kagi fetches nothing; a
//! federated domain's rotation is a deployment action, which keeps every
//! decision here verifiable offline.
//!
//! # The record
//!
//! | Off | Len | Field |
//! | --- | --- | --- |
//! | 0 | 4 | magic `KATT` |
//! | 4 | 1 | version |
//! | 5 | 1 | kind |
//! | 6 | 1 | direction ([`direction`]) |
//! | 7 | 1 | source-identity disclosure ([`disclosure`]) |
//! | 8 | 1 | consumer actor class (grant), producer actor class (publication) |
//! | 9 | 1 | accepted tenant count |
//! | 10 | 1 | accepted trust-domain count |
//! | 11 | 1 | reserved, zero |
//! | 12 | 16 | quotas: connections, bytes/s, flows, mirror credits (u32 each) |
//! | 28 | 4 | reserved, zero |
//! | 32 | 8 | issued at, Unix ms |
//! | 40 | 8 | expiry, Unix ms |
//! | 48 | 8 | revocation generation |
//! | 56 | 8 | attachment generation (grant), zero (publication) |
//! | 64 | 16 | producer tenant |
//! | 80 | 16 | service id |
//! | 96 | 16 | consumer tenant (grant), zero (publication) |
//! | 112 | 16 | attachment id (grant), zero (publication) |
//! | 128 | 16 | actor id: the consumer (grant) or producer (publication) |
//! | 144 | 32 | the actor's trust domain hash |
//! | 176 | 32 | publication digest (grant), zero (publication) |
//! | 208 | | accepted tenants `16 ×`, accepted domains `32 ×` |
//! | | | `issuer f8`, `kid f8`, `signature suite u16`, `signature f16` |
//!
//! A grant repeats the publication's accepted sets: it is self-contained
//! for an auditor, and a grant whose consumer is not in them does not
//! parse as a grant this profile issues.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::storage_key::{hex_into, Reader, Writer};

pub type Sha256Fn = fn(&[u8], &mut [u8; 32]);
pub type VerifyFn = fn(u16, &[u8], &[u8], &[u8]) -> bool;

pub const MAGIC: [u8; 4] = *b"KATT";
pub const VERSION: u8 = 1;

pub mod kind {
    pub const PUBLICATION: u8 = 1;
    pub const GRANT: u8 = 2;
}

/// Which way connections may be opened across the attachment.
pub mod direction {
    /// Consumer to producer only: the attachment's purpose.
    pub const CONSUMER_TO_PRODUCER: u8 = 1;
    /// Both. Declared, never inferred: the RFC forbids an undeclared reverse
    /// connection.
    pub const BIDIRECTIONAL: u8 = 2;

    #[must_use]
    pub const fn valid(d: u8) -> bool {
        matches!(d, CONSUMER_TO_PRODUCER | BIDIRECTIONAL)
    }
}

/// What the producer learns of the consumer's source identity.
pub mod disclosure {
    pub const NONE: u8 = 0;
    pub const TENANT: u8 = 1;
    pub const IDENTITY: u8 = 2;

    #[must_use]
    pub const fn valid(d: u8) -> bool {
        d <= IDENTITY
    }
}

pub const MAX_TENANTS: usize = 8;
pub const MAX_DOMAINS: usize = 8;
/// Longest trust-domain name a publication names.
pub const MAX_DOMAIN_NAME: usize = 253;
/// The longest a publication stands before it is re-published: 30 days.
pub const MAX_PUBLICATION_MS: u64 = 30 * 24 * 3600 * 1000;
/// The longest a grant stands: one day. The consumer re-requests, which is
/// when a revocation it missed reaches it.
pub const MAX_GRANT_MS: u64 = 24 * 3600 * 1000;
/// Issue-time skew a verifier allows: a record dated further ahead of the
/// verifier's clock than this is refused as not yet valid.
pub const SKEW_MS: u64 = 5_000;

pub const FIXED_LEN: usize = 208;
pub const MAX_ID: usize = 64;
pub const MAX_SIGNATURE: usize = 64;
pub const MAX_RECORD: usize =
    FIXED_LEN + MAX_TENANTS * 16 + MAX_DOMAINS * 32 + 2 * (1 + MAX_ID) + 2 + 2 + MAX_SIGNATURE;

pub const OFF_KIND: usize = 5;
pub const OFF_QUOTAS: usize = 12;
pub const OFF_REVOCATION: usize = 48;
pub const OFF_SERVICE: usize = 80;

/// Why an attachment act was refused. Stable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Refusal {
    Malformed = 1,
    NotAuthenticated = 2,
    /// A `*` domain, a zero tenant, or an empty accepted set.
    Wildcard = 3,
    /// The consumer tenant is not one the publication accepts.
    TenantNotAccepted = 4,
    /// The consumer's trust domain is not one the publication accepts.
    DomainNotAccepted = 5,
    /// The caller's class may not make this act: a device, or a host.
    ActorNotPermitted = 6,
    /// The request names another producer or service than its publication.
    WrongService = 7,
    /// A quota of zero, or above the publication's ceiling.
    QuotaExceeded = 8,
    /// The publication or grant is past its expiry.
    Expired = 9,
    /// The publication predates the service's revocation generation.
    Revoked = 10,
    BadSignature = 11,
    UnknownKey = 12,
    NoIssuerKey = 13,
    LedgerUnavailable = 14,
    Conflict = 15,
    NoClock = 16,
    Busy = 17,
    /// A revocation must name a generation above the current one.
    GenerationNotAdvanced = 18,
    WindowInvalid = 19,
    /// A producer act from outside this instance's own trust domain.
    ForeignProducer = 20,
    /// A publication presented where a grant is required, or the reverse
    /// ([`Record::verify_as`]).
    WrongKind = 21,
}

impl Refusal {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

fn rd_u32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd_u64(b: &[u8], at: usize) -> Option<u64> {
    let s = b.get(at..at + 8)?;
    let mut v = [0u8; 8];
    v.copy_from_slice(s);
    Some(u64::from_le_bytes(v))
}

fn rd_arr<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    let s = b.get(at..at + N)?;
    let mut v = [0u8; N];
    v.copy_from_slice(s);
    Some(v)
}

/// The four per-attachment credits.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Quotas {
    pub connections: u32,
    pub bytes_per_sec: u32,
    pub flows: u32,
    pub mirror_credits: u32,
}

impl Quotas {
    /// Every quota nonzero, except mirror credits which may be zero (no
    /// mirror), and none above `ceiling`.
    #[must_use]
    pub const fn within(&self, ceiling: &Self) -> bool {
        self.connections != 0
            && self.bytes_per_sec != 0
            && self.flows != 0
            && self.connections <= ceiling.connections
            && self.bytes_per_sec <= ceiling.bytes_per_sec
            && self.flows <= ceiling.flows
            && self.mirror_credits <= ceiling.mirror_credits
    }
}

/// A record's fixed part and its accepted sets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Attachment {
    pub kind: u8,
    pub direction: u8,
    pub disclosure: u8,
    pub actor_class: u8,
    pub quotas: Quotas,
    pub issued_ms: u64,
    pub expiry_ms: u64,
    pub revocation_generation: u64,
    pub attachment_generation: u64,
    pub producer_tenant: [u8; 16],
    pub service: [u8; 16],
    pub consumer_tenant: [u8; 16],
    pub attachment_id: [u8; 16],
    pub actor: [u8; 16],
    pub actor_domain: [u8; 32],
    pub publication: [u8; 32],
    pub tenants: [[u8; 16]; MAX_TENANTS],
    pub tenant_count: usize,
    pub domains: [[u8; 32]; MAX_DOMAINS],
    pub domain_count: usize,
}

impl Attachment {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            kind: 0,
            direction: 0,
            disclosure: 0,
            actor_class: 0,
            quotas: Quotas {
                connections: 0,
                bytes_per_sec: 0,
                flows: 0,
                mirror_credits: 0,
            },
            issued_ms: 0,
            expiry_ms: 0,
            revocation_generation: 0,
            attachment_generation: 0,
            producer_tenant: [0; 16],
            service: [0; 16],
            consumer_tenant: [0; 16],
            attachment_id: [0; 16],
            actor: [0; 16],
            actor_domain: [0; 32],
            publication: [0; 32],
            tenants: [[0; 16]; MAX_TENANTS],
            tenant_count: 0,
            domains: [[0; 32]; MAX_DOMAINS],
            domain_count: 0,
        }
    }

    #[must_use]
    pub fn tenants(&self) -> &[[u8; 16]] {
        self.tenants.get(..self.tenant_count).unwrap_or(&[])
    }

    #[must_use]
    pub fn domains(&self) -> &[[u8; 32]] {
        self.domains.get(..self.domain_count).unwrap_or(&[])
    }

    /// The accepted sets hold no wildcard: nonempty, no zero tenant, no
    /// repeated entry.
    pub fn check_sets(&self) -> Result<(), Refusal> {
        let tenants = self.tenants();
        let domains = self.domains();
        if tenants.is_empty() || domains.is_empty() {
            return Err(Refusal::Wildcard);
        }
        if tenants.contains(&[0; 16]) {
            return Err(Refusal::Wildcard);
        }
        for (i, t) in tenants.iter().enumerate() {
            if tenants.iter().skip(i + 1).any(|u| u == t) {
                return Err(Refusal::Malformed);
            }
        }
        for (i, d) in domains.iter().enumerate() {
            if domains.iter().skip(i + 1).any(|e| e == d) {
                return Err(Refusal::Malformed);
            }
        }
        Ok(())
    }

    /// The fixed part is one this profile issues.
    pub fn check(&self) -> Result<(), Refusal> {
        if !direction::valid(self.direction) || !disclosure::valid(self.disclosure) {
            return Err(Refusal::Malformed);
        }
        self.check_sets()?;
        let ceiling = match self.kind {
            kind::PUBLICATION => MAX_PUBLICATION_MS,
            kind::GRANT => MAX_GRANT_MS,
            _ => return Err(Refusal::Malformed),
        };
        if self.expiry_ms <= self.issued_ms || self.expiry_ms - self.issued_ms > ceiling {
            return Err(Refusal::WindowInvalid);
        }
        if self.kind == kind::PUBLICATION {
            if self.consumer_tenant != [0; 16]
                || self.attachment_id != [0; 16]
                || self.attachment_generation != 0
                || self.publication != [0; 32]
            {
                return Err(Refusal::Malformed);
            }
        } else {
            if self.attachment_generation == 0 || self.attachment_id == [0; 16] {
                return Err(Refusal::Malformed);
            }
            if !self.tenants().contains(&self.consumer_tenant) {
                return Err(Refusal::TenantNotAccepted);
            }
            if !self.domains().contains(&self.actor_domain) {
                return Err(Refusal::DomainNotAccepted);
            }
        }
        Ok(())
    }

    fn write(&self, w: &mut Writer<'_>) -> Option<()> {
        w.bytes(&MAGIC)?;
        w.u8(VERSION)?;
        w.u8(self.kind)?;
        w.u8(self.direction)?;
        w.u8(self.disclosure)?;
        w.u8(self.actor_class)?;
        w.u8(u8::try_from(self.tenant_count).ok()?)?;
        w.u8(u8::try_from(self.domain_count).ok()?)?;
        w.u8(0)?;
        w.u32(self.quotas.connections)?;
        w.u32(self.quotas.bytes_per_sec)?;
        w.u32(self.quotas.flows)?;
        w.u32(self.quotas.mirror_credits)?;
        w.u32(0)?;
        w.u64(self.issued_ms)?;
        w.u64(self.expiry_ms)?;
        w.u64(self.revocation_generation)?;
        w.u64(self.attachment_generation)?;
        w.bytes(&self.producer_tenant)?;
        w.bytes(&self.service)?;
        w.bytes(&self.consumer_tenant)?;
        w.bytes(&self.attachment_id)?;
        w.bytes(&self.actor)?;
        w.bytes(&self.actor_domain)?;
        w.bytes(&self.publication)?;
        for t in self.tenants() {
            w.bytes(t)?;
        }
        for d in self.domains() {
            w.bytes(d)?;
        }
        Some(())
    }

    /// The fixed part and the sets; answers where the sets end.
    fn read(b: &[u8]) -> Option<(Self, usize)> {
        if b.get(..4)? != MAGIC || *b.get(4)? != VERSION || *b.get(11)? != 0 {
            return None;
        }
        if rd_u32(b, 28)? != 0 {
            return None;
        }
        let tenant_count = usize::from(*b.get(9)?);
        let domain_count = usize::from(*b.get(10)?);
        if tenant_count > MAX_TENANTS || domain_count > MAX_DOMAINS {
            return None;
        }
        let mut a = Self {
            kind: *b.get(OFF_KIND)?,
            direction: *b.get(6)?,
            disclosure: *b.get(7)?,
            actor_class: *b.get(8)?,
            quotas: Quotas {
                connections: rd_u32(b, OFF_QUOTAS)?,
                bytes_per_sec: rd_u32(b, OFF_QUOTAS + 4)?,
                flows: rd_u32(b, OFF_QUOTAS + 8)?,
                mirror_credits: rd_u32(b, OFF_QUOTAS + 12)?,
            },
            issued_ms: rd_u64(b, 32)?,
            expiry_ms: rd_u64(b, 40)?,
            revocation_generation: rd_u64(b, OFF_REVOCATION)?,
            attachment_generation: rd_u64(b, 56)?,
            producer_tenant: rd_arr(b, 64)?,
            service: rd_arr(b, OFF_SERVICE)?,
            consumer_tenant: rd_arr(b, 96)?,
            attachment_id: rd_arr(b, 112)?,
            actor: rd_arr(b, 128)?,
            actor_domain: rd_arr(b, 144)?,
            publication: rd_arr(b, 176)?,
            tenants: [[0; 16]; MAX_TENANTS],
            tenant_count,
            domains: [[0; 32]; MAX_DOMAINS],
            domain_count,
        };
        let mut at = FIXED_LEN;
        for slot in a.tenants.iter_mut().take(tenant_count) {
            *slot = rd_arr(b, at)?;
            at += 16;
        }
        for slot in a.domains.iter_mut().take(domain_count) {
            *slot = rd_arr(b, at)?;
            at += 32;
        }
        Some((a, at))
    }
}

/// The signer a record names.
#[derive(Clone, Copy)]
pub struct Signer<'a> {
    pub issuer: &'a [u8],
    pub kid: &'a [u8],
}

pub fn write_unsigned(
    out: &mut [u8],
    a: &Attachment,
    signer: &Signer<'_>,
    signature_suite: u16,
) -> Option<usize> {
    if signer.issuer.is_empty()
        || signer.issuer.len() > MAX_ID
        || signer.kid.is_empty()
        || signer.kid.len() > MAX_ID
        || a.tenant_count > MAX_TENANTS
        || a.domain_count > MAX_DOMAINS
    {
        return None;
    }
    let mut w = Writer::new(out);
    a.write(&mut w)?;
    w.f8(signer.issuer)?;
    w.f8(signer.kid)?;
    w.u16(signature_suite)?;
    Some(w.len())
}

pub fn append_signature(out: &mut [u8], unsigned: usize, signature: &[u8]) -> Option<usize> {
    if signature.is_empty() || signature.len() > MAX_SIGNATURE {
        return None;
    }
    let mut w = Writer::new(out.get_mut(unsigned..)?);
    w.f16(signature)?;
    unsigned.checked_add(w.len())
}

/// A parsed record.
#[derive(Clone, Copy)]
pub struct Record<'a> {
    pub attachment: Attachment,
    pub signer: Signer<'a>,
    pub signature_suite: u16,
    pub signature: &'a [u8],
    pub signed: &'a [u8],
}

impl<'a> Record<'a> {
    /// Structure only; trailing bytes refused.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Refusal> {
        let (attachment, end) = Attachment::read(bytes).ok_or(Refusal::Malformed)?;
        let mut r = Reader::new(bytes);
        r.take(end).ok_or(Refusal::Malformed)?;
        let issuer = r.f8().ok_or(Refusal::Malformed)?;
        let kid = r.f8().ok_or(Refusal::Malformed)?;
        if issuer.is_empty() || issuer.len() > MAX_ID || kid.is_empty() || kid.len() > MAX_ID {
            return Err(Refusal::Malformed);
        }
        let signature_suite = r.u16().ok_or(Refusal::Malformed)?;
        let signed_len = r.position();
        let signature = r.f16().ok_or(Refusal::Malformed)?;
        if r.remaining() != 0 || signature.is_empty() || signature.len() > MAX_SIGNATURE {
            return Err(Refusal::Malformed);
        }
        Ok(Self {
            attachment,
            signer: Signer { issuer, kid },
            signature_suite,
            signature,
            signed: bytes.get(..signed_len).ok_or(Refusal::Malformed)?,
        })
    }

    /// Offline verification: well formed, signed by the key `lookup` names
    /// under its own suite, live at `now_ms` (`0` is no clock).
    pub fn verify<'k, F>(&self, lookup: F, verify: VerifyFn, now_ms: u64) -> Result<(), Refusal>
    where
        F: FnOnce(&[u8], &[u8]) -> Option<(u16, &'k [u8])>,
    {
        self.attachment.check()?;
        let (suite, public) =
            lookup(self.signer.issuer, self.signer.kid).ok_or(Refusal::UnknownKey)?;
        if self.signature_suite != suite || !verify(suite, public, self.signed, self.signature) {
            return Err(Refusal::BadSignature);
        }
        if now_ms == 0 {
            return Err(Refusal::NoClock);
        }
        if now_ms >= self.attachment.expiry_ms {
            return Err(Refusal::Expired);
        }
        if self.attachment.issued_ms > now_ms.saturating_add(SKEW_MS) {
            return Err(Refusal::WindowInvalid);
        }
        Ok(())
    }

    /// [`Record::verify`], and the record is of `want` ([`kind`]). What a
    /// broker runs before it installs an attachment from a grant: a
    /// publication verifies under the same key and must never stand in for
    /// one.
    pub fn verify_as<'k, F>(
        &self,
        want: u8,
        lookup: F,
        verify: VerifyFn,
        now_ms: u64,
    ) -> Result<&Attachment, Refusal>
    where
        F: FnOnce(&[u8], &[u8]) -> Option<(u16, &'k [u8])>,
    {
        self.verify(lookup, verify, now_ms)?;
        if self.attachment.kind == want {
            Ok(&self.attachment)
        } else {
            Err(Refusal::WrongKind)
        }
    }
}

#[must_use]
pub fn record_digest(sha: Sha256Fn, record: &[u8]) -> [u8; 32] {
    let mut d = [0u8; 32];
    sha(record, &mut d);
    d
}

/// How a trust domain is named in an accepted set: SHA-256 of its name.
///
/// The name must be a plain lowercase DNS-shaped label sequence. A `*`
/// anywhere, an empty name or an uppercase letter is not a domain this
/// profile names — the first two because they would be wildcards, the third
/// because a domain has one spelling and so one hash.
pub fn domain_hash(sha: Sha256Fn, name: &[u8]) -> Result<[u8; 32], Refusal> {
    // An explicit scan: `<[u8]>::contains` lowers to `memchr`, which a
    // position-independent module has no symbol for.
    #[expect(
        clippy::manual_contains,
        reason = "<[u8]>::contains links memchr, which a PIC module cannot resolve"
    )]
    let wildcard = name.iter().any(|&c| c == b'*');
    if wildcard {
        return Err(Refusal::Wildcard);
    }
    if name.is_empty()
        || name.len() > MAX_DOMAIN_NAME
        || !name
            .iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
    {
        return Err(Refusal::Malformed);
    }
    let mut d = [0u8; 32];
    sha(name, &mut d);
    Ok(d)
}

// ── The acts ────────────────────────────────────────────────────────────

/// `spiffe::Class` codes, restated.
pub mod class {
    pub const WORKLOAD: u8 = 2;
    pub const SERVICE: u8 = 3;
    pub const HOST: u8 = 4;
    pub const OPERATOR: u8 = 5;
}

/// An authenticated caller: its class, id and trust domain hash, and
/// whether that domain is this instance's own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Actor {
    pub class: u8,
    pub id: [u8; 16],
    pub domain: [u8; 32],
    pub local: bool,
}

/// A producer's publication request.
///
/// `[producer tenant 16][service 16][direction u8][disclosure u8]
/// [quota ceilings 4×u32][ttl ms u64][tenant count u8][tenants 16×]
/// [domain count u8][domains f8×][carrier f16]`
#[derive(Clone, Copy)]
pub struct Publish<'a> {
    pub producer_tenant: [u8; 16],
    pub service: [u8; 16],
    pub direction: u8,
    pub disclosure: u8,
    pub ceilings: Quotas,
    pub ttl_ms: u64,
    pub tenants: [[u8; 16]; MAX_TENANTS],
    pub tenant_count: usize,
    pub domains: [&'a [u8]; MAX_DOMAINS],
    pub domain_count: usize,
    pub carrier: &'a [u8],
}

fn read_quotas(r: &mut Reader<'_>) -> Option<Quotas> {
    Some(Quotas {
        connections: r.u32()?,
        bytes_per_sec: r.u32()?,
        flows: r.u32()?,
        mirror_credits: r.u32()?,
    })
}

fn write_quotas(w: &mut Writer<'_>, q: &Quotas) -> Option<()> {
    w.u32(q.connections)?;
    w.u32(q.bytes_per_sec)?;
    w.u32(q.flows)?;
    w.u32(q.mirror_credits)
}

impl<'a> Publish<'a> {
    pub fn decode(b: &'a [u8]) -> Result<Self, Refusal> {
        let bad = Refusal::Malformed;
        let mut r = Reader::new(b);
        let producer_tenant = r.arr().ok_or(bad)?;
        let service = r.arr().ok_or(bad)?;
        let direction = r.u8().ok_or(bad)?;
        let disclosure = r.u8().ok_or(bad)?;
        let ceilings = read_quotas(&mut r).ok_or(bad)?;
        let ttl_ms = r.u64().ok_or(bad)?;
        let tenant_count = usize::from(r.u8().ok_or(bad)?);
        if tenant_count > MAX_TENANTS {
            return Err(bad);
        }
        let mut tenants = [[0u8; 16]; MAX_TENANTS];
        for slot in tenants.iter_mut().take(tenant_count) {
            *slot = r.arr().ok_or(bad)?;
        }
        let domain_count = usize::from(r.u8().ok_or(bad)?);
        if domain_count > MAX_DOMAINS {
            return Err(bad);
        }
        let mut domains: [&[u8]; MAX_DOMAINS] = [&[]; MAX_DOMAINS];
        for slot in domains.iter_mut().take(domain_count) {
            *slot = r.f8().ok_or(bad)?;
        }
        let carrier = r.f16().ok_or(bad)?;
        if r.remaining() != 0 || carrier.is_empty() {
            return Err(bad);
        }
        Ok(Self {
            producer_tenant,
            service,
            direction,
            disclosure,
            ceilings,
            ttl_ms,
            tenants,
            tenant_count,
            domains,
            domain_count,
            carrier,
        })
    }

    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&self.producer_tenant)?;
        w.bytes(&self.service)?;
        w.u8(self.direction)?;
        w.u8(self.disclosure)?;
        write_quotas(&mut w, &self.ceilings)?;
        w.u64(self.ttl_ms)?;
        w.u8(u8::try_from(self.tenant_count).ok()?)?;
        for t in self.tenants.iter().take(self.tenant_count) {
            w.bytes(t)?;
        }
        w.u8(u8::try_from(self.domain_count).ok()?)?;
        for d in self.domains.iter().take(self.domain_count) {
            w.f8(d)?;
        }
        w.f16(self.carrier)?;
        Some(w.len())
    }
}

/// Decide a publication: the producer is a workload, service or operator of
/// this instance's own trust domain; every accepted domain is a named
/// domain and every tenant an exact one. Stamped with `generation`.
pub fn decide_publish(
    sha: Sha256Fn,
    req: &Publish<'_>,
    actor: Option<Actor>,
    generation: u64,
    now_ms: u64,
) -> Result<Attachment, Refusal> {
    if now_ms == 0 {
        return Err(Refusal::NoClock);
    }
    let actor = actor.ok_or(Refusal::NotAuthenticated)?;
    if !matches!(
        actor.class,
        class::WORKLOAD | class::SERVICE | class::OPERATOR
    ) {
        return Err(Refusal::ActorNotPermitted);
    }
    if !actor.local {
        return Err(Refusal::ForeignProducer);
    }
    if req.producer_tenant == [0; 16] || req.service == [0; 16] {
        return Err(Refusal::Malformed);
    }
    let mut a = Attachment::empty();
    a.kind = kind::PUBLICATION;
    a.direction = req.direction;
    a.disclosure = req.disclosure;
    a.actor_class = actor.class;
    a.quotas = req.ceilings;
    a.issued_ms = now_ms;
    a.expiry_ms = now_ms.saturating_add(req.ttl_ms.clamp(1, MAX_PUBLICATION_MS));
    a.revocation_generation = generation;
    a.producer_tenant = req.producer_tenant;
    a.service = req.service;
    a.actor = actor.id;
    a.actor_domain = actor.domain;
    a.tenants = req.tenants;
    a.tenant_count = req.tenant_count;
    for (slot, name) in a
        .domains
        .iter_mut()
        .zip(req.domains.iter().take(req.domain_count))
    {
        *slot = domain_hash(sha, name)?;
    }
    a.domain_count = req.domain_count;
    // A quota ceiling of zero admits nobody; a publication that cannot be
    // attached to is not one to sign.
    if !req.ceilings.within(&req.ceilings) {
        return Err(Refusal::QuotaExceeded);
    }
    a.check()?;
    Ok(a)
}

/// A consumer's request.
///
/// `[publication f16][producer tenant 16][service 16][consumer tenant 16]
/// [attachment generation u64][quotas 4×u32][ttl ms u64][carrier f16]`
#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub publication: &'a [u8],
    pub producer_tenant: [u8; 16],
    pub service: [u8; 16],
    pub consumer_tenant: [u8; 16],
    pub attachment_generation: u64,
    pub quotas: Quotas,
    pub ttl_ms: u64,
    pub carrier: &'a [u8],
}

impl<'a> Request<'a> {
    pub fn decode(b: &'a [u8]) -> Result<Self, Refusal> {
        let bad = Refusal::Malformed;
        let mut r = Reader::new(b);
        let req = Self {
            publication: r.f16().ok_or(bad)?,
            producer_tenant: r.arr().ok_or(bad)?,
            service: r.arr().ok_or(bad)?,
            consumer_tenant: r.arr().ok_or(bad)?,
            attachment_generation: r.u64().ok_or(bad)?,
            quotas: read_quotas(&mut r).ok_or(bad)?,
            ttl_ms: r.u64().ok_or(bad)?,
            carrier: r.f16().ok_or(bad)?,
        };
        if r.remaining() != 0 || req.carrier.is_empty() || req.publication.is_empty() {
            return Err(bad);
        }
        Ok(req)
    }

    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.f16(self.publication)?;
        w.bytes(&self.producer_tenant)?;
        w.bytes(&self.service)?;
        w.bytes(&self.consumer_tenant)?;
        w.u64(self.attachment_generation)?;
        write_quotas(&mut w, &self.quotas)?;
        w.u64(self.ttl_ms)?;
        w.f16(self.carrier)?;
        Some(w.len())
    }
}

/// Decide a consumer's request against the publication it carries, already
/// verified by the caller under this issuer's key. `generation` is the
/// service's current revocation generation and `attachment_id` a fresh id.
pub fn decide_request(
    req: &Request<'_>,
    publication: &Attachment,
    actor: Option<Actor>,
    generation: u64,
    attachment_id: [u8; 16],
    now_ms: u64,
) -> Result<Attachment, Refusal> {
    if now_ms == 0 {
        return Err(Refusal::NoClock);
    }
    let actor = actor.ok_or(Refusal::NotAuthenticated)?;
    if !matches!(actor.class, class::WORKLOAD | class::OPERATOR) {
        return Err(Refusal::ActorNotPermitted);
    }
    let p = publication;
    if p.kind != kind::PUBLICATION
        || p.producer_tenant != req.producer_tenant
        || p.service != req.service
    {
        return Err(Refusal::WrongService);
    }
    if p.revocation_generation != generation {
        return Err(Refusal::Revoked);
    }
    if now_ms >= p.expiry_ms {
        return Err(Refusal::Expired);
    }
    if req.consumer_tenant == [0; 16] {
        return Err(Refusal::Wildcard);
    }
    if !p.tenants().contains(&req.consumer_tenant) {
        return Err(Refusal::TenantNotAccepted);
    }
    if !p.domains().contains(&actor.domain) {
        return Err(Refusal::DomainNotAccepted);
    }
    if req.attachment_generation == 0 {
        return Err(Refusal::Malformed);
    }
    if !req.quotas.within(&p.quotas) {
        return Err(Refusal::QuotaExceeded);
    }
    let ttl = req.ttl_ms.clamp(1, MAX_GRANT_MS);
    let mut g = *p;
    g.kind = kind::GRANT;
    g.actor_class = actor.class;
    g.actor = actor.id;
    g.actor_domain = actor.domain;
    g.quotas = req.quotas;
    g.issued_ms = now_ms;
    // A grant never outlives the publication it was decided under.
    g.expiry_ms = now_ms.saturating_add(ttl).min(p.expiry_ms);
    g.revocation_generation = generation;
    g.attachment_generation = req.attachment_generation;
    g.consumer_tenant = req.consumer_tenant;
    g.attachment_id = attachment_id;
    g.check()?;
    Ok(g)
}

// ── Ledger ──────────────────────────────────────────────────────────────

pub const GENERATION_MAGIC: [u8; 4] = *b"KATR";
pub const GENERATION_LEN: usize = 12;

#[must_use]
pub fn encode_generation(g: u64) -> [u8; GENERATION_LEN] {
    let mut out = [0u8; GENERATION_LEN];
    for (d, s) in out
        .iter_mut()
        .zip(GENERATION_MAGIC.iter().chain(g.to_le_bytes().iter()))
    {
        *d = *s;
    }
    out
}

#[must_use]
pub fn decode_generation(b: &[u8]) -> Option<u64> {
    if b.len() != GENERATION_LEN || b.get(..4)? != GENERATION_MAGIC {
        return None;
    }
    rd_u64(b, 4)
}

/// The ledger key of a service's revocation generation:
/// `<producer tenant hex>-<service hex>`.
pub fn generation_key(
    producer_tenant: &[u8; 16],
    service: &[u8; 16],
    out: &mut [u8],
) -> Option<usize> {
    let n = hex_into(producer_tenant, out)?;
    *out.get_mut(n)? = b'-';
    let m = hex_into(service, out.get_mut(n + 1..)?)?;
    Some(n + 1 + m)
}

// ── The typed operation's wire ──────────────────────────────────────────

pub mod msg {
    /// `[op u8][body]`.
    pub const REQUEST: u8 = 0x96;
    /// `[op u8][status u8][record f16][generation u64]`.
    pub const REPLY: u8 = 0x97;
}

pub mod op {
    /// Body: a [`super::Publish`].
    pub const PUBLISH: u8 = 1;
    /// Body: a [`super::Request`].
    pub const REQUEST: u8 = 2;
    /// `attachment_revoke`. Body: `[producer tenant 16][service 16]
    /// [revocation generation u64][carrier f16]`.
    pub const REVOKE: u8 = 3;
}

pub const STATUS_OK: u8 = 0;

pub fn write_reply(
    code: u8,
    refusal: Option<Refusal>,
    record: &[u8],
    generation: u64,
    out: &mut [u8],
) -> Option<usize> {
    let mut w = Writer::new(out);
    w.u8(code)?;
    w.u8(refusal.map_or(STATUS_OK, Refusal::code))?;
    w.f16(if refusal.is_none() { record } else { &[] })?;
    w.u64(generation)?;
    Some(w.len())
}

#[must_use]
pub fn read_reply(b: &[u8]) -> Option<(u8, u8, &[u8], u64)> {
    let mut r = Reader::new(b);
    let code = r.u8()?;
    let status = r.u8()?;
    let record = r.f16()?;
    let generation = r.u64()?;
    if r.remaining() != 0 || (status != STATUS_OK && !record.is_empty()) {
        return None;
    }
    Some((code, status, record, generation))
}

//! The signed `service_dns` projection (`KSDN`): the regional answers a DNS
//! front end may give for a service, under Kagi's signature.
//!
//! Wormhole's RFC §11.10 and §21 Phase 9 give a service without global
//! anycast a `service_dns` projection: the set of regional addresses, their
//! health and weights, bound to the global and DR generations the region
//! controller derived it under. The controller publishes it unsigned
//! (`region_ctl.v1` record 0xB6, `upstream_core.rs` in Wormhole); Nanocloud's
//! `service_dns` composes answers from it only once a signature it trusts
//! covers it, and fails closed otherwise. This is that signature.
//!
//! Kagi signs the projection **verbatim**: the record carries Wormhole's 224
//! bytes unchanged, and the consumer hands those same bytes to Wormhole's
//! `dns_answers` once [`Record::verify`] has passed. Kagi restates the layout
//! only to refuse what it will not sign — it never re-encodes a field — so
//! there is one encoding of a projection and it is Wormhole's.
//!
//! Kagi decides two things and stores nothing:
//!
//! - **who may publish**: a projection is signed only for an authenticated
//!   publisher the deployment pinned to that service ([`Policy`]) — a region
//!   controller signs for its own service and no other;
//! - **that the projection is one a resolver may act on**: well formed, a
//!   generation, a TTL no longer than the projection is valid, valid for at
//!   most [`MAX_VALID_MS`], issued within [`SKEW_MS`] of Kagi's clock. Which
//!   regions it names is the controller's decision, not Kagi's.
//!
//! Staleness — a projection older than one the consumer has already seen —
//! is the consumer's check (`dns_answers`' minimum global generation): Kagi
//! keeps no per-service state to compare against.
//!
//! Pure `no_std`, and it mounts nothing but itself, so a relying party can
//! verify with this file alone. SHA-256 and signature verification are
//! injected.
//!
//! # The projection (Wormhole's `region_ctl.v1` 0xB6, 224 bytes)
//!
//! | Off | Len | Field |
//! | --- | --- | --- |
//! | 0 | 16 | service id |
//! | 16 | 8 | generation |
//! | 24 | 8 | global generation |
//! | 32 | 8 | DR generation |
//! | 40 | 8 | issued at, Unix ms |
//! | 48 | 4 | valid for, ms |
//! | 52 | 4 | DNS TTL, s |
//! | 56 | 1 | answer count, at most [`ANSWERS_MAX`] |
//! | 57 | 7 | reserved, zero |
//! | 64 | 4 × 32 | answers: `region u32`, `family u8` (4 or 6), `health u8` (1 healthy, 2 draining), `weight u16`, `address 16`, reserved 8 zero; unused answers all zero |
//! | 192 | 32 | reserved, zero — the signature is this record's, not the projection's |
//!
//! # The record
//!
//! | Off | Len | Field |
//! | --- | --- | --- |
//! | 0 | 4 | magic `KSDN` |
//! | 4 | 1 | version ([`VERSION`]) |
//! | 5 | 3 | reserved, zero |
//! | 8 | 224 | the projection, verbatim |
//! | 232 | | `issuer f8`, `kid f8`, `signature suite u16`, `signature f16` |
//!
//! The signature covers every byte before the signature field, suite
//! included; the `SERVICE_DNS` profile's key signs nothing else.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

pub type Sha256Fn = fn(&[u8], &mut [u8; 32]);
pub type VerifyFn = fn(u16, &[u8], &[u8], &[u8]) -> bool;

pub const MAGIC: [u8; 4] = *b"KSDN";
pub const VERSION: u8 = 1;

// ── The projection's layout ─────────────────────────────────────────────

pub const PROJECTION_LEN: usize = 224;
pub const ANSWERS_MAX: usize = 4;
pub const ANSWER_LEN: usize = 32;
pub const P_SERVICE: usize = 0;
pub const P_GENERATION: usize = 16;
pub const P_GLOBAL_GENERATION: usize = 24;
pub const P_DR_GENERATION: usize = 32;
pub const P_ISSUED: usize = 40;
pub const P_VALID: usize = 48;
pub const P_TTL: usize = 52;
pub const P_COUNT: usize = 56;
pub const P_ANSWERS: usize = 64;
/// Where the projection's own trailing field begins: reserved, zero.
pub const P_TRAILER: usize = 192;

/// Address families, as Wormhole's `NetAddr` numbers them.
pub mod family {
    pub const V4: u8 = 4;
    pub const V6: u8 = 6;
}

/// Answer health, as the projection states it.
pub mod health {
    pub const HEALTHY: u8 = 1;
    pub const DRAINING: u8 = 2;
}

// ── The record's layout ─────────────────────────────────────────────────

pub const OFF_VERSION: usize = 4;
pub const OFF_PROJECTION: usize = 8;
pub const FIXED_LEN: usize = OFF_PROJECTION + PROJECTION_LEN;
pub const MAX_ID: usize = 64;
pub const MAX_SIGNATURE: usize = 64;
pub const MAX_RECORD: usize = FIXED_LEN + 2 * (1 + MAX_ID) + 2 + 2 + MAX_SIGNATURE;

/// The longest a projection may be valid for. A resolver acting on a
/// projection an hour old is answering from a DR state that may have moved
/// many times since; past this the controller re-publishes.
pub const MAX_VALID_MS: u64 = 3_600_000;
/// How far a projection's issue time may sit from the signer's clock, and
/// ahead of a verifier's, before it is refused.
pub const SKEW_MS: u64 = 60_000;
/// Publishers one policy pins.
pub const MAX_PUBLISHERS: usize = 8;

/// `spiffe::Class` codes of the classes that may publish, restated.
pub mod class {
    pub const SERVICE: u8 = 3;
    pub const HOST: u8 = 4;
}

// ── Refusals ────────────────────────────────────────────────────────────

/// Why a projection was not signed, or a record not accepted. Stable; they
/// travel in replies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Refusal {
    /// Not a projection or not a record: a length, a reserved byte, a field
    /// out of range, trailing bytes.
    Malformed = 1,
    /// The request carried no identity, or one that did not verify.
    NotAuthenticated = 2,
    /// Authenticated, and not a publisher pinned to this projection's
    /// service.
    NotPublisher = 3,
    /// No validity, a validity past [`MAX_VALID_MS`], a TTL longer than the
    /// validity, or an issue time more than [`SKEW_MS`] from the signer's
    /// clock.
    WindowInvalid = 4,
    Expired = 5,
    /// Issued further ahead of the verifier's clock than [`SKEW_MS`].
    NotYetValid = 6,
    BadSignature = 7,
    UnknownKey = 8,
    NoIssuerKey = 9,
    NoClock = 10,
    /// The carrier the request authenticated with was presented before.
    Replayed = 11,
}

impl Refusal {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

fn rd_u16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
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

fn zero(b: &[u8], from: usize, to: usize) -> bool {
    b.get(from..to).is_some_and(|s| s.iter().all(|&x| x == 0))
}

/// A bounded writer over a caller's buffer.
struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, at: 0 }
    }

    fn len(&self) -> usize {
        self.at
    }

    fn bytes(&mut self, b: &[u8]) -> Option<()> {
        let end = self.at.checked_add(b.len())?;
        self.out.get_mut(self.at..end)?.copy_from_slice(b);
        self.at = end;
        Some(())
    }

    fn u8(&mut self, v: u8) -> Option<()> {
        self.bytes(&[v])
    }

    fn u16(&mut self, v: u16) -> Option<()> {
        self.bytes(&v.to_le_bytes())
    }

    fn f8(&mut self, b: &[u8]) -> Option<()> {
        self.u8(u8::try_from(b.len()).ok()?)?;
        self.bytes(b)
    }

    fn f16(&mut self, b: &[u8]) -> Option<()> {
        self.u16(u16::try_from(b.len()).ok()?)?;
        self.bytes(b)
    }
}

/// A bounded reader over untrusted bytes.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }

    fn position(&self) -> usize {
        self.at
    }

    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.at)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.b.get(self.at..end)?;
        self.at = end;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        rd_u16(self.take(2)?, 0)
    }

    fn f8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }

    fn f16(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
}

// ── The projection ──────────────────────────────────────────────────────

/// One regional answer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Answer {
    pub region: u32,
    pub family: u8,
    pub health: u8,
    pub weight: u16,
    pub address: [u8; 16],
}

impl Answer {
    const EMPTY: Self = Self {
        region: 0,
        family: 0,
        health: 0,
        weight: 0,
        address: [0; 16],
    };
}

/// A projection, as read. Kagi reads it to decide; it signs the bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Projection {
    pub service: [u8; 16],
    pub generation: u64,
    pub global_generation: u64,
    pub dr_generation: u64,
    pub issued_ms: u64,
    pub valid_ms: u32,
    pub ttl_s: u32,
    pub count: u8,
    pub answers: [Answer; ANSWERS_MAX],
}

impl Projection {
    /// Read the 224 bytes exactly as Wormhole's `ServiceDnsProjection::decode`
    /// admits them, and refuse a nonzero trailer: a projection that arrives
    /// carrying anything in the old inline-signature slot is not one the
    /// controller emitted.
    pub fn read(b: &[u8]) -> Result<Self, Refusal> {
        let bad = Refusal::Malformed;
        if b.len() != PROJECTION_LEN
            || !zero(b, P_COUNT + 1, P_ANSWERS)
            || !zero(b, P_TRAILER, PROJECTION_LEN)
        {
            return Err(bad);
        }
        let count = *b.get(P_COUNT).ok_or(bad)?;
        if usize::from(count) > ANSWERS_MAX {
            return Err(bad);
        }
        let mut answers = [Answer::EMPTY; ANSWERS_MAX];
        for (i, a) in answers.iter_mut().enumerate() {
            let at = P_ANSWERS + i * ANSWER_LEN;
            if i >= usize::from(count) {
                if !zero(b, at, at + ANSWER_LEN) {
                    return Err(bad);
                }
                continue;
            }
            if !zero(b, at + 24, at + ANSWER_LEN) {
                return Err(bad);
            }
            *a = Answer {
                region: rd_u32(b, at).ok_or(bad)?,
                family: *b.get(at + 4).ok_or(bad)?,
                health: *b.get(at + 5).ok_or(bad)?,
                weight: rd_u16(b, at + 6).ok_or(bad)?,
                address: rd_arr(b, at + 8).ok_or(bad)?,
            };
            let canonical = match a.family {
                family::V4 => a
                    .address
                    .get(..12)
                    .is_some_and(|p| p.iter().all(|&x| x == 0)),
                family::V6 => true,
                _ => false,
            };
            if !canonical || !matches!(a.health, health::HEALTHY | health::DRAINING) {
                return Err(bad);
            }
        }
        let p = Self {
            service: rd_arr(b, P_SERVICE).ok_or(bad)?,
            generation: rd_u64(b, P_GENERATION).ok_or(bad)?,
            global_generation: rd_u64(b, P_GLOBAL_GENERATION).ok_or(bad)?,
            dr_generation: rd_u64(b, P_DR_GENERATION).ok_or(bad)?,
            issued_ms: rd_u64(b, P_ISSUED).ok_or(bad)?,
            valid_ms: rd_u32(b, P_VALID).ok_or(bad)?,
            ttl_s: rd_u32(b, P_TTL).ok_or(bad)?,
            count,
            answers,
        };
        if p.generation == 0 || p.ttl_s == 0 {
            return Err(bad);
        }
        Ok(p)
    }

    /// Valid until, Unix ms.
    #[must_use]
    pub fn expiry_ms(&self) -> u64 {
        self.issued_ms.saturating_add(u64::from(self.valid_ms))
    }

    /// The window is one a resolver may act on: some validity, no more than
    /// [`MAX_VALID_MS`], and a TTL that ends inside it — a cached answer must
    /// not outlive the projection it came from.
    pub fn check_window(&self) -> Result<(), Refusal> {
        let valid = u64::from(self.valid_ms);
        if valid == 0 || valid > MAX_VALID_MS || u64::from(self.ttl_s) * 1000 > valid {
            return Err(Refusal::WindowInvalid);
        }
        Ok(())
    }

    /// Live at `now_ms`; `0` is no clock.
    pub fn live_at(&self, now_ms: u64) -> Result<(), Refusal> {
        if now_ms == 0 {
            return Err(Refusal::NoClock);
        }
        if now_ms >= self.expiry_ms() {
            return Err(Refusal::Expired);
        }
        if self.issued_ms > now_ms.saturating_add(SKEW_MS) {
            return Err(Refusal::NotYetValid);
        }
        Ok(())
    }
}

// ── Who may publish ─────────────────────────────────────────────────────

/// One publisher the deployment pinned: an identity and the one service it
/// publishes for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Publisher {
    /// [`class::SERVICE`] or [`class::HOST`].
    pub class: u8,
    pub id: [u8; 16],
    pub service: [u8; 16],
}

/// The pinned publishers. A deployment runs one region controller per
/// service, so a publisher is a `(identity, service)` pair and an identity
/// pinned for one service signs nothing for another.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Policy {
    pub publishers: [Publisher; MAX_PUBLISHERS],
    pub count: usize,
}

impl Policy {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            publishers: [Publisher {
                class: 0,
                id: [0; 16],
                service: [0; 16],
            }; MAX_PUBLISHERS],
            count: 0,
        }
    }

    /// Pin a publisher. False when the set is full, or for a class that may
    /// not publish or a zero id or service — a pin that names nobody is a
    /// wildcard.
    pub fn pin(&mut self, p: Publisher) -> bool {
        if !matches!(p.class, class::SERVICE | class::HOST)
            || p.id == [0; 16]
            || p.service == [0; 16]
        {
            return false;
        }
        if self.admits(p.class, &p.id, &p.service) {
            return true;
        }
        let Some(slot) = self.publishers.get_mut(self.count) else {
            return false;
        };
        *slot = p;
        self.count += 1;
        true
    }

    #[must_use]
    pub fn admits(&self, class: u8, id: &[u8; 16], service: &[u8; 16]) -> bool {
        self.publishers
            .iter()
            .take(self.count)
            .any(|p| p.class == class && p.id == *id && p.service == *service)
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether to sign `projection` for `requester` (the authenticated
/// `(class, id)` of the caller) at `now_ms`. Returns the projection read.
pub fn decide_sign(
    policy: &Policy,
    projection: &[u8],
    requester: Option<(u8, [u8; 16])>,
    now_ms: u64,
) -> Result<Projection, Refusal> {
    if now_ms == 0 {
        return Err(Refusal::NoClock);
    }
    let p = Projection::read(projection)?;
    let (class, id) = requester.ok_or(Refusal::NotAuthenticated)?;
    if !policy.admits(class, &id, &p.service) {
        return Err(Refusal::NotPublisher);
    }
    p.check_window()?;
    if p.issued_ms.abs_diff(now_ms) > SKEW_MS {
        return Err(Refusal::WindowInvalid);
    }
    Ok(p)
}

// ── The record ──────────────────────────────────────────────────────────

/// The signer a record names.
#[derive(Clone, Copy)]
pub struct Signer<'a> {
    pub issuer: &'a [u8],
    pub kid: &'a [u8],
}

/// Write the unsigned part of a record over `projection`; its length is the
/// signing input.
pub fn write_unsigned(
    out: &mut [u8],
    projection: &[u8],
    signer: &Signer<'_>,
    signature_suite: u16,
) -> Option<usize> {
    if projection.len() != PROJECTION_LEN
        || signer.issuer.is_empty()
        || signer.issuer.len() > MAX_ID
        || signer.kid.is_empty()
        || signer.kid.len() > MAX_ID
    {
        return None;
    }
    let mut w = Writer::new(out);
    w.bytes(&MAGIC)?;
    w.u8(VERSION)?;
    w.bytes(&[0; 3])?;
    w.bytes(projection)?;
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
    pub projection: Projection,
    /// The projection's 224 bytes, verbatim: what `dns_answers` reads.
    pub projection_bytes: &'a [u8],
    pub signer: Signer<'a>,
    pub signature_suite: u16,
    pub signature: &'a [u8],
    pub signed: &'a [u8],
}

impl<'a> Record<'a> {
    /// Structure only; trailing bytes refused.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Refusal> {
        let bad = Refusal::Malformed;
        if bytes.get(..4) != Some(&MAGIC[..])
            || bytes.get(OFF_VERSION) != Some(&VERSION)
            || !zero(bytes, OFF_VERSION + 1, OFF_PROJECTION)
        {
            return Err(bad);
        }
        let projection_bytes = bytes.get(OFF_PROJECTION..FIXED_LEN).ok_or(bad)?;
        let projection = Projection::read(projection_bytes)?;
        let mut r = Reader::new(bytes);
        r.take(FIXED_LEN).ok_or(bad)?;
        let issuer = r.f8().ok_or(bad)?;
        let kid = r.f8().ok_or(bad)?;
        if issuer.is_empty() || issuer.len() > MAX_ID || kid.is_empty() || kid.len() > MAX_ID {
            return Err(bad);
        }
        let signature_suite = r.u16().ok_or(bad)?;
        let signed_len = r.position();
        let signature = r.f16().ok_or(bad)?;
        if r.remaining() != 0 || signature.is_empty() || signature.len() > MAX_SIGNATURE {
            return Err(bad);
        }
        Ok(Self {
            projection,
            projection_bytes,
            signer: Signer { issuer, kid },
            signature_suite,
            signature,
            signed: bytes.get(..signed_len).ok_or(bad)?,
        })
    }

    /// Offline verification, as the consumer runs it before composing an
    /// answer: a window this profile signs, signed by the key `lookup`
    /// names under that key's own suite, live at `now_ms`.
    pub fn verify<'k, F>(&self, lookup: F, verify: VerifyFn, now_ms: u64) -> Result<(), Refusal>
    where
        F: FnOnce(&[u8], &[u8]) -> Option<(u16, &'k [u8])>,
    {
        self.projection.check_window()?;
        let (suite, public) =
            lookup(self.signer.issuer, self.signer.kid).ok_or(Refusal::UnknownKey)?;
        if self.signature_suite != suite || !verify(suite, public, self.signed, self.signature) {
            return Err(Refusal::BadSignature);
        }
        self.projection.live_at(now_ms)
    }
}

#[must_use]
pub fn record_digest(sha: Sha256Fn, record: &[u8]) -> [u8; 32] {
    let mut d = [0u8; 32];
    sha(record, &mut d);
    d
}

// ── The typed operation's wire ──────────────────────────────────────────

pub mod msg {
    /// `[projection f16][carrier f16]`.
    pub const REQUEST: u8 = 0x98;
    /// `[status u8][record f16]`, the record empty on every refusal.
    pub const REPLY: u8 = 0x99;
}

pub const STATUS_OK: u8 = 0;

/// A sign request: the unsigned projection and the publisher's cert-bound
/// identity carrier.
#[derive(Clone, Copy)]
pub struct SignRequest<'a> {
    pub projection: &'a [u8],
    pub carrier: &'a [u8],
}

impl<'a> SignRequest<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.f16(self.projection)?;
        w.f16(self.carrier)?;
        Some(w.len())
    }

    pub fn decode(b: &'a [u8]) -> Result<Self, Refusal> {
        let bad = Refusal::Malformed;
        let mut r = Reader::new(b);
        let req = Self {
            projection: r.f16().ok_or(bad)?,
            carrier: r.f16().ok_or(bad)?,
        };
        if r.remaining() != 0 || req.projection.len() != PROJECTION_LEN || req.carrier.is_empty() {
            return Err(bad);
        }
        Ok(req)
    }
}

/// Write a REPLY payload.
pub fn write_reply(refusal: Option<Refusal>, record: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.u8(refusal.map_or(STATUS_OK, Refusal::code))?;
    w.f16(if refusal.is_none() { record } else { &[] })?;
    Some(w.len())
}

/// Read a REPLY payload: `(status, record)`.
#[must_use]
pub fn read_reply(b: &[u8]) -> Option<(u8, &[u8])> {
    let mut r = Reader::new(b);
    let status = r.u8()?;
    let record = r.f16()?;
    if r.remaining() != 0 || (status != STATUS_OK && !record.is_empty()) {
        return None;
    }
    Some((status, record))
}

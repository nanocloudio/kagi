//! The key-custody transfer grant (`KTGR`): authority for one vault to move
//! the minimum live TLS continuity secrets of one connection to one admitted
//! standby, once.
//!
//! Wormhole's RFC §12.5.5 pairs a primary anchor with a standby. The standby
//! creates an attested, non-exportable recipient handle; the primary vault
//! wraps the continuity secret set directly to that recipient
//! (`KEY_WRAP`, destination-bound `FXKW` blobs) — but only against a
//! *committed transfer grant* naming the destination host, anchor, service,
//! flow and target epoch. This is that grant. Kagi decides it and signs it;
//! it never sees the secrets, and it holds nothing about the transfer but
//! the grant's single-use state in the ledger.
//!
//! A grant is issued only when (a) the requester is the authenticated host
//! the grant names as source, (b) the destination presents `ATTEST_KEY`
//! evidence for the recipient key meeting the custody the policy demands —
//! decided by the storage-key profile's own [`admit_custody`], so the two
//! profiles cannot come to disagree on what hardware custody means — and
//! (c) its nonce is claimed in the ledger. It is good for at most
//! [`TRANSFER_GRANT_TTL_MS`], and consumed once.
//!
//! Pure `no_std`. SHA-256 and signature verification are injected.
//!
//! # The record
//!
//! All integers little-endian.
//!
//! | Off | Len | Field |
//! | --- | --- | --- |
//! | 0 | 4 | magic `KTGR` |
//! | 4 | 1 | version ([`VERSION`]) |
//! | 5 | 1 | use: what the moved secret may do (`KEY_VAULT` usage class) |
//! | 6 | 1 | direction ([`direction`]) |
//! | 7 | 1 | custody established (`storage_key::custody`) |
//! | 8 | 1 | proven vault tier, `0xFF` when none was |
//! | 9 | 1 | reserved, zero |
//! | 10 | 2 | algorithm: the TLS cipher suite the secrets belong to |
//! | 12 | 4 | traffic epoch |
//! | 16 | 8 | target (flow) epoch |
//! | 24 | 8 | issued at, Unix ms |
//! | 32 | 8 | expiry, Unix ms |
//! | 40 | 8 | recovery generation the grant was issued under |
//! | 48 | 16 | service id |
//! | 64 | 16 | flow id |
//! | 80 | 16 | session id |
//! | 96 | 16 | source host id |
//! | 112 | 16 | destination host id |
//! | 128 | 8 | destination anchor |
//! | 136 | 16 | single-use nonce |
//! | 152 | 32 | recipient thumbprint: SHA-256 of the standby's recipient key |
//! | 184 | 32 | policy digest |
//! | 216 | | `issuer f8`, `kid f8`, `signature suite u16`, `signature f16` |
//!
//! The signature covers every byte before the signature field, suite
//! included; the `TRANSFER_GRANT` profile's key signs nothing else.
//!
//! # Single use, and unsafe recovery
//!
//! The ledger (`kagi/transfer-grants/`) holds, per `(flow, nonce)`, a
//! [`State`]: issued, then consumed or expired, each step a compare-and-swap
//! from the one before. It also holds the deployment's recovery generation.
//! A grant carries the generation it was issued under, and a consume refuses
//! any grant whose generation is not the current one — so an unsafe
//! directory recovery that advances the generation
//! (`transfer_grants_invalidate`) voids every outstanding grant at once,
//! without the ledger having to enumerate them, and forces the reconnect the
//! RFC requires rather than risking duplicate key or counter use.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::storage_key as sk;

pub type Sha256Fn = fn(&[u8], &mut [u8; 32]);
pub type VerifyFn = fn(u16, &[u8], &[u8], &[u8]) -> bool;

pub const MAGIC: [u8; 4] = *b"KTGR";
pub const VERSION: u8 = 1;

/// The longest a grant may be good for. The primary wraps within moments of
/// the standby arming; a grant still live after this is one somebody kept.
pub const TRANSFER_GRANT_TTL_MS: u64 = 30_000;
/// Issue-time skew a verifier allows.
pub const SKEW_MS: u64 = 5_000;

/// Which way the moved secrets flow on the connection.
pub mod direction {
    /// Client to server traffic secrets.
    pub const INBOUND: u8 = 1;
    /// Server to client.
    pub const OUTBOUND: u8 = 2;
    /// Both directions' secrets, one grant.
    pub const BOTH: u8 = 3;

    #[must_use]
    pub const fn valid(d: u8) -> bool {
        matches!(d, INBOUND | OUTBOUND | BOTH)
    }
}

// ── Layout ──────────────────────────────────────────────────────────────

pub const OFF_VERSION: usize = 4;
pub const OFF_USE: usize = 5;
pub const OFF_DIRECTION: usize = 6;
pub const OFF_CUSTODY: usize = 7;
pub const OFF_PROVEN_TIER: usize = 8;
pub const OFF_ALGORITHM: usize = 10;
pub const OFF_TRAFFIC_EPOCH: usize = 12;
pub const OFF_TARGET_EPOCH: usize = 16;
pub const OFF_ISSUED: usize = 24;
pub const OFF_EXPIRY: usize = 32;
pub const OFF_GENERATION: usize = 40;
pub const OFF_SERVICE: usize = 48;
pub const OFF_FLOW: usize = 64;
pub const OFF_SESSION: usize = 80;
pub const OFF_SOURCE: usize = 96;
pub const OFF_DESTINATION: usize = 112;
pub const OFF_ANCHOR: usize = 128;
pub const OFF_NONCE: usize = 136;
pub const OFF_RECIPIENT: usize = 152;
pub const OFF_POLICY: usize = 184;
pub const FIXED_LEN: usize = 216;

pub const MAX_ID: usize = 64;
pub const MAX_SIGNATURE: usize = 64;
pub const MAX_RECORD: usize = FIXED_LEN + 2 * (1 + MAX_ID) + 2 + 2 + MAX_SIGNATURE;

// ── Refusals ────────────────────────────────────────────────────────────

/// Why a grant was refused. Stable; they travel in replies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Refusal {
    Malformed = 1,
    /// The request carried no identity, or one that did not verify.
    NotAuthenticated = 2,
    /// The authenticated host is not the grant's source host.
    NotSource = 3,
    /// The destination leaf is not the destination host's, or does not
    /// chain to the authority.
    DestinationMismatch = 4,
    /// The policy demands hardware custody and no evidence was offered.
    AttestationRequired = 5,
    /// The evidence verifies and does not meet the policy: a software key,
    /// a tier too low, a persisted or wrongly-used key.
    AttestationInsufficient = 6,
    /// The evidence does not verify, or is not over this transfer.
    AttestationInvalid = 7,
    /// The evidence names another recipient key.
    WrongRecipient = 8,
    Expired = 9,
    /// The grant was consumed already.
    Replayed = 10,
    /// The grant predates the current recovery generation.
    Invalidated = 11,
    /// No state for this grant: not one this issuer recorded.
    UnknownGrant = 12,
    BadSignature = 13,
    UnknownKey = 14,
    NoIssuerKey = 15,
    LedgerUnavailable = 16,
    /// The ledger moved under a compare-and-swap.
    Conflict = 17,
    NoClock = 18,
    Busy = 19,
    /// Invalidation is an operator's act.
    NotOperator = 20,
    /// An invalidation must name a generation above the current one.
    GenerationNotAdvanced = 21,
    /// Expiry before issue, or longer than [`TRANSFER_GRANT_TTL_MS`].
    WindowInvalid = 22,
    /// The grant verifies but names another transfer than the wrap the
    /// vault host was asked for ([`Grant::authorizes`]).
    NotThisTransfer = 23,
}

impl Refusal {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    const fn from_storage(r: sk::Refusal) -> Self {
        match r {
            sk::Refusal::AttestationRequired => Self::AttestationRequired,
            sk::Refusal::AttestationInsufficient => Self::AttestationInsufficient,
            sk::Refusal::WrongRecipient => Self::WrongRecipient,
            _ => Self::AttestationInvalid,
        }
    }
}

// ── Little-endian helpers ───────────────────────────────────────────────

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

pub use sk::{Reader, Writer};

// ── The grant ───────────────────────────────────────────────────────────

/// The fixed part of a grant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Grant {
    pub key_use: u8,
    pub direction: u8,
    pub custody: u8,
    pub proven_tier: u8,
    pub algorithm: u16,
    pub traffic_epoch: u32,
    pub target_epoch: u64,
    pub issued_ms: u64,
    pub expiry_ms: u64,
    pub generation: u64,
    pub service: [u8; 16],
    pub flow: [u8; 16],
    pub session: [u8; 16],
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub anchor: [u8; 8],
    pub nonce: [u8; 16],
    pub recipient: [u8; 32],
    pub policy: [u8; 32],
}

impl Grant {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            key_use: 0,
            direction: 0,
            custody: sk::custody::POSSESSION_BOUND,
            proven_tier: sk::NOT_ATTESTED,
            algorithm: 0,
            traffic_epoch: 0,
            target_epoch: 0,
            issued_ms: 0,
            expiry_ms: 0,
            generation: 0,
            service: [0; 16],
            flow: [0; 16],
            session: [0; 16],
            source: [0; 16],
            destination: [0; 16],
            anchor: [0; 8],
            nonce: [0; 16],
            recipient: [0; 32],
            policy: [0; 32],
        }
    }

    fn write(&self, w: &mut Writer<'_>) -> Option<()> {
        w.bytes(&MAGIC)?;
        w.u8(VERSION)?;
        w.u8(self.key_use)?;
        w.u8(self.direction)?;
        w.u8(self.custody)?;
        w.u8(self.proven_tier)?;
        w.u8(0)?;
        w.u16(self.algorithm)?;
        w.u32(self.traffic_epoch)?;
        w.u64(self.target_epoch)?;
        w.u64(self.issued_ms)?;
        w.u64(self.expiry_ms)?;
        w.u64(self.generation)?;
        w.bytes(&self.service)?;
        w.bytes(&self.flow)?;
        w.bytes(&self.session)?;
        w.bytes(&self.source)?;
        w.bytes(&self.destination)?;
        w.bytes(&self.anchor)?;
        w.bytes(&self.nonce)?;
        w.bytes(&self.recipient)?;
        w.bytes(&self.policy)
    }

    fn read(b: &[u8]) -> Option<Self> {
        if b.get(..4)? != MAGIC || *b.get(OFF_VERSION)? != VERSION || *b.get(9)? != 0 {
            return None;
        }
        Some(Self {
            key_use: *b.get(OFF_USE)?,
            direction: *b.get(OFF_DIRECTION)?,
            custody: *b.get(OFF_CUSTODY)?,
            proven_tier: *b.get(OFF_PROVEN_TIER)?,
            algorithm: rd_u16(b, OFF_ALGORITHM)?,
            traffic_epoch: rd_u32(b, OFF_TRAFFIC_EPOCH)?,
            target_epoch: rd_u64(b, OFF_TARGET_EPOCH)?,
            issued_ms: rd_u64(b, OFF_ISSUED)?,
            expiry_ms: rd_u64(b, OFF_EXPIRY)?,
            generation: rd_u64(b, OFF_GENERATION)?,
            service: rd_arr(b, OFF_SERVICE)?,
            flow: rd_arr(b, OFF_FLOW)?,
            session: rd_arr(b, OFF_SESSION)?,
            source: rd_arr(b, OFF_SOURCE)?,
            destination: rd_arr(b, OFF_DESTINATION)?,
            anchor: rd_arr(b, OFF_ANCHOR)?,
            nonce: rd_arr(b, OFF_NONCE)?,
            recipient: rd_arr(b, OFF_RECIPIENT)?,
            policy: rd_arr(b, OFF_POLICY)?,
        })
    }

    /// The window is ordered and no longer than the profile allows.
    pub fn check(&self) -> Result<(), Refusal> {
        if !direction::valid(self.direction) || self.algorithm == 0 || self.key_use == 0 {
            return Err(Refusal::Malformed);
        }
        if self.expiry_ms <= self.issued_ms
            || self.expiry_ms - self.issued_ms > TRANSFER_GRANT_TTL_MS
        {
            return Err(Refusal::WindowInvalid);
        }
        Ok(())
    }

    /// Live at `now_ms`; `0` is no clock.
    pub fn live_at(&self, now_ms: u64) -> Result<(), Refusal> {
        if now_ms == 0 {
            return Err(Refusal::NoClock);
        }
        if now_ms >= self.expiry_ms {
            return Err(Refusal::Expired);
        }
        if self.issued_ms > now_ms.saturating_add(SKEW_MS) {
            return Err(Refusal::WindowInvalid);
        }
        Ok(())
    }
}

/// The signer a grant names.
#[derive(Clone, Copy)]
pub struct Signer<'a> {
    pub issuer: &'a [u8],
    pub kid: &'a [u8],
}

pub fn write_unsigned(
    out: &mut [u8],
    g: &Grant,
    signer: &Signer<'_>,
    signature_suite: u16,
) -> Option<usize> {
    if signer.issuer.is_empty()
        || signer.issuer.len() > MAX_ID
        || signer.kid.is_empty()
        || signer.kid.len() > MAX_ID
    {
        return None;
    }
    let mut w = Writer::new(out);
    g.write(&mut w)?;
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

/// A parsed grant.
#[derive(Clone, Copy)]
pub struct Record<'a> {
    pub grant: Grant,
    pub signer: Signer<'a>,
    pub signature_suite: u16,
    pub signature: &'a [u8],
    pub signed: &'a [u8],
}

impl<'a> Record<'a> {
    /// Structure only; trailing bytes refused.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Refusal> {
        let grant = Grant::read(bytes).ok_or(Refusal::Malformed)?;
        let mut r = Reader::new(bytes);
        r.take(FIXED_LEN).ok_or(Refusal::Malformed)?;
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
            grant,
            signer: Signer { issuer, kid },
            signature_suite,
            signature,
            signed: bytes.get(..signed_len).ok_or(Refusal::Malformed)?,
        })
    }

    /// Offline verification: well formed, signed by the key `lookup` names
    /// under that key's own suite, and live at `now_ms`. What the primary
    /// vault's host checks before it wraps; single use is the ledger's.
    pub fn verify<'k, F>(&self, lookup: F, verify: VerifyFn, now_ms: u64) -> Result<(), Refusal>
    where
        F: FnOnce(&[u8], &[u8]) -> Option<(u16, &'k [u8])>,
    {
        self.grant.check()?;
        let (suite, public) =
            lookup(self.signer.issuer, self.signer.kid).ok_or(Refusal::UnknownKey)?;
        if self.signature_suite != suite || !verify(suite, public, self.signed, self.signature) {
            return Err(Refusal::BadSignature);
        }
        self.grant.live_at(now_ms)
    }

    /// What the primary vault's host checks before it wraps: the grant
    /// verifies ([`Record::verify`]) and names exactly `wrap`
    /// ([`Grant::authorizes`]). Single use is still the ledger's — the
    /// source host consumes the grant (`op::CONSUME`) before the wrap.
    pub fn authorize_wrap<'k, F>(
        &self,
        lookup: F,
        verify: VerifyFn,
        now_ms: u64,
        wrap: &Wrap,
    ) -> Result<(), Refusal>
    where
        F: FnOnce(&[u8], &[u8]) -> Option<(u16, &'k [u8])>,
    {
        self.verify(lookup, verify, now_ms)?;
        self.grant.authorizes(wrap)
    }
}

/// The wrap a primary vault's host is asked for: the connection whose
/// secrets would move, where to, and what the moved objects may do. Every
/// field is something the vault host knows from its own connection state
/// and the request in front of it, never from the grant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Wrap {
    pub service: [u8; 16],
    pub flow: [u8; 16],
    pub session: [u8; 16],
    /// The host doing the wrap: the grant's source.
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub anchor: [u8; 8],
    pub target_epoch: u64,
    /// The traffic epoch of the secrets being wrapped.
    pub traffic_epoch: u32,
    /// The TLS cipher suite the secrets belong to.
    pub algorithm: u16,
    /// The `KEY_VAULT` usage the unwrapped objects are to carry.
    pub key_use: u8,
    /// Which secrets are being wrapped ([`direction`]).
    pub direction: u8,
    /// SHA-256 of the recipient key the vault is asked to wrap to.
    pub recipient: [u8; 32],
}

impl Grant {
    /// Whether this grant authorises `wrap`, field for field.
    ///
    /// A grant is the authority for one transfer, so anything it names must
    /// be what the wrap is: the connection (service, flow, session, traffic
    /// epoch, algorithm), the endpoints (source host, destination host and
    /// anchor, target epoch), the recipient key, and the use. Direction is
    /// the one containment: a `BOTH` grant covers a wrap of either side's
    /// secrets; a one-sided grant covers that side only. There is no
    /// wildcard — a zero field in the grant matches only a zero field in
    /// the wrap — because a grant that could stand for more than one
    /// transfer is a grant a second standby could be handed.
    pub fn authorizes(&self, wrap: &Wrap) -> Result<(), Refusal> {
        let direction_ok = direction::valid(wrap.direction)
            && (self.direction == wrap.direction || self.direction == direction::BOTH);
        let same = self.service == wrap.service
            && self.flow == wrap.flow
            && self.session == wrap.session
            && self.source == wrap.source
            && self.destination == wrap.destination
            && self.anchor == wrap.anchor
            && self.target_epoch == wrap.target_epoch
            && self.traffic_epoch == wrap.traffic_epoch
            && self.algorithm == wrap.algorithm
            && self.key_use == wrap.key_use
            && self.recipient == wrap.recipient;
        if same && direction_ok {
            Ok(())
        } else {
            Err(Refusal::NotThisTransfer)
        }
    }
}

#[must_use]
pub fn record_digest(sha: Sha256Fn, record: &[u8]) -> [u8; 32] {
    let mut d = [0u8; 32];
    sha(record, &mut d);
    d
}

// ── The issue decision ──────────────────────────────────────────────────

/// What the deployment demands of a standby's recipient key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Policy {
    /// Whether a possession-bound recipient (no hardware evidence, or
    /// evidence of a software key) may receive live secrets at all. The
    /// RFC requires the continuity policy to state the cost of widening the
    /// live-secret boundary; refusing by default is that statement.
    pub allow_possession: bool,
    /// The minimum vault tier hardware evidence must report.
    pub min_tier: u8,
}

/// The digest a policy is named by in a grant.
#[must_use]
pub fn policy_digest(sha: Sha256Fn, p: &Policy) -> [u8; 32] {
    let mut d = [0u8; 32];
    sha(
        &[
            b'K',
            b'T',
            b'G',
            b'P',
            u8::from(p.allow_possession),
            p.min_tier,
        ],
        &mut d,
    );
    d
}

/// The transfer a source host asks a grant for.
#[derive(Clone, Copy)]
pub struct IssueRequest<'a> {
    pub service: [u8; 16],
    pub flow: [u8; 16],
    pub session: [u8; 16],
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub anchor: [u8; 8],
    pub target_epoch: u64,
    pub traffic_epoch: u32,
    pub algorithm: u16,
    pub key_use: u8,
    pub direction: u8,
    pub ttl_ms: u32,
    /// The standby's fresh recipient key, uncompressed P-256.
    pub recipient_public: &'a [u8],
    /// `ATTEST_KEY` output for the recipient: `record ‖ signature`, signed
    /// by the destination host's identity key. Empty when none.
    pub evidence: &'a [u8],
    /// The destination host's leaf certificate, whose key signed the
    /// evidence.
    pub destination_leaf: &'a [u8],
    /// The source host's cert-bound identity carrier.
    pub carrier: &'a [u8],
}

impl<'a> IssueRequest<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&self.service)?;
        w.bytes(&self.flow)?;
        w.bytes(&self.session)?;
        w.bytes(&self.source)?;
        w.bytes(&self.destination)?;
        w.bytes(&self.anchor)?;
        w.u64(self.target_epoch)?;
        w.u32(self.traffic_epoch)?;
        w.u16(self.algorithm)?;
        w.u8(self.key_use)?;
        w.u8(self.direction)?;
        w.u32(self.ttl_ms)?;
        w.f8(self.recipient_public)?;
        w.f16(self.evidence)?;
        w.f16(self.destination_leaf)?;
        w.f16(self.carrier)?;
        Some(w.len())
    }

    pub fn decode(b: &'a [u8]) -> Result<Self, Refusal> {
        let bad = Refusal::Malformed;
        let mut r = Reader::new(b);
        let req = Self {
            service: r.arr().ok_or(bad)?,
            flow: r.arr().ok_or(bad)?,
            session: r.arr().ok_or(bad)?,
            source: r.arr().ok_or(bad)?,
            destination: r.arr().ok_or(bad)?,
            anchor: r.arr().ok_or(bad)?,
            target_epoch: r.u64().ok_or(bad)?,
            traffic_epoch: r.u32().ok_or(bad)?,
            algorithm: r.u16().ok_or(bad)?,
            key_use: r.u8().ok_or(bad)?,
            direction: r.u8().ok_or(bad)?,
            ttl_ms: r.u32().ok_or(bad)?,
            recipient_public: r.f8().ok_or(bad)?,
            evidence: r.f16().ok_or(bad)?,
            destination_leaf: r.f16().ok_or(bad)?,
            carrier: r.f16().ok_or(bad)?,
        };
        if r.remaining() != 0
            || req.carrier.is_empty()
            || req.destination_leaf.is_empty()
            || !direction::valid(req.direction)
            || req.algorithm == 0
            || req.key_use == 0
            || req.source == req.destination
        {
            return Err(bad);
        }
        Ok(req)
    }
}

/// The challenge a standby's `ATTEST_KEY` evidence must be over: the
/// transfer itself.
///
/// `SHA-256("KTGR attest" ‖ service ‖ flow ‖ session ‖ source ‖ destination
/// ‖ anchor ‖ target epoch ‖ traffic epoch)`. Evidence is therefore good for
/// exactly one transfer of one connection to one epoch; there is no
/// separate challenge round trip, because a standby arming for a target
/// epoch creates a fresh recipient handle for it anyway, and an evidence
/// record replayed for the same transfer authorises nothing the first did
/// not.
#[must_use]
pub fn attestation_challenge(sha: Sha256Fn, req: &IssueRequest<'_>) -> [u8; 32] {
    let mut buf = [0u8; 11 + 5 * 16 + 8 + 8 + 4];
    let mut w = Writer::new(&mut buf);
    let ok = w.bytes(b"KTGR attest").is_some()
        && w.bytes(&req.service).is_some()
        && w.bytes(&req.flow).is_some()
        && w.bytes(&req.session).is_some()
        && w.bytes(&req.source).is_some()
        && w.bytes(&req.destination).is_some()
        && w.bytes(&req.anchor).is_some()
        && w.u64(req.target_epoch).is_some()
        && w.u32(req.traffic_epoch).is_some();
    let n = if ok { w.len() } else { 0 };
    let mut d = [0u8; 32];
    sha(buf.get(..n).unwrap_or(&[]), &mut d);
    d
}

/// The checks before any ledger state moves: who asked, who receives, and
/// what custody the recipient key has. Returns the grant to stamp, minus the
/// nonce and generation the service adds.
///
/// `requester` is the authenticated `(class, id)` of the caller;
/// `destination_key` the `(suite, public)` of the destination host's leaf,
/// once the caller has established the leaf chains to the authority and
/// names the destination host — `None` when it did not.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one independently established fact the decision rests on"
)]
pub fn decide_issue(
    sha: Sha256Fn,
    verify: VerifyFn,
    policy: &Policy,
    req: &IssueRequest<'_>,
    requester: Option<(u8, [u8; 16])>,
    destination_key: Option<(u16, &[u8])>,
    host_class: u8,
    now_ms: u64,
) -> Result<Grant, Refusal> {
    if now_ms == 0 {
        return Err(Refusal::NoClock);
    }
    let (class, id) = requester.ok_or(Refusal::NotAuthenticated)?;
    if class != host_class || id != req.source {
        return Err(Refusal::NotSource);
    }
    let (dest_suite, dest_public) = destination_key.ok_or(Refusal::DestinationMismatch)?;
    let recipient = sk::recipient_public(&announcement(req.recipient_public)?)
        .map(|p| {
            let mut t = [0u8; 32];
            sha(p, &mut t);
            t
        })
        .ok_or(Refusal::Malformed)?;

    // The storage-key profile's custody admission, given the policy as the
    // grant it reads and the transfer as the request.
    let mut floor = sk::Binding::empty();
    floor.custody = if policy.allow_possession {
        sk::custody::POSSESSION_BOUND
    } else {
        sk::custody::HARDWARE_BOUND
    };
    floor.min_tier = policy.min_tier;
    let challenge = attestation_challenge(sha, req);
    let attach = sk::AttachRequest {
        kind: sk::kind::ATTACHMENT,
        resource_kind: 0,
        resource: [0; 16],
        epoch: 0,
        fence: 0,
        lifetime_secs: 0,
        expiry_ms: 0,
        anti_replay: [0; 16],
        challenge,
        ticket: [0; 16],
        recipient: &[],
        device: &[],
        device_suite: dest_suite,
        device_public: dest_public,
        proof: &[],
        evidence: req.evidence,
    };
    let held =
        sk::admit_custody(&floor, &attach, &recipient, verify).map_err(Refusal::from_storage)?;
    if held.custody != sk::custody::HARDWARE_BOUND && !policy.allow_possession {
        return Err(Refusal::AttestationInsufficient);
    }

    let ttl = u64::from(req.ttl_ms).clamp(1, TRANSFER_GRANT_TTL_MS);
    Ok(Grant {
        key_use: req.key_use,
        direction: req.direction,
        custody: held.custody,
        proven_tier: held.proven_tier,
        algorithm: req.algorithm,
        traffic_epoch: req.traffic_epoch,
        target_epoch: req.target_epoch,
        issued_ms: now_ms,
        expiry_ms: now_ms.saturating_add(ttl),
        generation: 0,
        service: req.service,
        flow: req.flow,
        session: req.session,
        source: req.source,
        destination: req.destination,
        anchor: req.anchor,
        nonce: [0; 16],
        recipient,
        policy: policy_digest(sha, policy),
    })
}

/// `"FXRK" ‖ public`, the shape `storage_key::recipient_public` reads, from
/// a bare uncompressed point.
fn announcement(public: &[u8]) -> Result<[u8; sk::RECIPIENT_LEN], Refusal> {
    let mut out = [0u8; sk::RECIPIENT_LEN];
    if public.len() != sk::PUBLIC_LEN {
        return Err(Refusal::Malformed);
    }
    for (d, s) in out
        .iter_mut()
        .zip(sk::RECIPIENT_MAGIC.iter().chain(public.iter()))
    {
        *d = *s;
    }
    Ok(out)
}

// ── The in-graph custody check (Fluxor TRANSPORT_CONTINUITY) ─────────────
//
// A continuity provider on the primary host asks its authority, before
// its vault wraps a flow's continuity key to a standby's attested
// recipient, whether that recipient may receive it: `[flow 16][epoch u32]
// [challenge 32][evidence]` (Fluxor's `TCS_MSG_CUSTODY_CHECK`), the
// evidence the standby's vault made over the transfer's challenge —
// `[record 148][recipient 65][signer 65][sig_len u16][sig]`, the record
// Kagi's own `ATTEST_KEY` evidence format and the signer the standby
// host's identity key. `custody_authority` answers it from this decision:
// the signer must be an enrolled host other than the source, the evidence
// must answer the challenge and meet the custody the policy demands
// (`storage_key::admit_custody`, as `decide_issue`), and the recipient is
// the key the record attests. The grant it yields is the KTGR the
// authority signs, records single-use in the ledger, and consumes at once:
// the provider wraps on the verdict.

/// The `algorithm` a custody-check grant names: not a TLS suite's secrets
/// but the flow's continuity key, the one key a Fluxor provider's vault
/// wraps to the standby (every secret of the flow is sealed under it).
pub const ALG_CONTINUITY_KEY: u16 = 0xFC01;

/// Fluxor's custody-check evidence layout.
pub mod tc_evidence {
    pub const RECORD_LEN: usize = 148;
    pub const PUB_LEN: usize = 65;
    pub const RECIPIENT: usize = RECORD_LEN;
    pub const SIGNER: usize = RECIPIENT + PUB_LEN;
    pub const SIG_LEN: usize = SIGNER + PUB_LEN;
    pub const SIG: usize = SIG_LEN + 2;
    pub const SIG_MAX: usize = 64;
    /// `[flow 16][epoch u32][challenge 32]` before the evidence.
    pub const CHECK_HDR: usize = 16 + 4 + 32;
}

/// One custody check, parsed.
#[derive(Clone, Copy)]
pub struct CustodyCheck<'a> {
    pub flow: [u8; 16],
    pub epoch: u32,
    pub challenge: [u8; 32],
    pub evidence: &'a [u8],
}

impl<'a> CustodyCheck<'a> {
    pub fn parse(b: &'a [u8]) -> Result<Self, Refusal> {
        use tc_evidence::*;
        if b.len() < CHECK_HDR + SIG + 1 || b.len() > CHECK_HDR + SIG + SIG_MAX {
            return Err(Refusal::Malformed);
        }
        let mut flow = [0u8; 16];
        flow.copy_from_slice(&b[..16]);
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&b[20..52]);
        let ev = &b[CHECK_HDR..];
        let sig_len = usize::from(u16::from_le_bytes([ev[SIG_LEN], ev[SIG_LEN + 1]]));
        if sig_len == 0 || SIG + sig_len != ev.len() {
            return Err(Refusal::Malformed);
        }
        Ok(Self {
            flow,
            epoch: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
            challenge,
            evidence: ev,
        })
    }

    fn signer(&self) -> &'a [u8] {
        &self.evidence[tc_evidence::SIGNER..tc_evidence::SIGNER + tc_evidence::PUB_LEN]
    }

    fn recipient(&self) -> &'a [u8] {
        &self.evidence[tc_evidence::RECIPIENT..tc_evidence::RECIPIENT + tc_evidence::PUB_LEN]
    }
}

/// A standby host this authority may hand a flow's key to: its id and its
/// identity key (uncompressed P-256), as enrolled.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EnrolledHost {
    pub id: [u8; 16],
    pub public: [u8; 65],
}

/// Decide a custody check from `source` (the host whose provider asks).
/// Returns the grant to stamp (the nonce derived from the challenge, the
/// generation for the caller to set) — the KTGR this transfer is.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one independently established fact the decision rests on"
)]
pub fn decide_custody_check(
    sha: Sha256Fn,
    verify: VerifyFn,
    policy: &Policy,
    source: &[u8; 16],
    hosts: &[EnrolledHost],
    check: &CustodyCheck<'_>,
    ttl_ms: u64,
    now_ms: u64,
) -> Result<Grant, Refusal> {
    if now_ms == 0 {
        return Err(Refusal::NoClock);
    }
    let signer = check.signer();
    let host = hosts
        .iter()
        .find(|h| h.public[..] == *signer)
        .ok_or(Refusal::DestinationMismatch)?;
    if host.id == *source {
        return Err(Refusal::DestinationMismatch);
    }
    let recipient_key = check.recipient();
    let recipient = sk::recipient_public(&announcement(recipient_key)?)
        .map(|p| {
            let mut t = [0u8; 32];
            sha(p, &mut t);
            t
        })
        .ok_or(Refusal::Malformed)?;
    // Kagi's evidence form is `record ‖ signature`.
    let mut ev = [0u8; tc_evidence::RECORD_LEN + tc_evidence::SIG_MAX];
    let sig = &check.evidence[tc_evidence::SIG..];
    ev[..tc_evidence::RECORD_LEN].copy_from_slice(&check.evidence[..tc_evidence::RECORD_LEN]);
    ev[tc_evidence::RECORD_LEN..tc_evidence::RECORD_LEN + sig.len()].copy_from_slice(sig);
    let evidence = &ev[..tc_evidence::RECORD_LEN + sig.len()];
    let mut floor = sk::Binding::empty();
    floor.custody = if policy.allow_possession {
        sk::custody::POSSESSION_BOUND
    } else {
        sk::custody::HARDWARE_BOUND
    };
    floor.min_tier = policy.min_tier;
    let attach = sk::AttachRequest {
        kind: sk::kind::ATTACHMENT,
        resource_kind: 0,
        resource: [0; 16],
        epoch: 0,
        fence: 0,
        lifetime_secs: 0,
        expiry_ms: 0,
        anti_replay: [0; 16],
        challenge: check.challenge,
        ticket: [0; 16],
        recipient: &[],
        device: &[],
        device_suite: crate::auth_wire::suite::ES256,
        device_public: signer,
        proof: &[],
        evidence,
    };
    let held =
        sk::admit_custody(&floor, &attach, &recipient, verify).map_err(Refusal::from_storage)?;
    if held.custody != sk::custody::HARDWARE_BOUND && !policy.allow_possession {
        return Err(Refusal::AttestationInsufficient);
    }
    // One transfer, one nonce: the challenge names the transfer.
    let mut nonce_in = [0u8; 18 + 32];
    nonce_in[..18].copy_from_slice(b"KTGR custody nonce");
    nonce_in[18..].copy_from_slice(&check.challenge);
    let mut d = [0u8; 32];
    sha(&nonce_in, &mut d);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&d[..16]);
    let ttl = ttl_ms.clamp(1, TRANSFER_GRANT_TTL_MS);
    Ok(Grant {
        key_use: 1,
        direction: direction::BOTH,
        custody: held.custody,
        proven_tier: held.proven_tier,
        algorithm: ALG_CONTINUITY_KEY,
        traffic_epoch: 0,
        target_epoch: u64::from(check.epoch),
        issued_ms: now_ms,
        expiry_ms: now_ms.saturating_add(ttl),
        generation: 0,
        service: [0; 16],
        flow: check.flow,
        session: [0; 16],
        source: *source,
        destination: host.id,
        anchor: [0; 8],
        nonce,
        recipient,
        policy: policy_digest(sha, policy),
    })
}

/// Fluxor's custody-check frame ids (`TCS_MSG_CUSTODY_CHECK` /
/// `TCS_MSG_CUSTODY_VERDICT`) and the verdict body:
/// `[flow 16][sha256(evidence) 32][verdict u8]`, 0 accepting.
pub const MSG_CUSTODY_CHECK: u8 = 0xC4;
pub const MSG_CUSTODY_VERDICT: u8 = 0xC5;
pub const CUSTODY_VERDICT_LEN: usize = 16 + 32 + 1;

/// The verdict body for `check`: 0 accepts; a refusal is `0x80 | code`.
#[must_use]
pub fn custody_verdict(
    sha: Sha256Fn,
    check: &CustodyCheck<'_>,
    refusal: Option<Refusal>,
) -> [u8; CUSTODY_VERDICT_LEN] {
    let mut out = [0u8; CUSTODY_VERDICT_LEN];
    out[..16].copy_from_slice(&check.flow);
    let mut d = [0u8; 32];
    sha(check.evidence, &mut d);
    out[16..48].copy_from_slice(&d);
    out[48] = refusal.map_or(0, |r| 0x80 | r.code());
    out
}

// ── Ledger state ────────────────────────────────────────────────────────

/// A grant's single-use state in the ledger.
pub mod state {
    pub const ISSUED: u8 = 1;
    pub const CONSUMED: u8 = 2;
    pub const EXPIRED: u8 = 3;
}

pub const STATE_MAGIC: [u8; 4] = *b"KTGS";
/// `[KTGS][state u8][generation u64][expiry u64][grant digest 32]`.
pub const STATE_LEN: usize = 4 + 1 + 8 + 8 + 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct State {
    pub state: u8,
    pub generation: u64,
    pub expiry_ms: u64,
    pub digest: [u8; 32],
}

impl State {
    pub fn encode(&self, out: &mut [u8; STATE_LEN]) {
        let mut w = Writer::new(out);
        let _ = w.bytes(&STATE_MAGIC);
        let _ = w.u8(self.state);
        let _ = w.u64(self.generation);
        let _ = w.u64(self.expiry_ms);
        let _ = w.bytes(&self.digest);
    }

    #[must_use]
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != STATE_LEN || b.get(..4)? != STATE_MAGIC {
            return None;
        }
        let s = Self {
            state: *b.get(4)?,
            generation: rd_u64(b, 5)?,
            expiry_ms: rd_u64(b, 13)?,
            digest: rd_arr(b, 21)?,
        };
        matches!(s.state, state::ISSUED | state::CONSUMED | state::EXPIRED).then_some(s)
    }
}

pub const GENERATION_MAGIC: [u8; 4] = *b"KTGG";
pub const GENERATION_LEN: usize = 12;
/// The ledger key the recovery generation lives under.
pub const GENERATION_KEY: &[u8] = b"generation";

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

/// The ledger key of a grant's state: `<flow hex>-<nonce hex>`.
pub fn state_key(flow: &[u8; 16], nonce: &[u8; 16], out: &mut [u8]) -> Option<usize> {
    let n = sk::hex_into(flow, out)?;
    *out.get_mut(n)? = b'-';
    let m = sk::hex_into(nonce, out.get_mut(n + 1..)?)?;
    Some(n + 1 + m)
}

// ── The typed operation's wire ──────────────────────────────────────────

pub mod msg {
    /// `[op u8][body]`.
    pub const REQUEST: u8 = 0x94;
    /// `[op u8][status u8][record f16][generation u64]`.
    pub const REPLY: u8 = 0x95;
}

/// Operations.
pub mod op {
    /// Body: an [`super::IssueRequest`].
    pub const ISSUE: u8 = 1;
    /// Body: `[grant f16][carrier f16]` — the source host consuming its
    /// grant before its vault wraps.
    pub const CONSUME: u8 = 2;
    /// `transfer_grants_invalidate(recovery_generation)`. Body:
    /// `[recovery generation u64][carrier f16]`, from an operator.
    pub const INVALIDATE: u8 = 3;
}

pub const STATUS_OK: u8 = 0;

/// Write a REPLY payload.
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

/// Read a REPLY payload: `(op, status, record, generation)`.
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

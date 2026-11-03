//! The signed control act: provenance for an ownership-changing request.
//!
//! A traffic fabric's control plane changes who owns what — a route generation, a
//! VIP, a flow's anchor, a private attachment — on the say-so of a host, an
//! operator or a workload. Its RFC (§15.1) requires every such request to
//! carry its actor, scope, operation id, target, expected epoch and a
//! signed, auditable provenance, and (§9.4) requires the record the traffic fabric
//! materialises to retain that provenance as a 32-byte digest. This fragment
//! is the signed artefact behind both: Kagi signs the act for an actor it
//! has authenticated, the traffic fabric verifies it offline against Kagi's published
//! keyset at ingestion, and the route record carries [`record_digest`] as its
//! `provenance_digest`.
//!
//! Kagi is never the state store for these acts. It signs one, audits that it
//! did, and forgets it: the act travels with the request it authorises, and
//! where it ends up — a route record, a fence confirmation, a directory
//! entry — is Lattice's and Clustor's to hold. Nothing here fetches anything.
//!
//! Pure `no_std`. SHA-256 and signature verification are injected, because a
//! module wires the SDK's and a host suite wires independent crates.
//!
//! # The record
//!
//! One layout for every kind. All integers little-endian.
//!
//! | Off | Len | Field |
//! | --- | --- | --- |
//! | 0 | 4 | magic `KCAC` |
//! | 4 | 1 | version ([`VERSION`]) |
//! | 5 | 1 | act kind ([`kind`]) |
//! | 6 | 1 | actor class (`spiffe::Class` code) |
//! | 7 | 1 | target kind ([`target`]) |
//! | 8 | 16 | actor id: the host, operator or workload id |
//! | 24 | 16 | scope: tenant id |
//! | 40 | 16 | scope: service id |
//! | 56 | 16 | target id |
//! | 72 | 16 | operation id |
//! | 88 | 8 | expected epoch |
//! | 96 | 8 | issued at, Unix ms |
//! | 104 | 8 | expiry, Unix ms |
//! | 112 | 32 | declaration digest: SHA-256 of the declaring payload |
//! | 144 | 32 | policy digest |
//! | 176 | | `issuer f8`, `kid f8` |
//! | | | `signature suite u16`, `signature f16` |
//!
//! The signature covers every byte before the signature field, suite
//! included. The magic is the domain separation: no other artefact this
//! issuer signs begins with it, and no other profile's key signs it
//! (`suite::profile::CONTROL_ACT`).
//!
//! The declaration digest binds the act to exactly one declaring payload —
//! the `WHR1` route record a publish carries, the attachment publication,
//! the fence confirmation — so an act cannot be lifted onto another payload
//! of the same kind. The traffic fabric checks it against the payload it ingests. The
//! policy digest names the policy object the actor was admitted under, for
//! the audit trail; this fragment carries it and does not interpret it.
//!
//! # Windows
//!
//! An act is a request, not a credential: it is good for at most
//! [`MAX_WINDOW_MS`] from issue, may not be dated in the future beyond
//! [`SKEW_MS`], and is refused once expired. A verifier with no trustworthy
//! clock refuses rather than skipping the window.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

/// SHA-256, into a caller's buffer.
pub type Sha256Fn = fn(&[u8], &mut [u8; 32]);

/// Verify a signature: `(suite, public_key, message, signature)`.
///
/// `suite` is a Kagi credential suite (`auth_wire::suite`). The verifier
/// applies the suite's convention: ES256 hashes the message with SHA-256,
/// Ed25519 verifies it whole.
pub type VerifyFn = fn(u16, &[u8], &[u8], &[u8]) -> bool;

pub const MAGIC: [u8; 4] = *b"KCAC";
/// The one layout version this fragment writes and reads.
pub const VERSION: u8 = 1;

/// Act kinds: what the actor asks to change.
pub mod kind {
    /// Publish a route generation (the declaration is the `WHR1` route
    /// record).
    pub const ROUTE_PUBLISH: u8 = 1;
    /// Declare an endpoint set for a service.
    pub const ENDPOINT_DECLARE: u8 = 2;
    /// Claim a VIP for a service.
    pub const VIP_CLAIM: u8 = 3;
    /// Confirm a fence of a fault domain, from its admitted fence provider.
    pub const FENCE_CONFIRM: u8 = 4;
    /// Fail a service or flow set over to a standby.
    pub const FAILOVER: u8 = 5;
    /// Evacuate a host.
    pub const EVACUATE: u8 = 6;
    /// Dial a relay or rescue tunnel.
    pub const DIAL: u8 = 7;
    /// A producer publishes a private attachment service.
    pub const ATTACHMENT_PUBLISH: u8 = 8;
    /// A consumer requests a private attachment.
    pub const ATTACHMENT_REQUEST: u8 = 9;

    #[must_use]
    pub const fn valid(k: u8) -> bool {
        k >= ROUTE_PUBLISH && k <= ATTACHMENT_REQUEST
    }

    /// Short stable token, for an operator-facing log line.
    #[must_use]
    pub const fn text(k: u8) -> &'static [u8] {
        match k {
            ROUTE_PUBLISH => b"route-publish",
            ENDPOINT_DECLARE => b"endpoint-declare",
            VIP_CLAIM => b"vip-claim",
            FENCE_CONFIRM => b"fence-confirm",
            FAILOVER => b"failover",
            EVACUATE => b"evacuate",
            DIAL => b"dial",
            ATTACHMENT_PUBLISH => b"attachment-publish",
            ATTACHMENT_REQUEST => b"attachment-request",
            _ => b"unknown",
        }
    }
}

/// What the target id names.
pub mod target {
    /// No target beyond the scope itself.
    pub const NONE: u8 = 0;
    /// A route generation.
    pub const ROUTE_GENERATION: u8 = 1;
    /// A VIP.
    pub const VIP: u8 = 2;
    /// A fault domain.
    pub const FAULT_DOMAIN: u8 = 3;
    /// A host.
    pub const HOST: u8 = 4;
    /// A flow.
    pub const FLOW: u8 = 5;
    /// A tunnel.
    pub const TUNNEL: u8 = 6;
    /// A private attachment.
    pub const ATTACHMENT: u8 = 7;

    #[must_use]
    pub const fn valid(k: u8) -> bool {
        k <= ATTACHMENT
    }
}

/// Actor classes, as `spiffe::Class` numbers them. Restated here so a
/// verifier that mounts only this fragment can name them.
pub mod actor {
    pub const DEVICE: u8 = 1;
    pub const WORKLOAD: u8 = 2;
    pub const SERVICE: u8 = 3;
    pub const HOST: u8 = 4;
    pub const OPERATOR: u8 = 5;

    /// The classes that may sign for a control act at all. A device is an
    /// enrolled end-user key; it owns nothing in a control plane.
    #[must_use]
    pub const fn may_act(class: u8) -> bool {
        matches!(class, WORKLOAD | SERVICE | HOST | OPERATOR)
    }
}

// ── Layout ──────────────────────────────────────────────────────────────

pub const OFF_VERSION: usize = 4;
pub const OFF_KIND: usize = 5;
pub const OFF_ACTOR_CLASS: usize = 6;
pub const OFF_TARGET_KIND: usize = 7;
pub const OFF_ACTOR: usize = 8;
pub const OFF_TENANT: usize = 24;
pub const OFF_SERVICE: usize = 40;
pub const OFF_TARGET: usize = 56;
pub const OFF_OPERATION: usize = 72;
pub const OFF_EPOCH: usize = 88;
pub const OFF_ISSUED: usize = 96;
pub const OFF_EXPIRY: usize = 104;
pub const OFF_DECLARATION: usize = 112;
pub const OFF_POLICY: usize = 144;
/// Where the variable part begins.
pub const FIXED_LEN: usize = 176;

/// Longest issuer identifier or kid a record carries.
pub const MAX_ID: usize = 64;
/// Longest signature: Ed25519 and ES256 are both 64 bytes. An act travels
/// inside a traffic-fabric control request and is named by its digest, so a suite
/// whose signature is kilobytes is not an act suite.
pub const MAX_SIGNATURE: usize = 64;
/// The largest record this profile produces.
pub const MAX_RECORD: usize = FIXED_LEN + 2 * (1 + MAX_ID) + 2 + 2 + MAX_SIGNATURE;

/// Longest an act may be good for: ten minutes from issue. An act good for
/// longer is a replayable artefact rather than a request.
pub const MAX_WINDOW_MS: u64 = 600_000;
/// How far in the future an act's issue time may sit before it is refused as
/// not yet valid: one minute of clock skew between issuer and verifier.
pub const SKEW_MS: u64 = 60_000;

// ── Refusals ────────────────────────────────────────────────────────────

/// Why an act is refused. The numbers travel in verdicts and audit entries
/// and are stable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Refusal {
    /// Not a record: wrong magic or version, a field out of range, trailing
    /// bytes, a signature of the wrong shape.
    Malformed = 1,
    /// The `(issuer, kid)` the record names is not in the verifier's keyset.
    UnknownKey = 2,
    /// The signature does not verify, or names another suite than the key.
    BadSignature = 3,
    /// Past its expiry.
    Expired = 4,
    /// Issued in the future, beyond the skew allowance.
    NotYetValid = 5,
    /// Expiry before issue, or a window longer than [`MAX_WINDOW_MS`].
    WindowInvalid = 6,
    /// An act kind this build does not know.
    UnknownKind = 7,
    /// An actor class that may not act, or a class this build does not know.
    ActorNotPermitted = 8,
    /// The issuer holds no signing key for this profile.
    NoIssuerKey = 9,
    /// A mint request carried no authenticated identity, or one that did not
    /// verify.
    NotAuthenticated = 10,
    /// The verifier has no trustworthy clock.
    NoClock = 11,
    /// The declaring payload presented is not the one the act's declaration
    /// digest names.
    DeclarationMismatch = 12,
    /// The carrier a mint request authenticated with was presented before.
    Replayed = 13,
}

impl Refusal {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

// ── Little-endian helpers ───────────────────────────────────────────────

fn rd_u16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
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

/// A bounded writer over a caller's buffer.
pub struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, at: 0 }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.at
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.at == 0
    }

    pub fn bytes(&mut self, b: &[u8]) -> Option<()> {
        let end = self.at.checked_add(b.len())?;
        self.out.get_mut(self.at..end)?.copy_from_slice(b);
        self.at = end;
        Some(())
    }

    pub fn u8(&mut self, v: u8) -> Option<()> {
        self.bytes(&[v])
    }

    pub fn u16(&mut self, v: u16) -> Option<()> {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u32(&mut self, v: u32) -> Option<()> {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u64(&mut self, v: u64) -> Option<()> {
        self.bytes(&v.to_le_bytes())
    }

    pub fn f8(&mut self, b: &[u8]) -> Option<()> {
        let n = u8::try_from(b.len()).ok()?;
        self.u8(n)?;
        self.bytes(b)
    }

    pub fn f16(&mut self, b: &[u8]) -> Option<()> {
        let n = u16::try_from(b.len()).ok()?;
        self.u16(n)?;
        self.bytes(b)
    }
}

/// A bounded reader over untrusted bytes.
pub struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }

    #[must_use]
    pub fn position(&self) -> usize {
        self.at
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.at)
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.b.get(self.at..end)?;
        self.at = end;
        Some(s)
    }

    pub fn u8(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }

    pub fn u16(&mut self) -> Option<u16> {
        rd_u16(self.take(2)?, 0)
    }

    pub fn u32(&mut self) -> Option<u32> {
        let s = self.take(4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn u64(&mut self) -> Option<u64> {
        rd_u64(self.take(8)?, 0)
    }

    pub fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        rd_arr(self.take(N)?, 0)
    }

    pub fn f8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }

    pub fn f16(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
}

// ── The act ─────────────────────────────────────────────────────────────

/// The fixed part of a record: everything the act binds that is not the
/// signer's name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Act {
    pub kind: u8,
    pub actor_class: u8,
    pub target_kind: u8,
    pub actor: [u8; 16],
    pub tenant: [u8; 16],
    pub service: [u8; 16],
    pub target: [u8; 16],
    pub operation: [u8; 16],
    pub expected_epoch: u64,
    pub issued_ms: u64,
    pub expiry_ms: u64,
    pub declaration: [u8; 32],
    pub policy: [u8; 32],
}

impl Act {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            kind: 0,
            actor_class: 0,
            target_kind: target::NONE,
            actor: [0; 16],
            tenant: [0; 16],
            service: [0; 16],
            target: [0; 16],
            operation: [0; 16],
            expected_epoch: 0,
            issued_ms: 0,
            expiry_ms: 0,
            declaration: [0; 32],
            policy: [0; 32],
        }
    }

    fn write(&self, w: &mut Writer<'_>) -> Option<()> {
        w.bytes(&MAGIC)?;
        w.u8(VERSION)?;
        w.u8(self.kind)?;
        w.u8(self.actor_class)?;
        w.u8(self.target_kind)?;
        w.bytes(&self.actor)?;
        w.bytes(&self.tenant)?;
        w.bytes(&self.service)?;
        w.bytes(&self.target)?;
        w.bytes(&self.operation)?;
        w.u64(self.expected_epoch)?;
        w.u64(self.issued_ms)?;
        w.u64(self.expiry_ms)?;
        w.bytes(&self.declaration)?;
        w.bytes(&self.policy)
    }

    fn read(b: &[u8]) -> Option<Self> {
        if b.get(..4)? != MAGIC || *b.get(OFF_VERSION)? != VERSION {
            return None;
        }
        Some(Self {
            kind: *b.get(OFF_KIND)?,
            actor_class: *b.get(OFF_ACTOR_CLASS)?,
            target_kind: *b.get(OFF_TARGET_KIND)?,
            actor: rd_arr(b, OFF_ACTOR)?,
            tenant: rd_arr(b, OFF_TENANT)?,
            service: rd_arr(b, OFF_SERVICE)?,
            target: rd_arr(b, OFF_TARGET)?,
            operation: rd_arr(b, OFF_OPERATION)?,
            expected_epoch: rd_u64(b, OFF_EPOCH)?,
            issued_ms: rd_u64(b, OFF_ISSUED)?,
            expiry_ms: rd_u64(b, OFF_EXPIRY)?,
            declaration: rd_arr(b, OFF_DECLARATION)?,
            policy: rd_arr(b, OFF_POLICY)?,
        })
    }

    /// Whether the fixed part is one this build can act on: a known kind, a
    /// known target kind, an actor class that may act, and a window that is
    /// ordered and bounded.
    pub fn check(&self) -> Result<(), Refusal> {
        if !kind::valid(self.kind) {
            return Err(Refusal::UnknownKind);
        }
        if !actor::may_act(self.actor_class) {
            return Err(Refusal::ActorNotPermitted);
        }
        if !target::valid(self.target_kind) {
            return Err(Refusal::Malformed);
        }
        if self.expiry_ms <= self.issued_ms || self.expiry_ms - self.issued_ms > MAX_WINDOW_MS {
            return Err(Refusal::WindowInvalid);
        }
        Ok(())
    }

    /// Whether the act is live at `now_ms`. `now_ms == 0` is no clock.
    pub fn live_at(&self, now_ms: u64) -> Result<(), Refusal> {
        if now_ms == 0 {
            return Err(Refusal::NoClock);
        }
        if now_ms >= self.expiry_ms {
            return Err(Refusal::Expired);
        }
        if self.issued_ms > now_ms.saturating_add(SKEW_MS) {
            return Err(Refusal::NotYetValid);
        }
        Ok(())
    }
}

/// The signer a record names.
#[derive(Clone, Copy)]
pub struct Signer<'a> {
    pub issuer: &'a [u8],
    pub kid: &'a [u8],
}

/// Write the unsigned part of a record: the act, the signer's name and the
/// signature suite. Returns its length, which is the signing input.
pub fn write_unsigned(
    out: &mut [u8],
    act: &Act,
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
    act.write(&mut w)?;
    w.f8(signer.issuer)?;
    w.f8(signer.kid)?;
    w.u16(signature_suite)?;
    Some(w.len())
}

/// Append the signature to a record whose unsigned part is `out[..unsigned]`.
pub fn append_signature(out: &mut [u8], unsigned: usize, signature: &[u8]) -> Option<usize> {
    if signature.is_empty() || signature.len() > MAX_SIGNATURE {
        return None;
    }
    let mut w = Writer::new(out.get_mut(unsigned..)?);
    w.f16(signature)?;
    unsigned.checked_add(w.len())
}

/// A parsed record, borrowing from the bytes it was read out of.
#[derive(Clone, Copy)]
pub struct Record<'a> {
    pub act: Act,
    pub signer: Signer<'a>,
    pub signature_suite: u16,
    pub signature: &'a [u8],
    /// The signed prefix: every byte before the signature field.
    pub signed: &'a [u8],
}

impl<'a> Record<'a> {
    /// Parse a record. Structure only: the signature is checked by
    /// [`Record::verify`], and the act's ranges by [`Act::check`] there.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Refusal> {
        let act = Act::read(bytes).ok_or(Refusal::Malformed)?;
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
            act,
            signer: Signer { issuer, kid },
            signature_suite,
            signature,
            signed: bytes.get(..signed_len).ok_or(Refusal::Malformed)?,
        })
    }

    /// Verify a record offline: the act is well formed, the key its signer
    /// names is in the keyset `lookup` answers for (as `(suite, public)`),
    /// the record names that key's suite and not another, the signature
    /// verifies, and the act is live at `now_ms`.
    ///
    /// `lookup` is generic rather than a keyset type so a verifier may hold
    /// its keys however it does — a `verify_keyset::Keyset`, a single pinned
    /// key, a test table — and so this fragment mounts nothing but itself.
    pub fn verify<'k, F>(&self, lookup: F, verify: VerifyFn, now_ms: u64) -> Result<(), Refusal>
    where
        F: FnOnce(&[u8], &[u8]) -> Option<(u16, &'k [u8])>,
    {
        self.act.check()?;
        let (suite, public) =
            lookup(self.signer.issuer, self.signer.kid).ok_or(Refusal::UnknownKey)?;
        if self.signature_suite != suite {
            return Err(Refusal::BadSignature);
        }
        if !verify(suite, public, self.signed, self.signature) {
            return Err(Refusal::BadSignature);
        }
        self.act.live_at(now_ms)
    }
}

/// SHA-256 of a whole record: what the traffic fabric stores as a route record's
/// `provenance_digest`, and how the audit trail names the act.
#[must_use]
pub fn record_digest(sha: Sha256Fn, record: &[u8]) -> [u8; 32] {
    let mut d = [0u8; 32];
    sha(record, &mut d);
    d
}

/// SHA-256 of a declaring payload: what an act's declaration digest is
/// computed over. Plain SHA-256 of the exact bytes, so the traffic fabric can compute
/// it over the `WHR1` record it ingests with nothing but a hash.
#[must_use]
pub fn declaration_digest(sha: Sha256Fn, declaration: &[u8]) -> [u8; 32] {
    let mut d = [0u8; 32];
    sha(declaration, &mut d);
    d
}

// ── Audit ───────────────────────────────────────────────────────────────

/// Audit record magic.
pub const AUDIT_MAGIC: [u8; 4] = *b"KCAA";

/// One audit entry: an act minted, or a mint refused.
///
/// | Off | Len | Field |
/// | --- | --- | --- |
/// | 0 | 4 | magic `KCAA` |
/// | 4 | 1 | act kind |
/// | 5 | 1 | outcome: 0 minted, 1 refused |
/// | 6 | 1 | refusal ([`Refusal`] code, 0 when minted) |
/// | 7 | 1 | actor class |
/// | 8 | 8 | decided at, Unix ms |
/// | 16 | 16 | actor id |
/// | 32 | 16 | tenant id |
/// | 48 | 16 | service id |
/// | 64 | 16 | operation id |
/// | 80 | 32 | digest of the record minted, zero when none |
/// | 112 | 32 | SVID (key hash) the actor authenticated with, zero when none |
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Audit {
    pub kind: u8,
    pub refusal: u8,
    pub actor_class: u8,
    pub at_ms: u64,
    pub actor: [u8; 16],
    pub tenant: [u8; 16],
    pub service: [u8; 16],
    pub operation: [u8; 16],
    pub record: [u8; 32],
    pub svid: [u8; 32],
}

pub const AUDIT_LEN: usize = 144;

impl Audit {
    #[must_use]
    pub const fn new(kind: u8, at_ms: u64) -> Self {
        Self {
            kind,
            refusal: 0,
            actor_class: 0,
            at_ms,
            actor: [0; 16],
            tenant: [0; 16],
            service: [0; 16],
            operation: [0; 16],
            record: [0; 32],
            svid: [0; 32],
        }
    }

    #[must_use]
    pub const fn allowed(&self) -> bool {
        self.refusal == 0
    }

    /// Fill the act fields from the act decided.
    pub fn record_act(&mut self, a: &Act) {
        self.kind = a.kind;
        self.actor_class = a.actor_class;
        self.actor = a.actor;
        self.tenant = a.tenant;
        self.service = a.service;
        self.operation = a.operation;
    }

    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.bytes(&AUDIT_MAGIC)?;
        w.u8(self.kind)?;
        w.u8(u8::from(self.refusal != 0))?;
        w.u8(self.refusal)?;
        w.u8(self.actor_class)?;
        w.u64(self.at_ms)?;
        w.bytes(&self.actor)?;
        w.bytes(&self.tenant)?;
        w.bytes(&self.service)?;
        w.bytes(&self.operation)?;
        w.bytes(&self.record)?;
        w.bytes(&self.svid)?;
        Some(w.len())
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.take(4)? != AUDIT_MAGIC {
            return None;
        }
        let kind = r.u8()?;
        let refused = r.u8()?;
        let refusal = r.u8()?;
        if (refused != 0) != (refusal != 0) {
            return None;
        }
        let a = Self {
            kind,
            refusal,
            actor_class: r.u8()?,
            at_ms: r.u64()?,
            actor: r.arr()?,
            tenant: r.arr()?,
            service: r.arr()?,
            operation: r.arr()?,
            record: r.arr()?,
            svid: r.arr()?,
        };
        if r.remaining() != 0 {
            return None;
        }
        Some(a)
    }
}

// ── The typed operations' wire ──────────────────────────────────────────

/// Message types of the two control-act operations. Numbered above
/// `state_wire`'s range (0x60–0x71) and beside the storage-key service's
/// (0x80–0x87), in the block `auth_wire.rs` reserves for the control-plane
/// profiles.
pub mod msg {
    /// `control_act_verify` request: `[record f16][declaration f16]`. The
    /// declaration may be empty, in which case the digest is not checked.
    pub const VERIFY_REQ: u8 = 0x90;
    /// `control_act_verify` answer: a [`super::Verdict`].
    pub const VERIFY_RESP: u8 = 0x91;
    /// `control_act_mint` request: a [`super::MintRequest`].
    pub const MINT_REQ: u8 = 0x92;
    /// `control_act_mint` answer: `[status u8][record f16]`, the record
    /// empty on every refusal.
    pub const MINT_RESP: u8 = 0x93;
    /// An audit entry ([`super::Audit`]) on `control_act_mint`'s
    /// `audit_out`: one per decision, minted or refused.
    pub const AUDIT: u8 = 0x9E;
}

/// Verdict status: 0 is ok, otherwise a [`Refusal`] code.
pub const STATUS_OK: u8 = 0;

/// What `control_act_verify` answers: the act's binding, typed, so a
/// consumer never parses the record itself.
///
/// `[status u8][kind u8][actor class u8][target kind u8][actor 16]
/// [tenant 16][service 16][target 16][operation 16][expected epoch u64]
/// [record digest 32]` — [`VERDICT_LEN`] bytes. A refusal carries every
/// field after `status` zero.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Verdict {
    pub status: u8,
    pub kind: u8,
    pub actor_class: u8,
    pub target_kind: u8,
    pub actor: [u8; 16],
    pub tenant: [u8; 16],
    pub service: [u8; 16],
    pub target: [u8; 16],
    pub operation: [u8; 16],
    pub expected_epoch: u64,
    pub record_digest: [u8; 32],
}

pub const VERDICT_LEN: usize = 4 + 5 * 16 + 8 + 32;

impl Verdict {
    #[must_use]
    pub const fn refused(refusal: Refusal) -> Self {
        Self {
            status: refusal.code(),
            kind: 0,
            actor_class: 0,
            target_kind: 0,
            actor: [0; 16],
            tenant: [0; 16],
            service: [0; 16],
            target: [0; 16],
            operation: [0; 16],
            expected_epoch: 0,
            record_digest: [0; 32],
        }
    }

    #[must_use]
    pub const fn ok(a: &Act, record_digest: [u8; 32]) -> Self {
        Self {
            status: STATUS_OK,
            kind: a.kind,
            actor_class: a.actor_class,
            target_kind: a.target_kind,
            actor: a.actor,
            tenant: a.tenant,
            service: a.service,
            target: a.target,
            operation: a.operation,
            expected_epoch: a.expected_epoch,
            record_digest,
        }
    }

    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.u8(self.status)?;
        w.u8(self.kind)?;
        w.u8(self.actor_class)?;
        w.u8(self.target_kind)?;
        w.bytes(&self.actor)?;
        w.bytes(&self.tenant)?;
        w.bytes(&self.service)?;
        w.bytes(&self.target)?;
        w.bytes(&self.operation)?;
        w.u64(self.expected_epoch)?;
        w.bytes(&self.record_digest)?;
        Some(w.len())
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        let v = Self {
            status: r.u8()?,
            kind: r.u8()?,
            actor_class: r.u8()?,
            target_kind: r.u8()?,
            actor: r.arr()?,
            tenant: r.arr()?,
            service: r.arr()?,
            target: r.arr()?,
            operation: r.arr()?,
            expected_epoch: r.u64()?,
            record_digest: r.arr()?,
        };
        if r.remaining() != 0 {
            return None;
        }
        // A refusal names nothing: a verdict that refused and still carried
        // an actor would be read as an actor by a consumer that ignored
        // the status.
        if v.status != STATUS_OK && v != Self::refused_code(v.status) {
            return None;
        }
        Some(v)
    }

    const fn refused_code(code: u8) -> Self {
        let mut v = Self::refused(Refusal::Malformed);
        v.status = code;
        v
    }
}

/// Decide a `VERIFY_REQ`: parse, verify against `lookup`, and when a
/// declaration is presented check its digest. Answers the typed verdict
/// either way.
pub fn decide_verify<'k, F>(
    sha: Sha256Fn,
    verify: VerifyFn,
    lookup: F,
    payload: &[u8],
    now_ms: u64,
) -> Verdict
where
    F: FnOnce(&[u8], &[u8]) -> Option<(u16, &'k [u8])>,
{
    let mut r = Reader::new(payload);
    let (Some(record), Some(declaration)) = (r.f16(), r.f16()) else {
        return Verdict::refused(Refusal::Malformed);
    };
    if r.remaining() != 0 {
        return Verdict::refused(Refusal::Malformed);
    }
    let rec = match Record::parse(record) {
        Ok(rec) => rec,
        Err(refusal) => return Verdict::refused(refusal),
    };
    if let Err(refusal) = rec.verify(lookup, verify, now_ms) {
        return Verdict::refused(refusal);
    }
    if !declaration.is_empty() && declaration_digest(sha, declaration) != rec.act.declaration {
        return Verdict::refused(Refusal::DeclarationMismatch);
    }
    Verdict::ok(&rec.act, record_digest(sha, record))
}

/// Write a `VERIFY_REQ` payload.
pub fn write_verify_request(record: &[u8], declaration: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.f16(record)?;
    w.f16(declaration)?;
    Some(w.len())
}

/// What `control_act_mint` is asked for, by an actor it has authenticated.
///
/// `[kind u8][target kind u8][tenant 16][service 16][target 16]
/// [operation 16][expected epoch u64][ttl ms u32][declaration digest 32]
/// [policy digest 32][carrier f16]`
///
/// The actor is not a field. It is established from `carrier`, the
/// cert-bound identity (`cert_bound_identity.rs`) the actor signed with its
/// leaf key moments ago: the leaf's SPIFFE name gives the class and id, and
/// `SHA-256(leaf public key)` — the SVID the mTLS control link would have
/// reported — is what the audit trail records. A free actor string would
/// be whatever the caller wrote.
#[derive(Clone, Copy)]
pub struct MintRequest<'a> {
    pub kind: u8,
    pub target_kind: u8,
    pub tenant: [u8; 16],
    pub service: [u8; 16],
    pub target: [u8; 16],
    pub operation: [u8; 16],
    pub expected_epoch: u64,
    pub ttl_ms: u32,
    pub declaration: [u8; 32],
    pub policy: [u8; 32],
    pub carrier: &'a [u8],
}

/// The fixed part of a mint request, before the carrier.
pub const MINT_FIXED: usize = 2 + 4 * 16 + 8 + 4 + 64;

impl<'a> MintRequest<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.u8(self.kind)?;
        w.u8(self.target_kind)?;
        w.bytes(&self.tenant)?;
        w.bytes(&self.service)?;
        w.bytes(&self.target)?;
        w.bytes(&self.operation)?;
        w.u64(self.expected_epoch)?;
        w.u32(self.ttl_ms)?;
        w.bytes(&self.declaration)?;
        w.bytes(&self.policy)?;
        w.f16(self.carrier)?;
        Some(w.len())
    }

    pub fn decode(b: &'a [u8]) -> Result<Self, Refusal> {
        let mut r = Reader::new(b);
        let bad = Refusal::Malformed;
        let req = Self {
            kind: r.u8().ok_or(bad)?,
            target_kind: r.u8().ok_or(bad)?,
            tenant: r.arr().ok_or(bad)?,
            service: r.arr().ok_or(bad)?,
            target: r.arr().ok_or(bad)?,
            operation: r.arr().ok_or(bad)?,
            expected_epoch: r.u64().ok_or(bad)?,
            ttl_ms: r.u32().ok_or(bad)?,
            declaration: r.arr().ok_or(bad)?,
            policy: r.arr().ok_or(bad)?,
            carrier: r.f16().ok_or(bad)?,
        };
        if r.remaining() != 0 || req.carrier.is_empty() {
            return Err(bad);
        }
        Ok(req)
    }

    /// The act this request asks for, once `actor` has been established,
    /// dated `now_ms`. The ttl is clamped to [`MAX_WINDOW_MS`] rather than
    /// refused: the caller asked for an act, and gets the longest one the
    /// profile issues.
    #[must_use]
    pub fn act(&self, actor_class: u8, actor: [u8; 16], now_ms: u64) -> Act {
        let ttl = u64::from(self.ttl_ms).clamp(1, MAX_WINDOW_MS);
        Act {
            kind: self.kind,
            actor_class,
            target_kind: self.target_kind,
            actor,
            tenant: self.tenant,
            service: self.service,
            target: self.target,
            operation: self.operation,
            expected_epoch: self.expected_epoch,
            issued_ms: now_ms,
            expiry_ms: now_ms.saturating_add(ttl),
            declaration: self.declaration,
            policy: self.policy,
        }
    }
}

/// Write a `MINT_RESP` payload: `[status u8][record f16]`.
pub fn write_mint_response(status: u8, record: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.u8(status)?;
    w.f16(if status == STATUS_OK { record } else { &[] })?;
    Some(w.len())
}

/// Read a `MINT_RESP` payload: `(status, record)`.
pub fn read_mint_response(payload: &[u8]) -> Option<(u8, &[u8])> {
    let mut r = Reader::new(payload);
    let status = r.u8()?;
    let record = r.f16()?;
    if r.remaining() != 0 || (status != STATUS_OK && !record.is_empty()) {
        return None;
    }
    Some((status, record))
}

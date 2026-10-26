//! Least-privilege operation scopes (`KSCP`): the authority one actor holds
//! for one kind of portfolio operation, on one object, at one level of the
//! cell → region → global hierarchy.
//!
//! Wormhole's RFC §22 asks Kagi to "authorize producer/consumer attachment,
//! imported-prefix, service-chain and failure-domain operations with
//! least-privilege scopes" and to "authorize route/fence/ownership acts
//! without becoming their state store". Attachments have their own profile
//! (`KATT`). This is the rest: failure-domain operations, prefix and address
//! operations, service-chain operations, DR intents and fences.
//!
//! A scope is shaped to be checked where Wormhole already checks scope. Its
//! object, level, region, cell, data locality and recovery generation are
//! exactly the fields of Wormhole's `ScopedGrant` (`scope_core.rs`), and its
//! kind uses that file's `scoped_kind` numbers, so a verified scope becomes a
//! `ScopedGrant` field for field and goes through `scope_admit` like every
//! other portfolio object. What a scope adds is the **operations** it allows
//! and **whose** they are.
//!
//! # Least privilege
//!
//! - **One kind per scope.** A scope for a service chain authorises nothing
//!   about prefixes; there is no "admin" scope.
//! - **Operations are a subset of the class's ceiling** ([`ceiling`]). A
//!   class's ceiling is the most any member of it may ever hold for a kind,
//!   whatever a policy says: a host may confirm its own zone's fence and
//!   nothing else; a workload may declare its own tenant's chains; a
//!   controller (service class) may act automatically within what operators
//!   admitted — evacuate on evidence, fail a region over, allocate and
//!   advertise inside admitted space, confirm fences as a fence provider; an
//!   operator holds the intents — imports, recovery marks, scheduled
//!   evacuations and restores — and never confirms a fence, because fence
//!   confirmation is accepted only from the admitted fence provider (§15.1).
//! - **Levels are fixed per kind** ([`level_permits`]): a DR intent acts on
//!   the global tier and is global; a regional fence is global, a zone fence
//!   is a cell's or a region's, and a fence scope holds one of the two, never
//!   both; failure-domain and chain operations are a cell's or a region's;
//!   prefixes are a region's or the global root's.
//! - **Short.** At most [`MAX_WINDOW_MS`]; a controller re-mints.
//!
//! Which actor holds which scope for which object is the deployment's
//! policy (Lattice), named here by digest as a control act names it: Kagi
//! applies the class ceilings, signs for the actor it authenticated, and
//! keeps nothing. The recovery generation is the requester's statement;
//! Wormhole refuses a scope whose generation is not the global manifest's
//! (`scope_admit`).
//!
//! Pure `no_std`, and it mounts nothing but itself, so a relying party can
//! verify with this file alone. SHA-256 and signature verification are
//! injected.
//!
//! # The record
//!
//! | Off | Len | Field |
//! | --- | --- | --- |
//! | 0 | 4 | magic `KSCP` |
//! | 4 | 1 | version ([`VERSION`]) |
//! | 5 | 1 | kind ([`kind`]) |
//! | 6 | 1 | level ([`level`]) |
//! | 7 | 1 | actor class (`spiffe::Class` code) |
//! | 8 | 4 | operations: a mask of the kind's bits |
//! | 12 | 4 | region |
//! | 16 | 4 | cell |
//! | 20 | 4 | data locality: a bit per region below 32, zero unrestricted |
//! | 24 | 8 | recovery generation |
//! | 32 | 8 | issued at, Unix ms |
//! | 40 | 8 | expiry, Unix ms |
//! | 48 | 16 | actor id |
//! | 64 | 16 | tenant |
//! | 80 | 16 | service |
//! | 96 | 16 | object id |
//! | 112 | 32 | policy digest |
//! | 144 | | `issuer f8`, `kid f8`, `signature suite u16`, `signature f16` |
//!
//! The signature covers every byte before the signature field, suite
//! included; the `OPERATION_SCOPE` profile's key signs nothing else.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

pub type Sha256Fn = fn(&[u8], &mut [u8; 32]);
pub type VerifyFn = fn(u16, &[u8], &[u8], &[u8]) -> bool;

pub const MAGIC: [u8; 4] = *b"KSCP";
pub const VERSION: u8 = 1;

/// Scope kinds, numbered as Wormhole's `scoped_kind`. Wormhole's dial,
/// attachment and egress-identity kinds (1, 2, 4) are not this profile's.
pub mod kind {
    pub const CHAIN: u8 = 3;
    pub const PREFIX: u8 = 5;
    pub const FAILURE_DOMAIN: u8 = 6;
    pub const DR_INTENT: u8 = 7;
    pub const FENCE: u8 = 8;

    #[must_use]
    pub const fn valid(k: u8) -> bool {
        matches!(k, CHAIN | PREFIX | FAILURE_DOMAIN | DR_INTENT | FENCE)
    }

    /// Short stable token, for an operator-facing log line.
    #[must_use]
    pub const fn text(k: u8) -> &'static [u8] {
        match k {
            CHAIN => b"chain",
            PREFIX => b"prefix",
            FAILURE_DOMAIN => b"failure-domain",
            DR_INTENT => b"dr-intent",
            FENCE => b"fence",
            _ => b"unknown",
        }
    }
}

/// Levels, numbered as Wormhole's `scope_level`.
pub mod level {
    pub const CELL: u8 = 1;
    pub const REGION: u8 = 2;
    pub const GLOBAL: u8 = 3;
}

/// Failure-domain operations (§14.5).
pub mod failure_domain {
    /// A scheduled evacuation intent.
    pub const EVACUATE: u32 = 1 << 0;
    /// A practice evacuation, which restores itself.
    pub const PRACTICE: u32 = 1 << 1;
    /// A restore intent.
    pub const RESTORE: u32 = 1 << 2;
    /// Initiating an evacuation from evidence, without an intent.
    pub const AUTOMATIC: u32 = 1 << 3;
    /// Aborting an evacuation in flight.
    pub const ABORT: u32 = 1 << 4;
    pub const ALL: u32 = EVACUATE | PRACTICE | RESTORE | AUTOMATIC | ABORT;
}

/// Prefix and address operations (§11.15).
pub mod prefix {
    /// Importing tenant-owned space (BYOIP).
    pub const IMPORT: u32 = 1 << 0;
    /// Carving a suballocation inside admitted space.
    pub const ALLOCATE: u32 = 1 << 1;
    /// Issuing an ADVERTISE authority for an allocation.
    pub const ADVERTISE: u32 = 1 << 2;
    /// Withdrawing an allocation.
    pub const WITHDRAW: u32 = 1 << 3;
    /// Binding reverse-DNS delegation to an allocation.
    pub const RDNS: u32 = 1 << 4;
    pub const ALL: u32 = IMPORT | ALLOCATE | ADVERTISE | WITHDRAW | RDNS;
}

/// Service-chain operations (§11.13).
pub mod chain {
    pub const DECLARE: u32 = 1 << 0;
    pub const REPLACE: u32 = 1 << 1;
    /// Draining a stage instance.
    pub const DRAIN_STAGE: u32 = 1 << 2;
    /// Moving a stage to its declared prepared standby.
    pub const FAILOVER_STAGE: u32 = 1 << 3;
    pub const ALL: u32 = DECLARE | REPLACE | DRAIN_STAGE | FAILOVER_STAGE;
}

/// DR intents (§13.6, §19.3).
pub mod dr {
    /// Removing or replacing a lost region in the owner set.
    pub const FAILOVER: u32 = 1 << 0;
    /// Draining a region.
    pub const DRAIN: u32 = 1 << 1;
    /// Restoring a region as an owner or DR target.
    pub const RESTORE: u32 = 1 << 2;
    /// Marking an unsafe recovery: advancing the recovery generation.
    pub const RECOVERY_MARK: u32 = 1 << 3;
    /// Admitting a DR policy.
    pub const ADMIT_POLICY: u32 = 1 << 4;
    pub const ALL: u32 = FAILOVER | DRAIN | RESTORE | RECOVERY_MARK | ADMIT_POLICY;
}

/// Fence confirmations (§11.6, §15.1).
pub mod fence {
    /// Confirming a zone's or host's fence.
    pub const CONFIRM: u32 = 1 << 0;
    /// Confirming a region's fence (upstream cut, power).
    pub const REGIONAL_CONFIRM: u32 = 1 << 1;
    pub const ALL: u32 = CONFIRM | REGIONAL_CONFIRM;
}

/// Actor classes, as `spiffe::Class` numbers them.
pub mod class {
    pub const DEVICE: u8 = 1;
    pub const WORKLOAD: u8 = 2;
    pub const SERVICE: u8 = 3;
    pub const HOST: u8 = 4;
    pub const OPERATOR: u8 = 5;
}

/// The most a member of `actor_class` may ever hold for `scope_kind`. Zero:
/// nothing.
#[must_use]
pub const fn ceiling(scope_kind: u8, actor_class: u8) -> u32 {
    match (scope_kind, actor_class) {
        (kind::FAILURE_DOMAIN, class::OPERATOR) => {
            failure_domain::EVACUATE
                | failure_domain::PRACTICE
                | failure_domain::RESTORE
                | failure_domain::ABORT
        }
        (kind::FAILURE_DOMAIN, class::SERVICE) => failure_domain::AUTOMATIC | failure_domain::ABORT,
        (kind::PREFIX, class::OPERATOR) => prefix::ALL,
        (kind::CHAIN, class::OPERATOR | class::SERVICE) => chain::ALL,
        (kind::PREFIX, class::SERVICE) => {
            prefix::ALLOCATE | prefix::ADVERTISE | prefix::WITHDRAW | prefix::RDNS
        }
        (kind::CHAIN, class::WORKLOAD) => chain::DECLARE | chain::REPLACE,
        (kind::DR_INTENT, class::OPERATOR) => dr::ALL,
        (kind::DR_INTENT, class::SERVICE) => dr::FAILOVER | dr::DRAIN,
        (kind::FENCE, class::SERVICE) => fence::ALL,
        (kind::FENCE, class::HOST) => fence::CONFIRM,
        _ => 0,
    }
}

/// Whether a scope of `scope_kind` holding `ops` may sit at `at` (see the
/// file comment).
#[must_use]
pub const fn level_permits(scope_kind: u8, ops: u32, at: u8) -> bool {
    match scope_kind {
        kind::DR_INTENT => at == level::GLOBAL,
        kind::FENCE => match ops {
            fence::REGIONAL_CONFIRM => at == level::GLOBAL,
            fence::CONFIRM => at == level::CELL || at == level::REGION,
            _ => false,
        },
        kind::FAILURE_DOMAIN | kind::CHAIN => at == level::CELL || at == level::REGION,
        kind::PREFIX => at == level::REGION || at == level::GLOBAL,
        _ => false,
    }
}

// ── Layout ──────────────────────────────────────────────────────────────

pub const OFF_VERSION: usize = 4;
pub const OFF_KIND: usize = 5;
pub const OFF_LEVEL: usize = 6;
pub const OFF_ACTOR_CLASS: usize = 7;
pub const OFF_OPS: usize = 8;
pub const OFF_REGION: usize = 12;
pub const OFF_CELL: usize = 16;
pub const OFF_LOCALITY: usize = 20;
pub const OFF_RECOVERY: usize = 24;
pub const OFF_ISSUED: usize = 32;
pub const OFF_EXPIRY: usize = 40;
pub const OFF_ACTOR: usize = 48;
pub const OFF_TENANT: usize = 64;
pub const OFF_SERVICE: usize = 80;
pub const OFF_OBJECT: usize = 96;
pub const OFF_POLICY: usize = 112;
pub const FIXED_LEN: usize = 144;

pub const MAX_ID: usize = 64;
pub const MAX_SIGNATURE: usize = 64;
pub const MAX_RECORD: usize = FIXED_LEN + 2 * (1 + MAX_ID) + 2 + 2 + MAX_SIGNATURE;

/// Longest a scope may stand: an hour from issue.
pub const MAX_WINDOW_MS: u64 = 3_600_000;
/// Issue-time skew a verifier allows.
pub const SKEW_MS: u64 = 60_000;

// ── Refusals ────────────────────────────────────────────────────────────

/// Why a scope was refused. Stable; they travel in replies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Refusal {
    Malformed = 1,
    /// The request carried no identity, or one that did not verify.
    NotAuthenticated = 2,
    /// A kind this profile does not issue.
    UnknownKind = 3,
    /// No operations, or operations beyond the actor class's ceiling.
    NotPermitted = 4,
    /// A level the kind may not sit at.
    LevelInvalid = 5,
    /// Expiry before issue, or longer than [`MAX_WINDOW_MS`].
    WindowInvalid = 6,
    Expired = 7,
    /// Issued further ahead of the verifier's clock than [`SKEW_MS`].
    NotYetValid = 8,
    BadSignature = 9,
    UnknownKey = 10,
    NoIssuerKey = 11,
    NoClock = 12,
    /// The carrier the request authenticated with was presented before.
    Replayed = 13,
    /// The scope verifies and does not cover what it is presented for
    /// ([`Scope::authorizes`]): another kind, operation, actor or object.
    OutOfScope = 14,
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

    fn u32(&mut self, v: u32) -> Option<()> {
        self.bytes(&v.to_le_bytes())
    }

    fn u64(&mut self, v: u64) -> Option<()> {
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

    fn u32(&mut self) -> Option<u32> {
        rd_u32(self.take(4)?, 0)
    }

    fn u64(&mut self) -> Option<u64> {
        rd_u64(self.take(8)?, 0)
    }

    fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        rd_arr(self.take(N)?, 0)
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

// ── The scope ───────────────────────────────────────────────────────────

/// The fixed part of a record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Scope {
    pub kind: u8,
    pub level: u8,
    pub actor_class: u8,
    pub ops: u32,
    pub region: u32,
    pub cell: u32,
    pub locality: u32,
    pub recovery_generation: u64,
    pub issued_ms: u64,
    pub expiry_ms: u64,
    pub actor: [u8; 16],
    pub tenant: [u8; 16],
    pub service: [u8; 16],
    pub object: [u8; 16],
    pub policy: [u8; 32],
}

impl Scope {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            kind: 0,
            level: 0,
            actor_class: 0,
            ops: 0,
            region: 0,
            cell: 0,
            locality: 0,
            recovery_generation: 0,
            issued_ms: 0,
            expiry_ms: 0,
            actor: [0; 16],
            tenant: [0; 16],
            service: [0; 16],
            object: [0; 16],
            policy: [0; 32],
        }
    }

    fn write(&self, w: &mut Writer<'_>) -> Option<()> {
        w.bytes(&MAGIC)?;
        w.u8(VERSION)?;
        w.u8(self.kind)?;
        w.u8(self.level)?;
        w.u8(self.actor_class)?;
        w.u32(self.ops)?;
        w.u32(self.region)?;
        w.u32(self.cell)?;
        w.u32(self.locality)?;
        w.u64(self.recovery_generation)?;
        w.u64(self.issued_ms)?;
        w.u64(self.expiry_ms)?;
        w.bytes(&self.actor)?;
        w.bytes(&self.tenant)?;
        w.bytes(&self.service)?;
        w.bytes(&self.object)?;
        w.bytes(&self.policy)
    }

    fn read(b: &[u8]) -> Option<Self> {
        if b.get(..4)? != MAGIC || *b.get(OFF_VERSION)? != VERSION {
            return None;
        }
        Some(Self {
            kind: *b.get(OFF_KIND)?,
            level: *b.get(OFF_LEVEL)?,
            actor_class: *b.get(OFF_ACTOR_CLASS)?,
            ops: rd_u32(b, OFF_OPS)?,
            region: rd_u32(b, OFF_REGION)?,
            cell: rd_u32(b, OFF_CELL)?,
            locality: rd_u32(b, OFF_LOCALITY)?,
            recovery_generation: rd_u64(b, OFF_RECOVERY)?,
            issued_ms: rd_u64(b, OFF_ISSUED)?,
            expiry_ms: rd_u64(b, OFF_EXPIRY)?,
            actor: rd_arr(b, OFF_ACTOR)?,
            tenant: rd_arr(b, OFF_TENANT)?,
            service: rd_arr(b, OFF_SERVICE)?,
            object: rd_arr(b, OFF_OBJECT)?,
            policy: rd_arr(b, OFF_POLICY)?,
        })
    }

    /// The scope is one this profile issues: a known kind, operations
    /// within the actor class's ceiling, a level the kind may sit at, and an
    /// ordered, bounded window. Checked at mint and again at every verify,
    /// so a record is held to the same least privilege wherever it is read.
    pub fn check(&self) -> Result<(), Refusal> {
        if !kind::valid(self.kind) {
            return Err(Refusal::UnknownKind);
        }
        let ceiling = ceiling(self.kind, self.actor_class);
        if self.ops == 0 || self.ops & !ceiling != 0 {
            return Err(Refusal::NotPermitted);
        }
        if !level_permits(self.kind, self.ops, self.level) {
            return Err(Refusal::LevelInvalid);
        }
        if self.actor == [0; 16] || self.object == [0; 16] {
            return Err(Refusal::Malformed);
        }
        if self.expiry_ms <= self.issued_ms || self.expiry_ms - self.issued_ms > MAX_WINDOW_MS {
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
            return Err(Refusal::NotYetValid);
        }
        Ok(())
    }

    /// Whether this scope covers `ask`: the same kind, every operation asked
    /// for among its own, the actor presenting it its own actor, and the
    /// same tenant, service and object. A scope is not a bearer token: the
    /// relying party checks it against the actor it authenticated.
    pub fn authorizes(&self, ask: &Ask) -> Result<(), Refusal> {
        let ok = self.kind == ask.kind
            && ask.ops != 0
            && ask.ops & !self.ops == 0
            && self.actor_class == ask.actor_class
            && self.actor == ask.actor
            && self.tenant == ask.tenant
            && self.service == ask.service
            && self.object == ask.object;
        if ok {
            Ok(())
        } else {
            Err(Refusal::OutOfScope)
        }
    }
}

/// What a relying party asks a scope to cover.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ask {
    pub kind: u8,
    pub ops: u32,
    pub actor_class: u8,
    pub actor: [u8; 16],
    pub tenant: [u8; 16],
    pub service: [u8; 16],
    pub object: [u8; 16],
}

// ── The record ──────────────────────────────────────────────────────────

/// The signer a record names.
#[derive(Clone, Copy)]
pub struct Signer<'a> {
    pub issuer: &'a [u8],
    pub kid: &'a [u8],
}

pub fn write_unsigned(
    out: &mut [u8],
    s: &Scope,
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
    s.write(&mut w)?;
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
    pub scope: Scope,
    pub signer: Signer<'a>,
    pub signature_suite: u16,
    pub signature: &'a [u8],
    pub signed: &'a [u8],
}

impl<'a> Record<'a> {
    /// Structure only; trailing bytes refused.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Refusal> {
        let bad = Refusal::Malformed;
        let scope = Scope::read(bytes).ok_or(bad)?;
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
            scope,
            signer: Signer { issuer, kid },
            signature_suite,
            signature,
            signed: bytes.get(..signed_len).ok_or(bad)?,
        })
    }

    /// Offline verification: a scope this profile issues, signed by the key
    /// `lookup` names under that key's own suite, live at `now_ms`.
    pub fn verify<'k, F>(&self, lookup: F, verify: VerifyFn, now_ms: u64) -> Result<(), Refusal>
    where
        F: FnOnce(&[u8], &[u8]) -> Option<(u16, &'k [u8])>,
    {
        self.scope.check()?;
        let (suite, public) =
            lookup(self.signer.issuer, self.signer.kid).ok_or(Refusal::UnknownKey)?;
        if self.signature_suite != suite || !verify(suite, public, self.signed, self.signature) {
            return Err(Refusal::BadSignature);
        }
        self.scope.live_at(now_ms)
    }

    /// [`Record::verify`], then [`Scope::authorizes`]: what a relying party
    /// runs before it acts on an operation the scope is presented for.
    pub fn authorize<'k, F>(
        &self,
        lookup: F,
        verify: VerifyFn,
        now_ms: u64,
        ask: &Ask,
    ) -> Result<&Scope, Refusal>
    where
        F: FnOnce(&[u8], &[u8]) -> Option<(u16, &'k [u8])>,
    {
        self.verify(lookup, verify, now_ms)?;
        self.scope.authorizes(ask)?;
        Ok(&self.scope)
    }
}

#[must_use]
pub fn record_digest(sha: Sha256Fn, record: &[u8]) -> [u8; 32] {
    let mut d = [0u8; 32];
    sha(record, &mut d);
    d
}

// ── The mint decision ───────────────────────────────────────────────────

/// What an actor asks a scope for. The actor is not a field: it is
/// established from `carrier`.
#[derive(Clone, Copy)]
pub struct MintRequest<'a> {
    pub kind: u8,
    pub level: u8,
    pub ops: u32,
    pub region: u32,
    pub cell: u32,
    pub locality: u32,
    pub recovery_generation: u64,
    pub tenant: [u8; 16],
    pub service: [u8; 16],
    pub object: [u8; 16],
    pub ttl_ms: u32,
    pub policy: [u8; 32],
    pub carrier: &'a [u8],
}

impl<'a> MintRequest<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.u8(self.kind)?;
        w.u8(self.level)?;
        w.u32(self.ops)?;
        w.u32(self.region)?;
        w.u32(self.cell)?;
        w.u32(self.locality)?;
        w.u64(self.recovery_generation)?;
        w.bytes(&self.tenant)?;
        w.bytes(&self.service)?;
        w.bytes(&self.object)?;
        w.u32(self.ttl_ms)?;
        w.bytes(&self.policy)?;
        w.f16(self.carrier)?;
        Some(w.len())
    }

    pub fn decode(b: &'a [u8]) -> Result<Self, Refusal> {
        let bad = Refusal::Malformed;
        let mut r = Reader::new(b);
        let req = Self {
            kind: r.u8().ok_or(bad)?,
            level: r.u8().ok_or(bad)?,
            ops: r.u32().ok_or(bad)?,
            region: r.u32().ok_or(bad)?,
            cell: r.u32().ok_or(bad)?,
            locality: r.u32().ok_or(bad)?,
            recovery_generation: r.u64().ok_or(bad)?,
            tenant: r.arr().ok_or(bad)?,
            service: r.arr().ok_or(bad)?,
            object: r.arr().ok_or(bad)?,
            ttl_ms: r.u32().ok_or(bad)?,
            policy: r.arr().ok_or(bad)?,
            carrier: r.f16().ok_or(bad)?,
        };
        if r.remaining() != 0 || req.carrier.is_empty() {
            return Err(bad);
        }
        Ok(req)
    }
}

/// The scope to sign for `requester` (the authenticated `(class, id)`), or
/// why not. The ttl is clamped to [`MAX_WINDOW_MS`] rather than refused, as
/// a control act's is.
pub fn decide_mint(
    req: &MintRequest<'_>,
    requester: Option<(u8, [u8; 16])>,
    now_ms: u64,
) -> Result<Scope, Refusal> {
    if now_ms == 0 {
        return Err(Refusal::NoClock);
    }
    let (actor_class, actor) = requester.ok_or(Refusal::NotAuthenticated)?;
    let ttl = u64::from(req.ttl_ms).clamp(1, MAX_WINDOW_MS);
    let s = Scope {
        kind: req.kind,
        level: req.level,
        actor_class,
        ops: req.ops,
        region: req.region,
        cell: req.cell,
        locality: req.locality,
        recovery_generation: req.recovery_generation,
        issued_ms: now_ms,
        expiry_ms: now_ms.saturating_add(ttl),
        actor,
        tenant: req.tenant,
        service: req.service,
        object: req.object,
        policy: req.policy,
    };
    s.check()?;
    Ok(s)
}

// ── The typed operation's wire ──────────────────────────────────────────

pub mod msg {
    /// A [`super::MintRequest`].
    pub const REQUEST: u8 = 0x9A;
    /// `[status u8][record f16]`, the record empty on every refusal.
    pub const REPLY: u8 = 0x9B;
}

pub const STATUS_OK: u8 = 0;

pub fn write_reply(refusal: Option<Refusal>, record: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.u8(refusal.map_or(STATUS_OK, Refusal::code))?;
    w.f16(if refusal.is_none() { record } else { &[] })?;
    Some(w.len())
}

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

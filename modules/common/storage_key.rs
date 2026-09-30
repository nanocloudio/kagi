//! The storage-key grant and attachment-envelope profile.
//!
//! A volume key never exists outside a Fluxor vault, so what Kagi issues for
//! encrypted storage is not a key. It is a decision, written down: which
//! resource, under which recovery set and epoch, may be reconstructed by
//! which device, into which fresh recipient key, under which lease fence, for
//! how long, proven how strongly. That decision is the signed record defined
//! here. Custodians read it before they release a share, `crypt_block`
//! receives the two envelopes it authorised, and the audit trail names it by
//! digest.
//!
//! Kagi owns the record, its policy checks and the envelope semantics. It
//! never holds a volume key or a plaintext share: shares are split in the
//! provisioning vault (`SHARE_SPLIT`), released by custodians' vaults
//! (`SHARE_REWRAP`) and reconstructed in the attaching node's vault
//! (`SHARE_COMBINE`). What this fragment does with an envelope is read its
//! public header.
//!
//! Pure `no_std`. SHA-256 and signature verification are injected, because a
//! module wires the SDK's and a host suite wires independent crates. The
//! share-envelope layout is read from the published `KEY_VAULT` contract
//! (`crate::key_vault::share`) rather than restated, so the two cannot drift.
//!
//! # The record
//!
//! One layout for every kind. All integers little-endian.
//!
//! | Off | Len | Field |
//! | --- | --- | --- |
//! | 0 | 4 | magic `KSKG` |
//! | 4 | 1 | kind ([`kind`]) |
//! | 5 | 1 | resource kind ([`resource`]) |
//! | 6 | 1 | purpose: envelope purpose, `share::purpose` |
//! | 7 | 1 | custody ([`custody`]): required on a grant, proven on a release |
//! | 8 | 1 | minimum vault tier (`key_vault::tier`) |
//! | 9 | 1 | proven vault tier, [`NOT_ATTESTED`] when none was |
//! | 10 | 1 | minimum enrolment assurance: NIST AAL 1–3, 0 = none required |
//! | 11 | 1 | flags ([`flag`]) |
//! | 12 | 2 | KEM suite (`share::kem`) |
//! | 14 | 2 | AEAD suite (`share::aead`) |
//! | 16 | 4 | key epoch |
//! | 20 | 4 | grant generation |
//! | 24 | 4 | handle lifetime, seconds: the maximum on a grant, the granted on a release |
//! | 28 | 4 | retained epochs: on a grant, how many earlier key epochs it still admits (its item lists them); 0 on every other kind |
//! | 32 | 8 | lease fence token |
//! | 40 | 8 | issued at, Unix ms |
//! | 48 | 8 | expiry, Unix ms (0 = none): on a release, the envelopes' expiry |
//! | 56 | 8 | revoked at, Unix ms (0 = not revoked) |
//! | 64 | 16 | protected resource id |
//! | 80 | 16 | grant id |
//! | 96 | 16 | recovery set id |
//! | 112 | 16 | anti-replay id of the request decided |
//! | 128 | 32 | policy digest ([`policy_digest`]) |
//! | 160 | 32 | recipient thumbprint: SHA-256 of the fresh recipient public key |
//! | 192 | 32 | request nonce: the challenge this service issued |
//! | 224 | | `issuer f8`, `tenant f8`, `device f8` |
//! | | | `count u8`, then `count` items, each `f16` |
//! | | | `signature suite u16`, `signature f16` |
//!
//! The signature covers every byte before the signature field, suite
//! included. The magic is the domain separation: no other artefact this
//! issuer signs begins with it.
//!
//! Items by kind: a grant has none, or one listing its retained epochs
//! ([`Retained`]); a creation authorisation carries the three custodians'
//! P-256 public keys in share-index order; a recovery set carries the three
//! custody envelopes; a release carries none while it is an authorisation on
//! its way to custodians and the two attachment envelopes once they are back;
//! a renewal carries the attachment id and the digest of the record it
//! renews, and never an envelope; an erasure carries none.
//!
//! # Retained epochs
//!
//! A data-key rotation moves the grant to a new epoch and keeps the one it
//! left admitted, so a volume mid-migration, a retained snapshot or a clone
//! sealed under it still attaches. A grant retains at most
//! [`MAX_RETAINED_EPOCHS`] earlier epochs, listed ascending as one item of
//! `u32`s; each stays admitted — for release, renewal and recovery — until
//! it is retired by name. Which epochs a snapshot still needs is the control
//! plane's knowledge, not this issuer's, so retirement is never implied.
//!
//! # Erasure
//!
//! An erasure ([`kind::ERASURE`]) replaces a resource's grant: it names the
//! last key epoch, and every epoch up to it is gone — its recovery set
//! deleted, the custodians ordered to refuse it. Nothing is issued for the
//! resource again, and the resource id is not reused.
//!
//! # Renewal
//!
//! An attachment lives `lifetime` seconds from its release. A renewal
//! ([`kind::RENEWAL`]) extends it without moving key material: the node keeps
//! the handle it reconstructed, and the custodians are not asked for
//! anything. The device re-proves, over a fresh challenge, the same device,
//! the same recipient key and the same lease fence ([`decide_renewal`]); a
//! changed fence means the writer changed, and the node detaches and attaches
//! again instead.
//!
//! A renewal copies the attachment's resource, epoch, fence, recipient, set,
//! policy and suites, and restates the rest:
//!
//! | Field | On a renewal |
//! | --- | --- |
//! | custody, proven tier | what this renewal's evidence established |
//! | minimum tier and assurance, generation | the grant's, now |
//! | lifetime | the lifetime granted by this renewal |
//! | issued at | the renewal decision |
//! | expiry | the attachment's new expiry: issued at + lifetime |
//! | anti-replay id | the renewal request's own |
//! | request nonce | the challenge the renewal answered |
//! | items | attachment id (16), digest of the renewed record (32) |
//!
//! The attachment id is the anti-replay id of the release that began the
//! attachment; every renewal in the chain carries it forward.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::key_vault::share;

/// SHA-256, into a caller's buffer.
pub type Sha256Fn = fn(&[u8], &mut [u8; 32]);

/// Verify a signature: `(suite, public_key, message, signature)`.
///
/// `suite` is a Kagi credential suite (`auth_wire::suite`). The verifier
/// applies the suite's convention: ES256 hashes the message with SHA-256,
/// Ed25519 verifies it whole.
pub type VerifyFn = fn(u16, &[u8], &[u8], &[u8]) -> bool;

pub const MAGIC: [u8; 4] = *b"KSKG";

/// Record kinds.
pub mod kind {
    /// A resource's durable grant: its device policy and current epochs.
    pub const GRANT: u8 = 1;
    /// A release of two shares to one attaching device.
    pub const ATTACHMENT: u8 = 2;
    /// A release of two shares to a recovering device under a recovery ticket.
    pub const RECOVERY: u8 = 3;
    /// A recorded recovery set: the three custody envelopes of one epoch.
    pub const RECOVERY_SET: u8 = 4;
    /// Authorisation to create a key epoch and split it to three custodians.
    pub const CREATION: u8 = 5;
    /// Authorisation for one recovering device to recover once.
    pub const RECOVERY_TICKET: u8 = 6;
    /// An attachment's lifetime extended: same device, recipient and fence,
    /// no envelopes.
    pub const RENEWAL: u8 = 7;
    /// A resource's key custody erased: held where its grant was, it names
    /// the last epoch, and every epoch up to it is destroyed.
    pub const ERASURE: u8 = 8;
}

/// What a protected resource id names.
pub mod resource {
    /// A block volume: the id is the container's volume id.
    pub const VOLUME: u8 = 1;
    /// A Clustor partition: the id is the cluster ‖ partition digest.
    pub const PARTITION: u8 = 2;
    /// A snapshot.
    pub const SNAPSHOT: u8 = 3;

    #[must_use]
    pub const fn valid(k: u8) -> bool {
        matches!(k, VOLUME | PARTITION | SNAPSHOT)
    }
}

/// How the recipient key's custody is established.
pub mod custody {
    /// Possession only: the enrolled device signed for the recipient key.
    pub const POSSESSION_BOUND: u8 = 0;
    /// Admitted attestation evidence binds the recipient key to a
    /// hardware backend at or above the grant's minimum tier.
    pub const HARDWARE_BOUND: u8 = 1;
}

/// Record flags.
pub mod flag {
    /// The grant is revoked: nothing further is released under it.
    pub const REVOKED: u8 = 1 << 0;
    /// A recovery ticket has been used.
    pub const CONSUMED: u8 = 1 << 1;
}

/// The proven-tier byte when no evidence was admitted.
pub const NOT_ATTESTED: u8 = 0xFF;

/// Vault tiers, as the `KEY_VAULT` contract numbers them.
pub use crate::key_vault::tier;

// ── Layout ──────────────────────────────────────────────────────────────

pub const OFF_KIND: usize = 4;
pub const OFF_RESOURCE_KIND: usize = 5;
pub const OFF_PURPOSE: usize = 6;
pub const OFF_CUSTODY: usize = 7;
pub const OFF_MIN_TIER: usize = 8;
pub const OFF_PROVEN_TIER: usize = 9;
pub const OFF_MIN_ASSURANCE: usize = 10;
pub const OFF_FLAGS: usize = 11;
pub const OFF_KEM: usize = 12;
pub const OFF_AEAD: usize = 14;
pub const OFF_EPOCH: usize = 16;
pub const OFF_GENERATION: usize = 20;
pub const OFF_LIFETIME: usize = 24;
pub const OFF_RETAINED: usize = 28;
pub const OFF_FENCE: usize = 32;
pub const OFF_ISSUED: usize = 40;
pub const OFF_EXPIRY: usize = 48;
pub const OFF_REVOKED: usize = 56;
pub const OFF_RESOURCE: usize = 64;
pub const OFF_GRANT_ID: usize = 80;
pub const OFF_SET_ID: usize = 96;
pub const OFF_ANTI_REPLAY: usize = 112;
pub const OFF_POLICY: usize = 128;
pub const OFF_RECIPIENT: usize = 160;
pub const OFF_NONCE: usize = 192;
/// Where the variable part begins.
pub const FIXED_LEN: usize = 224;

/// Longest issuer, tenant or device identifier a record carries.
pub const MAX_ID: usize = 128;
/// Most items a record carries.
pub const MAX_ITEMS: usize = 3;
/// Longest signature: Ed25519 and ES256 are both 64 bytes. Records are
/// stored in the ledger, whose values stop at 2048 bytes, so a suite whose
/// signature would not fit beside three envelopes is not a record suite.
pub const MAX_SIGNATURE: usize = 64;
/// The largest record this profile produces.
pub const MAX_RECORD: usize =
    FIXED_LEN + 3 * (1 + MAX_ID) + 1 + MAX_ITEMS * (2 + share::P256_LEN) + 2 + 2 + MAX_SIGNATURE;

/// A P-256 envelope's length.
pub const ENVELOPE_LEN: usize = share::P256_LEN;
/// A P-256 public key, uncompressed.
pub const PUBLIC_LEN: usize = share::P256_PUB_LEN;

// ── Recipient announcement and bundle ───────────────────────────────────

/// `"FXRK" ‖ public(65)`: `crypt_block`'s fresh recipient announcement.
pub const RECIPIENT_MAGIC: [u8; 4] = *b"FXRK";
pub const RECIPIENT_LEN: usize = 4 + PUBLIC_LEN;

/// `"FXSB"`, count 2, three zero bytes, then envelopes A and B.
pub const BUNDLE_MAGIC: [u8; 4] = *b"FXSB";
pub const BUNDLE_HEADER: usize = 8;
pub const BUNDLE_LEN: usize = BUNDLE_HEADER + 2 * ENVELOPE_LEN;

/// The recipient public key an announcement carries, if it is one.
#[must_use]
pub fn recipient_public(announcement: &[u8]) -> Option<&[u8]> {
    if announcement.len() != RECIPIENT_LEN || announcement.get(..4)? != RECIPIENT_MAGIC {
        return None;
    }
    let public = announcement.get(4..)?;
    // Uncompressed SEC1 only: the envelope thumbprint is over these 65
    // bytes, and a compressed encoding of the same point would name a
    // different recipient.
    if public.first() != Some(&0x04) {
        return None;
    }
    Some(public)
}

// ── Refusals ────────────────────────────────────────────────────────────

/// Why a decision refused. The numbers travel in replies and audit records.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Refusal {
    Malformed = 1,
    UnknownResource = 2,
    GrantRevoked = 3,
    DeviceNotGranted = 4,
    DeviceUnknown = 5,
    BadProof = 6,
    ChallengeUnknown = 7,
    RequestExpired = 8,
    Replayed = 9,
    WrongEpoch = 10,
    WrongRecipient = 11,
    LifetimeExceeded = 12,
    AttestationRequired = 13,
    AttestationInsufficient = 14,
    AttestationInvalid = 15,
    CustodianRefused = 16,
    EnvelopeInvalid = 17,
    LedgerUnavailable = 18,
    Conflict = 19,
    NoIssuerKey = 20,
    Busy = 21,
    NoRecoveryTicket = 22,
    FenceInvalid = 23,
    SetIncomplete = 24,
    RotationInProgress = 25,
    BadSignature = 26,
    WrongTenant = 27,
    /// The record a renewal names is not a live link of an attachment this
    /// issuer made for this resource.
    UnknownAttachment = 28,
    /// A renewal named another lease fence than its attachment's: the
    /// writer changed, and the node attaches again.
    FenceChanged = 29,
    /// The attachment a renewal names has already expired.
    AttachmentExpired = 30,
    /// The resource's key custody was erased: nothing is issued for it
    /// again.
    Erased = 31,
    /// The caller reported a retained snapshot or clone still needing one
    /// of the resource's epochs.
    EpochPinned = 32,
    /// The grant already retains [`MAX_RETAINED_EPOCHS`] earlier epochs: one
    /// is retired before the key rotates again.
    RetainedEpochsFull = 33,
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

/// Copy `src` into `dst` when their lengths match, and report whether they
/// did.
///
/// `copy_from_slice` on two lengths the compiler cannot prove equal keeps a
/// panic path, and a position-independent module has no panic handler to
/// link it against: the mismatch is answered here instead.
pub fn copy_exact(dst: &mut [u8], src: &[u8]) -> bool {
    if dst.len() != src.len() {
        return false;
    }
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
    }
    true
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
        let s = self.take(2)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        rd_u32(self.take(4)?, 0)
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

// ── The binding ─────────────────────────────────────────────────────────

/// The fixed part of a record: everything a decision binds that is not an
/// identifier string or an item.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Binding {
    pub kind: u8,
    pub resource_kind: u8,
    pub purpose: u8,
    pub custody: u8,
    pub min_tier: u8,
    pub proven_tier: u8,
    pub min_assurance: u8,
    pub flags: u8,
    pub kem: u16,
    pub aead: u16,
    pub epoch: u32,
    pub generation: u32,
    pub lifetime_secs: u32,
    /// On a grant, how many earlier epochs it still admits; see [`Retained`].
    pub retained: u32,
    pub fence: u64,
    pub issued_ms: u64,
    pub expiry_ms: u64,
    pub revoked_ms: u64,
    pub resource: [u8; 16],
    pub grant_id: [u8; 16],
    pub set_id: [u8; 16],
    pub anti_replay: [u8; 16],
    pub policy: [u8; 32],
    pub recipient: [u8; 32],
    pub nonce: [u8; 32],
}

impl Binding {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            kind: 0,
            resource_kind: 0,
            purpose: 0,
            custody: custody::POSSESSION_BOUND,
            min_tier: tier::SOFTWARE,
            proven_tier: NOT_ATTESTED,
            min_assurance: 0,
            flags: 0,
            kem: share::kem::P256,
            aead: share::aead::CHACHA20_POLY1305,
            epoch: 0,
            generation: 0,
            lifetime_secs: 0,
            retained: 0,
            fence: 0,
            issued_ms: 0,
            expiry_ms: 0,
            revoked_ms: 0,
            resource: [0; 16],
            grant_id: [0; 16],
            set_id: [0; 16],
            anti_replay: [0; 16],
            policy: [0; 32],
            recipient: [0; 32],
            nonce: [0; 32],
        }
    }

    #[must_use]
    pub const fn revoked(&self) -> bool {
        self.flags & flag::REVOKED != 0
    }

    fn write(&self, w: &mut Writer<'_>) -> Option<()> {
        w.bytes(&MAGIC)?;
        w.u8(self.kind)?;
        w.u8(self.resource_kind)?;
        w.u8(self.purpose)?;
        w.u8(self.custody)?;
        w.u8(self.min_tier)?;
        w.u8(self.proven_tier)?;
        w.u8(self.min_assurance)?;
        w.u8(self.flags)?;
        w.u16(self.kem)?;
        w.u16(self.aead)?;
        w.u32(self.epoch)?;
        w.u32(self.generation)?;
        w.u32(self.lifetime_secs)?;
        w.u32(self.retained)?;
        w.u64(self.fence)?;
        w.u64(self.issued_ms)?;
        w.u64(self.expiry_ms)?;
        w.u64(self.revoked_ms)?;
        w.bytes(&self.resource)?;
        w.bytes(&self.grant_id)?;
        w.bytes(&self.set_id)?;
        w.bytes(&self.anti_replay)?;
        w.bytes(&self.policy)?;
        w.bytes(&self.recipient)?;
        w.bytes(&self.nonce)
    }

    fn read(b: &[u8]) -> Option<Self> {
        if b.get(..4)? != MAGIC {
            return None;
        }
        Some(Self {
            kind: *b.get(OFF_KIND)?,
            resource_kind: *b.get(OFF_RESOURCE_KIND)?,
            purpose: *b.get(OFF_PURPOSE)?,
            custody: *b.get(OFF_CUSTODY)?,
            min_tier: *b.get(OFF_MIN_TIER)?,
            proven_tier: *b.get(OFF_PROVEN_TIER)?,
            min_assurance: *b.get(OFF_MIN_ASSURANCE)?,
            flags: *b.get(OFF_FLAGS)?,
            kem: rd_u16(b, OFF_KEM)?,
            aead: rd_u16(b, OFF_AEAD)?,
            epoch: rd_u32(b, OFF_EPOCH)?,
            generation: rd_u32(b, OFF_GENERATION)?,
            lifetime_secs: rd_u32(b, OFF_LIFETIME)?,
            retained: rd_u32(b, OFF_RETAINED)?,
            fence: rd_u64(b, OFF_FENCE)?,
            issued_ms: rd_u64(b, OFF_ISSUED)?,
            expiry_ms: rd_u64(b, OFF_EXPIRY)?,
            revoked_ms: rd_u64(b, OFF_REVOKED)?,
            resource: rd_arr(b, OFF_RESOURCE)?,
            grant_id: rd_arr(b, OFF_GRANT_ID)?,
            set_id: rd_arr(b, OFF_SET_ID)?,
            anti_replay: rd_arr(b, OFF_ANTI_REPLAY)?,
            policy: rd_arr(b, OFF_POLICY)?,
            recipient: rd_arr(b, OFF_RECIPIENT)?,
            nonce: rd_arr(b, OFF_NONCE)?,
        })
    }
}

/// The identifiers a record names.
#[derive(Clone, Copy)]
pub struct Names<'a> {
    pub issuer: &'a [u8],
    pub tenant: &'a [u8],
    /// The device: the granted device on a grant (empty = none granted yet),
    /// the receiving device on a release or ticket.
    pub device: &'a [u8],
}

/// Write the unsigned part of a record: the binding, names, items and the
/// signature suite. Returns its length, which is the signing input.
pub fn write_unsigned(
    out: &mut [u8],
    b: &Binding,
    names: &Names<'_>,
    items: &[&[u8]],
    signature_suite: u16,
) -> Option<usize> {
    if names.issuer.len() > MAX_ID
        || names.tenant.len() > MAX_ID
        || names.device.len() > MAX_ID
        || items.len() > MAX_ITEMS
    {
        return None;
    }
    let mut w = Writer::new(out);
    b.write(&mut w)?;
    w.f8(names.issuer)?;
    w.f8(names.tenant)?;
    w.f8(names.device)?;
    w.u8(u8::try_from(items.len()).ok()?)?;
    for item in items {
        w.f16(item)?;
    }
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
    pub binding: Binding,
    pub names: Names<'a>,
    items: [&'a [u8]; MAX_ITEMS],
    item_count: usize,
    pub signature_suite: u16,
    pub signature: &'a [u8],
    /// The signed prefix: every byte before the signature field.
    pub signed: &'a [u8],
}

impl<'a> Record<'a> {
    /// Parse a record. Structure only: the signature is checked by
    /// [`Record::verify`].
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Refusal> {
        let binding = Binding::read(bytes).ok_or(Refusal::Malformed)?;
        let mut r = Reader::new(bytes);
        r.take(FIXED_LEN).ok_or(Refusal::Malformed)?;
        let issuer = r.f8().ok_or(Refusal::Malformed)?;
        let tenant = r.f8().ok_or(Refusal::Malformed)?;
        let device = r.f8().ok_or(Refusal::Malformed)?;
        let count = usize::from(r.u8().ok_or(Refusal::Malformed)?);
        if count > MAX_ITEMS {
            return Err(Refusal::Malformed);
        }
        let mut items: [&[u8]; MAX_ITEMS] = [&[]; MAX_ITEMS];
        for slot in items.iter_mut().take(count) {
            *slot = r.f16().ok_or(Refusal::Malformed)?;
        }
        let signature_suite = r.u16().ok_or(Refusal::Malformed)?;
        let signed_len = r.position();
        let signature = r.f16().ok_or(Refusal::Malformed)?;
        if r.remaining() != 0 || signature.is_empty() || signature.len() > MAX_SIGNATURE {
            return Err(Refusal::Malformed);
        }
        Ok(Self {
            binding,
            names: Names {
                issuer,
                tenant,
                device,
            },
            items,
            item_count: count,
            signature_suite,
            signature,
            signed: bytes.get(..signed_len).ok_or(Refusal::Malformed)?,
        })
    }

    #[must_use]
    pub fn items(&self) -> &[&'a [u8]] {
        self.items.get(..self.item_count).unwrap_or(&[])
    }

    #[must_use]
    pub fn item(&self, i: usize) -> Option<&'a [u8]> {
        self.items().get(i).copied()
    }

    /// Check the issuer's signature. The suite is the verifier's to pin: a
    /// record that names another suite than the issuer key's is refused
    /// rather than verified under the suite it claims.
    pub fn verify(
        &self,
        verify: VerifyFn,
        issuer_suite: u16,
        issuer_public: &[u8],
    ) -> Result<(), Refusal> {
        if self.signature_suite != issuer_suite {
            return Err(Refusal::BadSignature);
        }
        if verify(issuer_suite, issuer_public, self.signed, self.signature) {
            Ok(())
        } else {
            Err(Refusal::BadSignature)
        }
    }
}

/// SHA-256 of a whole record: how audit entries and envelopes name it.
#[must_use]
pub fn record_digest(sha: Sha256Fn, record: &[u8]) -> [u8; 32] {
    let mut d = [0u8; 32];
    sha(record, &mut d);
    d
}

/// SHA-256 of an uncompressed public key: how an envelope names its
/// recipient, and how the formats define a thumbprint.
#[must_use]
pub fn thumbprint(sha: Sha256Fn, public: &[u8]) -> [u8; 32] {
    let mut d = [0u8; 32];
    sha(public, &mut d);
    d
}

/// The policy digest one key epoch's envelopes carry.
///
/// `SHA-256("KSKG policy" ‖ issuer f8 ‖ tenant f8 ‖ resource kind ‖ resource
/// ‖ grant id ‖ set id ‖ epoch)`. It names the issuer's policy object for a
/// resource and epoch — what `crypt_block`'s container records as its policy
/// digest — so it stays the same across grant rotation and changes with a
/// data-key rotation, whose new epoch is a new recovery set.
#[must_use]
pub fn policy_digest(sha: Sha256Fn, b: &Binding, issuer: &[u8], tenant: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 16 + 2 * (1 + MAX_ID) + 1 + 16 + 16 + 16 + 4];
    let mut w = Writer::new(&mut buf);
    let ok = w.bytes(b"KSKG policy").is_some()
        && w.f8(issuer.get(..issuer.len().min(MAX_ID)).unwrap_or(&[]))
            .is_some()
        && w.f8(tenant.get(..tenant.len().min(MAX_ID)).unwrap_or(&[]))
            .is_some()
        && w.u8(b.resource_kind).is_some()
        && w.bytes(&b.resource).is_some()
        && w.bytes(&b.grant_id).is_some()
        && w.bytes(&b.set_id).is_some()
        && w.u32(b.epoch).is_some();
    let n = if ok { w.len() } else { 0 };
    let mut d = [0u8; 32];
    sha(buf.get(..n).unwrap_or(&[]), &mut d);
    d
}

// ── Retained epochs ─────────────────────────────────────────────────────

/// Most earlier key epochs one grant keeps admitted besides its current one.
///
/// Each is a recovery set still held and a key a retained snapshot or clone
/// may still be sealed under. Eight covers a rotation in flight plus a
/// snapshot kept across each of seven more; a grant at the ceiling refuses
/// the next rotation ([`Refusal::RetainedEpochsFull`]) until one is retired.
pub const MAX_RETAINED_EPOCHS: usize = 8;
/// The longest retained-epochs item: one `u32` per epoch.
pub const RETAINED_ITEM_MAX: usize = 4 * MAX_RETAINED_EPOCHS;

/// The earlier epochs a grant still admits, ascending, each below the
/// grant's current epoch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Retained {
    epochs: [u32; MAX_RETAINED_EPOCHS],
    len: usize,
}

impl Retained {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            epochs: [0; MAX_RETAINED_EPOCHS],
            len: 0,
        }
    }

    /// Read a grant's retained epochs: its count field and its one item
    /// agree, the epochs ascend strictly, and each is below the current one.
    pub fn of(grant: &Record<'_>) -> Result<Self, Refusal> {
        let g = &grant.binding;
        if g.kind != kind::GRANT {
            return Err(Refusal::Malformed);
        }
        let n = usize::try_from(g.retained).map_err(|_| Refusal::Malformed)?;
        let mut out = Self::none();
        if n == 0 {
            return if grant.items().is_empty() {
                Ok(out)
            } else {
                Err(Refusal::Malformed)
            };
        }
        let item = match grant.items() {
            [item] if n <= MAX_RETAINED_EPOCHS && item.len() == 4 * n => *item,
            _ => return Err(Refusal::Malformed),
        };
        let mut last = 0u32;
        for (slot, chunk) in out.epochs.iter_mut().zip(item.chunks_exact(4)) {
            let e = rd_u32(chunk, 0).ok_or(Refusal::Malformed)?;
            if e <= last || e >= g.epoch {
                return Err(Refusal::Malformed);
            }
            *slot = e;
            last = e;
        }
        out.len = n;
        Ok(out)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u32] {
        self.epochs.get(..self.len).unwrap_or(&[])
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len >= MAX_RETAINED_EPOCHS
    }

    /// The count a grant's fixed part carries.
    #[must_use]
    pub fn count(&self) -> u32 {
        u32::try_from(self.len).unwrap_or(0)
    }

    #[must_use]
    pub fn contains(&self, epoch: u32) -> bool {
        epoch != 0 && self.as_slice().contains(&epoch)
    }

    /// Keep `epoch` admitted: the epoch a rotation leaves, above every one
    /// already retained.
    pub fn push(&mut self, epoch: u32) -> Result<(), Refusal> {
        if self.is_full() {
            return Err(Refusal::RetainedEpochsFull);
        }
        if epoch == 0 || self.as_slice().last().is_some_and(|&l| l >= epoch) {
            return Err(Refusal::WrongEpoch);
        }
        let slot = self
            .epochs
            .get_mut(self.len)
            .ok_or(Refusal::RetainedEpochsFull)?;
        *slot = epoch;
        self.len += 1;
        Ok(())
    }

    /// Stop admitting `epoch`. Whether it was retained.
    pub fn remove(&mut self, epoch: u32) -> bool {
        let Some(at) = self.as_slice().iter().position(|&e| e == epoch) else {
            return false;
        };
        let mut i = at;
        while i + 1 < self.len {
            let next = self.epochs.get(i + 1).copied().unwrap_or(0);
            if let Some(slot) = self.epochs.get_mut(i) {
                *slot = next;
            }
            i += 1;
        }
        if let Some(slot) = self.epochs.get_mut(self.len.saturating_sub(1)) {
            *slot = 0;
        }
        self.len = self.len.saturating_sub(1);
        true
    }

    /// The grant's item: each epoch as a little-endian `u32`. Returns its
    /// length, 0 when none is retained.
    pub fn write_item(&self, out: &mut [u8; RETAINED_ITEM_MAX]) -> usize {
        for (chunk, e) in out.chunks_exact_mut(4).zip(self.as_slice()) {
            for (d, s) in chunk.iter_mut().zip(e.to_le_bytes()) {
                *d = s;
            }
        }
        4 * self.len
    }
}

/// Whether a grant admits `epoch`: its current epoch, or one it retains.
#[must_use]
pub fn admits(grant: &Record<'_>, epoch: u32) -> bool {
    epoch != 0
        && grant.binding.kind == kind::GRANT
        && (epoch == grant.binding.epoch || Retained::of(grant).is_ok_and(|r| r.contains(epoch)))
}

// ── The device's attach proof ───────────────────────────────────────────

/// What a device presents to obtain a release.
#[derive(Clone, Copy)]
pub struct AttachRequest<'a> {
    /// Which record this asks for: [`kind::ATTACHMENT`],
    /// [`kind::RECOVERY`] under a recovery ticket, or [`kind::RENEWAL`] of a
    /// live attachment. Not the envelope purpose a record carries at
    /// [`OFF_PURPOSE`].
    pub kind: u8,
    pub resource_kind: u8,
    pub resource: [u8; 16],
    pub epoch: u32,
    pub fence: u64,
    pub lifetime_secs: u32,
    /// When the request stops being admissible, Unix ms.
    pub expiry_ms: u64,
    pub anti_replay: [u8; 16],
    pub challenge: [u8; 32],
    /// The recovery ticket a recovery names, the attachment id a renewal
    /// names; zero on an attachment.
    pub ticket: [u8; 16],
    /// `crypt_block`'s `"FXRK" ‖ public` announcement.
    pub recipient: &'a [u8],
    pub device: &'a [u8],
    /// The device's enrolled public key and its credential suite.
    pub device_suite: u16,
    pub device_public: &'a [u8],
    /// The device's signature over [`write_proof_input`].
    pub proof: &'a [u8],
    /// `ATTEST_KEY` output for the recipient key: `record ‖ signature`,
    /// empty when the device offers none.
    pub evidence: &'a [u8],
}

/// Longest proof signing input.
pub const MAX_PROOF_INPUT: usize =
    4 + 1 + 1 + 16 + 4 + 8 + 4 + 8 + 16 + 32 + 16 + RECIPIENT_LEN + 2 * (1 + MAX_ID);

/// The bytes a device signs with its enrolled key to bind a fresh recipient
/// key to one attach.
///
/// `"KSKP" ‖ record kind ‖ resource kind ‖ resource ‖ epoch ‖ fence ‖ lifetime ‖
/// request expiry ‖ anti-replay id ‖ challenge ‖ ticket ‖ FXRK announcement ‖
/// device f8 ‖ issuer f8`. Every field a release is decided on is here, so a
/// proof cannot be carried to another volume, lease, recipient, lifetime or
/// issuer. The record kind keeps an attach proof and a renewal proof apart.
pub fn write_proof_input(req: &AttachRequest<'_>, issuer: &[u8], out: &mut [u8]) -> Option<usize> {
    if req.device.len() > MAX_ID || issuer.len() > MAX_ID {
        return None;
    }
    let mut w = Writer::new(out);
    w.bytes(b"KSKP")?;
    w.u8(req.kind)?;
    w.u8(req.resource_kind)?;
    w.bytes(&req.resource)?;
    w.u32(req.epoch)?;
    w.u64(req.fence)?;
    w.u32(req.lifetime_secs)?;
    w.u64(req.expiry_ms)?;
    w.bytes(&req.anti_replay)?;
    w.bytes(&req.challenge)?;
    w.bytes(&req.ticket)?;
    w.bytes(req.recipient)?;
    w.f8(req.device)?;
    w.f8(issuer)?;
    Some(w.len())
}

/// How far ahead a request may date its own expiry. A request good for
/// longer than this is a replayable artefact rather than a request.
pub const MAX_REQUEST_WINDOW_MS: u64 = 120_000;
/// How long a released envelope stays openable. The attaching node combines
/// within seconds of the release; the envelope is dead after this.
pub const ENVELOPE_TTL_MS: u64 = 60_000;
/// How long a challenge stays redeemable.
pub const CHALLENGE_TTL_MS: u64 = 60_000;
/// Longest handle lifetime a grant may allow, and so the longest any one
/// attach or renewal grants: a week.
pub const MAX_LIFETIME_SECS: u32 = 7 * 24 * 3600;

// ── Attestation evidence (ATTEST_KEY) ───────────────────────────────────

pub mod evidence {
    //! The `ATTEST_KEY` record, as `key_vault::attest_key` lays it out.
    pub use crate::key_vault::attest_key::*;
}

/// What admitted evidence established.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Custody {
    pub custody: u8,
    pub proven_tier: u8,
}

/// The only uses a fresh recipient key may carry: agree, and export its
/// public half. `PERSIST` would outlive the attach; `WRAP` would let it
/// leave; `SIGN` would make it a second identity.
pub const RECIPIENT_USAGE: u32 =
    crate::key_vault::usage::AGREE | crate::key_vault::usage::EXPORT_PUBLIC;

/// Decide what the device's custody evidence establishes for this grant.
///
/// A hardware-bound grant requires evidence: signed by the device's
/// enrolled key, over this service's challenge, naming this recipient key,
/// with the recipient key's immutable fresh-recipient usage, held unpersisted
/// by a hardware backend at or above the grant's minimum tier. A
/// possession-bound grant is released without evidence and says so; evidence
/// offered to one is still checked, because evidence that does not verify is
/// not neutral.
///
/// A software backend can sign a record claiming anything about itself, so
/// no evidence from the kernel backend ever establishes hardware custody.
pub fn admit_custody(
    grant: &Binding,
    req: &AttachRequest<'_>,
    recipient_thumbprint: &[u8; 32],
    verify: VerifyFn,
) -> Result<Custody, Refusal> {
    let possession = Custody {
        custody: custody::POSSESSION_BOUND,
        proven_tier: NOT_ATTESTED,
    };
    if req.evidence.is_empty() {
        return if grant.custody == custody::HARDWARE_BOUND {
            Err(Refusal::AttestationRequired)
        } else {
            Ok(possession)
        };
    }
    let record = req
        .evidence
        .get(..evidence::RECORD_LEN)
        .ok_or(Refusal::AttestationInvalid)?;
    let signature = req
        .evidence
        .get(evidence::RECORD_LEN..)
        .ok_or(Refusal::AttestationInvalid)?;
    if record.get(..4) != Some(&evidence::MAGIC[..])
        || record.get(evidence::R_CHALLENGE..evidence::R_CHALLENGE + 32) != Some(&req.challenge[..])
    {
        return Err(Refusal::AttestationInvalid);
    }
    if !verify(req.device_suite, req.device_public, record, signature) {
        return Err(Refusal::AttestationInvalid);
    }
    if record.get(evidence::R_THUMBPRINT..evidence::R_THUMBPRINT + 32)
        != Some(&recipient_thumbprint[..])
    {
        return Err(Refusal::WrongRecipient);
    }
    let suite = rd_u16(record, evidence::R_SUITE).ok_or(Refusal::AttestationInvalid)?;
    let usage = rd_u32(record, evidence::R_USAGE).ok_or(Refusal::AttestationInvalid)?;
    let persisted = *record
        .get(evidence::R_PERSISTED)
        .ok_or(Refusal::AttestationInvalid)?;
    let backend = *record
        .get(evidence::R_BACKEND)
        .ok_or(Refusal::AttestationInvalid)?;
    let reported = *record
        .get(evidence::R_TIER)
        .ok_or(Refusal::AttestationInvalid)?;
    if suite != crate::key_vault::suite::P256 || usage != RECIPIENT_USAGE || persisted != 0 {
        return Err(Refusal::AttestationInsufficient);
    }
    let hardware = backend == evidence::backend::PKCS11 && reported >= tier::PROCESS_HW;
    if hardware && reported >= grant.min_tier {
        return Ok(Custody {
            custody: custody::HARDWARE_BOUND,
            proven_tier: reported,
        });
    }
    if grant.custody == custody::HARDWARE_BOUND {
        return Err(Refusal::AttestationInsufficient);
    }
    // Valid evidence of a software key: the tier is proven, the custody is
    // still possession.
    Ok(Custody {
        custody: custody::POSSESSION_BOUND,
        proven_tier: reported,
    })
}

// ── The release decision ────────────────────────────────────────────────

/// What the directory says about the requesting device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceFacts {
    /// Enrolled and not revoked.
    pub active: bool,
    /// Enrolled under the grant's tenant.
    pub in_tenant: bool,
    /// The presented public key is the one the directory bound at enrolment.
    pub key_bound: bool,
    /// The enrolment's assurance level.
    pub assurance: u8,
}

/// The outcome of [`decide_release`]: the authorisation to send to
/// custodians, minus the fields the caller stamps after signing.
#[derive(Clone, Copy, Debug)]
pub struct Release {
    pub binding: Binding,
}

/// Decide a release.
///
/// Everything here is checked before any durable state moves: the replay
/// claim that follows is the last check, so a refused request leaves no
/// trace but its audit entry.
///
/// `set` is the recorded recovery set for the requested epoch, `ticket` the
/// recovery ticket when `req.kind` is [`kind::RECOVERY`].
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one independently read fact the decision rests on"
)]
pub fn decide_release(
    sha: Sha256Fn,
    verify: VerifyFn,
    issuer: &[u8],
    grant: &Record<'_>,
    set: &Record<'_>,
    ticket: Option<&Record<'_>>,
    device: DeviceFacts,
    req: &AttachRequest<'_>,
    now_ms: u64,
) -> Result<Release, Refusal> {
    let g = &grant.binding;
    if g.kind != kind::GRANT
        || g.resource_kind != req.resource_kind
        || g.resource != req.resource
        || grant.names.issuer != issuer
    {
        return Err(Refusal::UnknownResource);
    }
    if now_ms >= req.expiry_ms || req.expiry_ms - now_ms > MAX_REQUEST_WINDOW_MS {
        return Err(Refusal::RequestExpired);
    }
    if req.fence == 0 {
        return Err(Refusal::FenceInvalid);
    }
    if !device.active {
        return Err(Refusal::DeviceUnknown);
    }
    if !device.in_tenant {
        return Err(Refusal::WrongTenant);
    }
    if !device.key_bound {
        return Err(Refusal::BadProof);
    }
    if device.assurance < g.min_assurance {
        return Err(Refusal::DeviceNotGranted);
    }
    match req.kind {
        kind::ATTACHMENT => {
            if g.revoked() {
                return Err(Refusal::GrantRevoked);
            }
            if grant.names.device.is_empty() || grant.names.device != req.device {
                return Err(Refusal::DeviceNotGranted);
            }
            if req.ticket != [0; 16] {
                return Err(Refusal::Malformed);
            }
        }
        kind::RECOVERY => {
            let t = ticket.ok_or(Refusal::NoRecoveryTicket)?;
            let tb = &t.binding;
            if tb.kind != kind::RECOVERY_TICKET
                || tb.resource_kind != req.resource_kind
                || tb.resource != req.resource
                || tb.grant_id != req.ticket
                || t.names.device != req.device
                || t.names.issuer != issuer
            {
                return Err(Refusal::NoRecoveryTicket);
            }
            if tb.flags & flag::CONSUMED != 0 || (tb.expiry_ms != 0 && now_ms >= tb.expiry_ms) {
                return Err(Refusal::NoRecoveryTicket);
            }
            if tb.epoch != req.epoch {
                return Err(Refusal::WrongEpoch);
            }
        }
        _ => return Err(Refusal::Malformed),
    }
    if !admits(grant, req.epoch) {
        return Err(Refusal::WrongEpoch);
    }
    let s = &set.binding;
    if s.kind != kind::RECOVERY_SET {
        return Err(Refusal::SetIncomplete);
    }
    if s.resource != g.resource || s.epoch != req.epoch || s.resource_kind != g.resource_kind {
        return Err(Refusal::WrongEpoch);
    }
    if req.lifetime_secs == 0 || req.lifetime_secs > g.lifetime_secs {
        return Err(Refusal::LifetimeExceeded);
    }
    let public = recipient_public(req.recipient).ok_or(Refusal::Malformed)?;
    let recipient = thumbprint(sha, public);

    // The proof is checked against the key the directory bound, which the
    // caller established in `key_bound`: a key that arrived with the request
    // is trusted only for that reason.
    let mut input = [0u8; MAX_PROOF_INPUT];
    let n = write_proof_input(req, issuer, &mut input).ok_or(Refusal::Malformed)?;
    if !verify(
        req.device_suite,
        req.device_public,
        input.get(..n).ok_or(Refusal::Malformed)?,
        req.proof,
    ) {
        return Err(Refusal::BadProof);
    }

    let held = admit_custody(g, req, &recipient, verify)?;

    let mut b = Binding::empty();
    b.kind = req.kind;
    b.resource_kind = g.resource_kind;
    b.purpose = share::purpose::ATTACHMENT;
    b.custody = held.custody;
    b.min_tier = g.min_tier;
    b.proven_tier = held.proven_tier;
    b.min_assurance = g.min_assurance;
    b.kem = s.kem;
    b.aead = s.aead;
    b.epoch = req.epoch;
    b.generation = g.generation;
    b.lifetime_secs = req.lifetime_secs;
    b.fence = req.fence;
    b.issued_ms = now_ms;
    b.expiry_ms = now_ms.saturating_add(ENVELOPE_TTL_MS);
    b.resource = g.resource;
    b.grant_id = g.grant_id;
    b.set_id = s.set_id;
    b.anti_replay = req.anti_replay;
    b.policy = s.policy;
    b.recipient = recipient;
    b.nonce = req.challenge;
    Ok(Release { binding: b })
}

// ── The renewal decision ────────────────────────────────────────────────

/// The item lengths a renewal carries: attachment id, renewed digest.
pub const RENEWAL_ID_LEN: usize = 16;
pub const RENEWAL_PREVIOUS_LEN: usize = 32;

/// When an attachment or renewal record stops holding, Unix ms: a release
/// holds `lifetime` from its decision, a renewal until its expiry. 0 for any
/// other kind.
#[must_use]
pub fn attachment_expiry(b: &Binding) -> u64 {
    match b.kind {
        kind::ATTACHMENT => b
            .issued_ms
            .saturating_add(u64::from(b.lifetime_secs).saturating_mul(1000)),
        kind::RENEWAL => b.expiry_ms,
        _ => 0,
    }
}

/// The attachment a record is a link of: a completed release (two
/// envelopes) names itself by its anti-replay id, a renewal carries the id
/// forward as its first item. `None` for anything else — an authorisation
/// still on its way to custodians is not an attachment.
#[must_use]
pub fn attachment_id(rec: &Record<'_>) -> Option<[u8; 16]> {
    match rec.binding.kind {
        kind::ATTACHMENT if rec.items().len() == 2 => Some(rec.binding.anti_replay),
        kind::RENEWAL if rec.items().len() == 2 => {
            let id = rec.item(0)?;
            if id.len() != RENEWAL_ID_LEN || rec.item(1)?.len() != RENEWAL_PREVIOUS_LEN {
                return None;
            }
            rd_arr(id, 0)
        }
        _ => None,
    }
}

/// The outcome of [`decide_renewal`]: the renewal to sign, and its items.
#[derive(Clone, Copy, Debug)]
pub struct Renewal {
    pub binding: Binding,
    pub attachment_id: [u8; 16],
    /// Digest of the record renewed.
    pub previous: [u8; 32],
}

/// Where a renewal's chain stands in the ledger.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Chain {
    /// No renewal of this attachment is recorded: only the release itself
    /// may be renewed.
    Unrenewed,
    /// The digest of the latest renewal recorded: only it may be renewed.
    Head([u8; 32]),
}

/// Decide a renewal.
///
/// In order, each refusal its own:
///
/// 1. the record presented is an attachment or renewal this issuer signed,
///    for this resource, naming the attachment id the proof binds
///    ([`Refusal::BadSignature`], [`Refusal::UnknownAttachment`]);
/// 2. the grant is this resource's and the attachment's, and not revoked
///    ([`Refusal::UnknownResource`], [`Refusal::GrantRevoked`]);
/// 3. the attachment has not expired ([`Refusal::AttachmentExpired`]) and
///    the request is inside its own window;
/// 4. the device is active, in the tenant, presents the key the directory
///    bound, meets the assurance floor, and is the device both the grant and
///    the attachment name;
/// 5. the recipient key is the attachment's ([`Refusal::WrongRecipient`]);
/// 6. the lease fence is the attachment's ([`Refusal::FenceChanged`]);
/// 7. the epoch is the attachment's and still admitted;
/// 8. the lifetime is inside the grant's and [`MAX_LIFETIME_SECS`];
/// 9. the proof verifies under the device key;
/// 10. custody evidence, over this request's challenge, meets the grant's
///     policy now — a hardware-bound grant asks for it again;
/// 11. the record is the chain's head ([`Refusal::Conflict`]).
///
/// The challenge was spent before any of this, and the anti-replay claim
/// follows it; neither is this function's.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one independently read fact the decision rests on"
)]
pub fn decide_renewal(
    sha: Sha256Fn,
    verify: VerifyFn,
    issuer: &[u8],
    issuer_suite: u16,
    issuer_public: &[u8],
    grant: &Record<'_>,
    attachment: &[u8],
    chain: Chain,
    device: DeviceFacts,
    req: &AttachRequest<'_>,
    now_ms: u64,
) -> Result<Renewal, Refusal> {
    if req.kind != kind::RENEWAL {
        return Err(Refusal::Malformed);
    }
    let att = Record::parse(attachment).map_err(|_| Refusal::UnknownAttachment)?;
    att.verify(verify, issuer_suite, issuer_public)?;
    let a = &att.binding;
    let id = attachment_id(&att).ok_or(Refusal::UnknownAttachment)?;
    if att.names.issuer != issuer
        || a.resource_kind != req.resource_kind
        || a.resource != req.resource
        || a.purpose != share::purpose::ATTACHMENT
        || id != req.ticket
    {
        return Err(Refusal::UnknownAttachment);
    }

    let g = &grant.binding;
    if g.kind != kind::GRANT
        || g.resource_kind != req.resource_kind
        || g.resource != req.resource
        || grant.names.issuer != issuer
    {
        return Err(Refusal::UnknownResource);
    }
    if g.grant_id != a.grant_id || grant.names.tenant != att.names.tenant {
        return Err(Refusal::UnknownAttachment);
    }
    if g.revoked() {
        return Err(Refusal::GrantRevoked);
    }

    if now_ms >= attachment_expiry(a) {
        return Err(Refusal::AttachmentExpired);
    }
    if now_ms >= req.expiry_ms || req.expiry_ms - now_ms > MAX_REQUEST_WINDOW_MS {
        return Err(Refusal::RequestExpired);
    }

    if !device.active {
        return Err(Refusal::DeviceUnknown);
    }
    if !device.in_tenant {
        return Err(Refusal::WrongTenant);
    }
    if !device.key_bound {
        return Err(Refusal::BadProof);
    }
    if device.assurance < g.min_assurance {
        return Err(Refusal::DeviceNotGranted);
    }
    if grant.names.device.is_empty()
        || grant.names.device != req.device
        || att.names.device != req.device
    {
        return Err(Refusal::DeviceNotGranted);
    }

    let public = recipient_public(req.recipient).ok_or(Refusal::Malformed)?;
    let recipient = thumbprint(sha, public);
    if recipient != a.recipient {
        return Err(Refusal::WrongRecipient);
    }
    if req.fence == 0 {
        return Err(Refusal::FenceInvalid);
    }
    if req.fence != a.fence {
        return Err(Refusal::FenceChanged);
    }
    if req.epoch != a.epoch || !admits(grant, req.epoch) {
        return Err(Refusal::WrongEpoch);
    }
    if req.lifetime_secs == 0
        || req.lifetime_secs > g.lifetime_secs
        || req.lifetime_secs > MAX_LIFETIME_SECS
    {
        return Err(Refusal::LifetimeExceeded);
    }

    let mut input = [0u8; MAX_PROOF_INPUT];
    let n = write_proof_input(req, issuer, &mut input).ok_or(Refusal::Malformed)?;
    if !verify(
        req.device_suite,
        req.device_public,
        input.get(..n).ok_or(Refusal::Malformed)?,
        req.proof,
    ) {
        return Err(Refusal::BadProof);
    }

    let held = admit_custody(g, req, &recipient, verify)?;

    let previous = record_digest(sha, attachment);
    let at_head = match chain {
        Chain::Unrenewed => a.kind == kind::ATTACHMENT,
        Chain::Head(d) => d == previous,
    };
    if !at_head {
        return Err(Refusal::Conflict);
    }

    let mut b = *a;
    b.kind = kind::RENEWAL;
    b.custody = held.custody;
    b.proven_tier = held.proven_tier;
    b.min_tier = g.min_tier;
    b.min_assurance = g.min_assurance;
    b.flags = 0;
    b.generation = g.generation;
    b.lifetime_secs = req.lifetime_secs;
    b.retained = 0;
    b.issued_ms = now_ms;
    b.expiry_ms = now_ms.saturating_add(u64::from(req.lifetime_secs).saturating_mul(1000));
    b.revoked_ms = 0;
    b.anti_replay = req.anti_replay;
    b.nonce = req.challenge;
    Ok(Renewal {
        binding: b,
        attachment_id: id,
        previous,
    })
}

// ── Envelopes ───────────────────────────────────────────────────────────

/// An envelope's public header, read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EnvelopeHeader {
    pub kem: u16,
    pub aead: u16,
    pub purpose: u8,
    pub index: u8,
    pub set_id: [u8; 16],
    pub resource: [u8; 16],
    pub epoch: u32,
    pub recipient: [u8; 32],
    pub fence: u64,
    pub expiry_ms: u64,
    pub anti_replay: [u8; 16],
    pub policy: [u8; 32],
}

/// Read a P-256 envelope's header, refusing anything that is not one: the
/// wrong length, magic, KEM, encapsulation length, threshold, count, index
/// or purpose.
pub fn read_envelope(env: &[u8]) -> Result<EnvelopeHeader, Refusal> {
    let bad = Refusal::EnvelopeInvalid;
    if env.len() != ENVELOPE_LEN || env.get(..4) != Some(&share::MAGIC[..]) {
        return Err(bad);
    }
    let h = EnvelopeHeader {
        kem: rd_u16(env, share::KEM).ok_or(bad)?,
        aead: rd_u16(env, share::AEAD).ok_or(bad)?,
        purpose: *env.get(share::PURPOSE).ok_or(bad)?,
        index: *env.get(share::INDEX).ok_or(bad)?,
        set_id: rd_arr(env, share::SET_ID).ok_or(bad)?,
        resource: rd_arr(env, share::RESOURCE).ok_or(bad)?,
        epoch: rd_u32(env, share::EPOCH).ok_or(bad)?,
        recipient: rd_arr(env, share::RECIPIENT).ok_or(bad)?,
        fence: rd_u64(env, share::FENCE).ok_or(bad)?,
        expiry_ms: rd_u64(env, share::EXPIRY).ok_or(bad)?,
        anti_replay: rd_arr(env, share::ANTI_REPLAY).ok_or(bad)?,
        policy: rd_arr(env, share::POLICY).ok_or(bad)?,
    };
    let enc_len = usize::from(rd_u16(env, share::ENC_LEN).ok_or(bad)?);
    if h.kem != share::kem::P256
        || enc_len != share::P256_PUB_LEN
        || !matches!(
            h.aead,
            share::aead::CHACHA20_POLY1305 | share::aead::AES_256_GCM
        )
        || *env.get(share::THRESHOLD).ok_or(bad)? != share::THRESHOLD_V1
        || *env.get(share::COUNT).ok_or(bad)? != share::COUNT_V1
        || !(1..=share::COUNT_V1).contains(&h.index)
        || !matches!(
            h.purpose,
            share::purpose::ATTACHMENT | share::purpose::RECOVERY
        )
    {
        return Err(bad);
    }
    Ok(h)
}

/// Check a custodian's released envelope against the authorisation it was
/// released under. Returns its share index.
///
/// The vault would refuse most of these at `SHARE_COMBINE`; checking here
/// keeps a wrong envelope from ever being signed into a record as though it
/// were the authorised one.
pub fn check_released(env: &[u8], auth: &Binding) -> Result<u8, Refusal> {
    let h = read_envelope(env)?;
    if h.purpose != share::purpose::ATTACHMENT
        || h.aead != auth.aead
        || h.set_id != auth.set_id
        || h.resource != auth.resource
        || h.epoch != auth.epoch
        || h.fence != auth.fence
        || h.expiry_ms != auth.expiry_ms
        || h.policy != auth.policy
    {
        return Err(Refusal::EnvelopeInvalid);
    }
    if h.recipient != auth.recipient {
        return Err(Refusal::WrongRecipient);
    }
    Ok(h.index)
}

/// Check the three envelopes `SHARE_SPLIT` produced against the creation
/// authorisation that asked for them. Custody envelopes are durable: no
/// fence, no expiry.
pub fn check_custody_set(
    sha: Sha256Fn,
    creation: &Record<'_>,
    envelopes: &[&[u8]; 3],
) -> Result<(), Refusal> {
    let c = &creation.binding;
    if c.kind != kind::CREATION || creation.items().len() != 3 {
        return Err(Refusal::Malformed);
    }
    for (i, env) in envelopes.iter().enumerate() {
        let h = read_envelope(env)?;
        let custodian = creation.item(i).ok_or(Refusal::Malformed)?;
        if h.purpose != share::purpose::RECOVERY
            || usize::from(h.index) != i + 1
            || h.aead != c.aead
            || h.set_id != c.set_id
            || h.resource != c.resource
            || h.epoch != c.epoch
            || h.fence != 0
            || h.expiry_ms != 0
            || h.policy != c.policy
        {
            return Err(Refusal::EnvelopeInvalid);
        }
        if h.recipient != thumbprint(sha, custodian) {
            return Err(Refusal::WrongRecipient);
        }
    }
    Ok(())
}

/// Assemble the `FXSB` bundle `crypt_block` takes on its `bundle` input.
///
/// Envelope A is the one with the lower share index. Both are checked
/// against the authorisation, and their indices must differ: two envelopes
/// carrying the same share reconstruct nothing.
pub fn write_bundle(
    a: &[u8],
    b: &[u8],
    auth: &Binding,
    out: &mut [u8; BUNDLE_LEN],
) -> Result<(), Refusal> {
    let ia = check_released(a, auth)?;
    let ib = check_released(b, auth)?;
    if ia == ib {
        return Err(Refusal::EnvelopeInvalid);
    }
    let (first, second) = if ia < ib { (a, b) } else { (b, a) };
    out.fill(0);
    out[..4].copy_from_slice(&BUNDLE_MAGIC);
    out[4] = 2;
    let (_, envelopes) = out.split_at_mut(BUNDLE_HEADER);
    let (a_slot, b_slot) = envelopes.split_at_mut(ENVELOPE_LEN);
    if copy_exact(a_slot, first) && copy_exact(b_slot, second) {
        Ok(())
    } else {
        Err(Refusal::EnvelopeInvalid)
    }
}

// ── Vault arguments (KEY_VAULT share operations) ────────────────────────

/// The `share::grant` block a split or rewrap binds its envelopes to: the
/// binding's set, resource, epoch, AEAD and policy, under `purpose`,
/// `fence` and `expiry_ms`.
fn write_share_grant(
    out: &mut [u8],
    purpose: u8,
    b: &Binding,
    fence: u64,
    expiry_ms: u64,
) -> Option<()> {
    use share::grant as g;
    let block = out.get_mut(..g::LEN)?;
    block.fill(0);
    block[g::PURPOSE] = purpose;
    block[g::AEAD..g::AEAD + 2].copy_from_slice(&b.aead.to_le_bytes());
    block[g::SET_ID..g::SET_ID + 16].copy_from_slice(&b.set_id);
    block[g::RESOURCE..g::RESOURCE + 16].copy_from_slice(&b.resource);
    block[g::EPOCH..g::EPOCH + 4].copy_from_slice(&b.epoch.to_le_bytes());
    block[g::FENCE..g::FENCE + 8].copy_from_slice(&fence.to_le_bytes());
    block[g::EXPIRY..g::EXPIRY + 8].copy_from_slice(&expiry_ms.to_le_bytes());
    block[g::POLICY..g::POLICY + 32].copy_from_slice(&b.policy);
    Some(())
}

/// The `SHARE_SPLIT` argument a provisioning vault runs under a creation
/// authorisation: recovery-custody envelopes, durable, to the three
/// custodians the authorisation names, in share-index order.
pub fn write_split_arg(
    creation: &Record<'_>,
    out_ptr: u64,
    out_cap: u32,
    arg: &mut [u8; share::split::LEN],
) -> Result<(), Refusal> {
    use share::split as a;
    let c = &creation.binding;
    if c.kind != kind::CREATION || creation.items().len() != 3 {
        return Err(Refusal::Malformed);
    }
    arg.fill(0);
    // Custody envelopes are durable: no fence, no expiry.
    write_share_grant(&mut arg[..], share::purpose::RECOVERY, c, 0, 0).ok_or(Refusal::Malformed)?;
    for i in 0..3 {
        let public = creation.item(i).ok_or(Refusal::Malformed)?;
        if public.len() != PUBLIC_LEN {
            return Err(Refusal::Malformed);
        }
        let at = a::RECIPIENTS + i * PUBLIC_LEN;
        if !copy_exact(&mut arg[at..at + PUBLIC_LEN], public) {
            return Err(Refusal::Malformed);
        }
    }
    arg[a::OUT_PTR..a::OUT_PTR + 8].copy_from_slice(&out_ptr.to_le_bytes());
    arg[a::OUT_CAP..a::OUT_CAP + 4].copy_from_slice(&out_cap.to_le_bytes());
    Ok(())
}

/// The fixed length of a `SHARE_REWRAP` argument around one P-256 envelope.
pub const REWRAP_ARG_LEN: usize = share::rewrap::ENV + ENVELOPE_LEN;

/// The `SHARE_REWRAP` argument a custodian runs to release its share to the
/// authorised recipient: purpose attachment, the authorisation's fence,
/// expiry and policy. The vault carries the set, resource, epoch and AEAD
/// over from the custody envelope itself.
pub fn write_rewrap_arg(
    auth: &Binding,
    recipient_public: &[u8],
    custody_envelope: &[u8],
    out_ptr: u64,
    out_cap: u32,
    arg: &mut [u8; REWRAP_ARG_LEN],
) -> Result<(), Refusal> {
    use share::rewrap as a;
    if recipient_public.len() != PUBLIC_LEN || custody_envelope.len() != ENVELOPE_LEN {
        return Err(Refusal::Malformed);
    }
    arg.fill(0);
    write_share_grant(
        &mut arg[..],
        share::purpose::ATTACHMENT,
        auth,
        auth.fence,
        auth.expiry_ms,
    )
    .ok_or(Refusal::Malformed)?;
    if !copy_exact(
        &mut arg[a::RECIPIENT..a::RECIPIENT + PUBLIC_LEN],
        recipient_public,
    ) || !copy_exact(&mut arg[a::ENV..a::ENV + ENVELOPE_LEN], custody_envelope)
    {
        return Err(Refusal::Malformed);
    }
    arg[a::OUT_PTR..a::OUT_PTR + 8].copy_from_slice(&out_ptr.to_le_bytes());
    arg[a::OUT_CAP..a::OUT_CAP + 4].copy_from_slice(&out_cap.to_le_bytes());
    #[expect(
        clippy::cast_possible_truncation,
        reason = "ENVELOPE_LEN is a 260-byte constant"
    )]
    arg[a::ENV_LEN..a::ENV_LEN + 2].copy_from_slice(&(ENVELOPE_LEN as u16).to_le_bytes());
    Ok(())
}

// ── The custodian's admission of an order ───────────────────────────────

/// What a custodian establishes before it releases its share.
///
/// The custodian's vault holds the share; the authorisation to release it
/// is the issuer's signature over a release with no items yet. A custodian
/// admits an order only when:
///
/// - the issuer signed it, under the suite the custodian pins;
/// - it is a release (attachment or recovery) still inside its expiry;
/// - the recipient public key it carries is the one the release names;
/// - the custody envelope is this custodian's, for the same recovery set,
///   resource, epoch and AEAD suite the release names;
/// - its anti-replay id has not been admitted before (`seen`).
///
/// Returns the release's binding, which is what [`write_rewrap_arg`] takes.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one independently held fact the admission rests on"
)]
pub fn admit_order(
    sha: Sha256Fn,
    verify: VerifyFn,
    issuer_suite: u16,
    issuer_public: &[u8],
    own_thumbprint: &[u8; 32],
    record: &[u8],
    recipient_public: &[u8],
    custody_envelope: &[u8],
    now_ms: u64,
    seen: &[[u8; 16]],
) -> Result<Binding, Refusal> {
    let rec = Record::parse(record)?;
    rec.verify(verify, issuer_suite, issuer_public)?;
    let b = rec.binding;
    if !matches!(b.kind, kind::ATTACHMENT | kind::RECOVERY) || !rec.items().is_empty() {
        return Err(Refusal::Malformed);
    }
    if b.purpose != share::purpose::ATTACHMENT || b.fence == 0 {
        return Err(Refusal::Malformed);
    }
    if b.expiry_ms == 0 || now_ms >= b.expiry_ms {
        return Err(Refusal::RequestExpired);
    }
    if recipient_public.len() != PUBLIC_LEN || thumbprint(sha, recipient_public) != b.recipient {
        return Err(Refusal::WrongRecipient);
    }
    let h = read_envelope(custody_envelope)?;
    if h.purpose != share::purpose::RECOVERY || h.recipient != *own_thumbprint {
        return Err(Refusal::EnvelopeInvalid);
    }
    if h.set_id != b.set_id || h.resource != b.resource || h.epoch != b.epoch || h.aead != b.aead {
        return Err(Refusal::WrongEpoch);
    }
    if seen.contains(&b.anti_replay) {
        return Err(Refusal::Replayed);
    }
    Ok(b)
}

/// What a custodian establishes before it records an erasure: the issuer
/// signed it, under the suite the custodian pins, and it is an erasure —
/// no items, a valid resource, a last epoch. Returns its binding: the
/// resource the custodian stops releasing shares of.
///
/// An erasure is not a request for anything, so it carries no expiry and no
/// anti-replay id: admitting the same one twice changes nothing.
pub fn admit_erase(
    verify: VerifyFn,
    issuer_suite: u16,
    issuer_public: &[u8],
    record: &[u8],
) -> Result<Binding, Refusal> {
    let rec = Record::parse(record)?;
    rec.verify(verify, issuer_suite, issuer_public)?;
    let b = rec.binding;
    if b.kind != kind::ERASURE
        || !rec.items().is_empty()
        || !resource::valid(b.resource_kind)
        || b.epoch == 0
    {
        return Err(Refusal::Malformed);
    }
    Ok(b)
}

/// Refuse a custody envelope whose resource this custodian was ordered to
/// erase. Checked beside [`admit_order`]: an issuer that has erased a
/// resource never orders a release of it, so this refuses only an order the
/// issuer's own records would not have produced.
pub fn refuse_erased(custody_envelope: &[u8], erased: &[[u8; 16]]) -> Result<(), Refusal> {
    let h = read_envelope(custody_envelope)?;
    if erased.contains(&h.resource) {
        return Err(Refusal::Erased);
    }
    Ok(())
}

// ── Audit ───────────────────────────────────────────────────────────────

/// Audit record magic.
pub const AUDIT_MAGIC: [u8; 4] = *b"KSKA";

/// Operations, as requests and audit entries number them.
pub mod op {
    pub const CHALLENGE: u8 = 1;
    pub const CREATE: u8 = 2;
    pub const RECORD_SET: u8 = 3;
    pub const GRANT: u8 = 4;
    pub const ATTACH: u8 = 5;
    pub const REVOKE: u8 = 6;
    pub const REPLACE_DEVICE: u8 = 7;
    pub const ROTATE_GRANT: u8 = 8;
    pub const ROTATE_KEY: u8 = 9;
    pub const RETIRE_EPOCH: u8 = 10;
    pub const RECOVERY_AUTHORISE: u8 = 11;
    pub const RECOVER: u8 = 12;
    pub const RENEW_ATTACHMENT: u8 = 13;
    pub const ERASE: u8 = 14;
}

/// One audit entry.
///
/// | Off | Len | Field |
/// | --- | --- | --- |
/// | 0 | 4 | magic `KSKA` |
/// | 4 | 1 | operation ([`op`]) |
/// | 5 | 1 | outcome: 0 allowed, 1 refused |
/// | 6 | 1 | refusal ([`Refusal`] code, 0 when allowed) |
/// | 7 | 1 | resource kind |
/// | 8 | 8 | decided at, Unix ms |
/// | 16 | 16 | resource id |
/// | 32 | 4 | key epoch |
/// | 36 | 4 | grant generation |
/// | 40 | 16 | anti-replay id |
/// | 56 | 32 | digest of the record issued, zero when none |
/// | 88 | 32 | recipient thumbprint |
/// | 120 | 8 | lease fence |
/// | 128 | 1 | custody established |
/// | 129 | 1 | proven vault tier |
/// | 130 | 2 | reserved, zero |
/// | 132 | | `device f8`, `actor f8` |
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Audit {
    pub op: u8,
    pub refusal: u8,
    pub resource_kind: u8,
    pub at_ms: u64,
    pub resource: [u8; 16],
    pub epoch: u32,
    pub generation: u32,
    pub anti_replay: [u8; 16],
    pub record: [u8; 32],
    pub recipient: [u8; 32],
    pub fence: u64,
    pub custody: u8,
    pub proven_tier: u8,
}

pub const AUDIT_FIXED: usize = 132;
pub const MAX_AUDIT: usize = AUDIT_FIXED + 2 * (1 + MAX_ID);

impl Audit {
    #[must_use]
    pub const fn new(op: u8, resource_kind: u8, resource: [u8; 16], at_ms: u64) -> Self {
        Self {
            op,
            refusal: 0,
            resource_kind,
            at_ms,
            resource,
            epoch: 0,
            generation: 0,
            anti_replay: [0; 16],
            record: [0; 32],
            recipient: [0; 32],
            fence: 0,
            custody: custody::POSSESSION_BOUND,
            proven_tier: NOT_ATTESTED,
        }
    }

    #[must_use]
    pub const fn allowed(&self) -> bool {
        self.refusal == 0
    }

    /// Fill the release fields from a binding.
    pub fn record_binding(&mut self, b: &Binding) {
        self.epoch = b.epoch;
        self.generation = b.generation;
        self.anti_replay = b.anti_replay;
        self.recipient = b.recipient;
        self.fence = b.fence;
        self.custody = b.custody;
        self.proven_tier = b.proven_tier;
    }

    pub fn encode(&self, device: &[u8], actor: &[u8], out: &mut [u8]) -> Option<usize> {
        if device.len() > MAX_ID || actor.len() > MAX_ID {
            return None;
        }
        let mut w = Writer::new(out);
        w.bytes(&AUDIT_MAGIC)?;
        w.u8(self.op)?;
        w.u8(u8::from(self.refusal != 0))?;
        w.u8(self.refusal)?;
        w.u8(self.resource_kind)?;
        w.u64(self.at_ms)?;
        w.bytes(&self.resource)?;
        w.u32(self.epoch)?;
        w.u32(self.generation)?;
        w.bytes(&self.anti_replay)?;
        w.bytes(&self.record)?;
        w.bytes(&self.recipient)?;
        w.u64(self.fence)?;
        w.u8(self.custody)?;
        w.u8(self.proven_tier)?;
        w.u16(0)?;
        w.f8(device)?;
        w.f8(actor)?;
        Some(w.len())
    }

    /// Decode an entry: the fixed fields, then `(device, actor)`.
    pub fn decode(b: &[u8]) -> Option<(Self, &[u8], &[u8])> {
        let mut r = Reader::new(b);
        if r.take(4)? != AUDIT_MAGIC {
            return None;
        }
        let op = r.u8()?;
        let refused = r.u8()?;
        let refusal = r.u8()?;
        if (refused != 0) != (refusal != 0) {
            return None;
        }
        let a = Self {
            op,
            refusal,
            resource_kind: r.u8()?,
            at_ms: r.u64()?,
            resource: r.arr()?,
            epoch: r.u32()?,
            generation: r.u32()?,
            anti_replay: r.arr()?,
            record: r.arr()?,
            recipient: r.arr()?,
            fence: r.u64()?,
            custody: r.u8()?,
            proven_tier: r.u8()?,
        };
        r.u16()?;
        let device = r.f8()?;
        let actor = r.f8()?;
        if r.remaining() != 0 {
            return None;
        }
        Some((a, device, actor))
    }
}

// ── Ledger keys ─────────────────────────────────────────────────────────

/// Lower-case hex of `bytes` into `out`; returns the length written.
pub fn hex_into(bytes: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = bytes.len().checked_mul(2)?;
    let dst = out.get_mut(..n)?;
    for (i, b) in bytes.iter().enumerate() {
        dst[2 * i] = hex_digit(b >> 4);
        dst[2 * i + 1] = hex_digit(b & 0x0F);
    }
    Some(n)
}

const fn hex_digit(v: u8) -> u8 {
    if v < 10 {
        b'0' + v
    } else {
        b'a' + (v - 10)
    }
}

/// The ledger key of a resource: `<kind>-<resource hex>`.
pub fn resource_key(resource_kind: u8, resource: &[u8; 16], out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.u8(hex_digit(resource_kind & 0x0F))?;
    w.u8(b'-')?;
    let at = w.len();
    let n = hex_into(resource, out.get_mut(at..)?)?;
    Some(at + n)
}

/// The ledger key of one epoch's recovery set: `<resource key>/<epoch hex>`.
pub fn set_key(
    resource_kind: u8,
    resource: &[u8; 16],
    epoch: u32,
    out: &mut [u8],
) -> Option<usize> {
    suffixed_key(resource_kind, resource, &epoch.to_be_bytes(), out)
}

/// The ledger key of a recovery ticket: `<resource key>/<ticket hex>`.
pub fn ticket_key(
    resource_kind: u8,
    resource: &[u8; 16],
    ticket: &[u8; 16],
    out: &mut [u8],
) -> Option<usize> {
    suffixed_key(resource_kind, resource, ticket, out)
}

/// The ledger key of an attachment's renewal chain head:
/// `<resource key>/<attachment id hex>`.
pub fn attachment_key(
    resource_kind: u8,
    resource: &[u8; 16],
    attachment: &[u8; 16],
    out: &mut [u8],
) -> Option<usize> {
    suffixed_key(resource_kind, resource, attachment, out)
}

/// The ledger key of an audit entry: `<resource key>/<time hex><id hex>`,
/// so a resource's entries list in decision order.
pub fn audit_key(
    resource_kind: u8,
    resource: &[u8; 16],
    at_ms: u64,
    id: [u8; 8],
    out: &mut [u8],
) -> Option<usize> {
    let mut suffix = [0u8; 16];
    suffix[..8].copy_from_slice(&at_ms.to_be_bytes());
    suffix[8..].copy_from_slice(&id);
    suffixed_key(resource_kind, resource, &suffix, out)
}

/// The anti-replay claim key of a release request: `sk-<id hex>`.
pub fn replay_key(anti_replay: &[u8; 16], out: &mut [u8]) -> Option<usize> {
    let head = out.get_mut(..3)?;
    head.copy_from_slice(b"sk-");
    let n = hex_into(anti_replay, out.get_mut(3..)?)?;
    Some(3 + n)
}

fn suffixed_key(
    resource_kind: u8,
    resource: &[u8; 16],
    suffix: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let n = resource_key(resource_kind, resource, out)?;
    *out.get_mut(n)? = b'/';
    let m = hex_into(suffix, out.get_mut(n + 1..)?)?;
    Some(n + 1 + m)
}

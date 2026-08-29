//! The Kagi security-state wire — the requests and replies of the durable
//! identity ledger.
//!
//! Kagi's security decisions need three operations and no more: create a
//! record only if one does not exist, replace a record only if it is still
//! the one you read, and read a record. Enrollment transactions, device
//! membership, key-package claims and endpoint high-water marks are all
//! expressible as those three, which is deliberate — lattice offers no atomic
//! multi-key transaction, so a transition that cannot be written as one key's
//! compare-and-swap cannot be made atomic at all. Designing the keyspace
//! around that constraint up front is cheaper than discovering it later.
//!
//! ## Namespaces
//!
//! Every request names a namespace, and the store module — not the caller —
//! turns it into the provider key's prefix. A caller therefore cannot reach
//! another namespace by naming a key, which matters: `keypackage_endpoint`
//! must not be able to write a device record.
//!
//! ## Expiry is carried, not delegated
//!
//! `expiry_unix` travels inside the record and is checked by the reader.
//! Provider-side expiry, where a provider has it at all, is a capacity and
//! cleanup mechanism and never the security check — lattice implements no
//! standalone TTL, so a design that leaned on one would be unimplementable on
//! the intended backend.
//!
//! ## Replies carry an etag
//!
//! A `get` returns the etag its value was read at, and that etag is what a
//! following `compare_and_swap` presents. The etag is opaque here: it is
//! whatever the provider issued, handed back unread. Only the *absent*
//! precondition is synthesised, and it is synthesised in exactly one place in
//! the store module so there is one site to change.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::auth_wire::{PayloadReader, PayloadWriter, WireError};

// ── Message types ───────────────────────────────────────────────────────
//
// `0x60`+ because `auth_wire` has claimed through `0x54`.

/// Read a record: `[corr u32][req u8][ns u8][key f8]`.
pub const MSG_STATE_GET: u8 = 0x60;
/// Create a record only if absent:
/// `[corr u32][req u8][ns u8][key f8][value f16][expiry_unix u64]`.
pub const MSG_STATE_PUT_ABS: u8 = 0x61;
/// Replace a record only if the etag still matches:
/// `[corr u32][req u8][ns u8][key f8][etag f8][value f16][expiry_unix u64]`.
pub const MSG_STATE_CAS: u8 = 0x62;
/// Remove a record only if the etag still matches:
/// `[corr u32][req u8][ns u8][key f8][etag f8]`.
pub const MSG_STATE_DELETE: u8 = 0x63;

/// A read result: `[corr u32][req u8][status u8][etag f8][value f16]`.
pub const MSG_STATE_VALUE: u8 = 0x70;
/// A write result: `[corr u32][req u8][status u8][etag f8]`.
pub const MSG_STATE_ACK: u8 = 0x71;

// ── Namespaces ──────────────────────────────────────────────────────────

/// Enrollment transactions: created at `/start`, consumed once at `/redeem`.
pub const NS_ENROL_TXN: u8 = 1;
/// The device directory — membership, status, generation.
pub const NS_DEVICE: u8 = 2;
/// Rate-limit counters, bucketed by period.
pub const NS_RATE: u8 = 3;
/// Published key packages and their one-time claim state.
pub const NS_KEYPKG: u8 = 4;
/// E2EE endpoint high-water marks.
pub const NS_E2EE_STATE: u8 = 5;
/// Replay identifiers.
pub const NS_REPLAY: u8 = 6;
/// OIDC authorization codes — single-use, consumed exactly once.
pub const NS_OAUTH_CODE: u8 = 7;
/// OIDC client registry — allowed redirect_uris and scopes per client_id.
pub const NS_OAUTH_CLIENT: u8 = 8;

/// The prefix a namespace maps to under the provider's keyspace.
///
/// An unknown namespace has no prefix rather than a default one: a request
/// naming a namespace this build does not know is refused, not silently
/// written somewhere plausible.
#[must_use]
pub const fn namespace_prefix(ns: u8) -> Option<&'static str> {
    match ns {
        NS_ENROL_TXN => Some("kagi/enrol/txn/"),
        NS_DEVICE => Some("kagi/device/"),
        NS_RATE => Some("kagi/rate/"),
        NS_KEYPKG => Some("kagi/keypkg/"),
        NS_E2EE_STATE => Some("kagi/e2ee/state/"),
        NS_REPLAY => Some("kagi/replay/"),
        NS_OAUTH_CODE => Some("kagi/oauth/code/"),
        NS_OAUTH_CLIENT => Some("kagi/oauth/client/"),
        _ => None,
    }
}

/// The longest prefix above, so a caller can size a key buffer.
pub const MAX_PREFIX: usize = 16;
/// The longest caller-supplied key this wire carries.
pub const MAX_KEY: usize = 128;
/// The largest record value.
pub const MAX_VALUE: usize = 2048;
/// The longest etag a provider may hand back.
pub const MAX_ETAG: usize = 64;

/// A decoded request.
///
/// `req` is the requesting module's client id. The store's `replies` port
/// fans out to every consumer, so each drops what is not addressed to it and
/// correlation ids need only be unique per client rather than graph-wide.
pub struct StateRequest<'a> {
    pub correlation: u32,
    pub client: u8,
    pub namespace: u8,
    pub key: &'a [u8],
    pub etag: &'a [u8],
    pub value: &'a [u8],
    pub expiry_unix: u64,
}

impl<'a> StateRequest<'a> {
    /// Decode a `GET` payload.
    pub fn decode_get(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let correlation = r.u32()?;
        let client = r.u8()?;
        let namespace = r.u8()?;
        let key = r.field8()?;
        Ok(Self {
            correlation,
            client,
            namespace,
            key,
            etag: &[],
            value: &[],
            expiry_unix: 0,
        })
    }

    /// Decode a `PUT_ABS` payload.
    pub fn decode_put_abs(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let correlation = r.u32()?;
        let client = r.u8()?;
        let namespace = r.u8()?;
        let key = r.field8()?;
        let value = r.field16()?;
        let expiry_unix = r.u64()?;
        Ok(Self {
            correlation,
            client,
            namespace,
            key,
            etag: &[],
            value,
            expiry_unix,
        })
    }

    /// Decode a `CAS` payload.
    pub fn decode_cas(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let correlation = r.u32()?;
        let client = r.u8()?;
        let namespace = r.u8()?;
        let key = r.field8()?;
        let etag = r.field8()?;
        let value = r.field16()?;
        let expiry_unix = r.u64()?;
        Ok(Self {
            correlation,
            client,
            namespace,
            key,
            etag,
            value,
            expiry_unix,
        })
    }

    /// Decode a `DELETE` payload.
    pub fn decode_delete(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let correlation = r.u32()?;
        let client = r.u8()?;
        let namespace = r.u8()?;
        let key = r.field8()?;
        let etag = r.field8()?;
        Ok(Self {
            correlation,
            client,
            namespace,
            key,
            etag,
            value: &[],
            expiry_unix: 0,
        })
    }

    /// Decode whichever request `msg_type` names.
    pub fn decode(msg_type: u8, payload: &'a [u8]) -> Result<Self, WireError> {
        match msg_type {
            MSG_STATE_GET => Self::decode_get(payload),
            MSG_STATE_PUT_ABS => Self::decode_put_abs(payload),
            MSG_STATE_CAS => Self::decode_cas(payload),
            MSG_STATE_DELETE => Self::decode_delete(payload),
            _ => Err(WireError::Truncated),
        }
    }
}

/// Encode a request of `msg_type` from `req`.
///
/// The mirror of `StateRequest::decode`, and deliberately one function
/// rather than four: the fields a given message carries are stated once, in
/// the same `match` that reads them back, so the two cannot drift.
pub fn encode_request(
    out: &mut [u8],
    msg_type: u8,
    req: &StateRequest<'_>,
) -> Result<usize, WireError> {
    let mut payload = [0u8; 32 + MAX_KEY + MAX_ETAG + MAX_VALUE];
    let mut w = PayloadWriter::new(&mut payload);
    w.u32(req.correlation)?;
    w.u8(req.client)?;
    w.u8(req.namespace)?;
    w.field8(req.key)?;
    match msg_type {
        MSG_STATE_GET => {}
        MSG_STATE_PUT_ABS => {
            w.field16(req.value)?;
            w.u64(req.expiry_unix)?;
        }
        MSG_STATE_CAS => {
            w.field8(req.etag)?;
            w.field16(req.value)?;
            w.u64(req.expiry_unix)?;
        }
        MSG_STATE_DELETE => {
            w.field8(req.etag)?;
        }
        _ => return Err(WireError::FieldTooLong),
    }
    let n = w.len();
    crate::auth_wire::write_envelope(msg_type, &payload[..n], out)
}

/// A read request for `key` in `namespace`.
#[must_use]
pub fn get<'a>(correlation: u32, client: u8, namespace: u8, key: &'a [u8]) -> StateRequest<'a> {
    StateRequest {
        correlation,
        client,
        namespace,
        key,
        etag: &[],
        value: &[],
        expiry_unix: 0,
    }
}

/// A create-only-if-absent request.
#[must_use]
pub fn put_if_absent<'a>(
    correlation: u32,
    client: u8,
    namespace: u8,
    key: &'a [u8],
    value: &'a [u8],
    expiry_unix: u64,
) -> StateRequest<'a> {
    StateRequest {
        correlation,
        client,
        namespace,
        key,
        etag: &[],
        value,
        expiry_unix,
    }
}

/// A replace-only-if-unchanged request.
#[must_use]
pub fn compare_and_swap<'a>(
    correlation: u32,
    client: u8,
    namespace: u8,
    key: &'a [u8],
    etag: &'a [u8],
    value: &'a [u8],
    expiry_unix: u64,
) -> StateRequest<'a> {
    StateRequest {
        correlation,
        client,
        namespace,
        key,
        etag,
        value,
        expiry_unix,
    }
}

/// A decoded reply.
pub struct StateReply<'a> {
    pub correlation: u32,
    pub client: u8,
    pub status: u8,
    pub etag: &'a [u8],
    pub value: &'a [u8],
}

impl<'a> StateReply<'a> {
    /// Decode a `VALUE` or `ACK` payload. An `ACK` carries no value.
    pub fn decode(msg_type: u8, payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let correlation = r.u32()?;
        let client = r.u8()?;
        let status = r.u8()?;
        let etag = r.field8()?;
        let value = if msg_type == MSG_STATE_VALUE {
            r.field16()?
        } else {
            &[]
        };
        Ok(Self {
            correlation,
            client,
            status,
            etag,
            value,
        })
    }
}

/// Encode a `VALUE` reply.
pub fn encode_value(
    out: &mut [u8],
    correlation: u32,
    client: u8,
    status: u8,
    etag: &[u8],
    value: &[u8],
) -> Result<usize, WireError> {
    let mut payload = [0u8; 16 + MAX_ETAG + MAX_VALUE];
    let mut w = PayloadWriter::new(&mut payload);
    w.u32(correlation)?;
    w.u8(client)?;
    w.u8(status)?;
    w.field8(etag)?;
    w.field16(value)?;
    let n = w.len();
    crate::auth_wire::write_envelope(MSG_STATE_VALUE, &payload[..n], out)
}

/// Encode an `ACK` reply.
pub fn encode_ack(
    out: &mut [u8],
    correlation: u32,
    client: u8,
    status: u8,
    etag: &[u8],
) -> Result<usize, WireError> {
    let mut payload = [0u8; 16 + MAX_ETAG];
    let mut w = PayloadWriter::new(&mut payload);
    w.u32(correlation)?;
    w.u8(client)?;
    w.u8(status)?;
    w.field8(etag)?;
    let n = w.len();
    crate::auth_wire::write_envelope(MSG_STATE_ACK, &payload[..n], out)
}

/// Compose the provider key for `namespace` and `key` into `out`.
///
/// Returns `None` for an unknown namespace or a key that does not fit, which
/// the store answers as a malformed request rather than a miss.
pub fn compose_key(namespace: u8, key: &[u8], out: &mut [u8]) -> Option<usize> {
    let prefix = namespace_prefix(namespace)?;
    let total = prefix.len().checked_add(key.len())?;
    if total > out.len() || key.len() > MAX_KEY {
        return None;
    }
    // The provider keyspace is UTF-8, so a key with a byte outside the
    // portable set is refused here rather than becoming an unreadable record.
    if !key.iter().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':' | b'@' | b'+')
    }) {
        return None;
    }
    out[..prefix.len()].copy_from_slice(prefix.as_bytes());
    out[prefix.len()..total].copy_from_slice(key);
    Some(total)
}

/// Build the replay claim for a proof, as a create-only write.
///
/// A replay check that reads and then writes is not a replay check: two
/// replicas both read "unseen" and both admit. Create-if-absent is the claim
/// itself — it succeeds for the first caller and returns a conflict to every
/// other, at one linearization point, which is the property `NS_REPLAY`
/// declares and the reason it may not be served from a volatile view.
///
/// The entry expires with the proof. A proof outside its freshness window is
/// refused before it is ever offered here, so remembering it past that point
/// would be paying to store what nothing can present.
///
/// `key` is the proof's replay identifier, already in the keyspace's
/// alphabet — a base64url digest, not the raw `jti`, which is whatever the
/// client wrote.
#[must_use]
pub fn claim_replay<'a>(
    correlation: u32,
    client: u8,
    key: &'a [u8],
    expires_at: u64,
) -> StateRequest<'a> {
    StateRequest {
        correlation,
        client,
        namespace: NS_REPLAY,
        key,
        etag: &[],
        // The record's presence is the whole of its meaning, so it carries
        // no body: what a reader wants to know is whether the write
        // succeeded, not what it stored.
        value: b"{}",
        expiry_unix: expires_at,
    }
}

/// What a replay claim's reply means.
///
/// `Unavailable` is deliberately not "probably fine": a claim that could not
/// be made is a proof whose freshness nothing established, and admitting it
/// would make the ledger's absence a way to replay.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReplayClaim {
    /// This proof had not been seen. It has now been recorded.
    Fresh,
    /// Seen before, by this process or another sharing the ledger.
    Replayed,
    /// The ledger could not answer.
    Unavailable,
}

/// Read a replay claim's reply status.
#[must_use]
pub const fn replay_claim_result(status: u8) -> ReplayClaim {
    match status {
        crate::auth_wire::ST_OK => ReplayClaim::Fresh,
        crate::auth_wire::ST_CONFLICT => ReplayClaim::Replayed,
        _ => ReplayClaim::Unavailable,
    }
}

// ── Durability requirements per state class (C2) ────────────────────────
//
// Every namespace above holds a different kind of security state, and they
// do not all need the same thing from a store. Writing that down as a table
// rather than leaving each caller to decide is the point: a caller deciding
// for itself is a caller that can decide wrong, and the failure is silent —
// a credential issued against state that was never committed looks exactly
// like one issued against state that was.
//
// The adapter REFUSES a call whose requirement the backend cannot deliver.
// That is what makes a reduced fence set a refusal rather than a downgrade,
// and it is why a browser-hosted kagi verifies credentials but does not
// hold the authority's ledger.

/// The fence tags, mirroring fluxor's `sdk/fence.rs`. Ordered by strength,
/// so a requirement is "at least this".
pub mod fence {
    /// In memory. Survives nothing.
    pub const VOLATILE: u8 = 0;
    /// Committed to local storage — survives a restart, not a node loss.
    pub const LOCAL_DURABLE: u8 = 1;
    /// Acknowledged by a quorum — survives the loss of any one replica.
    pub const REPLICATED_DURABLE: u8 = 2;
    /// A consistent read of a snapshot. Says nothing about durability.
    pub const VIEW_CONSISTENT: u8 = 5;

    /// How much a fence is worth, for an "at least" comparison.
    ///
    /// `VIEW_CONSISTENT` is deliberately ranked below `LOCAL_DURABLE`: it
    /// is a statement about what a reader sees, not about what survives,
    /// and treating a consistent view as durability is precisely the
    /// conflation this ranking exists to prevent.
    #[must_use]
    pub const fn strength(tag: u8) -> u8 {
        match tag {
            VOLATILE => 0,
            VIEW_CONSISTENT => 1,
            LOCAL_DURABLE => 2,
            REPLICATED_DURABLE => 3,
            _ => 0,
        }
    }
}

/// Whether a write to `ns` must be linearized — visible to every replica
/// sharing this authority before it is acknowledged.
///
/// A single-use consume that is not linearized is not single-use: two
/// replicas each see the record unconsumed, each wins its own CAS, and the
/// grant is spent twice. That is the defect the whole state adapter exists
/// to close, so it is a property of the namespace rather than of the call.
#[must_use]
pub const fn requires_linearized(ns: u8) -> bool {
    matches!(
        ns,
        NS_ENROL_TXN
            | NS_DEVICE
            | NS_KEYPKG
            | NS_E2EE_STATE
            | NS_REPLAY
            | NS_OAUTH_CODE
            | NS_OAUTH_CLIENT
    )
}

/// The weakest fence a write to `ns` may be acknowledged under.
///
/// The reasoning per class, because the differences are the interesting
/// part and a uniform answer would be wrong in both directions:
///
/// - **`NS_REPLAY`** needs linearized visibility across the replicas
///   sharing the authority, and nothing more: a replay record is worthless
///   after the proof it guards expires, so paying for durability past that
///   lifetime buys nothing. `VIEW_CONSISTENT` is the floor.
/// - **`NS_ENROL_TXN`** is a grant that must be consumed exactly once, and
///   losing the consume re-opens it. `LOCAL_DURABLE` on a declared
///   single-node authority; a replicated deployment needs
///   `REPLICATED_DURABLE`, which is the deployment's choice to make and
///   `min_fence_replicated` states.
/// - **`NS_DEVICE`** is membership and revocation. Losing a revocation
///   un-revokes a device, so this is the class where durability is not
///   negotiable.
/// - **`NS_KEYPKG`** and **`NS_E2EE_STATE`** carry one-time material and a
///   ratchet. Losing either hands out key material twice.
/// - **`NS_ENROL_TXN`** also carries operator-minted transactions — the QR
///   ceremony writes exactly the same record `/start` does, because it IS
///   the same object with a different delivery channel. A separate namespace
///   was drafted for it and dropped: two record types with one meaning is
///   how a `/redeem` ends up able to consume the wrong one.
/// - **`NS_RATE`** is a counter. Losing it lets an attacker retry sooner,
///   which is a real cost but a bounded one, and paying for replication on
///   every increment would make the limiter the slowest thing in the path.
#[must_use]
pub const fn min_fence(ns: u8) -> u8 {
    match ns {
        NS_REPLAY => fence::VIEW_CONSISTENT,
        NS_RATE => fence::VOLATILE,
        _ => fence::LOCAL_DURABLE,
    }
}

/// The floor for `ns` in a deployment that has declared itself replicated.
///
/// Separate from [`min_fence`] because a single-node authority genuinely
/// may take `LocalDurable` — it has no other replica to lose to — and
/// forcing `ReplicatedDurable` on it would refuse every write in a
/// deployment that is correct. The deployment declares which it is; the
/// adapter does not guess.
#[must_use]
pub const fn min_fence_replicated(ns: u8) -> u8 {
    match ns {
        NS_REPLAY => fence::VIEW_CONSISTENT,
        NS_RATE => fence::VOLATILE,
        NS_DEVICE | NS_ENROL_TXN | NS_KEYPKG | NS_E2EE_STATE | NS_OAUTH_CODE | NS_OAUTH_CLIENT => {
            fence::REPLICATED_DURABLE
        }
        _ => fence::LOCAL_DURABLE,
    }
}

/// The weakest view a READ of `ns` may be decided on.
///
/// A read asks a different question from a write. A write asks what survives;
/// a read asks whether what it is looking at is a view anything can be
/// decided on. So this is not [`min_fence`] applied to the read path — a
/// provider legitimately answers a read with `VIEW_CONSISTENT` and a write
/// with `LOCAL_DURABLE`, and requiring the write's floor on the read would
/// refuse every correct read.
///
/// For a namespace whose writes must be linearized, the floor is a
/// consistent snapshot: a single-use record read from a view with no
/// linearization point is how a consumed transaction reads as unconsumed and
/// is spent twice. `VOLATILE` is what a provider reports when it has no such
/// point to offer — an object surface backed by an HTTP fetch, say — and a
/// ledger decision must never rest on one.
#[must_use]
pub const fn min_read_fence(ns: u8) -> u8 {
    if requires_linearized(ns) {
        fence::VIEW_CONSISTENT
    } else {
        fence::VOLATILE
    }
}

/// Whether a read of `ns` served under `achieved` may be answered.
///
/// Compared on [`fence::strength`], so a durable read satisfies a
/// view-consistent floor as well.
#[must_use]
pub const fn read_fence_satisfies(ns: u8, achieved: u8) -> bool {
    fence::strength(achieved) >= fence::strength(min_read_fence(ns))
}

/// Whether a write to `ns` acknowledged under `achieved` may be reported as
/// committed.
///
/// The comparison is on [`fence::strength`], so a stronger fence than
/// required always passes and `VIEW_CONSISTENT` never stands in for
/// durability.
#[must_use]
pub const fn fence_satisfies(ns: u8, achieved: u8, replicated: bool) -> bool {
    let required = if replicated {
        min_fence_replicated(ns)
    } else {
        min_fence(ns)
    };
    fence::strength(achieved) >= fence::strength(required)
}

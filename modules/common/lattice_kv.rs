//! The `lattice.data` backend for kagi's security-state adapter.
//!
//! `security_state`'s first backend is `storage.object`, which is a
//! provider call: synchronous, local, and durable only to this node's disk.
//! That is the right shape for a single-process authority and the wrong one
//! for a replicated deployment, where losing the node holding a revocation
//! un-revokes a device.
//!
//! This is the second backend. It speaks `MSG_KV_REQUEST` /
//! `MSG_KV_RESPONSE` to lattice's `lattice_data_client` over channels —
//! asynchronous, correlated, and answering with a durability class the
//! adapter checks against its per-namespace fence floor.
//!
//! # What lattice can and cannot do, and what that forced
//!
//! Three constraints shaped this, and they are constraints of the engine
//! rather than of taste:
//!
//! - **No multi-key atomicity.** etcd `Txn` is unimplemented and Redis
//!   `MULTI`/`EXEC` is not atomic and has no `WATCH`. So **every kagi
//!   security transition is expressed as a single-key CAS.** There is no
//!   operation here that touches two keys, because there is no way to make
//!   one atomic and a non-atomic one would be a transition that can half
//!   happen.
//! - **No standalone TTL.** `EXPIRE`/`TTL`/`SETEX` are absent. So a
//!   record's expiry lives INSIDE the authenticated value and is checked by
//!   kagi on read — see [`Record`]. A record that has expired is treated as
//!   absent, which is what lets a replay window and an enrolment grant age
//!   out without the store knowing what either is.
//! - **Watch and lease state is in-memory per node.** Nothing here
//!   subscribes; every read is a read.
//!
//! # Create-if-absent
//!
//! `KV_OP_CAS` takes a `witness` — the `mod_revision` the caller believes
//! the key holds. Witness `0` is "the key does not exist", which is exactly
//! `put_if_absent`. That is the same conflation `storage.object` had before
//! B3 gave it an explicit `Precondition`, and it is safe HERE only because
//! lattice's revisions start at 1: revision 0 is not a revision a live key
//! can hold, so it cannot be confused with a CAS against one.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

// Crate-sibling references, the same convention `state_wire.rs` itself
// uses for `auth_wire`: every consumer (module or harness) mounts the
// fragments as crate-level modules, and a self-`#[path]` mount here would
// load the same file twice in any consumer that also mounts them.
use crate::auth_wire;
use crate::state_wire;

/// Compute → `lattice_data_client`.
pub const MSG_KV_REQUEST: u8 = 0xC0;
/// `lattice_data_client` → compute.
pub const MSG_KV_RESPONSE: u8 = 0xC1;

/// Operations this backend uses. Three opcodes carrying four operations —
/// `CAS` with witness `0` is create-if-absent — and deliberately no more:
/// a security ledger reaching for more of lattice's surface would be one
/// whose transitions are not a single key's compare-and-swap.
///
/// Values verified against lattice `modules/common/types.rs` (`KV_OP_GET`
/// `0x01`, `KV_OP_DELETE` `0x03`, `KV_OP_CAS` `0x06`) on 2026-09-01.
pub mod op {
    pub const GET: u8 = 0x01;
    pub const DELETE: u8 = 0x03;
    /// Compare-and-swap on a `mod_revision` witness. Witness `0` creates.
    pub const CAS: u8 = 0x06;
}

/// Result codes, mirroring lattice's `KV_RESULT_*`. Verified against
/// lattice `modules/common/types.rs:455-461` on 2026-09-01.
pub mod result {
    pub const OK: u8 = 0x00;
    pub const NOT_FOUND: u8 = 0x01;
    pub const EXISTS: u8 = 0x02;
    pub const CAS_FAILED: u8 = 0x04;
    pub const UNAUTH: u8 = 0x06;
}

/// Consistency levels, mirroring lattice's `Consistency`
/// (`db_context.rs:27-36`, verified 2026-09-01).
pub mod consistency {
    /// The only level a security decision may read at.
    ///
    /// A single-use consume read at anything weaker is not single-use: two
    /// replicas each see the record unconsumed, each wins its own CAS, and
    /// the grant is spent twice. Named as a constant so no call site can
    /// quietly pick a cheaper one.
    pub const LINEARIZABLE: u8 = 0x01;
}

/// Durability classes, mirroring lattice's `Durability`
/// (`db_context.rs:42-51`, verified 2026-09-01). Ordered by strength.
///
/// These are LATTICE's three classes and they are not the same vocabulary
/// as `state_wire`'s fence tags — only `REPLICATED_DURABLE` names the same
/// thing on both sides. `to_fence` below is the whole of the translation,
/// and every statement about durability should say which vocabulary it is
/// speaking.
pub mod durability {
    /// Single-node acknowledgement. Survives nothing.
    pub const VOLATILE: u8 = 0x01;
    /// In a quorum's memory, not fsynced. Survives a node, not a power cut.
    pub const REPLICATED_VOLATILE: u8 = 0x02;
    /// Quorum durable proof observed — the only class that may be described
    /// to a caller as durable.
    pub const REPLICATED_DURABLE: u8 = 0x03;

    /// Translate to the fence tag `state_wire`'s policy compares on.
    ///
    /// `REPLICATED_VOLATILE` maps to `LOCAL_DURABLE` rather than to
    /// `REPLICATED_DURABLE`: it survives losing a replica but not losing
    /// power to the quorum, so it is worth roughly what a local fsync is
    /// worth and must not satisfy a floor that asked for replicated
    /// durability. Mapping it upward would be the silent downgrade the
    /// whole fence policy exists to prevent.
    #[must_use]
    pub const fn to_fence(d: u8) -> u8 {
        match d {
            REPLICATED_DURABLE => super::state_wire::fence::REPLICATED_DURABLE,
            REPLICATED_VOLATILE => super::state_wire::fence::LOCAL_DURABLE,
            _ => super::state_wire::fence::VOLATILE,
        }
    }
}

// Envelope layout, verified against lattice `modules/common/wire.rs` on
// 2026-09-01: the request head at `:46-48`, `KvResponseHead::LEN` at
// `:756`, and `KV_RESPONSE_FENCE_TAIL_LEN` at `:101`. The fence tail is
// `[applied_index:u64][applied_term:u64][source_id:u32][durability:u8]
// [catalog_generation:u64][commit_frontier:u64]`, which is what puts
// `durability` at offset 20.

/// Fixed part of a `MSG_KV_REQUEST` payload, before the op body.
/// `[corr:8][proto:1][tenant:4][conn:1][consistency:1][op:1][body_len:2]`.
pub const REQUEST_HEAD: usize = 8 + 1 + 4 + 1 + 1 + 1 + 2;
/// Fixed part of a `MSG_KV_RESPONSE` payload, before the body.
pub const RESPONSE_HEAD: usize = 8 + 1 + 1 + 8 + 2;
/// The trailing fence record every response carries.
pub const RESPONSE_FENCE_TAIL: usize = 8 + 8 + 4 + 1 + 8 + 8;
/// Offset of `durability` within the fence tail.
pub const FENCE_DURABILITY_AT: usize = 8 + 8 + 4;

/// Protocol of origin, mirroring lattice's `types::PROTO_INTERNAL_DATA`.
///
/// It was `0x05` here until 2026-09-01, which is lattice's
/// `PROTO_INTERNAL_WATCH`. Nothing caught it because nothing runs this
/// file: it is mounted by the host suites and by no application module,
/// no config and no runtime graph.
///
/// Be precise about what the byte does, because the wrong version of that
/// story is what let the wrong value look right. `lattice_data_anchor`
/// stamps this field, and `kv_request_router` selects the reply port from
/// it. `lattice_data_client` — the module kagi actually speaks to —
/// parses the envelope's corr/tenant/conn/consistency/op/body_len and
/// never reads byte 8 at all, so on kagi's path a wrong value is inert
/// rather than a misroute. That makes this a correctness fix, not an
/// outage fix: a constant that claims to mirror lattice's must, or the
/// next reader takes it as evidence about lattice.
pub const PROTO_INTERNAL_DATA: u8 = 0x09;

/// A stored security record: kagi's value bytes with the expiry lattice
/// cannot enforce.
///
/// `expires_at_unix` is INSIDE the value and covered by whatever
/// authenticates it, because lattice has no standalone TTL. A record past
/// its expiry reads as absent — which is how a replay window and an
/// enrolment grant age out without the store being taught what either is.
///
/// `0` means no expiry. Membership and revocation records use it: a device
/// that stopped existing because a TTL lapsed would silently re-admit
/// itself, which is the opposite of what a revocation is for.
pub struct Record<'a> {
    pub expires_at_unix: u64,
    pub value: &'a [u8],
}

impl<'a> Record<'a> {
    /// `[expires_at_unix:u64 LE][value…]`.
    pub const HEAD: usize = 8;

    #[must_use]
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let total = Self::HEAD + self.value.len();
        if out.len() < total {
            return None;
        }
        out[..8].copy_from_slice(&self.expires_at_unix.to_le_bytes());
        out[8..total].copy_from_slice(self.value);
        Some(total)
    }

    /// Decode, treating an expired record as absent.
    ///
    /// `None` for both "did not parse" and "has expired": a caller must not
    /// be able to act on an expired record, and giving it a way to tell the
    /// two apart is giving it a way to try.
    #[must_use]
    pub fn decode(bytes: &'a [u8], now_unix: u64) -> Option<Self> {
        if bytes.len() < Self::HEAD {
            return None;
        }
        let expires_at_unix = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        if expires_at_unix != 0 && now_unix >= expires_at_unix {
            return None;
        }
        Some(Self {
            expires_at_unix,
            value: &bytes[Self::HEAD..],
        })
    }
}

/// Write a `MSG_KV_REQUEST` envelope carrying `op` and `body`.
///
/// Returns the total length. The envelope is kagi's own 3-byte one, so a
/// consumer hands the payload to `channel_write_msg` rather than the whole
/// buffer — the same rule as every other kagi wire.
#[must_use]
pub fn encode_request(
    corr_id: u64,
    tenant_id: u32,
    op: u8,
    body: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let payload_len = REQUEST_HEAD + body.len();
    if out.len() < payload_len || body.len() > usize::from(u16::MAX) {
        return None;
    }
    out[0..8].copy_from_slice(&corr_id.to_le_bytes());
    out[8] = PROTO_INTERNAL_DATA;
    out[9..13].copy_from_slice(&tenant_id.to_le_bytes());
    // `conn_id` is the anchor's slot for a protocol client. This request
    // originates inside the graph, so there is no client socket and the
    // field is zero — not a real slot 0, which is why the response is
    // matched on `corr_id` and never on this.
    out[13] = 0;
    out[14] = consistency::LINEARIZABLE;
    out[15] = op;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by the u16::MAX check above"
    )]
    let bl = body.len() as u16;
    out[16..18].copy_from_slice(&bl.to_le_bytes());
    out[18..payload_len].copy_from_slice(body);
    Some(payload_len)
}

/// A decoded `MSG_KV_RESPONSE`.
pub struct Response<'a> {
    pub corr_id: u64,
    pub result: u8,
    /// MVCC position of the answer — the witness a following CAS uses.
    pub revision: u64,
    pub body: &'a [u8],
    /// The durability class the write achieved, as a `state_wire::fence`
    /// tag. Meaningless on a read, and a caller must not check a read
    /// against a durability floor.
    pub fence: u8,
}

/// Parse a `MSG_KV_RESPONSE` payload.
#[must_use]
pub fn decode_response(payload: &[u8], now_unused: u64) -> Option<Response<'_>> {
    let _ = now_unused;
    if payload.len() < RESPONSE_HEAD {
        return None;
    }
    let corr_id = u64::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
        payload[7],
    ]);
    let result = payload[9];
    let revision = u64::from_le_bytes([
        payload[10],
        payload[11],
        payload[12],
        payload[13],
        payload[14],
        payload[15],
        payload[16],
        payload[17],
    ]);
    let body_len = usize::from(u16::from_le_bytes([payload[18], payload[19]]));
    let body_at = RESPONSE_HEAD;
    if payload.len() < body_at + body_len + RESPONSE_FENCE_TAIL {
        // The fence tail is ALWAYS present. A response without one is a
        // response from something that is not lattice, and reading a
        // durability class out of whatever followed the body would be
        // reading an authorisation-relevant value out of nothing.
        return None;
    }
    let tail_at = body_at + body_len;
    let fence = durability::to_fence(payload[tail_at + FENCE_DURABILITY_AT]);
    Some(Response {
        corr_id,
        result,
        revision,
        body: &payload[body_at..body_at + body_len],
        fence,
    })
}

/// `KV_OP_GET` body: `[klen:u16 LE][key…]`.
#[must_use]
pub fn encode_get(key: &[u8], out: &mut [u8]) -> Option<usize> {
    encode_key_only(key, out)
}

/// `KV_OP_DELETE` body: `[klen:u16 LE][key…]`.
#[must_use]
pub fn encode_delete(key: &[u8], out: &mut [u8]) -> Option<usize> {
    encode_key_only(key, out)
}

fn encode_key_only(key: &[u8], out: &mut [u8]) -> Option<usize> {
    if key.is_empty() || key.len() > usize::from(u16::MAX) || out.len() < 2 + key.len() {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by the u16::MAX check above"
    )]
    let kl = key.len() as u16;
    out[0..2].copy_from_slice(&kl.to_le_bytes());
    out[2..2 + key.len()].copy_from_slice(key);
    Some(2 + key.len())
}

/// `KV_OP_CAS` body: `[klen:u16 LE][key…][witness:u64 LE][vlen:u32 LE][value…]`.
///
/// `witness` is the `mod_revision` the caller believes the key holds; `0`
/// means "must not exist". Safe only because lattice revisions start at 1,
/// so `0` is not a revision a live key can hold — the same conflation
/// `storage.object` had before B3, without the ambiguity that made it a bug
/// there.
#[must_use]
pub fn encode_cas(key: &[u8], witness: u64, value: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = 2 + key.len() + 8 + 4 + value.len();
    if key.is_empty() || key.len() > usize::from(u16::MAX) || out.len() < total {
        return None;
    }
    if value.len() > u32::MAX as usize {
        return None;
    }
    let mut p = 0usize;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by the u16::MAX check above"
    )]
    let kl = key.len() as u16;
    out[p..p + 2].copy_from_slice(&kl.to_le_bytes());
    p += 2;
    out[p..p + key.len()].copy_from_slice(key);
    p += key.len();
    out[p..p + 8].copy_from_slice(&witness.to_le_bytes());
    p += 8;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by the u32::MAX check above"
    )]
    let vl = value.len() as u32;
    out[p..p + 4].copy_from_slice(&vl.to_le_bytes());
    p += 4;
    out[p..p + value.len()].copy_from_slice(value);
    Some(total)
}

/// Map a lattice result to the kagi status a caller sees.
///
/// `CAS_FAILED` and `EXISTS` both become `ST_CONFLICT`: from the caller's
/// side they are the same fact — you did not win — and the distinction
/// between "somebody created it first" and "somebody changed it under you"
/// only matters to a retry policy this adapter does not own.
///
/// Everything unrecognised becomes `ST_UNAVAILABLE` rather than a guess. A
/// result nobody here understands must not be read as success, and reading
/// it as `NOT_FOUND` would be worse still: "the ledger says no such device"
/// is the answer that admits a credential.
#[must_use]
pub const fn to_status(result: u8) -> u8 {
    match result {
        result::OK => auth_wire::ST_OK,
        result::NOT_FOUND => auth_wire::ST_NOT_FOUND,
        result::EXISTS | result::CAS_FAILED => auth_wire::ST_CONFLICT,
        _ => auth_wire::ST_UNAVAILABLE,
    }
}

//! The storage-key service: the operations of the grant and
//! attachment-envelope profile, over the security-state ledger and the three
//! recovery custodians.
//!
//! Sans-IO. The service is a state machine fed messages and a clock; what it
//! says goes out through [`Host::send`]. The module moves bytes between its
//! ports and this, and a host suite drives the same code against a modelled
//! ledger and modelled custodians — so the decisions under test are the ones
//! a device runs.
//!
//! # State
//!
//! Every durable fact is a ledger record, in five namespaces:
//!
//! | Namespace | Key | Record |
//! | --- | --- | --- |
//! | `NS_STORAGE_GRANT` | resource | the resource's grant: device policy and epochs |
//! | `NS_STORAGE_SET` | resource, epoch | the creation authorisation, then the recorded recovery set |
//! | `NS_STORAGE_TICKET` | resource, ticket | a one-time recovery authorisation |
//! | `NS_STORAGE_AUDIT` | resource, time, id | one entry per decision |
//! | `NS_STORAGE_ATTACHMENT` | resource, attachment id | the attachment's latest renewal |
//!
//! Release and renewal anti-replay ids are claimed create-if-absent in
//! `NS_REPLAY`, the namespace every other Kagi proof claims its freshness
//! in. Challenges are
//! held here, in memory: a challenge is spent at the first request that
//! names it, whatever that request's fate, and a restart forgets them all,
//! which costs a device one round trip and nothing else.
//!
//! # Ordering
//!
//! A release is decided in full — grant, directory, ticket, recovery set,
//! proof and custody evidence — before the anti-replay claim, which is the
//! last check and the first durable step. The two envelopes are released to
//! the requester only after the audit entry naming them is written: a
//! release the audit trail does not hold is not one this service made.
//!
//! A renewal ([`sk::op::RENEW_ATTACHMENT`]) runs the same way without the
//! custodians: challenge spent, grant, directory record and the
//! attachment's renewal chain read, decided in full
//! ([`sk::decide_renewal`]), anti-replay id claimed, the chain advanced to
//! the new renewal by compare-and-swap, audited, answered. No envelope is
//! issued and no share moves.
//!
//! An erasure ([`sk::op::ERASE`]) replaces the grant with the erasure record
//! first, by compare-and-swap, so from that write on nothing is issued for
//! the resource; then deletes every epoch's recovery set; then orders all
//! three custodians to refuse the resource; and only when all three confirm
//! is it audited as allowed and answered. A retry of an erasure that stopped
//! part-way finds the erasure record and runs the rest again.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::auth_wire;
use crate::key_vault::share;
use crate::state_wire;
use crate::storage_key::{self as sk, Binding, Record, Refusal};

// ── Wire ────────────────────────────────────────────────────────────────

/// Message types. `0x80`+: `state_wire` holds `0x60`–`0x71`, the lattice
/// adapter `0xC0`+.
pub mod msg {
    /// `[corr u32][op u8][resource kind u8][resource 16][body]`.
    pub const REQUEST: u8 = 0x80;
    /// `[corr u32][op u8][status u8][refusal u8][audited u8]
    ///  [record f16][bundle f16][extra f16]`.
    pub const REPLY: u8 = 0x81;
    /// To custodians: `[corr u32][custodian u8][record f16][recipient f8]
    /// [envelope f16]`.
    pub const REWRAP_ORDER: u8 = 0x82;
    /// From custodians: `[corr u32][custodian u8][status u8][refusal u8]
    /// [envelope f16]`.
    pub const REWRAP_RESULT: u8 = 0x83;
    /// To one custodian: `[corr u32][custodian u8]`.
    pub const CUSTODIAN_KEY_REQ: u8 = 0x84;
    /// `[corr u32][custodian u8][status u8][public f8]`.
    pub const CUSTODIAN_KEY: u8 = 0x85;
    /// To custodians: `[corr u32][custodian u8][erasure record f16]`.
    pub const ERASE_ORDER: u8 = 0x86;
    /// From custodians: as [`REWRAP_RESULT`], the envelope always empty.
    pub const ERASE_RESULT: u8 = 0x87;
}

/// Reply status.
pub const STATUS_OK: u8 = 0;
pub const STATUS_REFUSED: u8 = 1;

/// This service's client id on the ledger's shared reply port.
pub const STATE_CLIENT: u8 = 12;

/// Concurrent operations.
pub const MAX_OPS: usize = 4;
/// Outstanding challenges.
pub const MAX_CHALLENGES: usize = 16;
/// Longest request body this service holds: a renewal carries an attach
/// body and the whole release it renews, two envelopes included.
pub const MAX_REQUEST: usize = 2048;
/// How long any one stage may wait on the ledger or a custodian.
pub const STAGE_TIMEOUT_MS: u64 = 10_000;
/// Longest handle lifetime a grant may allow: a week.
pub const MAX_LIFETIME_SECS: u32 = sk::MAX_LIFETIME_SECS;
/// Longest a recovery ticket stays usable: an hour.
pub const MAX_TICKET_SECS: u32 = 3600;
/// Largest frame this service writes: a reply carrying a record and a
/// bundle, or a ledger write carrying a record.
pub const MAX_FRAME: usize = 3 + 8 + 2 + sk::MAX_RECORD + 2 + sk::BUNDLE_LEN + 2 + 64;
/// Longest ledger key this service composes.
const MAX_KEY: usize = 96;

/// Where a frame goes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Port {
    /// The security-state ledger.
    Ledger,
    /// The custodians' shared order port.
    Custodian,
    /// The requester.
    Reply,
}

/// What the service needs from wherever it runs.
///
/// Generic, never `dyn`: a trait object's vtable is a table of absolute
/// addresses, which a position-independent module cannot hold.
pub trait Host {
    /// Wall-clock Unix milliseconds. 0 when no trustworthy clock exists.
    fn now_ms(&mut self) -> u64;
    /// Fill `out` from the CSPRNG.
    fn random(&mut self, out: &mut [u8]) -> bool;
    fn sha256(&self) -> sk::Sha256Fn;
    fn verify(&self) -> sk::VerifyFn;
    /// The issuer key's credential suite, 0 when no key is loaded.
    fn issuer_suite(&self) -> u16;
    fn issuer_public(&self) -> &[u8];
    /// Sign `message` with the issuer key, per its suite's convention.
    fn sign(&mut self, message: &[u8], signature: &mut [u8]) -> Option<usize>;
    /// Read a directory record: is the device active, in `tenant`, and is
    /// `public` the key it enrolled.
    fn device_facts(
        &self,
        record: &[u8],
        tenant: &[u8],
        suite: u16,
        public: &[u8],
    ) -> sk::DeviceFacts;
    /// Write one whole `[type][len][payload]` frame to `port`.
    fn send(&mut self, port: Port, frame: &[u8]) -> bool;
}

/// Counters, one per outcome an operator asks about.
#[derive(Clone, Copy)]
pub struct Stats {
    pub allowed: u32,
    pub refused: u32,
    pub released: u32,
    pub replayed: u32,
    pub audit_failed: u32,
    pub busy: u32,
}

impl Stats {
    const ZERO: Self = Self {
        allowed: 0,
        refused: 0,
        released: 0,
        replayed: 0,
        audit_failed: 0,
        busy: 0,
    };
}

// ── Stages ──────────────────────────────────────────────────────────────

mod stage {
    pub const GET_GRANT: u8 = 1;
    pub const GET_DEVICE: u8 = 2;
    pub const GET_TICKET: u8 = 3;
    pub const GET_SET: u8 = 4;
    pub const CLAIM_REPLAY: u8 = 5;
    pub const CONSUME_TICKET: u8 = 6;
    pub const CUSTODIANS: u8 = 7;
    pub const PUT_GRANT: u8 = 8;
    pub const PUT_SET: u8 = 9;
    pub const CAS_SET: u8 = 10;
    pub const CAS_GRANT: u8 = 11;
    pub const PUT_TICKET: u8 = 12;
    pub const GET_OLD_SET: u8 = 13;
    pub const DELETE_SET: u8 = 14;
    pub const WRITE_AUDIT: u8 = 15;
    pub const GET_CHAIN: u8 = 16;
    pub const PUT_CHAIN: u8 = 17;
    pub const GET_CURRENT_SET: u8 = 18;
    pub const ERASE_GET_SET: u8 = 19;
    pub const ERASE_DELETE_SET: u8 = 20;
    pub const ERASE_CUSTODIANS: u8 = 21;

    /// Whether `stage` waits on custodians rather than the ledger.
    pub const fn custodians(stage: u8) -> bool {
        matches!(stage, CUSTODIANS | ERASE_CUSTODIANS)
    }
}

/// One challenge this service issued.
#[derive(Clone, Copy)]
struct Challenge {
    nonce: [u8; 32],
    resource_kind: u8,
    resource: [u8; 16],
    device: [u8; 32],
    expires_ms: u64,
}

impl Challenge {
    const fn empty() -> Self {
        Self {
            nonce: [0; 32],
            resource_kind: 0,
            resource: [0; 16],
            device: [0; 32],
            expires_ms: 0,
        }
    }
}

/// A held record and the etag it was read at.
struct Held {
    bytes: [u8; sk::MAX_RECORD],
    len: u16,
    etag: [u8; state_wire::MAX_ETAG],
    etag_len: u8,
}

impl Held {
    const fn empty() -> Self {
        Self {
            bytes: [0; sk::MAX_RECORD],
            len: 0,
            etag: [0; state_wire::MAX_ETAG],
            etag_len: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
        self.etag_len = 0;
    }

    fn bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    fn etag(&self) -> &[u8] {
        self.etag.get(..usize::from(self.etag_len)).unwrap_or(&[])
    }

    fn store(&mut self, value: &[u8], etag: &[u8]) -> Result<(), Refusal> {
        self.bytes
            .get_mut(..value.len())
            .ok_or(Refusal::Malformed)?
            .copy_from_slice(value);
        self.etag
            .get_mut(..etag.len())
            .ok_or(Refusal::Malformed)?
            .copy_from_slice(etag);
        self.len = u16::try_from(value.len()).map_err(|_| Refusal::Malformed)?;
        self.etag_len = u8::try_from(etag.len()).map_err(|_| Refusal::Malformed)?;
        Ok(())
    }

    fn record(&self) -> Result<Record<'_>, Refusal> {
        Record::parse(self.bytes())
    }
}

/// A record an operation writes.
struct Built {
    bytes: [u8; sk::MAX_RECORD],
    len: u16,
}

impl Built {
    const fn empty() -> Self {
        Self {
            bytes: [0; sk::MAX_RECORD],
            len: 0,
        }
    }

    fn bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// A renewal chain's head as the ledger holds it: the digest of the latest
/// renewal and the etag it was read at. Only the digest is needed — the
/// record presented is verified, and the head decides only whether it is the
/// latest.
struct ChainHead {
    present: bool,
    digest: [u8; 32],
    etag: [u8; state_wire::MAX_ETAG],
    etag_len: u8,
}

impl ChainHead {
    const fn empty() -> Self {
        Self {
            present: false,
            digest: [0; 32],
            etag: [0; state_wire::MAX_ETAG],
            etag_len: 0,
        }
    }

    fn etag(&self) -> &[u8] {
        self.etag.get(..usize::from(self.etag_len)).unwrap_or(&[])
    }

    fn chain(&self) -> sk::Chain {
        if self.present {
            sk::Chain::Head(self.digest)
        } else {
            sk::Chain::Unrenewed
        }
    }
}

/// One operation in flight.
struct Op {
    live: bool,
    code: u8,
    stage: u8,
    /// The requester's correlation id.
    corr: u32,
    /// This operation's id towards the ledger and custodians.
    icorr: u32,
    deadline_ms: u64,
    req: [u8; MAX_REQUEST],
    req_len: u16,
    grant: Held,
    set: Held,
    ticket: Held,
    /// A renewal's chain head.
    chain: ChainHead,
    facts: sk::DeviceFacts,
    /// The record the reply carries.
    out: Built,
    /// A second record the operation writes: a new grant beside a creation,
    /// a consumed ticket.
    aux: Built,
    /// A release's authorisation.
    auth: Binding,
    envs: [[u8; sk::ENVELOPE_LEN]; 2],
    env_count: u8,
    asked: u8,
    answered: u8,
    /// An erasure's sweep: the next epoch whose set it deletes.
    cursor: u32,
    audit: sk::Audit,
    refusal: Option<Refusal>,
}

const NO_FACTS: sk::DeviceFacts = sk::DeviceFacts {
    active: false,
    in_tenant: false,
    key_bound: false,
    assurance: 0,
};

impl Op {
    const fn empty() -> Self {
        Self {
            live: false,
            code: 0,
            stage: 0,
            corr: 0,
            icorr: 0,
            deadline_ms: 0,
            req: [0; MAX_REQUEST],
            req_len: 0,
            grant: Held::empty(),
            set: Held::empty(),
            ticket: Held::empty(),
            chain: ChainHead::empty(),
            facts: NO_FACTS,
            out: Built::empty(),
            aux: Built::empty(),
            auth: Binding::empty(),
            envs: [[0; sk::ENVELOPE_LEN]; 2],
            env_count: 0,
            asked: 0,
            answered: 0,
            cursor: 0,
            audit: sk::Audit::new(0, 0, [0; 16], 0),
            refusal: None,
        }
    }

    fn reset(&mut self) {
        self.live = false;
        self.code = 0;
        self.stage = 0;
        self.corr = 0;
        self.icorr = 0;
        self.deadline_ms = 0;
        // A request and a released share envelope are not left in a free
        // slot.
        self.req.fill(0);
        self.req_len = 0;
        self.grant.clear();
        self.set.clear();
        self.ticket.clear();
        self.chain = ChainHead::empty();
        self.facts = NO_FACTS;
        self.out.len = 0;
        self.aux.len = 0;
        self.auth = Binding::empty();
        for e in &mut self.envs {
            e.fill(0);
        }
        self.env_count = 0;
        self.asked = 0;
        self.answered = 0;
        self.cursor = 0;
        self.audit = sk::Audit::new(0, 0, [0; 16], 0);
        self.refusal = None;
    }

    fn body(&self) -> &[u8] {
        self.req.get(..usize::from(self.req_len)).unwrap_or(&[])
    }

    fn release_kind(&self) -> u8 {
        if self.code == sk::op::RECOVER {
            sk::kind::RECOVERY
        } else {
            sk::kind::ATTACHMENT
        }
    }

    /// Whether the operation is decided on a device's proof: an attach, a
    /// recovery or a renewal.
    fn proven(&self) -> bool {
        matches!(
            self.code,
            sk::op::ATTACH | sk::op::RECOVER | sk::op::RENEW_ATTACHMENT
        )
    }

    fn attach(&self) -> Result<sk::AttachRequest<'_>, Refusal> {
        if self.code == sk::op::RENEW_ATTACHMENT {
            return read_renew_body(self.body()).map(|(req, _)| req);
        }
        read_attach_body(self.release_kind(), self.body())
    }
}

/// Deployment configuration.
struct Config {
    issuer: [u8; sk::MAX_ID],
    issuer_len: u8,
}

impl Config {
    fn issuer(&self) -> &[u8] {
        self.issuer
            .get(..usize::from(self.issuer_len))
            .unwrap_or(&[])
    }
}

/// The service.
pub struct Service {
    cfg: Config,
    next_corr: u32,
    challenges: [Challenge; MAX_CHALLENGES],
    ops: [Op; MAX_OPS],
    frame: [u8; MAX_FRAME],
    pub stats: Stats,
}

/// What every stage function reaches besides its own operation.
struct Cx<'a, H: Host> {
    host: &'a mut H,
    cfg: &'a Config,
    frame: &'a mut [u8; MAX_FRAME],
    stats: &'a mut Stats,
}

// ── Request bodies ──────────────────────────────────────────────────────

/// A request's common head.
struct Head<'a> {
    resource_kind: u8,
    resource: [u8; 16],
    rest: sk::Reader<'a>,
}

fn head(body: &[u8]) -> Result<Head<'_>, Refusal> {
    let mut r = sk::Reader::new(body);
    let resource_kind = r.u8().ok_or(Refusal::Malformed)?;
    let resource = r.arr::<16>().ok_or(Refusal::Malformed)?;
    if !sk::resource::valid(resource_kind) {
        return Err(Refusal::Malformed);
    }
    Ok(Head {
        resource_kind,
        resource,
        rest: r,
    })
}

/// The policy a create or grant carries:
/// `[custody u8][min tier u8][min assurance u8][lifetime u32]`.
#[derive(Clone, Copy)]
struct PolicyFields {
    custody: u8,
    min_tier: u8,
    min_assurance: u8,
    lifetime_secs: u32,
}

const POLICY_LEN: usize = 7;

fn policy_fields(r: &mut sk::Reader<'_>) -> Result<PolicyFields, Refusal> {
    let p = PolicyFields {
        custody: r.u8().ok_or(Refusal::Malformed)?,
        min_tier: r.u8().ok_or(Refusal::Malformed)?,
        min_assurance: r.u8().ok_or(Refusal::Malformed)?,
        lifetime_secs: r.u32().ok_or(Refusal::Malformed)?,
    };
    let custody_ok = match p.custody {
        sk::custody::POSSESSION_BOUND => p.min_tier <= sk::tier::DEVICE_HW,
        // A hardware-bound policy whose floor a software vault meets would
        // be a hardware claim nothing can prove.
        sk::custody::HARDWARE_BOUND => {
            p.min_tier >= sk::tier::PROCESS_HW && p.min_tier <= sk::tier::DEVICE_HW
        }
        _ => false,
    };
    if !custody_ok || p.lifetime_secs == 0 || p.lifetime_secs > MAX_LIFETIME_SECS {
        return Err(Refusal::Malformed);
    }
    Ok(p)
}

fn custodian_keys<'a>(r: &mut sk::Reader<'a>) -> Result<[&'a [u8]; 3], Refusal> {
    let a = r.take(sk::PUBLIC_LEN).ok_or(Refusal::Malformed)?;
    let b = r.take(sk::PUBLIC_LEN).ok_or(Refusal::Malformed)?;
    let c = r.take(sk::PUBLIC_LEN).ok_or(Refusal::Malformed)?;
    let keys = [a, b, c];
    // Three custodians means three keys: one key named twice would put two
    // shares in one custodian's hands, and that custodian alone would hold
    // the volume.
    if keys.iter().any(|k| k.first() != Some(&0x04)) || a == b || b == c || a == c {
        return Err(Refusal::Malformed);
    }
    Ok(keys)
}

fn id_field<'a>(r: &mut sk::Reader<'a>) -> Result<&'a [u8], Refusal> {
    let v = r.f8().ok_or(Refusal::Malformed)?;
    if v.is_empty() || v.len() > sk::MAX_ID {
        return Err(Refusal::Malformed);
    }
    Ok(v)
}

/// The last field of every control request: who asked.
fn actor(r: &mut sk::Reader<'_>) -> Result<(), Refusal> {
    id_field(r)?;
    if r.remaining() != 0 {
        return Err(Refusal::Malformed);
    }
    Ok(())
}

/// Encode an attach or recover body for `req`: what a node sends.
pub fn write_attach_body(req: &sk::AttachRequest<'_>, out: &mut [u8]) -> Option<usize> {
    let mut w = sk::Writer::new(out);
    w.u8(req.resource_kind)?;
    w.bytes(&req.resource)?;
    w.u32(req.epoch)?;
    w.u64(req.fence)?;
    w.u32(req.lifetime_secs)?;
    w.u64(req.expiry_ms)?;
    w.bytes(&req.anti_replay)?;
    w.bytes(&req.challenge)?;
    w.bytes(&req.ticket)?;
    w.f8(req.recipient)?;
    w.f8(req.device)?;
    w.u16(req.device_suite)?;
    w.f8(req.device_public)?;
    w.f8(req.proof)?;
    w.f16(req.evidence)?;
    Some(w.len())
}

/// Read an attach or recover body.
pub fn read_attach_body(kind: u8, body: &[u8]) -> Result<sk::AttachRequest<'_>, Refusal> {
    let mut r = sk::Reader::new(body);
    let req = read_attach_fields(kind, &mut r)?;
    if r.remaining() != 0 {
        return Err(Refusal::Malformed);
    }
    Ok(req)
}

/// Encode a renewal body: the attach fields under kind
/// [`sk::kind::RENEWAL`], `ticket` carrying the attachment id, then the
/// record renewed — the release, or the latest renewal — as `f16`.
pub fn write_renew_body(
    req: &sk::AttachRequest<'_>,
    attachment: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let n = write_attach_body(req, out)?;
    let mut w = sk::Writer::new(out.get_mut(n..)?);
    w.f16(attachment)?;
    n.checked_add(w.len())
}

/// Read a renewal body: the request and the record it renews.
pub fn read_renew_body(body: &[u8]) -> Result<(sk::AttachRequest<'_>, &[u8]), Refusal> {
    let mut r = sk::Reader::new(body);
    let req = read_attach_fields(sk::kind::RENEWAL, &mut r)?;
    let attachment = r.f16().ok_or(Refusal::Malformed)?;
    if r.remaining() != 0 || attachment.is_empty() {
        return Err(Refusal::Malformed);
    }
    Ok((req, attachment))
}

fn read_attach_fields<'a>(
    kind: u8,
    r: &mut sk::Reader<'a>,
) -> Result<sk::AttachRequest<'a>, Refusal> {
    let m = Refusal::Malformed;
    let req = sk::AttachRequest {
        kind,
        resource_kind: r.u8().ok_or(m)?,
        resource: r.arr().ok_or(m)?,
        epoch: r.u32().ok_or(m)?,
        fence: r.u64().ok_or(m)?,
        lifetime_secs: r.u32().ok_or(m)?,
        expiry_ms: r.u64().ok_or(m)?,
        anti_replay: r.arr().ok_or(m)?,
        challenge: r.arr().ok_or(m)?,
        ticket: r.arr().ok_or(m)?,
        recipient: r.f8().ok_or(m)?,
        device: r.f8().ok_or(m)?,
        device_suite: r.u16().ok_or(m)?,
        device_public: r.f8().ok_or(m)?,
        proof: r.f8().ok_or(m)?,
        evidence: r.f16().ok_or(m)?,
    };
    if !sk::resource::valid(req.resource_kind)
        || req.device.is_empty()
        || req.device.len() > sk::MAX_ID
    {
        return Err(m);
    }
    Ok(req)
}

/// Encode a request frame.
pub fn write_request(corr: u32, op: u8, body: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut payload = [0u8; 5 + MAX_REQUEST];
    let mut w = sk::Writer::new(&mut payload);
    w.u32(corr)?;
    w.u8(op)?;
    w.bytes(body)?;
    let n = w.len();
    auth_wire::write_envelope(msg::REQUEST, payload.get(..n)?, out).ok()
}

/// A decoded reply.
pub struct Reply<'a> {
    pub corr: u32,
    pub op: u8,
    pub status: u8,
    pub refusal: u8,
    pub audited: bool,
    pub record: &'a [u8],
    pub bundle: &'a [u8],
    pub extra: &'a [u8],
}

pub fn read_reply(payload: &[u8]) -> Option<Reply<'_>> {
    let mut r = sk::Reader::new(payload);
    let reply = Reply {
        corr: r.u32()?,
        op: r.u8()?,
        status: r.u8()?,
        refusal: r.u8()?,
        audited: r.u8()? != 0,
        record: r.f16()?,
        bundle: r.f16()?,
        extra: r.f16()?,
    };
    (r.remaining() == 0).then_some(reply)
}

/// A decoded rewrap order.
pub struct Order<'a> {
    pub corr: u32,
    pub custodian: u8,
    pub record: &'a [u8],
    pub recipient: &'a [u8],
    pub envelope: &'a [u8],
}

pub fn read_order(payload: &[u8]) -> Option<Order<'_>> {
    let mut r = sk::Reader::new(payload);
    let o = Order {
        corr: r.u32()?,
        custodian: r.u8()?,
        record: r.f16()?,
        recipient: r.f8()?,
        envelope: r.f16()?,
    };
    (r.remaining() == 0).then_some(o)
}

/// Encode a custodian's rewrap result frame.
pub fn write_result(
    corr: u32,
    custodian: u8,
    refusal: Option<Refusal>,
    envelope: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut payload = [0u8; 16 + sk::ENVELOPE_LEN];
    let mut w = sk::Writer::new(&mut payload);
    w.u32(corr)?;
    w.u8(custodian)?;
    w.u8(if refusal.is_some() {
        STATUS_REFUSED
    } else {
        STATUS_OK
    })?;
    w.u8(refusal.map_or(0, Refusal::code))?;
    w.f16(envelope)?;
    let n = w.len();
    auth_wire::write_envelope(msg::REWRAP_RESULT, payload.get(..n)?, out).ok()
}

/// A decoded erase order.
pub struct EraseOrder<'a> {
    pub corr: u32,
    pub custodian: u8,
    pub record: &'a [u8],
}

pub fn read_erase_order(payload: &[u8]) -> Option<EraseOrder<'_>> {
    let mut r = sk::Reader::new(payload);
    let o = EraseOrder {
        corr: r.u32()?,
        custodian: r.u8()?,
        record: r.f16()?,
    };
    (r.remaining() == 0).then_some(o)
}

/// Encode a custodian's answer to an erase order.
pub fn write_erase_result(
    corr: u32,
    custodian: u8,
    refusal: Option<Refusal>,
    out: &mut [u8],
) -> Option<usize> {
    let mut payload = [0u8; 16];
    let mut w = sk::Writer::new(&mut payload);
    w.u32(corr)?;
    w.u8(custodian)?;
    w.u8(if refusal.is_some() {
        STATUS_REFUSED
    } else {
        STATUS_OK
    })?;
    w.u8(refusal.map_or(0, Refusal::code))?;
    w.f16(&[])?;
    let n = w.len();
    auth_wire::write_envelope(msg::ERASE_RESULT, payload.get(..n)?, out).ok()
}

// ── The service ─────────────────────────────────────────────────────────

impl Service {
    /// A service by value, for a host that has a heap to box it on. A
    /// module initialises its state in place with [`Service::init`].
    #[must_use]
    pub const fn new() -> Self {
        const OP: Op = Op::empty();
        Self {
            cfg: Config {
                issuer: [0; sk::MAX_ID],
                issuer_len: 0,
            },
            next_corr: 1,
            challenges: [Challenge::empty(); MAX_CHALLENGES],
            ops: [OP; MAX_OPS],
            frame: [0; MAX_FRAME],
            stats: Stats::ZERO,
        }
    }

    /// Initialise in place. A service is large; constructing one by value
    /// and moving it would stage the whole of it on the stack.
    pub fn init(&mut self, issuer: &[u8]) {
        let n = issuer.len().min(sk::MAX_ID);
        self.cfg.issuer.fill(0);
        if let (Some(dst), Some(src)) = (self.cfg.issuer.get_mut(..n), issuer.get(..n)) {
            dst.copy_from_slice(src);
        }
        self.cfg.issuer_len = u8::try_from(n).unwrap_or(0);
        self.next_corr = 1;
        for c in &mut self.challenges {
            *c = Challenge::empty();
        }
        for op in &mut self.ops {
            op.reset();
        }
        self.stats = Stats::ZERO;
    }

    /// Whether a request could start now.
    #[must_use]
    pub fn has_room(&self) -> bool {
        self.ops.iter().any(|o| !o.live)
    }

    /// Operations in flight.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.ops.iter().filter(|o| o.live).count()
    }

    /// A `REQUEST` payload arrived.
    pub fn on_request<H: Host>(&mut self, host: &mut H, payload: &[u8]) {
        let Self {
            cfg,
            next_corr,
            challenges,
            ops,
            frame,
            stats,
        } = self;
        let mut cx = Cx {
            host,
            cfg,
            frame,
            stats,
        };
        let mut r = sk::Reader::new(payload);
        let (Some(corr), Some(code)) = (r.u32(), r.u8()) else {
            return;
        };
        let body = payload.get(r.position()..).unwrap_or(&[]);
        let now = cx.host.now_ms();
        if code == sk::op::CHALLENGE {
            match issue_challenge(&mut cx, challenges, body, now) {
                Ok(extra) => send_reply(&mut cx, corr, code, None, true, &[], &[], &extra),
                Err(refusal) => refuse_now(&mut cx, corr, code, refusal),
            }
            return;
        }
        let refusal = if cx.host.issuer_suite() == 0 {
            Some(Refusal::NoIssuerKey)
        } else if now == 0 {
            // No clock, no expiry: every decision here is dated.
            Some(Refusal::LedgerUnavailable)
        } else if body.len() > MAX_REQUEST {
            Some(Refusal::Malformed)
        } else {
            None
        };
        if let Some(refusal) = refusal {
            refuse_now(&mut cx, corr, code, refusal);
            return;
        }
        let Some(op) = ops.iter_mut().find(|o| !o.live) else {
            cx.stats.busy = cx.stats.busy.saturating_add(1);
            refuse_now(&mut cx, corr, code, Refusal::Busy);
            return;
        };
        op.reset();
        op.live = true;
        op.code = code;
        op.corr = corr;
        op.icorr = *next_corr;
        *next_corr = next_corr.wrapping_add(1).max(1);
        op.req[..body.len()].copy_from_slice(body);
        op.req_len = u16::try_from(body.len()).unwrap_or(0);
        let (rk, res) = head(body).map_or((0, [0; 16]), |h| (h.resource_kind, h.resource));
        op.audit = sk::Audit::new(code, rk, res, now);
        if let Err(refusal) = start(&mut cx, challenges, op, now) {
            finish(&mut cx, op, Err(refusal));
        }
    }

    /// A ledger reply arrived.
    pub fn on_ledger<H: Host>(&mut self, host: &mut H, msg_type: u8, payload: &[u8]) {
        if msg_type != state_wire::MSG_STATE_VALUE && msg_type != state_wire::MSG_STATE_ACK {
            return;
        }
        let Ok(reply) = state_wire::StateReply::decode(msg_type, payload) else {
            return;
        };
        if reply.client != STATE_CLIENT {
            return;
        }
        let Self {
            cfg,
            ops,
            frame,
            stats,
            ..
        } = self;
        let Some(op) = ops
            .iter_mut()
            .find(|o| o.live && o.icorr == reply.correlation && !stage::custodians(o.stage))
        else {
            return;
        };
        let mut cx = Cx {
            host,
            cfg,
            frame,
            stats,
        };
        let now = cx.host.now_ms();
        if let Err(refusal) = advance(&mut cx, op, reply.status, reply.etag, reply.value, now) {
            finish(&mut cx, op, Err(refusal));
        }
    }

    /// A custodian's result arrived.
    pub fn on_custodian<H: Host>(&mut self, host: &mut H, payload: &[u8]) {
        let mut r = sk::Reader::new(payload);
        let (Some(corr), Some(custodian), Some(status), Some(_refusal), Some(env)) =
            (r.u32(), r.u8(), r.u8(), r.u8(), r.f16())
        else {
            return;
        };
        let Self {
            cfg,
            ops,
            frame,
            stats,
            ..
        } = self;
        let Some(op) = ops
            .iter_mut()
            .find(|o| o.live && o.icorr == corr && stage::custodians(o.stage))
        else {
            return;
        };
        let mut cx = Cx {
            host,
            cfg,
            frame,
            stats,
        };
        let now = cx.host.now_ms();
        let outcome = if op.stage == stage::ERASE_CUSTODIANS {
            erase_result(&mut cx, op, custodian, status)
        } else {
            custodian_result(&mut cx, op, custodian, status, env, now)
        };
        if let Err(refusal) = outcome {
            finish(&mut cx, op, Err(refusal));
        }
    }

    /// Expire whatever has waited too long.
    pub fn tick<H: Host>(&mut self, host: &mut H) {
        let Self {
            cfg,
            challenges,
            ops,
            frame,
            stats,
            ..
        } = self;
        let mut cx = Cx {
            host,
            cfg,
            frame,
            stats,
        };
        let now = cx.host.now_ms();
        for c in challenges.iter_mut() {
            if c.expires_ms != 0 && now >= c.expires_ms {
                *c = Challenge::empty();
            }
        }
        for op in ops.iter_mut() {
            if !op.live || now < op.deadline_ms {
                continue;
            }
            if op.stage == stage::WRITE_AUDIT {
                // The audit write did not answer: the decision stands
                // unrecorded, and a release is withheld.
                cx.stats.audit_failed = cx.stats.audit_failed.saturating_add(1);
                reply(&mut cx, op, false);
                op.reset();
                continue;
            }
            let refusal = if stage::custodians(op.stage) {
                Refusal::CustodianRefused
            } else {
                Refusal::LedgerUnavailable
            };
            finish(&mut cx, op, Err(refusal));
        }
    }
}

// ── Challenges ──────────────────────────────────────────────────────────

/// Issue a challenge: `[device f8]` after the head. Answers
/// `challenge(32) ‖ expiry ms(8)`.
fn issue_challenge<H: Host>(
    cx: &mut Cx<'_, H>,
    challenges: &mut [Challenge; MAX_CHALLENGES],
    body: &[u8],
    now: u64,
) -> Result<[u8; 40], Refusal> {
    let mut h = head(body)?;
    let device = id_field(&mut h.rest)?;
    if h.rest.remaining() != 0 {
        return Err(Refusal::Malformed);
    }
    if now == 0 {
        return Err(Refusal::LedgerUnavailable);
    }
    let device = sk::thumbprint(cx.host.sha256(), device);
    // A full table evicts the entry closest to expiry: a flood of challenge
    // requests can make a slow device ask again, never make a stale
    // challenge last longer.
    let mut slot = 0usize;
    let mut soonest = u64::MAX;
    for (i, c) in challenges.iter().enumerate() {
        if c.expires_ms == 0 {
            slot = i;
            break;
        }
        if c.expires_ms < soonest {
            soonest = c.expires_ms;
            slot = i;
        }
    }
    let mut nonce = [0u8; 32];
    if !cx.host.random(&mut nonce) {
        return Err(Refusal::Busy);
    }
    let expires_ms = now.saturating_add(sk::CHALLENGE_TTL_MS);
    if let Some(c) = challenges.get_mut(slot) {
        *c = Challenge {
            nonce,
            resource_kind: h.resource_kind,
            resource: h.resource,
            device,
            expires_ms,
        };
    }
    let mut extra = [0u8; 40];
    extra[..32].copy_from_slice(&nonce);
    extra[32..].copy_from_slice(&expires_ms.to_le_bytes());
    Ok(extra)
}

/// Spend the challenge a release names. It is removed whether or not the
/// rest of the request holds.
fn spend_challenge(
    challenges: &mut [Challenge; MAX_CHALLENGES],
    sha: sk::Sha256Fn,
    req: &sk::AttachRequest<'_>,
    now: u64,
) -> Result<(), Refusal> {
    let device = sk::thumbprint(sha, req.device);
    let c = challenges
        .iter_mut()
        .find(|c| c.expires_ms != 0 && c.nonce == req.challenge)
        .ok_or(Refusal::ChallengeUnknown)?;
    let held = *c;
    *c = Challenge::empty();
    if now >= held.expires_ms
        || held.resource_kind != req.resource_kind
        || held.resource != req.resource
        || held.device != device
    {
        return Err(Refusal::ChallengeUnknown);
    }
    Ok(())
}

// ── Starting ────────────────────────────────────────────────────────────

fn start<H: Host>(
    cx: &mut Cx<'_, H>,
    challenges: &mut [Challenge; MAX_CHALLENGES],
    op: &mut Op,
    now: u64,
) -> Result<(), Refusal> {
    match op.code {
        sk::op::CREATE => start_create(cx, op, now),
        sk::op::RECORD_SET => {
            let mut h = head(op.body())?;
            let epoch = h.rest.u32().ok_or(Refusal::Malformed)?;
            op.audit.epoch = epoch;
            get(cx, op, stage::GET_GRANT, &Key::Grant, now)
        }
        sk::op::GRANT
        | sk::op::ROTATE_GRANT
        | sk::op::REPLACE_DEVICE
        | sk::op::REVOKE
        | sk::op::ROTATE_KEY
        | sk::op::RETIRE_EPOCH
        | sk::op::RECOVERY_AUTHORISE
        | sk::op::ERASE => {
            head(op.body())?;
            get(cx, op, stage::GET_GRANT, &Key::Grant, now)
        }
        sk::op::ATTACH | sk::op::RECOVER | sk::op::RENEW_ATTACHMENT => {
            let (fields, spent) = {
                let req = op.attach()?;
                let spent = spend_challenge(challenges, cx.host.sha256(), &req, now);
                ((req.anti_replay, req.fence, req.epoch), spent)
            };
            (op.audit.anti_replay, op.audit.fence, op.audit.epoch) = fields;
            spent?;
            get(cx, op, stage::GET_GRANT, &Key::Grant, now)
        }
        _ => Err(Refusal::Malformed),
    }
}

/// Authorise creating a resource's first key epoch: a grant with no device
/// yet, and the creation authorisation the provisioning vault splits under.
///
/// Body: `[tenant f8][policy][aead u16][custodian public ×3][actor f8]`.
fn start_create<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op, now: u64) -> Result<(), Refusal> {
    let sha = cx.host.sha256();
    let mut ids = [0u8; 32];
    if !cx.host.random(&mut ids) {
        return Err(Refusal::Busy);
    }
    let Op {
        req,
        req_len,
        out,
        aux,
        audit,
        ..
    } = op;
    let body = req.get(..usize::from(*req_len)).unwrap_or(&[]);
    let mut h = head(body)?;
    let tenant = id_field(&mut h.rest)?;
    let policy = policy_fields(&mut h.rest)?;
    let aead = h.rest.u16().ok_or(Refusal::Malformed)?;
    let keys = custodian_keys(&mut h.rest)?;
    actor(&mut h.rest)?;
    if !matches!(
        aead,
        share::aead::CHACHA20_POLY1305 | share::aead::AES_256_GCM
    ) {
        return Err(Refusal::Malformed);
    }
    let issuer = cx.cfg.issuer();
    let mut g = Binding::empty();
    g.kind = sk::kind::GRANT;
    g.resource_kind = h.resource_kind;
    g.resource = h.resource;
    g.purpose = share::purpose::ATTACHMENT;
    g.custody = policy.custody;
    g.min_tier = policy.min_tier;
    g.min_assurance = policy.min_assurance;
    g.lifetime_secs = policy.lifetime_secs;
    g.aead = aead;
    g.epoch = 1;
    g.generation = 1;
    g.issued_ms = now;
    g.grant_id.copy_from_slice(&ids[..16]);
    g.set_id.copy_from_slice(&ids[16..]);
    g.policy = sk::policy_digest(sha, &g, issuer, tenant);
    let names = sk::Names {
        issuer,
        tenant,
        device: &[],
    };
    let mut c = g;
    c.kind = sk::kind::CREATION;
    c.purpose = share::purpose::RECOVERY;
    sign_into(cx.host, aux, &g, &names, &[])?;
    sign_into(cx.host, out, &c, &names, &keys)?;
    audit.epoch = 1;
    audit.generation = 1;
    // The grant is written first and create-if-absent: it is what claims the
    // resource, so a second creation of the same resource stops here.
    put(cx, op, stage::PUT_GRANT, &Key::Grant, Which::Aux, now)
}

// ── Advancing ───────────────────────────────────────────────────────────

fn advance<H: Host>(
    cx: &mut Cx<'_, H>,
    op: &mut Op,
    status: u8,
    etag: &[u8],
    value: &[u8],
    now: u64,
) -> Result<(), Refusal> {
    match op.stage {
        stage::GET_GRANT => {
            read_status(status)?;
            op.grant.store(value, etag)?;
            // An erasure stands where the grant stood: every operation but
            // the erasure's own retry stops at it.
            match verify_kind(cx.host, op.grant.bytes())? {
                sk::kind::GRANT => {}
                sk::kind::ERASURE if op.code == sk::op::ERASE => {}
                sk::kind::ERASURE => return Err(Refusal::Erased),
                _ => return Err(Refusal::Malformed),
            }
            after_grant(cx, op, now)
        }
        stage::GET_CURRENT_SET => {
            // A rotation waits for the last one's recovery set: an epoch
            // with only a creation behind it has no custody yet.
            if status == auth_wire::ST_NOT_FOUND {
                return Err(Refusal::RotationInProgress);
            }
            read_status(status)?;
            op.set.store(value, etag)?;
            if verify_kind(cx.host, op.set.bytes())? != sk::kind::RECOVERY_SET {
                return Err(Refusal::RotationInProgress);
            }
            rotate_key(cx, op, now)
        }
        stage::ERASE_GET_SET => {
            if status == auth_wire::ST_NOT_FOUND {
                op.cursor = op.cursor.saturating_add(1);
                return erase_next(cx, op, now);
            }
            read_status(status)?;
            op.set.store(value, etag)?;
            let epoch = op.cursor;
            delete(cx, op, stage::ERASE_DELETE_SET, &Key::Set(epoch), now)
        }
        stage::ERASE_DELETE_SET => {
            if status != auth_wire::ST_NOT_FOUND {
                write_status(status)?;
            }
            op.cursor = op.cursor.saturating_add(1);
            erase_next(cx, op, now)
        }
        stage::GET_DEVICE => {
            if status == auth_wire::ST_NOT_FOUND {
                return Err(Refusal::DeviceUnknown);
            }
            read_status(status)?;
            let (facts, next) = {
                let grant = op.grant.record()?;
                let req = op.attach()?;
                let facts = cx.host.device_facts(
                    value,
                    grant.names.tenant,
                    req.device_suite,
                    req.device_public,
                );
                let next = if op.code == sk::op::RECOVER {
                    (stage::GET_TICKET, Key::Ticket(req.ticket))
                } else if op.code == sk::op::RENEW_ATTACHMENT {
                    (stage::GET_CHAIN, Key::Attachment(req.ticket))
                } else {
                    (stage::GET_SET, Key::Set(req.epoch))
                };
                (facts, next)
            };
            op.facts = facts;
            get(cx, op, next.0, &next.1, now)
        }
        stage::GET_TICKET => {
            if status == auth_wire::ST_NOT_FOUND {
                return Err(Refusal::NoRecoveryTicket);
            }
            read_status(status)?;
            op.ticket.store(value, etag)?;
            verify_stored(cx.host, op.ticket.bytes(), sk::kind::RECOVERY_TICKET)?;
            let epoch = op.attach()?.epoch;
            get(cx, op, stage::GET_SET, &Key::Set(epoch), now)
        }
        stage::GET_SET => {
            if status == auth_wire::ST_NOT_FOUND {
                return Err(if op.code == sk::op::RECORD_SET {
                    Refusal::UnknownResource
                } else {
                    Refusal::SetIncomplete
                });
            }
            read_status(status)?;
            op.set.store(value, etag)?;
            if op.code == sk::op::RECORD_SET {
                record_set(cx, op, now)
            } else {
                decide(cx, op, now)
            }
        }
        stage::GET_CHAIN => {
            if status == auth_wire::ST_OK {
                op.chain.present = true;
                op.chain.digest = sk::record_digest(cx.host.sha256(), value);
                op.chain.etag_len = u8::try_from(etag.len()).map_err(|_| Refusal::Malformed)?;
                op.chain
                    .etag
                    .get_mut(..etag.len())
                    .ok_or(Refusal::Malformed)?
                    .copy_from_slice(etag);
            } else if status != auth_wire::ST_NOT_FOUND {
                read_status(status)?;
            }
            decide_renewal(cx, op, now)
        }
        stage::GET_OLD_SET => {
            if status == auth_wire::ST_NOT_FOUND {
                // Nothing held for the retired epoch: there is nothing to
                // destroy, and the retirement stands.
                finish(cx, op, Ok(()));
                return Ok(());
            }
            read_status(status)?;
            op.set.store(value, etag)?;
            let epoch = op.audit.epoch;
            delete(cx, op, stage::DELETE_SET, &Key::Set(epoch), now)
        }
        stage::CLAIM_REPLAY => {
            match state_wire::replay_claim_result(status) {
                state_wire::ReplayClaim::Fresh => {}
                state_wire::ReplayClaim::Replayed => {
                    cx.stats.replayed = cx.stats.replayed.saturating_add(1);
                    return Err(Refusal::Replayed);
                }
                state_wire::ReplayClaim::Unavailable => return Err(Refusal::LedgerUnavailable),
            }
            match op.code {
                sk::op::RECOVER => consume_ticket(cx, op, now),
                sk::op::RENEW_ATTACHMENT => advance_chain(cx, op, now),
                _ => order(cx, op, now),
            }
        }
        stage::CONSUME_TICKET => {
            write_status(status)?;
            order(cx, op, now)
        }
        stage::PUT_GRANT => {
            write_status(status)?;
            // The grant claimed the resource; record the creation
            // authorisation under its epoch.
            let epoch = op.audit.epoch;
            put(cx, op, stage::PUT_SET, &Key::Set(epoch), Which::Out, now)
        }
        stage::PUT_SET => {
            write_status(status)?;
            if op.code == sk::op::ROTATE_KEY {
                // The new epoch's creation is recorded; the grant moves to
                // it and keeps admitting the old one until it is retired.
                cas(cx, op, stage::CAS_GRANT, &Key::Grant, Which::Aux, now)
            } else {
                finish(cx, op, Ok(()));
                Ok(())
            }
        }
        stage::CAS_GRANT => {
            write_status(status)?;
            if op.code == sk::op::ERASE {
                // The erasure record stands: nothing more is issued. Now
                // destroy what is held.
                op.cursor = 1;
                return erase_next(cx, op, now);
            }
            if op.code == sk::op::RETIRE_EPOCH {
                // The grant no longer admits the old epoch. Its custody
                // envelopes are destroyed next, and the removal is audited
                // as part of this decision.
                let epoch = op.audit.epoch;
                return get(cx, op, stage::GET_OLD_SET, &Key::Set(epoch), now);
            }
            finish(cx, op, Ok(()));
            Ok(())
        }
        stage::CAS_SET | stage::PUT_TICKET | stage::DELETE_SET | stage::PUT_CHAIN => {
            write_status(status)?;
            finish(cx, op, Ok(()));
            Ok(())
        }
        stage::WRITE_AUDIT => {
            let ok = status == auth_wire::ST_OK;
            if !ok {
                cx.stats.audit_failed = cx.stats.audit_failed.saturating_add(1);
            }
            reply(cx, op, ok);
            op.reset();
            Ok(())
        }
        _ => Ok(()),
    }
}

/// The grant is read: what each control operation does with it.
fn after_grant<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op, now: u64) -> Result<(), Refusal> {
    let code = op.code;
    if op.proven() {
        let mut device = [0u8; sk::MAX_ID];
        let n = {
            let req = op.attach()?;
            let grant = op.grant.record()?;
            // An epoch the grant does not admit has no set worth reading:
            // say which it is rather than that the set is missing.
            if !sk::admits(&grant, req.epoch) {
                return Err(Refusal::WrongEpoch);
            }
            device[..req.device.len()].copy_from_slice(req.device);
            req.device.len()
        };
        return get(cx, op, stage::GET_DEVICE, &Key::Device(device, n), now);
    }
    if code == sk::op::ERASE {
        return start_erase(cx, op, now);
    }
    let Op {
        req,
        req_len,
        grant,
        out,
        audit,
        ..
    } = op;
    let held = grant.record()?;
    let mut g = held.binding;
    let mut retained = sk::Retained::of(&held)?;
    audit.epoch = g.epoch;
    audit.generation = g.generation;
    let body = req.get(..usize::from(*req_len)).unwrap_or(&[]);
    let mut h = head(body)?;
    let issuer = cx.cfg.issuer();
    let tenant = held.names.tenant;
    let mut device: &[u8] = held.names.device;
    match code {
        sk::op::RECORD_SET => {
            // A set is recorded only for an epoch the grant admits: an
            // erased resource, or a creation a failed rotation left behind,
            // takes no custody envelopes.
            let epoch = h.rest.u32().ok_or(Refusal::Malformed)?;
            if !sk::admits(&held, epoch) {
                return Err(Refusal::WrongEpoch);
            }
            audit.epoch = epoch;
            return get(cx, op, stage::GET_SET, &Key::Set(epoch), now);
        }
        sk::op::GRANT | sk::op::ROTATE_GRANT => {
            let named = id_field(&mut h.rest)?;
            let policy = policy_fields(&mut h.rest)?;
            actor(&mut h.rest)?;
            if code == sk::op::GRANT {
                // A live grant is changed by rotation or replacement, each of
                // which names what it replaces; a plain grant over one would
                // change a device policy silently.
                if !held.names.device.is_empty() && !g.revoked() {
                    return Err(Refusal::Conflict);
                }
                g.flags &= !sk::flag::REVOKED;
                g.revoked_ms = 0;
            } else {
                if g.revoked() {
                    return Err(Refusal::GrantRevoked);
                }
                if held.names.device != named {
                    return Err(Refusal::DeviceNotGranted);
                }
            }
            g.custody = policy.custody;
            g.min_tier = policy.min_tier;
            g.min_assurance = policy.min_assurance;
            g.lifetime_secs = policy.lifetime_secs;
            device = named;
        }
        sk::op::REPLACE_DEVICE => {
            let old = id_field(&mut h.rest)?;
            let new = id_field(&mut h.rest)?;
            actor(&mut h.rest)?;
            if old == new {
                return Err(Refusal::Malformed);
            }
            if g.revoked() {
                return Err(Refusal::GrantRevoked);
            }
            if held.names.device != old {
                return Err(Refusal::Conflict);
            }
            device = new;
        }
        sk::op::REVOKE => {
            actor(&mut h.rest)?;
            if g.revoked() {
                return Err(Refusal::GrantRevoked);
            }
            g.flags |= sk::flag::REVOKED;
            g.revoked_ms = now;
        }
        sk::op::RETIRE_EPOCH => {
            // Only the epoch named, and only a retained one: the current
            // epoch is never retired, and which retained epoch no snapshot
            // needs any longer is the caller's knowledge.
            let epoch = h.rest.u32().ok_or(Refusal::Malformed)?;
            actor(&mut h.rest)?;
            if !retained.remove(epoch) {
                return Err(Refusal::WrongEpoch);
            }
            audit.epoch = epoch;
        }
        sk::op::ROTATE_KEY => {
            custodian_keys(&mut h.rest)?;
            actor(&mut h.rest)?;
            if retained.is_full() {
                return Err(Refusal::RetainedEpochsFull);
            }
            let epoch = g.epoch;
            return get(cx, op, stage::GET_CURRENT_SET, &Key::Set(epoch), now);
        }
        sk::op::RECOVERY_AUTHORISE => {
            let epoch = h.rest.u32().ok_or(Refusal::Malformed)?;
            let recovering = id_field(&mut h.rest)?;
            let ttl = h.rest.u32().ok_or(Refusal::Malformed)?;
            actor(&mut h.rest)?;
            if ttl == 0 || ttl > MAX_TICKET_SECS {
                return Err(Refusal::Malformed);
            }
            if !sk::admits(&held, epoch) {
                return Err(Refusal::WrongEpoch);
            }
            let mut ticket = [0u8; 16];
            if !cx.host.random(&mut ticket) {
                return Err(Refusal::Busy);
            }
            let mut t = g;
            t.kind = sk::kind::RECOVERY_TICKET;
            t.epoch = epoch;
            t.retained = 0;
            t.flags = 0;
            t.revoked_ms = 0;
            t.issued_ms = now;
            t.expiry_ms = now.saturating_add(u64::from(ttl).saturating_mul(1000));
            // A ticket's id rides in the grant-id field: it is what the
            // recovering node names, and what the ledger keys it by.
            t.grant_id = ticket;
            let names = sk::Names {
                issuer,
                tenant,
                device: recovering,
            };
            sign_into(cx.host, out, &t, &names, &[])?;
            audit.epoch = epoch;
            return put(
                cx,
                op,
                stage::PUT_TICKET,
                &Key::Ticket(ticket),
                Which::Out,
                now,
            );
        }
        _ => return Err(Refusal::Malformed),
    }
    // A grant change: one new generation, re-signed whole.
    g.generation = g.generation.wrapping_add(1);
    g.issued_ms = now;
    let names = sk::Names {
        issuer,
        tenant,
        device,
    };
    sign_grant(cx.host, out, &g, &names, &retained)?;
    audit.generation = g.generation;
    cas(cx, op, stage::CAS_GRANT, &Key::Grant, Which::Out, now)
}

/// The current epoch's recovery set is recorded: authorise the next epoch.
/// The grant moves to it and keeps admitting the one it left, among its
/// retained epochs, until that is retired by name.
///
/// Body: `[custodian public ×3][actor f8]`.
fn rotate_key<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op, now: u64) -> Result<(), Refusal> {
    let sha = cx.host.sha256();
    let mut set_id = [0u8; 16];
    if !cx.host.random(&mut set_id) {
        return Err(Refusal::Busy);
    }
    let Op {
        req,
        req_len,
        grant,
        out,
        aux,
        audit,
        ..
    } = op;
    let held = grant.record()?;
    let mut g = held.binding;
    let mut retained = sk::Retained::of(&held)?;
    let body = req.get(..usize::from(*req_len)).unwrap_or(&[]);
    let mut h = head(body)?;
    let keys = custodian_keys(&mut h.rest)?;
    actor(&mut h.rest)?;
    let issuer = cx.cfg.issuer();
    let tenant = held.names.tenant;
    let next = g.epoch.checked_add(1).ok_or(Refusal::WrongEpoch)?;
    retained.push(g.epoch)?;
    g.epoch = next;
    g.set_id = set_id;
    g.policy = sk::policy_digest(sha, &g, issuer, tenant);
    g.generation = g.generation.wrapping_add(1);
    g.issued_ms = now;
    let mut c = g;
    c.kind = sk::kind::CREATION;
    c.purpose = share::purpose::RECOVERY;
    c.retained = 0;
    c.flags = 0;
    c.revoked_ms = 0;
    let creation_names = sk::Names {
        issuer,
        tenant,
        device: &[],
    };
    let grant_names = sk::Names {
        issuer,
        tenant,
        device: held.names.device,
    };
    sign_into(cx.host, out, &c, &creation_names, &keys)?;
    sign_grant(cx.host, aux, &g, &grant_names, &retained)?;
    audit.epoch = next;
    audit.generation = g.generation;
    put(cx, op, stage::PUT_SET, &Key::Set(next), Which::Out, now)
}

/// Erase a resource's key custody.
///
/// Body: `[epoch u32][pins u32][actor f8]`. `epoch` is the current key
/// epoch the caller's pin scan covered, `pins` how many retained snapshots
/// or clones that scan found still needing any epoch of the resource. This
/// issuer cannot see snapshots, so the scan is the caller's; what it decides
/// on is its own records: a scan that found a pin is refused
/// ([`Refusal::EpochPinned`]), and one that predates the grant's current
/// epoch — a rotation it did not see — is refused as stale
/// ([`Refusal::WrongEpoch`]). Both are audited, the assertion with them.
///
/// On a grant, the erasure record replaces it by compare-and-swap. On an
/// erasure record — a retry — the record stands and the destruction runs
/// again: every set it finds is deleted, the custodians are ordered again,
/// and the reply carries the same record.
fn start_erase<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op, now: u64) -> Result<(), Refusal> {
    let resumed = {
        let Op {
            req,
            req_len,
            grant,
            out,
            audit,
            ..
        } = op;
        let held = grant.record()?;
        let g = held.binding;
        audit.epoch = g.epoch;
        audit.generation = g.generation;
        let body = req.get(..usize::from(*req_len)).unwrap_or(&[]);
        let mut h = head(body)?;
        let checked = h.rest.u32().ok_or(Refusal::Malformed)?;
        let pins = h.rest.u32().ok_or(Refusal::Malformed)?;
        actor(&mut h.rest)?;
        if pins != 0 {
            return Err(Refusal::EpochPinned);
        }
        if checked != g.epoch {
            return Err(Refusal::WrongEpoch);
        }
        if g.kind == sk::kind::ERASURE {
            let bytes = grant.bytes();
            out.bytes
                .get_mut(..bytes.len())
                .ok_or(Refusal::Malformed)?
                .copy_from_slice(bytes);
            out.len = grant.len;
            true
        } else {
            let mut e = g;
            e.kind = sk::kind::ERASURE;
            e.flags = sk::flag::REVOKED;
            e.revoked_ms = now;
            e.issued_ms = now;
            e.expiry_ms = 0;
            e.retained = 0;
            e.generation = g.generation.wrapping_add(1);
            let names = sk::Names {
                issuer: cx.cfg.issuer(),
                tenant: held.names.tenant,
                device: &[],
            };
            sign_into(cx.host, out, &e, &names, &[])?;
            audit.generation = e.generation;
            false
        }
    };
    if resumed {
        op.cursor = 1;
        return erase_next(cx, op, now);
    }
    cas(cx, op, stage::CAS_GRANT, &Key::Grant, Which::Out, now)
}

/// Delete the next epoch's recovery set, or when every one is gone, order
/// the custodians.
///
/// The sweep runs from epoch 1 through the epoch after the last: retired
/// epochs were deleted at retirement, but one whose deletion did not land
/// is found here, and so is a creation authorised by a rotation that raced
/// the erasure.
fn erase_next<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op, now: u64) -> Result<(), Refusal> {
    let last = op.audit.epoch.saturating_add(1);
    if op.cursor <= last {
        let epoch = op.cursor;
        return get(cx, op, stage::ERASE_GET_SET, &Key::Set(epoch), now);
    }
    op.stage = stage::ERASE_CUSTODIANS;
    op.deadline_ms = now.saturating_add(STAGE_TIMEOUT_MS);
    op.asked = 0;
    op.answered = 0;
    for c in 0..3u8 {
        send_erase_order(cx, op, c)?;
    }
    Ok(())
}

fn send_erase_order<H: Host>(
    cx: &mut Cx<'_, H>,
    op: &mut Op,
    custodian: u8,
) -> Result<(), Refusal> {
    op.asked |= 1 << custodian;
    let mut payload = [0u8; 8 + sk::MAX_RECORD];
    let mut w = sk::Writer::new(&mut payload);
    let ok =
        w.u32(op.icorr).is_some() && w.u8(custodian).is_some() && w.f16(op.out.bytes()).is_some();
    if !ok {
        return Err(Refusal::Malformed);
    }
    let len = w.len();
    let n = auth_wire::write_envelope(
        msg::ERASE_ORDER,
        payload.get(..len).unwrap_or(&[]),
        cx.frame,
    )
    .map_err(|_| Refusal::Malformed)?;
    if cx
        .host
        .send(Port::Custodian, cx.frame.get(..n).unwrap_or(&[]))
    {
        Ok(())
    } else {
        Err(Refusal::Busy)
    }
}

/// One custodian's answer to an erase order. All three must confirm: a
/// custodian that refuses or stays silent leaves the erasure unfinished,
/// and a retry orders it again.
fn erase_result<H: Host>(
    cx: &mut Cx<'_, H>,
    op: &mut Op,
    custodian: u8,
    status: u8,
) -> Result<(), Refusal> {
    if custodian > 2 {
        return Ok(());
    }
    let bit = 1u8 << custodian;
    if op.asked & bit == 0 || op.answered & bit != 0 {
        return Ok(());
    }
    op.answered |= bit;
    if status != STATUS_OK {
        return Err(Refusal::CustodianRefused);
    }
    if op.answered == 0b111 {
        finish(cx, op, Ok(()));
    }
    Ok(())
}

/// A creation's three custody envelopes are back: record the set.
///
/// Body: `[epoch u32][envelope f16 ×3][actor f8]`.
fn record_set<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op, now: u64) -> Result<(), Refusal> {
    let sha = cx.host.sha256();
    verify_stored(cx.host, op.set.bytes(), sk::kind::CREATION)?;
    let Op {
        req,
        req_len,
        set,
        out,
        audit,
        ..
    } = op;
    let creation = set.record()?;
    let body = req.get(..usize::from(*req_len)).unwrap_or(&[]);
    let mut h = head(body)?;
    let epoch = h.rest.u32().ok_or(Refusal::Malformed)?;
    let first = h.rest.f16().ok_or(Refusal::Malformed)?;
    let second = h.rest.f16().ok_or(Refusal::Malformed)?;
    let third = h.rest.f16().ok_or(Refusal::Malformed)?;
    actor(&mut h.rest)?;
    let created = creation.binding;
    if created.resource != h.resource
        || created.resource_kind != h.resource_kind
        || created.epoch != epoch
    {
        return Err(Refusal::WrongEpoch);
    }
    let envs = [first, second, third];
    sk::check_custody_set(sha, &creation, &envs)?;
    let mut recorded = created;
    recorded.kind = sk::kind::RECOVERY_SET;
    recorded.issued_ms = now;
    sign_into(cx.host, out, &recorded, &creation.names, &envs)?;
    audit.epoch = epoch;
    audit.generation = created.generation;
    cas(cx, op, stage::CAS_SET, &Key::Set(epoch), Which::Out, now)
}

/// Everything a release rests on is read: decide it, then claim its
/// anti-replay id.
fn decide<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op, now: u64) -> Result<(), Refusal> {
    let (sha, verify) = (cx.host.sha256(), cx.host.verify());
    verify_stored(cx.host, op.set.bytes(), sk::kind::RECOVERY_SET)
        .map_err(|_| Refusal::SetIncomplete)?;
    let (auth, anti_replay, expiry_ms, generation) = {
        let req = op.attach()?;
        let grant = op.grant.record()?;
        let set = op.set.record()?;
        let ticket = if op.ticket.len > 0 {
            Some(op.ticket.record()?)
        } else {
            None
        };
        let release = sk::decide_release(
            sha,
            verify,
            cx.cfg.issuer(),
            &grant,
            &set,
            ticket.as_ref(),
            op.facts,
            &req,
            now,
        )?;
        (
            release.binding,
            req.anti_replay,
            req.expiry_ms,
            grant.binding.generation,
        )
    };
    op.auth = auth;
    op.audit.record_binding(&auth);
    op.audit.generation = generation;
    let mut key = [0u8; MAX_KEY];
    let n = sk::replay_key(&anti_replay, &mut key).ok_or(Refusal::Malformed)?;
    // The claim lasts as long as the request could have been presented; a
    // request is refused on its own expiry before the claim is consulted.
    let claim = state_wire::claim_replay(
        op.icorr,
        STATE_CLIENT,
        key.get(..n).unwrap_or(&[]),
        expiry_ms.saturating_add(999) / 1000,
    );
    send_state(
        cx,
        op,
        state_wire::MSG_STATE_PUT_ABS,
        &claim,
        stage::CLAIM_REPLAY,
        now,
    )
}

/// Everything a renewal rests on is read: decide it, sign it, then claim
/// its anti-replay id.
fn decide_renewal<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op, now: u64) -> Result<(), Refusal> {
    let (sha, verify) = (cx.host.sha256(), cx.host.verify());
    let (renewal, expiry_ms) = {
        let (req, attachment) = read_renew_body(op.body())?;
        let grant = op.grant.record()?;
        let renewal = sk::decide_renewal(
            sha,
            verify,
            cx.cfg.issuer(),
            cx.host.issuer_suite(),
            cx.host.issuer_public(),
            &grant,
            attachment,
            op.chain.chain(),
            op.facts,
            &req,
            now,
        )?;
        (renewal, req.expiry_ms)
    };
    op.audit.record_binding(&renewal.binding);
    {
        let Op {
            req,
            req_len,
            grant,
            out,
            ..
        } = op;
        let (r, _) = read_renew_body(req.get(..usize::from(*req_len)).unwrap_or(&[]))?;
        let g = grant.record()?;
        let names = sk::Names {
            issuer: g.names.issuer,
            tenant: g.names.tenant,
            device: r.device,
        };
        sign_into(
            cx.host,
            out,
            &renewal.binding,
            &names,
            &[&renewal.attachment_id, &renewal.previous],
        )?;
    }
    op.auth = renewal.binding;
    let mut key = [0u8; MAX_KEY];
    let n = sk::replay_key(&renewal.binding.anti_replay, &mut key).ok_or(Refusal::Malformed)?;
    let claim = state_wire::claim_replay(
        op.icorr,
        STATE_CLIENT,
        key.get(..n).unwrap_or(&[]),
        expiry_ms.saturating_add(999) / 1000,
    );
    send_state(
        cx,
        op,
        state_wire::MSG_STATE_PUT_ABS,
        &claim,
        stage::CLAIM_REPLAY,
        now,
    )
}

/// Advance the attachment's renewal chain to the renewal just signed:
/// create-if-absent on its first renewal, compare-and-swap on the head read
/// after. The entry lives as long as the attachment it renews.
fn advance_chain<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op, now: u64) -> Result<(), Refusal> {
    let id = read_renew_body(op.body())?.0.ticket;
    let key = Key::Attachment(id);
    let mut k = [0u8; MAX_KEY];
    let (ns, n) = compose(op, &key, &mut k)?;
    let expiry = op.auth.expiry_ms.saturating_add(999) / 1000;
    let request = if op.chain.present {
        state_wire::compare_and_swap(
            op.icorr,
            STATE_CLIENT,
            ns,
            k.get(..n).unwrap_or(&[]),
            op.chain.etag(),
            op.out.bytes(),
            expiry,
        )
    } else {
        state_wire::put_if_absent(
            op.icorr,
            STATE_CLIENT,
            ns,
            k.get(..n).unwrap_or(&[]),
            op.out.bytes(),
            expiry,
        )
    };
    let msg_type = if op.chain.present {
        state_wire::MSG_STATE_CAS
    } else {
        state_wire::MSG_STATE_PUT_ABS
    };
    let frame_len =
        state_wire::encode_request(cx.frame, msg_type, &request).map_err(|_| Refusal::Malformed)?;
    commit_send(cx, op, frame_len, stage::PUT_CHAIN, now)
}

/// Mark the recovery ticket used, conditional on the revision read.
fn consume_ticket<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op, now: u64) -> Result<(), Refusal> {
    let Op { ticket, aux, .. } = op;
    let t = ticket.record()?;
    let mut b = t.binding;
    b.flags |= sk::flag::CONSUMED;
    let id = b.grant_id;
    sign_into(cx.host, aux, &b, &t.names, &[])?;
    cas(
        cx,
        op,
        stage::CONSUME_TICKET,
        &Key::Ticket(id),
        Which::Aux,
        now,
    )
}

/// Sign the authorisation and ask two custodians for their shares.
fn order<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op, now: u64) -> Result<(), Refusal> {
    {
        let Op {
            req,
            req_len,
            grant,
            out,
            auth,
            code,
            ..
        } = op;
        let kind = if *code == sk::op::RECOVER {
            sk::kind::RECOVERY
        } else {
            sk::kind::ATTACHMENT
        };
        let r = read_attach_body(kind, req.get(..usize::from(*req_len)).unwrap_or(&[]))?;
        let g = grant.record()?;
        let names = sk::Names {
            issuer: g.names.issuer,
            tenant: g.names.tenant,
            device: r.device,
        };
        sign_into(cx.host, out, auth, &names, &[])?;
    }
    op.stage = stage::CUSTODIANS;
    op.deadline_ms = now.saturating_add(STAGE_TIMEOUT_MS);
    send_order(cx, op, 0)?;
    send_order(cx, op, 1)
}

fn send_order<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op, custodian: u8) -> Result<(), Refusal> {
    op.asked |= 1 << custodian;
    let set = op.set.record()?;
    let envelope = set
        .item(usize::from(custodian))
        .ok_or(Refusal::SetIncomplete)?;
    let req = op.attach()?;
    let recipient = sk::recipient_public(req.recipient).ok_or(Refusal::Malformed)?;
    let mut payload = [0u8; 16 + sk::MAX_RECORD + sk::PUBLIC_LEN + sk::ENVELOPE_LEN];
    let mut w = sk::Writer::new(&mut payload);
    let ok = w.u32(op.icorr).is_some()
        && w.u8(custodian).is_some()
        && w.f16(op.out.bytes()).is_some()
        && w.f8(recipient).is_some()
        && w.f16(envelope).is_some();
    if !ok {
        return Err(Refusal::Malformed);
    }
    let len = w.len();
    let n = auth_wire::write_envelope(
        msg::REWRAP_ORDER,
        payload.get(..len).unwrap_or(&[]),
        cx.frame,
    )
    .map_err(|_| Refusal::Malformed)?;
    if cx
        .host
        .send(Port::Custodian, cx.frame.get(..n).unwrap_or(&[]))
    {
        Ok(())
    } else {
        Err(Refusal::Busy)
    }
}

fn custodian_result<H: Host>(
    cx: &mut Cx<'_, H>,
    op: &mut Op,
    custodian: u8,
    status: u8,
    env: &[u8],
    now: u64,
) -> Result<(), Refusal> {
    if custodian > 2 {
        return Ok(());
    }
    let bit = 1u8 << custodian;
    if op.asked & bit == 0 || op.answered & bit != 0 {
        return Ok(());
    }
    op.answered |= bit;
    let checked = if status == STATUS_OK {
        sk::check_released(env, &op.auth).and_then(|index| {
            if index == custodian + 1 {
                Ok(())
            } else {
                Err(Refusal::EnvelopeInvalid)
            }
        })
    } else {
        Err(Refusal::CustodianRefused)
    };
    match checked {
        Ok(()) => {
            let slot = usize::from(op.env_count);
            let Some(dst) = op.envs.get_mut(slot) else {
                return Ok(());
            };
            if !sk::copy_exact(dst, env) {
                return Err(Refusal::EnvelopeInvalid);
            }
            op.env_count += 1;
        }
        Err(refusal) => {
            // One custodian failing is what the third share is for.
            let spare = (0u8..3).find(|c| op.asked & (1 << c) == 0);
            return match spare {
                Some(c) => {
                    op.deadline_ms = now.saturating_add(STAGE_TIMEOUT_MS);
                    send_order(cx, op, c)
                }
                None => Err(refusal),
            };
        }
    }
    if op.env_count < 2 {
        return Ok(());
    }
    release(cx, op)
}

/// Both envelopes are in: assemble the bundle, sign the record whole.
fn release<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op) -> Result<(), Refusal> {
    let mut bundle = [0u8; sk::BUNDLE_LEN];
    sk::write_bundle(&op.envs[0], &op.envs[1], &op.auth, &mut bundle)?;
    let a = &bundle[sk::BUNDLE_HEADER..sk::BUNDLE_HEADER + sk::ENVELOPE_LEN];
    let b = &bundle[sk::BUNDLE_HEADER + sk::ENVELOPE_LEN..];
    {
        let Op {
            req,
            req_len,
            grant,
            out,
            auth,
            code,
            ..
        } = op;
        let kind = if *code == sk::op::RECOVER {
            sk::kind::RECOVERY
        } else {
            sk::kind::ATTACHMENT
        };
        let r = read_attach_body(kind, req.get(..usize::from(*req_len)).unwrap_or(&[]))?;
        let g = grant.record()?;
        let names = sk::Names {
            issuer: g.names.issuer,
            tenant: g.names.tenant,
            device: r.device,
        };
        sign_into(cx.host, out, auth, &names, &[a, b])?;
    }
    // Held in bundle order, so the reply's bundle is the record's.
    op.envs[0].copy_from_slice(a);
    op.envs[1].copy_from_slice(b);
    finish(cx, op, Ok(()));
    Ok(())
}

// ── Finishing ───────────────────────────────────────────────────────────

/// Audit the decision, then answer once the entry is written. Every allowed
/// and every refused operation passes through here.
fn finish<H: Host>(cx: &mut Cx<'_, H>, op: &mut Op, outcome: Result<(), Refusal>) {
    let sha = cx.host.sha256();
    let now = cx.host.now_ms();
    match outcome {
        Ok(()) => {
            op.refusal = None;
            op.audit.refusal = 0;
            op.audit.record = sk::record_digest(sha, op.out.bytes());
            cx.stats.allowed = cx.stats.allowed.saturating_add(1);
        }
        Err(refusal) => {
            op.refusal = Some(refusal);
            op.audit.refusal = refusal.code();
            op.audit.record = [0; 32];
            op.out.len = 0;
            op.env_count = 0;
            cx.stats.refused = cx.stats.refused.saturating_add(1);
        }
    }
    op.audit.at_ms = now;
    let (device, actor_name) = audit_names(op);
    let mut entry = [0u8; sk::MAX_AUDIT];
    let encoded = op
        .audit
        .encode(device.as_slice(), actor_name.as_slice(), &mut entry);
    let mut id = [0u8; 8];
    let keyed = cx.host.random(&mut id);
    let mut key = [0u8; MAX_KEY];
    let key_len = sk::audit_key(
        op.audit.resource_kind,
        &op.audit.resource,
        now,
        id,
        &mut key,
    );
    let sent = match (encoded, key_len, keyed) {
        (Some(len), Some(key_len), true) => {
            let request = state_wire::put_if_absent(
                op.icorr,
                STATE_CLIENT,
                state_wire::NS_STORAGE_AUDIT,
                key.get(..key_len).unwrap_or(&[]),
                entry.get(..len).unwrap_or(&[]),
                0,
            );
            send_state(
                cx,
                op,
                state_wire::MSG_STATE_PUT_ABS,
                &request,
                stage::WRITE_AUDIT,
                now,
            )
            .is_ok()
        }
        _ => false,
    };
    if !sent {
        cx.stats.audit_failed = cx.stats.audit_failed.saturating_add(1);
        reply(cx, op, false);
        op.reset();
    }
}

/// The device and actor an audit entry names.
///
/// A proven request carries its device in the proof. A control request does
/// not, so its body is walked again here for the actor every one of them
/// ends with — a second reading of layouts the deciding path already knows,
/// which is why `every_control_decision_names_the_actor_that_asked_for_it`
/// drives each verb and matches the name it used.
fn audit_names(op: &Op) -> (Name, Name) {
    let mut device = Name::empty();
    let mut who = Name::empty();
    if op.proven() {
        if let Ok(req) = op.attach() {
            device.set(req.device);
            who.set(req.device);
        }
        return (device, who);
    }
    let Ok(mut h) = head(op.body()) else {
        return (device, who);
    };
    let r = &mut h.rest;
    // Skip to the actor, the last field of every control request, noting
    // the device the operation concerns on the way.
    let walked = match op.code {
        sk::op::GRANT | sk::op::ROTATE_GRANT => r
            .f8()
            .map(|d| device.set(d))
            .and_then(|()| r.take(POLICY_LEN)),
        sk::op::REPLACE_DEVICE => r.f8().and_then(|_| r.f8()).map(|d| {
            device.set(d);
            &[][..]
        }),
        sk::op::RECOVERY_AUTHORISE => r
            .u32()
            .and_then(|_| r.f8())
            .map(|d| device.set(d))
            .and_then(|()| r.u32())
            .map(|_| &[][..]),
        sk::op::CREATE => r
            .f8()
            .and_then(|_| r.take(POLICY_LEN + 2 + 3 * sk::PUBLIC_LEN)),
        sk::op::RECORD_SET => r
            .u32()
            .and_then(|_| r.f16())
            .and_then(|_| r.f16())
            .and_then(|_| r.f16()),
        sk::op::ROTATE_KEY => r.take(3 * sk::PUBLIC_LEN),
        sk::op::RETIRE_EPOCH => r.u32().map(|_| &[][..]),
        sk::op::ERASE => r.u32().and_then(|_| r.u32()).map(|_| &[][..]),
        _ => Some(&[][..]),
    };
    if walked.is_some() {
        if let Some(a) = r.f8() {
            who.set(a);
        }
    }
    (device, who)
}

/// Answer the requester.
fn reply<H: Host>(cx: &mut Cx<'_, H>, op: &Op, audited: bool) {
    let release = op.code == sk::op::ATTACH || op.code == sk::op::RECOVER;
    // A release or renewal the audit trail does not hold is withheld.
    let refusal = match op.refusal {
        None if op.proven() && !audited => Some(Refusal::LedgerUnavailable),
        other => other,
    };
    let mut bundle = [0u8; sk::BUNDLE_LEN];
    let with_bundle = release && refusal.is_none() && op.env_count == 2;
    if with_bundle {
        bundle[..4].copy_from_slice(&sk::BUNDLE_MAGIC);
        bundle[4] = 2;
        bundle[sk::BUNDLE_HEADER..sk::BUNDLE_HEADER + sk::ENVELOPE_LEN]
            .copy_from_slice(&op.envs[0]);
        bundle[sk::BUNDLE_HEADER + sk::ENVELOPE_LEN..].copy_from_slice(&op.envs[1]);
        cx.stats.released = cx.stats.released.saturating_add(1);
    }
    let record: &[u8] = if refusal.is_none() {
        op.out.bytes()
    } else {
        &[]
    };
    let bundle: &[u8] = if with_bundle { &bundle } else { &[] };
    send_reply(cx, op.corr, op.code, refusal, audited, record, bundle, &[]);
}

/// Answer a request that never took a slot: no key, no clock, no room, or
/// a challenge. There is no decision about a resource to audit.
fn refuse_now<H: Host>(cx: &mut Cx<'_, H>, corr: u32, op: u8, refusal: Refusal) {
    cx.stats.refused = cx.stats.refused.saturating_add(1);
    send_reply(cx, corr, op, Some(refusal), false, &[], &[], &[]);
}

#[expect(clippy::too_many_arguments, reason = "one reply frame, field by field")]
fn send_reply<H: Host>(
    cx: &mut Cx<'_, H>,
    corr: u32,
    op: u8,
    refusal: Option<Refusal>,
    audited: bool,
    record: &[u8],
    bundle: &[u8],
    extra: &[u8],
) {
    let mut payload = [0u8; MAX_FRAME];
    let mut w = sk::Writer::new(&mut payload);
    let status = if refusal.is_some() {
        STATUS_REFUSED
    } else {
        STATUS_OK
    };
    let ok = w.u32(corr).is_some()
        && w.u8(op).is_some()
        && w.u8(status).is_some()
        && w.u8(refusal.map_or(0, Refusal::code)).is_some()
        && w.u8(u8::from(audited)).is_some()
        && w.f16(record).is_some()
        && w.f16(bundle).is_some()
        && w.f16(extra).is_some();
    if !ok {
        return;
    }
    let len = w.len();
    if let Ok(n) =
        auth_wire::write_envelope(msg::REPLY, payload.get(..len).unwrap_or(&[]), cx.frame)
    {
        let _ = cx.host.send(Port::Reply, cx.frame.get(..n).unwrap_or(&[]));
    }
}

// ── Ledger requests ─────────────────────────────────────────────────────

/// Which ledger record an operation reads or writes.
enum Key {
    Grant,
    Set(u32),
    Ticket([u8; 16]),
    Attachment([u8; 16]),
    Device([u8; sk::MAX_ID], usize),
}

/// Which of an operation's built records a write carries.
#[derive(Clone, Copy)]
enum Which {
    Out,
    Aux,
}

fn compose(op: &Op, key: &Key, out: &mut [u8; MAX_KEY]) -> Result<(u8, usize), Refusal> {
    let h = head(op.body())?;
    let (rk, res) = (h.resource_kind, h.resource);
    let (ns, n) = match key {
        Key::Grant => (
            state_wire::NS_STORAGE_GRANT,
            sk::resource_key(rk, &res, out),
        ),
        Key::Set(epoch) => (
            state_wire::NS_STORAGE_SET,
            sk::set_key(rk, &res, *epoch, out),
        ),
        Key::Ticket(t) => (
            state_wire::NS_STORAGE_TICKET,
            sk::ticket_key(rk, &res, t, out),
        ),
        Key::Attachment(a) => (
            state_wire::NS_STORAGE_ATTACHMENT,
            sk::attachment_key(rk, &res, a, out),
        ),
        Key::Device(d, n) => {
            let src = d.get(..*n).ok_or(Refusal::Malformed)?;
            out.get_mut(..*n)
                .ok_or(Refusal::Malformed)?
                .copy_from_slice(src);
            (state_wire::NS_DEVICE, Some(*n))
        }
    };
    Ok((ns, n.ok_or(Refusal::Malformed)?))
}

fn get<H: Host>(
    cx: &mut Cx<'_, H>,
    op: &mut Op,
    next: u8,
    key: &Key,
    now: u64,
) -> Result<(), Refusal> {
    let mut k = [0u8; MAX_KEY];
    let (ns, n) = compose(op, key, &mut k)?;
    let request = state_wire::get(op.icorr, STATE_CLIENT, ns, k.get(..n).unwrap_or(&[]));
    send_state(cx, op, state_wire::MSG_STATE_GET, &request, next, now)
}

fn put<H: Host>(
    cx: &mut Cx<'_, H>,
    op: &mut Op,
    next: u8,
    key: &Key,
    which: Which,
    now: u64,
) -> Result<(), Refusal> {
    let mut k = [0u8; MAX_KEY];
    let (ns, n) = compose(op, key, &mut k)?;
    let value = match which {
        Which::Out => op.out.bytes(),
        Which::Aux => op.aux.bytes(),
    };
    let request = state_wire::put_if_absent(
        op.icorr,
        STATE_CLIENT,
        ns,
        k.get(..n).unwrap_or(&[]),
        value,
        0,
    );
    let frame_len = state_wire::encode_request(cx.frame, state_wire::MSG_STATE_PUT_ABS, &request)
        .map_err(|_| Refusal::Malformed)?;
    commit_send(cx, op, frame_len, next, now)
}

fn cas<H: Host>(
    cx: &mut Cx<'_, H>,
    op: &mut Op,
    next: u8,
    key: &Key,
    which: Which,
    now: u64,
) -> Result<(), Refusal> {
    let mut k = [0u8; MAX_KEY];
    let (ns, n) = compose(op, key, &mut k)?;
    let value = match which {
        Which::Out => op.out.bytes(),
        Which::Aux => op.aux.bytes(),
    };
    let etag = match key {
        Key::Grant => op.grant.etag(),
        Key::Set(_) => op.set.etag(),
        Key::Ticket(_) => op.ticket.etag(),
        Key::Attachment(_) => op.chain.etag(),
        Key::Device(..) => return Err(Refusal::Malformed),
    };
    let request = state_wire::compare_and_swap(
        op.icorr,
        STATE_CLIENT,
        ns,
        k.get(..n).unwrap_or(&[]),
        etag,
        value,
        0,
    );
    let frame_len = state_wire::encode_request(cx.frame, state_wire::MSG_STATE_CAS, &request)
        .map_err(|_| Refusal::Malformed)?;
    commit_send(cx, op, frame_len, next, now)
}

fn delete<H: Host>(
    cx: &mut Cx<'_, H>,
    op: &mut Op,
    next: u8,
    key: &Key,
    now: u64,
) -> Result<(), Refusal> {
    let mut k = [0u8; MAX_KEY];
    let (ns, n) = compose(op, key, &mut k)?;
    let request = state_wire::StateRequest {
        correlation: op.icorr,
        client: STATE_CLIENT,
        namespace: ns,
        key: k.get(..n).unwrap_or(&[]),
        etag: op.set.etag(),
        value: &[],
        expiry_unix: 0,
    };
    let frame_len = state_wire::encode_request(cx.frame, state_wire::MSG_STATE_DELETE, &request)
        .map_err(|_| Refusal::Malformed)?;
    commit_send(cx, op, frame_len, next, now)
}

fn send_state<H: Host>(
    cx: &mut Cx<'_, H>,
    op: &mut Op,
    msg_type: u8,
    request: &state_wire::StateRequest<'_>,
    next: u8,
    now: u64,
) -> Result<(), Refusal> {
    let n =
        state_wire::encode_request(cx.frame, msg_type, request).map_err(|_| Refusal::Malformed)?;
    commit_send(cx, op, n, next, now)
}

/// Send the encoded frame at the front of `cx.frame` to the ledger and move
/// the operation to `next`.
fn commit_send<H: Host>(
    cx: &mut Cx<'_, H>,
    op: &mut Op,
    frame_len: usize,
    next: u8,
    now: u64,
) -> Result<(), Refusal> {
    if !cx
        .host
        .send(Port::Ledger, cx.frame.get(..frame_len).unwrap_or(&[]))
    {
        return Err(Refusal::LedgerUnavailable);
    }
    op.stage = next;
    op.deadline_ms = now.saturating_add(STAGE_TIMEOUT_MS);
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// A bounded identifier copy.
struct Name {
    b: [u8; sk::MAX_ID],
    n: usize,
}

impl Name {
    const fn empty() -> Self {
        Self {
            b: [0; sk::MAX_ID],
            n: 0,
        }
    }

    fn set(&mut self, v: &[u8]) {
        let n = v.len().min(sk::MAX_ID);
        if let (Some(dst), Some(src)) = (self.b.get_mut(..n), v.get(..n)) {
            dst.copy_from_slice(src);
            self.n = n;
        }
    }

    fn as_slice(&self) -> &[u8] {
        self.b.get(..self.n).unwrap_or(&[])
    }
}

fn read_status(status: u8) -> Result<(), Refusal> {
    match status {
        auth_wire::ST_OK => Ok(()),
        auth_wire::ST_NOT_FOUND => Err(Refusal::UnknownResource),
        auth_wire::ST_MALFORMED => Err(Refusal::Malformed),
        _ => Err(Refusal::LedgerUnavailable),
    }
}

fn write_status(status: u8) -> Result<(), Refusal> {
    match status {
        auth_wire::ST_OK => Ok(()),
        auth_wire::ST_CONFLICT => Err(Refusal::Conflict),
        auth_wire::ST_NOT_FOUND => Err(Refusal::UnknownResource),
        auth_wire::ST_MALFORMED => Err(Refusal::Malformed),
        _ => Err(Refusal::LedgerUnavailable),
    }
}

/// A record read back from the ledger is checked against this issuer's own
/// key: the ledger is durable storage, not a party to the decision, and a
/// record written there by anything else is not a grant.
fn verify_stored<H: Host>(host: &H, bytes: &[u8], want: u8) -> Result<(), Refusal> {
    if verify_kind(host, bytes)? != want {
        return Err(Refusal::Malformed);
    }
    Ok(())
}

/// Verify a record read back from the ledger, and say which kind it is.
fn verify_kind<H: Host>(host: &H, bytes: &[u8]) -> Result<u8, Refusal> {
    let rec = Record::parse(bytes)?;
    rec.verify(host.verify(), host.issuer_suite(), host.issuer_public())?;
    Ok(rec.binding.kind)
}

/// Sign a grant, carrying the epochs it retains: the count in its fixed
/// part, the list as its one item.
fn sign_grant<H: Host>(
    host: &mut H,
    out: &mut Built,
    g: &Binding,
    names: &sk::Names<'_>,
    retained: &sk::Retained,
) -> Result<(), Refusal> {
    let mut b = *g;
    b.retained = retained.count();
    let mut item = [0u8; sk::RETAINED_ITEM_MAX];
    let n = retained.write_item(&mut item);
    if n == 0 {
        return sign_into(host, out, &b, names, &[]);
    }
    sign_into(host, out, &b, names, &[item.get(..n).unwrap_or(&[])])
}

/// Write and sign a record into `out`.
fn sign_into<H: Host>(
    host: &mut H,
    out: &mut Built,
    b: &Binding,
    names: &sk::Names<'_>,
    items: &[&[u8]],
) -> Result<(), Refusal> {
    let suite = host.issuer_suite();
    let unsigned =
        sk::write_unsigned(&mut out.bytes, b, names, items, suite).ok_or(Refusal::Malformed)?;
    let mut sig = [0u8; sk::MAX_SIGNATURE];
    let n = host
        .sign(out.bytes.get(..unsigned).unwrap_or(&[]), &mut sig)
        .ok_or(Refusal::NoIssuerKey)?;
    let total = sig
        .get(..n)
        .and_then(|s| sk::append_signature(&mut out.bytes, unsigned, s))
        .ok_or(Refusal::NoIssuerKey)?;
    out.len = u16::try_from(total).map_err(|_| Refusal::Malformed)?;
    Ok(())
}

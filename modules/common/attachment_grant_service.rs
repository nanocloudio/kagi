//! The attachment-authorisation service: producer publications, consumer
//! grants and revocation (`attachment_grant.rs`), against the ledger's
//! per-service revocation generation.
//!
//! A state machine with no I/O of its own, like the other services: the
//! `attachment_authorize` module is its host. Each act reads the service's
//! revocation generation (`kagi/attachments/<producer>-<service>`) once:
//!
//! - **Publish** stamps the publication with it.
//! - **Request** refuses a publication from any other generation, so a
//!   revocation stops new grants under every earlier publication at once.
//! - **Revoke** advances it by compare-and-swap.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::attachment_grant::{self as ag, op, Actor, Attachment, Refusal};
use crate::auth_wire;
use crate::state_wire;

pub const STATE_CLIENT: u8 = 15;
pub const MAX_OPS: usize = 4;
pub const STAGE_TIMEOUT_MS: u64 = 10_000;
pub const MAX_REQUEST: usize = 6144;
pub const CALLER_LEN: usize = 14;
pub type Caller = [u8; CALLER_LEN];
pub const KID: &[u8] = b"attachment-grant";
pub const PEER_LEN: usize = 32;

const MAX_KEY: usize = 80;
const MAX_FRAME: usize = 3 + 64 + ag::MAX_RECORD;

/// What the service needs from wherever it runs.
pub trait Host {
    fn now_ms(&mut self) -> u64;
    fn random(&mut self, out: &mut [u8]) -> bool;
    fn sha256(&self) -> ag::Sha256Fn;
    fn verify(&self) -> ag::VerifyFn;
    fn issuer_suite(&self) -> u16;
    fn issuer_public(&self) -> &[u8];
    fn sign(&mut self, message: &[u8], signature: &mut [u8]) -> Option<usize>;
    /// The caller a cert-bound carrier proves, in this instance's own trust
    /// domain or a pinned federated one, bound to the link's SVID.
    fn authenticate(&mut self, carrier: &[u8], peer: Option<&[u8; PEER_LEN]>) -> Option<Actor>;
    fn send_ledger(&mut self, frame: &[u8]) -> bool;
    fn answer(&mut self, caller: &Caller, frame: &[u8]) -> bool;
}

#[derive(Clone, Copy)]
pub struct Stats {
    pub published: u32,
    pub granted: u32,
    pub revoked: u32,
    pub refused: u32,
    pub busy: u32,
}

mod stage {
    pub const GET_GENERATION: u8 = 1;
    pub const SET_GENERATION: u8 = 2;
}

/// What an operation decides once its generation is read.
#[derive(Clone, Copy)]
enum Pending {
    None,
    /// A verified publication and the request's own fields.
    Grant {
        publication: Attachment,
        publication_digest: [u8; 32],
        consumer_tenant: [u8; 16],
        attachment_generation: u64,
        quotas: ag::Quotas,
        ttl_ms: u64,
        actor: Actor,
    },
    /// A publication decided but for its generation.
    Publication(Attachment),
    /// The generation a revocation advances to.
    Revoke(u64),
}

struct Op {
    live: bool,
    code: u8,
    stage: u8,
    caller: Caller,
    corr: u32,
    deadline_ms: u64,
    producer_tenant: [u8; 16],
    service: [u8; 16],
    pending: Pending,
    generation: u64,
}

impl Op {
    const EMPTY: Self = Self {
        live: false,
        code: 0,
        stage: 0,
        caller: [0; CALLER_LEN],
        corr: 0,
        deadline_ms: 0,
        producer_tenant: [0; 16],
        service: [0; 16],
        pending: Pending::None,
        generation: 0,
    };
}

pub struct Service {
    issuer: [u8; ag::MAX_ID],
    issuer_len: usize,
    next_corr: u32,
    ops: [Op; MAX_OPS],
    pub stats: Stats,
}

macro_rules! must {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => return Some(Err(Refusal::Malformed)),
        }
    };
}

impl Service {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            issuer: [0; ag::MAX_ID],
            issuer_len: 0,
            next_corr: 1,
            ops: [Op::EMPTY; MAX_OPS],
            stats: Stats {
                published: 0,
                granted: 0,
                revoked: 0,
                refused: 0,
                busy: 0,
            },
        }
    }

    pub fn init(&mut self, issuer: &[u8]) {
        let n = issuer.len().min(ag::MAX_ID);
        for (d, s) in self.issuer.iter_mut().zip(issuer.iter().take(n)) {
            *d = *s;
        }
        self.issuer_len = n;
        self.next_corr = 1;
        for o in &mut self.ops {
            *o = Op::EMPTY;
        }
    }

    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.ops.iter().filter(|o| o.live).count()
    }

    /// A REQUEST payload arrived from `caller`, whose link authenticated
    /// `peer` (empty when none).
    pub fn on_request<H: Host>(
        &mut self,
        host: &mut H,
        caller: &Caller,
        peer: &[u8],
        payload: &[u8],
    ) {
        let Some((&code, body)) = payload.split_first() else {
            reply(host, caller, 0, Some(Refusal::Malformed), &[], 0);
            return;
        };
        let now = host.now_ms();
        let pre = if host.issuer_suite() == 0 {
            Some(Refusal::NoIssuerKey)
        } else if now == 0 {
            Some(Refusal::NoClock)
        } else if body.len() > MAX_REQUEST {
            Some(Refusal::Malformed)
        } else {
            None
        };
        if let Some(r) = pre {
            self.stats.refused = self.stats.refused.saturating_add(1);
            reply(host, caller, code, Some(r), &[], 0);
            return;
        }
        let svid: Option<[u8; PEER_LEN]> = <[u8; PEER_LEN]>::try_from(peer).ok();
        let started = match code {
            op::PUBLISH => start_publish(host, body, svid.as_ref(), now),
            op::REQUEST => start_request(
                host,
                self.issuer.get(..self.issuer_len).unwrap_or(&[]),
                body,
                svid.as_ref(),
                now,
            ),
            op::REVOKE => start_revoke(host, body, svid.as_ref()),
            _ => Err(Refusal::Malformed),
        };
        let mut op = match started {
            Ok(op) => op,
            Err(r) => {
                self.stats.refused = self.stats.refused.saturating_add(1);
                reply(host, caller, code, Some(r), &[], 0);
                return;
            }
        };
        let Some(slot) = self.ops.iter().position(|o| !o.live) else {
            self.stats.busy = self.stats.busy.saturating_add(1);
            reply(host, caller, code, Some(Refusal::Busy), &[], 0);
            return;
        };
        op.live = true;
        op.code = code;
        op.caller = *caller;
        op.corr = self.next_corr;
        self.next_corr = self.next_corr.wrapping_add(1).max(1);
        op.deadline_ms = now.saturating_add(STAGE_TIMEOUT_MS);
        op.stage = stage::GET_GENERATION;
        let mut key = [0u8; MAX_KEY];
        let sent =
            ag::generation_key(&op.producer_tenant, &op.service, &mut key).is_some_and(|n| {
                send(
                    host,
                    state_wire::MSG_STATE_GET,
                    &state_wire::get(
                        op.corr,
                        STATE_CLIENT,
                        state_wire::NS_ATTACHMENT,
                        key.get(..n).unwrap_or(&[]),
                    ),
                )
            });
        if !sent {
            self.stats.refused = self.stats.refused.saturating_add(1);
            reply(host, caller, code, Some(Refusal::LedgerUnavailable), &[], 0);
            return;
        }
        self.ops[slot] = op;
    }

    /// A ledger reply arrived.
    pub fn on_ledger<H: Host>(&mut self, host: &mut H, msg_type: u8, payload: &[u8]) {
        if msg_type != state_wire::MSG_STATE_VALUE && msg_type != state_wire::MSG_STATE_ACK {
            return;
        }
        let Ok(r) = state_wire::StateReply::decode(msg_type, payload) else {
            return;
        };
        if r.client != STATE_CLIENT {
            return;
        }
        let issuer = self.issuer;
        let issuer_len = self.issuer_len;
        let Some(op) = self
            .ops
            .iter_mut()
            .find(|o| o.live && o.corr == r.correlation)
        else {
            return;
        };
        let now = host.now_ms();
        let outcome = advance(
            host,
            op,
            issuer.get(..issuer_len).unwrap_or(&[]),
            r.status,
            r.etag,
            r.value,
            now,
        );
        if let Some((result, record, len)) = outcome.map(|o| match o {
            Ok((rec, n)) => (Ok(()), rec, n),
            Err(e) => (Err(e), [0u8; ag::MAX_RECORD], 0),
        }) {
            finish(
                host,
                op,
                &mut self.stats,
                result,
                record.get(..len).unwrap_or(&[]),
            );
        }
    }

    pub fn tick<H: Host>(&mut self, host: &mut H) {
        let now = host.now_ms();
        for op in &mut self.ops {
            if op.live && now != 0 && now > op.deadline_ms {
                finish(
                    host,
                    op,
                    &mut self.stats,
                    Err(Refusal::LedgerUnavailable),
                    &[],
                );
            }
        }
    }
}

impl Default for Service {
    fn default() -> Self {
        Self::new()
    }
}

fn start_publish<H: Host>(
    host: &mut H,
    body: &[u8],
    peer: Option<&[u8; PEER_LEN]>,
    now: u64,
) -> Result<Op, Refusal> {
    let req = ag::Publish::decode(body)?;
    let actor = host.authenticate(req.carrier, peer);
    // Decided now, at generation 0, so a refusal costs no ledger round trip;
    // the generation is stamped once it is read.
    let a = ag::decide_publish(host.sha256(), &req, actor, 0, now)?;
    let mut op = Op::EMPTY;
    op.producer_tenant = a.producer_tenant;
    op.service = a.service;
    op.pending = Pending::Publication(a);
    Ok(op)
}

fn start_request<H: Host>(
    host: &mut H,
    issuer: &[u8],
    body: &[u8],
    peer: Option<&[u8; PEER_LEN]>,
    now: u64,
) -> Result<Op, Refusal> {
    let req = ag::Request::decode(body)?;
    let rec = ag::Record::parse(req.publication)?;
    let suite = host.issuer_suite();
    let public = host.issuer_public();
    rec.verify(
        |i, kid| (i == issuer && kid == KID).then_some((suite, public)),
        host.verify(),
        now,
    )?;
    if rec.attachment.kind != ag::kind::PUBLICATION {
        return Err(Refusal::Malformed);
    }
    let publication_digest = ag::record_digest(host.sha256(), req.publication);
    let actor = host
        .authenticate(req.carrier, peer)
        .ok_or(Refusal::NotAuthenticated)?;
    // Everything but the generation, decided before the round trip.
    ag::decide_request(
        &req,
        &rec.attachment,
        Some(actor),
        rec.attachment.revocation_generation,
        [1; 16],
        now,
    )?;
    let mut op = Op::EMPTY;
    op.producer_tenant = req.producer_tenant;
    op.service = req.service;
    op.pending = Pending::Grant {
        publication: rec.attachment,
        publication_digest,
        consumer_tenant: req.consumer_tenant,
        attachment_generation: req.attachment_generation,
        quotas: req.quotas,
        ttl_ms: req.ttl_ms,
        actor,
    };
    Ok(op)
}

fn start_revoke<H: Host>(
    host: &mut H,
    body: &[u8],
    peer: Option<&[u8; PEER_LEN]>,
) -> Result<Op, Refusal> {
    let mut r = crate::storage_key::Reader::new(body);
    let (Some(producer_tenant), Some(service), Some(generation), Some(carrier)) =
        (r.arr::<16>(), r.arr::<16>(), r.u64(), r.f16())
    else {
        return Err(Refusal::Malformed);
    };
    if r.remaining() != 0 {
        return Err(Refusal::Malformed);
    }
    let actor = host
        .authenticate(carrier, peer)
        .ok_or(Refusal::NotAuthenticated)?;
    // The producer side's act: a workload, service or operator of this
    // instance's own domain.
    if !matches!(
        actor.class,
        ag::class::WORKLOAD | ag::class::SERVICE | ag::class::OPERATOR
    ) {
        return Err(Refusal::ActorNotPermitted);
    }
    if !actor.local {
        return Err(Refusal::ForeignProducer);
    }
    let mut op = Op::EMPTY;
    op.producer_tenant = producer_tenant;
    op.service = service;
    op.pending = Pending::Revoke(generation);
    Ok(op)
}

fn send<H: Host>(host: &mut H, msg_type: u8, req: &state_wire::StateRequest<'_>) -> bool {
    let mut frame = [0u8; 3 + 32 + state_wire::MAX_KEY + state_wire::MAX_ETAG + 64];
    match state_wire::encode_request(&mut frame, msg_type, req) {
        Ok(n) => host.send_ledger(frame.get(..n).unwrap_or(&[])),
        Err(_) => false,
    }
}

type Signed = ([u8; ag::MAX_RECORD], usize);

/// One step on a ledger answer. `Some` ends the operation, with the signed
/// record on success.
fn advance<H: Host>(
    host: &mut H,
    op: &mut Op,
    issuer: &[u8],
    status: u8,
    etag: &[u8],
    value: &[u8],
    now: u64,
) -> Option<Result<Signed, Refusal>> {
    let unavailable = Some(Err(Refusal::LedgerUnavailable));
    match op.stage {
        stage::GET_GENERATION => {
            let current = match status {
                auth_wire::ST_OK => must!(ag::decode_generation(value)),
                auth_wire::ST_NOT_FOUND => 0,
                _ => return unavailable,
            };
            op.generation = current;
            match op.pending {
                Pending::Publication(mut a) => {
                    a.revocation_generation = current;
                    Some(sign(host, &a, issuer))
                }
                Pending::Grant {
                    publication,
                    publication_digest,
                    consumer_tenant,
                    attachment_generation,
                    quotas,
                    ttl_ms,
                    actor,
                } => {
                    let mut id = [0u8; 16];
                    if !host.random(&mut id) {
                        return Some(Err(Refusal::Busy));
                    }
                    let req = ag::Request {
                        publication: &[],
                        producer_tenant: publication.producer_tenant,
                        service: publication.service,
                        consumer_tenant,
                        attachment_generation,
                        quotas,
                        ttl_ms,
                        carrier: &[],
                    };
                    let mut g =
                        match ag::decide_request(&req, &publication, Some(actor), current, id, now)
                        {
                            Ok(g) => g,
                            Err(e) => return Some(Err(e)),
                        };
                    g.publication = publication_digest;
                    Some(sign(host, &g, issuer))
                }
                Pending::Revoke(target) => {
                    if target <= current {
                        return Some(Err(Refusal::GenerationNotAdvanced));
                    }
                    let value = ag::encode_generation(target);
                    let mut key = [0u8; MAX_KEY];
                    let n = must!(ag::generation_key(
                        &op.producer_tenant,
                        &op.service,
                        &mut key
                    ));
                    let key = must!(key.get(..n));
                    op.stage = stage::SET_GENERATION;
                    let (msg, req) = if status == auth_wire::ST_OK {
                        (
                            state_wire::MSG_STATE_CAS,
                            state_wire::compare_and_swap(
                                op.corr,
                                STATE_CLIENT,
                                state_wire::NS_ATTACHMENT,
                                key,
                                etag,
                                &value,
                                0,
                            ),
                        )
                    } else {
                        (
                            state_wire::MSG_STATE_PUT_ABS,
                            state_wire::put_if_absent(
                                op.corr,
                                STATE_CLIENT,
                                state_wire::NS_ATTACHMENT,
                                key,
                                &value,
                                0,
                            ),
                        )
                    };
                    if send(host, msg, &req) {
                        op.generation = target;
                        None
                    } else {
                        unavailable
                    }
                }
                Pending::None => Some(Err(Refusal::Malformed)),
            }
        }
        stage::SET_GENERATION => match status {
            auth_wire::ST_OK => Some(Ok(([0; ag::MAX_RECORD], 0))),
            auth_wire::ST_CONFLICT => Some(Err(Refusal::Conflict)),
            _ => unavailable,
        },
        _ => Some(Err(Refusal::Malformed)),
    }
}

fn sign<H: Host>(host: &mut H, a: &Attachment, issuer: &[u8]) -> Result<Signed, Refusal> {
    let suite = host.issuer_suite();
    let mut out = [0u8; ag::MAX_RECORD];
    let unsigned = ag::write_unsigned(&mut out, a, &ag::Signer { issuer, kid: KID }, suite)
        .ok_or(Refusal::Malformed)?;
    let mut signature = [0u8; ag::MAX_SIGNATURE];
    let n = host
        .sign(out.get(..unsigned).unwrap_or(&[]), &mut signature)
        .ok_or(Refusal::NoIssuerKey)?;
    let len = ag::append_signature(&mut out, unsigned, signature.get(..n).unwrap_or(&[]))
        .ok_or(Refusal::Malformed)?;
    Ok((out, len))
}

fn finish<H: Host>(
    host: &mut H,
    op: &mut Op,
    stats: &mut Stats,
    result: Result<(), Refusal>,
    record: &[u8],
) {
    let refusal = result.err();
    match (refusal, op.code) {
        (None, op::PUBLISH) => stats.published = stats.published.saturating_add(1),
        (None, op::REQUEST) => stats.granted = stats.granted.saturating_add(1),
        (None, op::REVOKE) => stats.revoked = stats.revoked.saturating_add(1),
        _ => stats.refused = stats.refused.saturating_add(1),
    }
    let caller = op.caller;
    reply(host, &caller, op.code, refusal, record, op.generation);
    *op = Op::EMPTY;
}

fn reply<H: Host>(
    host: &mut H,
    caller: &Caller,
    code: u8,
    refusal: Option<Refusal>,
    record: &[u8],
    generation: u64,
) {
    let mut payload = [0u8; MAX_FRAME];
    let Some(n) = ag::write_reply(code, refusal, record, generation, &mut payload) else {
        return;
    };
    let mut frame = [0u8; MAX_FRAME + 3];
    if let Ok(m) =
        auth_wire::write_envelope(ag::msg::REPLY, payload.get(..n).unwrap_or(&[]), &mut frame)
    {
        host.answer(caller, frame.get(..m).unwrap_or(&[]));
    }
}

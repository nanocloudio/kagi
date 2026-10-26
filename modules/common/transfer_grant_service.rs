//! The transfer-grant service: issue, consume and invalidate key-custody
//! transfer grants (`transfer_grant.rs`) against the security-state ledger.
//!
//! A state machine that does no I/O of its own, like `storage_key_service`:
//! the `transfer_grant` module is its host, and a host suite drives the same
//! code against a modelled ledger.
//!
//! - **Issue.** The source host authenticates; its request is decided
//!   (`transfer_grant::decide_issue`); the current recovery generation is
//!   read; the grant is stamped with it and a fresh nonce, signed, and its
//!   state created in the ledger — create-if-absent, so a nonce is claimed
//!   exactly once — before it is answered.
//! - **Consume.** The source host presents its grant before its vault wraps.
//!   The grant must verify under this issuer's key, name the caller as
//!   source, carry the current generation, and be `ISSUED` in the ledger;
//!   a compare-and-swap moves it to `CONSUMED`, or to `EXPIRED` when it is
//!   past its expiry. A second consume finds it `CONSUMED`.
//! - **Invalidate.** An operator advances the recovery generation after an
//!   unsafe directory recovery. Every grant issued under an earlier
//!   generation is refused from then on (`Invalidated`), without the ledger
//!   enumerating them.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::auth_wire;
use crate::state_wire;
use crate::transfer_grant::{self as tg, op, Grant, Policy, Refusal};

/// The ledger client id this service writes under.
pub const STATE_CLIENT: u8 = 14;
pub const MAX_OPS: usize = 4;
pub const STAGE_TIMEOUT_MS: u64 = 10_000;
pub const MAX_REQUEST: usize = 6144;
pub const CALLER_LEN: usize = 14;
pub type Caller = [u8; CALLER_LEN];
/// The kid every grant names.
pub const KID: &[u8] = b"transfer-grant";
/// An SVID's length.
pub const PEER_LEN: usize = 32;
/// `spiffe::Class` codes, restated.
pub const CLASS_HOST: u8 = 4;
pub const CLASS_OPERATOR: u8 = 5;

const MAX_KEY: usize = 80;
const MAX_FRAME: usize = 3 + 64 + tg::MAX_RECORD;

/// What the service needs from wherever it runs.
pub trait Host {
    /// Wall-clock Unix milliseconds; 0 when no trustworthy clock exists.
    fn now_ms(&mut self) -> u64;
    fn random(&mut self, out: &mut [u8]) -> bool;
    fn sha256(&self) -> tg::Sha256Fn;
    fn verify(&self) -> tg::VerifyFn;
    /// The grant key's suite, 0 when no key is loaded.
    fn issuer_suite(&self) -> u16;
    fn issuer_public(&self) -> &[u8];
    fn sign(&mut self, message: &[u8], signature: &mut [u8]) -> Option<usize>;
    /// The authenticated `(class, id)` a cert-bound carrier proves, bound to
    /// the exchange's verified SVID when there is one.
    fn authenticate(
        &mut self,
        carrier: &[u8],
        peer: Option<&[u8; PEER_LEN]>,
    ) -> Option<(u8, [u8; 16])>;
    /// The `(suite, public)` of `leaf` when it chains to the authority and
    /// its SPIFFE name is the host `host_id`. The key is copied into `out`;
    /// the answer is its suite and length.
    fn host_leaf_key(
        &self,
        leaf: &[u8],
        host_id: &[u8; 16],
        out: &mut [u8; 65],
    ) -> Option<(u16, usize)>;
    /// Write one whole `[type][len][payload]` frame to the ledger.
    fn send_ledger(&mut self, frame: &[u8]) -> bool;
    /// Answer `caller` with one whole REPLY envelope.
    fn answer(&mut self, caller: &Caller, frame: &[u8]) -> bool;
}

#[derive(Clone, Copy)]
pub struct Stats {
    pub issued: u32,
    pub consumed: u32,
    pub refused: u32,
    pub invalidated: u32,
    pub busy: u32,
}

mod stage {
    pub const GET_GENERATION: u8 = 1;
    pub const CLAIM: u8 = 2;
    pub const GET_STATE: u8 = 3;
    pub const MARK: u8 = 4;
    pub const SET_GENERATION: u8 = 5;
}

struct Op {
    live: bool,
    code: u8,
    stage: u8,
    caller: Caller,
    corr: u32,
    deadline_ms: u64,
    grant: Grant,
    record: [u8; tg::MAX_RECORD],
    record_len: usize,
    etag: [u8; state_wire::MAX_ETAG],
    etag_len: usize,
    generation: u64,
    /// The generation an invalidation advances to.
    target_generation: u64,
    /// The outcome a MARK stage reports once its write lands.
    pending: Option<Refusal>,
}

impl Op {
    const EMPTY: Self = Self {
        live: false,
        code: 0,
        stage: 0,
        caller: [0; CALLER_LEN],
        corr: 0,
        deadline_ms: 0,
        grant: Grant::empty(),
        record: [0; tg::MAX_RECORD],
        record_len: 0,
        etag: [0; state_wire::MAX_ETAG],
        etag_len: 0,
        generation: 0,
        target_generation: 0,
        pending: None,
    };
}

/// The service.
pub struct Service {
    issuer: [u8; tg::MAX_ID],
    issuer_len: usize,
    policy: Policy,
    next_corr: u32,
    ops: [Op; MAX_OPS],
    pub stats: Stats,
}

impl Service {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            issuer: [0; tg::MAX_ID],
            issuer_len: 0,
            policy: Policy {
                allow_possession: false,
                min_tier: 1,
            },
            next_corr: 1,
            ops: [Op::EMPTY; MAX_OPS],
            stats: Stats {
                issued: 0,
                consumed: 0,
                refused: 0,
                invalidated: 0,
                busy: 0,
            },
        }
    }

    /// Initialise in place.
    pub fn init(&mut self, issuer: &[u8], policy: Policy) {
        let n = issuer.len().min(tg::MAX_ID);
        for (d, s) in self.issuer.iter_mut().zip(issuer.iter().take(n)) {
            *d = *s;
        }
        self.issuer_len = n;
        self.policy = policy;
        self.next_corr = 1;
        for o in &mut self.ops {
            *o = Op::EMPTY;
        }
    }

    fn issuer(&self) -> &[u8] {
        self.issuer.get(..self.issuer_len).unwrap_or(&[])
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
            op::ISSUE => self.start_issue(host, body, svid.as_ref(), now),
            op::CONSUME => self.start_consume(host, body, svid.as_ref(), now),
            op::INVALIDATE => Self::start_invalidate(host, body, svid.as_ref()),
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
        let key_ok = send(
            host,
            &op,
            state_wire::MSG_STATE_GET,
            &state_wire::get(
                op.corr,
                STATE_CLIENT,
                state_wire::NS_TRANSFER_GRANT,
                tg::GENERATION_KEY,
            ),
        );
        if !key_ok {
            self.stats.refused = self.stats.refused.saturating_add(1);
            reply(host, caller, code, Some(Refusal::LedgerUnavailable), &[], 0);
            return;
        }
        self.ops[slot] = op;
    }

    fn start_issue<H: Host>(
        &self,
        host: &mut H,
        body: &[u8],
        peer: Option<&[u8; PEER_LEN]>,
        now: u64,
    ) -> Result<Op, Refusal> {
        let req = tg::IssueRequest::decode(body)?;
        let requester = host.authenticate(req.carrier, peer);
        let mut dest = [0u8; 65];
        let dest_key = host.host_leaf_key(req.destination_leaf, &req.destination, &mut dest);
        let dest_key = match dest_key {
            Some((suite, n)) => Some((suite, dest.get(..n).ok_or(Refusal::Malformed)?)),
            None => None,
        };
        let grant = tg::decide_issue(
            host.sha256(),
            host.verify(),
            &self.policy,
            &req,
            requester,
            dest_key,
            CLASS_HOST,
            now,
        )?;
        let mut op = Op::EMPTY;
        op.grant = grant;
        if !host.random(&mut op.grant.nonce) {
            return Err(Refusal::Busy);
        }
        Ok(op)
    }

    fn start_consume<H: Host>(
        &self,
        host: &mut H,
        body: &[u8],
        peer: Option<&[u8; PEER_LEN]>,
        now: u64,
    ) -> Result<Op, Refusal> {
        let mut r = tg::Reader::new(body);
        let (Some(record), Some(carrier)) = (r.f16(), r.f16()) else {
            return Err(Refusal::Malformed);
        };
        if r.remaining() != 0 || record.len() > tg::MAX_RECORD {
            return Err(Refusal::Malformed);
        }
        let (class, id) = host
            .authenticate(carrier, peer)
            .ok_or(Refusal::NotAuthenticated)?;
        let rec = tg::Record::parse(record)?;
        let issuer = self.issuer();
        let suite = host.issuer_suite();
        let public = host.issuer_public();
        // Verified at the window only for its signature here: an expired
        // grant still reaches the ledger, which records it EXPIRED.
        let verified = rec.verify(
            |i, kid| (i == issuer && kid == KID).then_some((suite, public)),
            host.verify(),
            now,
        );
        match verified {
            Ok(()) | Err(Refusal::Expired) => {}
            Err(e) => return Err(e),
        }
        if class != CLASS_HOST || id != rec.grant.source {
            return Err(Refusal::NotSource);
        }
        let mut op = Op::EMPTY;
        op.grant = rec.grant;
        for (d, s) in op.record.iter_mut().zip(record) {
            *d = *s;
        }
        op.record_len = record.len();
        Ok(op)
    }

    fn start_invalidate<H: Host>(
        host: &mut H,
        body: &[u8],
        peer: Option<&[u8; PEER_LEN]>,
    ) -> Result<Op, Refusal> {
        let mut r = tg::Reader::new(body);
        let (Some(generation), Some(carrier)) = (r.u64(), r.f16()) else {
            return Err(Refusal::Malformed);
        };
        if r.remaining() != 0 {
            return Err(Refusal::Malformed);
        }
        let (class, _) = host
            .authenticate(carrier, peer)
            .ok_or(Refusal::NotAuthenticated)?;
        if class != CLASS_OPERATOR {
            return Err(Refusal::NotOperator);
        }
        let mut op = Op::EMPTY;
        op.target_generation = generation;
        Ok(op)
    }

    /// A ledger reply arrived.
    pub fn on_ledger<H: Host>(&mut self, host: &mut H, msg_type: u8, payload: &[u8]) {
        if msg_type != state_wire::MSG_STATE_VALUE && msg_type != state_wire::MSG_STATE_ACK {
            return;
        }
        let Ok(reply_msg) = state_wire::StateReply::decode(msg_type, payload) else {
            return;
        };
        if reply_msg.client != STATE_CLIENT {
            return;
        }
        let issuer_len = self.issuer_len;
        let issuer = self.issuer;
        let Some(op) = self
            .ops
            .iter_mut()
            .find(|o| o.live && o.corr == reply_msg.correlation)
        else {
            return;
        };
        let now = host.now_ms();
        let outcome = advance(
            host,
            op,
            issuer.get(..issuer_len).unwrap_or(&[]),
            reply_msg.status,
            reply_msg.etag,
            reply_msg.value,
            now,
        );
        if let Some(result) = outcome {
            finish(host, op, &mut self.stats, result);
        }
    }

    /// Expire operations whose ledger stage outlived its deadline.
    pub fn tick<H: Host>(&mut self, host: &mut H) {
        let now = host.now_ms();
        for op in &mut self.ops {
            if op.live && now != 0 && now > op.deadline_ms {
                finish(host, op, &mut self.stats, Err(Refusal::LedgerUnavailable));
            }
        }
    }
}

impl Default for Service {
    fn default() -> Self {
        Self::new()
    }
}

/// Send one ledger request for `op`.
fn send<H: Host>(host: &mut H, _op: &Op, msg_type: u8, req: &state_wire::StateRequest<'_>) -> bool {
    let mut frame = [0u8; 3 + 32 + state_wire::MAX_KEY + state_wire::MAX_ETAG + 256];
    match state_wire::encode_request(&mut frame, msg_type, req) {
        Ok(n) => host.send_ledger(frame.get(..n).unwrap_or(&[])),
        Err(_) => false,
    }
}

fn state_key(g: &Grant, out: &mut [u8; MAX_KEY]) -> Option<usize> {
    tg::state_key(&g.flow, &g.nonce, out)
}

/// An `Option` that must hold inside [`advance`]: a `None` there ends the
/// operation as malformed. A bare `?` would return `None`, which `advance`
/// means as "not finished", and leave the operation to time out.
macro_rules! must {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => return Some(Err(Refusal::Malformed)),
        }
    };
}

/// One step of `op` on a ledger answer. `Some` ends it.
fn advance<H: Host>(
    host: &mut H,
    op: &mut Op,
    issuer: &[u8],
    status: u8,
    etag: &[u8],
    value: &[u8],
    now: u64,
) -> Option<Result<(), Refusal>> {
    let unavailable = Some(Err(Refusal::LedgerUnavailable));
    match op.stage {
        stage::GET_GENERATION => {
            let current = match status {
                auth_wire::ST_OK => must!(tg::decode_generation(value)),
                auth_wire::ST_NOT_FOUND => 0,
                _ => return unavailable,
            };
            let etag_len = etag.len().min(state_wire::MAX_ETAG);
            for (d, s) in op.etag.iter_mut().zip(etag.iter().take(etag_len)) {
                *d = *s;
            }
            op.etag_len = if status == auth_wire::ST_OK {
                etag_len
            } else {
                0
            };
            op.generation = current;
            match op.code {
                op::ISSUE => {
                    op.grant.generation = current;
                    let n = match sign(host, &op.grant, issuer, &mut op.record) {
                        Ok(n) => n,
                        Err(r) => return Some(Err(r)),
                    };
                    op.record_len = n;
                    let mut st = [0u8; tg::STATE_LEN];
                    tg::State {
                        state: tg::state::ISSUED,
                        generation: current,
                        expiry_ms: op.grant.expiry_ms,
                        digest: tg::record_digest(host.sha256(), must!(op.record.get(..n))),
                    }
                    .encode(&mut st);
                    let mut key = [0u8; MAX_KEY];
                    let kn = must!(state_key(&op.grant, &mut key));
                    op.stage = stage::CLAIM;
                    let ok = send(
                        host,
                        op,
                        state_wire::MSG_STATE_PUT_ABS,
                        &state_wire::put_if_absent(
                            op.corr,
                            STATE_CLIENT,
                            state_wire::NS_TRANSFER_GRANT,
                            must!(key.get(..kn)),
                            &st,
                            op.grant.expiry_ms / 1000 + 60,
                        ),
                    );
                    if ok {
                        None
                    } else {
                        unavailable
                    }
                }
                op::CONSUME => {
                    if op.grant.generation != current {
                        return Some(Err(Refusal::Invalidated));
                    }
                    let mut key = [0u8; MAX_KEY];
                    let kn = must!(state_key(&op.grant, &mut key));
                    op.stage = stage::GET_STATE;
                    let ok = send(
                        host,
                        op,
                        state_wire::MSG_STATE_GET,
                        &state_wire::get(
                            op.corr,
                            STATE_CLIENT,
                            state_wire::NS_TRANSFER_GRANT,
                            must!(key.get(..kn)),
                        ),
                    );
                    if ok {
                        None
                    } else {
                        unavailable
                    }
                }
                op::INVALIDATE => {
                    if op.target_generation <= current {
                        return Some(Err(Refusal::GenerationNotAdvanced));
                    }
                    let value = tg::encode_generation(op.target_generation);
                    op.stage = stage::SET_GENERATION;
                    let req = if status == auth_wire::ST_OK {
                        state_wire::compare_and_swap(
                            op.corr,
                            STATE_CLIENT,
                            state_wire::NS_TRANSFER_GRANT,
                            tg::GENERATION_KEY,
                            must!(op.etag.get(..op.etag_len)),
                            &value,
                            0,
                        )
                    } else {
                        state_wire::put_if_absent(
                            op.corr,
                            STATE_CLIENT,
                            state_wire::NS_TRANSFER_GRANT,
                            tg::GENERATION_KEY,
                            &value,
                            0,
                        )
                    };
                    let msg = if status == auth_wire::ST_OK {
                        state_wire::MSG_STATE_CAS
                    } else {
                        state_wire::MSG_STATE_PUT_ABS
                    };
                    if send(host, op, msg, &req) {
                        None
                    } else {
                        unavailable
                    }
                }
                _ => Some(Err(Refusal::Malformed)),
            }
        }
        stage::CLAIM => match status {
            auth_wire::ST_OK => Some(Ok(())),
            // A nonce already claimed: the CSPRNG repeated, or a replay of
            // the write. Either way this grant is not the one recorded.
            auth_wire::ST_CONFLICT => Some(Err(Refusal::Conflict)),
            _ => unavailable,
        },
        stage::GET_STATE => {
            let st = match status {
                auth_wire::ST_OK => match tg::State::decode(value) {
                    Some(st) => st,
                    None => return Some(Err(Refusal::UnknownGrant)),
                },
                auth_wire::ST_NOT_FOUND => return Some(Err(Refusal::UnknownGrant)),
                _ => return unavailable,
            };
            let digest = tg::record_digest(host.sha256(), must!(op.record.get(..op.record_len)));
            if st.digest != digest || st.generation != op.grant.generation {
                return Some(Err(Refusal::UnknownGrant));
            }
            match st.state {
                tg::state::CONSUMED => return Some(Err(Refusal::Replayed)),
                tg::state::EXPIRED => return Some(Err(Refusal::Expired)),
                _ => {}
            }
            let expired = now >= op.grant.expiry_ms;
            let next = tg::State {
                state: if expired {
                    tg::state::EXPIRED
                } else {
                    tg::state::CONSUMED
                },
                ..st
            };
            op.pending = expired.then_some(Refusal::Expired);
            let mut buf = [0u8; tg::STATE_LEN];
            next.encode(&mut buf);
            let mut key = [0u8; MAX_KEY];
            let kn = must!(state_key(&op.grant, &mut key));
            op.stage = stage::MARK;
            let ok = send(
                host,
                op,
                state_wire::MSG_STATE_CAS,
                &state_wire::compare_and_swap(
                    op.corr,
                    STATE_CLIENT,
                    state_wire::NS_TRANSFER_GRANT,
                    must!(key.get(..kn)),
                    etag,
                    &buf,
                    op.grant.expiry_ms / 1000 + 60,
                ),
            );
            if ok {
                None
            } else {
                unavailable
            }
        }
        stage::MARK => match status {
            auth_wire::ST_OK => Some(op.pending.map_or(Ok(()), Err)),
            // Another consume won the swap: this one is the replay.
            auth_wire::ST_CONFLICT => Some(Err(Refusal::Replayed)),
            _ => unavailable,
        },
        stage::SET_GENERATION => match status {
            auth_wire::ST_OK => {
                op.generation = op.target_generation;
                Some(Ok(()))
            }
            auth_wire::ST_CONFLICT => Some(Err(Refusal::Conflict)),
            _ => unavailable,
        },
        _ => Some(Err(Refusal::Malformed)),
    }
}

/// Sign `g` under the host's key into `out`.
fn sign<H: Host>(
    host: &mut H,
    g: &Grant,
    issuer: &[u8],
    out: &mut [u8; tg::MAX_RECORD],
) -> Result<usize, Refusal> {
    let suite = host.issuer_suite();
    let unsigned = tg::write_unsigned(out, g, &tg::Signer { issuer, kid: KID }, suite)
        .ok_or(Refusal::Malformed)?;
    let mut message = [0u8; tg::MAX_RECORD];
    for (d, s) in message.iter_mut().zip(out.iter().take(unsigned)) {
        *d = *s;
    }
    let mut signature = [0u8; tg::MAX_SIGNATURE];
    let n = host
        .sign(message.get(..unsigned).unwrap_or(&[]), &mut signature)
        .ok_or(Refusal::NoIssuerKey)?;
    tg::append_signature(out, unsigned, signature.get(..n).unwrap_or(&[])).ok_or(Refusal::Malformed)
}

fn finish<H: Host>(host: &mut H, op: &mut Op, stats: &mut Stats, result: Result<(), Refusal>) {
    let refusal = result.err();
    match (refusal, op.code) {
        (None, op::ISSUE) => stats.issued = stats.issued.saturating_add(1),
        (None, op::CONSUME) => stats.consumed = stats.consumed.saturating_add(1),
        (None, op::INVALIDATE) => stats.invalidated = stats.invalidated.saturating_add(1),
        _ => stats.refused = stats.refused.saturating_add(1),
    }
    let record: &[u8] = if op.code == op::ISSUE {
        op.record.get(..op.record_len).unwrap_or(&[])
    } else {
        &[]
    };
    let caller = op.caller;
    let code = op.code;
    let generation = op.generation;
    reply(host, &caller, code, refusal, record, generation);
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
    let Some(n) = tg::write_reply(code, refusal, record, generation, &mut payload) else {
        return;
    };
    let mut frame = [0u8; MAX_FRAME + 3];
    if let Ok(m) =
        auth_wire::write_envelope(tg::msg::REPLY, payload.get(..n).unwrap_or(&[]), &mut frame)
    {
        host.answer(caller, frame.get(..m).unwrap_or(&[]));
    }
}

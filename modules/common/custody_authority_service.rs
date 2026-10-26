//! The continuity authority a Fluxor `TRANSPORT_CONTINUITY` provider asks
//! (its `auth_req` / `auth_rsp`), as a state machine with no I/O of its own:
//! the `custody_authority` module is its host, and a host suite drives the
//! same code against a modelled ledger.
//!
//! A provider asks two questions before it acts on a flow:
//!
//! - **May this recipient receive this flow's continuity key?** (custody
//!   check, `0xC4`): decided here (`transfer_grant::decide_custody_check` —
//!   an enrolled standby host's identity key signed evidence over the
//!   transfer's challenge, meeting the custody the policy demands), the
//!   recovery generation read from the ledger and stamped, the grant (a
//!   `KTGR`, this transfer's) signed, and its single-use state written
//!   CONSUMED create-if-absent under `(flow, nonce)` — the nonce is the
//!   challenge's, so the same transfer is granted once and a replay of its
//!   evidence finds it claimed. Only then the verdict accepts (`0xC5`, 0);
//!   the signed grant goes out on `grant_out` for audit. Anything else —
//!   no clock, no key, an unknown signer, insufficient custody, a claimed
//!   nonce, the ledger silent past [`STAGE_TIMEOUT_MS`] — refuses, failing
//!   closed.
//! - **Is this the per-flow emission token the authority minted?** (token
//!   check, `0xC2`): Clustor's session directory's question
//!   (`session_directory` answers it from its committed registries). It is
//!   relayed whole on `token_out` and its verdict (`0xC3`) back, so one
//!   module is the provider's whole authority.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::auth_wire;
use crate::state_wire;
use crate::transfer_grant::{
    self as tg, CustodyCheck, EnrolledHost, Grant, Policy, Refusal, CUSTODY_VERDICT_LEN,
    MSG_CUSTODY_CHECK, MSG_CUSTODY_VERDICT,
};

/// The ledger client id this authority writes under (the transfer-grant
/// service's: the two share the `kagi/transfer-grants/` namespace and its
/// recovery generation).
pub const STATE_CLIENT: u8 = 14;
/// Checks in flight at once; one more is refused `Busy`.
pub const MAX_OPS: usize = 4;
pub const STAGE_TIMEOUT_MS: u64 = 10_000;
/// Standby hosts one authority knows.
pub const MAX_HOSTS: usize = 8;
/// The kid every grant names (the transfer-grant service's).
pub const KID: &[u8] = b"transfer-grant";
/// Fluxor's token-check frame ids (`TCS_MSG_TOKEN_CHECK` / `_VERDICT`).
pub const MSG_TOKEN_CHECK: u8 = 0xC2;
pub const MSG_TOKEN_VERDICT: u8 = 0xC3;
/// The frame a granted `KTGR` record leaves on `grant_out` as.
pub const MSG_KTGR_RECORD: u8 = 0x4B;

const MAX_KEY: usize = 80;

/// What the authority needs from wherever it runs.
pub trait Host {
    /// Wall-clock Unix milliseconds; 0 when no trustworthy clock exists.
    fn now_ms(&mut self) -> u64;
    fn sha256(&self) -> tg::Sha256Fn;
    fn verify(&self) -> tg::VerifyFn;
    /// The grant key's suite, 0 when no key is loaded.
    fn issuer_suite(&self) -> u16;
    fn sign(&mut self, message: &[u8], signature: &mut [u8]) -> Option<usize>;
    /// One whole `[type][len][payload]` frame to the ledger.
    fn send_ledger(&mut self, frame: &[u8]) -> bool;
    /// One whole frame to the provider (`auth_rsp`).
    fn send_provider(&mut self, frame: &[u8]) -> bool;
    /// One whole frame to the directory (`requests`).
    fn send_token(&mut self, frame: &[u8]) -> bool;
    /// One signed grant record (audit).
    fn send_grant(&mut self, record: &[u8]) -> bool;
}

#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub granted: u32,
    pub refused: u32,
    pub replayed: u32,
    pub tokens_relayed: u32,
    pub verdicts_relayed: u32,
    pub busy: u32,
}

mod stage {
    pub const GET_GENERATION: u8 = 1;
    pub const CLAIM: u8 = 2;
}

#[derive(Clone, Copy)]
struct Op {
    live: bool,
    stage: u8,
    corr: u32,
    deadline_ms: u64,
    flow: [u8; 16],
    evidence_digest: [u8; 32],
    grant: Grant,
    record: [u8; tg::MAX_RECORD],
    record_len: usize,
}

impl Op {
    const EMPTY: Self = Self {
        live: false,
        stage: 0,
        corr: 0,
        deadline_ms: 0,
        flow: [0; 16],
        evidence_digest: [0; 32],
        grant: Grant::empty(),
        record: [0; tg::MAX_RECORD],
        record_len: 0,
    };
}

/// The authority's configuration.
#[derive(Clone, Copy)]
pub struct Config {
    /// This host: the source every check here is from.
    pub source: [u8; 16],
    pub hosts: [EnrolledHost; MAX_HOSTS],
    pub host_count: usize,
    pub policy: Policy,
    pub ttl_ms: u64,
    pub issuer: [u8; tg::MAX_ID],
    pub issuer_len: usize,
}

impl Config {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            source: [0; 16],
            hosts: [EnrolledHost {
                id: [0; 16],
                public: [0; 65],
            }; MAX_HOSTS],
            host_count: 0,
            policy: Policy {
                allow_possession: false,
                min_tier: 1,
            },
            ttl_ms: tg::TRANSFER_GRANT_TTL_MS,
            issuer: [0; tg::MAX_ID],
            issuer_len: 0,
        }
    }

    /// Enroll a standby host; `false` when the table is full.
    pub fn enroll(&mut self, id: [u8; 16], public: [u8; 65]) -> bool {
        if self.host_count == MAX_HOSTS {
            return false;
        }
        self.hosts[self.host_count] = EnrolledHost { id, public };
        self.host_count += 1;
        true
    }

    fn issuer(&self) -> &[u8] {
        self.issuer.get(..self.issuer_len).unwrap_or(&[])
    }
}

pub struct Authority {
    pub config: Config,
    next_corr: u32,
    ops: [Op; MAX_OPS],
    pub stats: Stats,
}

impl Authority {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config: Config::empty(),
            next_corr: 1,
            ops: [Op::EMPTY; MAX_OPS],
            stats: Stats {
                granted: 0,
                refused: 0,
                replayed: 0,
                tokens_relayed: 0,
                verdicts_relayed: 0,
                busy: 0,
            },
        }
    }

    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.ops.iter().filter(|o| o.live).count()
    }

    /// A frame from the provider's `auth_req`: `msg_type` and its payload.
    pub fn on_provider<H: Host>(&mut self, host: &mut H, msg_type: u8, payload: &[u8]) {
        match msg_type {
            MSG_TOKEN_CHECK => {
                let mut f = [0u8; 3 + 64];
                if payload.len() <= 64 {
                    let n = frame(&mut f, MSG_TOKEN_CHECK, payload);
                    if host.send_token(f.get(..n).unwrap_or(&[])) {
                        self.stats.tokens_relayed = self.stats.tokens_relayed.saturating_add(1);
                    }
                }
            }
            MSG_CUSTODY_CHECK => self.custody(host, payload),
            _ => {}
        }
    }

    /// A frame from the directory's `replies`: its token verdicts go back to
    /// the provider whole; anything else on the shared port is not ours.
    pub fn on_token<H: Host>(&mut self, host: &mut H, msg_type: u8, payload: &[u8]) {
        if msg_type != MSG_TOKEN_VERDICT || payload.len() > 64 {
            return;
        }
        let mut f = [0u8; 3 + 64];
        let n = frame(&mut f, MSG_TOKEN_VERDICT, payload);
        if host.send_provider(f.get(..n).unwrap_or(&[])) {
            self.stats.verdicts_relayed = self.stats.verdicts_relayed.saturating_add(1);
        }
    }

    fn custody<H: Host>(&mut self, host: &mut H, payload: &[u8]) {
        let Ok(check) = CustodyCheck::parse(payload) else {
            // Nothing to name in a verdict: the provider's own wait ends it.
            self.stats.refused = self.stats.refused.saturating_add(1);
            return;
        };
        let sha = host.sha256();
        let now = host.now_ms();
        let refuse = |host: &mut H, stats: &mut Stats, r: Refusal| {
            stats.refused = stats.refused.saturating_add(1);
            verdict(host, &tg::custody_verdict(sha, &check, Some(r)));
        };
        if host.issuer_suite() == 0 {
            refuse(host, &mut self.stats, Refusal::NoIssuerKey);
            return;
        }
        let cfg = self.config;
        let grant = match tg::decide_custody_check(
            sha,
            host.verify(),
            &cfg.policy,
            &cfg.source,
            cfg.hosts.get(..cfg.host_count).unwrap_or(&[]),
            &check,
            cfg.ttl_ms,
            now,
        ) {
            Ok(g) => g,
            Err(r) => {
                refuse(host, &mut self.stats, r);
                return;
            }
        };
        let Some(slot) = self.ops.iter().position(|o| !o.live) else {
            self.stats.busy = self.stats.busy.saturating_add(1);
            refuse(host, &mut self.stats, Refusal::Busy);
            return;
        };
        let mut op = Op::EMPTY;
        op.live = true;
        op.stage = stage::GET_GENERATION;
        op.corr = self.next_corr;
        self.next_corr = self.next_corr.wrapping_add(1).max(1);
        op.deadline_ms = now.saturating_add(STAGE_TIMEOUT_MS);
        op.flow = check.flow;
        sha(check.evidence, &mut op.evidence_digest);
        op.grant = grant;
        if !send(
            host,
            state_wire::MSG_STATE_GET,
            &state_wire::get(
                op.corr,
                STATE_CLIENT,
                state_wire::NS_TRANSFER_GRANT,
                tg::GENERATION_KEY,
            ),
        ) {
            self.stats.refused = self.stats.refused.saturating_add(1);
            verdict(host, &verdict_of(&op, Some(Refusal::LedgerUnavailable)));
            return;
        }
        self.ops[slot] = op;
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
        let issuer = self.config.issuer;
        let issuer_len = self.config.issuer_len;
        let Some(op) = self
            .ops
            .iter_mut()
            .find(|o| o.live && o.corr == reply.correlation)
        else {
            return;
        };
        let outcome = advance(
            host,
            op,
            issuer.get(..issuer_len).unwrap_or(&[]),
            reply.status,
            reply.value,
        );
        if let Some(result) = outcome {
            finish(host, op, &mut self.stats, result);
        }
    }

    /// Refuse every check whose ledger stage outlived its deadline.
    pub fn tick<H: Host>(&mut self, host: &mut H) {
        let now = host.now_ms();
        for op in &mut self.ops {
            if op.live && now != 0 && now > op.deadline_ms {
                finish(host, op, &mut self.stats, Err(Refusal::LedgerUnavailable));
            }
        }
    }
}

impl Default for Authority {
    fn default() -> Self {
        Self::new()
    }
}

fn frame(out: &mut [u8], msg_type: u8, payload: &[u8]) -> usize {
    out[0] = msg_type;
    out[1..3].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    out[3..3 + payload.len()].copy_from_slice(payload);
    3 + payload.len()
}

fn verdict<H: Host>(host: &mut H, body: &[u8; CUSTODY_VERDICT_LEN]) {
    let mut f = [0u8; 3 + CUSTODY_VERDICT_LEN];
    let n = frame(&mut f, MSG_CUSTODY_VERDICT, body);
    let _ = host.send_provider(f.get(..n).unwrap_or(&[]));
}

fn verdict_of(op: &Op, refusal: Option<Refusal>) -> [u8; CUSTODY_VERDICT_LEN] {
    let mut out = [0u8; CUSTODY_VERDICT_LEN];
    out[..16].copy_from_slice(&op.flow);
    out[16..48].copy_from_slice(&op.evidence_digest);
    out[48] = refusal.map_or(0, |r| 0x80 | r.code());
    out
}

fn send<H: Host>(host: &mut H, msg_type: u8, req: &state_wire::StateRequest<'_>) -> bool {
    let mut f = [0u8; 3 + 32 + state_wire::MAX_KEY + state_wire::MAX_ETAG + 256];
    match state_wire::encode_request(&mut f, msg_type, req) {
        Ok(n) => host.send_ledger(f.get(..n).unwrap_or(&[])),
        Err(_) => false,
    }
}

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
    message[..unsigned].copy_from_slice(&out[..unsigned]);
    let mut signature = [0u8; tg::MAX_SIGNATURE];
    let n = host
        .sign(&message[..unsigned], &mut signature)
        .ok_or(Refusal::NoIssuerKey)?;
    tg::append_signature(out, unsigned, &signature[..n]).ok_or(Refusal::Malformed)
}

/// One step of `op` on a ledger answer. `Some` ends it.
fn advance<H: Host>(
    host: &mut H,
    op: &mut Op,
    issuer: &[u8],
    status: u8,
    value: &[u8],
) -> Option<Result<(), Refusal>> {
    let unavailable = Some(Err(Refusal::LedgerUnavailable));
    match op.stage {
        stage::GET_GENERATION => {
            let current = match status {
                auth_wire::ST_OK => match tg::decode_generation(value) {
                    Some(g) => g,
                    None => return Some(Err(Refusal::Malformed)),
                },
                auth_wire::ST_NOT_FOUND => 0,
                _ => return unavailable,
            };
            op.grant.generation = current;
            let n = match sign(host, &op.grant, issuer, &mut op.record) {
                Ok(n) => n,
                Err(r) => return Some(Err(r)),
            };
            op.record_len = n;
            // The provider wraps on the verdict: the grant is consumed by
            // this very transfer, so its state is written CONSUMED.
            let mut st = [0u8; tg::STATE_LEN];
            tg::State {
                state: tg::state::CONSUMED,
                generation: current,
                expiry_ms: op.grant.expiry_ms,
                digest: tg::record_digest(host.sha256(), &op.record[..n]),
            }
            .encode(&mut st);
            let mut key = [0u8; MAX_KEY];
            let Some(kn) = tg::state_key(&op.grant.flow, &op.grant.nonce, &mut key) else {
                return Some(Err(Refusal::Malformed));
            };
            op.stage = stage::CLAIM;
            let ok = send(
                host,
                state_wire::MSG_STATE_PUT_ABS,
                &state_wire::put_if_absent(
                    op.corr,
                    STATE_CLIENT,
                    state_wire::NS_TRANSFER_GRANT,
                    &key[..kn],
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
        stage::CLAIM => match status {
            auth_wire::ST_OK => Some(Ok(())),
            // The transfer was granted before: its evidence is replayed.
            auth_wire::ST_CONFLICT => Some(Err(Refusal::Replayed)),
            _ => unavailable,
        },
        _ => Some(Err(Refusal::Malformed)),
    }
}

fn finish<H: Host>(host: &mut H, op: &mut Op, stats: &mut Stats, result: Result<(), Refusal>) {
    match result {
        Ok(()) => {
            let _ = host.send_grant(&op.record[..op.record_len]);
            stats.granted = stats.granted.saturating_add(1);
            verdict(host, &verdict_of(op, None));
        }
        Err(r) => {
            if r == Refusal::Replayed {
                stats.replayed = stats.replayed.saturating_add(1);
            }
            stats.refused = stats.refused.saturating_add(1);
            verdict(host, &verdict_of(op, Some(r)));
        }
    }
    *op = Op::EMPTY;
}

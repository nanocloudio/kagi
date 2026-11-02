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
//!
//! And one question before a transfer is planned:
//!
//! - **Could these hosts take over now?** (`CUSTODY_READY`, [`ready`]): per
//!   host, whether it is enrolled here, the custody tier its own attested
//!   evidence last proved to this authority, whether a grant could be
//!   issued to it now (grant key open, trusted clock, the ledger answering a
//!   read made for this question, the posture admitting the grant key's
//!   vault), and whether it holds a live identity certificate this
//!   deployment's CA issued (delivered on the enrolment path, checked
//!   against the CA's key). Every fact is one this authority observed; one
//!   it has not observed answers not-ready, never ready.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::auth_wire;
use crate::spiffe;
use crate::state_wire;
use crate::transfer_grant::{
    self as tg, CustodyCheck, EnrolledHost, Grant, Policy, Refusal, CUSTODY_VERDICT_LEN,
    MSG_CUSTODY_CHECK, MSG_CUSTODY_VERDICT,
};
use crate::x509_leaf;

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

/// `CUSTODY_READY`: whether hosts could take over a Service's traffic now —
/// enrolled, their proven custody tier, a grant issuable to them, a live
/// identity certificate (`docs/architecture/typed-operations.md`).
pub mod ready {
    /// `[service 16][n u8][host 16 × n]`.
    pub const REQUEST: u8 = 0xA0;
    /// `[status u8][n u8]` then per host `[host 16][enrolled u8][tier u8]
    /// [grant_ready u8][cert_ready u8][not_after u64]`.
    pub const REPLY: u8 = 0xA1;
    /// Hosts one question may name.
    pub const MAX_HOSTS: usize = 32;
    /// One host's row.
    pub const ROW_LEN: usize = 16 + 4 + 8;
    /// The longest reply.
    pub const REPLY_MAX: usize = 2 + MAX_HOSTS * ROW_LEN;
    /// Questions waiting on the ledger at once; one more is answered BUSY.
    pub const PROBES: usize = 2;
    /// How long the ledger has to answer before it is reported unreachable.
    pub const TIMEOUT_MS: u64 = 2_000;
    /// A tier no attested evidence has proven.
    pub const TIER_UNKNOWN: u8 = 0xFF;
    pub mod status {
        pub const OK: u8 = 0;
        /// Not `17 + 16·n` bytes, or `n` outside `1..=MAX_HOSTS`.
        pub const MALFORMED: u8 = 1;
        /// [`super::PROBES`] questions already wait on the ledger.
        pub const BUSY: u8 = 2;
    }
}

/// A host's identity certificate, as this authority last took it.
#[derive(Clone, Copy)]
pub struct HeldCert {
    pub not_before: u64,
    pub not_after: u64,
}

/// What this authority has observed of one enrolled host.
#[derive(Clone, Copy)]
pub struct Observed {
    /// The tier the host's own attested evidence proved in a custody check
    /// that verified here; [`ready::TIER_UNKNOWN`] until one has.
    pub tier: u8,
    pub cert: Option<HeldCert>,
}

impl Observed {
    const NONE: Self = Self {
        tier: ready::TIER_UNKNOWN,
        cert: None,
    };
}

#[derive(Clone, Copy)]
struct Probe {
    live: bool,
    corr: u32,
    slot: usize,
    deadline_ms: u64,
    n: usize,
    hosts: [[u8; 16]; ready::MAX_HOSTS],
}

impl Probe {
    const EMPTY: Self = Self {
        live: false,
        corr: 0,
        slot: 0,
        deadline_ms: 0,
        n: 0,
        hosts: [[0; 16]; ready::MAX_HOSTS],
    };
}

/// Longest trust domain held.
pub const TRUST_DOMAIN_MAX: usize = 128;

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
    /// The `CUSTODY_READY` reply payload for the question the host asked in
    /// `slot` ([`Authority::ready_request`]).
    fn send_ready(&mut self, slot: usize, reply: &[u8]) -> bool;
}

#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub granted: u32,
    pub refused: u32,
    pub replayed: u32,
    pub tokens_relayed: u32,
    pub verdicts_relayed: u32,
    pub busy: u32,
    pub certs_taken: u32,
    pub certs_refused: u32,
    pub ready_answered: u32,
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
    /// The trust domain host identities are named in.
    pub trust_domain: [u8; TRUST_DOMAIN_MAX],
    pub trust_domain_len: usize,
    /// The CA's key, as `x509_leaf::anchor` reads it; empty until one is
    /// delivered, and while empty no certificate is taken.
    pub anchor: [u8; 2 + 65],
    pub anchor_len: usize,
    /// Whether the deployment's posture admits the grant key's vault tier
    /// (`key_custody::permits(TransferGrant, …)`).
    pub posture_admits: bool,
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
            trust_domain: [0; TRUST_DOMAIN_MAX],
            trust_domain_len: 0,
            anchor: [0; 2 + 65],
            anchor_len: 0,
            posture_admits: false,
        }
    }

    /// Set the trust domain; `false` when it does not fit.
    pub fn set_trust_domain(&mut self, td: &[u8]) -> bool {
        let Some(dst) = self.trust_domain.get_mut(..td.len()) else {
            return false;
        };
        dst.copy_from_slice(td);
        self.trust_domain_len = td.len();
        true
    }

    /// Set the CA's key (`[suite u16 LE][public]`); `false`, and nothing
    /// changed, when it is not one `x509_leaf::anchor` reads.
    pub fn set_anchor(&mut self, anchor: &[u8]) -> bool {
        if x509_leaf::anchor(anchor).is_none() {
            return false;
        }
        let Some(dst) = self.anchor.get_mut(..anchor.len()) else {
            return false;
        };
        dst.copy_from_slice(anchor);
        self.anchor_len = anchor.len();
        true
    }

    fn enrolled(&self, id: &[u8; 16]) -> Option<usize> {
        self.hosts
            .get(..self.host_count)?
            .iter()
            .position(|h| h.id == *id)
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
    /// Per enrolled host (the index of `config.hosts`).
    pub observed: [Observed; MAX_HOSTS],
    probes: [Probe; ready::PROBES],
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
                certs_taken: 0,
                certs_refused: 0,
                ready_answered: 0,
            },
            observed: [Observed::NONE; MAX_HOSTS],
            probes: [Probe::EMPTY; ready::PROBES],
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
        let decided = tg::decide_custody_check(
            sha,
            host.verify(),
            &cfg.policy,
            &cfg.source,
            cfg.hosts.get(..cfg.host_count).unwrap_or(&[]),
            &check,
            cfg.ttl_ms,
            now,
        );
        // The standby's evidence verified: the tier it proved is a fact
        // about that host whatever the ledger does next.
        if let Ok(g) = &decided {
            if let Some(i) = cfg.enrolled(&g.destination) {
                if let Some(o) = self.observed.get_mut(i) {
                    o.tier = g.proven_tier;
                }
            }
        }
        let grant = match decided {
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
        if let Some(i) = self
            .probes
            .iter()
            .position(|p| p.live && p.corr == reply.correlation)
        {
            // The ledger answered a read: reachable, unless it said it is
            // not.
            let reachable = matches!(reply.status, auth_wire::ST_OK | auth_wire::ST_NOT_FOUND);
            self.answer_probe(host, i, reachable);
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

    /// Refuse every check whose ledger stage outlived its deadline, and
    /// answer every readiness question the ledger left unanswered.
    pub fn tick<H: Host>(&mut self, host: &mut H) {
        let now = host.now_ms();
        for op in &mut self.ops {
            if op.live && now != 0 && now > op.deadline_ms {
                finish(host, op, &mut self.stats, Err(Refusal::LedgerUnavailable));
            }
        }
        for i in 0..ready::PROBES {
            let p = self.probes[i];
            if p.live && now != 0 && now > p.deadline_ms {
                self.answer_probe(host, i, false);
            }
        }
    }

    /// A chain from the enrolment path (`identity_cert`'s payload: `leaf
    /// DER ‖ issuer DER ‖ …`). Taken when the leaf is one the CA signed and
    /// names an enrolled host (`spiffe://<trust domain>/host/<id>`); the
    /// later-expiring of two certificates for one host is kept. True when
    /// taken.
    pub fn on_cert(&mut self, verify: tg::VerifyFn, sha: tg::Sha256Fn, chain: &[u8]) -> bool {
        let taken = self.take_cert(verify, sha, chain);
        if taken {
            self.stats.certs_taken = self.stats.certs_taken.saturating_add(1);
        } else {
            self.stats.certs_refused = self.stats.certs_refused.saturating_add(1);
        }
        taken
    }

    fn take_cert(&mut self, verify: tg::VerifyFn, sha: tg::Sha256Fn, chain: &[u8]) -> bool {
        let cfg = &self.config;
        let Some((suite, public)) =
            x509_leaf::anchor(cfg.anchor.get(..cfg.anchor_len).unwrap_or(&[]))
        else {
            return false;
        };
        let Some(leaf) = x509_leaf::element_len(chain)
            .and_then(|n| chain.get(..n))
            .and_then(x509_leaf::parse)
        else {
            return false;
        };
        if !x509_leaf::signed_by(&leaf, verify, suite, public) || leaf.not_after <= leaf.not_before
        {
            return false;
        }
        let td = cfg.trust_domain.get(..cfg.trust_domain_len).unwrap_or(&[]);
        let Some(who) = spiffe::parse(sha, leaf.san_uri, td) else {
            return false;
        };
        if who.class != spiffe::Class::Host {
            return false;
        }
        let Some(i) = cfg.enrolled(&who.id) else {
            return false;
        };
        let Some(o) = self.observed.get_mut(i) else {
            return false;
        };
        if o.cert.is_some_and(|c| c.not_after > leaf.not_after) {
            // An older certificate delivered late changes nothing.
            return true;
        }
        o.cert = Some(HeldCert {
            not_before: leaf.not_before,
            not_after: leaf.not_after,
        });
        true
    }

    /// Whether a `CUSTODY_READY` question could be taken now: the slot it
    /// would wait in, `None` when [`ready::PROBES`] already wait.
    #[must_use]
    pub fn ready_slot(&self) -> Option<usize> {
        self.probes.iter().position(|p| !p.live)
    }

    /// A `CUSTODY_READY` request payload, asked in `slot` (from
    /// [`Self::ready_slot`]). Answered through [`Host::send_ready`] — at
    /// once when it does not decode or no slot is free, otherwise when the
    /// ledger answers the read made for it, or [`ready::TIMEOUT_MS`] after.
    pub fn ready_request<H: Host>(&mut self, host: &mut H, slot: usize, payload: &[u8]) {
        let Some(hosts) = decode_ready(payload) else {
            let reply = [ready::status::MALFORMED, 0];
            let _ = host.send_ready(slot, &reply);
            return;
        };
        if self.probes.get(slot).is_none_or(|p| p.live) {
            let reply = [ready::status::BUSY, 0];
            let _ = host.send_ready(slot, &reply);
            return;
        }
        let mut probe = Probe::EMPTY;
        probe.live = true;
        probe.slot = slot;
        probe.corr = self.next_corr;
        self.next_corr = self.next_corr.wrapping_add(1).max(1);
        probe.deadline_ms = host.now_ms().saturating_add(ready::TIMEOUT_MS);
        probe.n = hosts.len() / 16;
        for (dst, src) in probe.hosts.iter_mut().zip(hosts.chunks_exact(16)) {
            dst.copy_from_slice(src);
        }
        self.probes[slot] = probe;
        // The ledger is asked now, for this question: reachability is what
        // it does, not what it did.
        let sent = send(
            host,
            state_wire::MSG_STATE_GET,
            &state_wire::get(
                probe.corr,
                STATE_CLIENT,
                state_wire::NS_TRANSFER_GRANT,
                tg::GENERATION_KEY,
            ),
        );
        if !sent {
            self.answer_probe(host, slot, false);
        }
    }

    fn answer_probe<H: Host>(&mut self, host: &mut H, i: usize, ledger: bool) {
        let Some(p) = self.probes.get(i).copied() else {
            return;
        };
        if !p.live {
            return;
        }
        self.probes[i] = Probe::EMPTY;
        let now_ms = host.now_ms();
        let key = host.issuer_suite() != 0;
        let mut reply = [0u8; ready::REPLY_MAX];
        reply[0] = ready::status::OK;
        #[expect(clippy::cast_possible_truncation, reason = "at most MAX_HOSTS")]
        {
            reply[1] = p.n as u8;
        }
        let cfg = &self.config;
        let anchored = x509_leaf::anchor(cfg.anchor.get(..cfg.anchor_len).unwrap_or(&[])).is_some();
        for (row, id) in reply[2..]
            .chunks_exact_mut(ready::ROW_LEN)
            .zip(p.hosts.iter().take(p.n))
        {
            let at = cfg.enrolled(id);
            let seen = at
                .and_then(|i| self.observed.get(i).copied())
                .unwrap_or(Observed::NONE);
            let enrolled = at.is_some();
            let grant_ready = enrolled && key && now_ms != 0 && ledger && cfg.posture_admits;
            let unix_secs = now_ms / 1000;
            let cert_ready = seen.cert.is_some_and(|c| {
                anchored && now_ms != 0 && c.not_before <= unix_secs && unix_secs < c.not_after
            });
            row[..16].copy_from_slice(id);
            row[16] = u8::from(enrolled);
            row[17] = seen.tier;
            row[18] = u8::from(grant_ready);
            row[19] = u8::from(cert_ready);
            row[20..28].copy_from_slice(&seen.cert.map_or(0, |c| c.not_after).to_le_bytes());
        }
        self.stats.ready_answered = self.stats.ready_answered.saturating_add(1);
        let _ = host.send_ready(p.slot, &reply[..2 + p.n * ready::ROW_LEN]);
    }
}

impl Default for Authority {
    fn default() -> Self {
        Self::new()
    }
}

/// The host ids a `CUSTODY_READY` request names (`16·n` bytes), when it is
/// exactly `[service 16][n u8][host 16 × n]` with `n` in `1..=MAX_HOSTS`.
#[must_use]
pub fn decode_ready(payload: &[u8]) -> Option<&[u8]> {
    let n = usize::from(*payload.get(16)?);
    if n == 0 || n > ready::MAX_HOSTS || payload.len() != 17 + 16 * n {
        return None;
    }
    payload.get(17..)
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

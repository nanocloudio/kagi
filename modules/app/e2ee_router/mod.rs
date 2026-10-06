//! E2EE path router — one listener for the whole `/e2ee/` family.
//!
//! wave's `http` has exactly one `request_out`, so two application modules cannot
//! share a listener without something in between. That is normally a reason
//! to give each endpoint its own listener, and it is why the issuer graph had
//! three for the E2EE family. It cannot keep them.
//!
//! `LINUX_NET_MAX_INBOUND` is **8**: eight inbound command lanes, one per
//! module driving the network. The issuer graph uses all eight. A ninth
//! producer is not refused — it is accepted, lands in a slot nothing reads,
//! and its bind never issues, so the port simply never accepts with nothing
//! in the log to say why. Adding the mail path the enrollment gate needs
//! therefore requires giving a lane back first, and collapsing three
//! listeners that serve one path family into one is where the slack is.
//!
//! Toward the listener this module is a PROVIDER of the workspace exchange
//! contract (`request_in` / `response_out`); toward each endpoint it is the
//! requester, forwarding the listener's records verbatim. Requests fan out by
//! path prefix, and the endpoints' answers come back through here on one lane
//! each and are forwarded verbatim too. Every record carries the exchange id
//! the listener chose, and an endpoint echoes it, so this module needs no
//! correlation table — which is the difference between a router and a proxy,
//! and the reason this one cannot lose a reply or mis-address one.

#![no_std]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in target/fluxor/fluxor-abi/sdk/"
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "see file-level allow: SDK surface is shared across modules"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/http_endpoint.rs"]
mod http_endpoint;

use abi::contracts::exchange::{self as x, parse_request, ExchangeId, Record, RequestRecord};

/// The path families, longest-first so `/e2ee/state/` is tested before any
/// shorter prefix could swallow it.
const PATH_KEYPKG: &[u8] = b"/e2ee/keypackages";
const PATH_STATE: &[u8] = b"/e2ee/state";
const PATH_CREDENTIAL: &[u8] = b"/e2ee/credential";

/// Exchanges routed at once.
const MAX_ROUTES: usize = 16;

const BUF_LEN: usize = x::RECORD_MAX;
const MAX_REQS_PER_STEP: usize = 8;

/// Endpoints whose answers this router forwards: credential, key packages,
/// endpoint state — one input lane each.
const ANSWER_LANES: usize = 3;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    /// The endpoints' answers, one edge each. See the manifest for why they do
    /// not go straight to the listener.
    in_answers: [i32; ANSWER_LANES],
    out_credential: i32,
    out_keypkg: i32,
    out_state: i32,
    out_response: i32,
    /// Which endpoint each live exchange was routed to.
    ///
    /// An exchange is streamed: its HEAD names the target, and the BODY
    /// records that follow name only the exchange. So the decision is made
    /// once, on the HEAD, and every later record of that exchange follows it
    /// — a router that re-decided per record could split one request across
    /// two endpoints.
    routes: [(ExchangeId, i32); MAX_ROUTES],
    routes_live: u8,
    buf: [u8; BUF_LEN],
    /// `buf[..held_len]` is a record taken off the input and not yet placed,
    /// bound for `held_out`.
    ///
    /// A record cannot be un-read. Taking one off the input and then letting a
    /// refused write drop it loses a BODY record out of the middle of a
    /// streamed request, and the request simply never completes: the endpoint
    /// waits for a body that will not arrive, the client waits out its own
    /// timeout, and nothing anywhere reports an error. So a record that cannot
    /// be placed is HELD, and the input is not read again until it is away —
    /// which is what makes the endpoint's back-pressure reach `http`, where
    /// the credit that governs the exchange is issued.
    held_len: usize,
    held_out: i32,
    out: [u8; 256],
    /// The router's OWN answers — a 404 for a path it does not route, a 503
    /// for a port this graph does not have. Held on a refused write for the
    /// same reason as a forwarded record: an unanswered request is a client
    /// waiting out its own timeout against a server that looks hung.
    resp_held: usize,
    /// One endpoint answer read and not yet placed on `response_out`, and the
    /// lane it is to be drained from next. Round-robin so a busy endpoint
    /// cannot starve a quiet one.
    answer: [u8; BUF_LEN],
    answer_len: usize,
    answer_lane: usize,
    answers_forwarded: u32,
    routed_credential: u32,
    routed_keypackage: u32,
    routed_state: u32,
    unrouted: u32,
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs), the
    // kernel passes a valid, exclusively-borrowed `state` of at least
    // `module_state_size()` bytes, and a `syscalls` table whose function
    // pointers reach live kernel routines.
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<ModuleState>() {
            return -2;
        }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.in_requests = in_chan;
        s.out_credential = out_chan;
        s.routes = [(ExchangeId::NONE, -1); MAX_ROUTES];
        s.routes_live = 0;
        s.held_len = 0;
        s.held_out = -1;
        s.resp_held = 0;
        s.in_answers = [
            dev_channel_port(sys, 0, 1),
            dev_channel_port(sys, 0, 2),
            dev_channel_port(sys, 0, 3),
        ];
        s.answer_len = 0;
        s.answer_lane = 0;
        s.answers_forwarded = 0;
        s.out_keypkg = dev_channel_port(sys, 1, 1);
        s.out_state = dev_channel_port(sys, 1, 2);
        s.out_response = dev_channel_port(sys, 1, 3);
        s.routed_credential = 0;
        s.routed_keypackage = 0;
        s.routed_state = 0;
        s.unrouted = 0;
        dev_log(sys, 3, b"[e2eert] init".as_ptr(), 13);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: as `module_new`.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // The router's own answer goes before anything else: it shares one
        // staging buffer, so a second answer would overwrite it.
        if s.resp_held > 0 {
            if (sys.channel_write)(s.out_response, s.out.as_ptr(), s.resp_held) > 0 {
                s.resp_held = 0;
            } else {
                return 0;
            }
        }
        forward_answers(s, sys);

        for _ in 0..MAX_REQS_PER_STEP {
            // Whatever is held goes first, and nothing new is read until it
            // has gone.
            if s.held_len > 0 {
                if (sys.channel_write)(s.held_out, s.buf.as_ptr(), s.held_len) <= 0 {
                    break;
                }
                s.held_len = 0;
            }
            if !chan::can_read(sys, s.in_requests) {
                break;
            }
            let n = (sys.channel_read)(s.in_requests, s.buf.as_mut_ptr(), s.buf.len());
            if n < x::HDR as i32 {
                break;
            }
            route(s, sys, n as usize);
        }
        0
    }
}

/// Pass the endpoints' answers on to the listener, verbatim.
///
/// The record addresses itself — the exchange id the listener chose and the
/// endpoint echoed — so this is a copy and not a decision, and there is
/// nothing here that can send an answer to the wrong exchange.
///
/// One answer is held at a time and placed before the next is read, for the
/// same reason the request side holds: a record taken off a lane and then lost
/// to a full output is an exchange answered with silence.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn forward_answers(s: &mut ModuleState, sys: &SyscallTable) {
    for _ in 0..MAX_REQS_PER_STEP {
        if s.answer_len > 0 {
            if (sys.channel_write)(s.out_response, s.answer.as_ptr(), s.answer_len) <= 0 {
                return;
            }
            s.answer_len = 0;
            s.answers_forwarded = s.answers_forwarded.saturating_add(1);
        }
        // Round-robin, so one talkative endpoint cannot hold the lane.
        let mut found = None;
        for step in 0..ANSWER_LANES {
            let lane = (s.answer_lane + step) % ANSWER_LANES;
            let chan = s.in_answers[lane];
            if chan >= 0 && chan::can_read(sys, chan) {
                found = Some((lane, chan));
                break;
            }
        }
        let Some((lane, chan)) = found else {
            return;
        };
        s.answer_lane = (lane + 1) % ANSWER_LANES;
        let n = (sys.channel_read)(chan, s.answer.as_mut_ptr(), BUF_LEN);
        if n < x::HDR as i32 {
            return;
        }
        s.answer_len = n as usize;
    }
}

/// Forward one request to whichever endpoint owns its path.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn route(s: &mut ModuleState, sys: &SyscallTable, len: usize) {
    let record = s.buf.get(..len).unwrap_or(&[]);
    let Some(parsed) = parse_request(record) else {
        return;
    };
    let out = match parsed {
        Record::Head(head) => {
            let path = head.target;
            // Longest prefix first. `/e2ee/state` and `/e2ee/keypackages`
            // share no prefix today, but ordering by length is what keeps
            // that true when one of them grows a sub-path.
            let chosen = if starts_with(path, PATH_KEYPKG) {
                s.routed_keypackage = s.routed_keypackage.saturating_add(1);
                s.out_keypkg
            } else if starts_with(path, PATH_STATE) {
                s.routed_state = s.routed_state.saturating_add(1);
                s.out_state
            } else if starts_with(path, PATH_CREDENTIAL) {
                s.routed_credential = s.routed_credential.saturating_add(1);
                s.out_credential
            } else {
                s.unrouted = s.unrouted.saturating_add(1);
                let (id, credit) = (head.id, head.resp_credit);
                respond_not_found(s, sys, &id, credit);
                return;
            };
            if chosen < 0 {
                // No such port in this graph: the path routes somewhere this
                // deployment does not have, which is a 503 and not a hold —
                // holding would wait on a port that will never drain.
                let (id, credit) = (head.id, head.resp_credit);
                respond_unavailable(s, sys, &id, credit);
                return;
            }
            remember_route(s, &head.id, chosen);
            chosen
        }
        // Every later record of an exchange goes where its HEAD went.
        other => {
            let id = record_id(&other);
            let Some(known) = route_of(s, &id) else {
                return;
            };
            if matches!(other, Record::Abort { .. }) {
                forget_route(s, &id);
            }
            known
        }
    };
    // Held rather than dropped when the endpoint cannot take it now; the step
    // loop retries before it reads anything else.
    if (sys.channel_write)(out, s.buf.as_ptr(), len) <= 0 {
        s.held_len = len;
        s.held_out = out;
    }
}

/// The exchange a non-HEAD record belongs to.
fn record_id(rec: &RequestRecord<'_>) -> ExchangeId {
    match rec {
        Record::Head(h) => h.id,
        Record::Body { id, .. }
        | Record::Abort { id, .. }
        | Record::Credit { id, .. }
        | Record::Datagram { id, .. } => *id,
        Record::Link { .. } => ExchangeId::NONE,
    }
}

fn same(a: &ExchangeId, b: &ExchangeId) -> bool {
    a == b
}

/// Record where an exchange was routed, replacing any stale entry for it.
fn remember_route(s: &mut ModuleState, id: &ExchangeId, out: i32) {
    if let Some(slot) = s.routes.iter_mut().find(|(known, _)| same(known, id)) {
        slot.1 = out;
        return;
    }
    let live = usize::from(s.routes_live);
    if let Some(slot) = s.routes.get_mut(live) {
        *slot = (*id, out);
        s.routes_live = s.routes_live.saturating_add(1);
        return;
    }
    // Full: the oldest entry goes. An exchange whose route is forgotten has
    // its later records dropped, which the listener answers as a timeout —
    // better than sending one request's body to another's endpoint.
    s.routes.rotate_left(1);
    if let Some(slot) = s.routes.last_mut() {
        *slot = (*id, out);
    }
}

fn route_of(s: &ModuleState, id: &ExchangeId) -> Option<i32> {
    s.routes
        .iter()
        .take(usize::from(s.routes_live))
        .find(|(known, _)| same(known, id))
        .map(|(_, out)| *out)
}

fn forget_route(s: &mut ModuleState, id: &ExchangeId) {
    if let Some(at) = s.routes.iter().position(|(known, _)| same(known, id)) {
        let live = usize::from(s.routes_live);
        if live > 0 {
            s.routes.swap(at, live - 1);
            s.routes_live -= 1;
        }
    }
}

fn starts_with(path: &[u8], prefix: &[u8]) -> bool {
    path.len() >= prefix.len() && &path[..prefix.len()] == prefix
}

/// Answer a request this router owns no endpoint for.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn respond_not_found(s: &mut ModuleState, sys: &SyscallTable, id: &ExchangeId, credit: u32) {
    reply(s, sys, id, credit, 404, b"{\"error\":\"not_found\"}");
}

/// Answer when the owning endpoint cannot take the request right now.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn respond_unavailable(
    s: &mut ModuleState,
    sys: &SyscallTable,
    id: &ExchangeId,
    credit: u32,
) {
    reply(
        s,
        sys,
        id,
        credit,
        503,
        b"{\"error\":\"temporarily_unavailable\"}",
    );
}

/// Compose a response addressed to the request's own exchange.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn reply(
    s: &mut ModuleState,
    sys: &SyscallTable,
    id: &ExchangeId,
    credit: u32,
    status: u16,
    body: &[u8],
) {
    if s.out_response < 0 || !chan::can_write(sys, s.out_response) {
        return;
    }
    // One response HEAD carrying the whole body, on the request's own
    // exchange id — which is what addresses the answer to the client that
    // asked.
    const CTYPE: &[u8] = b"application/json";
    let Some(total) = http_endpoint::write_response(id, status, CTYPE, body, credit, &mut s.out)
    else {
        return;
    };
    if (sys.channel_write)(s.out_response, s.out.as_ptr(), total) <= 0 {
        s.resp_held = total;
    }
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

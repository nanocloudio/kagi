//! Endpoint state for an encrypted group, kept so that recovery can never
//! reuse a message generation or roll an epoch backwards.
//!
//! A group protocol's endpoint holds a ratchet. Its safety rests on state only
//! ever moving forward: a generation used twice means a key and nonce used
//! twice, which is not a degraded guarantee but no guarantee at all. Every way
//! state can move backwards is a way to lose confidentiality — restoring a
//! backup, failing over to a stale replica, resuming from a snapshot taken
//! before the last send.
//!
//! Two mechanisms, both necessary.
//!
//! **Conditional commit** means a commit quotes the revision the caller
//! believed it was advancing from, so two writers racing produce one winner
//! and one refusal rather than a merge nobody designed. The revision is
//! assigned here and cannot be constructed by a caller for state it did not
//! load, which is what makes the condition a real one.
//!
//! **A backward commit poisons the endpoint**, and it stays poisoned. A
//! caller that quotes the current revision — so it did load the current
//! state — and then offers a position BEHIND it has a ratchet that has gone
//! backwards: a restored backup, a stale replica, a snapshot from before its
//! last send. Continuing would encrypt under a position already used, and no
//! amount of retrying makes that safe, so only a person who has worked out
//! what replaced the state should clear it.
//!
//! That is deliberately distinguished from offering the SAME position, which
//! is what an optimistic retry after an ambiguous failure looks like. Both
//! are refused; only one is evidence that something is wrong.
//!
//! The host store this replaces kept a separate high-water mark, written to
//! its own file after the state, so that restoring a backup of the state file
//! alone would be caught. Module-resident state has no second file to fall
//! out of step with — the mark would live in the same memory as the state it
//! attests to, and could not disagree with it. So the furthest position ever
//! reached IS the committed marker here, and the check is against that.
//!
//! Two paths:
//!
//! * `POST /e2ee/state/load` returns the current state and its revision.
//! * `POST /e2ee/state/commit` advances it, conditionally.

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

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/b64.rs"]
mod b64;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/jose.rs"]
mod jose;

const STEP_DID_WORK: i32 = 2;
const REQ_HDR: usize = 12;
const RESP_HDR: usize = 12;
const METHOD_POST: u8 = 3;

/// Endpoints this module holds state for.
const MAX_ENDPOINTS: usize = 16;
/// The group protocol's own bytes, opaque here.
const MAX_PAYLOAD: usize = 1024;
/// Longest endpoint key accepted.
const MAX_KEY: usize = 96;
const MAX_REQS_PER_STEP: usize = 2;

/// How far an endpoint has advanced in one group.
///
/// Ordered epoch first: an epoch change outranks any generation, because a
/// new epoch restarts the ratchet with new secrets and its generation counter
/// legitimately begins again.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Marker {
    epoch: u64,
    generation: u32,
}

impl Marker {
    const ZERO: Self = Self {
        epoch: 0,
        generation: 0,
    };

    /// Whether this marker is strictly ahead of `previous`.
    ///
    /// Strictly: equal is not ahead. Committing the same position twice is how
    /// a retry after an ambiguous failure turns into a reused generation, so
    /// it is refused rather than treated as a harmless repeat.
    const fn advances_on(self, previous: Self) -> bool {
        if self.epoch != previous.epoch {
            return self.epoch > previous.epoch;
        }
        self.generation > previous.generation
    }
}

#[derive(Clone, Copy)]
struct Endpoint {
    key: [u8; MAX_KEY],
    key_len: u8,
    /// The state as last committed. `has_state` is false before the first.
    marker: Marker,
    revision: u64,
    payload: [u8; MAX_PAYLOAD],
    payload_len: u16,
    has_state: bool,
    poisoned: bool,
    live: bool,
}

impl Endpoint {
    const fn empty() -> Self {
        Self {
            key: [0; MAX_KEY],
            key_len: 0,
            marker: Marker::ZERO,
            revision: 0,
            payload: [0; MAX_PAYLOAD],
            payload_len: 0,
            has_state: false,
            poisoned: false,
            live: false,
        }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    out_responses: i32,

    endpoints: [Endpoint; MAX_ENDPOINTS],

    state_loaded: u32,
    state_committed: u32,
    state_superseded: u32,
    state_not_advancing: u32,
    state_rolled_back: u32,
    state_poisoned: u32,
    state_table_full: u32,

    buf: [u8; abi::CHANNEL_BUFFER_SIZE],
    out: [u8; abi::CHANNEL_BUFFER_SIZE],
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
    // SAFETY: per the module ABI, the kernel passes a valid, exclusively
    // borrowed `state` of at least `module_state_size()` bytes and a live
    // syscall table.
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
        s.out_responses = out_chan;
        s.endpoints = [Endpoint::empty(); MAX_ENDPOINTS];
        s.state_loaded = 0;
        s.state_committed = 0;
        s.state_superseded = 0;
        s.state_not_advancing = 0;
        s.state_rolled_back = 0;
        s.state_poisoned = 0;
        s.state_table_full = 0;

        dev_log(sys, 3, b"[e2ee-state] init".as_ptr(), 17);
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

        let mut worked = false;
        for _ in 0..MAX_REQS_PER_STEP {
            if !chan::can_read(sys, s.in_requests) || !chan::can_write(sys, s.out_responses) {
                break;
            }
            let n = (sys.channel_read)(s.in_requests, s.buf.as_mut_ptr(), s.buf.len());
            if n < REQ_HDR as i32 {
                break;
            }
            handle_request(s, sys, n as usize);
            worked = true;
        }

        if worked {
            STEP_DID_WORK
        } else {
            0
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a live syscall table.
unsafe fn handle_request(s: &mut ModuleState, sys: &SyscallTable, plen: usize) {
    if plen < REQ_HDR {
        return;
    }
    let conn = u16::from_le_bytes([s.buf[0], s.buf[1]]);
    let stream = u16::from_le_bytes([s.buf[2], s.buf[3]]);
    let method = s.buf[4];
    let path_len = u16::from_le_bytes([s.buf[6], s.buf[7]]) as usize;
    let hdr_len = u16::from_le_bytes([s.buf[8], s.buf[9]]) as usize;
    let body_len = u16::from_le_bytes([s.buf[10], s.buf[11]]) as usize;

    let Some(body_at) = REQ_HDR
        .checked_add(path_len)
        .and_then(|at| at.checked_add(hdr_len))
    else {
        return;
    };
    let Some(body_end) = body_at.checked_add(body_len) else {
        return;
    };
    if body_end > plen {
        respond(s, sys, conn, stream, 400, br#"{"error":"invalid_request"}"#);
        return;
    }

    let path = &s.buf[REQ_HDR..REQ_HDR + path_len];
    let loading = path == b"/e2ee/state/load";
    let committing = path == b"/e2ee/state/commit";
    if !loading && !committing {
        respond(s, sys, conn, stream, 404, br#"{"error":"not_found"}"#);
        return;
    }
    if method != METHOD_POST {
        respond(s, sys, conn, stream, 405, br#"{"error":"invalid_request"}"#);
        return;
    }

    if loading {
        load(s, sys, conn, stream, body_at, body_end);
    } else {
        commit(s, sys, conn, stream, body_at, body_end);
    }
}

/// The current state, or nothing before the first commit.
///
/// # Safety
///
/// As `handle_request`.
unsafe fn load(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    body_at: usize,
    body_end: usize,
) {
    let mut key = [0u8; MAX_KEY];
    let key_len = {
        let body = &s.buf[body_at..body_end];
        json_string(body, b"endpoint", &mut key)
    };
    if key_len == 0 {
        respond(s, sys, conn, stream, 400, br#"{"error":"invalid_request"}"#);
        return;
    }

    let Some(index) = find(s, &key[..key_len]) else {
        // Nothing committed yet is not a refusal: it is the ordinary state of
        // an endpoint that has not sent anything. The caller commits against
        // revision 0.
        s.state_loaded = s.state_loaded.saturating_add(1);
        respond(
            s,
            sys,
            conn,
            stream,
            200,
            br#"{"revision":0,"present":false}"#,
        );
        return;
    };
    if s.endpoints[index].poisoned {
        s.state_poisoned = s.state_poisoned.saturating_add(1);
        respond(
            s,
            sys,
            conn,
            stream,
            409,
            br#"{"error":"poisoned","detail":"the endpoint is stopped and needs a person"}"#,
        );
        return;
    }

    let endpoint = s.endpoints[index];
    if !endpoint.has_state {
        s.state_loaded = s.state_loaded.saturating_add(1);
        respond(
            s,
            sys,
            conn,
            stream,
            200,
            br#"{"revision":0,"present":false}"#,
        );
        return;
    }

    let mut encoded = [0u8; MAX_PAYLOAD * 2];
    let Some(encoded_len) = b64::encode(
        &endpoint.payload[..usize::from(endpoint.payload_len)],
        &mut encoded,
    ) else {
        respond(s, sys, conn, stream, 500, br#"{"error":"server_error"}"#);
        return;
    };

    let mut body = [0u8; MAX_PAYLOAD * 2 + 192];
    let mut at = 0usize;
    let _ = put(&mut body, &mut at, br#"{"epoch":"#);
    let _ = put_u64(&mut body, &mut at, endpoint.marker.epoch);
    let _ = put(&mut body, &mut at, br#","generation":"#);
    let _ = put_u64(&mut body, &mut at, u64::from(endpoint.marker.generation));
    let _ = put(&mut body, &mut at, br#","payload":""#);
    let _ = put(&mut body, &mut at, &encoded[..encoded_len]);
    let _ = put(&mut body, &mut at, br#"","present":true,"revision":"#);
    let _ = put_u64(&mut body, &mut at, endpoint.revision);
    let _ = put(&mut body, &mut at, b"}");

    s.state_loaded = s.state_loaded.saturating_add(1);
    respond(s, sys, conn, stream, 200, &body[..at]);
}

/// Advance the state, conditionally.
///
/// # Safety
///
/// As `handle_request`.
unsafe fn commit(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    body_at: usize,
    body_end: usize,
) {
    let mut key = [0u8; MAX_KEY];
    let mut payload = [0u8; MAX_PAYLOAD];
    let (key_len, payload_len, expected, epoch, generation) = {
        let body = &s.buf[body_at..body_end];
        let key_len = json_string(body, b"endpoint", &mut key);
        let mut encoded = [0u8; MAX_PAYLOAD * 2];
        let encoded_len = json_string(body, b"payload", &mut encoded);
        let payload_len = if encoded_len == 0 {
            0
        } else {
            b64::decode(&encoded[..encoded_len], &mut payload).unwrap_or(0)
        };
        (
            key_len,
            payload_len,
            jose::claim_u64(body, b"expected_revision").unwrap_or(u64::MAX),
            jose::claim_u64(body, b"epoch").unwrap_or(0),
            jose::claim_u64(body, b"generation").unwrap_or(0),
        )
    };

    let Ok(generation) = u32::try_from(generation) else {
        respond(s, sys, conn, stream, 400, br#"{"error":"invalid_request"}"#);
        return;
    };
    if key_len == 0 || payload_len == 0 || expected == u64::MAX {
        respond(s, sys, conn, stream, 400, br#"{"error":"invalid_request"}"#);
        return;
    }
    let offered = Marker { epoch, generation };

    let index = match find(s, &key[..key_len]) {
        Some(index) => index,
        None => {
            let Some(free) = s.endpoints.iter().position(|e| !e.live) else {
                s.state_table_full = s.state_table_full.saturating_add(1);
                respond(
                    s,
                    sys,
                    conn,
                    stream,
                    503,
                    br#"{"error":"temporarily_unavailable"}"#,
                );
                return;
            };
            let endpoint = &mut s.endpoints[free];
            *endpoint = Endpoint::empty();
            endpoint.key[..key_len].copy_from_slice(&key[..key_len]);
            #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_KEY")]
            {
                endpoint.key_len = key_len as u8;
            }
            endpoint.live = true;
            free
        }
    };

    if s.endpoints[index].poisoned {
        s.state_poisoned = s.state_poisoned.saturating_add(1);
        respond(s, sys, conn, stream, 409, br#"{"error":"poisoned"}"#);
        return;
    }

    // The condition, before anything else: a commit that lost the race has
    // not been evaluated against the state that won, so nothing it says about
    // advancing means anything yet.
    if expected != s.endpoints[index].revision {
        s.state_superseded = s.state_superseded.saturating_add(1);
        let mut body = [0u8; 128];
        let mut at = 0usize;
        let _ = put(&mut body, &mut at, br#"{"error":"superseded","found":"#);
        let _ = put_u64(&mut body, &mut at, s.endpoints[index].revision);
        let _ = put(&mut body, &mut at, b"}");
        respond(s, sys, conn, stream, 409, &body[..at]);
        return;
    }

    if s.endpoints[index].has_state && !offered.advances_on(s.endpoints[index].marker) {
        let held = s.endpoints[index].marker;
        if offered == held {
            // The same position again: an optimistic retry after an ambiguous
            // failure. Refused — committing a position twice is how a retry
            // turns into a reused generation — but it is not evidence that
            // anything is wrong, so the endpoint keeps running.
            s.state_not_advancing = s.state_not_advancing.saturating_add(1);
            respond(s, sys, conn, stream, 409, br#"{"error":"not_advancing"}"#);
        } else {
            // Behind the current position, while quoting the current
            // revision: the caller loaded this state and is offering
            // something older than it. Its ratchet has gone backwards.
            s.endpoints[index].poisoned = true;
            s.state_rolled_back = s.state_rolled_back.saturating_add(1);
            respond(s, sys, conn, stream, 409, br#"{"error":"rolled_back"}"#);
        }
        return;
    }

    let endpoint = &mut s.endpoints[index];
    endpoint.marker = offered;
    endpoint.payload = [0; MAX_PAYLOAD];
    endpoint.payload[..payload_len].copy_from_slice(&payload[..payload_len]);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_PAYLOAD")]
    {
        endpoint.payload_len = payload_len as u16;
    }
    endpoint.revision = endpoint.revision.saturating_add(1);
    endpoint.has_state = true;

    let revision = endpoint.revision;
    s.state_committed = s.state_committed.saturating_add(1);
    let mut body = [0u8; 96];
    let mut at = 0usize;
    let _ = put(&mut body, &mut at, br#"{"committed":true,"revision":"#);
    let _ = put_u64(&mut body, &mut at, revision);
    let _ = put(&mut body, &mut at, b"}");
    respond(s, sys, conn, stream, 200, &body[..at]);
}

fn find(s: &ModuleState, key: &[u8]) -> Option<usize> {
    s.endpoints
        .iter()
        .position(|e| e.live && &e.key[..usize::from(e.key_len)] == key)
}

fn json_string(body: &[u8], key: &[u8], out: &mut [u8]) -> usize {
    let Some(value) = jose::claim_str(body, key) else {
        return 0;
    };
    if value.is_empty() || value.len() > out.len() {
        return 0;
    }
    out[..value.len()].copy_from_slice(value);
    value.len()
}

fn put(out: &mut [u8], at: &mut usize, bytes: &[u8]) -> Option<()> {
    let end = at.checked_add(bytes.len())?;
    out.get_mut(*at..end)?.copy_from_slice(bytes);
    *at = end;
    Some(())
}

fn put_u64(out: &mut [u8], at: &mut usize, mut value: u64) -> Option<()> {
    if value == 0 {
        return put(out, at, b"0");
    }
    let mut digits = [0u8; 20];
    let mut n = 0usize;
    while value > 0 && n < digits.len() {
        digits[n] = b'0' + u8::try_from(value % 10).ok()?;
        value /= 10;
        n += 1;
    }
    let mut ordered = [0u8; 20];
    for i in 0..n {
        ordered[i] = digits[n - 1 - i];
    }
    put(out, at, &ordered[..n])
}

/// # Safety
///
/// As `handle_request`.
unsafe fn respond(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    status: u16,
    body: &[u8],
) {
    const CT: &[u8] = b"application/json";
    let total = RESP_HDR + CT.len() + body.len();
    if total > s.out.len() {
        return;
    }
    s.out[0..2].copy_from_slice(&conn.to_le_bytes());
    s.out[2..4].copy_from_slice(&stream.to_le_bytes());
    s.out[4..6].copy_from_slice(&status.to_le_bytes());
    s.out[6] = 0;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "CT is a 16-byte literal, so the length fits a u8"
    )]
    {
        s.out[7] = CT.len() as u8;
    }
    s.out[8..10].copy_from_slice(&0u16.to_le_bytes());
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by the `total > s.out.len()` check above"
    )]
    {
        s.out[10..12].copy_from_slice(&(body.len() as u16).to_le_bytes());
    }
    s.out[RESP_HDR..RESP_HDR + CT.len()].copy_from_slice(CT);
    s.out[RESP_HDR + CT.len()..total].copy_from_slice(body);

    (sys.channel_write)(s.out_responses, s.out.as_ptr(), total);
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

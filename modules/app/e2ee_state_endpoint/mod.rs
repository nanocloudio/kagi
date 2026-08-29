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
//! There is no separate high-water mark. A store that keeps its state in a
//! file wants one in a second file, so that restoring a backup of the first
//! alone is caught by the second; here the state lives in this module's own
//! memory, where a mark would sit in the same memory as the state it attests
//! to and could never disagree with it. The committed marker IS the furthest
//! position ever reached, and the check is against that.
//!
//! **What that does not survive is a restart.** The table is memory and
//! nothing else: a module that restarts comes back with every endpoint at
//! revision 0 and no marker, and will accept a first commit at any position
//! — including one already used. Nothing here can detect that, because the
//! evidence went with the state. An endpoint whose module has restarted must
//! rejoin the group rather than resume, and a deployment that cannot promise
//! a restart is rare needs the marker somewhere that outlives the module.
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
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha384.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/hmac.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/p256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/ed25519.rs");

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/b64.rs"]
mod b64;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/device_auth.rs"]
mod device_auth;
#[path = "../../common/dpop.rs"]
mod dpop;
#[path = "../../common/jose.rs"]
mod jose;
#[path = "../../common/jwk.rs"]
mod jwk;
#[path = "../../common/time_policy.rs"]
mod time_policy;
#[path = "../../common/verify_keyset.rs"]
mod verify_keyset;

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

/// How long a DPoP proof stays fresh, and therefore how long its `jti`
/// must be remembered.
///
/// One constant for both, because they are one number: remembering a proof
/// for less than its freshness window leaves a replayable gap, and
/// remembering it for longer wastes a slot on a proof `check_proof` would
/// refuse anyway.
const PROOF_WINDOW_SECS: u64 = 300;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    in_verify_key: i32,

    /// The issuer keyset. More than one key, indexed by the `kid` a
    /// credential names — see `verify_keyset.rs` for why a single
    /// overwritten key made rotation destructive here.
    keyset: verify_keyset::Keyset,
    /// Proof replay, for this process.
    ///
    /// Time-bounded and fail-closed: an entry lives until the proof it came
    /// from would be refused as stale anyway, and a saturated window refuses
    /// rather than evicting — an eviction under load is an admission under
    /// load.
    ///
    /// Process-local, and correctly so: the state this module guards is its
    /// own memory, so a proof replayed at another replica reaches a
    /// different pool of state and can take nothing this one holds. The
    /// modules whose decisions rest on the shared ledger — admission and the
    /// authorization-code flow — claim their replay identifiers there
    /// instead, because there a replay at another replica reaches the same
    /// state.
    replay: dpop::ReplayWindow<128>,

    state_unauthenticated: u32,
    state_not_owner: u32,
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
        s.in_verify_key = dev_channel_port(sys, 0, 1);
        s.keyset = verify_keyset::Keyset::new();
        s.replay = dpop::ReplayWindow::new();
        s.state_unauthenticated = 0;
        s.state_not_owner = 0;
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

        drain_verify_key(s, sys);

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

    // ── who is asking about whose state ──────────────────────────────────
    //
    // This endpoint held the high-water mark that makes rollback detectable
    // and served it to anyone: a load returned another party's state and a
    // commit advanced it. It is the one endpoint where exposure is least
    // acceptable, because the state it holds is what a rollback attack has to
    // defeat — and it was the one with no authentication at all.
    let mut route = [0u8; MAX_KEY];
    let route_len = path_len.min(MAX_KEY);
    route[..route_len].copy_from_slice(&s.buf[REQ_HDR..REQ_HDR + route_len]);
    let Some(device) = authenticate(s, sys, conn, stream, &route[..route_len], body_at) else {
        return;
    };

    if loading {
        load(s, sys, conn, stream, body_at, body_end, &device);
    } else {
        commit(s, sys, conn, stream, body_at, body_end, &device);
    }
}

/// The device a verified certificate names.
#[derive(Clone, Copy)]
struct AuthenticatedDevice {
    id: [u8; MAX_KEY],
    len: usize,
}

impl AuthenticatedDevice {
    fn as_bytes(&self) -> &[u8] {
        &self.id[..self.len]
    }

    /// Whether `key` is state this device owns.
    ///
    /// Ownership is a prefix rule: an endpoint key belongs to the device
    /// whose id it starts with. That lets one device hold several endpoints
    /// — one per group it is in — without needing a registry, while keeping
    /// every one of them out of reach of anybody else.
    ///
    /// This is what closes both the cross-device read and the deliberate
    /// poisoning: only the owner can trip its own ratchet, so the poisoned
    /// flag stops being a denial-of-service primitive anyone can reach for.
    fn owns(&self, key: &[u8]) -> bool {
        let id = self.as_bytes();
        key.len() >= id.len() && &key[..id.len()] == id
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
    device: &AuthenticatedDevice,
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

    // The endpoint has to be one this device owns. Without this a caller
    // could read another party's high-water mark, or advance it — and the
    // poisoned flag would be a denial-of-service anybody could reach.
    if !device.owns(&key[..key_len]) {
        s.state_not_owner = s.state_not_owner.saturating_add(1);
        respond(s, sys, conn, stream, 403, br#"{"error":"forbidden"}"#);
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
    device: &AuthenticatedDevice,
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

    // ── validate first, allocate second ──────────────────────────────────
    //
    // Nothing is allocated here: a miss is evaluated as revision 0 with no
    // state, and the slot is taken only in the write step. Claiming a slot
    // before the `expected` comparison below would let an invalid first
    // commit for an unknown key hold one permanently, and MAX_ENDPOINTS of
    // them would exhaust the table for every legitimate endpoint.

    // The endpoint has to be one this device owns. Without this a caller
    // could read another party's high-water mark, or advance it — and the
    // poisoned flag would be a denial-of-service anybody could reach.
    if !device.owns(&key[..key_len]) {
        s.state_not_owner = s.state_not_owner.saturating_add(1);
        respond(s, sys, conn, stream, 403, br#"{"error":"forbidden"}"#);
        return;
    }
    let existing = find(s, &key[..key_len]);
    let (held_revision, held_marker, held_has_state, held_poisoned) = match existing {
        Some(index) => (
            s.endpoints[index].revision,
            s.endpoints[index].marker,
            s.endpoints[index].has_state,
            s.endpoints[index].poisoned,
        ),
        None => (0, Marker::ZERO, false, false),
    };

    if held_poisoned {
        s.state_poisoned = s.state_poisoned.saturating_add(1);
        respond(s, sys, conn, stream, 409, br#"{"error":"poisoned"}"#);
        return;
    }

    // The condition, before anything else: a commit that lost the race has
    // not been evaluated against the state that won, so nothing it says about
    // advancing means anything yet.
    if expected != held_revision {
        s.state_superseded = s.state_superseded.saturating_add(1);
        let mut body = [0u8; 128];
        let mut at = 0usize;
        let _ = put(&mut body, &mut at, br#"{"error":"superseded","found":"#);
        let _ = put_u64(&mut body, &mut at, held_revision);
        let _ = put(&mut body, &mut at, b"}");
        respond(s, sys, conn, stream, 409, &body[..at]);
        return;
    }

    if held_has_state && !offered.advances_on(held_marker) {
        let held = held_marker;
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
            //
            // Only a slot that already exists can be poisoned. A first commit
            // cannot roll anything back — there is nothing behind it — so an
            // unknown key never reaches here with `held_has_state`.
            if let Some(index) = existing {
                s.endpoints[index].poisoned = true;
            }
            s.state_rolled_back = s.state_rolled_back.saturating_add(1);
            respond(s, sys, conn, stream, 409, br#"{"error":"rolled_back"}"#);
        }
        return;
    }

    // Allocation happens here, once the commit has been shown to be valid.
    let index = match existing {
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

/// The primitives the shared authentication fragment is given.
const VERIFIERS: device_auth::Verifiers = device_auth::Verifiers {
    sha256: sha256_into,
    ecdsa_verify,
    ed25519_verify,
};

/// Device certificates only.
const POLICY: device_auth::Policy = device_auth::Policy {
    proof_max_age_secs: PROOF_WINDOW_SECS,
    clock_skew_secs: 60,
    expected_cty: Some(b"dc+jwt"),
};

fn sha256_into(data: &[u8], out: &mut [u8; 32]) {
    *out = sha256(data);
}

/// Verify the presented device certificate and return the device it names.
///
/// # Safety
///
/// As `handle_request`.
unsafe fn authenticate(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    path: &[u8],
    body_at: usize,
) -> Option<AuthenticatedDevice> {
    if s.keyset.is_empty() {
        respond(
            s,
            sys,
            conn,
            stream,
            503,
            br#"{"error":"temporarily_unavailable"}"#,
        );
        return None;
    }
    let path_len = path.len();
    let mut credential = [0u8; device_auth::MAX_SEGMENT];
    let mut proof = [0u8; device_auth::MAX_SEGMENT];
    let (credential_len, proof_len) = {
        let headers = &s.buf[REQ_HDR + path_len..body_at];
        (
            header_value(headers, b"authorization")
                .and_then(strip_dpop_scheme)
                .map_or(0, |v| copy_into(v, &mut credential)),
            header_value(headers, b"dpop").map_or(0, |v| copy_into(v, &mut proof)),
        )
    };
    if credential_len == 0 || proof_len == 0 {
        s.state_unauthenticated = s.state_unauthenticated.saturating_add(1);
        respond(s, sys, conn, stream, 401, br#"{"error":"invalid_client"}"#);
        return None;
    }

    // A credential's validity window is a statement about a date, so it
    // needs a clock worth believing — and 503 rather than 401, because a
    // deployment without a trustworthy clock has not been given what it
    // needs, which is not the caller's fault.
    //
    // `dev_unix_millis(sys) / 1000` returns 0 on a platform with no RTC,
    // and 0 is a NUMBER: it flowed into the window comparison and the
    // comparison answered. Every `exp` exceeds 0, so a missing clock read
    // as "not yet expired".
    let obs = dev_trusted_unix(sys);
    let Some(now) = time_policy::now_for(time_policy::Decision::CredentialWindow, &obs) else {
        s.state_unauthenticated = s.state_unauthenticated.saturating_add(1);
        respond(
            s,
            sys,
            conn,
            stream,
            503,
            br#"{"error":"temporarily_unavailable"}"#,
        );
        return None;
    };
    let mut claims_buf = [0u8; device_auth::MAX_SEGMENT];
    // Which key signed the credential is the credential's own claim, in
    // its JOSE header. It is looked up, never guessed: an unknown kid is
    // refused rather than checked against whatever key is loaded.
    let mut pubkey = [0u8; 65];
    let mut pubkey_len = 0usize;
    let mut key_suite = 0u16;
    let mut kid = [0u8; verify_keyset::MAX_KID_LEN];
    if let Some(kid_len) = device_auth::credential_kid(&credential[..credential_len], &mut kid) {
        if let Some(k) = s.keyset.select(&kid[..kid_len], now) {
            pubkey_len = k.pubkey_bytes().len();
            pubkey[..pubkey_len].copy_from_slice(k.pubkey_bytes());
            key_suite = k.suite;
        }
    }

    let admitted = {
        // The window fails closed: a saturated one refuses rather than
        // evicting a live entry, because an eviction under load is an
        // admission under load. Both refusals reach `device_auth` as
        // `false`; the counters below keep them apart for an operator,
        // since "somebody replayed a proof" and "the window is saturated"
        // are different problems.
        let mut replay = |jti: &[u8; 32]| match s.replay.offer(jti, now, now + PROOF_WINDOW_SECS) {
            dpop::Replay::Recorded => true,
            dpop::Replay::Seen => false,
            dpop::Replay::Full => false,
        };
        device_auth::authenticate(
            &VERIFIERS,
            &device_auth::IssuerKey {
                suite: key_suite,
                public: &pubkey[..pubkey_len],
            },
            &device_auth::Presentation {
                credential: &credential[..credential_len],
                proof: &proof[..proof_len],
            },
            &device_auth::Request {
                method: b"POST",
                uri: path,
                now,
            },
            &POLICY,
            &mut claims_buf,
            &mut replay,
        )
    };
    let Ok(admitted) = admitted else {
        s.state_unauthenticated = s.state_unauthenticated.saturating_add(1);
        respond(s, sys, conn, stream, 401, br#"{"error":"invalid_client"}"#);
        return None;
    };
    let Some(device_id) = jose::claim_str(admitted.claims, b"device_id") else {
        s.state_unauthenticated = s.state_unauthenticated.saturating_add(1);
        respond(s, sys, conn, stream, 401, br#"{"error":"invalid_client"}"#);
        return None;
    };
    let mut out = AuthenticatedDevice {
        id: [0u8; MAX_KEY],
        len: 0,
    };
    let n = device_id.len().min(MAX_KEY);
    out.id[..n].copy_from_slice(&device_id[..n]);
    out.len = n;
    Some(out)
}

/// Drain `verify_key`, keeping the key lifecycle into the keyset.
///
/// # Safety
///
/// As `handle_request`.
unsafe fn drain_verify_key(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_verify_key < 0 {
        return;
    }
    for _ in 0..4 {
        if !chan::can_read(sys, s.in_verify_key) {
            break;
        }
        let mut buf = [0u8; 256];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_verify_key, &mut buf);
        let payload = &buf[..plen as usize];
        // The whole key lifecycle, not a single overwriting delivery. See
        // `verify_keyset.rs`: a store holding one key and discarding the kid
        // cannot rotate — the new key invalidates every live credential the
        // moment it lands, and an unknown kid is checked against whatever
        // arrived last.
        s.keyset.apply(msg_type, payload);
    }
}

/// A header value by lowercase name.
fn header_value<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut at = 0usize;
    while at < headers.len() {
        let end = headers[at..]
            .iter()
            .position(|b| *b == b'\n')
            .map_or(headers.len(), |p| at + p);
        let line = &headers[at..end];
        if let Some(colon) = line.iter().position(|b| *b == b':') {
            let (key, value) = line.split_at(colon);
            if key.len() == name.len()
                && key
                    .iter()
                    .zip(name)
                    .all(|(a, b)| a.to_ascii_lowercase() == *b)
            {
                return Some(trim(&value[1..]));
            }
        }
        at = end + 1;
    }
    None
}

fn strip_dpop_scheme(value: &[u8]) -> Option<&[u8]> {
    let scheme = b"DPoP ";
    if value.len() > scheme.len() && value[..scheme.len()].eq_ignore_ascii_case(scheme) {
        Some(trim(&value[scheme.len()..]))
    } else {
        None
    }
}

fn copy_into(value: &[u8], out: &mut [u8]) -> usize {
    let n = value.len().min(out.len());
    out[..n].copy_from_slice(&value[..n]);
    if value.len() > out.len() {
        0
    } else {
        n
    }
}

fn trim(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = bytes.split_last() {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

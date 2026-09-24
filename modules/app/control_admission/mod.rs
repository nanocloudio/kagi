//! Control-plane admission — decide who may open the issuer's control socket.
//!
//! The reference issuer distributes its signing key, its verification keys,
//! KEK epochs and revocation input over one WebSocket. A caller who reaches
//! that socket does not merely obtain a credential for a subject of their
//! choosing: they obtain the authority to mint any credential the deployment
//! can mint, and to withhold the revocation input that would otherwise
//! contain the damage. It is the highest-value surface in the graph and it
//! has been the least protected.
//!
//! Two layers protect it, and they answer different questions.
//!
//! `tls` answers *is this peer who they claim to be* — it refuses the
//! handshake outright unless the client presents a certificate under the
//! configured peer-auth profile, and it refuses to construct at all if no
//! profile is set. This module answers the second question, *and is this
//! particular peer allowed here*, because a trust anchor authenticates a key
//! and not an operator role. A deployment that issues client certificates for
//! several purposes from one CA would otherwise find every one of them able
//! to feed the issuer a signing key.
//!
//! ## Why the decision happens before the upgrade
//!
//! wave's `http` reports the upgrade on `ws_admit_out` and composes the 101
//! only once this module answers accept. That timing is the point. A gate
//! placed downstream of a completed upgrade can refuse to act on frames, but
//! the socket is already open and the peer already believes it is talking to
//! the issuer; here nothing above ever sees a frame from a connection that
//! was not admitted, and a refusal reaches the client as an HTTP status
//! rather than a socket that opens and then goes quiet.
//!
//! ## The correlation, and the race it has to survive
//!
//! `http` sits above whatever terminated TLS, and its admission record
//! deliberately carries no transport facts — no peer address, no "secure"
//! flag — because those would be values invented at that seam. So the
//! verified identity arrives separately, on `tls`'s own `peer_identity` port,
//! and the two are joined by connection id, which `tls` preserves as it
//! proxies between `linux_net` and `http`.
//!
//! They arrive on different channels and can therefore arrive out of order.
//! An admission request whose identity has not landed yet is **held**, for a
//! bounded number of steps, and refused when that budget runs out. It is
//! never admitted on the assumption that the identity is merely late: an
//! ordering accident must not become an authentication bypass.
//!
//! ## What this module does not do
//!
//! It does not enforce certificate lifetimes. Under the `pinned` peer-auth
//! profile `tls` is configured with `clock_policy: unchecked`, because
//! `timer::UNIX_MILLIS` may legitimately return zero on a platform with no
//! RTC and a control plane that refuses every handshake after a clock failure
//! is its own outage. Pin rotation is therefore the revocation mechanism for
//! control-plane clients, and that is a consequence of the missing trusted-time
//! surface rather than a choice made here.

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

// `chan` reads message envelopes, so it needs `auth_wire` alongside it even
// though this module speaks wave's admission wire rather than kagi's.
#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/chan.rs"]
mod chan;

// wave's admission wire, mounted from the materialised `wave-common` tree
// rather than restated here. A second copy of a wire definition is how two
// repos come to disagree about a layout neither can check for the other.
#[path = "../../../target/fluxor/wave-common/ws_admit.rs"]
mod ws_admit;

use ws_admit::{
    parse_ws_admit_request, write_ws_admit_decision, WS_ADMIT_ACCEPT, WS_ADMIT_REJECT,
    WS_OP_ADMIT_REQUEST, WS_OP_EVENT,
};

/// fluxor `tls`'s peer-identity envelope.
///
/// The payload is a record of typed facts, not a boolean: see
/// `MSG_PEER_IDENTITY` in `fluxor/modules/foundation/tls/mod.rs`. What this
/// gate needs from it is the session id, whether verification succeeded, and
/// the peer's key fingerprint.
const MSG_PEER_IDENTITY: u8 = 0x5A;
/// Envelope header: type plus the u16 length.
const PEER_ENVELOPE_HDR: usize = 3;
/// Fixed part of the payload, before the fingerprint and principal.
const PEER_FIXED: usize = 4 + 1 + 1 + 2 + 8 + 8 + 4 + 1 + 1 + 2;
/// `verification_result == OK`.
const PEER_RESULT_OK: u8 = 0;
/// Field offsets within the payload.
const PEER_OFF_SESSION: usize = 0;
const PEER_OFF_RESULT: usize = 4;
const PEER_OFF_FLAGS: usize = 24;
const PEER_OFF_FP_LEN: usize = 29;
/// `verification_flags` bits this gate insists on. A chain that was
/// validated and a key whose possession was proved are the two facts that
/// make a fingerprint mean anything: without the first the fingerprint is
/// from an untrusted certificate, and without the second it is from a
/// certificate the peer merely copied.
const PEER_CHECK_CHAIN: u32 = 0x0000_0001;
const PEER_CHECK_KEY_POSSESSION: u32 = 0x0000_0010;
/// A SHA-256 fingerprint of the peer leaf's subject key.
const MAX_SVID: usize = 32;

/// Connections whose identity is remembered at once.
const MAX_CONNS: usize = 32;
/// Admission requests held waiting for an identity at once.
const MAX_PENDING: usize = 16;
/// How many steps an admission request may wait for its identity.
///
/// The two edges are driven by the same scheduler, so an identity that is
/// coming at all arrives quickly — but "quickly" is measured in scheduler
/// steps on a loaded host, not in handshakes, and `tls` latches the identity
/// and RETRIES it on backpressure, so it can be several steps behind the
/// upgrade it belongs to. At a 500 µs tick this is about two seconds:
/// generous enough that a busy graph does not refuse honest clients, and
/// bounded so a refusal is still a refusal rather than a hang.
///
/// Waiting longer is always safe. The failure direction that matters is
/// admitting without an identity, which no budget can cause.
const PENDING_MAX_STEPS: u16 = 4000;

/// Allowlist capacity, in 32-byte entries.
const MAX_ALLOWED: usize = 8;

const MAX_PATH: usize = 64;
const BUF_LEN: usize = 4096;

/// A connection whose TLS identity has been observed.
#[derive(Clone, Copy)]
struct Peer {
    conn: u32,
    verified: bool,
    svid: [u8; MAX_SVID],
    svid_len: u8,
    live: bool,
}

impl Peer {
    const fn zero() -> Self {
        Self {
            conn: 0,
            verified: false,
            svid: [0u8; MAX_SVID],
            svid_len: 0,
            live: false,
        }
    }
}

/// An upgrade request waiting for its connection's identity.
#[derive(Clone, Copy)]
struct Pending {
    conn: u32,
    path: [u8; MAX_PATH],
    path_len: u8,
    waited: u16,
    live: bool,
}

impl Pending {
    const fn zero() -> Self {
        Self {
            conn: 0,
            path: [0u8; MAX_PATH],
            path_len: 0,
            waited: 0,
            live: false,
        }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    out_admit: i32,
    in_peer: i32,
    in_admit: i32,
    in_event: i32,

    /// Concatenated 32-byte peer-key hashes, from the `allowed_svid` param.
    allowed: [u8; MAX_ALLOWED * MAX_SVID],
    allowed_count: u8,
    /// The path this gate guards. An upgrade on any other path is refused.
    control_path: [u8; MAX_PATH],
    control_path_len: u8,
    /// When zero, an unverified peer is admitted.
    ///
    /// It exists so a development graph can run the same module without
    /// certificates, and it defaults to on. A deployment that turns it off
    /// has removed the gate, which is why doing so is logged at start-up.
    require_verified: u8,

    peers: [Peer; MAX_CONNS],
    pending: [Pending; MAX_PENDING],

    buf: [u8; BUF_LEN],
    out: [u8; BUF_LEN],

    admit_granted: u32,
    admit_refused_unverified: u32,
    admit_refused_not_allowed: u32,
    admit_refused_path: u32,
    admit_refused_timeout: u32,
    peer_identities: u32,
}

define_params! {
    ModuleState;

    1, allowed_svid, str, 0 => |s, d, len| {
        // Concatenated lowercase hex, 64 characters per entry. Hex rather
        // than raw bytes because this arrives from a YAML graph, where a
        // string is the only thing a value can be — and an operator can read
        // a hex digest back out of a config, which is the point of pinning
        // one. Anything that is not a whole number of entries contributes
        // only its whole ones: a partial entry would compare against zero
        // padding and match a peer whose hash happened to end in zeros.
        let cap = MAX_ALLOWED * MAX_SVID * 2;
        let n = if len > cap { cap } else { len };
        let entries = n / (MAX_SVID * 2);
        let mut e = 0usize;
        while e < entries {
            let mut b = 0usize;
            while b < MAX_SVID {
                let at = (e * MAX_SVID * 2) + (b * 2);
                let hi = hex_nibble(*d.add(at));
                let lo = hex_nibble(*d.add(at + 1));
                // A non-hex character makes the whole entry meaningless, so
                // the entry is dropped rather than silently zero-filled.
                if hi == 0xFF || lo == 0xFF {
                    return;
                }
                s.allowed[(e * MAX_SVID) + b] = (hi << 4) | lo;
                b += 1;
            }
            e += 1;
        }
        #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_ALLOWED")]
        {
            s.allowed_count = entries as u8;
        }
    };

    2, control_path, str, 0 => |s, d, len| {
        let n = if len > MAX_PATH { MAX_PATH } else { len };
        let mut i = 0usize;
        while i < n {
            s.control_path[i] = *d.add(i);
            i += 1;
        }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_PATH above")]
        {
            s.control_path_len = n as u8;
        }
    };

    3, require_verified, u8, 1 => |s, d, len| {
        if len >= 1 {
            s.require_verified = *d;
        }
    };
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[expect(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "fluxor module ABI entry point: the runtime owns these pointers \
              and the signature is fixed by the contract"
)]
#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
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

        s.out_admit = out_chan;
        s.in_peer = dev_channel_port(sys, 0, 0);
        s.in_admit = dev_channel_port(sys, 0, 1);
        s.in_event = dev_channel_port(sys, 0, 2);

        s.peers = [Peer::zero(); MAX_CONNS];
        s.pending = [Pending::zero(); MAX_PENDING];
        s.allowed = [0u8; MAX_ALLOWED * MAX_SVID];
        s.allowed_count = 0;
        s.control_path = [0u8; MAX_PATH];
        s.control_path_len = 0;
        s.admit_granted = 0;
        s.admit_refused_unverified = 0;
        s.admit_refused_not_allowed = 0;
        s.admit_refused_path = 0;
        s.admit_refused_timeout = 0;
        s.peer_identities = 0;

        parse_tlv(s, params, params_len);

        if s.require_verified == 0 {
            dev_log(
                sys,
                1,
                b"[ctladm] require_verified=0: the control gate is OFF".as_ptr(),
                49,
            );
        }
        if s.allowed_count == 0 {
            // Not an error: a deployment may choose to let the trust anchor
            // be the whole policy. Said out loud because it is the difference
            // between "this operator" and "anyone this CA has ever signed".
            dev_log(
                sys,
                2,
                b"[ctladm] no allowed_svid: any verified peer is admitted".as_ptr(),
                55,
            );
        }
        dev_log(sys, 3, b"[ctladm] init".as_ptr(), 13);
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

        // Identities first, so an admission request that arrived in the same
        // step as its identity is answered now rather than held for a step.
        drain_peer_identities(s, sys);
        drain_events(s, sys);
        drain_admissions(s, sys);
        service_pending(s, sys);
        0
    }
}

/// Latch verified identities as they arrive.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn drain_peer_identities(s: &mut ModuleState, sys: &SyscallTable) {
    while chan::can_read(sys, s.in_peer) {
        let n = (sys.channel_read)(s.in_peer, s.buf.as_mut_ptr(), s.buf.len());
        if n <= 0 {
            break;
        }
        let n = n as usize;
        if n < PEER_ENVELOPE_HDR + PEER_FIXED || s.buf[0] != MSG_PEER_IDENTITY {
            continue;
        }
        let at = PEER_ENVELOPE_HDR;
        let conn = u32::from_le_bytes([
            s.buf[at + PEER_OFF_SESSION],
            s.buf[at + PEER_OFF_SESSION + 1],
            s.buf[at + PEER_OFF_SESSION + 2],
            s.buf[at + PEER_OFF_SESSION + 3],
        ]);
        let flags = u32::from_le_bytes([
            s.buf[at + PEER_OFF_FLAGS],
            s.buf[at + PEER_OFF_FLAGS + 1],
            s.buf[at + PEER_OFF_FLAGS + 2],
            s.buf[at + PEER_OFF_FLAGS + 3],
        ]);
        // Not "the result byte says OK", but "the checks that make a
        // fingerprint meaningful actually ran". A result of OK with the
        // chain unchecked would be a peer this gate has no reason to trust,
        // and the record exists precisely so that is expressible.
        let verified = s.buf[at + PEER_OFF_RESULT] == PEER_RESULT_OK
            && (flags & PEER_CHECK_CHAIN) != 0
            && (flags & PEER_CHECK_KEY_POSSESSION) != 0;
        let svid_len = usize::from(s.buf[at + PEER_OFF_FP_LEN]).min(MAX_SVID);
        let svid_at = at + PEER_FIXED;
        if svid_at + svid_len > n {
            continue;
        }
        let mut svid = [0u8; MAX_SVID];
        svid[..svid_len].copy_from_slice(&s.buf[svid_at..svid_at + svid_len]);

        // `tls` latches this envelope and retries it on backpressure, so it
        // is at-least-once: a repeat for a connection already recorded
        // overwrites rather than allocating a second row.
        let slot = s
            .peers
            .iter()
            .position(|p| p.live && p.conn == conn)
            .or_else(|| s.peers.iter().position(|p| !p.live));
        let Some(slot) = slot else {
            // The table is full of live connections. Dropping the identity
            // means the pending request for it will time out and be refused,
            // which is the safe direction.
            continue;
        };
        s.peers[slot] = Peer {
            conn,
            verified,
            svid,
            #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_SVID")]
            svid_len: svid_len as u8,
            live: true,
        };
        s.peer_identities = s.peer_identities.saturating_add(1);
    }
}

/// Release a connection's identity when it closes.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn drain_events(s: &mut ModuleState, sys: &SyscallTable) {
    while chan::can_read(sys, s.in_event) {
        let n = (sys.channel_read)(s.in_event, s.buf.as_mut_ptr(), s.buf.len());
        if n <= 0 {
            break;
        }
        let n = n as usize;
        if n < ws_admit::WS_EVENT_HDR || s.buf[0] != WS_OP_EVENT {
            continue;
        }
        let conn = u32::from_le_bytes([s.buf[1], s.buf[2], s.buf[3], s.buf[4]]);
        if s.buf[5] != ws_admit::WS_EV_CLOSED {
            continue;
        }
        for peer in &mut s.peers {
            if peer.live && peer.conn == conn {
                *peer = Peer::zero();
            }
        }
    }
}

/// Answer, or hold, each upgrade request.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn drain_admissions(s: &mut ModuleState, sys: &SyscallTable) {
    while chan::can_read(sys, s.in_admit) {
        if !chan::can_write(sys, s.out_admit) {
            break;
        }
        let n = (sys.channel_read)(s.in_admit, s.buf.as_mut_ptr(), s.buf.len());
        if n <= 0 {
            break;
        }
        let n = n as usize;
        if s.buf[0] != WS_OP_ADMIT_REQUEST {
            continue;
        }
        let Some(view) = parse_ws_admit_request(&s.buf[..n]) else {
            continue;
        };
        let mut path = [0u8; MAX_PATH];
        let path_len = view.path_len.min(MAX_PATH);
        path[..path_len].copy_from_slice(&s.buf[view.path_at..view.path_at + path_len]);

        // The path is this module's to check, and it is checked before the
        // identity: a request for a route this gate does not guard is a
        // configuration error, and answering it as an authentication failure
        // would send an operator looking in the wrong place.
        if !path_matches(s, &path[..path_len]) {
            s.admit_refused_path = s.admit_refused_path.saturating_add(1);
            refuse(s, sys, view.conn, b"path");
            continue;
        }

        match lookup(s, view.conn) {
            Some(idx) => decide(s, sys, view.conn, idx),
            None => hold(s, view.conn, &path[..path_len]),
        }
    }
}

/// Retry held requests, and refuse the ones whose budget has run out.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn service_pending(s: &mut ModuleState, sys: &SyscallTable) {
    for i in 0..MAX_PENDING {
        if !s.pending[i].live {
            continue;
        }
        if !chan::can_write(sys, s.out_admit) {
            return;
        }
        let conn = s.pending[i].conn;
        if let Some(idx) = lookup(s, conn) {
            s.pending[i] = Pending::zero();
            decide(s, sys, conn, idx);
            continue;
        }
        s.pending[i].waited = s.pending[i].waited.saturating_add(1);
        if s.pending[i].waited >= PENDING_MAX_STEPS {
            s.pending[i] = Pending::zero();
            s.admit_refused_timeout = s.admit_refused_timeout.saturating_add(1);
            // Never admitted on the assumption the identity is merely late.
            refuse(s, sys, conn, b"identity");
        }
    }
}

/// Hold a request whose identity has not arrived.
fn hold(s: &mut ModuleState, conn: u32, path: &[u8]) {
    let Some(slot) = s.pending.iter().position(|p| !p.live) else {
        // No room to wait. The request is simply not answered here; wave's
        // own admission timeout closes it, which is a refusal.
        return;
    };
    let mut buf = [0u8; MAX_PATH];
    let n = path.len().min(MAX_PATH);
    buf[..n].copy_from_slice(&path[..n]);
    s.pending[slot] = Pending {
        conn,
        path: buf,
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_PATH")]
        path_len: n as u8,
        waited: 0,
        live: true,
    };
}

/// Find a connection's latched identity.
fn lookup(s: &ModuleState, conn: u32) -> Option<usize> {
    s.peers.iter().position(|p| p.live && p.conn == conn)
}

/// Accept or refuse, given a latched identity.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn decide(s: &mut ModuleState, sys: &SyscallTable, conn: u32, idx: usize) {
    let peer = s.peers[idx];
    if s.require_verified != 0 && !peer.verified {
        s.admit_refused_unverified = s.admit_refused_unverified.saturating_add(1);
        refuse(s, sys, conn, b"unverified");
        return;
    }
    if !svid_allowed(s, &peer) {
        s.admit_refused_not_allowed = s.admit_refused_not_allowed.saturating_add(1);
        refuse(s, sys, conn, b"not-allowed");
        return;
    }
    s.admit_granted = s.admit_granted.saturating_add(1);
    let Some(len) = write_ws_admit_decision(conn, WS_ADMIT_ACCEPT, 101, &[], &[], &mut s.out)
    else {
        return;
    };
    let _ = (sys.channel_write)(s.out_admit, s.out.as_ptr(), len);
}

/// Refuse an upgrade with 403 and a short reason.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn refuse(s: &mut ModuleState, sys: &SyscallTable, conn: u32, reason: &[u8]) {
    let Some(len) = write_ws_admit_decision(conn, WS_ADMIT_REJECT, 403, &[], reason, &mut s.out)
    else {
        return;
    };
    let _ = (sys.channel_write)(s.out_admit, s.out.as_ptr(), len);
}

/// One hex character's value, or `0xFF` for anything that is not one.
const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0xFF,
    }
}

/// Whether a peer's key hash is on the allowlist.
///
/// An empty allowlist admits any verified peer — the trust anchor is then the
/// whole policy, which `module_new` says out loud at start-up.
fn svid_allowed(s: &ModuleState, peer: &Peer) -> bool {
    if s.allowed_count == 0 {
        return true;
    }
    let len = usize::from(peer.svid_len);
    if len != MAX_SVID {
        return false;
    }
    for i in 0..usize::from(s.allowed_count) {
        let at = i * MAX_SVID;
        if s.allowed[at..at + MAX_SVID] == peer.svid[..MAX_SVID] {
            return true;
        }
    }
    false
}

/// Whether the upgrade names the path this gate guards.
///
/// An unset `control_path` guards every path the module is wired to, which is
/// the safe default: a typo in the parameter must not silently open a route.
fn path_matches(s: &ModuleState, path: &[u8]) -> bool {
    let want = usize::from(s.control_path_len);
    if want == 0 {
        return true;
    }
    path == &s.control_path[..want]
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

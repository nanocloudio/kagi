//! E2EE path router — one listener for the whole `/e2ee/` family.
//!
//! wave's `http` has exactly one `req_out`, so two application modules cannot
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
//! Requests fan out by path prefix. Responses do **not** come back through
//! here: `HttpResponse` carries its own connection and stream ids, so each
//! endpoint answers the listener directly and this module needs no
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

/// `HttpRequest` fixed header, as every kagi endpoint reads it:
/// `[conn u32][method u8][_][path_len u16][hdr_len u16][_]`.
const REQ_HDR: usize = 12;

/// The path families, longest-first so `/e2ee/state/` is tested before any
/// shorter prefix could swallow it.
const PATH_KEYPKG: &[u8] = b"/e2ee/keypackages";
const PATH_STATE: &[u8] = b"/e2ee/state";
const PATH_CREDENTIAL: &[u8] = b"/e2ee/credential";

const BUF_LEN: usize = 8192;
const MAX_REQS_PER_STEP: usize = 8;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    out_credential: i32,
    out_keypkg: i32,
    out_state: i32,
    out_response: i32,
    buf: [u8; BUF_LEN],
    out: [u8; 256],
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

        for _ in 0..MAX_REQS_PER_STEP {
            if !chan::can_read(sys, s.in_requests) {
                break;
            }
            let n = (sys.channel_read)(s.in_requests, s.buf.as_mut_ptr(), s.buf.len());
            if n < REQ_HDR as i32 {
                break;
            }
            route(s, sys, n as usize);
        }
        0
    }
}

/// Forward one request to whichever endpoint owns its path.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn route(s: &mut ModuleState, sys: &SyscallTable, plen: usize) {
    let path_len = usize::from(u16::from_le_bytes([s.buf[6], s.buf[7]]));
    let Some(path_end) = REQ_HDR.checked_add(path_len) else {
        return;
    };
    if path_end > plen {
        return;
    }
    let path = &s.buf[REQ_HDR..path_end];

    // Longest prefix first. `/e2ee/state` and `/e2ee/keypackages` share no
    // prefix today, but ordering by length is what keeps that true when one
    // of them grows a sub-path.
    let out = if starts_with(path, PATH_KEYPKG) {
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
        respond_not_found(s, sys);
        return;
    };

    if out < 0 || !chan::can_write(sys, out) {
        // Backpressure on the endpoint. Dropping the request would leave the
        // connection open until the listener timed it out, which reads as a
        // hung server; a 503 says what happened.
        respond_unavailable(s, sys);
        return;
    }
    let _ = (sys.channel_write)(out, s.buf.as_ptr(), plen);
}

fn starts_with(path: &[u8], prefix: &[u8]) -> bool {
    path.len() >= prefix.len() && &path[..prefix.len()] == prefix
}

/// Answer a request this router owns no endpoint for.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn respond_not_found(s: &mut ModuleState, sys: &SyscallTable) {
    reply(s, sys, 404, b"{\"error\":\"not_found\"}");
}

/// Answer when the owning endpoint cannot take the request right now.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn respond_unavailable(s: &mut ModuleState, sys: &SyscallTable) {
    reply(s, sys, 503, b"{\"error\":\"temporarily_unavailable\"}");
}

/// Compose an `HttpResponse` addressed to the request's own connection.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn reply(s: &mut ModuleState, sys: &SyscallTable, status: u16, body: &[u8]) {
    if s.out_response < 0 || !chan::can_write(sys, s.out_response) {
        return;
    }
    // The `HttpResponse` layout every kagi endpoint writes:
    // `[conn u16][stream u16][status u16][_][ct_len u8][_ u16][body_len u16]`
    // then the content type and the body. `conn` and `stream` are copied
    // straight from the request's own header, which is what addresses the
    // answer to the client that asked.
    const CTYPE: &[u8] = b"application/json";
    const RESP_HDR: usize = 12;
    let total = RESP_HDR + CTYPE.len() + body.len();
    if total > s.out.len() {
        return;
    }
    s.out[0..4].copy_from_slice(&s.buf[0..4]); // conn + stream
    s.out[4..6].copy_from_slice(&status.to_le_bytes());
    s.out[6] = 0;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "CTYPE is a 16-byte literal, so the length fits a u8"
    )]
    {
        s.out[7] = CTYPE.len() as u8;
    }
    s.out[8..10].copy_from_slice(&0u16.to_le_bytes());
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by the `total > s.out.len()` check above"
    )]
    {
        s.out[10..12].copy_from_slice(&(body.len() as u16).to_le_bytes());
    }
    s.out[RESP_HDR..RESP_HDR + CTYPE.len()].copy_from_slice(CTYPE);
    s.out[RESP_HDR + CTYPE.len()..total].copy_from_slice(body);
    let _ = (sys.channel_write)(s.out_response, s.out.as_ptr(), total);
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

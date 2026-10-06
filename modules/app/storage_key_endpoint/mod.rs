//! The storage-key service's network edge: `POST /storage-key`, for the
//! operations a node sends. The routing is `modules/common/
//! storage_key_endpoint.rs`; this module moves records.
//!
//! It is a PROVIDER of the workspace exchange contract toward wave's `http`
//! (`request_in` / `response_out`) and the REQUESTER of the `storage_key`
//! module's exchange (`service_out` / `service_in`): each admitted request
//! becomes one exchange with the service, its body the `msg::REQUEST`
//! envelope, and the service's `msg::REPLY` payload is the HTTP answer.

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

#[path = "../../common/http_endpoint.rs"]
mod http_endpoint;

use abi::contracts::exchange::{self as x, ExchangeId};

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/storage_key_endpoint.rs"]
mod endpoint;
#[path = "../../../target/fluxor/fluxor-abi/sdk/contracts/key_vault.rs"]
mod key_vault;
#[path = "../../common/state_wire.rs"]
mod state_wire;
#[path = "../../common/storage_key.rs"]
mod storage_key;
#[path = "../../common/storage_key_service.rs"]
mod storage_key_service;
#[path = "../../common/typed_exchange.rs"]
mod typed_exchange;

use typed_exchange::Answer;

use storage_key_service::msg;

const PORT_INPUT: u8 = 0;
const PORT_OUTPUT: u8 = 1;
/// Requests admitted per step. The service holds four operations at once and
/// answers a fifth busy, so there is nothing to gain from draining the port
/// faster than it can decide.
const MAX_REQUESTS_PER_STEP: usize = 4;
const BUF: usize = x::RECORD_MAX;
const STEP_DID_WORK: i32 = 2;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    request_in: i32,
    response_out: i32,
    service_out: i32,
    service_in: i32,
    resolved: u32,
    timeout_ms: u32,
    table: endpoint::Table,
    /// Monotonic; numbers the exchanges this endpoint opens with the service.
    next_call: u64,
    /// The one call owed to `service_out`, and the record it lives in.
    call_outbox: ExchangeOutbox,
    call_buf: [u8; BUF],
    /// Requests being collected: an exchange's body may be streamed, so a
    /// request is answered once its body is whole.
    exch: http_endpoint::Requests,
    /// One response or body-credit record owed to `response_out`.
    ///
    /// Three places in this module answer — a service reply, a timeout, and a
    /// refusal of the request itself — and all three share the one slot: what
    /// is owed is placed before anything else is read. See
    /// [`ExchangeOutbox`] for why a dropped answer is the worst failure
    /// available here.
    outbox: ExchangeOutbox,
    buf: [u8; BUF],
    out: [u8; BUF],
}

mod params_def {
    use super::p_u32;
    use super::State;
    use super::SCHEMA_MAX;

    define_params! {
        State;

        1, timeout_ms, u32, 30000
            => |s, d, len| { s.timeout_ms = p_u32(d, len, 0, 30000); };
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state`/`syscalls` are the loader-owned
/// instance arena and syscall table.
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() || state_size < core::mem::size_of::<State>() {
        return -1;
    }
    let s = &mut *(state as *mut State);
    s.syscalls = syscalls as *const SyscallTable;
    s.request_in = in_chan;
    s.response_out = out_chan;
    s.service_out = -1;
    s.service_in = -1;
    s.table = endpoint::Table::new();
    s.exch = http_endpoint::Requests::new();
    s.outbox = ExchangeOutbox::new();
    s.call_outbox = ExchangeOutbox::new();
    s.next_call = 1;
    params_def::set_defaults(s);
    params_def::parse_tlv(s, params, params_len);
    0
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: as `module_new`.
    unsafe {
        let s = &mut *(state as *mut State);
        let sys = &*s.syscalls;
        if s.resolved == 0 {
            s.service_out = dev_channel_port(sys, PORT_OUTPUT, 1);
            s.service_in = dev_channel_port(sys, PORT_INPUT, 1);
            s.resolved = 1;
        }
        if s.request_in < 0 || s.response_out < 0 || s.service_out < 0 || s.service_in < 0 {
            return 0;
        }
        let mut worked = false;
        // A call still held goes before anything new is read.
        if !s.call_outbox.flush(sys, s.service_out, &s.call_buf) {
            return 0;
        }
        // Answers first: they free slots and answer waiting nodes.
        while s.outbox.flush(sys, s.response_out, &s.out) && chan::can_read(sys, s.service_in) {
            let n = (sys.channel_read)(s.service_in, s.buf.as_mut_ptr(), BUF);
            if n <= 0 {
                break;
            }
            worked = true;
            let record = s.buf;
            match typed_exchange::read_answer(&record[..n as usize]) {
                Answer::Message {
                    id: call,
                    msg_type,
                    payload,
                } => {
                    let Some((id, credit)) = s.table.answer(&call) else {
                        continue;
                    };
                    if msg_type == msg::REPLY {
                        respond(s, sys, &id, credit, 200, payload);
                    } else {
                        respond(s, sys, &id, credit, x::status::BAD_GATEWAY, &[]);
                    }
                }
                // The service refused the exchange itself, or it ended with
                // no answer: the node is told the service's status verbatim.
                Answer::Failed { id: call, status } => {
                    if let Some((id, credit)) = s.table.answer(&call) {
                        respond(s, sys, &id, credit, status, &[]);
                    }
                }
                // No LINK of its own to act on: a request the service drops
                // past a DOWN is answered by the timeout below.
                Answer::Link { .. } | Answer::Ignored => {}
            }
        }
        let now = dev_millis(sys);
        while s.outbox.flush(sys, s.response_out, &s.out) {
            let Some((id, credit)) = s.table.expire(now, u64::from(s.timeout_ms)) else {
                break;
            };
            respond(s, sys, &id, credit, 504, &[]);
            worked = true;
        }
        for _ in 0..MAX_REQUESTS_PER_STEP {
            if !s.outbox.flush(sys, s.response_out, &s.out)
                || !s.call_outbox.flush(sys, s.service_out, &s.call_buf)
            {
                break;
            }
            if !chan::can_read(sys, s.request_in) {
                break;
            }
            // One exchange record per read: the edge is a mailbox.
            let n = (sys.channel_read)(s.request_in, s.buf.as_mut_ptr(), BUF);
            if n < x::HDR as i32 {
                break;
            }
            worked = true;
            let outcome = {
                let State { exch, buf, .. } = &mut *s;
                exch.accept(buf.get(..n as usize).unwrap_or(&[]))
            };
            // Request-body credit the collector owes: the server forwards a
            // body only up to what this endpoint has granted.
            if let Some((gid, bytes)) = s.exch.take_grant() {
                if let Some(n) = http_endpoint::write_grant(&gid, bytes, &mut s.out) {
                    s.outbox.send(sys, s.response_out, &s.out, n);
                }
            }
            if let Some((rid, why)) = s.exch.take_refusal() {
                respond(s, sys, &rid, 0, why.status(), &[]);
            }
            if let Ok(Some(at)) = outcome {
                handle(s, sys, at, now);
            }
        }
        if worked {
            STEP_DID_WORK
        } else {
            0
        }
    }
}

/// One HTTP request: refused here, or carried to the service as an exchange
/// of this endpoint's own.
unsafe fn handle(s: &mut State, sys: &SyscallTable, at: usize, now: u64) {
    let Some(req) = s.exch.request(at) else {
        return;
    };
    let (id, credit, method) = (req.id, req.resp_credit, req.method);
    let mut path = [0u8; 32];
    let pl = req.target.len().min(path.len());
    path[..pl].copy_from_slice(&req.target[..pl]);
    let path = &path[..if req.target.len() > 32 { 0 } else { pl }];
    // The body is copied out of the collector so its slot is free before
    // the call is written.
    let body_len = req.body.len();
    let mut payload = [0u8; http_endpoint::MAX_BODY];
    if body_len > payload.len() || body_len > typed_exchange::CALL_MAX - auth_wire::ENVELOPE {
        s.exch.release(at);
        respond(s, sys, &id, credit, 400, &[]);
        return;
    }
    payload[..body_len].copy_from_slice(req.body);
    s.exch.release(at);
    let call = typed_exchange::call_id(s.next_call, s.service_out);
    match s
        .table
        .admit(method, path, &id, credit, &payload[..body_len], &call, now)
    {
        Ok(()) => {
            s.next_call = s.next_call.wrapping_add(1);
            let sealed = auth_wire::write_envelope(
                msg::REQUEST,
                &payload[..body_len],
                &mut s.call_buf[typed_exchange::CALL_AT..],
            )
            .ok()
            .and_then(|n| typed_exchange::seal_call(&call, n, &mut s.call_buf));
            match sealed {
                // Placed now or held for the next step: owed either way.
                Some(n) => {
                    s.call_outbox.send(sys, s.service_out, &s.call_buf, n);
                }
                None => {
                    // Release the slot the admit took: no answer will come.
                    let _ = s.table.answer(&call);
                    respond(s, sys, &id, credit, 503, &[]);
                }
            }
        }
        Err(refusal) => respond(s, sys, &id, credit, refusal.status(), &[]),
    }
}

unsafe fn respond(
    s: &mut State,
    sys: &SyscallTable,
    id: &ExchangeId,
    credit: u32,
    status: u16,
    body: &[u8],
) {
    const CT: &[u8] = b"application/octet-stream";
    let Some(total) = http_endpoint::write_response(id, status, CT, body, credit, &mut s.out)
    else {
        return;
    };
    s.outbox.send(sys, s.response_out, &s.out, total);
}

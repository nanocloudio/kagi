//! Security state — Kagi's durable identity ledger, as a module.
//!
//! Three operations: create only if absent, replace only if unchanged, and
//! read. Enrollment transactions, device membership, key-package claims and
//! endpoint high-water marks are all written in terms of those, because
//! lattice offers no atomic multi-key transaction and a transition that
//! cannot be one key's compare-and-swap cannot be made atomic on a
//! replicated backend at all.
//!
//! Two backends answer them, chosen by the graph's `backend` parameter and
//! never inferred. `object` runs the three against a local
//! `storage.object` provider; `lattice` runs them against a
//! `lattice_data_client` over the module's kv lane, which is the only
//! backend whose commits leave this node. The operations are the same
//! either way — that is the point of there being exactly three.
//!
//! ## Why this exists rather than `secret_store`
//!
//! `secret_store` cannot be this. It has no conditional write, so single-use
//! consumption cannot be expressed against it. It rewrites its whole file
//! image from a 32-entry table on every put, which is a demonstration
//! capacity rather than a device population. And its put replies `ST_OK`
//! whether the record was fsynced, deferred, short-written or lost to
//! memory-only mode, so a caller cannot tell durable from not. This module
//! answers only after the provider has committed.
//!
//! ## Fail closed, never memory-only
//!
//! At start-up this checks that the declared backend can actually answer:
//! `object` probes for a conditional-write provider, `lattice` requires its
//! kv lane to be wired. If the check fails, every subsequent request is
//! refused with `ST_UNAVAILABLE` for the life of the module — it never
//! falls back to RAM, and it never quietly answers from the other backend. `ST_UNAVAILABLE` and
//! `ST_NOT_FOUND` are deliberately different answers: "there is no ledger"
//! and "the ledger says no such device" must never look alike to a caller
//! deciding whether to issue a credential.
//!
//! ## The read ordering, which is load-bearing
//!
//! A read is `HEAD` (for the etag) and then `GET`/`RANGE_GET` (for the
//! value), in that order and not the other. If a writer lands between the
//! two, this order pairs a stale etag with a fresh value, so a following
//! compare-and-swap fails and the caller retries. The reverse order would
//! pair a fresh etag with a stale value, and the compare-and-swap would
//! succeed on a basis that was never true.

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
#[path = "../../common/lattice_kv.rs"]
mod lattice_kv;
#[path = "../../common/state_wire.rs"]
mod state_wire;
#[path = "../../common/time_policy.rs"]
mod time_policy;

use state_wire::StateRequest;

// ── `storage.object` opcodes ────────────────────────────────────────────
//
// From `target/fluxor/fluxor-abi/sdk/contracts/storage/object.rs`.
const OBJECT_PUT: u32 = 0x1420;
const OBJECT_GET: u32 = 0x1421;
const OBJECT_HEAD: u32 = 0x1422;
const OBJECT_RANGE_GET: u32 = 0x1423;
const OBJECT_DELETE: u32 = 0x1424;
const OBJECT_CLOSE: u32 = 0x1425;

/// `fence::WIRE_MAX_LEN` — the `ReplicatedDurable` variant is the widest.
/// Whether this deployment has declared itself a replicated authority.
///
/// A single-node authority genuinely may take `LocalDurable`: it has no other
/// replica to lose the write to, and forcing `ReplicatedDurable` on it would
/// refuse every write in a deployment that is correct. A replicated one must
/// not, because a `LocalDurable` ack for a revocation is lost with the node
/// that took it.
///
/// So the deployment declares which it is, and there is no default in either
/// direction. A default of single-node is silently permissive — the
/// replicated deployment that forgot gets the weaker floor and no
/// indication. A default of replicated refuses a correct single-node graph.
/// Undeclared is therefore its own answer: the module refuses every request,
/// the same posture it takes with no conditional provider, because in both
/// cases there is no durability claim it is entitled to make.
const AUTHORITY_UNDECLARED: u8 = 0;
const AUTHORITY_SINGLE_NODE: u8 = 1;
const AUTHORITY_REPLICATED: u8 = 2;

const FENCE_CAP: usize = 62;

/// The record body's MIME tag. Opaque to the provider; named so an operator
/// reading the store can tell what wrote a blob.
const CONTENT_TYPE: &[u8] = b"application/vnd.kagi.state";

/// The `storage.object` precondition values.
///
/// These used to be a synthesised 32-byte all-zero etag meaning "must not
/// exist" — a convention that lived in the Linux provider and in no
/// contract, so a second provider had no way to reproduce it and this module
/// had no way to know whether it still held. Worse, it was not expressible:
/// "must not exist" and "must be at revision 0" were the same value, so one
/// of those two requests was always answered wrongly. The contract now
/// states the condition, and this is the mapping.
const PRECONDITION_ABSENT: u8 = 1;
const PRECONDITION_ETAG: u8 = 2;

/// Requests answered per step, so one busy client cannot starve the graph.
const MAX_REQS_PER_STEP: usize = 8;

/// The key this module HEADs at start-up to decide whether a conditional
/// provider is present. Under the ledger's own prefix so it cannot collide
/// with an application key, and never written.
const PROBE_KEY: &[u8] = b"kagi/probe/conditional-writes";

const MAX_COMPOSED_KEY: usize = state_wire::MAX_PREFIX + state_wire::MAX_KEY;

define_params! {
    ModuleState;

    // Which authority this ledger is. Required: an undeclared ledger refuses
    // every request rather than guessing, because both guesses are wrong in a
    // way nobody would notice. Written as a word rather than a flag so the
    // graph says what it means and an unrecognised value is undeclared
    // instead of true.
    1, authority, str, 0 => |s, d, len| {
        s.authority = match_authority(d, len);
    };

    // Which backend holds the ledger. `object` is the provider-call path
    // (synchronous, this node's disk) — right for a single-node authority.
    // `lattice` speaks MSG_KV_REQUEST to a `lattice_data_client` over the
    // kv ports — asynchronous, correlated, answering with a durability
    // class checked against the namespace floor, and the only backend a
    // `replicated` authority can honestly run on.
    2, backend, u8, 0, enum { object=0, lattice=1 }
        => |s, d, len| { s.backend = p_u8(d, len, 0, BACKEND_OBJECT); };
}

const BACKEND_OBJECT: u8 = 0;
const BACKEND_LATTICE: u8 = 1;

/// Requests parked on a lattice answer. Small and refusing when full —
/// parked requests are admissions-in-waiting, and an unbounded queue is
/// the eviction-under-load shape.
const MAX_KV_PENDING: usize = 8;

/// One request parked on the lattice's answer.
#[derive(Clone, Copy)]
struct KvPending {
    live: bool,
    kv_corr: u64,
    corr: u32,
    client: u8,
    namespace: u8,
    is_read: bool,
}

impl KvPending {
    const fn zero() -> Self {
        Self {
            live: false,
            kv_corr: 0,
            corr: 0,
            client: 0,
            namespace: 0,
            is_read: false,
        }
    }
}
const MSG_BUF_LEN: usize = 4096;
const ARG_BUF_LEN: usize = 512;
const HEAD_BUF_LEN: usize = 256;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    out_replies: i32,

    /// Set once at start-up. When true every request is refused; there is no
    /// path that clears it, because a provider that was absent at init is not
    /// something this module may start trusting mid-run.
    unavailable: bool,
    probed: bool,
    /// Which authority this ledger is, as the graph declared it. Undeclared
    /// refuses everything — see the constants.
    authority: u8,
    /// Which backend (`BACKEND_*`), from the `backend` param.
    backend: u8,
    /// out[1]/in[1]: the lattice kv lane, used only in `lattice` mode.
    out_kv: i32,
    in_kv: i32,
    kv_pending: [KvPending; MAX_KV_PENDING],
    next_kv_corr: u64,
    kv_buf: [u8; MSG_BUF_LEN],

    msg_buf: [u8; MSG_BUF_LEN],
    out_buf: [u8; MSG_BUF_LEN],
    key_buf: [u8; MAX_COMPOSED_KEY],
    value_buf: [u8; state_wire::MAX_VALUE],
    etag_buf: [u8; state_wire::MAX_ETAG],
    arg_buf: [u8; ARG_BUF_LEN],
    head_buf: [u8; HEAD_BUF_LEN],
    fence_buf: [u8; FENCE_CAP],

    state_get: u32,
    state_put_absent: u32,
    state_cas: u32,
    state_delete: u32,
    state_conflict: u32,
    state_unavailable: u32,
    state_malformed: u32,
    /// Reads refused because the view they were served from is weaker than
    /// the namespace allows a decision to rest on.
    state_read_too_weak: u32,
}

/// The authority a declaration names, or undeclared.
///
/// Compared in full. A prefix or a length would make `replicated-soon` or a
/// truncated word mean something, and the one value that must never be
/// arrived at by accident is the permissive one.
///
/// # Safety
///
/// `d` points to at least `len` readable bytes, as the params ABI guarantees.
unsafe fn match_authority(d: *const u8, len: usize) -> u8 {
    const SINGLE_NODE: &[u8] = b"single-node";
    const REPLICATED: &[u8] = b"replicated";

    let mut matches_single = len == SINGLE_NODE.len();
    let mut matches_replicated = len == REPLICATED.len();
    let mut i = 0usize;
    while i < len {
        let byte = *d.add(i);
        if matches_single && byte != SINGLE_NODE[i] {
            matches_single = false;
        }
        if matches_replicated && byte != REPLICATED[i] {
            matches_replicated = false;
        }
        i += 1;
    }
    if matches_single {
        AUTHORITY_SINGLE_NODE
    } else if matches_replicated {
        AUTHORITY_REPLICATED
    } else {
        AUTHORITY_UNDECLARED
    }
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
    in_chan: i32,
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
        s.in_requests = in_chan;
        s.out_replies = out_chan;
        s.unavailable = false;
        s.probed = false;
        s.authority = AUTHORITY_UNDECLARED;
        s.backend = BACKEND_OBJECT;
        s.out_kv = dev_channel_port(sys, 1, 1);
        s.in_kv = dev_channel_port(sys, 0, 1);
        s.kv_pending = [KvPending::zero(); MAX_KV_PENDING];
        s.next_kv_corr = 1;
        parse_tlv(s, params, params_len);
        s.state_get = 0;
        s.state_put_absent = 0;
        s.state_cas = 0;
        s.state_delete = 0;
        s.state_conflict = 0;
        s.state_unavailable = 0;
        s.state_malformed = 0;
        s.state_read_too_weak = 0;
        dev_log(sys, 3, b"[state] init".as_ptr(), 12);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: as `module_new`; the kernel's guarantees hold for the life of
    // the module.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        if !s.probed {
            probe(s, sys);
        }

        drain_kv(s, sys);

        for _ in 0..MAX_REQS_PER_STEP {
            if !chan::can_read(sys, s.in_requests) {
                break;
            }
            // Every request produces exactly one reply; do not consume a
            // request that cannot be answered this step.
            if !chan::can_write(sys, s.out_replies) {
                break;
            }
            let (msg_type, plen) = chan::channel_read_msg(sys, s.in_requests, &mut s.msg_buf);
            if msg_type == 0 {
                continue;
            }
            handle_request(s, sys, msg_type, plen as usize);
        }
        0
    }
}

/// Decide, once, whether a conditional-write provider is present.
///
/// A `HEAD` on a key that was never written answers `ENXIO` from a working
/// provider and `ENOSYS` from one that does not implement the op at all. The
/// first is a healthy store; the second is not a store this module can use.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn probe(s: &mut ModuleState, sys: &SyscallTable) {
    s.probed = true;

    // An undeclared authority is refused here, beside the missing provider,
    // because it is the same kind of fact: this module cannot say what a
    // commit is worth, so it must not acknowledge one. Decided once, on the
    // first step, and never revisited — an authority that was undeclared at
    // start-up is not something this module may start assuming later.
    if s.authority == AUTHORITY_UNDECLARED {
        s.unavailable = true;
        dev_log(
            sys,
            1,
            b"[state] no authority declared (single-node|replicated); refusing all requests"
                .as_ptr(),
            77,
        );
        return;
    }

    if s.backend == BACKEND_LATTICE {
        // The lattice backend needs its lane, not the object provider. A
        // replicated authority on the OBJECT backend would be a ledger
        // whose commits never leave this node — refused as the same class
        // of undeclarable claim.
        if s.out_kv < 0 || s.in_kv < 0 {
            s.unavailable = true;
            dev_log(
                sys,
                1,
                b"[state] lattice backend declared but kv lane unwired; refusing all requests"
                    .as_ptr(),
                76,
            );
        }
        return;
    }
    if s.authority == AUTHORITY_REPLICATED {
        s.unavailable = true;
        dev_log(
            sys,
            1,
            b"[state] replicated authority requires the lattice backend; refusing all requests"
                .as_ptr(),
            79,
        );
        return;
    }
    let rc = head_object(s, sys, PROBE_KEY);
    // `ENXIO` — absent — is the expected healthy answer. Anything that is not
    // a real answer about a key means there is no conditional store here.
    if rc == abi::kernel_abi::errno::ENOSYS
        || rc == abi::kernel_abi::errno::EINVAL
        || rc == abi::kernel_abi::errno::ENODEV
    {
        s.unavailable = true;
        dev_log(
            sys,
            1,
            b"[state] no conditional storage.object provider; refusing all requests".as_ptr(),
            72,
        );
    }
}

/// Answer one request.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn handle_request(s: &mut ModuleState, sys: &SyscallTable, msg_type: u8, plen: usize) {
    let is_read = msg_type == state_wire::MSG_STATE_GET;

    let Ok(req) = StateRequest::decode(msg_type, &s.msg_buf[..plen]) else {
        s.state_malformed = s.state_malformed.saturating_add(1);
        // A payload this module cannot parse carries no correlation id it can
        // trust, so there is nothing to address a reply to.
        return;
    };
    let (corr, client) = (req.correlation, req.client);

    if s.unavailable {
        s.state_unavailable = s.state_unavailable.saturating_add(1);
        reply(
            s,
            sys,
            corr,
            client,
            auth_wire::ST_UNAVAILABLE,
            &[],
            is_read,
        );
        return;
    }

    // The namespace prefix is applied here, by the store, never by the
    // caller: a module that could name a raw key could write another
    // module's records.
    let ns = req.namespace;
    let Some(key_len) = state_wire::compose_key(ns, req.key, &mut s.key_buf) else {
        s.state_malformed = s.state_malformed.saturating_add(1);
        reply(s, sys, corr, client, auth_wire::ST_MALFORMED, &[], is_read);
        return;
    };

    if s.backend == BACKEND_LATTICE {
        let expiry = req.expiry_unix;
        let etag_len = copy_field(&mut s.etag_buf, req.etag);
        let value_len = copy_field(&mut s.value_buf, req.value);
        kv_request(
            s, sys, msg_type, ns, key_len, value_len, etag_len, expiry, corr, client, is_read,
        );
        return;
    }

    match msg_type {
        state_wire::MSG_STATE_GET => {
            s.state_get = s.state_get.saturating_add(1);
            do_get(s, sys, ns, key_len, corr, client);
        }
        state_wire::MSG_STATE_PUT_ABS => {
            s.state_put_absent = s.state_put_absent.saturating_add(1);
            let value_len = copy_field(&mut s.value_buf, req.value);
            do_write(s, sys, ns, key_len, value_len, true, 0, corr, client);
        }
        state_wire::MSG_STATE_CAS => {
            s.state_cas = s.state_cas.saturating_add(1);
            let etag_len = copy_field(&mut s.etag_buf, req.etag);
            let value_len = copy_field(&mut s.value_buf, req.value);
            do_write(
                s, sys, ns, key_len, value_len, false, etag_len, corr, client,
            );
        }
        state_wire::MSG_STATE_DELETE => {
            s.state_delete = s.state_delete.saturating_add(1);
            let etag_len = copy_field(&mut s.etag_buf, req.etag);
            do_delete(s, sys, key_len, etag_len, corr, client);
        }
        _ => {
            s.state_malformed = s.state_malformed.saturating_add(1);
            reply(s, sys, corr, client, auth_wire::ST_MALFORMED, &[], is_read);
        }
    }
}

/// Copy a request field out of `msg_buf` into its own buffer.
///
/// Takes the destination rather than the whole state so the borrow stays
/// disjoint from the decoded request, which still borrows `msg_buf`.
/// Truncation is impossible: the wire caps both fields.
fn copy_field(dst: &mut [u8], src: &[u8]) -> usize {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
}

/// Read a record: `HEAD` for the etag, then `GET`/`RANGE_GET` for the value.
/// See the module note for why that order and not the reverse.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn do_get(
    s: &mut ModuleState,
    sys: &SyscallTable,
    ns: u8,
    key_len: usize,
    corr: u32,
    client: u8,
) {
    let mut key = [0u8; MAX_COMPOSED_KEY];
    key[..key_len].copy_from_slice(&s.key_buf[..key_len]);

    let rc = head_object(s, sys, &key[..key_len]);
    if rc < 0 {
        // Absent is a miss; anything else is the store failing to answer,
        // which must not be reported as "no such record".
        let status = if rc == abi::kernel_abi::errno::ENXIO {
            auth_wire::ST_NOT_FOUND
        } else {
            s.state_unavailable = s.state_unavailable.saturating_add(1);
            auth_wire::ST_UNAVAILABLE
        };
        reply(s, sys, corr, client, status, &[], true);
        return;
    }

    // WHICH VIEW answered. `HEAD` writes back the fence its answer was
    // served under, and the namespace says how strong a view a decision on
    // this class of state may rest on. A single-use record read from a view
    // with no linearization point is how a consumed transaction reads as
    // unconsumed and is spent twice — so a read below the floor is refused
    // rather than answered.
    //
    // Read floor, not the write floor: a provider legitimately answers a
    // read `ViewConsistent` and a write `LocalDurable`, and they answer
    // different questions. `ST_UNAVAILABLE`, because from the caller's side
    // this is the same fact as no store — there is no view it may decide on.
    let served_under = s.fence_buf[0];
    if !state_wire::read_fence_satisfies(ns, served_under) {
        s.state_read_too_weak = s.state_read_too_weak.saturating_add(1);
        reply(s, sys, corr, client, auth_wire::ST_UNAVAILABLE, &[], true);
        return;
    }

    let Some((size, etag_len)) = parse_head(&s.head_buf[..rc as usize], &mut s.etag_buf) else {
        reply(s, sys, corr, client, auth_wire::ST_UNAVAILABLE, &[], true);
        return;
    };

    let value_len = read_body(s, sys, &key[..key_len], size);
    let Some(value_len) = value_len else {
        reply(s, sys, corr, client, auth_wire::ST_UNAVAILABLE, &[], true);
        return;
    };

    let mut etag = [0u8; state_wire::MAX_ETAG];
    etag[..etag_len].copy_from_slice(&s.etag_buf[..etag_len]);
    let mut value = [0u8; state_wire::MAX_VALUE];
    value[..value_len].copy_from_slice(&s.value_buf[..value_len]);

    let n = match state_wire::encode_value(
        &mut s.out_buf,
        corr,
        client,
        auth_wire::ST_OK,
        &etag[..etag_len],
        &value[..value_len],
    ) {
        Ok(n) => n,
        Err(_) => {
            reply(s, sys, corr, client, auth_wire::ST_FULL, &[], true);
            return;
        }
    };
    write_out(s, sys, n);
}

/// Write a record under a precondition.
///
/// `absent` selects the create-only precondition; otherwise the caller's etag
/// is the guard. A provider `EAGAIN` is a lost race, which is `ST_CONFLICT`
/// and never a generic error — the caller must be able to tell "someone else
/// won" from "the store is broken".
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
#[allow(
    clippy::too_many_arguments,
    reason = "one write path; splitting the guard from the record it guards would let a caller build a write with no precondition"
)]
unsafe fn do_write(
    s: &mut ModuleState,
    sys: &SyscallTable,
    namespace: u8,
    key_len: usize,
    value_len: usize,
    absent: bool,
    etag_len: usize,
    corr: u32,
    client: u8,
) {
    let mut guard = [0u8; state_wire::MAX_ETAG];
    let (precondition, guard_len) = if absent {
        (PRECONDITION_ABSENT, 0)
    } else {
        guard[..etag_len].copy_from_slice(&s.etag_buf[..etag_len]);
        (PRECONDITION_ETAG, etag_len)
    };
    if precondition == PRECONDITION_ETAG && guard_len == 0 {
        // A compare-and-swap with no etag is not a weaker condition, it is a
        // malformed request. An unconditional write is not an operation this
        // module offers at all: a caller that wants one wants a different
        // module.
        s.state_malformed = s.state_malformed.saturating_add(1);
        reply(s, sys, corr, client, auth_wire::ST_MALFORMED, &[], false);
        return;
    }

    let body_ptr = s.value_buf.as_ptr();
    // Cleared for the same reason `head_object` clears it: a provider that
    // writes no fence must not leave a previous call's stronger one standing
    // in for this commit. Zero is `Volatile`, which no namespace accepts.
    s.fence_buf = [0u8; FENCE_CAP];
    let fence_ptr = s.fence_buf.as_mut_ptr();
    let key_ptr = s.key_buf.as_ptr();
    let Some(arg_len) = encode_put_arg(
        &mut s.arg_buf,
        key_ptr,
        key_len,
        body_ptr,
        value_len,
        precondition,
        &guard[..guard_len],
        fence_ptr,
    ) else {
        reply(s, sys, corr, client, auth_wire::ST_FULL, &[], false);
        return;
    };

    let rc = (sys.provider_call)(-1, OBJECT_PUT, s.arg_buf.as_mut_ptr(), arg_len);
    // `EEXIST` — the key was already there, so a create-only caller LOST.
    // `EAGAIN` — the key moved under a compare-and-swap. Both mean "you did
    // not win"; only the second is worth retrying after a re-read.
    if rc == abi::kernel_abi::errno::EEXIST || rc == abi::kernel_abi::errno::EAGAIN {
        s.state_conflict = s.state_conflict.saturating_add(1);
        reply(s, sys, corr, client, auth_wire::ST_CONFLICT, &[], false);
        return;
    }
    if rc < 0 {
        s.state_unavailable = s.state_unavailable.saturating_add(1);
        reply(s, sys, corr, client, auth_wire::ST_UNAVAILABLE, &[], false);
        return;
    }

    // The provider committed — but committed to WHAT? The fence it wrote
    // back says which guarantee the commit actually achieved, and the
    // namespace says which one this class of state needs. A write that
    // reached a weaker one is refused rather than acknowledged: reporting
    // it as committed is how a credential comes to be issued against state
    // that was never really committed, and the two are indistinguishable to
    // everything downstream.
    //
    // Not a downgrade, not a warning. `ST_UNAVAILABLE` is the same answer a
    // missing store gets, because from a caller's point of view they are
    // the same fact — there is no durable place to record this.
    let achieved = s.fence_buf[0];
    if !state_wire::fence_satisfies(namespace, achieved, s.authority == AUTHORITY_REPLICATED) {
        s.state_unavailable = s.state_unavailable.saturating_add(1);
        reply(s, sys, corr, client, auth_wire::ST_UNAVAILABLE, &[], false);
        return;
    }

    // Re-read the etag the write produced so the
    // caller can chain a compare-and-swap without a further round trip.
    let mut key = [0u8; MAX_COMPOSED_KEY];
    key[..key_len].copy_from_slice(&s.key_buf[..key_len]);
    let head_rc = head_object(s, sys, &key[..key_len]);
    let mut etag_out = [0u8; state_wire::MAX_ETAG];
    let mut etag_out_len = 0usize;
    if head_rc > 0 {
        if let Some((_, n)) = parse_head(&s.head_buf[..head_rc as usize], &mut s.etag_buf) {
            etag_out[..n].copy_from_slice(&s.etag_buf[..n]);
            etag_out_len = n;
        }
    }
    reply(
        s,
        sys,
        corr,
        client,
        auth_wire::ST_OK,
        &etag_out[..etag_out_len],
        false,
    );
}

/// Remove a record under an etag guard.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn do_delete(
    s: &mut ModuleState,
    sys: &SyscallTable,
    key_len: usize,
    etag_len: usize,
    corr: u32,
    client: u8,
) {
    if etag_len == 0 {
        s.state_malformed = s.state_malformed.saturating_add(1);
        reply(s, sys, corr, client, auth_wire::ST_MALFORMED, &[], false);
        return;
    }
    let mut guard = [0u8; state_wire::MAX_ETAG];
    guard[..etag_len].copy_from_slice(&s.etag_buf[..etag_len]);

    s.fence_buf = [0u8; FENCE_CAP];
    let fence_ptr = s.fence_buf.as_mut_ptr();
    let key_ptr = s.key_buf.as_ptr();
    let Some(arg_len) = encode_delete_arg(
        &mut s.arg_buf,
        key_ptr,
        key_len,
        &guard[..etag_len],
        fence_ptr,
    ) else {
        reply(s, sys, corr, client, auth_wire::ST_FULL, &[], false);
        return;
    };
    let rc = (sys.provider_call)(-1, OBJECT_DELETE, s.arg_buf.as_mut_ptr(), arg_len);
    let status = if rc == abi::kernel_abi::errno::EAGAIN {
        s.state_conflict = s.state_conflict.saturating_add(1);
        auth_wire::ST_CONFLICT
    } else if rc == abi::kernel_abi::errno::ENXIO {
        auth_wire::ST_NOT_FOUND
    } else if rc < 0 {
        s.state_unavailable = s.state_unavailable.saturating_add(1);
        auth_wire::ST_UNAVAILABLE
    } else {
        auth_wire::ST_OK
    };
    reply(s, sys, corr, client, status, &[], false);
}

/// `HEAD` a key into `s.head_buf`. Returns the provider's result: bytes
/// written, or a negative errno.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn head_object(s: &mut ModuleState, sys: &SyscallTable, key: &[u8]) -> i32 {
    // Cleared first: a provider that writes no fence leaves whatever the last
    // call left, and a stale strong fence would pass a floor this answer never
    // met. Zero is `Volatile`, the weakest, so silence fails closed.
    s.fence_buf = [0u8; FENCE_CAP];
    let out_ptr = s.head_buf.as_mut_ptr();
    let fence_ptr = s.fence_buf.as_mut_ptr();
    let Some(arg_len) = encode_head_arg(&mut s.arg_buf, key, out_ptr, fence_ptr) else {
        return abi::kernel_abi::errno::EINVAL;
    };
    (sys.provider_call)(-1, OBJECT_HEAD, s.arg_buf.as_mut_ptr(), arg_len)
}

/// Read a body of `size` bytes into `s.value_buf` via `GET`/`RANGE_GET`.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn read_body(
    s: &mut ModuleState,
    sys: &SyscallTable,
    key: &[u8],
    size: u64,
) -> Option<usize> {
    let want = usize::try_from(size).ok()?;
    if want > s.value_buf.len() {
        return None;
    }
    let mut key_arg = [0u8; MAX_COMPOSED_KEY];
    key_arg[..key.len()].copy_from_slice(key);
    let handle = (sys.provider_call)(-1, OBJECT_GET, key_arg.as_mut_ptr(), key.len());
    if handle < 0 {
        return None;
    }

    let out_ptr = s.value_buf.as_mut_ptr();
    let mut arg = [0u8; 24];
    arg[0..8].copy_from_slice(&0u64.to_le_bytes());
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bounded by value_buf.len() above"
    )]
    arg[8..12].copy_from_slice(&(want as u32).to_le_bytes());
    arg[12..20].copy_from_slice(&(out_ptr as u64).to_le_bytes());
    let n = (sys.provider_call)(handle, OBJECT_RANGE_GET, arg.as_mut_ptr(), 20);
    let mut nothing = [0u8; 1];
    let _ = (sys.provider_call)(handle, OBJECT_CLOSE, nothing.as_mut_ptr(), 0);
    if n < 0 {
        return None;
    }
    usize::try_from(n).ok()
}

/// Pull `size` and the etag out of a HEAD record.
///
/// Layout, from the contract:
/// `[size u64][mtime u64][content_type_len u8][ct][etag_len u8][etag]`.
fn parse_head(record: &[u8], etag_out: &mut [u8]) -> Option<(u64, usize)> {
    if record.len() < 17 {
        return None;
    }
    let size = u64::from_le_bytes([
        record[0], record[1], record[2], record[3], record[4], record[5], record[6], record[7],
    ]);
    let ct_len = usize::from(record[16]);
    let etag_len_at = 17usize.checked_add(ct_len)?;
    if etag_len_at >= record.len() {
        return None;
    }
    let etag_len = usize::from(record[etag_len_at]);
    let etag_at = etag_len_at.checked_add(1)?;
    let etag_end = etag_at.checked_add(etag_len)?;
    if etag_end > record.len() || etag_len > etag_out.len() {
        return None;
    }
    etag_out[..etag_len].copy_from_slice(&record[etag_at..etag_end]);
    Some((size, etag_len))
}

/// Build the `storage.object::PUT` arg block.
#[allow(
    clippy::too_many_arguments,
    reason = "one PUT arg block, spelled out; separating the guard from the record it guards is how a write loses its precondition"
)]
fn encode_put_arg(
    arg: &mut [u8],
    key_ptr: *const u8,
    key_len: usize,
    body_ptr: *const u8,
    body_len: usize,
    precondition: u8,
    etag: &[u8],
    fence_ptr: *mut u8,
) -> Option<usize> {
    let total = 2 + key_len + 1 + CONTENT_TYPE.len() + 8 + 8 + 2 + etag.len() + 8 + 2;
    if total > arg.len() || key_len > usize::from(u16::MAX) || etag.len() > 255 {
        return None;
    }
    let mut p = 0usize;
    #[allow(clippy::cast_possible_truncation, reason = "checked against u16::MAX")]
    arg[p..p + 2].copy_from_slice(&(key_len as u16).to_le_bytes());
    p += 2;
    // SAFETY: `key_ptr` addresses `key_len` initialised bytes in module state
    // and does not overlap `arg`.
    unsafe { core::ptr::copy_nonoverlapping(key_ptr, arg.as_mut_ptr().add(p), key_len) };
    p += key_len;
    #[allow(clippy::cast_possible_truncation, reason = "a fixed short constant")]
    {
        arg[p] = CONTENT_TYPE.len() as u8;
    }
    p += 1;
    arg[p..p + CONTENT_TYPE.len()].copy_from_slice(CONTENT_TYPE);
    p += CONTENT_TYPE.len();
    arg[p..p + 8].copy_from_slice(&(body_ptr as u64).to_le_bytes());
    p += 8;
    arg[p..p + 8].copy_from_slice(&(body_len as u64).to_le_bytes());
    p += 8;
    arg[p] = precondition;
    #[allow(clippy::cast_possible_truncation, reason = "checked against 255")]
    {
        arg[p + 1] = etag.len() as u8;
    }
    p += 2;
    arg[p..p + etag.len()].copy_from_slice(etag);
    p += etag.len();
    arg[p..p + 8].copy_from_slice(&(fence_ptr as u64).to_le_bytes());
    p += 8;
    #[allow(clippy::cast_possible_truncation, reason = "a fixed small constant")]
    arg[p..p + 2].copy_from_slice(&(FENCE_CAP as u16).to_le_bytes());
    p += 2;
    Some(p)
}

/// Build the `storage.object::DELETE` arg block.
fn encode_delete_arg(
    arg: &mut [u8],
    key_ptr: *const u8,
    key_len: usize,
    etag: &[u8],
    fence_ptr: *mut u8,
) -> Option<usize> {
    let total = 2 + key_len + 2 + etag.len() + 8 + 2;
    if total > arg.len() || key_len > usize::from(u16::MAX) || etag.len() > 255 {
        return None;
    }
    let mut p = 0usize;
    #[allow(clippy::cast_possible_truncation, reason = "checked against u16::MAX")]
    arg[p..p + 2].copy_from_slice(&(key_len as u16).to_le_bytes());
    p += 2;
    // SAFETY: as `encode_put_arg`.
    unsafe { core::ptr::copy_nonoverlapping(key_ptr, arg.as_mut_ptr().add(p), key_len) };
    p += key_len;
    // A delete this module issues is always guarded: removing a security
    // record unconditionally is not something a caller here may ask for.
    arg[p] = PRECONDITION_ETAG;
    #[allow(clippy::cast_possible_truncation, reason = "checked against 255")]
    {
        arg[p + 1] = etag.len() as u8;
    }
    p += 2;
    arg[p..p + etag.len()].copy_from_slice(etag);
    p += etag.len();
    arg[p..p + 8].copy_from_slice(&(fence_ptr as u64).to_le_bytes());
    p += 8;
    #[allow(clippy::cast_possible_truncation, reason = "a fixed small constant")]
    arg[p..p + 2].copy_from_slice(&(FENCE_CAP as u16).to_le_bytes());
    p += 2;
    Some(p)
}

/// Build the `storage.object::HEAD` arg block.
fn encode_head_arg(
    arg: &mut [u8],
    key: &[u8],
    out_ptr: *mut u8,
    fence_ptr: *mut u8,
) -> Option<usize> {
    let total = 2 + key.len() + 8 + 4 + 8 + 2;
    if total > arg.len() || key.len() > usize::from(u16::MAX) {
        return None;
    }
    let mut p = 0usize;
    #[allow(clippy::cast_possible_truncation, reason = "checked against u16::MAX")]
    arg[p..p + 2].copy_from_slice(&(key.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + key.len()].copy_from_slice(key);
    p += key.len();
    arg[p..p + 8].copy_from_slice(&(out_ptr as u64).to_le_bytes());
    p += 8;
    #[allow(clippy::cast_possible_truncation, reason = "a fixed small constant")]
    arg[p..p + 4].copy_from_slice(&(HEAD_BUF_LEN as u32).to_le_bytes());
    p += 4;
    arg[p..p + 8].copy_from_slice(&(fence_ptr as u64).to_le_bytes());
    p += 8;
    #[allow(clippy::cast_possible_truncation, reason = "a fixed small constant")]
    arg[p..p + 2].copy_from_slice(&(FENCE_CAP as u16).to_le_bytes());
    p += 2;
    Some(p)
}

/// Emit a status-only reply, as a `VALUE` for a read and an `ACK` otherwise.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
/// Hex-encode a lattice `mod_revision` as the etag callers CAS against.
fn revision_etag(revision: u64, out: &mut [u8; 16]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, byte) in revision.to_be_bytes().iter().enumerate() {
        out[i * 2] = HEX[usize::from(byte >> 4)];
        out[i * 2 + 1] = HEX[usize::from(byte & 0x0F)];
    }
}

/// Parse a caller's etag back into the revision witness it encodes.
fn etag_revision(etag: &[u8]) -> Option<u64> {
    if etag.len() != 16 {
        return None;
    }
    let mut rev = 0u64;
    for &b in etag {
        let nibble = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => return None,
        };
        rev = (rev << 4) | u64::from(nibble);
    }
    Some(rev)
}

/// Encode one lattice request, park the caller, send it.
///
/// Fail closed at every seam: no pending slot, an encode that will not
/// fit, or a lane that will not take the frame all answer
/// `ST_UNAVAILABLE` now rather than admitting later on nothing.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
#[expect(
    clippy::too_many_arguments,
    reason = "one call site, mirrors the object path's split"
)]
unsafe fn kv_request(
    s: &mut ModuleState,
    sys: &SyscallTable,
    msg_type: u8,
    ns: u8,
    key_len: usize,
    value_len: usize,
    etag_len: usize,
    expiry_unix: u64,
    corr: u32,
    client: u8,
    is_read: bool,
) {
    let Some(slot) = s.kv_pending.iter().position(|p| !p.live) else {
        s.state_unavailable = s.state_unavailable.saturating_add(1);
        reply(
            s,
            sys,
            corr,
            client,
            auth_wire::ST_UNAVAILABLE,
            &[],
            is_read,
        );
        return;
    };

    // The op body, in kv_buf's tail; the enveloped request lands in its
    // head afterwards. Values travel as a Record so expiry lives INSIDE
    // the authenticated bytes — lattice has no standalone TTL on this op
    // set, and the decode-on-read treats an expired record as absent.
    let mut body = [0u8; MSG_BUF_LEN / 2];
    let key = &s.key_buf[..key_len];
    let encoded_body = match msg_type {
        state_wire::MSG_STATE_GET => {
            s.state_get = s.state_get.saturating_add(1);
            lattice_kv::encode_get(key, &mut body)
        }
        state_wire::MSG_STATE_PUT_ABS | state_wire::MSG_STATE_CAS => {
            let witness = if msg_type == state_wire::MSG_STATE_PUT_ABS {
                s.state_put_absent = s.state_put_absent.saturating_add(1);
                Some(0)
            } else {
                s.state_cas = s.state_cas.saturating_add(1);
                etag_revision(&s.etag_buf[..etag_len])
            };
            let Some(witness) = witness else {
                s.state_malformed = s.state_malformed.saturating_add(1);
                reply(s, sys, corr, client, auth_wire::ST_MALFORMED, &[], is_read);
                return;
            };
            let record = lattice_kv::Record {
                expires_at_unix: expiry_unix,
                value: &s.value_buf[..value_len],
            };
            let mut record_buf = [0u8; MSG_BUF_LEN / 2];
            let Some(record_len) = record.encode(&mut record_buf) else {
                s.state_malformed = s.state_malformed.saturating_add(1);
                reply(s, sys, corr, client, auth_wire::ST_MALFORMED, &[], is_read);
                return;
            };
            lattice_kv::encode_cas(key, witness, &record_buf[..record_len], &mut body)
        }
        state_wire::MSG_STATE_DELETE => {
            s.state_delete = s.state_delete.saturating_add(1);
            lattice_kv::encode_delete(key, &mut body)
        }
        _ => {
            s.state_malformed = s.state_malformed.saturating_add(1);
            reply(s, sys, corr, client, auth_wire::ST_MALFORMED, &[], is_read);
            return;
        }
    };
    let Some(body_len) = encoded_body else {
        s.state_malformed = s.state_malformed.saturating_add(1);
        reply(s, sys, corr, client, auth_wire::ST_MALFORMED, &[], is_read);
        return;
    };

    let op = match msg_type {
        state_wire::MSG_STATE_GET => lattice_kv::op::GET,
        state_wire::MSG_STATE_DELETE => lattice_kv::op::DELETE,
        _ => lattice_kv::op::CAS,
    };
    let kv_corr = s.next_kv_corr;
    s.next_kv_corr = s.next_kv_corr.wrapping_add(1).max(1);
    let Some(frame_len) =
        lattice_kv::encode_request(kv_corr, 0, op, &body[..body_len], &mut s.kv_buf)
    else {
        s.state_unavailable = s.state_unavailable.saturating_add(1);
        reply(
            s,
            sys,
            corr,
            client,
            auth_wire::ST_UNAVAILABLE,
            &[],
            is_read,
        );
        return;
    };
    if chan::channel_write_msg(
        sys,
        s.out_kv,
        lattice_kv::MSG_KV_REQUEST,
        &s.kv_buf[..frame_len],
    ) <= 0
    {
        s.state_unavailable = s.state_unavailable.saturating_add(1);
        reply(
            s,
            sys,
            corr,
            client,
            auth_wire::ST_UNAVAILABLE,
            &[],
            is_read,
        );
        return;
    }
    s.kv_pending[slot] = KvPending {
        live: true,
        kv_corr,
        corr,
        client,
        namespace: ns,
        is_read,
    };
}

/// Answer parked requests from the lattice's replies.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn drain_kv(s: &mut ModuleState, sys: &SyscallTable) {
    if s.backend != BACKEND_LATTICE || s.in_kv < 0 {
        return;
    }
    while chan::can_read(sys, s.in_kv) {
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_kv, &mut s.kv_buf);
        if msg_type == 0 {
            break;
        }
        if msg_type != lattice_kv::MSG_KV_RESPONSE {
            continue;
        }
        // kv_buf is both the response and the reply scratch below, so the
        // decode borrows a copy of the fields it needs before reply() reuses
        // the buffer.
        let Some(resp) = lattice_kv::decode_response(&s.kv_buf[..plen as usize], 0) else {
            continue;
        };
        let Some(slot) = s
            .kv_pending
            .iter()
            .position(|p| p.live && p.kv_corr == resp.corr_id)
        else {
            continue;
        };
        let entry = s.kv_pending[slot];
        s.kv_pending[slot] = KvPending::zero();

        let status = lattice_kv::to_status(resp.result);
        if entry.is_read {
            if status != auth_wire::ST_OK {
                if status == auth_wire::ST_CONFLICT {
                    s.state_conflict = s.state_conflict.saturating_add(1);
                }
                reply(s, sys, entry.corr, entry.client, status, &[], true);
                continue;
            }
            // Expiry lives inside the record; an expired record IS absent.
            // The clock this needs is the replay-expiry decision's: absent
            // a trustworthy clock, a record that carries an expiry cannot
            // be served — refusing beats serving a spent grant forever.
            let obs = dev_trusted_unix(sys);
            let now = time_policy::now_for(time_policy::Decision::ReplayRecordExpiry, &obs);
            let mut value_copy = [0u8; state_wire::MAX_VALUE];
            let mut value_len = 0usize;
            let mut expired_or_bad = false;
            let mut needs_clock = false;
            if resp.body.is_empty() {
                expired_or_bad = true;
            } else if let Some(now) = now {
                match lattice_kv::Record::decode(resp.body, now) {
                    Some(rec) if rec.value.len() <= value_copy.len() => {
                        value_len = rec.value.len();
                        value_copy[..value_len].copy_from_slice(rec.value);
                    }
                    _ => expired_or_bad = true,
                }
            } else if resp.body.len() >= lattice_kv::Record::HEAD && resp.body[..8] == [0u8; 8] {
                // No expiry on the record: no clock needed.
                let v = &resp.body[lattice_kv::Record::HEAD..];
                if v.len() <= value_copy.len() {
                    value_len = v.len();
                    value_copy[..value_len].copy_from_slice(v);
                } else {
                    expired_or_bad = true;
                }
            } else {
                needs_clock = true;
            }
            if needs_clock {
                s.state_unavailable = s.state_unavailable.saturating_add(1);
                reply(
                    s,
                    sys,
                    entry.corr,
                    entry.client,
                    auth_wire::ST_UNAVAILABLE,
                    &[],
                    true,
                );
                continue;
            }
            if expired_or_bad {
                reply(
                    s,
                    sys,
                    entry.corr,
                    entry.client,
                    auth_wire::ST_NOT_FOUND,
                    &[],
                    true,
                );
                continue;
            }
            // A LINEARIZABLE read is served at the linearization point by
            // construction — the read-floor question the object path asks
            // of its fence does not arise on this lane.
            let mut etag = [0u8; 16];
            revision_etag(resp.revision, &mut etag);
            let encoded = state_wire::encode_value(
                &mut s.out_buf,
                entry.corr,
                entry.client,
                auth_wire::ST_OK,
                &etag,
                &value_copy[..value_len],
            );
            if let Ok(len) = encoded {
                write_out(s, sys, len);
            }
            continue;
        }

        // A write: the durability the lane achieved is checked against the
        // namespace's floor, exactly as the object path checks its fence.
        if status == auth_wire::ST_OK
            && !state_wire::fence_satisfies(
                entry.namespace,
                resp.fence,
                s.authority == AUTHORITY_REPLICATED,
            )
        {
            s.state_unavailable = s.state_unavailable.saturating_add(1);
            reply(
                s,
                sys,
                entry.corr,
                entry.client,
                auth_wire::ST_UNAVAILABLE,
                &[],
                false,
            );
            continue;
        }
        if status == auth_wire::ST_CONFLICT {
            s.state_conflict = s.state_conflict.saturating_add(1);
        }
        let mut etag = [0u8; 16];
        revision_etag(resp.revision, &mut etag);
        let etag_slice: &[u8] = if status == auth_wire::ST_OK {
            &etag
        } else {
            &[]
        };
        reply(s, sys, entry.corr, entry.client, status, etag_slice, false);
    }
}

unsafe fn reply(
    s: &mut ModuleState,
    sys: &SyscallTable,
    corr: u32,
    client: u8,
    status: u8,
    etag: &[u8],
    is_read: bool,
) {
    let mut scratch = [0u8; state_wire::MAX_ETAG];
    let n = etag.len().min(scratch.len());
    scratch[..n].copy_from_slice(&etag[..n]);
    let encoded = if is_read {
        state_wire::encode_value(&mut s.out_buf, corr, client, status, &scratch[..n], &[])
    } else {
        state_wire::encode_ack(&mut s.out_buf, corr, client, status, &scratch[..n])
    };
    if let Ok(len) = encoded {
        write_out(s, sys, len);
    }
}

/// Push an already-enveloped reply out of `out_buf`.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn write_out(s: &mut ModuleState, sys: &SyscallTable, len: usize) {
    let Ok((msg_type, payload)) = auth_wire::read_envelope(&s.out_buf[..len]) else {
        return;
    };
    let mut copy = [0u8; MSG_BUF_LEN];
    let n = payload.len().min(copy.len());
    copy[..n].copy_from_slice(&payload[..n]);
    chan::channel_write_msg(sys, s.out_replies, msg_type, &copy[..n]);
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

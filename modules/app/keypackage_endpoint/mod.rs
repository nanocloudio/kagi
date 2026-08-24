//! Key packages: what a device publishes so others can add it to a group
//! without it being online.
//!
//! A group protocol adds a member by consuming a key package that member
//! published in advance. The package carries an initial key-agreement key,
//! and the security of the resulting group depends on that key being used
//! **once**. A package handed out twice puts two different groups on the same
//! initial secret, which is precisely the forward-secrecy property the
//! protocol was chosen for.
//!
//! So claiming is a one-time operation, and it is the only interesting thing
//! here. Publication, expiry and rotation exist to keep the pool of claimable
//! packages honest.
//!
//! **A module gets the hard part for free.** The host store this replaces had
//! to make claiming one indivisible operation, because a store that read the
//! pool, chose a package and wrote the pool back would hand the same package
//! to two concurrent joiners under load. A module steps once at a time over
//! state nothing else can reach, so the interleaving that failure needs
//! cannot occur — the guarantee is structural rather than upheld.
//!
//! Two paths:
//!
//! * `POST /e2ee/keypackages` publishes a batch for a device.
//! * `POST /e2ee/keypackages/claim` consumes one.

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

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/b64.rs"]
mod b64;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/e2ee_credential.rs"]
mod credential;
#[path = "../../common/jose.rs"]
mod jose;
#[path = "../../common/jwk.rs"]
mod jwk;

use credential::Ciphersuite;

const STEP_DID_WORK: i32 = 2;
const REQ_HDR: usize = 12;
const RESP_HDR: usize = 12;
const METHOD_POST: u8 = 3;

/// Devices whose pools this module holds.
///
/// Bounded, like everything a module keeps resident. A deployment with more
/// devices than this needs a pool per shard, which is a graph decision; a
/// module that grew instead would be a module that runs out of memory at a
/// time nobody chose.
const MAX_DEVICES: usize = 16;
/// Packages one device may have waiting.
const MAX_PACKAGES: usize = 8;
/// The group protocol's own bytes, opaque here.
const MAX_PAYLOAD: usize = 512;
/// Longest device identifier accepted.
const MAX_ID: usize = 64;
const MAX_REQS_PER_STEP: usize = 2;

/// How a package may be consumed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reuse {
    /// Consumed once and then gone. What every package should be.
    Once,
    /// May be served after the pool is empty, repeatedly.
    ///
    /// A deliberate weakening: it keeps a device addable when it has been
    /// offline long enough to exhaust its pool, at the cost of the initial
    /// secret for those additions no longer being unique. Marked so nothing
    /// serves one by accident and a caller that receives one knows it holds
    /// the weaker guarantee.
    LastResort,
}

#[derive(Clone, Copy)]
struct Package {
    payload: [u8; MAX_PAYLOAD],
    payload_len: u16,
    generation: u32,
    not_after: u64,
    reuse: Reuse,
    live: bool,
}

impl Package {
    const fn empty() -> Self {
        Self {
            payload: [0; MAX_PAYLOAD],
            payload_len: 0,
            generation: 0,
            not_after: 0,
            reuse: Reuse::Once,
            live: false,
        }
    }
}

#[derive(Clone, Copy)]
struct Pool {
    device: [u8; MAX_ID],
    device_len: u8,
    /// The generation this pool is for. A rotation makes every earlier
    /// generation unclaimable, which is expressed by emptying the pool
    /// rather than by filtering on read — a package nobody can claim is not
    /// a package worth keeping resident.
    generation: u32,
    packages: [Package; MAX_PACKAGES],
    live: bool,
}

impl Pool {
    const fn empty() -> Self {
        Self {
            device: [0; MAX_ID],
            device_len: 0,
            generation: 0,
            packages: [Package::empty(); MAX_PACKAGES],
            live: false,
        }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    out_responses: i32,

    pools: [Pool; MAX_DEVICES],

    package_published: u32,
    package_claimed_exclusive: u32,
    package_claimed_last_resort: u32,
    package_pool_empty: u32,
    package_pool_full: u32,
    package_malformed: u32,

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
        s.pools = [Pool::empty(); MAX_DEVICES];
        s.package_published = 0;
        s.package_claimed_exclusive = 0;
        s.package_claimed_last_resort = 0;
        s.package_pool_empty = 0;
        s.package_pool_full = 0;
        s.package_malformed = 0;

        dev_log(sys, 3, b"[keypkg] init".as_ptr(), 13);
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
    let claiming = path == b"/e2ee/keypackages/claim";
    let publishing = path == b"/e2ee/keypackages";
    if !claiming && !publishing {
        respond(s, sys, conn, stream, 404, br#"{"error":"not_found"}"#);
        return;
    }
    if method != METHOD_POST {
        respond(s, sys, conn, stream, 405, br#"{"error":"invalid_request"}"#);
        return;
    }

    if claiming {
        claim(s, sys, conn, stream, body_at, body_end);
    } else {
        publish(s, sys, conn, stream, body_at, body_end);
    }
}

/// Add a package to a device's pool.
///
/// # Safety
///
/// As `handle_request`.
unsafe fn publish(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    body_at: usize,
    body_end: usize,
) {
    let mut device = [0u8; MAX_ID];
    let mut payload = [0u8; MAX_PAYLOAD];
    let (device_len, payload_len, generation, not_after, reuse, suite_ok) = {
        let body = &s.buf[body_at..body_end];
        let device_len = json_string(body, b"device_id", &mut device);
        let mut encoded = [0u8; MAX_PAYLOAD * 2];
        let encoded_len = json_string(body, b"payload", &mut encoded);
        let payload_len = if encoded_len == 0 {
            0
        } else {
            b64::decode(&encoded[..encoded_len], &mut payload).unwrap_or(0)
        };
        let generation = jose::claim_u64(body, b"generation").unwrap_or(0);
        let not_after = jose::claim_u64(body, b"not_after").unwrap_or(0);
        let reuse = match jose::claim_str(body, b"reuse") {
            Some(b"last_resort") => Reuse::LastResort,
            _ => Reuse::Once,
        };
        // A joiner must not be handed a package from a suite its group does
        // not run, so a package naming a suite this build does not attest to
        // is refused at publication rather than discovered at a join.
        let suite_ok = jose::claim_u64(body, b"suite")
            .and_then(|code| u16::try_from(code).ok())
            .and_then(Ciphersuite::from_code)
            .is_some();
        (
            device_len,
            payload_len,
            generation,
            not_after,
            reuse,
            suite_ok,
        )
    };

    if device_len == 0 || payload_len == 0 || generation == 0 || not_after == 0 || !suite_ok {
        s.package_malformed = s.package_malformed.saturating_add(1);
        respond(s, sys, conn, stream, 400, br#"{"error":"invalid_request"}"#);
        return;
    }
    let Ok(generation) = u32::try_from(generation) else {
        s.package_malformed = s.package_malformed.saturating_add(1);
        respond(s, sys, conn, stream, 400, br#"{"error":"invalid_request"}"#);
        return;
    };

    let Some(index) = pool_for(s, &device[..device_len], generation) else {
        s.package_pool_full = s.package_pool_full.saturating_add(1);
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

    let Some(slot) = s.pools[index].packages.iter().position(|p| !p.live) else {
        s.package_pool_full = s.package_pool_full.saturating_add(1);
        respond(s, sys, conn, stream, 409, br#"{"error":"pool_full"}"#);
        return;
    };

    let package = &mut s.pools[index].packages[slot];
    package.payload = [0; MAX_PAYLOAD];
    package.payload[..payload_len].copy_from_slice(&payload[..payload_len]);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_PAYLOAD")]
    {
        package.payload_len = payload_len as u16;
    }
    package.generation = generation;
    package.not_after = not_after;
    package.reuse = reuse;
    package.live = true;

    s.package_published = s.package_published.saturating_add(1);
    respond(s, sys, conn, stream, 200, br#"{"published":true}"#);
}

/// Consume one package for a device.
///
/// # Safety
///
/// As `handle_request`.
unsafe fn claim(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    body_at: usize,
    body_end: usize,
) {
    let mut device = [0u8; MAX_ID];
    let device_len = {
        let body = &s.buf[body_at..body_end];
        json_string(body, b"device_id", &mut device)
    };
    if device_len == 0 {
        s.package_malformed = s.package_malformed.saturating_add(1);
        respond(s, sys, conn, stream, 400, br#"{"error":"invalid_request"}"#);
        return;
    }
    let now = dev_unix_millis(sys) / 1000;

    let Some(index) = s
        .pools
        .iter()
        .position(|p| p.live && p.device[..usize::from(p.device_len)] == device[..device_len])
    else {
        s.package_pool_empty = s.package_pool_empty.saturating_add(1);
        respond(s, sys, conn, stream, 404, br#"{"error":"no_packages"}"#);
        return;
    };

    // A one-time package first, always. A last-resort package is served only
    // when nothing else is left, because serving one while an exclusive
    // package was available would give away the stronger guarantee for free.
    let exclusive = s.pools[index]
        .packages
        .iter()
        .position(|p| p.live && p.reuse == Reuse::Once && now < p.not_after);
    let chosen = exclusive.or_else(|| {
        s.pools[index]
            .packages
            .iter()
            .position(|p| p.live && p.reuse == Reuse::LastResort && now < p.not_after)
    });
    let Some(slot) = chosen else {
        s.package_pool_empty = s.package_pool_empty.saturating_add(1);
        respond(s, sys, conn, stream, 404, br#"{"error":"no_packages"}"#);
        return;
    };

    let package = s.pools[index].packages[slot];
    if package.reuse == Reuse::Once {
        // Consumed here, before anything is written back to the caller. A
        // module steps once at a time, so there is no interleaving in which
        // the same package leaves twice — but marking it spent before the
        // answer is composed keeps that true of any future step that learns
        // to yield partway.
        s.pools[index].packages[slot].live = false;
        s.package_claimed_exclusive = s.package_claimed_exclusive.saturating_add(1);
    } else {
        s.package_claimed_last_resort = s.package_claimed_last_resort.saturating_add(1);
    }

    let mut encoded = [0u8; MAX_PAYLOAD * 2];
    let Some(encoded_len) = b64::encode(
        &package.payload[..usize::from(package.payload_len)],
        &mut encoded,
    ) else {
        respond(s, sys, conn, stream, 500, br#"{"error":"server_error"}"#);
        return;
    };

    let mut body = [0u8; MAX_PAYLOAD * 2 + 128];
    let mut at = 0usize;
    let _ = put(&mut body, &mut at, br#"{"exclusive":"#);
    let _ = put(
        &mut body,
        &mut at,
        if package.reuse == Reuse::Once {
            b"true"
        } else {
            b"false"
        },
    );
    let _ = put(&mut body, &mut at, br#","generation":"#);
    let _ = put_u64(&mut body, &mut at, u64::from(package.generation));
    let _ = put(&mut body, &mut at, br#","payload":"#);
    let _ = put(&mut body, &mut at, b"\"");
    let _ = put(&mut body, &mut at, &encoded[..encoded_len]);
    let _ = put(&mut body, &mut at, b"\"}");

    respond(s, sys, conn, stream, 200, &body[..at]);
}

/// The pool for a device at `generation`, creating or rotating as needed.
///
/// A newer generation empties the pool rather than filtering on read: a
/// package nobody can claim is not a package worth keeping resident, and a
/// filter would leave the pool looking full while every entry was dead.
fn pool_for(s: &mut ModuleState, device: &[u8], generation: u32) -> Option<usize> {
    if let Some(index) = s
        .pools
        .iter()
        .position(|p| p.live && &p.device[..usize::from(p.device_len)] == device)
    {
        if generation > s.pools[index].generation {
            s.pools[index].packages = [Package::empty(); MAX_PACKAGES];
            s.pools[index].generation = generation;
        } else if generation < s.pools[index].generation {
            // A package for a generation already rotated past is not
            // publishable: it would be claimable material bound to a key the
            // device has said it no longer uses.
            return None;
        }
        return Some(index);
    }

    let free = s.pools.iter().position(|p| !p.live)?;
    if device.len() > MAX_ID {
        return None;
    }
    let pool = &mut s.pools[free];
    *pool = Pool::empty();
    pool.device[..device.len()].copy_from_slice(device);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_ID above")]
    {
        pool.device_len = device.len() as u8;
    }
    pool.generation = generation;
    pool.live = true;
    Some(free)
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

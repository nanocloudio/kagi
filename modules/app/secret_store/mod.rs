//! Secret Store — sealed secret records behind a channel request API.
//!
//! Serves MSG_SECRET_GET/PUT/LIST/ROTATE requests over `requests`,
//! replying on `replies`. Records are sealed with AES-256-GCM under the
//! current KEK (delivered on `key_update` as MSG_KEY_EPOCH) using the
//! shared `secret_record` envelope, held in a fixed in-memory table, and
//! persisted as a single rewrite-on-change file (`secrets/store.bin`)
//! via the FS contract. Degrades silently to memory-only when no FS
//! provider is present; on FS E_AGAIN (provider still initialising) it
//! waits and retries next step.

#![no_std]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in target/fluxor/fluxor-abi/sdk/"
)]
#![allow(
    clippy::needless_return,
    reason = "fires inside the SDK's aes_gcm.rs, which this module mounts by path; \
              target/fluxor/** is materialised by `fluxor sync` and not ours to edit"
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

// Crypto primitives (crate-root include, mirroring fluxor's tls module).
// aes_gcm's key zeroisation lives in p256.rs, and p256 in turn needs
// hmac + both hash widths, so the include set is the full chain.
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha384.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/hmac.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/aes_gcm.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/p256.rs");

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/secret_record.rs"]
mod secret_record;

use auth_wire::{PayloadReader, PayloadWriter};

// FS opcodes (see target/fluxor/fluxor-abi/sdk/contracts/storage/fs.rs)
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_CLOSE: u32 = 0x0903;
const FS_FSYNC: u32 = 0x0905;
const FS_WRITE: u32 = 0x0906;
/// Write-side opener. `FS_OPEN` is read-only-if-exists per the FS
/// contract; store-file creation needs the write tier.
const FS_OPEN_CREATE: u32 = 0x0909;

/// FS E_AGAIN: the FS provider is present but still initialising.
/// Distinct from a hard error (ENODEV/ENOSYS = no provider): on
/// E_AGAIN we retry next step rather than degrading to memory-only.
const FS_E_AGAIN: i32 = -11;

// Module phases
const PHASE_LOAD: u8 = 0;
const PHASE_NORMAL: u8 = 1;

/// Bounds for a stored record. `SLOT_LEN` is the sealed envelope for
/// the maxima; every record fits in one fixed slot.
const MAX_ID_LEN: usize = 64;
const MAX_VER_LEN: usize = 16;
const MAX_VALUE_LEN: usize = 1024;
const SLOT_LEN: usize = secret_record::sealed_len(MAX_ID_LEN, MAX_VER_LEN, MAX_VALUE_LEN);
const MAX_RECORDS: usize = 32;

/// Store-file header: `[magic "KSF1"][body_len u32 LE]` followed by
/// `body_len` bytes of concatenated sealed records. The length prefix
/// makes rewrites safe against a stale longer tail left behind by an
/// OPEN_CREATE that does not truncate.
const FILE_MAGIC: [u8; 4] = *b"KSF1";
const FILE_HDR: usize = 8;
const FILE_BUF_LEN: usize = FILE_HDR + MAX_RECORDS * SLOT_LEN;

const STORE_PATH: &[u8] = b"secrets/store.bin";

/// WCET bound: requests handled per step.
const MAX_REQS_PER_STEP: usize = 8;

/// AEAD seal via the SDK's AES-256-GCM, in the fn-pointer shape
/// `secret_record::AeadSealFn` expects.
fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8; secret_record::NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
) -> [u8; secret_record::TAG_LEN] {
    AesGcm::new_256(key).encrypt(nonce, aad, data)
}

/// AEAD open counterpart (`secret_record::AeadOpenFn`).
fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; secret_record::NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; secret_record::TAG_LEN],
) -> bool {
    AesGcm::new_256(key).decrypt(nonce, aad, data, tag)
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Record {
    used: bool,
    /// Rotation counter; version_id becomes its ascii decimal on rotate.
    ver_ctr: u32,
    /// Encoded (sealed) length of `data`.
    len: u16,
    /// Denormalised id for cheap lookup (also inside the sealed envelope).
    id_len: u8,
    id: [u8; MAX_ID_LEN],
    /// Sealed record bytes (`secret_record` envelope).
    data: [u8; SLOT_LEN],
}

impl Record {
    const fn zero() -> Self {
        Self {
            used: false,
            ver_ctr: 0,
            len: 0,
            id_len: 0,
            id: [0; MAX_ID_LEN],
            data: [0; SLOT_LEN],
        }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,   // in[0]: MSG_SECRET_* requests
    out_replies: i32,   // out[0]: MSG_SECRET_VALUE / ACK / LIST_PAGE
    in_key_update: i32, // in[1]: MSG_KEY_EPOCH from the key source

    // KEK
    kek: [u8; 32],
    kek_epoch: u32,
    has_kek: bool,

    /// Monotonic per-seal counter; nonce = `[epoch u32 LE][ctr u64 LE]`.
    /// Seeded from wall-clock millis at boot so a restart under a
    /// re-delivered (epoch, KEK) pair cannot reuse a nonce.
    nonce_ctr: u64,

    // FS
    phase: u8, // PHASE_LOAD | PHASE_NORMAL
    /// Hard FS failure seen on the write path — degrade to memory-only.
    no_fs: bool,
    no_fs_logged: bool,
    /// A persist is owed (E_AGAIN or channel pressure); retry next step.
    dirty: bool,

    records: [Record; MAX_RECORDS],

    // Metrics (names mirror manifest [observability])
    get_ops: u32,
    put_ops: u32,
    list_ops: u32,
    rotate_ops: u32,
    decrypt_failures: u32,
    records_count: u32,
    bytes_stored: u32,

    // Scratch
    msg_buf: [u8; 4096],
    file_buf: [u8; FILE_BUF_LEN],
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
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
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
        s.in_key_update = dev_channel_port(sys, 0, 1);

        s.has_kek = false;
        s.kek = [0u8; 32];
        s.kek_epoch = 0;
        s.nonce_ctr = dev_unix_millis(sys);

        s.phase = PHASE_LOAD;
        s.no_fs = false;
        s.no_fs_logged = false;
        s.dirty = false;
        s.records = [Record::zero(); MAX_RECORDS];
        s.get_ops = 0;
        s.put_ops = 0;
        s.list_ops = 0;
        s.rotate_ops = 0;
        s.decrypt_failures = 0;
        s.records_count = 0;
        s.bytes_stored = 0;

        dev_log(sys, 3, b"[sstore] init".as_ptr(), 13);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        if s.phase == PHASE_LOAD {
            // Load the store file before serving requests. On FS
            // E_AGAIN this holds (requests backpressure) and retries.
            return step_load(s, sys);
        }

        // KEK updates first, so a same-step PUT uses the latest epoch.
        drain_key_updates(s, sys);

        // Owed persist from a previous E_AGAIN — retry before new work.
        if s.dirty && !s.no_fs {
            persist(s, sys);
        }

        for _ in 0..MAX_REQS_PER_STEP {
            if !chan::can_read(sys, s.in_requests) {
                break;
            }
            // Every request produces exactly one reply; don't consume a
            // request we cannot answer.
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

// ── KEK intake ──────────────────────────────────────────────

/// Drain `key_update`, keeping the latest MSG_KEY_EPOCH
/// (`[epoch u32 LE][kek 32B]`).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_key_updates(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_key_update < 0 {
        return;
    }
    for _ in 0..4 {
        if !chan::can_read(sys, s.in_key_update) {
            break;
        }
        let mut buf = [0u8; 64];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_key_update, &mut buf);
        if msg_type != auth_wire::MSG_KEY_EPOCH || (plen as usize) < 36 {
            continue;
        }
        s.kek_epoch = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        s.kek.copy_from_slice(&buf[4..36]);
        s.has_kek = true;
    }
}

/// Next unique nonce for the current KEK: `[epoch u32 LE][ctr u64 LE]`.
fn next_nonce(s: &mut ModuleState) -> [u8; secret_record::NONCE_LEN] {
    s.nonce_ctr = s.nonce_ctr.wrapping_add(1);
    let mut nonce = [0u8; secret_record::NONCE_LEN];
    nonce[..4].copy_from_slice(&s.kek_epoch.to_le_bytes());
    nonce[4..].copy_from_slice(&s.nonce_ctr.to_le_bytes());
    nonce
}

// ── Request handling ────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_request(s: &mut ModuleState, sys: &SyscallTable, msg_type: u8, plen: usize) {
    // Correlation id is the first field of every request; a payload too
    // short even for that is dropped (no way to address a reply).
    if plen < 4 {
        return;
    }
    let corr = u32::from_le_bytes([s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3]]);

    match msg_type {
        auth_wire::MSG_SECRET_GET => handle_get(s, sys, corr, plen),
        auth_wire::MSG_SECRET_PUT => handle_put(s, sys, corr, plen),
        auth_wire::MSG_SECRET_LIST => handle_list(s, sys, corr, plen),
        auth_wire::MSG_SECRET_ROTATE => handle_rotate(s, sys, corr, plen),
        _ => {}
    }
}

fn find_record(s: &ModuleState, id: &[u8]) -> Option<usize> {
    s.records
        .iter()
        .position(|r| r.used && &r.id[..usize::from(r.id_len)] == id)
}

/// `MSG_SECRET_GET` = `[corr u32][id f8]` → `MSG_SECRET_VALUE`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_get(s: &mut ModuleState, sys: &SyscallTable, corr: u32, plen: usize) {
    s.get_ops = s.get_ops.saturating_add(1);
    let mut r = PayloadReader::new(&s.msg_buf[..plen]);
    let _ = r.u32();
    let Ok(id_field) = r.field8() else {
        reply_value(s, sys, corr, auth_wire::ST_MALFORMED, &[], &[], &[]);
        return;
    };
    let mut id = [0u8; MAX_ID_LEN];
    if id_field.len() > MAX_ID_LEN {
        reply_value(s, sys, corr, auth_wire::ST_MALFORMED, &[], &[], &[]);
        return;
    }
    id[..id_field.len()].copy_from_slice(id_field);
    let id = &id[..id_field.len()];

    let Some(idx) = find_record(s, id) else {
        reply_value(s, sys, corr, auth_wire::ST_NOT_FOUND, id, &[], &[]);
        return;
    };
    if !s.has_kek {
        reply_value(s, sys, corr, auth_wire::ST_NO_KEY, id, &[], &[]);
        return;
    }

    // Copy the sealed bytes out of the table so the RecordView borrow
    // doesn't pin `s.records` while we build the reply.
    let mut sealed = [0u8; SLOT_LEN];
    let sealed_len = usize::from(s.records[idx].len);
    sealed[..sealed_len].copy_from_slice(&s.records[idx].data[..sealed_len]);

    let mut ver = [0u8; MAX_VER_LEN];
    let mut ver_len = 0usize;
    let mut value = [0u8; MAX_VALUE_LEN];
    let opened = match secret_record::RecordView::parse(&sealed[..sealed_len]) {
        Ok(view) => {
            ver_len = view.version_id.len().min(MAX_VER_LEN);
            ver[..ver_len].copy_from_slice(&view.version_id[..ver_len]);
            view.open_into(aead_open, &s.kek, &mut value).ok()
        }
        Err(_) => None,
    };
    match opened {
        Some(n) => {
            let mut v = [0u8; MAX_VALUE_LEN];
            v[..n].copy_from_slice(&value[..n]);
            reply_value(s, sys, corr, auth_wire::ST_OK, id, &ver[..ver_len], &v[..n]);
        }
        None => {
            s.decrypt_failures = s.decrypt_failures.saturating_add(1);
            reply_value(s, sys, corr, auth_wire::ST_DECRYPT_FAILED, id, &[], &[]);
        }
    }
}

/// `MSG_SECRET_PUT` = `[corr u32][id f8][ver f8][value f16]` → ACK.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_put(s: &mut ModuleState, sys: &SyscallTable, corr: u32, plen: usize) {
    s.put_ops = s.put_ops.saturating_add(1);

    let (id, ver, value) = {
        let mut r = PayloadReader::new(&s.msg_buf[..plen]);
        let _ = r.u32();
        let (Ok(id), Ok(ver), Ok(value)) = (r.field8(), r.field8(), r.field16()) else {
            reply_ack(s, sys, corr, auth_wire::ST_MALFORMED);
            return;
        };
        (id, ver, value)
    };
    if id.is_empty()
        || id.len() > MAX_ID_LEN
        || ver.len() > MAX_VER_LEN
        || value.len() > MAX_VALUE_LEN
    {
        reply_ack(s, sys, corr, auth_wire::ST_MALFORMED);
        return;
    }
    if !s.has_kek {
        reply_ack(s, sys, corr, auth_wire::ST_NO_KEY);
        return;
    }

    // Copy fields off msg_buf before mutating state.
    let mut id_b = [0u8; MAX_ID_LEN];
    id_b[..id.len()].copy_from_slice(id);
    let id_len = id.len();
    let mut ver_b = [0u8; MAX_VER_LEN];
    ver_b[..ver.len()].copy_from_slice(ver);
    let ver_len = ver.len();
    let mut val_b = [0u8; MAX_VALUE_LEN];
    val_b[..value.len()].copy_from_slice(value);
    let val_len = value.len();

    let idx = match find_record(s, &id_b[..id_len]) {
        Some(i) => i,
        None => match s.records.iter().position(|r| !r.used) {
            Some(i) => i,
            None => {
                reply_ack(s, sys, corr, auth_wire::ST_FULL);
                return;
            }
        },
    };

    let nonce = next_nonce(s);
    let mut sealed = [0u8; SLOT_LEN];
    let sealed_len = match secret_record::seal_into(
        aead_seal,
        &s.kek,
        &nonce,
        &id_b[..id_len],
        &ver_b[..ver_len],
        &val_b[..val_len],
        &mut sealed,
    ) {
        Ok(n) => n,
        Err(_) => {
            reply_ack(s, sys, corr, auth_wire::ST_MALFORMED);
            return;
        }
    };

    store_record(s, idx, &id_b[..id_len], &sealed[..sealed_len], 1);
    persist(s, sys);
    reply_ack(s, sys, corr, auth_wire::ST_OK);
}

/// `MSG_SECRET_LIST` = `[corr u32][prefix f8]` → `MSG_SECRET_LIST_PAGE`
/// `[corr][count u8][{id f8} x count][more u8]`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_list(s: &mut ModuleState, sys: &SyscallTable, corr: u32, plen: usize) {
    s.list_ops = s.list_ops.saturating_add(1);
    let mut prefix = [0u8; MAX_ID_LEN];
    let prefix_len = {
        let mut r = PayloadReader::new(&s.msg_buf[..plen]);
        let _ = r.u32();
        match r.field8() {
            Ok(p) if p.len() <= MAX_ID_LEN => {
                prefix[..p.len()].copy_from_slice(p);
                p.len()
            }
            _ => 0,
        }
    };
    let prefix = &prefix[..prefix_len];

    let mut payload = [0u8; 2560];
    let mut w = PayloadWriter::new(&mut payload);
    let _ = w.u32(corr);
    let _ = w.u8(0); // count, patched below
    let mut count: u8 = 0;
    let mut more: u8 = 0;
    for rec in s.records.iter().filter(|r| r.used) {
        let id = &rec.id[..usize::from(rec.id_len)];
        if !id.starts_with(prefix) {
            continue;
        }
        if count == u8::MAX || w.field8(id).is_err() {
            more = 1;
            break;
        }
        count += 1;
    }
    let _ = w.u8(more);
    let n = w.len();
    payload[4] = count;
    chan::channel_write_msg(
        sys,
        s.out_replies,
        auth_wire::MSG_SECRET_LIST_PAGE,
        &payload[..n],
    );
}

/// `MSG_SECRET_ROTATE` = `[corr u32][id f8]` → ACK. Re-seals the record
/// under the current KEK with a fresh nonce and a bumped version
/// counter (version_id becomes the counter's ascii decimal).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_rotate(s: &mut ModuleState, sys: &SyscallTable, corr: u32, plen: usize) {
    s.rotate_ops = s.rotate_ops.saturating_add(1);
    let mut id = [0u8; MAX_ID_LEN];
    let id_len = {
        let mut r = PayloadReader::new(&s.msg_buf[..plen]);
        let _ = r.u32();
        match r.field8() {
            Ok(f) if !f.is_empty() && f.len() <= MAX_ID_LEN => {
                id[..f.len()].copy_from_slice(f);
                f.len()
            }
            _ => {
                reply_ack(s, sys, corr, auth_wire::ST_MALFORMED);
                return;
            }
        }
    };
    let id = &id[..id_len];

    let Some(idx) = find_record(s, id) else {
        reply_ack(s, sys, corr, auth_wire::ST_NOT_FOUND);
        return;
    };
    if !s.has_kek {
        reply_ack(s, sys, corr, auth_wire::ST_NO_KEY);
        return;
    }

    let mut sealed = [0u8; SLOT_LEN];
    let sealed_len = usize::from(s.records[idx].len);
    sealed[..sealed_len].copy_from_slice(&s.records[idx].data[..sealed_len]);

    let mut value = [0u8; MAX_VALUE_LEN];
    let opened = match secret_record::RecordView::parse(&sealed[..sealed_len]) {
        Ok(view) => view.open_into(aead_open, &s.kek, &mut value).ok(),
        Err(_) => None,
    };
    let Some(val_len) = opened else {
        s.decrypt_failures = s.decrypt_failures.saturating_add(1);
        reply_ack(s, sys, corr, auth_wire::ST_DECRYPT_FAILED);
        return;
    };

    let new_ver = s.records[idx].ver_ctr.saturating_add(1);
    let mut ver_buf = [0u8; MAX_VER_LEN];
    let ver_len = fmt_ver_dec(new_ver, &mut ver_buf);

    let nonce = next_nonce(s);
    let mut resealed = [0u8; SLOT_LEN];
    let resealed_len = match secret_record::seal_into(
        aead_seal,
        &s.kek,
        &nonce,
        id,
        &ver_buf[..ver_len],
        &value[..val_len],
        &mut resealed,
    ) {
        Ok(n) => n,
        Err(_) => {
            reply_ack(s, sys, corr, auth_wire::ST_MALFORMED);
            return;
        }
    };

    store_record(s, idx, id, &resealed[..resealed_len], new_ver);
    persist(s, sys);
    reply_ack(s, sys, corr, auth_wire::ST_OK);
}

/// Place a sealed record in slot `idx` and refresh the aggregate
/// metrics (`records`, `bytes_stored`).
fn store_record(s: &mut ModuleState, idx: usize, id: &[u8], sealed: &[u8], ver_ctr: u32) {
    let rec = &mut s.records[idx];
    rec.used = true;
    rec.ver_ctr = ver_ctr;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "sealed fits SLOT_LEN < u16::MAX"
    )]
    {
        rec.len = sealed.len() as u16;
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "id bounded by MAX_ID_LEN (64)"
    )]
    {
        rec.id_len = id.len() as u8;
    }
    rec.id[..id.len()].copy_from_slice(id);
    rec.data[..sealed.len()].copy_from_slice(sealed);

    let mut count = 0u32;
    let mut bytes = 0u32;
    for r in s.records.iter().filter(|r| r.used) {
        count += 1;
        bytes += u32::from(r.len);
    }
    s.records_count = count;
    s.bytes_stored = bytes;
}

/// Ascii-decimal formatter for version counters. Returns digit count.
/// (Named apart from the SDK runtime's `fmt_u32_dec`, which lands at
/// the crate root via `include!`.)
fn fmt_ver_dec(mut v: u32, out: &mut [u8; MAX_VER_LEN]) -> usize {
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let n = digits.len() - i;
    out[..n].copy_from_slice(&digits[i..]);
    n
}

// ── Replies ─────────────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn reply_ack(s: &mut ModuleState, sys: &SyscallTable, corr: u32, status: u8) {
    let mut payload = [0u8; 8];
    let mut w = PayloadWriter::new(&mut payload);
    let _ = w.u32(corr);
    let _ = w.u8(status);
    let n = w.len();
    chan::channel_write_msg(sys, s.out_replies, auth_wire::MSG_SECRET_ACK, &payload[..n]);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn reply_value(
    s: &mut ModuleState,
    sys: &SyscallTable,
    corr: u32,
    status: u8,
    id: &[u8],
    ver: &[u8],
    value: &[u8],
) {
    let mut payload = [0u8; 2048];
    let mut w = PayloadWriter::new(&mut payload);
    let _ = w.u32(corr);
    let _ = w.u8(status);
    let _ = w.field8(id);
    let _ = w.field8(ver);
    let _ = w.field16(value);
    let n = w.len();
    chan::channel_write_msg(
        sys,
        s.out_replies,
        auth_wire::MSG_SECRET_VALUE,
        &payload[..n],
    );
}

// ── Persistence ─────────────────────────────────────────────

/// One-time boot load of `secrets/store.bin`. E_AGAIN holds the module
/// in PHASE_LOAD (requests backpressure); any other open failure —
/// missing file or missing provider — starts empty.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn step_load(s: &mut ModuleState, sys: &SyscallTable) -> i32 {
    let mut path = [0u8; 32];
    path[..STORE_PATH.len()].copy_from_slice(STORE_PATH);
    let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), STORE_PATH.len());
    if fd == FS_E_AGAIN {
        // Provider still initialising — retry next step.
        return 0;
    }
    if fd < 0 {
        // No file yet (fresh deployment) or no provider. Start empty;
        // the write path decides memory-only degradation on its own.
        s.phase = PHASE_NORMAL;
        return 0;
    }

    let mut total = 0usize;
    while total < FILE_BUF_LEN {
        let r = (sys.provider_call)(
            fd,
            FS_READ,
            s.file_buf.as_mut_ptr().add(total),
            FILE_BUF_LEN - total,
        );
        if r <= 0 {
            break;
        }
        total += r as usize;
    }
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);

    if total >= FILE_HDR && s.file_buf[..4] == FILE_MAGIC {
        let body_len =
            u32::from_le_bytes([s.file_buf[4], s.file_buf[5], s.file_buf[6], s.file_buf[7]])
                as usize;
        let end = FILE_HDR + body_len.min(total.saturating_sub(FILE_HDR));
        let mut off = FILE_HDR;
        let mut slot = 0usize;
        while off < end && slot < MAX_RECORDS {
            // Copy each candidate out so the parse borrow doesn't pin
            // `s.file_buf` while `store_record` mutates `s`.
            let avail = (end - off).min(SLOT_LEN);
            let mut sealed = [0u8; SLOT_LEN];
            sealed[..avail].copy_from_slice(&s.file_buf[off..off + avail]);
            let Ok(view) = secret_record::RecordView::parse(&sealed[..avail]) else {
                // Torn tail / corrupt record — stop loading here.
                break;
            };
            let (enc_len, id_len) = (view.encoded_len, view.id.len());
            if id_len == 0 || id_len > MAX_ID_LEN {
                break;
            }
            let mut id = [0u8; MAX_ID_LEN];
            id[..id_len].copy_from_slice(view.id);
            let ver_ctr = parse_dec_u32(view.version_id).unwrap_or(1);
            store_record(s, slot, &id[..id_len], &sealed[..enc_len], ver_ctr);
            off += enc_len;
            slot += 1;
        }
    }

    s.phase = PHASE_NORMAL;
    0
}

/// Best-effort ascii-decimal parse (rotate counters round-trip).
fn parse_dec_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 10 {
        return None;
    }
    let mut v: u32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(v)
}

/// Rewrite the whole store file (`[magic][body_len][records...]`) via
/// OPEN_CREATE + WRITE + FSYNC + CLOSE. On E_AGAIN the write is owed
/// (`dirty`) and retried next step; on a hard failure the store
/// degrades to memory-only permanently (logged once).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn persist(s: &mut ModuleState, sys: &SyscallTable) {
    if s.no_fs {
        return;
    }

    // Build the file image.
    let mut total = FILE_HDR;
    for i in 0..MAX_RECORDS {
        if !s.records[i].used {
            continue;
        }
        let len = usize::from(s.records[i].len);
        let (rec_ptr, dst_ptr) = (
            s.records[i].data.as_ptr(),
            s.file_buf.as_mut_ptr().add(total),
        );
        // Disjoint state fields (records vs file_buf); lengths bounded
        // by FILE_BUF_LEN = FILE_HDR + MAX_RECORDS * SLOT_LEN.
        core::ptr::copy_nonoverlapping(rec_ptr, dst_ptr, len);
        total += len;
    }
    s.file_buf[..4].copy_from_slice(&FILE_MAGIC);
    let body_len = (total - FILE_HDR) as u32;
    s.file_buf[4..8].copy_from_slice(&body_len.to_le_bytes());

    let mut path = [0u8; 32];
    path[..STORE_PATH.len()].copy_from_slice(STORE_PATH);
    let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_mut_ptr(), STORE_PATH.len());
    if fd == FS_E_AGAIN {
        s.dirty = true;
        return;
    }
    if fd < 0 {
        // Hard failure — no write-capable provider. Memory-only from
        // here on; say so exactly once.
        s.no_fs = true;
        s.dirty = false;
        if !s.no_fs_logged {
            s.no_fs_logged = true;
            dev_log(sys, 2, b"[sstore] no fs; memory-only".as_ptr(), 27);
        }
        return;
    }

    // OPEN_CREATE position is provider-defined; pin to 0 for a rewrite.
    let seek = 0i32.to_le_bytes();
    (sys.provider_call)(fd, FS_SEEK, seek.as_ptr() as *mut u8, 4);
    let w = (sys.provider_call)(fd, FS_WRITE, s.file_buf.as_mut_ptr(), total);
    if (w as usize) == total {
        (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0);
        s.dirty = false;
    } else {
        // Short/failed write: keep the persist owed and retry.
        s.dirty = true;
    }
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
}

// WASM entry wrappers (module_init_wasm / module_step_wasm). Emits
// nothing on non-wasm targets; on wasm32 it adapts the PIC exports
// above to the browser kernel's calling convention.
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/wasm_entry.rs");

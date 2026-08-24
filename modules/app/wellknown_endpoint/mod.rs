//! The issuer's public documents: its key set, and its revocations.
//!
//! Both say what a relying party may trust, both are fetched by anyone, and
//! both are answered here — one module, because a listener behind wave's
//! `foundation/http` fans out to one application, and an issuer that wants
//! both documents on separate listeners pays for it in `linux_net` lanes.
//!
//! `LINUX_NET_MAX_INBOUND` is 8: the provider takes at most eight distinct
//! producer modules, each on its own priority lane so a bulk flood on one
//! cannot serialise ahead of latency-critical traffic on another. That is a
//! bound on how many modules drive the network, NOT on how many ports exist
//! — `linux_net` holds 128 connection slots — and one `http` module serving
//! many routes costs one lane whatever the route count. So the way to fit is
//! a module that owns a path family rather than a single path, which is what
//! this is.
//!
//! `GET /jwks` (or `/.well-known/jwks.json`) is answered with an RFC 7517
//! JWK Set built from whatever keys have arrived — the same MSG_VERIFY_KEY
//! frames `token_verify` and `resource_gate` take, so one key distribution
//! reaches everything that needs it and there is no second shape to keep in
//! step.
//!
//! `GET /.well-known/revocations.json` is answered with a Bloom filter over
//! revoked device identifiers.
//!
//! **A filter, not a list.** The document is public and a list would
//! enumerate every device the issuer has ever revoked — how many there are,
//! and, to anyone who can guess an identifier, which. A filter answers the
//! only question a relying party actually asks and answers nothing else. The
//! error it admits is the safe direction: a device that was never revoked may
//! occasionally be refused, and no revoked device is ever accepted.
//!
//! It is a hint, never an authority. A relying party treating a miss as proof
//! of good standing has misread it — the document is at most as fresh as its
//! `updated_at`.
//!
//! Only public material is ever here. The mint holds the private half and
//! this module is never told it, which is what makes it safe for this to be
//! the one endpoint with no authentication in front of it.
//!
//! **An empty set is served, not a 404.** A relying party that asked before
//! any key had arrived needs to tell "this issuer has no keys right now" from
//! "this is not an issuer" — the first is a reason to retry, the second is a
//! reason to give up, and answering 404 would send it to the wrong one.

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
#[path = "../../common/jwk.rs"]
mod jwk;

use auth_wire::PayloadReader;

/// `module_step` return code for "did work, step me again".
const STEP_DID_WORK: i32 = 2;

/// `HttpRequest`  `[conn u16][stream u16][method u8][flags u8][path_len u16][hdr_len u16][body_len u16]`
const REQ_HDR: usize = 12;
/// `HttpResponse` `[conn u16][stream u16][status u16][flags u8][ct_len u8][hdr_len u16][body_len u16]`
const RESP_HDR: usize = 12;

/// wave's `wire::method::METHOD_GET`.
const METHOD_GET: u8 = 1;
/// wave's `wire::method::METHOD_HEAD`.
const METHOD_HEAD: u8 = 4;

/// SEC1 uncompressed P-256 points are 65 bytes — the widest key stored.
const MAX_PUBKEY_LEN: usize = 65;
/// Longest `kid` carried.
const MAX_KID: usize = 64;

/// How many keys the set may hold at once.
///
/// A set exists to carry a rotation: the key being retired and the one
/// replacing it, and briefly a third while a third-party cache catches up.
/// Four is room for that and no room for a leak — a module that accumulated
/// every key it had ever seen would keep publishing one whose private half
/// was destroyed.
const MAX_KEYS: usize = 4;

/// WCET bound: requests answered per step.
const MAX_REQS_PER_STEP: usize = 4;

/// `[id f8]` — a device identifier to revoke.
///
/// A new message type rather than a reuse: a revocation is not a key and not
/// a mint, and giving it its own tag means a frame delivered to the wrong
/// channel is dropped rather than misread.
const MSG_REVOKE: u8 = 0x51;

/// Bitmap size in bits.
///
/// Bitmap size in bits: 2 KiB of bitmap.
///
/// Bounded by what one response can carry, not by what the filter would like.
/// The document must fit a single `HttpResponse` envelope — a larger body
/// needs `MORE_BODY` chunking, and a document that arrives in pieces needs a
/// resumption story for the client that fetches it. Base64 of 2 KiB is 2 731
/// characters and the JSON around it a couple of hundred more, which clears
/// the gateway's send buffer with room to spare.
///
/// That bound is not a limitation to work around: a document a client fetches
/// on every cold start should be small.
///
/// Sized here rather than configured, because the document's shape is what
/// clients parse and a deployment that could change it would change the
/// document under them.
const BITMAP_BITS: usize = 16_384;
const BITMAP_BYTES: usize = BITMAP_BITS / 8;

/// How many independent bit positions each identifier sets.
///
/// Three, derived from one SHA-256: the digest gives 32 bytes and each
/// position needs 17 bits, so one hash covers all three with room over. A
/// second hash call per insert would buy nothing.
const HASH_FUNCTIONS: u32 = 3;

/// The capacity the bitmap holds at roughly a 1% false-positive rate.
///
/// Reported in the document so a client can see what it is trusting, and
/// watched by `revocation_saturated`. A deployment revoking more than this
/// has outgrown a document fetched whole, and needs a distribution mechanism
/// rather than a bigger constant.
const CAPACITY: u32 = 1_000;

const MAX_REVOCATIONS_PER_STEP: usize = 16;
/// Longest device identifier accepted.
const MAX_ID: usize = 128;

/// One published key.
#[derive(Clone, Copy)]
struct PublishedKey {
    kid: [u8; MAX_KID],
    kid_len: u8,
    pubkey: [u8; MAX_PUBKEY_LEN],
    pubkey_len: u8,
    alg: u8,
    live: bool,
}

impl PublishedKey {
    const fn empty() -> Self {
        Self {
            kid: [0; MAX_KID],
            kid_len: 0,
            pubkey: [0; MAX_PUBKEY_LEN],
            pubkey_len: 0,
            alg: 0,
            live: false,
        }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,   // in[0]:  HttpRequest
    out_responses: i32, // out[0]: HttpResponse
    in_key: i32,        // in[1]:  MSG_VERIFY_KEY

    keys: [PublishedKey; MAX_KEYS],
    /// Where the next key lands once the set is full: oldest out first, so a
    /// rotation displaces the key it replaces rather than being refused.
    next_slot: usize,

    bitmap: [u8; BITMAP_BYTES],
    /// A per-deployment salt, so two issuers' documents cannot be compared
    /// to learn that they revoked the same device.
    salt: [u8; 8],
    inserted: u32,
    updated_at: u64,

    jwks_served: u32,
    jwks_empty: u32,
    jwks_not_found: u32,
    revocation_served: u32,
    revocation_recorded: u32,
    revocation_saturated: u32,

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
        s.out_responses = out_chan;
        s.in_key = dev_channel_port(sys, 0, 1);

        s.keys = [PublishedKey::empty(); MAX_KEYS];
        s.next_slot = 0;
        s.bitmap = [0; BITMAP_BYTES];
        s.salt = [0; 8];
        // A predictable salt would let two issuers' documents be compared; an
        // unavailable CSPRNG is not a reason to refuse to serve, so a zero
        // salt stands and the document is simply less private.
        let _ = (sys.provider_call)(-1, 0x0C3C, s.salt.as_mut_ptr(), 8);
        s.inserted = 0;
        s.updated_at = dev_unix_millis(sys) / 1000;
        s.jwks_served = 0;
        s.jwks_empty = 0;
        s.jwks_not_found = 0;
        s.revocation_served = 0;
        s.revocation_recorded = 0;
        s.revocation_saturated = 0;

        dev_log(sys, 3, b"[wellknown] init".as_ptr(), 16);
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

        // Keys first, so a same-step request sees the latest set.
        drain_keys(s, sys);

        let mut worked = false;
        for _ in 0..MAX_REQS_PER_STEP {
            if !chan::can_read(sys, s.in_requests) {
                break;
            }
            if !chan::can_write(sys, s.out_responses) {
                break;
            }
            // A raw envelope, not a typed message: wave's `http` writes the
            // HttpRequest with `channel_write`.
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

/// Take every MSG_VERIFY_KEY that has arrived.
///
/// A key whose `kid` is already published replaces it in place rather than
/// taking a second slot: re-announcing a key is how a deployment says "still
/// this one", and treating that as a new key would evict a live one.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn drain_keys(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_key < 0 {
        return;
    }
    for _ in 0..MAX_KEYS {
        if !chan::can_read(sys, s.in_key) {
            break;
        }
        let mut buf = [0u8; 256];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_key, &mut buf);
        if msg_type == MSG_REVOKE {
            // The same control channel carries both. Each is a typed frame
            // and each module takes its own type, which is what lets one
            // channel feed two concerns without either seeing the other's.
            record_revocation(s, sys, &buf[..plen as usize]);
            continue;
        }
        if msg_type != auth_wire::MSG_VERIFY_KEY {
            continue;
        }
        let mut r = PayloadReader::new(&buf[..plen as usize]);
        let (Ok(alg), Ok(kid), Ok(pubkey)) = (r.u8(), r.field8(), r.field8()) else {
            continue;
        };
        let valid = match alg {
            auth_wire::MINT_ALG_ES256 => pubkey.len() == 33 || pubkey.len() == 65,
            auth_wire::MINT_ALG_ED25519 => pubkey.len() == 32,
            _ => false,
        };
        if !valid || kid.len() > MAX_KID || pubkey.len() > MAX_PUBKEY_LEN {
            continue;
        }

        let slot = match s
            .keys
            .iter()
            .position(|k| k.live && &k.kid[..usize::from(k.kid_len)] == kid)
        {
            Some(existing) => existing,
            None => {
                let free = s.keys.iter().position(|k| !k.live);
                free.unwrap_or_else(|| {
                    let at = s.next_slot % MAX_KEYS;
                    s.next_slot = at + 1;
                    at
                })
            }
        };

        let mut key = PublishedKey::empty();
        key.kid[..kid.len()].copy_from_slice(kid);
        key.pubkey[..pubkey.len()].copy_from_slice(pubkey);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "both lengths are bounded above"
        )]
        {
            key.kid_len = kid.len() as u8;
            key.pubkey_len = pubkey.len() as u8;
        }
        key.alg = alg;
        key.live = true;
        s.keys[slot] = key;
    }
}

/// Record one MSG_REVOKE frame (`[id f8]`).
///
/// # Safety
///
/// As `drain_keys`.
unsafe fn record_revocation(s: &mut ModuleState, sys: &SyscallTable, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    let len = usize::from(payload[0]);
    if len == 0 || len + 1 > payload.len() || len > MAX_ID {
        return;
    }
    let mut id = [0u8; MAX_ID];
    id[..len].copy_from_slice(&payload[1..=len]);
    insert(s, &id[..len]);
    s.updated_at = dev_unix_millis(sys) / 1000;
    s.revocation_recorded = s.revocation_recorded.saturating_add(1);
    s.inserted = s.inserted.saturating_add(1);
    if s.inserted > CAPACITY {
        // Past capacity the false-positive rate climbs past what the document
        // claims. Counted rather than refused: dropping a revocation would be
        // the unsafe direction.
        s.revocation_saturated = s.revocation_saturated.saturating_add(1);
    }
}

/// Set this identifier's bits.
fn insert(s: &mut ModuleState, id: &[u8]) {
    for bit in positions(&s.salt, id) {
        s.bitmap[bit / 8] |= 1 << (bit % 8);
    }
}

/// The bit positions an identifier occupies.
///
/// One salted SHA-256, sliced into three 17-bit windows. Salting is what
/// stops the same identifier producing the same positions at two issuers.
fn positions(salt: &[u8; 8], id: &[u8]) -> [usize; HASH_FUNCTIONS as usize] {
    let mut input = [0u8; 8 + MAX_ID];
    input[..8].copy_from_slice(salt);
    let len = id.len().min(MAX_ID);
    input[8..8 + len].copy_from_slice(&id[..len]);
    let digest = sha256(&input[..8 + len]);

    let mut out = [0usize; HASH_FUNCTIONS as usize];
    for (index, slot) in out.iter_mut().enumerate() {
        let at = index * 4;
        let word = u32::from_le_bytes([digest[at], digest[at + 1], digest[at + 2], digest[at + 3]]);
        *slot = (word as usize) % BITMAP_BITS;
    }
    out
}

/// Write the response envelope and the document into `s.out`, and send it.
///
/// Returns whether it fitted.
///
/// # Safety
///
/// As `drain_revocations`.
unsafe fn serve_document(s: &mut ModuleState, sys: &SyscallTable, conn: u16, stream: u16) -> bool {
    const CT: &[u8] = b"application/json";
    let body_at = RESP_HDR + CT.len();
    // The bitmap is read while the envelope around it is written, so it is
    // copied out first: one borrow of `s` at a time.
    let bitmap = s.bitmap;
    let salt = s.salt;
    let inserted = s.inserted;
    let updated_at = s.updated_at;

    let Some(body_len) =
        write_document(&bitmap, &salt, inserted, updated_at, &mut s.out[body_at..])
    else {
        return false;
    };
    let total = body_at + body_len;

    s.out[0..2].copy_from_slice(&conn.to_le_bytes());
    s.out[2..4].copy_from_slice(&stream.to_le_bytes());
    s.out[4..6].copy_from_slice(&200u16.to_le_bytes());
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
        reason = "bounded by the buffer `write_document` wrote into"
    )]
    {
        s.out[10..12].copy_from_slice(&(body_len as u16).to_le_bytes());
    }
    s.out[RESP_HDR..body_at].copy_from_slice(CT);

    (sys.channel_write)(s.out_responses, s.out.as_ptr(), total);
    true
}

/// The document, in the shape a client parses.
fn write_document(
    bitmap: &[u8; BITMAP_BYTES],
    salt: &[u8; 8],
    inserted: u32,
    updated_at: u64,
    out: &mut [u8],
) -> Option<usize> {
    let mut at = 0usize;
    put(out, &mut at, br#"{"bitmap":""#)?;
    let written = b64::encode(bitmap, &mut out[at..])?;
    at += written;
    put(out, &mut at, br#"","bitmap_bits":"#)?;
    put_u64(out, &mut at, BITMAP_BITS as u64)?;
    put(out, &mut at, br#","capacity":"#)?;
    put_u64(out, &mut at, u64::from(CAPACITY))?;
    put(out, &mut at, br#","hash_functions":"#)?;
    put_u64(out, &mut at, u64::from(HASH_FUNCTIONS))?;
    put(out, &mut at, br#","inserted":"#)?;
    put_u64(out, &mut at, u64::from(inserted))?;
    put(out, &mut at, br#","salt":""#)?;
    let mut encoded = [0u8; 16];
    let n = b64::encode(salt, &mut encoded)?;
    put(out, &mut at, &encoded[..n])?;
    put(out, &mut at, br#"","updated_at":"#)?;
    put_u64(out, &mut at, updated_at)?;
    put(out, &mut at, b"}")?;
    Some(at)
}

/// Answer one `HttpRequest`.
///
/// # Safety
///
/// As `drain_keys`.
unsafe fn handle_request(s: &mut ModuleState, sys: &SyscallTable, plen: usize) {
    if plen < REQ_HDR {
        return;
    }
    let conn = u16::from_le_bytes([s.buf[0], s.buf[1]]);
    let stream = u16::from_le_bytes([s.buf[2], s.buf[3]]);
    let method = s.buf[4];
    let path_len = u16::from_le_bytes([s.buf[6], s.buf[7]]) as usize;
    let Some(path_end) = REQ_HDR.checked_add(path_len) else {
        return;
    };
    if path_end > plen {
        return;
    }

    let revocations = {
        let path = &s.buf[REQ_HDR..path_end];
        path == b"/.well-known/revocations.json"
    };
    let known_path = {
        let path = &s.buf[REQ_HDR..path_end];
        path == b"/jwks" || path == b"/.well-known/jwks.json"
    };
    if revocations {
        if method != METHOD_GET && method != METHOD_HEAD {
            respond(s, sys, conn, stream, 405, b"application/json", b"{}");
            return;
        }
        if serve_document(s, sys, conn, stream) {
            s.revocation_served = s.revocation_served.saturating_add(1);
        } else {
            respond(s, sys, conn, stream, 500, b"application/json", b"{}");
        }
        return;
    }
    if !known_path {
        s.jwks_not_found = s.jwks_not_found.saturating_add(1);
        respond(s, sys, conn, stream, 404, b"application/json", b"{}");
        return;
    }
    if method != METHOD_GET && method != METHOD_HEAD {
        respond(s, sys, conn, stream, 405, b"application/json", b"{}");
        return;
    }

    let mut body = [0u8; abi::CHANNEL_BUFFER_SIZE / 2];
    let Some(len) = write_jwks(s, &mut body) else {
        // The set outgrew the buffer. Serving a truncated one would publish
        // JSON that parses into fewer keys than the issuer signs with, and a
        // relying party would reject tokens it should accept.
        respond(s, sys, conn, stream, 500, b"application/json", b"{}");
        return;
    };
    if s.keys.iter().all(|key| !key.live) {
        s.jwks_empty = s.jwks_empty.saturating_add(1);
    } else {
        s.jwks_served = s.jwks_served.saturating_add(1);
    }
    respond(
        s,
        sys,
        conn,
        stream,
        200,
        b"application/jwk-set+json",
        &body[..len],
    );
}

/// `{"keys":[…]}` over every live key.
fn write_jwks(s: &ModuleState, out: &mut [u8]) -> Option<usize> {
    let mut at = 0usize;
    put(out, &mut at, br#"{"keys":["#)?;
    let mut first = true;
    for key in s.keys.iter().filter(|key| key.live) {
        if !first {
            put(out, &mut at, b",")?;
        }
        first = false;
        let mut canonical = [0u8; jwk::MAX_CANONICAL];
        let n = write_key(key, &mut canonical)?;
        put(out, &mut at, &canonical[..n])?;
    }
    put(out, &mut at, b"]}")?;
    Some(at)
}

/// One key as a JWK.
///
/// Built through `JwkRecord`, which is the same type the thumbprint is taken
/// over. A second spelling here would publish a key whose `kid` a relying
/// party could compute a different thumbprint from.
fn write_key(key: &PublishedKey, out: &mut [u8]) -> Option<usize> {
    let mut record = jwk::JwkRecord::new();
    record.kid = jwk::Field::set(&key.kid[..usize::from(key.kid_len)]).ok()?;
    let pubkey = &key.pubkey[..usize::from(key.pubkey_len)];
    match key.alg {
        auth_wire::MINT_ALG_ED25519 => {
            record.kty = jwk::Field::set(b"OKP").ok()?;
            record.crv = jwk::Field::set(b"Ed25519").ok()?;
            record.alg = jwk::Field::set(b"EdDSA").ok()?;
            let mut x = [0u8; 64];
            let n = b64::encode(pubkey, &mut x)?;
            record.x = jwk::Field::set(&x[..n]).ok()?;
        }
        auth_wire::MINT_ALG_ES256 => {
            record.kty = jwk::Field::set(b"EC").ok()?;
            record.crv = jwk::Field::set(b"P-256").ok()?;
            record.alg = jwk::Field::set(b"ES256").ok()?;
            // Only the uncompressed SEC1 point carries both coordinates. A
            // compressed one would need the curve arithmetic to recover Y,
            // which is not this module's work — it is refused instead, so a
            // deployment finds out at publication rather than at the first
            // verification.
            if pubkey.len() != 65 || pubkey[0] != 0x04 {
                return None;
            }
            let mut coord = [0u8; 64];
            let n = b64::encode(&pubkey[1..33], &mut coord)?;
            record.x = jwk::Field::set(&coord[..n]).ok()?;
            let n = b64::encode(&pubkey[33..65], &mut coord)?;
            record.y = jwk::Field::set(&coord[..n]).ok()?;
        }
        _ => return None,
    }
    record.canonical_json(out).ok()
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

/// Emit one `HttpResponse`.
///
/// # Safety
///
/// As `drain_keys`.
unsafe fn respond(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    status: u16,
    content_type: &[u8],
    body: &[u8],
) {
    let total = RESP_HDR + content_type.len() + body.len();
    if total > s.out.len() {
        return;
    }
    s.out[0..2].copy_from_slice(&conn.to_le_bytes());
    s.out[2..4].copy_from_slice(&stream.to_le_bytes());
    s.out[4..6].copy_from_slice(&status.to_le_bytes());
    s.out[6] = 0;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "content types here are short literals"
    )]
    {
        s.out[7] = content_type.len() as u8;
    }
    s.out[8..10].copy_from_slice(&0u16.to_le_bytes());
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by the `total > s.out.len()` check above"
    )]
    {
        s.out[10..12].copy_from_slice(&(body.len() as u16).to_le_bytes());
    }
    s.out[RESP_HDR..RESP_HDR + content_type.len()].copy_from_slice(content_type);
    s.out[RESP_HDR + content_type.len()..total].copy_from_slice(body);

    (sys.channel_write)(s.out_responses, s.out.as_ptr(), total);
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

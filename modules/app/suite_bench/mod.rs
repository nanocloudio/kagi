//! Suite bench — the step-cost instrument.
//!
//! Every WCET constant in this tree is a statement about how long a
//! credential operation takes on the hardware that runs it, and this module
//! is where that statement is measured rather than assumed. It does one
//! operation per step — a vault SIGN, an in-module verify, or the SHA-256 a
//! thumbprint costs — timed with the monotonic microsecond clock, for every
//! implemented suite in turn, and reports each window of samples as a
//! RECURRING beat on telemetry. `docs/performance/step-costs.md` is the
//! table it fills. Beats, never one-shot lines: a one-shot log
//! does not survive the UDP telemetry attach.
//!
//! One operation per step is the design, not a convenience: the step guard
//! bounds a STEP, so an operation that outruns the deadline shows up here as
//! this module being the thing the guard kills — on the graph's declared
//! `step_deadline_us`, which the bench graph sets high precisely so the
//! measurement can exist. The numbers then say what the production graphs
//! may declare.
//!
//! Beat shape, one line per completed window:
//!
//!   [bench] s=<suite> op=<sign|vrfy|hash> n=<samples> min= avg= max=  (µs)
//!
//! A suite whose vault key will not open is retried once per cycle and
//! beats its outcome instead, every cycle — absence that recurs, not
//! absence that scrolls off:
//!
//!   [bench] s=<suite> open=fail rc=-<errno>
//!   [bench] s=<suite> open=recovered tries=<n>

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
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha3.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/ml_dsa.rs");
include!("../../common/sdk_bridge.rs");

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/issuer_key.rs"]
mod issuer_key;

#[path = "../../../target/fluxor/fluxor-abi/sdk/contracts/key_vault.rs"]
mod key_vault;

/// The suites measured, in rotation order — every implemented singleton.
/// The hybrid signs as its two halves, so it is priced by addition.
const SUITES: [u16; 5] = [
    auth_wire::suite::ES256,
    auth_wire::suite::ED25519,
    auth_wire::suite::ML_DSA_44,
    auth_wire::suite::ML_DSA_65,
    auth_wire::suite::ML_DSA_87,
];

/// Samples per (suite, op) window. Small enough that every window recurs
/// well inside a rig scenario's observation span; large enough that min
/// and max mean something.
const WINDOW: u32 = 16;

/// Visits between two retry-and-beat attempts of the same dead suite.
/// A dead suite is visited once per rotation cycle (seconds at the bench
/// tick with live suites measuring), so every visit is already a walking
/// pace the transport survives.
const DEAD_BEAT_EVERY: u32 = 32;

/// Ops per suite.
const OP_SIGN: u8 = 0;
const OP_VERIFY: u8 = 1;
const OP_HASH: u8 = 2;
const OPS: u8 = 3;

/// The fixed message every suite signs — 64 bytes, the size of a JOSE
/// signing input's digest neighbourhood rather than of a whole token; the
/// point is comparability across suites, not realism of payload.
const MSG: &[u8; 64] = b"kagi suite-bench: one fixed message, sixty-four bytes, measured.";

#[repr(C)]
struct Stats {
    n: u32,
    min_us: u32,
    max_us: u32,
    sum_us: u64,
}

impl Stats {
    const fn zero() -> Self {
        Self {
            n: 0,
            min_us: u32::MAX,
            max_us: 0,
            sum_us: 0,
        }
    }
    fn record(&mut self, us: u32) {
        self.n += 1;
        self.sum_us += u64::from(us);
        if us < self.min_us {
            self.min_us = us;
        }
        if us > self.max_us {
            self.max_us = us;
        }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    out_tick: i32,

    keys: [issuer_key::IssuerKey; SUITES.len()],
    open_ok: [bool; SUITES.len()],
    /// The raw OPEN_OR_GENERATE rc per suite when open failed, so the
    /// recurring fail beat names the errno instead of a bare fact.
    open_rc: [i32; SUITES.len()],
    /// Open attempts per suite, so a recovery beat can say how many tries
    /// the cold-boot transient cost.
    open_tries: [u32; SUITES.len()],
    /// Dead-suite beats are throttled to one per `DEAD_BEAT_EVERY` visits:
    /// an unthrottled fail beat per step floods the debug-to-net transport
    /// (observed as `log_net: dropped` and truncated lines) and the drops
    /// eat the very diagnosis the beat carries.
    dead_visits: [u32; SUITES.len()],

    /// Rotation position.
    suite_idx: usize,
    op: u8,
    window: Stats,

    /// The last signature, verified by the next OP_VERIFY step.
    sig: [u8; auth_wire::suite::MAX_IMPLEMENTED_SIGNATURE_LEN],
    sig_len: u16,

    /// Vault SIGN scratch: header + message + widest signature.
    scratch: [u8; issuer_key::SIGN_SCRATCH_OVERHEAD
        + MSG.len()
        + auth_wire::suite::MAX_IMPLEMENTED_SIGNATURE_LEN],

    // Metrics (names mirror manifest [observability]).
    ops_done: u32,
    sign_failures: u32,
    verify_failures: u32,
    beats: u32,
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
    _in_chan: i32,
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
        s.out_tick = out_chan;

        s.keys = [issuer_key::IssuerKey::empty(); SUITES.len()];
        s.open_ok = [false; SUITES.len()];
        // One labelled key per suite, generated in whatever vault backend
        // this platform runs. Opening at construction keeps generation cost
        // out of the step measurements.
        s.open_rc = [0; SUITES.len()];
        s.dead_visits = [0; SUITES.len()];
        s.open_tries = [1; SUITES.len()];
        for (i, &suite) in SUITES.iter().enumerate() {
            let mut label = *b"bench-s0";
            label[7] += suite as u8;
            s.open_ok[i] = s.keys[i].open(sys, suite, &label);
            if !s.open_ok[i] {
                // Repeat the raw call to capture the rc the wrapper folds
                // into a bool. Diagnostic only; the slot stays closed.
                s.open_rc[i] = raw_open_rc(sys, suite, &label);
                dev_log(sys, 2, b"[bench] open failed for a suite".as_ptr(), 31);
            }
        }

        s.suite_idx = 0;
        s.op = OP_SIGN;
        s.window = Stats::zero();
        s.sig_len = 0;
        s.ops_done = 0;
        s.sign_failures = 0;
        s.verify_failures = 0;
        s.beats = 0;
        dev_log(sys, 3, b"[bench] up".as_ptr(), 10);
        0
    }
}

/// Raw OPEN_OR_GENERATE, returning the provider rc — the diagnostic the
/// bool wrapper cannot give. Mirrors `issuer_key::open`'s encoding.
///
/// # Safety
///
/// Caller supplies a valid syscall table per the module ABI.
unsafe fn raw_open_rc(sys: &SyscallTable, suite: u16, label: &[u8]) -> i32 {
    const USAGE: u32 =
        key_vault::usage::SIGN | key_vault::usage::EXPORT_PUBLIC | key_vault::usage::PERSIST;
    let vault = match suite {
        auth_wire::suite::ES256 => key_vault::suite::P256,
        auth_wire::suite::ED25519 => key_vault::suite::ED25519,
        auth_wire::suite::ML_DSA_44 => key_vault::suite::ML_DSA_44,
        auth_wire::suite::ML_DSA_65 => key_vault::suite::ML_DSA_65,
        auth_wire::suite::ML_DSA_87 => key_vault::suite::ML_DSA_87,
        _ => return -999,
    };
    let mut pub_out = [0u8; issuer_key::MAX_ISSUER_PUBKEY];
    let mut arg = [0u8; 8 + 32 + 12];
    arg[0..2].copy_from_slice(&vault.to_le_bytes());
    arg[2..6].copy_from_slice(&USAGE.to_le_bytes());
    arg[6] = 0;
    arg[7] = label.len() as u8;
    arg[8..8 + label.len()].copy_from_slice(label);
    let tail = 8 + label.len();
    arg[tail..tail + 8].copy_from_slice(&(pub_out.as_mut_ptr() as u64).to_le_bytes());
    arg[tail + 8..tail + 10].copy_from_slice(&(issuer_key::MAX_ISSUER_PUBKEY as u16).to_le_bytes());
    arg[tail + 10..tail + 12].copy_from_slice(&0u16.to_le_bytes());
    let rc = (sys.provider_call)(-1, key_vault::OPEN_OR_GENERATE, arg.as_mut_ptr(), tail + 12);
    if rc >= 0 {
        // The diagnostic retry SUCCEEDED where the wrapper failed — a
        // transient. Close the handle so the probe cannot leak a vault
        // slot; the step-side retry will reopen it properly.
        let _ = (sys.provider_call)(rc, key_vault::DESTROY, core::ptr::null_mut(), 0);
    }
    rc
}

/// Append a labelled decimal to a beat line.
///
/// # Safety
///
/// `buf` must have room for the label and up to 10 digits at `at`.
unsafe fn put(buf: &mut [u8], at: &mut usize, label: &[u8], val: u32) {
    buf[*at..*at + label.len()].copy_from_slice(label);
    *at += label.len();
    *at += fmt_u32_raw(buf.as_mut_ptr().add(*at), val);
}

/// Emit the completed window as one beat line and reset it.
///
/// # Safety
///
/// Caller holds `&mut ModuleState` and a valid syscall table per the ABI.
unsafe fn emit_beat(s: &mut ModuleState, sys: &SyscallTable) {
    let suite = SUITES[s.suite_idx];
    let op: &[u8] = match s.op {
        OP_SIGN => b" op=sign",
        OP_VERIFY => b" op=vrfy",
        _ => b" op=hash",
    };
    let mut line = [0u8; 96];
    let mut at = 0usize;
    put(&mut line, &mut at, b"[bench] s=", u32::from(suite));
    line[at..at + op.len()].copy_from_slice(op);
    at += op.len();
    put(&mut line, &mut at, b" n=", s.window.n);
    if s.window.n > 0 {
        let avg = (s.window.sum_us / u64::from(s.window.n)) as u32;
        put(&mut line, &mut at, b" min=", s.window.min_us);
        put(&mut line, &mut at, b" avg=", avg);
        put(&mut line, &mut at, b" max=", s.window.max_us);
    }
    dev_log(sys, 3, line.as_ptr(), at);
    s.beats = s.beats.saturating_add(1);
    // The port write is a liveness pulse for the scheduler, not data.
    let pulse = [0x42u8];
    (sys.channel_write)(s.out_tick, pulse.as_ptr(), 1);
    s.window = Stats::zero();
}

/// Advance the rotation: next op, then next suite.
fn advance(s: &mut ModuleState) {
    s.op += 1;
    if s.op >= OPS {
        s.op = OP_SIGN;
        s.suite_idx = (s.suite_idx + 1) % SUITES.len();
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: per the module ABI, `state` is valid and exclusively borrowed,
    // and the syscall table it holds reaches live kernel routines.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // Once per rotation through suite 0: the platform probe beat,
        // discriminating WHERE an open failure lives. `rng` is the CSPRNG
        // provider (the salt call wellknown makes); `tier` is the vault's
        // own answer. A vault that answers TIER but cannot OPEN, next to a
        // failing RNG, is a platform-entropy defect; next to a healthy RNG
        // it is the vault's own keygen/public path.
        if s.suite_idx == 0 && s.op == OP_SIGN {
            let mut rng_buf = [0u8; 64];
            let rng_rc = (sys.provider_call)(-1, 0x0C3C, rng_buf.as_mut_ptr(), 8);
            let rng32_rc = (sys.provider_call)(-1, 0x0C3C, rng_buf.as_mut_ptr(), 32);
            let mut tier_buf = [0u8; 4];
            let tier_rc =
                (sys.provider_call)(-1, key_vault::TIER, tier_buf.as_mut_ptr(), tier_buf.len());
            let mut line = [0u8; 64];
            let mut at = 0usize;
            line[..12].copy_from_slice(b"[bench] rng=");
            at += 12;
            at += fmt_u32_raw(line.as_mut_ptr().add(at), rng_rc.unsigned_abs());
            if rng_rc < 0 {
                line[at] = b'-';
                at += 1;
            }
            put(&mut line, &mut at, b" rng32=", rng32_rc.unsigned_abs());
            if rng32_rc < 0 {
                line[at] = b'-';
                at += 1;
            }
            put(&mut line, &mut at, b" tierrc=", tier_rc.unsigned_abs());
            put(&mut line, &mut at, b" tier=", u32::from(tier_buf[0]));
            dev_log(sys, 3, line.as_ptr(), at);
        }

        let i = s.suite_idx;
        let suite = SUITES[i];
        if !s.open_ok[i] {
            // A dead suite still recurs, so its absence cannot scroll off —
            // and it RETRIES at the same walking pace, because the first
            // on-silicon runs showed vault opens failing nondeterministically
            // at cold boot (rc=-1, a different suite each boot). Whether a
            // retry recovers is itself a measurement: a transient means any
            // issuer module refusing construction on a failed open would
            // refuse a whole boot for a warm-up condition. (`% EVERY == 0`
            // post-increment — an earlier `== 1` spelling never fired at
            // EVERY=1, x % 1 being always 0, and silenced two rig runs.)
            s.dead_visits[i] = s.dead_visits[i].wrapping_add(1);
            if s.dead_visits[i].is_multiple_of(DEAD_BEAT_EVERY) {
                let mut label = *b"bench-s0";
                label[7] += suite as u8;
                s.open_ok[i] = s.keys[i].open(sys, suite, &label);
                s.open_tries[i] = s.open_tries[i].saturating_add(1);
                let mut line = [0u8; 64];
                let mut at = 0usize;
                put(&mut line, &mut at, b"[bench] s=", u32::from(suite));
                if s.open_ok[i] {
                    line[at..at + 15].copy_from_slice(b" open=recovered");
                    at += 15;
                    put(&mut line, &mut at, b" tries=", s.open_tries[i]);
                } else {
                    s.open_rc[i] = raw_open_rc(sys, suite, &label);
                    line[at..at + 10].copy_from_slice(b" open=fail");
                    at += 10;
                    let rc = s.open_rc[i];
                    put(&mut line, &mut at, b" rc=-", rc.unsigned_abs());
                }
                dev_log(sys, 2, line.as_ptr(), at);
            }
            s.suite_idx = (s.suite_idx + 1) % SUITES.len();
            s.op = OP_SIGN;
            return 0;
        }

        // ECDSA signs a DIGEST — the vault's sign_mode for ES256 — so the
        // input handed to it must be the 32-byte hash, exactly as
        // token_mint hashes its signing input before the vault call. The
        // hash cost is priced separately by OP_HASH.
        let es256_digest = sha256(MSG);
        let sign_input: &[u8] = if suite == auth_wire::suite::ES256 {
            &es256_digest
        } else {
            MSG
        };

        let t0 = dev_micros(sys);
        let ok = match s.op {
            OP_SIGN => match s.keys[i].sign(sys, &mut s.scratch, sign_input, &mut s.sig) {
                Some(n) => {
                    s.sig_len = n as u16;
                    true
                }
                None => {
                    s.sign_failures = s.sign_failures.saturating_add(1);
                    false
                }
            },
            OP_VERIFY => {
                let sig = &s.sig[..usize::from(s.sig_len)];
                let pk = s.keys[i].public_key();
                let verified = !sig.is_empty()
                    && match suite {
                        auth_wire::suite::ES256 => ecdsa_verify(pk, &es256_digest, sig),
                        auth_wire::suite::ED25519 => ed25519_verify_slice(pk, MSG, sig),
                        _ => ml_dsa_verify_suite(suite, pk, MSG, sig),
                    };
                if !verified {
                    s.verify_failures = s.verify_failures.saturating_add(1);
                }
                verified
            }
            _ => {
                // What a thumbprint costs: one SHA-256 over the public key.
                let _ = sha256(s.keys[i].public_key());
                true
            }
        };
        let t1 = dev_micros(sys);

        if ok {
            s.ops_done = s.ops_done.saturating_add(1);
            s.window.record(t1.saturating_sub(t0) as u32);
        }
        if s.window.n >= WINDOW || !ok {
            emit_beat(s, sys);
            advance(s);
        }
        0
    }
}

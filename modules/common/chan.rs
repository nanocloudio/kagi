//! Channel I/O wrappers over fluxor's `SyscallTable`.
//!
//! PIC-only companion to `auth_wire.rs`. A host mount takes only the pure
//! no_std surface (`auth_wire.rs` constants and codecs); the wrappers in
//! this file touch `SyscallTable`, which exists only on target, so they
//! are a separate file rather than a `cfg` inside one. Each app module
//! mounts both side by side:
//!
//! ```ignore
//! #[path = "../../common/auth_wire.rs"]
//! mod auth_wire;
//! #[path = "../../common/chan.rs"]
//! mod chan;
//! ```
//!
//! Function bodies reference the envelope layout from
//! `crate::auth_wire` (`[msg_type: u8][len: u16 LE][payload]`), which
//! resolves because every consumer mounts `auth_wire.rs` at the crate
//! root as `mod auth_wire`.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::auth_wire::{ENVELOPE, MAX_PAYLOAD};

/// `channel_poll` event bits (mirror `runtime.rs::POLL_IN/POLL_OUT`;
/// duplicated here so this fragment doesn't depend on `runtime.rs`
/// having been `include!`'d before it).
const EV_READABLE: u32 = 0x01;
const EV_WRITABLE: u32 = 0x02;

/// True when `chan` has at least one readable byte pending.
///
/// # Safety
/// `sys` must point to a valid SyscallTable. `chan` must be a valid handle.
#[inline]
pub unsafe fn can_read(sys: &crate::abi::SyscallTable, chan: i32) -> bool {
    if chan < 0 {
        return false;
    }
    let poll = (sys.channel_poll)(chan, EV_READABLE);
    poll > 0 && (poll as u32 & EV_READABLE) != 0
}

/// True when `chan` has room for a write.
///
/// # Safety
/// `sys` must point to a valid SyscallTable. `chan` must be a valid handle.
#[inline]
pub unsafe fn can_write(sys: &crate::abi::SyscallTable, chan: i32) -> bool {
    if chan < 0 {
        return false;
    }
    let poll = (sys.channel_poll)(chan, EV_WRITABLE);
    poll > 0 && (poll as u32 & EV_WRITABLE) != 0
}

/// Write a complete envelope (header + payload) into a channel as ONE
/// `channel_write`. Returns bytes written (`ENVELOPE + payload.len()`)
/// on success, 0 when the frame did not fit, or a negative errno.
///
/// Why one write, not two: fluxor FIFO channels are byte rings whose
/// `channel_write` is all-or-nothing. Writing the header and payload as
/// two calls tears a frame whenever the ring has room for the header
/// but not the payload, desyncing every subsequent frame. A single
/// combined write is atomic against that limit.
///
/// # Safety
/// `sys` must point to a valid SyscallTable. `chan` must be a valid channel handle.
#[inline]
pub unsafe fn channel_write_msg(
    sys: &crate::abi::SyscallTable,
    chan: i32,
    msg_type: u8,
    payload: &[u8],
) -> i32 {
    if payload.len() > MAX_PAYLOAD {
        return -1;
    }
    let total = ENVELOPE + payload.len();
    // The channel ring caps at CHANNEL_BUFFER_SIZE; a larger frame can
    // never be delivered. Reject up front rather than half-write.
    if total > crate::abi::CHANNEL_BUFFER_SIZE {
        return -1;
    }
    let mut buf = [0u8; crate::abi::CHANNEL_BUFFER_SIZE];
    buf[0] = msg_type;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by MAX_PAYLOAD (u16::MAX) above"
    )]
    let len = payload.len() as u16;
    buf[1..3].copy_from_slice(&len.to_le_bytes());
    buf[ENVELOPE..total].copy_from_slice(payload);
    let w = (sys.channel_write)(chan, buf.as_ptr(), total);
    // Compare SIGNED: a negative errno cast to usize would read as a
    // huge success. Anything that didn't fully land is a failure; pass
    // negative errnos through so callers can tell full-vs-error.
    if w < total as i32 {
        return if w < 0 { w } else { 0 };
    }
    total as i32
}

/// Read a complete envelope (header + payload) from a channel into `buf`.
/// The header is consumed but NOT stored in buf — only the payload is
/// placed at `buf[0..payload_len]`. Returns `(msg_type, payload_len)` on
/// success, or `(0, 0)` if no data is available or `buf` is too small
/// (oversized payloads are drained and discarded so the channel doesn't
/// desync).
///
/// # Safety
/// `sys` must point to a valid SyscallTable. `chan` must be a valid channel handle.
#[inline]
pub unsafe fn channel_read_msg(
    sys: &crate::abi::SyscallTable,
    chan: i32,
    buf: &mut [u8],
) -> (u8, u16) {
    let mut hdr = [0u8; ENVELOPE];
    let n = (sys.channel_read)(chan, hdr.as_mut_ptr(), ENVELOPE);
    if n < ENVELOPE as i32 {
        return (0, 0);
    }

    let msg_type = hdr[0];
    let payload_len = u16::from_le_bytes([hdr[1], hdr[2]]);
    let plen = payload_len as usize;

    if plen == 0 {
        return (msg_type, 0);
    }

    if plen > buf.len() {
        // Payload too large for buffer — drain and discard.
        let mut discard = [0u8; 256];
        let mut remaining = plen;
        while remaining > 0 {
            let chunk = remaining.min(256);
            let r = (sys.channel_read)(chan, discard.as_mut_ptr(), chunk);
            if r <= 0 {
                break;
            }
            remaining -= r as usize;
        }
        return (0, 0);
    }

    let n2 = (sys.channel_read)(chan, buf.as_mut_ptr(), plen);
    if (n2 as usize) < plen {
        return (0, 0);
    }

    (msg_type, payload_len)
}

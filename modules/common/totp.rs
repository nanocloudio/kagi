//! HOTP (RFC 4226) and TOTP (RFC 6238) — the authenticator-app factor.
//!
//! Pure `no_std` fragment; the HMAC primitive is injected by the consumer
//! (PIC modules: the fluxor SDK's `crypto/hmac.rs`; the host suites: the
//! `hmac`/`sha1`/`sha2` crates). The algorithm itself is deterministic
//! integer arithmetic, so both agree byte for byte on every code.
//!
//! Two independent pieces live here:
//!
//! - **Code derivation** — `hotp` (counter-based) and `totp` (time-based,
//!   `counter = (unix_seconds - t0) / period`), plus `verify_totp`, which
//!   sweeps a skew window and reports the matching counter so the caller can
//!   enforce single-use.
//! - **Base32** (RFC 4648, unpadded, uppercase) — the encoding every
//!   authenticator app expects for a shared secret, used to build the
//!   `otpauth://totp/...` provisioning URI.
//!
//! The shared secret is never held here: the caller unseals it from a
//! `secret_record` envelope, passes the bytes in, and drops them.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

/// Largest HMAC output the fragment buffers (SHA-512 would be 64; kagi mints
/// SHA-1/SHA-256 only, but the buffer costs nothing).
pub const MAX_MAC: usize = 64;

/// Longest shared secret accepted. RFC 4226 recommends 160 bits; 64 bytes
/// covers SHA-256 secrets and any authenticator app's output.
pub const MAX_SECRET: usize = 64;

/// Digits an OTP may carry. Six is universal; eight is the common upgrade.
pub const MIN_DIGITS: u8 = 6;
pub const MAX_DIGITS: u8 = 8;

/// Default TOTP step, in seconds (RFC 6238 §4).
pub const DEFAULT_PERIOD: u64 = 30;

/// HMAC primitive injected by the consumer: `(key, message, out) -> mac_len`.
/// `out` is at least `MAX_MAC` bytes; the implementation writes its full
/// digest and returns how many bytes it wrote. The hash choice is baked into
/// the function pointer, so a caller wiring `HMAC-SHA1` and one wiring
/// `HMAC-SHA256` use the same fragment code.
pub type HmacFn = fn(&[u8], &[u8], &mut [u8]) -> usize;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TotpError {
    /// Secret was empty or longer than [`MAX_SECRET`].
    BadSecret,
    /// `digits` outside [`MIN_DIGITS`]..=[`MAX_DIGITS`].
    BadDigits,
    /// `period` was zero.
    BadPeriod,
    /// The injected HMAC returned a digest shorter than the 4 bytes dynamic
    /// truncation needs (or longer than [`MAX_MAC`]).
    BadMac,
    /// Output buffer too small.
    BufferTooSmall,
    /// Input was not valid unpadded RFC 4648 base32.
    BadBase32,
}

/// Powers of ten for the truncation modulus. Indexed by `digits`, so the
/// table covers 0..=8 and is looked up by a `match` rather than a stored
/// slice — the same PIC-safety reason `jose.rs` avoids pointer tables.
const fn pow10(digits: u8) -> u32 {
    match digits {
        6 => 1_000_000,
        7 => 10_000_000,
        _ => 100_000_000,
    }
}

/// RFC 4226 HOTP. Returns the OTP as an integer in `0..10^digits`; render it
/// zero-padded to `digits` characters with [`format_code`].
pub fn hotp(hmac: HmacFn, secret: &[u8], counter: u64, digits: u8) -> Result<u32, TotpError> {
    if secret.is_empty() || secret.len() > MAX_SECRET {
        return Err(TotpError::BadSecret);
    }
    if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        return Err(TotpError::BadDigits);
    }

    // RFC 4226 §5.1: the moving factor is the counter, big-endian, 8 bytes.
    let message = counter.to_be_bytes();
    let mut mac = [0u8; MAX_MAC];
    let mac_len = hmac(secret, &message, &mut mac);
    if !(4..=MAX_MAC).contains(&mac_len) {
        return Err(TotpError::BadMac);
    }

    // RFC 4226 §5.3 dynamic truncation: the low nibble of the last byte
    // selects a 4-byte window, whose top bit is masked off.
    let offset = (mac[mac_len - 1] & 0x0f) as usize;
    let binary = (u32::from(mac[offset] & 0x7f) << 24)
        | (u32::from(mac[offset + 1]) << 16)
        | (u32::from(mac[offset + 2]) << 8)
        | u32::from(mac[offset + 3]);

    Ok(binary % pow10(digits))
}

/// The TOTP counter for `unix_seconds` (RFC 6238 §4.2). `t0` is the epoch
/// offset, conventionally 0.
pub fn counter_at(unix_seconds: u64, t0: u64, period: u64) -> Result<u64, TotpError> {
    if period == 0 {
        return Err(TotpError::BadPeriod);
    }
    Ok(unix_seconds.saturating_sub(t0) / period)
}

/// RFC 6238 TOTP for the step containing `unix_seconds`.
pub fn totp(
    hmac: HmacFn,
    secret: &[u8],
    unix_seconds: u64,
    t0: u64,
    period: u64,
    digits: u8,
) -> Result<u32, TotpError> {
    let counter = counter_at(unix_seconds, t0, period)?;
    hotp(hmac, secret, counter, digits)
}

/// A successful TOTP verification. `counter` is the step the presented code
/// matched; the caller must persist it and reject any later presentation
/// whose counter is not strictly greater, so a code cannot be replayed
/// within its own validity window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TotpMatch {
    pub counter: u64,
}

/// Verify `code` against the shared secret, sweeping `skew` steps either side
/// of the current one to tolerate client clock drift (RFC 6238 §6). Returns
/// the matching counter, or `None` if no step in the window matched.
///
/// `last_counter` is the last counter this secret successfully authenticated
/// with; steps at or below it are refused, which is what makes a code
/// single-use. Pass `None` for the first-ever verification.
///
/// The comparison is over integers derived from the HMAC, and every step in
/// the window is evaluated before returning, so the running time does not
/// depend on which step matched.
#[expect(
    clippy::too_many_arguments,
    reason = "the RFC 6238 parameter set (t0, period, digits, skew) is the surface; \
              grouping it into a struct would only move the same fields"
)]
pub fn verify_totp(
    hmac: HmacFn,
    secret: &[u8],
    code: u32,
    unix_seconds: u64,
    t0: u64,
    period: u64,
    digits: u8,
    skew: u64,
    last_counter: Option<u64>,
) -> Result<Option<TotpMatch>, TotpError> {
    let centre = counter_at(unix_seconds, t0, period)?;
    let first = centre.saturating_sub(skew);
    let last = centre.saturating_add(skew);

    let mut found: Option<u64> = None;
    let mut counter = first;
    loop {
        let expected = hotp(hmac, secret, counter, digits)?;
        // Constant-time-ish: fold every step's comparison into `found`
        // without an early exit, so a match late in the window costs the
        // same as one early in it.
        let fresh = last_counter.is_none_or(|seen| counter > seen);
        if expected == code && fresh && found.is_none() {
            found = Some(counter);
        }
        if counter == last {
            break;
        }
        counter += 1;
    }

    Ok(found.map(|counter| TotpMatch { counter }))
}

/// Render `code` zero-padded to `digits` ASCII characters into `out`.
/// Returns the number of bytes written (always `digits`).
pub fn format_code(code: u32, digits: u8, out: &mut [u8]) -> Result<usize, TotpError> {
    if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        return Err(TotpError::BadDigits);
    }
    let n = digits as usize;
    if out.len() < n {
        return Err(TotpError::BufferTooSmall);
    }
    let mut value = code % pow10(digits);
    for slot in out[..n].iter_mut().rev() {
        *slot = b'0' + (value % 10) as u8;
        value /= 10;
    }
    Ok(n)
}

/// Parse `digits` ASCII decimal characters into an OTP integer. Rejects any
/// non-digit byte and any length outside [`MIN_DIGITS`]..=[`MAX_DIGITS`], so
/// a caller can hand user input straight in.
pub fn parse_code(text: &[u8]) -> Result<u32, TotpError> {
    if text.len() < MIN_DIGITS as usize || text.len() > MAX_DIGITS as usize {
        return Err(TotpError::BadDigits);
    }
    let mut value: u32 = 0;
    for &byte in text {
        if !byte.is_ascii_digit() {
            return Err(TotpError::BadDigits);
        }
        value = value * 10 + u32::from(byte - b'0');
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// Base32 (RFC 4648), unpadded uppercase — the shared-secret encoding every
// authenticator app consumes.
// ---------------------------------------------------------------------------

/// Encoded length of `n` raw bytes in unpadded base32.
pub const fn base32_encoded_len(n: usize) -> usize {
    n.div_ceil(5) * 8
        - match n % 5 {
            1 => 6,
            2 => 4,
            3 => 3,
            4 => 1,
            _ => 0,
        }
}

/// Encode `data` as unpadded uppercase base32 into `out`; returns length.
pub fn base32_encode(data: &[u8], out: &mut [u8]) -> Result<usize, TotpError> {
    let needed = base32_encoded_len(data.len());
    if out.len() < needed {
        return Err(TotpError::BufferTooSmall);
    }
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    let mut written = 0usize;
    for &byte in data {
        buffer = (buffer << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as u8;
            out[written] = base32_symbol(index);
            written += 1;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as u8;
        out[written] = base32_symbol(index);
        written += 1;
    }
    Ok(written)
}

/// Decode unpadded (or `=`-padded) base32 into `out`; returns length.
/// Accepts either case and ignores ASCII whitespace, so a secret pasted from
/// a QR-code fallback string decodes as typed.
pub fn base32_decode(text: &[u8], out: &mut [u8]) -> Result<usize, TotpError> {
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    let mut written = 0usize;
    for &byte in text {
        if byte.is_ascii_whitespace() || byte == b'=' {
            continue;
        }
        let value = base32_value(byte).ok_or(TotpError::BadBase32)?;
        buffer = (buffer << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if written >= out.len() {
                return Err(TotpError::BufferTooSmall);
            }
            out[written] = ((buffer >> bits) & 0xff) as u8;
            written += 1;
        }
    }
    // Any leftover bits must be zero padding; a non-zero remainder means the
    // input encoded a partial byte, which is not a valid encoding.
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return Err(TotpError::BadBase32);
    }
    Ok(written)
}

/// Base32 alphabet lookup by index. A `match` rather than a stored table for
/// PIC safety on-target (see `jose.rs::is_reserved_key`).
const fn base32_symbol(index: u8) -> u8 {
    if index < 26 {
        b'A' + index
    } else {
        b'2' + (index - 26)
    }
}

/// Inverse of [`base32_symbol`], case-insensitive.
const fn base32_value(symbol: u8) -> Option<u8> {
    match symbol {
        b'A'..=b'Z' => Some(symbol - b'A'),
        b'a'..=b'z' => Some(symbol - b'a'),
        b'2'..=b'7' => Some(symbol - b'2' + 26),
        _ => None,
    }
}

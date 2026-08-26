//! base64url (RFC 4648 §5, unpadded) encode/decode into caller buffers.
//!
//! Pure `no_std` fragment, `#[path]`-mounted by kagi's PIC modules and by the
//! host suites under `tests/harness`, which pin it against
//! `base64ct::Base64UrlUnpadded`.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encoded length for `n` input bytes (unpadded).
pub const fn encoded_len(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

/// Decoded length for `n` encoded chars, if `n` is a valid unpadded
/// base64url length (`n % 4 != 1`).
pub const fn decoded_len(n: usize) -> Option<usize> {
    if n % 4 == 1 {
        return None;
    }
    Some((n / 4) * 3 + [0, 0, 1, 2][n % 4])
}

/// Encode `input` into `out`, returning the number of chars written.
/// Returns `None` if `out` is smaller than `encoded_len(input.len())`.
pub fn encode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    let need = encoded_len(input.len());
    if out.len() < need {
        return None;
    }
    let mut o = 0;
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out[o] = ALPHABET[(n >> 18) as usize & 63];
        out[o + 1] = ALPHABET[(n >> 12) as usize & 63];
        out[o + 2] = ALPHABET[(n >> 6) as usize & 63];
        out[o + 3] = ALPHABET[n as usize & 63];
        o += 4;
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let n = u32::from(rem[0]) << 16;
            out[o] = ALPHABET[(n >> 18) as usize & 63];
            out[o + 1] = ALPHABET[(n >> 12) as usize & 63];
            o += 2;
        }
        2 => {
            let n = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
            out[o] = ALPHABET[(n >> 18) as usize & 63];
            out[o + 1] = ALPHABET[(n >> 12) as usize & 63];
            out[o + 2] = ALPHABET[(n >> 6) as usize & 63];
            o += 3;
        }
        _ => {}
    }
    Some(o)
}

/// Decode `input` into `out`, returning the number of bytes written.
/// Returns `None` on invalid length, invalid characters, or short `out`.
pub fn decode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    let need = decoded_len(input.len())?;
    if out.len() < need {
        return None;
    }
    let mut o = 0;
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in input {
        let v = decode_char(c)?;
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out[o] = (acc >> bits).to_be_bytes()[3];
            o += 1;
        }
    }
    // Reject non-canonical trailing bits (matches base64ct strictness).
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(o)
}

fn decode_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decode STANDARD base64 (`+/`, `=` padding) into `out`.
///
/// JOSE is base64url everywhere except `x5c`, which RFC 7515 §4.1.6 defines
/// as standard base64 with padding — the DER goes on the wire in the same
/// encoding a PEM file uses. Decoding it with the url-safe alphabet fails on
/// any certificate whose DER happens to produce a `+` or `/`, which is most
/// of them, and fails at a byte offset that says nothing about why.
///
/// A separate function rather than an alphabet-tolerant one: a decoder that
/// accepted both alphabets would give every input two valid spellings, and
/// two spellings of a certificate is two certificates as far as anything
/// comparing bytes is concerned.
pub fn decode_standard(input: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut o = 0usize;
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in input {
        if c == b'=' {
            // Padding only ever ends the input; anything after it would be
            // a second encoding of the same bytes.
            continue;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if o >= out.len() {
                return None;
            }
            out[o] = (acc >> bits) as u8;
            o += 1;
        }
    }
    Some(o)
}

/// Encode a 32-byte digest into the fixed 43-char base64url form.
pub fn encode_digest32(digest: &[u8; 32]) -> [u8; 43] {
    let mut out = [0u8; 43];
    // 32 bytes always encode to exactly 43 chars; out is sized for it.
    let _ = encode(digest, &mut out);
    out
}

/// Encode `input` as STANDARD base64 with padding, for PEM.
///
/// The url and standard alphabets differ in two characters and in whether
/// padding is written, so this translates the url encoding rather than
/// carrying a second encoder — one place decides how three bytes become four
/// characters.
pub fn encode_standard(input: &[u8], out: &mut [u8]) -> Option<usize> {
    let unpadded = encode(input, out)?;
    for slot in out.get_mut(..unpadded)? {
        match *slot {
            b'-' => *slot = b'+',
            b'_' => *slot = b'/',
            _ => {}
        }
    }
    let padded = unpadded.div_ceil(4) * 4;
    for slot in out.get_mut(unpadded..padded)? {
        *slot = b'=';
    }
    Some(padded)
}

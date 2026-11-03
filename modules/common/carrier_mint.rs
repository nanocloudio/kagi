//! Minting a certificate-bound identity carrier — the producer's half of
//! `cert_bound_identity.rs`.
//!
//! A carrier is a compact JWS the holder of a leaf signs with the leaf's own
//! key, the leaf in its `x5c` header, naming one relying party (`aud`) for at
//! most five minutes. `cert_bound_identity.rs` is what every relying party
//! runs to decide one; this is what writes one that decision accepts, so the
//! two halves of the contract live side by side and a suite proves them
//! against each other.
//!
//! What it writes:
//!
//! ```text
//! header  {"alg":"ES256","typ":"JWT","x5c":["<std b64 of the leaf DER>"]}
//! claims  {"iss":"<SAN>","sub":"<SAN>","aud":"<aud>","iat":N,"exp":N,"jti":"<b64url 16 bytes>"}
//! carrier b64url(header) "." b64url(claims) "." b64url(r‖s)
//! ```
//!
//! `x5c` holds the leaf ALONE: the verifier's chain is a leaf and a
//! configured anchor (`x509_leaf::verify_chain` takes a chain of one), so an
//! issuer certificate carried beside it would be refused, not ignored. `iss`
//! and `sub` are the leaf's first URI SAN, the identity the chain is
//! validated against. The signature is ES256 over SHA-256 of the signing
//! input — the 64-byte low-S `r‖s` a `KEY_VAULT` `SIGN` in `DIGEST` mode
//! answers is the segment as it stands.
//!
//! What it checks before it will write: the chain handed to it certifies the
//! key that will sign (a chain for any other key is refused, so a confused
//! or hostile issuer cannot make the holder present a certificate it cannot
//! prove possession of), the leaf is a P-256 leaf with a SPIFFE URI SAN that
//! fits the verifier's bounds, and the carrier as a whole fits them too:
//! every bound below is the verifier's, restated so a carrier this writes is
//! never one that verifier refuses for size.
//!
//! Pure `no_std`, allocation-free; the digest, the signature and the
//! randomness are the caller's.

#![allow(
    dead_code,
    reason = "shared via #[path] into the minter module and the host harness; each uses a subset"
)]

use crate::b64;
use crate::x509_leaf;

/// `identity_req`: `[0x5B][len u16 LE = 65][SEC1 uncompressed point]`, the
/// frame Fluxor's `tls` asks for a certificate with.
pub const MSG_IDENTITY_REQ: u8 = 0x5B;
/// `identity_cert`: `[0x5C][len u16 LE][leaf DER ‖ issuer DER ‖ …]`.
pub const MSG_IDENTITY_CERT: u8 = 0x5C;
/// An uncompressed P-256 point.
pub const POINT_LEN: usize = 65;
/// The longest leaf carried. The verifier decodes a header of at most 2048
/// bytes (`cert_bound_identity` `HEADER_MAX`); the header's fixed text is 38
/// bytes and the leaf's base64 four thirds of it, so a leaf over 1500 bytes
/// would write a header the verifier cannot read.
pub const LEAF_MAX: usize = 1500;
/// The longest SPIFFE id: the verifier's `CARRIER_SPIFFE_MAX`.
pub const SPIFFE_MAX: usize = 96;
/// The longest audience written.
pub const AUDIENCE_MAX: usize = 128;
/// The longest a carrier may be valid for: the verifier's bound.
pub const LIFETIME_MAX_SECS: u64 = 300;
/// The `jti`: 128 bits of the caller's CSPRNG.
pub const JTI_LEN: usize = 16;
/// The longest compact JWS a consumer takes (the traffic fabric's `dns_sign_relay`
/// `carrier_in`: 4608 bytes).
pub const CARRIER_MAX: usize = 4608;
/// The longest claims set written: three strings bounded above, two
/// twenty-digit integers, a 22-character `jti` and the punctuation.
pub const CLAIMS_MAX: usize = 512;
/// The longest header written: the fixed text and the leaf's base64.
pub const HEADER_MAX: usize = HEADER_HEAD.len() + HEADER_TAIL.len() + LEAF_MAX.div_ceil(3) * 4;
/// Scratch a [`write_signing_input`] call needs: the larger JSON document.
pub const SCRATCH: usize = HEADER_MAX;

const HEADER_HEAD: &[u8] = b"{\"alg\":\"ES256\",\"typ\":\"JWT\",\"x5c\":[\"";
const HEADER_TAIL: &[u8] = b"\"]}";
const SPIFFE_SCHEME: &[u8] = b"spiffe://";

/// Why a chain on `identity_cert` was not taken.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChainRefusal {
    /// Not a certificate this profile reads, or no leaf at all.
    Malformed,
    /// The leaf certifies another key than the one that signs.
    NotThisKey,
    /// The leaf names no SPIFFE URI, one past the verifier's bound, one
    /// with a byte a JSON string cannot carry unescaped, or not the one the
    /// graph expects.
    Identity,
    /// The leaf is longer than [`LEAF_MAX`].
    TooLarge,
    /// The leaf's window is empty.
    Window,
}

/// A chain this holder may present: its leaf, read.
#[derive(Clone, Copy)]
pub struct Certified<'a> {
    /// The leaf DER, exactly as issued.
    pub leaf: &'a [u8],
    /// Its first URI SAN: `iss` and `sub`.
    pub spiffe: &'a [u8],
    /// Unix seconds.
    pub not_before: u64,
    pub not_after: u64,
}

/// A byte a JSON string written here may hold as itself: printable ASCII
/// other than the quote and the backslash. Anything else is refused rather
/// than escaped, because the verifier's reader does not unescape.
fn json_plain(b: &[u8]) -> bool {
    b.iter()
        .all(|&c| (0x20..0x7F).contains(&c) && c != b'"' && c != b'\\')
}

/// Whether `audience` is one this writer can put in `aud`.
#[must_use]
pub fn audience_ok(audience: &[u8]) -> bool {
    !audience.is_empty() && audience.len() <= AUDIENCE_MAX && json_plain(audience)
}

/// Take the chain an `identity_cert` frame carries (`leaf DER ‖ issuer DER
/// ‖ …`, its payload) for the key `point`. Only the leaf is kept; the
/// issuer certificates are the enrolment path's to send and the verifier's
/// anchor is configured, never carried. `expect_spiffe`, when not empty, is
/// the one SAN the graph will present.
pub fn take_chain<'a>(
    chain: &'a [u8],
    point: &[u8; POINT_LEN],
    expect_spiffe: &[u8],
) -> Result<Certified<'a>, ChainRefusal> {
    let leaf_len = x509_leaf::element_len(chain).ok_or(ChainRefusal::Malformed)?;
    let leaf = chain.get(..leaf_len).ok_or(ChainRefusal::Malformed)?;
    if leaf.len() > LEAF_MAX {
        return Err(ChainRefusal::TooLarge);
    }
    let parsed = x509_leaf::parse(leaf).ok_or(ChainRefusal::Malformed)?;
    if parsed.suite != x509_leaf::ES256 || parsed.public != point.as_slice() {
        return Err(ChainRefusal::NotThisKey);
    }
    let spiffe = parsed.san_uri;
    if spiffe.len() <= SPIFFE_SCHEME.len()
        || spiffe.len() > SPIFFE_MAX
        || !spiffe.starts_with(SPIFFE_SCHEME)
        || !json_plain(spiffe)
        || (!expect_spiffe.is_empty() && spiffe != expect_spiffe)
    {
        return Err(ChainRefusal::Identity);
    }
    if parsed.not_after <= parsed.not_before {
        return Err(ChainRefusal::Window);
    }
    Ok(Certified {
        leaf,
        spiffe,
        not_before: parsed.not_before,
        not_after: parsed.not_after,
    })
}

/// A cursor over a caller's buffer.
struct Out<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl Out<'_> {
    fn put(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.at.checked_add(bytes.len())?;
        self.buf.get_mut(self.at..end)?.copy_from_slice(bytes);
        self.at = end;
        Some(())
    }

    fn put_u64(&mut self, mut v: u64) -> Option<()> {
        let mut digits = [0u8; 20];
        let mut n = 0;
        loop {
            digits[n] = b'0' + u8::try_from(v % 10).unwrap_or(0);
            n += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        digits[..n].reverse();
        self.put(&digits[..n])
    }

    fn put_str(&mut self, key: &[u8], value: &[u8]) -> Option<()> {
        self.put(b"\"")?;
        self.put(key)?;
        self.put(b"\":\"")?;
        self.put(value)?;
        self.put(b"\"")
    }

    /// Base64url `data` (without padding) at the cursor.
    fn put_b64url(&mut self, data: &[u8]) -> Option<()> {
        let n = b64::encode(data, self.buf.get_mut(self.at..)?)?;
        self.at += n;
        Some(())
    }
}

/// What one carrier says.
pub struct Claims<'a> {
    pub spiffe: &'a [u8],
    pub audience: &'a [u8],
    /// Unix seconds, from a trusted clock.
    pub iat: u64,
    pub exp: u64,
    pub jti: &'a [u8; JTI_LEN],
}

/// Write `b64url(header) "." b64url(claims)` into `out` — the bytes whose
/// SHA-256 the leaf key signs — answering its length. `scratch` holds each
/// JSON document while it is encoded ([`SCRATCH`] bytes). `None` when a
/// field is outside the verifier's bounds or a buffer is short.
pub fn write_signing_input(
    leaf: &[u8],
    claims: &Claims<'_>,
    scratch: &mut [u8],
    out: &mut [u8],
) -> Option<usize> {
    if leaf.is_empty()
        || leaf.len() > LEAF_MAX
        || claims.spiffe.is_empty()
        || claims.spiffe.len() > SPIFFE_MAX
        || !json_plain(claims.spiffe)
        || !audience_ok(claims.audience)
        || claims.exp <= claims.iat
        || claims.exp - claims.iat > LIFETIME_MAX_SECS
    {
        return None;
    }
    let mut o = Out { buf: out, at: 0 };

    // ── header ─────────────────────────────────────────────────────────
    let header_len = {
        let mut h = Out {
            buf: &mut *scratch,
            at: 0,
        };
        h.put(HEADER_HEAD)?;
        let n = b64::encode_standard(leaf, h.buf.get_mut(h.at..)?)?;
        h.at += n;
        h.put(HEADER_TAIL)?;
        h.at
    };
    o.put_b64url(scratch.get(..header_len)?)?;
    o.put(b".")?;

    // ── claims ─────────────────────────────────────────────────────────
    let mut jti = [0u8; 22];
    let jn = b64::encode(claims.jti, &mut jti)?;
    let claims_len = {
        let mut c = Out {
            buf: &mut *scratch,
            at: 0,
        };
        c.put(b"{")?;
        c.put_str(b"iss", claims.spiffe)?;
        c.put(b",")?;
        c.put_str(b"sub", claims.spiffe)?;
        c.put(b",")?;
        c.put_str(b"aud", claims.audience)?;
        c.put(b",\"iat\":")?;
        c.put_u64(claims.iat)?;
        c.put(b",\"exp\":")?;
        c.put_u64(claims.exp)?;
        c.put(b",")?;
        c.put_str(b"jti", jti.get(..jn)?)?;
        c.put(b"}")?;
        c.at
    };
    if claims_len > CLAIMS_MAX {
        return None;
    }
    o.put_b64url(scratch.get(..claims_len)?)?;
    Some(o.at)
}

/// Append `"." b64url(signature)` after the signing input at `out[..len]`,
/// answering the carrier's length; `None` past [`CARRIER_MAX`].
pub fn append_signature(out: &mut [u8], len: usize, signature: &[u8; 64]) -> Option<usize> {
    let mut o = Out { buf: out, at: len };
    o.put(b".")?;
    o.put_b64url(signature)?;
    if o.at > CARRIER_MAX {
        return None;
    }
    Some(o.at)
}

/// The `identity_req` frame for `point`.
#[must_use]
pub fn identity_req(point: &[u8; POINT_LEN]) -> [u8; 3 + POINT_LEN] {
    let mut f = [0u8; 3 + POINT_LEN];
    f[0] = MSG_IDENTITY_REQ;
    #[expect(clippy::cast_possible_truncation, reason = "65")]
    f[1..3].copy_from_slice(&(POINT_LEN as u16).to_le_bytes());
    f[3..].copy_from_slice(point);
    f
}

/// When a certificate with this window is renewed, in milliseconds after
/// it was taken: at two thirds of its lifetime, as Fluxor's `tls` renews.
#[must_use]
pub fn renew_after_ms(not_before: u64, not_after: u64) -> u64 {
    not_after.saturating_sub(not_before).saturating_mul(2000) / 3
}

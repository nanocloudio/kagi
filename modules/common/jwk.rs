//! Fixed-shape JSON Web Key records: canonical emission and thumbprints.
//!
//! Pure `no_std` fragment. Canonicalization is RFC 8785-style (object keys
//! sorted lexicographically). Two canonical forms live here and they are
//! not interchangeable: [`JwkRecord::canonical_json`] emits every member
//! that is set, which is what publishing a key set needs, and
//! [`JwkRecord::canonical_thumbprint_json`] emits only RFC 7638's REQUIRED
//! members, which is what a thumbprint is defined over.
//!
//! The fragment supports the fixed member set `alg`, `crv`, `kid`, `kty`,
//! `x`, `y` — already in lexicographic order — with plain-ASCII values that
//! need no JSON string escaping (base64url text and algorithm/curve names).
//! A JWK of arbitrary shape needs an allocator, so canonicalising one is a
//! caller's job; what happens to the bytes afterwards is
//! [`thumbprint_from_canonical`], which is here.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

// Cross-fragment reference: every PIC module and the host harness mount
// b64.rs at the crate root as `b64`.
use crate::b64;

/// SHA-256 primitive injected by the consumer (host: `sha2`; PIC: SDK).
pub type Sha256Fn = fn(&[u8], &mut [u8; 32]);

pub const MAX_FIELD: usize = 64;
/// Enough for six quoted members plus separators at `MAX_FIELD` each.
pub const MAX_CANONICAL: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JwkError {
    FieldTooLong,
    BufferTooSmall,
    NotAscii,
}

/// A JWK member value: fixed buffer + length.
#[derive(Clone, Copy)]
pub struct Field {
    buf: [u8; MAX_FIELD],
    len: u8,
}

impl Field {
    pub const fn empty() -> Self {
        Self {
            buf: [0; MAX_FIELD],
            len: 0,
        }
    }

    pub fn set(bytes: &[u8]) -> Result<Self, JwkError> {
        if bytes.len() > MAX_FIELD {
            return Err(JwkError::FieldTooLong);
        }
        // Values must be plain printable ASCII without `"` or `\` so the
        // canonical emission below needs no JSON escaping.
        for &c in bytes {
            if !(0x20..0x7f).contains(&c) || c == b'"' || c == b'\\' {
                return Err(JwkError::NotAscii);
            }
        }
        let mut buf = [0u8; MAX_FIELD];
        buf[..bytes.len()].copy_from_slice(bytes);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "len bounded by MAX_FIELD (64) above"
        )]
        Ok(Self {
            buf,
            len: bytes.len() as u8,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Fixed-shape JWK. Empty fields are omitted from emission.
pub struct JwkRecord {
    pub alg: Field,
    pub crv: Field,
    pub kid: Field,
    pub kty: Field,
    pub x: Field,
    pub y: Field,
}

impl Default for JwkRecord {
    fn default() -> Self {
        Self::new()
    }
}

impl JwkRecord {
    pub const fn new() -> Self {
        Self {
            alg: Field::empty(),
            crv: Field::empty(),
            kid: Field::empty(),
            kty: Field::empty(),
            x: Field::empty(),
            y: Field::empty(),
        }
    }

    /// OKP / Ed25519 public JWK (no alg/kid — matches the device-JWK shape
    /// used for thumbprint binding).
    pub fn okp_ed25519(x_b64: &[u8]) -> Result<Self, JwkError> {
        let mut r = Self::new();
        r.kty = Field::set(b"OKP")?;
        r.crv = Field::set(b"Ed25519")?;
        r.x = Field::set(x_b64)?;
        Ok(r)
    }

    /// EC / P-256 public JWK.
    pub fn ec_p256(x_b64: &[u8], y_b64: &[u8]) -> Result<Self, JwkError> {
        let mut r = Self::new();
        r.kty = Field::set(b"EC")?;
        r.crv = Field::set(b"P-256")?;
        r.x = Field::set(x_b64)?;
        r.y = Field::set(y_b64)?;
        Ok(r)
    }

    /// Emit the canonical JSON object (keys in lexicographic order, no
    /// whitespace) into `out`; returns bytes written.
    pub fn canonical_json(&self, out: &mut [u8]) -> Result<usize, JwkError> {
        let mut w = Writer { out, pos: 0 };
        w.push(b'{')?;
        let mut first = true;
        for (name, field) in [
            (&b"alg"[..], &self.alg),
            (&b"crv"[..], &self.crv),
            (&b"kid"[..], &self.kid),
            (&b"kty"[..], &self.kty),
            (&b"x"[..], &self.x),
            (&b"y"[..], &self.y),
        ] {
            if field.is_empty() {
                continue;
            }
            if !first {
                w.push(b',')?;
            }
            first = false;
            w.quoted(name)?;
            w.push(b':')?;
            w.quoted(field.as_bytes())?;
        }
        w.push(b'}')?;
        Ok(w.pos)
    }

    /// The RFC 7638 canonical form: the REQUIRED members for this key type,
    /// sorted, and nothing else.
    ///
    /// Not the same bytes as [`canonical_json`], which emits every member
    /// that is set. `alg` and `kid` are decorations: a key that acquires a
    /// `kid` is the same key, and a thumbprint that moved when one was added
    /// would break every `cnf.jkt` binding already issued against it.
    ///
    /// [`canonical_json`]: Self::canonical_json
    pub fn canonical_thumbprint_json(&self, out: &mut [u8]) -> Result<usize, JwkError> {
        let mut w = Writer { out, pos: 0 };
        w.push(b'{')?;
        let mut first = true;
        // RFC 7638 §3.2: `crv`, `kty`, `x`, `y` for EC; `crv`, `kty`, `x`
        // for OKP — already in lexicographic order, and `y` is simply
        // unset on an OKP record.
        for (name, field) in [
            (&b"crv"[..], &self.crv),
            (&b"kty"[..], &self.kty),
            (&b"x"[..], &self.x),
            (&b"y"[..], &self.y),
        ] {
            if field.is_empty() {
                continue;
            }
            if !first {
                w.push(b',')?;
            }
            first = false;
            w.quoted(name)?;
            w.push(b':')?;
            w.quoted(field.as_bytes())?;
        }
        w.push(b'}')?;
        Ok(w.pos)
    }

    /// `b64url(sha256(canonical_thumbprint_json))` — RFC 7638's thumbprint.
    pub fn thumbprint(&self, sha256: Sha256Fn) -> Result<[u8; 43], JwkError> {
        let mut buf = [0u8; MAX_CANONICAL];
        let n = self.canonical_thumbprint_json(&mut buf)?;
        Ok(thumbprint_from_canonical(sha256, &buf[..n]))
    }
}

/// The thumbprint of pre-canonicalized JWK bytes.
///
/// The host path, where an arbitrary JWK is canonicalized with `serde_json`
/// rather than by [`JwkRecord::canonical_json`] — the same split `ids` makes
/// for device identifiers, and for the same reason: which canonicalizer runs
/// depends on whether the JWK has a fixed shape, but what happens to the
/// bytes afterwards must not.
pub fn thumbprint_from_canonical(sha256: Sha256Fn, canonical: &[u8]) -> [u8; 43] {
    let mut digest = [0u8; 32];
    sha256(canonical, &mut digest);
    b64::encode_digest32(&digest)
}

struct Writer<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn push(&mut self, c: u8) -> Result<(), JwkError> {
        if self.pos >= self.out.len() {
            return Err(JwkError::BufferTooSmall);
        }
        self.out[self.pos] = c;
        self.pos += 1;
        Ok(())
    }

    fn quoted(&mut self, bytes: &[u8]) -> Result<(), JwkError> {
        self.push(b'"')?;
        for &c in bytes {
            self.push(c)?;
        }
        self.push(b'"')
    }
}

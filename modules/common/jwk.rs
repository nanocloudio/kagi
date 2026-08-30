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

/// Longest `pub` member: base64url-unpadded of the widest public key
/// this build can verify under.
///
/// A member type of its own rather than a wider [`MAX_FIELD`], because
/// only one member is ever this size. RFC 9964's `AKP` carries a whole
/// public key in a single value; `EC` and `OKP` split theirs into
/// coordinates that fit in [`MAX_FIELD`]. Widening every member instead
/// would make the record six times larger to serve one of them.
pub const MAX_PUB_FIELD: usize = {
    // base64url, unpadded: four characters per three bytes.
    crate::auth_wire::suite::MAX_IMPLEMENTED_PUBLIC_KEY_LEN.div_ceil(3) * 4
};

/// Enough for six quoted members plus separators at `MAX_FIELD` each,
/// and the one that is [`MAX_PUB_FIELD`].
pub const MAX_CANONICAL: usize = 512 + MAX_PUB_FIELD;

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

/// A JWK member wide enough for a lattice public key.
///
/// Separate from [`Field`] rather than a wider one, so the six members
/// that are never more than 64 bytes stay 64 bytes — see
/// [`MAX_PUB_FIELD`].
#[derive(Clone, Copy)]
pub struct PubField {
    buf: [u8; MAX_PUB_FIELD],
    len: u16,
}

impl PubField {
    pub const fn empty() -> Self {
        Self {
            buf: [0; MAX_PUB_FIELD],
            len: 0,
        }
    }

    pub fn set(bytes: &[u8]) -> Result<Self, JwkError> {
        if bytes.len() > MAX_PUB_FIELD {
            return Err(JwkError::FieldTooLong);
        }
        // base64url-unpadded only: the emission below does no JSON
        // escaping, and the one thing this member ever holds is base64url.
        for &c in bytes {
            if !(c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
                return Err(JwkError::NotAscii);
            }
        }
        let mut buf = [0u8; MAX_PUB_FIELD];
        buf[..bytes.len()].copy_from_slice(bytes);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "len bounded by MAX_PUB_FIELD above, which is far below u16::MAX"
        )]
        Ok(Self {
            buf,
            len: bytes.len() as u16,
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
    /// RFC 9964's `pub` member, the whole public key of an `AKP` key.
    pub pub_key: PubField,
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
            pub_key: PubField::empty(),
            x: Field::empty(),
            y: Field::empty(),
        }
    }

    /// AKP public JWK for an ML-DSA key (RFC 9964). `alg` is REQUIRED
    /// rather than decorative here: `AKP` names a key-pair shape and not
    /// an algorithm, so without `alg` the key does not say which
    /// parameter set it belongs to.
    pub fn akp(alg: &[u8], pub_b64: &[u8]) -> Result<Self, JwkError> {
        let mut r = Self::new();
        r.kty = Field::set(b"AKP")?;
        r.alg = Field::set(alg)?;
        r.pub_key = PubField::set(pub_b64)?;
        Ok(r)
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
        // Lexicographic: alg, crv, kid, kty, pub, x, y.
        for (name, bytes) in [
            (&b"alg"[..], self.alg.as_bytes()),
            (&b"crv"[..], self.crv.as_bytes()),
            (&b"kid"[..], self.kid.as_bytes()),
            (&b"kty"[..], self.kty.as_bytes()),
            (&b"pub"[..], self.pub_key.as_bytes()),
            (&b"x"[..], self.x.as_bytes()),
            (&b"y"[..], self.y.as_bytes()),
        ] {
            if bytes.is_empty() {
                continue;
            }
            if !first {
                w.push(b',')?;
            }
            first = false;
            w.quoted(name)?;
            w.push(b':')?;
            w.quoted(bytes)?;
        }
        w.push(b'}')?;
        Ok(w.pos)
    }

    /// The RFC 7638 canonical form: the REQUIRED members for this key type,
    /// sorted, and nothing else.
    ///
    /// Not the same bytes as [`canonical_json`], which emits every member
    /// that is set. For `EC` and `OKP`, `alg` and `kid` are decorations: a
    /// key that acquires a `kid` is the same key, and a thumbprint that
    /// moved when one was added would break every `cnf.jkt` binding already
    /// issued against it.
    ///
    /// `AKP` is the exception, and it is a required one rather than an
    /// inconsistency: RFC 9964 makes `alg` a REQUIRED member of an AKP key
    /// and therefore of its thumbprint, because `AKP` alone does not say
    /// which algorithm the key belongs to. Two ML-DSA parameter sets that
    /// shared a thumbprint would be two keys a relying party could not tell
    /// apart.
    ///
    /// [`canonical_json`]: Self::canonical_json
    pub fn canonical_thumbprint_json(&self, out: &mut [u8]) -> Result<usize, JwkError> {
        let mut w = Writer { out, pos: 0 };
        w.push(b'{')?;
        let mut first = true;
        // RFC 7638 §3.2 by key type, each already in lexicographic order:
        // `crv`, `kty`, `x`, `y` for EC; `crv`, `kty`, `x` for OKP, where
        // `y` is simply unset; `alg`, `kty`, `pub` for RFC 9964's AKP.
        let akp: [(&[u8], &[u8]); 3] = [
            (b"alg", self.alg.as_bytes()),
            (b"kty", self.kty.as_bytes()),
            (b"pub", self.pub_key.as_bytes()),
        ];
        let curve: [(&[u8], &[u8]); 4] = [
            (b"crv", self.crv.as_bytes()),
            (b"kty", self.kty.as_bytes()),
            (b"x", self.x.as_bytes()),
            (b"y", self.y.as_bytes()),
        ];
        let required: &[(&[u8], &[u8])] = if self.kty.as_bytes() == b"AKP" {
            &akp
        } else {
            &curve
        };
        for &(name, bytes) in required {
            if bytes.is_empty() {
                continue;
            }
            if !first {
                w.push(b',')?;
            }
            first = false;
            w.quoted(name)?;
            w.push(b':')?;
            w.quoted(bytes)?;
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

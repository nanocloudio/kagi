//! Encrypted secret record wire format.
//!
//! Pure `no_std` fragment defining the durable envelope used by the
//! `secret_store` module (and any host/wasm/HSM backend that wants
//! byte-compatible storage). Style follows the fluxor SDK's
//! `genstore_wire.rs`: fixed layout, validated views over byte slices,
//! zero allocation; the AEAD primitive is injected by the consumer
//! (host: `aes-gcm` crate; PIC: SDK `aes_gcm.rs`; HSM: device op).
//!
//! Layout (all integers little-endian):
//! ```text
//! [magic  4B = "KSR1"]
//! [suite  1B = 1 (AES-256-GCM)]
//! [id_len 1B][id ...]
//! [ver_len 1B][version_id ...]          // may be empty
//! [nonce 12B]
//! [ct_len 2B][ciphertext ...][tag 16B]
//! ```
//! AAD = `id || 0x00 || version_id` — binds ciphertext to its identity so
//! records can't be swapped between ids/versions undetected.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

pub const MAGIC: [u8; 4] = *b"KSR1";
pub const SUITE_AES256_GCM: u8 = 1;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const MAX_ID: usize = 255;
pub const MAX_SECRET: usize = 4096;
pub const MAX_AAD: usize = MAX_ID + 1 + MAX_ID;

/// AEAD seal: `(key, nonce, aad, data_in_place) -> tag`. Mirrors the SDK's
/// `AesGcm::encrypt` shape.
pub type AeadSealFn = fn(&[u8; 32], &[u8; NONCE_LEN], &[u8], &mut [u8]) -> [u8; TAG_LEN];
/// AEAD open: `(key, nonce, aad, data_in_place, tag) -> ok`. Mirrors
/// `AesGcm::decrypt`.
pub type AeadOpenFn = fn(&[u8; 32], &[u8; NONCE_LEN], &[u8], &mut [u8], &[u8; TAG_LEN]) -> bool;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordError {
    BufferTooSmall,
    IdTooLong,
    SecretTooLong,
    Truncated,
    BadMagic,
    BadSuite,
    AuthFailed,
}

/// Total encoded size for the given field lengths.
pub const fn sealed_len(id_len: usize, ver_len: usize, secret_len: usize) -> usize {
    4 + 1 + 1 + id_len + 1 + ver_len + NONCE_LEN + 2 + secret_len + TAG_LEN
}

/// Seal `plaintext` into `out` as a full record. The caller supplies the
/// nonce (must be unique per key; e.g. counter or runtime entropy).
/// Returns bytes written.
pub fn seal_into(
    seal: AeadSealFn,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    id: &[u8],
    version_id: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, RecordError> {
    if id.len() > MAX_ID || version_id.len() > MAX_ID {
        return Err(RecordError::IdTooLong);
    }
    if plaintext.len() > MAX_SECRET {
        return Err(RecordError::SecretTooLong);
    }
    let total = sealed_len(id.len(), version_id.len(), plaintext.len());
    if out.len() < total {
        return Err(RecordError::BufferTooSmall);
    }

    let mut aad = [0u8; MAX_AAD];
    let aad_len = build_aad(id, version_id, &mut aad);

    let mut o = 0;
    out[o..o + 4].copy_from_slice(&MAGIC);
    o += 4;
    out[o] = SUITE_AES256_GCM;
    o += 1;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "lengths bounded by MAX_ID above"
    )]
    {
        out[o] = id.len() as u8;
    }
    o += 1;
    out[o..o + id.len()].copy_from_slice(id);
    o += id.len();
    #[expect(
        clippy::cast_possible_truncation,
        reason = "lengths bounded by MAX_ID above"
    )]
    {
        out[o] = version_id.len() as u8;
    }
    o += 1;
    out[o..o + version_id.len()].copy_from_slice(version_id);
    o += version_id.len();
    out[o..o + NONCE_LEN].copy_from_slice(nonce);
    o += NONCE_LEN;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "length bounded by MAX_SECRET (4096) above"
    )]
    let ct_len = plaintext.len() as u16;
    out[o..o + 2].copy_from_slice(&ct_len.to_le_bytes());
    o += 2;
    out[o..o + plaintext.len()].copy_from_slice(plaintext);
    let tag = seal(
        key,
        nonce,
        &aad[..aad_len],
        &mut out[o..o + plaintext.len()],
    );
    o += plaintext.len();
    out[o..o + TAG_LEN].copy_from_slice(&tag);
    o += TAG_LEN;
    Ok(o)
}

/// Validated read-only view over an encoded record.
pub struct RecordView<'a> {
    pub id: &'a [u8],
    pub version_id: &'a [u8],
    pub nonce: &'a [u8; NONCE_LEN],
    pub ciphertext: &'a [u8],
    pub tag: &'a [u8; TAG_LEN],
    /// Total encoded length consumed from the input.
    pub encoded_len: usize,
}

impl<'a> RecordView<'a> {
    /// Parse and bounds-check a record at the start of `bytes`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, RecordError> {
        let mut o = 0;
        let take = |o: &mut usize, n: usize| -> Result<&'a [u8], RecordError> {
            if *o + n > bytes.len() {
                return Err(RecordError::Truncated);
            }
            let s = &bytes[*o..*o + n];
            *o += n;
            Ok(s)
        };

        if take(&mut o, 4)? != MAGIC {
            return Err(RecordError::BadMagic);
        }
        if take(&mut o, 1)?[0] != SUITE_AES256_GCM {
            return Err(RecordError::BadSuite);
        }
        let id_len = usize::from(take(&mut o, 1)?[0]);
        let id = take(&mut o, id_len)?;
        let ver_len = usize::from(take(&mut o, 1)?[0]);
        let version_id = take(&mut o, ver_len)?;
        let nonce_slice = take(&mut o, NONCE_LEN)?;
        let ct_len_bytes = take(&mut o, 2)?;
        let ct_len = usize::from(u16::from_le_bytes([ct_len_bytes[0], ct_len_bytes[1]]));
        let ciphertext = take(&mut o, ct_len)?;
        let tag_slice = take(&mut o, TAG_LEN)?;

        // Slice-to-array conversions cannot fail: lengths checked above.
        let nonce: &[u8; NONCE_LEN] = match nonce_slice.try_into() {
            Ok(n) => n,
            Err(_) => return Err(RecordError::Truncated),
        };
        let tag: &[u8; TAG_LEN] = match tag_slice.try_into() {
            Ok(t) => t,
            Err(_) => return Err(RecordError::Truncated),
        };

        Ok(Self {
            id,
            version_id,
            nonce,
            ciphertext,
            tag,
            encoded_len: o,
        })
    }

    /// Decrypt into `out` (which must hold `ciphertext.len()` bytes).
    /// Returns plaintext length.
    pub fn open_into(
        &self,
        open: AeadOpenFn,
        key: &[u8; 32],
        out: &mut [u8],
    ) -> Result<usize, RecordError> {
        if out.len() < self.ciphertext.len() {
            return Err(RecordError::BufferTooSmall);
        }
        let mut aad = [0u8; MAX_AAD];
        let aad_len = build_aad(self.id, self.version_id, &mut aad);
        let data = &mut out[..self.ciphertext.len()];
        data.copy_from_slice(self.ciphertext);
        if !open(key, self.nonce, &aad[..aad_len], data, self.tag) {
            return Err(RecordError::AuthFailed);
        }
        Ok(self.ciphertext.len())
    }
}

fn build_aad(id: &[u8], version_id: &[u8], out: &mut [u8; MAX_AAD]) -> usize {
    let mut n = 0;
    out[n..n + id.len()].copy_from_slice(id);
    n += id.len();
    out[n] = 0;
    n += 1;
    out[n..n + version_id.len()].copy_from_slice(version_id);
    n + version_id.len()
}

// ── Key wrapping (envelope encryption / DEK service, P4) ─────────────────
//
// A compact self-contained wrapped blob for small secrets (data-encryption
// keys, key material): `[nonce 12][ciphertext][tag 16]`, AES-256-GCM under a
// key-encryption key (KEK). The caller supplies the AAD as a context string
// so a wrapped blob can't be replayed into a different context. Unlike the
// full record above there is no id/version framing — the caller owns
// identity/versioning of the wrapped key.

/// Encoded size of a wrapped blob for the given plaintext length.
pub const fn wrapped_len(plaintext_len: usize) -> usize {
    NONCE_LEN + plaintext_len + TAG_LEN
}

/// Wrap (seal) `plaintext` under `kek` into `out = [nonce][ct][tag]`. The
/// caller supplies a unique `nonce` (per KEK) and an `aad` context binding.
/// Returns bytes written.
pub fn wrap_into(
    seal: AeadSealFn,
    kek: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, RecordError> {
    let total = wrapped_len(plaintext.len());
    if out.len() < total {
        return Err(RecordError::BufferTooSmall);
    }
    out[..NONCE_LEN].copy_from_slice(nonce);
    let ct = &mut out[NONCE_LEN..NONCE_LEN + plaintext.len()];
    ct.copy_from_slice(plaintext);
    let tag = seal(kek, nonce, aad, ct);
    out[NONCE_LEN + plaintext.len()..total].copy_from_slice(&tag);
    Ok(total)
}

/// Unwrap (open) a `[nonce][ct][tag]` blob under `kek` into `out`, checking
/// `aad`. Returns the plaintext length; `AuthFailed` on tamper / wrong KEK /
/// wrong context.
pub fn unwrap_into(
    open: AeadOpenFn,
    kek: &[u8; 32],
    aad: &[u8],
    wrapped: &[u8],
    out: &mut [u8],
) -> Result<usize, RecordError> {
    if wrapped.len() < NONCE_LEN + TAG_LEN {
        return Err(RecordError::Truncated);
    }
    let pt_len = wrapped.len() - NONCE_LEN - TAG_LEN;
    if out.len() < pt_len {
        return Err(RecordError::BufferTooSmall);
    }
    let nonce: &[u8; NONCE_LEN] = match wrapped[..NONCE_LEN].try_into() {
        Ok(n) => n,
        Err(_) => return Err(RecordError::Truncated),
    };
    let tag: &[u8; TAG_LEN] = match wrapped[NONCE_LEN + pt_len..].try_into() {
        Ok(t) => t,
        Err(_) => return Err(RecordError::Truncated),
    };
    let data = &mut out[..pt_len];
    data.copy_from_slice(&wrapped[NONCE_LEN..NONCE_LEN + pt_len]);
    if !open(kek, nonce, aad, data, tag) {
        return Err(RecordError::AuthFailed);
    }
    Ok(pt_len)
}

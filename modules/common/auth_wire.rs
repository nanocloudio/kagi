//! Wire format for kagi inter-module channel messages.
//!
//! Every message uses Kagi's 3-byte envelope over Fluxor byte-stream ports:
//!   `[msg_type: u8] [len: u16 LE] [payload: len bytes]`
//!
//! ## Stability — DRAFT (do not pin consumers to these encodings yet)
//! Numeric ids and payload field orders may change without notice until
//! the kagi module surface is promoted to v1. External consumers should
//! go through the published common-source encode/decode helpers, never raw
//! offsets.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

// ── Message type constants ──────────────────────────────────────────────

// secret_store requests
pub const MSG_SECRET_GET: u8 = 0x01;
pub const MSG_SECRET_PUT: u8 = 0x02;
pub const MSG_SECRET_LIST: u8 = 0x03;
pub const MSG_SECRET_ROTATE: u8 = 0x04;

// secret_store replies
pub const MSG_SECRET_VALUE: u8 = 0x11;
pub const MSG_SECRET_ACK: u8 = 0x12;
pub const MSG_SECRET_LIST_PAGE: u8 = 0x13;

// key material / epochs
/// KEK epoch delivery to `secret_store`: `[epoch: u32 LE][kek: 32B]`.
pub const MSG_KEY_EPOCH: u8 = 0x21;
/// Signing-key delivery to `token_mint`:
/// `[alg: u8][kid_len: u8][kid][key: 32B]` — for `MINT_ALG_ES256` the key
/// is the P-256 private scalar (big-endian); for `MINT_ALG_ED25519` it is
/// the RFC 8032 seed.
pub const MSG_MINT_KEY: u8 = 0x22;

// token_mint
pub const MSG_MINT_REQ: u8 = 0x31;
pub const MSG_MINT_RESP: u8 = 0x32;

// token_verify
/// Verifying-key delivery to `token_verify`:
/// `[alg: u8][kid_len: u8][kid][pubkey_len: u8][pubkey]` — for
/// `MINT_ALG_ES256` the key is the SEC1 public point (33 or 65 bytes);
/// for `MINT_ALG_ED25519` it is the 32-byte public key.
pub const MSG_VERIFY_KEY: u8 = 0x41;
/// Verify request: `[corr u32][token f16]` (the compact JWS to check).
pub const MSG_VERIFY_REQ: u8 = 0x42;
/// Verify response: `[corr u32][status u8][claims f16]`. `ST_OK` = signature
/// valid and within the time window, and `claims` carries the decoded JWS
/// payload JSON so the caller can authorize on `iss`/`aud`/`scope`/custom
/// claims (the module verifies the token; the caller owns the policy
/// decision). On any non-OK status `claims` is empty.
pub const MSG_VERIFY_RESP: u8 = 0x43;

// ── Status codes (replies) ──────────────────────────────────────────────

pub const ST_OK: u8 = 0;
pub const ST_NOT_FOUND: u8 = 1;
pub const ST_DECRYPT_FAILED: u8 = 2;
pub const ST_MALFORMED: u8 = 3;
pub const ST_NO_KEY: u8 = 4;
pub const ST_FULL: u8 = 5;
/// `token_verify`: signature did not verify against the loaded key.
pub const ST_BAD_SIGNATURE: u8 = 6;
/// `token_verify`: signature valid but outside the iat/exp window.
pub const ST_EXPIRED: u8 = 7;

// ── Envelope ────────────────────────────────────────────────────────────

pub const ENVELOPE: usize = 3;
pub const MAX_PAYLOAD: usize = u16::MAX as usize;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireError {
    BufferTooSmall,
    Truncated,
    FieldTooLong,
}

/// Write a `[type][len u16 LE][payload]` envelope; returns total length.
pub fn write_envelope(msg_type: u8, payload: &[u8], out: &mut [u8]) -> Result<usize, WireError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(WireError::FieldTooLong);
    }
    let total = ENVELOPE + payload.len();
    if out.len() < total {
        return Err(WireError::BufferTooSmall);
    }
    out[0] = msg_type;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by MAX_PAYLOAD above"
    )]
    let len = payload.len() as u16;
    out[1..3].copy_from_slice(&len.to_le_bytes());
    out[3..total].copy_from_slice(payload);
    Ok(total)
}

/// Parse an envelope at the start of `bytes`: `(msg_type, payload)`.
pub fn read_envelope(bytes: &[u8]) -> Result<(u8, &[u8]), WireError> {
    if bytes.len() < ENVELOPE {
        return Err(WireError::Truncated);
    }
    let len = usize::from(u16::from_le_bytes([bytes[1], bytes[2]]));
    if bytes.len() < ENVELOPE + len {
        return Err(WireError::Truncated);
    }
    Ok((bytes[0], &bytes[ENVELOPE..ENVELOPE + len]))
}

// ── Payload cursor helpers ──────────────────────────────────────────────

/// Incremental payload writer over a caller buffer.
pub struct PayloadWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl<'a> PayloadWriter<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, pos: 0 }
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    pub fn u8(&mut self, v: u8) -> Result<(), WireError> {
        self.bytes(&[v])
    }

    pub fn u32(&mut self, v: u32) -> Result<(), WireError> {
        self.bytes(&v.to_le_bytes())
    }

    pub fn bytes(&mut self, b: &[u8]) -> Result<(), WireError> {
        if self.pos + b.len() > self.out.len() {
            return Err(WireError::BufferTooSmall);
        }
        self.out[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
        Ok(())
    }

    /// `[len: u8][bytes]` — short field (ids, kids, scopes).
    pub fn field8(&mut self, b: &[u8]) -> Result<(), WireError> {
        if b.len() > usize::from(u8::MAX) {
            return Err(WireError::FieldTooLong);
        }
        #[expect(clippy::cast_possible_truncation, reason = "bounded by u8::MAX above")]
        self.u8(b.len() as u8)?;
        self.bytes(b)
    }

    /// `[len: u16 LE][bytes]` — long field (secret values, tokens).
    pub fn field16(&mut self, b: &[u8]) -> Result<(), WireError> {
        if b.len() > usize::from(u16::MAX) {
            return Err(WireError::FieldTooLong);
        }
        #[expect(clippy::cast_possible_truncation, reason = "bounded by u16::MAX above")]
        let len = b.len() as u16;
        self.bytes(&len.to_le_bytes())?;
        self.bytes(b)
    }
}

/// Incremental payload reader.
pub struct PayloadReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> PayloadReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.pos + n > self.bytes.len() {
            return Err(WireError::Truncated);
        }
        let s = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// The as-yet-unconsumed tail of the payload (for measuring how many
    /// bytes a sub-parse walked over without exposing `pos`).
    pub fn rest(&self) -> &'a [u8] {
        &self.bytes[self.pos..]
    }

    pub fn field8(&mut self) -> Result<&'a [u8], WireError> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    pub fn field16(&mut self) -> Result<&'a [u8], WireError> {
        let b = self.take(2)?;
        let len = usize::from(u16::from_le_bytes([b[0], b[1]]));
        self.take(len)
    }
}

// ── Typed messages ──────────────────────────────────────────────────────

/// Algorithm ids for `MintRequest::alg` and `MSG_MINT_KEY`.
pub const MINT_ALG_ES256: u8 = 1;
pub const MINT_ALG_ED25519: u8 = 2;

/// Current `MSG_MINT_REQ` wire version. `decode` rejects any other value so
/// consumers fail closed rather than misparse a future layout.
pub const MINT_REQ_VERSION: u8 = 2;

/// Upper bound on custom claims carried in a `MintRequest` — matches the
/// `jose` fragment's `MAX_EXTRA_CLAIMS`, so a decoded request can always be
/// forwarded to `write_access_claims_ext` without further truncation.
pub const MAX_EXTRA_CLAIMS: usize = 32;

// `valtype` discriminants for an extra-claim value (mirrors `jose::ClaimValue`).
const VAL_STR: u8 = 1;
const VAL_U64: u8 = 2;
const VAL_BOOL: u8 = 3;
const VAL_RAW: u8 = 4;

/// A custom-claim value on the mint wire. Mirrors `jose::ClaimValue` so a
/// decoded claim maps across one-to-one. `U64` is carried as an 8-byte
/// little-endian value inside its `field16`; `Bool` as a single 0/1 byte.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MintClaimValue<'a> {
    Str(&'a [u8]),
    U64(u64),
    Bool(bool),
    Raw(&'a [u8]),
}

/// A custom (non-reserved) claim on the mint wire: `[key f8][valtype u8][value f16]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MintClaim<'a> {
    pub key: &'a [u8],
    pub value: MintClaimValue<'a>,
}

fn encode_claim(w: &mut PayloadWriter<'_>, claim: &MintClaim<'_>) -> Result<(), WireError> {
    w.field8(claim.key)?;
    match claim.value {
        MintClaimValue::Str(s) => {
            w.u8(VAL_STR)?;
            w.field16(s)
        }
        MintClaimValue::U64(n) => {
            w.u8(VAL_U64)?;
            w.field16(&n.to_le_bytes())
        }
        MintClaimValue::Bool(b) => {
            w.u8(VAL_BOOL)?;
            w.field16(&[u8::from(b)])
        }
        MintClaimValue::Raw(r) => {
            w.u8(VAL_RAW)?;
            w.field16(r)
        }
    }
}

fn decode_claim<'a>(r: &mut PayloadReader<'a>) -> Result<MintClaim<'a>, WireError> {
    let key = r.field8()?;
    let valtype = r.u8()?;
    let value_bytes = r.field16()?;
    let value = match valtype {
        VAL_STR => MintClaimValue::Str(value_bytes),
        VAL_U64 => {
            let b: [u8; 8] = value_bytes.try_into().map_err(|_| WireError::Truncated)?;
            MintClaimValue::U64(u64::from_le_bytes(b))
        }
        VAL_BOOL => {
            if value_bytes.len() != 1 {
                return Err(WireError::Truncated);
            }
            MintClaimValue::Bool(value_bytes[0] != 0)
        }
        VAL_RAW => MintClaimValue::Raw(value_bytes),
        _ => return Err(WireError::FieldTooLong),
    };
    Ok(MintClaim { key, value })
}

/// The extra-claims trailer of a `MintRequest`. `Slice` is the build side
/// (caller-supplied claims to encode); `Encoded` is the decode side (the raw
/// wire region, iterated lazily so no owned storage is needed on-target).
#[derive(Clone, Copy)]
pub enum ExtraClaims<'a> {
    Slice(&'a [MintClaim<'a>]),
    Encoded { count: usize, bytes: &'a [u8] },
}

impl<'a> ExtraClaims<'a> {
    /// No custom claims.
    pub fn none() -> Self {
        ExtraClaims::Slice(&[])
    }

    pub fn len(&self) -> usize {
        match self {
            ExtraClaims::Slice(s) => s.len(),
            ExtraClaims::Encoded { count, .. } => *count,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate the claims. Decoded (`Encoded`) claims were validated during
    /// `MintRequest::decode`, so re-parsing here cannot fail; a malformed
    /// entry simply ends iteration.
    pub fn iter(&self) -> ExtraClaimsIter<'a> {
        match *self {
            ExtraClaims::Slice(s) => ExtraClaimsIter::Slice(s.iter()),
            ExtraClaims::Encoded { count, bytes } => ExtraClaimsIter::Encoded {
                reader: PayloadReader::new(bytes),
                remaining: count,
            },
        }
    }
}

impl<'a> IntoIterator for &ExtraClaims<'a> {
    type Item = MintClaim<'a>;
    type IntoIter = ExtraClaimsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub enum ExtraClaimsIter<'a> {
    Slice(core::slice::Iter<'a, MintClaim<'a>>),
    Encoded {
        reader: PayloadReader<'a>,
        remaining: usize,
    },
}

impl<'a> Iterator for ExtraClaimsIter<'a> {
    type Item = MintClaim<'a>;

    fn next(&mut self) -> Option<MintClaim<'a>> {
        match self {
            ExtraClaimsIter::Slice(it) => it.next().copied(),
            ExtraClaimsIter::Encoded { reader, remaining } => {
                if *remaining == 0 {
                    return None;
                }
                *remaining -= 1;
                decode_claim(reader).ok()
            }
        }
    }
}

/// `MSG_MINT_REQ` payload — versioned, forward-compatible (W1):
/// ```text
/// [version u8 = MINT_REQ_VERSION]
/// [corr u32 LE]
/// [alg u8]
/// [ttl_seconds u32 LE]
/// [iss f8][sub f8][aud f8][scope f8]
/// [jkt f8]          // len 0 = no cnf; len 43 = the b64url thumbprint
/// [extra_count u8]  // 0..=MAX_EXTRA_CLAIMS
/// ( [key f8][valtype u8][value f16] ) * extra_count
/// ```
/// `jkt` is `Option<&[u8; 43]>` (an empty `jkt` field decodes to `None`),
/// and `extra` carries optional custom claims forwarded to
/// `jose::write_access_claims_ext`.
pub struct MintRequest<'a> {
    pub correlation: u32,
    pub alg: u8,
    pub ttl_seconds: u32,
    pub iss: &'a [u8],
    pub sub: &'a [u8],
    pub aud: &'a [u8],
    pub scope: &'a [u8],
    pub jkt: Option<&'a [u8; 43]>,
    pub extra: ExtraClaims<'a>,
}

impl<'a> MintRequest<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        if self.extra.len() > MAX_EXTRA_CLAIMS {
            return Err(WireError::FieldTooLong);
        }
        let mut payload = [0u8; 4096];
        let mut w = PayloadWriter::new(&mut payload);
        w.u8(MINT_REQ_VERSION)?;
        w.u32(self.correlation)?;
        w.u8(self.alg)?;
        w.u32(self.ttl_seconds)?;
        w.field8(self.iss)?;
        w.field8(self.sub)?;
        w.field8(self.aud)?;
        w.field8(self.scope)?;
        match self.jkt {
            Some(jkt) => w.field8(jkt)?,
            None => w.field8(&[])?,
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "bounded by MAX_EXTRA_CLAIMS above"
        )]
        w.u8(self.extra.len() as u8)?;
        for claim in &self.extra {
            encode_claim(&mut w, &claim)?;
        }
        let n = w.len();
        write_envelope(MSG_MINT_REQ, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let version = r.u8()?;
        if version != MINT_REQ_VERSION {
            return Err(WireError::FieldTooLong);
        }
        let correlation = r.u32()?;
        let alg = r.u8()?;
        let ttl_seconds = r.u32()?;
        let iss = r.field8()?;
        let sub = r.field8()?;
        let aud = r.field8()?;
        let scope = r.field8()?;
        let jkt_slice = r.field8()?;
        let jkt: Option<&[u8; 43]> = match jkt_slice.len() {
            0 => None,
            43 => Some(jkt_slice.try_into().map_err(|_| WireError::Truncated)?),
            _ => return Err(WireError::FieldTooLong),
        };
        let count = usize::from(r.u8()?);
        if count > MAX_EXTRA_CLAIMS {
            return Err(WireError::FieldTooLong);
        }
        // Validate the whole extra region up front and capture its exact byte
        // span, so `ExtraClaims::iter` can re-walk it infallibly.
        let region = r.rest();
        for _ in 0..count {
            decode_claim(&mut r)?;
        }
        let consumed = region.len() - r.rest().len();
        let extra = ExtraClaims::Encoded {
            count,
            bytes: &region[..consumed],
        };
        Ok(Self {
            correlation,
            alg,
            ttl_seconds,
            iss,
            sub,
            aud,
            scope,
            jkt,
            extra,
        })
    }
}

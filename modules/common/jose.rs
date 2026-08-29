//! JWS compact serialization: header/claims emission and token assembly.
//!
//! Pure `no_std` fragment: the access tokens kagi mints are assembled here,
//! by `token_mint` and by every endpoint that signs. What a JSON library
//! would emit is the compatibility target, since that is what a relying
//! party's parser expects:
//! - `serde_json::json!`'s default map is a `BTreeMap` — object keys come
//!   out in lexicographic order. The writers below emit the same fixed key
//!   orders.
//! - String escaping matches `serde_json`'s: `"` and `\` escaped, control
//!   chars as `\b \f \n \r \t` or `\u00XX`; nothing else escaped.
//! - The signature segment is `b64url(raw_sig)`; ES256 signatures must be
//!   the raw 64-byte `r||s` form (the SDK's `p256::ecdsa_sign` output).

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::b64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JoseError {
    BufferTooSmall,
    /// More custom claims than `MAX_EXTRA_CLAIMS`.
    TooManyClaims,
    /// A custom claim key duplicates another custom key or a reserved
    /// (standard) claim key. Duplicate object keys are invalid JSON.
    DuplicateClaimKey,
    /// A custom claim key is not sorted-mergeable (contains a byte the
    /// standard-claim comparison can't order deterministically). Keys must
    /// be printable ASCII without `"`/`\`.
    InvalidClaimKey,
}

/// Maximum custom claims mergeable into one token.
pub const MAX_EXTRA_CLAIMS: usize = 32;

/// JWS algorithm names as emitted in headers.
pub const ALG_EDDSA: &[u8] = b"EdDSA";
pub const ALG_ES256: &[u8] = b"ES256";

/// Claims for the kagi access token. String values are borrowed raw bytes.
/// `jkt` is the base64url JWK thumbprint for `DPoP` binding; `None`
/// omits the `cnf` claim entirely (e.g. `ServiceAccount` / id-token-shaped
/// tokens with no proof-of-possession binding).
pub struct AccessClaims<'a> {
    pub iss: &'a [u8],
    pub sub: &'a [u8],
    pub aud: &'a [u8],
    pub scope: &'a [u8],
    /// Its length follows from the thumbprint algorithm the caller used —
    /// 43 characters for SHA-256, 64 for SHA-384 — so this is a slice
    /// rather than a fixed `[u8; 43]`. The fixed form made a SHA-384
    /// thumbprint inexpressible and accepted any other 43-byte value as a
    /// SHA-256 one; `auth_wire` checks the length against the named
    /// algorithm before a value ever reaches here.
    pub jkt: Option<&'a [u8]>,
    pub iat: u64,
    pub exp: u64,
}

/// A custom claim value. Scalars cover the common cases; `Raw` carries a
/// pre-serialized JSON fragment (object/array/etc.) emitted verbatim, which
/// the host uses to pass arbitrary `serde_json::Value`s while staying
/// byte-identical.
#[derive(Clone, Copy)]
pub enum ClaimValue<'a> {
    /// JSON string (escaped on emit).
    Str(&'a [u8]),
    /// JSON number.
    U64(u64),
    /// JSON `true`/`false`.
    Bool(bool),
    /// Verbatim pre-serialized JSON (caller guarantees validity).
    Raw(&'a [u8]),
}

/// A custom (non-reserved) claim. `key` must not collide with a reserved
/// claim (`aud,cnf,exp,iat,iss,scope,sub`) and must be printable ASCII
/// without `"`/`\`.
#[derive(Clone, Copy)]
pub struct Claim<'a> {
    pub key: &'a [u8],
    pub value: ClaimValue<'a>,
}

/// Number of reserved claim keys (`aud,cnf,exp,iat,iss,scope,sub`).
const RESERVED_KEY_COUNT: usize = 7;

/// `true` iff `k` is one of the reserved claim keys. Each comparison is
/// against a PC-relative byte literal, so this is PIC-safe on-target — unlike
/// a `const [&[u8]; N]`, whose stored fat-pointer table the module loader
/// does not relocate (dereferencing it traps on aarch64 PIC modules).
fn is_reserved_key(k: &[u8]) -> bool {
    k == b"aud"
        || k == b"cnf"
        || k == b"exp"
        || k == b"iat"
        || k == b"iss"
        || k == b"scope"
        || k == b"sub"
}

/// Lexicographic `reserved_key(i) > other` for the reserved key at ordered
/// index `i` (`0=aud … 6=sub`). Kept as per-arm literal comparisons (no
/// stored pointer table) for the same PIC-safety reason as `is_reserved_key`.
fn reserved_key_greater(i: usize, other: &[u8]) -> bool {
    match i {
        0 => key_greater(b"aud", other),
        1 => key_greater(b"cnf", other),
        2 => key_greater(b"exp", other),
        3 => key_greater(b"iat", other),
        4 => key_greater(b"iss", other),
        5 => key_greater(b"scope", other),
        _ => key_greater(b"sub", other),
    }
}

/// Emit the claims JSON (`aud,cnf,exp,iat,iss,scope,sub` — lexicographic,
/// matching `serde_json`'s `BTreeMap` emission) into `out`; returns length.
pub fn write_access_claims(claims: &AccessClaims<'_>, out: &mut [u8]) -> Result<usize, JoseError> {
    write_access_claims_ext(claims, &[], out)
}

/// Emit the claims JSON with `extra` custom claims merged in. All keys
/// (reserved + custom) are emitted in a single lexicographic order, so the
/// output matches `serde_json`'s `BTreeMap` serialization of the same flat
/// object — the property `tests/common_fragments.rs` pins. `extra` may be
/// in any order; the fragment sorts it. Errors on collisions, duplicates,
/// invalid keys, or more than `MAX_EXTRA_CLAIMS`.
pub fn write_access_claims_ext(
    claims: &AccessClaims<'_>,
    extra: &[Claim<'_>],
    out: &mut [u8],
) -> Result<usize, JoseError> {
    if extra.len() > MAX_EXTRA_CLAIMS {
        return Err(JoseError::TooManyClaims);
    }
    // Sort extra by key (indices; insertion sort, N small). Validate keys.
    let mut order = [0usize; MAX_EXTRA_CLAIMS];
    for (i, slot) in order.iter_mut().enumerate().take(extra.len()) {
        *slot = i;
    }
    for &c in extra {
        if !is_valid_key(c.key) {
            return Err(JoseError::InvalidClaimKey);
        }
        if is_reserved_key(c.key) {
            return Err(JoseError::DuplicateClaimKey);
        }
    }
    let ord = &mut order[..extra.len()];
    for i in 1..ord.len() {
        let mut j = i;
        while j > 0 && key_greater(extra[ord[j - 1]].key, extra[ord[j]].key) {
            ord.swap(j - 1, j);
            j -= 1;
        }
    }
    // Reject duplicate custom keys (adjacent after sort).
    for w in 1..ord.len() {
        if extra[ord[w - 1]].key == extra[ord[w]].key {
            return Err(JoseError::DuplicateClaimKey);
        }
    }

    // Active reserved keys in lexicographic order — `cnf` (index 1) is
    // omitted when there is no DPoP thumbprint.
    let mut active = [0usize; RESERVED_KEY_COUNT];
    let mut ac = 0;
    for i in 0..RESERVED_KEY_COUNT {
        if i == 1 && claims.jkt.is_none() {
            continue;
        }
        active[ac] = i;
        ac += 1;
    }
    let active = &active[..ac];

    let mut w = JsonWriter { out, pos: 0 };
    w.raw(b"{")?;
    let mut first = true;
    let mut si = 0usize; // index into `active`
    let mut ei = 0usize; // extra (sorted) index
    while si < active.len() || ei < ord.len() {
        // Choose the lexicographically smaller of the next reserved/custom key.
        let take_reserved = if si >= active.len() {
            false
        } else if ei >= ord.len() {
            true
        } else {
            !reserved_key_greater(active[si], extra[ord[ei]].key)
        };
        if !first {
            w.raw(b",")?;
        }
        first = false;
        if take_reserved {
            emit_reserved(&mut w, active[si], claims)?;
            si += 1;
        } else {
            let c = extra[ord[ei]];
            w.string(c.key)?;
            w.raw(b":")?;
            w.value(&c.value)?;
            ei += 1;
        }
    }
    w.raw(b"}")?;
    Ok(w.pos)
}

/// Emit the reserved claim at ordered index `i` (key + `:` + value).
fn emit_reserved(
    w: &mut JsonWriter<'_>,
    i: usize,
    claims: &AccessClaims<'_>,
) -> Result<(), JoseError> {
    match i {
        0 => {
            w.raw(b"\"aud\":")?;
            w.string(claims.aud)
        }
        1 => {
            // Only reached when `jkt` is present (see the active-key filter).
            let jkt = claims.jkt.unwrap_or(b"");
            w.raw(b"\"cnf\":{\"jkt\":")?;
            w.string(jkt)?;
            w.raw(b"}")
        }
        2 => {
            w.raw(b"\"exp\":")?;
            w.number(claims.exp)
        }
        3 => {
            w.raw(b"\"iat\":")?;
            w.number(claims.iat)
        }
        4 => {
            w.raw(b"\"iss\":")?;
            w.string(claims.iss)
        }
        5 => {
            w.raw(b"\"scope\":")?;
            w.string(claims.scope)
        }
        _ => {
            w.raw(b"\"sub\":")?;
            w.string(claims.sub)
        }
    }
}

/// Bytewise lexicographic `a > b` (matches `serde_json` `BTreeMap` ordering,
/// which is Rust `String` Ord = UTF-8 byte order).
fn key_greater(a: &[u8], b: &[u8]) -> bool {
    let n = if a.len() < b.len() { a.len() } else { b.len() };
    let mut i = 0;
    while i < n {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
        i += 1;
    }
    a.len() > b.len()
}

fn is_valid_key(key: &[u8]) -> bool {
    !key.is_empty()
        && key
            .iter()
            .all(|&c| (0x20..0x7f).contains(&c) && c != b'"' && c != b'\\')
}

/// Emit the JOSE header (`alg,kid,typ` — lexicographic) into `out`.
pub fn write_header(alg: &[u8], kid: &[u8], out: &mut [u8]) -> Result<usize, JoseError> {
    let mut w = JsonWriter { out, pos: 0 };
    w.raw(b"{\"alg\":")?;
    w.string(alg)?;
    w.raw(b",\"kid\":")?;
    w.string(kid)?;
    w.raw(b",\"typ\":\"JWT\"}")?;
    Ok(w.pos)
}

/// Assemble `b64(header_json) . b64(claims_json)` — the JWS signing input.
/// Returns the length written into `out`.
pub fn signing_input(
    header_json: &[u8],
    claims_json: &[u8],
    out: &mut [u8],
) -> Result<usize, JoseError> {
    let h = b64::encoded_len(header_json.len());
    let c = b64::encoded_len(claims_json.len());
    let need = h + 1 + c;
    if out.len() < need {
        return Err(JoseError::BufferTooSmall);
    }
    b64::encode(header_json, &mut out[..h]).ok_or(JoseError::BufferTooSmall)?;
    out[h] = b'.';
    b64::encode(claims_json, &mut out[h + 1..need]).ok_or(JoseError::BufferTooSmall)?;
    Ok(need)
}

/// Append `. b64(signature)` after an existing signing input in `out`
/// (which holds `input_len` bytes). Returns the total token length.
pub fn append_signature(
    out: &mut [u8],
    input_len: usize,
    signature: &[u8],
) -> Result<usize, JoseError> {
    let s = b64::encoded_len(signature.len());
    let need = input_len + 1 + s;
    if out.len() < need {
        return Err(JoseError::BufferTooSmall);
    }
    out[input_len] = b'.';
    b64::encode(signature, &mut out[input_len + 1..need]).ok_or(JoseError::BufferTooSmall)?;
    Ok(need)
}

/// Time-window check shared by token validators: `iat` may be up to
/// `skew` in the future, `exp` is hard (no grace).
pub fn within_window(now: u64, iat: u64, exp: u64, skew: u64) -> bool {
    iat <= now.saturating_add(skew) && now < exp
}

/// A parsed compact JWS (`header.payload.signature`) as byte-slice views.
/// `signing_input` is the exact `header.payload` ASCII the signature
/// covers; `header_b64`/`payload_b64` are the individual segments (still
/// base64url); `signature_b64` is the trailing segment.
pub struct Jws<'a> {
    pub signing_input: &'a [u8],
    pub header_b64: &'a [u8],
    pub payload_b64: &'a [u8],
    pub signature_b64: &'a [u8],
}

impl<'a> Jws<'a> {
    /// Split a compact JWS on its two `.` separators. Returns `None` if
    /// there are not exactly two dots or any segment is empty.
    pub fn split(token: &'a [u8]) -> Option<Self> {
        let mut dot1 = None;
        let mut dot2 = None;
        for (i, &b) in token.iter().enumerate() {
            if b == b'.' {
                if dot1.is_none() {
                    dot1 = Some(i);
                } else if dot2.is_none() {
                    dot2 = Some(i);
                } else {
                    return None; // a third dot: not compact JWS
                }
            }
        }
        let d1 = dot1?;
        let d2 = dot2?;
        if d1 == 0 || d2 == d1 + 1 || d2 + 1 >= token.len() {
            return None; // empty header, payload, or signature
        }
        Some(Self {
            signing_input: &token[..d2],
            header_b64: &token[..d1],
            payload_b64: &token[d1 + 1..d2],
            signature_b64: &token[d2 + 1..],
        })
    }
}

/// Extract an unsigned-integer claim from a flat JSON object (the decoded
/// JWS payload). Matches `"<key>"` as an object member and reads the
/// non-negative integer value that follows. Returns `None` if the key is
/// absent or its value is not a bare integer. Sufficient for `exp`/`iat`;
/// not a general JSON parser (no nested objects, strings, or escapes are
/// interpreted — the scan only needs the top-level numeric claims kagi
/// emits, which are written by `write_access_claims`).
pub fn claim_u64(payload_json: &[u8], key: &[u8]) -> Option<u64> {
    let needle_len = key.len() + 2; // "key"
    let mut i = 0;
    while i + needle_len <= payload_json.len() {
        if payload_json[i] == b'"'
            && payload_json[i + 1..i + 1 + key.len()] == *key
            && payload_json[i + 1 + key.len()] == b'"'
        {
            // Advance past the quote, optional spaces, and the colon.
            let mut j = i + needle_len;
            while j < payload_json.len() && payload_json[j] == b' ' {
                j += 1;
            }
            if j >= payload_json.len() || payload_json[j] != b':' {
                i += 1;
                continue;
            }
            j += 1;
            while j < payload_json.len() && payload_json[j] == b' ' {
                j += 1;
            }
            // Read decimal digits.
            let start = j;
            let mut value: u64 = 0;
            while j < payload_json.len() && payload_json[j].is_ascii_digit() {
                value = value
                    .checked_mul(10)?
                    .checked_add(u64::from(payload_json[j] - b'0'))?;
                j += 1;
            }
            if j > start {
                return Some(value);
            }
            return None; // present but not a bare integer
        }
        i += 1;
    }
    None
}

/// Extract a string claim's raw bytes from a flat JSON object. Matches
/// `"<key>":"<value>"` and returns the value bytes as they appear in the
/// source (escape sequences NOT decoded — callers compare against expected
/// ASCII values like `DPoP` `htm`/`htu`, which contain no escapes). Returns
/// `None` if the key is absent or its value is not a string. Like
/// `claim_u64`, this is a scanner for kagi's flat claim objects, not a
/// general JSON parser.
/// Whether `value` may be written into a record that [`claim_str`] will read
/// back, without escaping it.
///
/// [`claim_str`] scans for the FIRST `"key":"…"` anywhere in the bytes,
/// including inside another value. So a record built by concatenation, whose
/// values are not checked, lets one value introduce a key: a `nonce` carrying
/// `","scope":"admin` places a scope ahead of the real one and wins the read.
///
/// The answer is to refuse rather than to escape. `claim_str` returns the raw
/// bytes between the quotes, so an escaped value reads back with its
/// backslashes still in it — a nonce that is not the nonce that was sent.
/// Control bytes go too: they cannot appear raw in a JSON string.
///
/// This is the writer's half of that scanner's contract, and it lives here so
/// the two cannot be reasoned about separately.
#[must_use]
pub const fn is_record_safe(value: &[u8]) -> bool {
    let mut i = 0usize;
    while i < value.len() {
        let byte = value[i];
        if byte == b'"' || byte == b'\\' || byte < 0x20 {
            return false;
        }
        i += 1;
    }
    true
}

pub fn claim_str<'a>(payload_json: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let needle_len = key.len() + 2; // "key"
    let mut i = 0;
    while i + needle_len <= payload_json.len() {
        if payload_json[i] == b'"'
            && payload_json[i + 1..i + 1 + key.len()] == *key
            && payload_json[i + 1 + key.len()] == b'"'
        {
            let mut j = i + needle_len;
            while j < payload_json.len() && payload_json[j] == b' ' {
                j += 1;
            }
            if j >= payload_json.len() || payload_json[j] != b':' {
                i += 1;
                continue;
            }
            j += 1;
            while j < payload_json.len() && payload_json[j] == b' ' {
                j += 1;
            }
            if j >= payload_json.len() || payload_json[j] != b'"' {
                return None; // present but not a string value
            }
            j += 1;
            let start = j;
            // Scan to the closing quote, honouring backslash escapes so an
            // escaped `\"` doesn't terminate the value early.
            while j < payload_json.len() {
                match payload_json[j] {
                    b'\\' => j += 2,
                    b'"' => return Some(&payload_json[start..j]),
                    _ => j += 1,
                }
            }
            return None; // unterminated string
        }
        i += 1;
    }
    None
}

struct JsonWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl JsonWriter<'_> {
    /// Emit a custom `ClaimValue`.
    fn value(&mut self, v: &ClaimValue<'_>) -> Result<(), JoseError> {
        match v {
            ClaimValue::Str(s) => self.string(s),
            ClaimValue::U64(n) => self.number(*n),
            ClaimValue::Bool(true) => self.raw(b"true"),
            ClaimValue::Bool(false) => self.raw(b"false"),
            ClaimValue::Raw(bytes) => self.raw(bytes),
        }
    }

    fn push(&mut self, c: u8) -> Result<(), JoseError> {
        if self.pos >= self.out.len() {
            return Err(JoseError::BufferTooSmall);
        }
        self.out[self.pos] = c;
        self.pos += 1;
        Ok(())
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), JoseError> {
        for &c in bytes {
            self.push(c)?;
        }
        Ok(())
    }

    /// Quoted JSON string with serde_json-compatible escaping.
    fn string(&mut self, bytes: &[u8]) -> Result<(), JoseError> {
        self.push(b'"')?;
        for &c in bytes {
            match c {
                b'"' => self.raw(b"\\\"")?,
                b'\\' => self.raw(b"\\\\")?,
                0x08 => self.raw(b"\\b")?,
                0x0c => self.raw(b"\\f")?,
                b'\n' => self.raw(b"\\n")?,
                b'\r' => self.raw(b"\\r")?,
                b'\t' => self.raw(b"\\t")?,
                0x00..=0x1f => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    self.raw(b"\\u00")?;
                    self.push(HEX[usize::from(c >> 4)])?;
                    self.push(HEX[usize::from(c & 0x0f)])?;
                }
                _ => self.push(c)?,
            }
        }
        self.push(b'"')
    }

    fn number(&mut self, mut n: u64) -> Result<(), JoseError> {
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        loop {
            i -= 1;
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        self.raw(&digits[i..])
    }
}

/// Every string element of a JSON array claim, in order.
///
/// For claims that are a LIST of equals — `amr` is the one this exists for —
/// where reading only the first would drop the methods that make a level.
/// Contrast [`claim_array_first_str`], which reads one deliberately.
///
/// Elements are returned raw, exactly as [`claim_str`] returns a string: no
/// unescaping, because the values this reads are registry tokens and a value
/// needing an escape is a value that does not match any of them.
#[must_use]
pub fn claim_array<'a>(json: &'a [u8], key: &[u8]) -> Option<ClaimArray<'a>> {
    let mut i = 0usize;
    let at = loop {
        if i + key.len() + 2 > json.len() {
            return None;
        }
        if json[i] == b'"'
            && json[i + 1..].starts_with(key)
            && json.get(i + 1 + key.len()) == Some(&b'"')
        {
            break i + key.len() + 2;
        }
        i += 1;
    };
    let mut p = at;
    while p < json.len() && (json[p] == b' ' || json[p] == b':') {
        p += 1;
    }
    if json.get(p) != Some(&b'[') {
        return None;
    }
    Some(ClaimArray { json, at: p + 1 })
}

/// The string elements of one JSON array claim.
pub struct ClaimArray<'a> {
    json: &'a [u8],
    at: usize,
}

impl<'a> Iterator for ClaimArray<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        // Skip separators to the next element's opening quote, stopping at
        // the array's end so a following claim is never read as an element.
        while self.at < self.json.len() {
            match self.json[self.at] {
                b' ' | b',' => self.at += 1,
                b'"' => break,
                _ => return None,
            }
        }
        if self.json.get(self.at) != Some(&b'"') {
            return None;
        }
        let start = self.at + 1;
        let mut end = start;
        while end < self.json.len() {
            match self.json[end] {
                b'\\' => end += 2,
                b'"' => {
                    self.at = end + 1;
                    return Some(&self.json[start..end]);
                }
                _ => end += 1,
            }
        }
        None
    }
}

/// The first string element of a JSON array claim, e.g. `x5c`'s leaf.
///
/// Only the first: a carrier presents a leaf, never a chain, and reading
/// past it would let a client supply intermediates that reach an anchor it
/// was never meant to reach.
#[must_use]
pub fn claim_array_first_str<'a>(json: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    // Find `"key"` at an object position and step to its value.
    let mut i = 0usize;
    let at = loop {
        if i + key.len() + 2 > json.len() {
            return None;
        }
        if json[i] == b'"'
            && json[i + 1..].starts_with(key)
            && json.get(i + 1 + key.len()) == Some(&b'"')
        {
            break i + key.len() + 2;
        }
        i += 1;
    };
    let mut p = at;
    while p < json.len() && (json[p] == b' ' || json[p] == b':') {
        p += 1;
    }
    if json.get(p) != Some(&b'[') {
        return None;
    }
    p += 1;
    while p < json.len() && json[p] == b' ' {
        p += 1;
    }
    if json.get(p) != Some(&b'"') {
        return None;
    }
    p += 1;
    let start = p;
    while p < json.len() && json[p] != b'"' {
        // No escape handling: a base64 element has no escapable character,
        // and accepting an escape here would mean two spellings of one
        // certificate.
        if json[p] == b'\\' {
            return None;
        }
        p += 1;
    }
    if p >= json.len() {
        return None;
    }
    Some(&json[start..p])
}

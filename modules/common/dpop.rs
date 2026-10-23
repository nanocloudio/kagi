//! `DPoP` proof-of-possession verification (RFC 9449) — the deterministic,
//! reusable parts. Pure `no_std` fragment; crypto is injected.
//!
//! A `DPoP` proof is a compact JWS whose header carries the prover's public
//! `jwk`, an asymmetric `alg` and `typ:"dpop+jwt"`, and whose claims are
//! `htm` (the HTTP method), `htu` (the HTTP target URI, without query and
//! fragment), `iat`, a unique `jti`, and — because every presentation kagi
//! verifies carries a DPoP-bound credential in `Authorization: DPoP` — `ath`,
//! the base64url SHA-256 of that credential.
//!
//! This fragment owns the parts of RFC 9449 §4.3 that are the same on host
//! and on-target:
//!
//! - [`proof_key`]: the header checks — `typ`, an `alg` that is asymmetric,
//!   supported and the algorithm of the key the header carries, and a `jwk`
//!   that is present, public and of a supported type (checks 3, 4 and 6);
//! - [`check_proof`]: the claim checks — `htm`, `htu`, `ath`, `iat` and
//!   `jti` (checks 2, 7, 8, 9, 11), with `htu` compared under RFC 3986
//!   syntax- and scheme-based normalization ([`htu_matches`]);
//! - [`ReplayWindow`]: a bounded replay record over `jti` digests (check 10).
//!
//! Signature verification (check 5) is caller-wired (host:
//! `p256`/`ed25519-dalek`; module: the fluxor SDK), since it depends on the
//! injected verify primitive. Binding the proof key to the credential's
//! `cnf.jkt` is the caller's too (see `device_auth`).
//!
//! # The expected `htu`
//!
//! A server compares `htu` with the target URI of the request it received.
//! A module never learns that URI from the request: the `Host` header is
//! written by the client, and a server that built its expectation from it
//! would accept a proof minted for any host the client cares to name. So a
//! verifying module is configured with its own public `origin`
//! (`scheme://authority`, what clients connect to) and the expected target
//! URI is that origin followed by the request's path.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::b64;
use crate::jwk::Sha256Fn;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DpopError {
    /// The header or claims are not a well-formed JSON object, or a member
    /// appears in one more than once.
    Malformed,
    /// Header `typ` is not `dpop+jwt`.
    BadType,
    /// Header `alg` is absent, not asymmetric, not supported, or not the
    /// algorithm of the key the header carries.
    BadAlgorithm,
    /// Header `jwk` is absent, not a supported public key, or carries
    /// private key material.
    BadKey,
    /// A required claim (`htm`/`htu`/`ath`/`iat`/`jti`) is missing.
    MissingClaim,
    /// `htm` or `htu` does not match the request the proof was presented
    /// with, or `htu` is not an `http`/`https` URI within [`MAX_URI`].
    BindingMismatch,
    /// `ath` is not the hash of the credential the proof was presented with.
    TokenMismatch,
    /// `iat` is outside the freshness window.
    Stale,
    /// `jti` was already seen (replay).
    Replay,
}

/// The longest `origin` a module accepts. A fluxor string parameter is at
/// most 255 bytes, so this is the parameter's own bound.
pub const MAX_ORIGIN: usize = 255;

/// The longest URI, as written or as normalized, this fragment compares.
///
/// Wide enough for a [`MAX_ORIGIN`] origin followed by a 256-byte path. A
/// longer one is refused — never compared on a prefix.
pub const MAX_URI: usize = 512;

/// The public key a proof's header carries, after [`proof_key`] has checked
/// it. The coordinates are base64url as written in the `jwk`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProofKey<'a> {
    /// `kty: EC`, `crv: P-256`, `alg: ES256`.
    Es256 { x: &'a [u8], y: &'a [u8] },
    /// `kty: OKP`, `crv: Ed25519`, `alg: EdDSA` or `Ed25519`.
    Ed25519 { x: &'a [u8] },
}

/// The header checks of RFC 9449 §4.3: `typ` is `dpop+jwt`, `jwk` is a
/// supported public key with no private member, and `alg` is the asymmetric
/// algorithm that key signs with.
///
/// `alg` is checked for agreement and never used to choose a verifier: the
/// key type does that, so a header naming `none`, an HMAC or another key's
/// algorithm is refused here rather than routed anywhere.
///
/// `header_json` is the base64url-decoded header segment. Members are read
/// at the top level of the header and of the `jwk` only, so a member of the
/// same name nested elsewhere is never mistaken for one of them.
pub fn proof_key(header_json: &[u8]) -> Result<ProofKey<'_>, DpopError> {
    let header = Object::parse(header_json)?;
    // typ must be dpop+jwt (case-sensitive per RFC 9449).
    if header.string(b"typ")? != Some(&b"dpop+jwt"[..]) {
        return Err(DpopError::BadType);
    }
    let Some(jwk_json) = header.object(b"jwk")? else {
        return Err(DpopError::BadKey);
    };
    let jwk = Object::parse(jwk_json)?;
    // A private key in the header is refused whatever its type: the member
    // is the key's secret, and a prover that publishes it holds nothing.
    if jwk.has(b"d")? {
        return Err(DpopError::BadKey);
    }
    let alg = header.string(b"alg")?.ok_or(DpopError::BadAlgorithm)?;
    let kty = jwk.string(b"kty")?.ok_or(DpopError::BadKey)?;
    let crv = jwk.string(b"crv")?.ok_or(DpopError::BadKey)?;
    let x = jwk.string(b"x")?.ok_or(DpopError::BadKey)?;
    match (kty, crv) {
        (b"EC", b"P-256") => {
            let y = jwk.string(b"y")?.ok_or(DpopError::BadKey)?;
            if alg != b"ES256" {
                return Err(DpopError::BadAlgorithm);
            }
            Ok(ProofKey::Es256 { x, y })
        }
        (b"OKP", b"Ed25519") => {
            // `EdDSA` (RFC 8037) and its fully-specified `Ed25519` (RFC 9864)
            // name the one algorithm this key signs with.
            if alg != b"EdDSA" && alg != b"Ed25519" {
                return Err(DpopError::BadAlgorithm);
            }
            Ok(ProofKey::Ed25519 { x })
        }
        _ => Err(DpopError::BadKey),
    }
}

/// The request a proof must be bound to, and the credential presented with
/// it.
pub struct Binding<'a> {
    /// The HTTP method, as `htm` spells it.
    pub method: &'a [u8],
    /// The verifying module's public origin, `scheme://authority`.
    pub origin: &'a [u8],
    /// The request's path, in origin form. A query, if the path carries one,
    /// is not part of the comparison.
    pub path: &'a [u8],
    /// The credential presented in `Authorization: DPoP`, whose hash `ath`
    /// must carry.
    pub access_token: &'a [u8],
}

/// The validated, request-bound facts extracted from a `DPoP` proof.
pub struct ProofFacts {
    /// `sha256(jti)` — a fixed-width replay key, so the window need not store
    /// variable-length ids.
    pub jti_digest: [u8; 32],
    pub iat: u64,
    /// The first second at which [`check_proof`] refuses this proof as
    /// stale, so the earliest a replay record of it may be forgotten.
    pub replayable_until: u64,
}

/// Claim checks on a `DPoP` proof whose header [`proof_key`] has accepted and
/// whose signature the caller has ALREADY verified with that key.
///
/// Confirms the `htm`/`htu` binding, the `ath` binding to the presented
/// credential, and `iat` freshness; extracts the `jti` digest for the replay
/// window. A proof is fresh when `iat` is no more than `max_age_secs` in the
/// past and no more than `skew_secs` in the future.
///
/// `payload_json` is the base64url-decoded claims segment.
pub fn check_proof(
    sha256: Sha256Fn,
    payload_json: &[u8],
    binding: &Binding<'_>,
    now: u64,
    max_age_secs: u64,
    skew_secs: u64,
) -> Result<ProofFacts, DpopError> {
    let claims = Object::parse(payload_json)?;

    let htm = claims.string(b"htm")?.ok_or(DpopError::MissingClaim)?;
    let htu = claims.string(b"htu")?.ok_or(DpopError::MissingClaim)?;
    if htm != binding.method || !htu_matches(htu, binding.origin, binding.path) {
        return Err(DpopError::BindingMismatch);
    }

    let ath = claims.string(b"ath")?.ok_or(DpopError::MissingClaim)?;
    let mut token_hash = [0u8; 32];
    sha256(binding.access_token, &mut token_hash);
    if ath != b64::encode_digest32(&token_hash) {
        return Err(DpopError::TokenMismatch);
    }

    let iat = claims.integer(b"iat")?.ok_or(DpopError::MissingClaim)?;
    if now.saturating_sub(iat) > max_age_secs || iat > now.saturating_add(skew_secs) {
        return Err(DpopError::Stale);
    }

    let jti = claims.string(b"jti")?.ok_or(DpopError::MissingClaim)?;
    if jti.is_empty() {
        return Err(DpopError::MissingClaim);
    }
    let mut jti_digest = [0u8; 32];
    sha256(jti, &mut jti_digest);

    Ok(ProofFacts {
        jti_digest,
        iat,
        replayable_until: iat.saturating_add(max_age_secs).saturating_add(1),
    })
}

// ── htu: the target-URI comparison ─────────────────────────────────────────

/// Whether `htu` names the request whose expected target URI is `origin`
/// followed by `path`.
///
/// RFC 9449 §4.3 compares `htu` with the request's target URI ignoring query
/// and fragment, after RFC 3986 syntax-based (§6.2.2) and scheme-based
/// (§6.2.3) normalization. Both sides are normalized the same way:
///
/// - the query and fragment are dropped;
/// - the scheme and host are lowercased, and percent-encoded octets have
///   their hex digits uppercased;
/// - a percent-encoded unreserved character (`ALPHA DIGIT - . _ ~`) is
///   decoded;
/// - dot-segments are removed from the path;
/// - a port that is empty or the scheme's default (443 for `https`, 80 for
///   `http`) is dropped, and an empty path is `/`.
///
/// Anything that is not a well-formed `http`/`https` URI — a userinfo, a
/// character outside RFC 3986's set, a broken percent-encoding, a port beyond
/// 65535, an empty host — matches nothing, as does a URI longer than
/// [`MAX_URI`] on either side. `path` must be in origin form (start with
/// `/`).
#[must_use]
pub fn htu_matches(htu: &[u8], origin: &[u8], path: &[u8]) -> bool {
    if path.first() != Some(&b'/') || origin.len() + path.len() > MAX_URI {
        return false;
    }
    let mut expected = [0u8; MAX_URI];
    expected[..origin.len()].copy_from_slice(origin);
    expected[origin.len()..origin.len() + path.len()].copy_from_slice(path);
    let expected = &expected[..origin.len() + path.len()];

    let mut want = [0u8; MAX_URI];
    let mut got = [0u8; MAX_URI];
    let (Some(want_len), Some(got_len)) =
        (normalize(expected, &mut want), normalize(htu, &mut got))
    else {
        return false;
    };
    want[..want_len] == got[..got_len]
}

/// Whether `origin` is a well-formed module origin: `http` or `https`, an
/// authority, and nothing else — no path (not even `/`), query, fragment or
/// userinfo — within [`MAX_ORIGIN`].
///
/// One spelling, so a configured origin cannot carry a path prefix that the
/// request's own path would then be appended to.
#[must_use]
pub fn origin_valid(origin: &[u8]) -> bool {
    if origin.len() > MAX_ORIGIN {
        return false;
    }
    let mut out = [0u8; MAX_URI];
    let mut w = Out::new(&mut out);
    matches!(authority_form(origin, &mut w), Some(end) if end == origin.len())
}

/// A verifying module's declared public origin, held in module state.
///
/// Filled from the module's `origin` parameter and checked once, at
/// construction: a module whose origin is absent or malformed refuses to
/// construct rather than compare every proof against an expectation nobody
/// declared.
#[derive(Clone, Copy)]
pub struct Origin {
    bytes: [u8; MAX_ORIGIN],
    len: usize,
}

impl Origin {
    pub const fn empty() -> Self {
        Self {
            bytes: [0u8; MAX_ORIGIN],
            len: 0,
        }
    }

    /// Take the parameter's value. One longer than [`MAX_ORIGIN`] leaves
    /// the origin empty — refused at construction, never cut to fit.
    pub fn set(&mut self, value: &[u8]) {
        if value.len() > MAX_ORIGIN {
            self.len = 0;
            return;
        }
        self.bytes[..value.len()].copy_from_slice(value);
        self.len = value.len();
    }

    /// The origin, if one was declared and it is well-formed
    /// ([`origin_valid`]).
    #[must_use]
    pub fn declared(&self) -> Option<&[u8]> {
        let origin = &self.bytes[..self.len];
        (!origin.is_empty() && origin_valid(origin)).then_some(origin)
    }

    /// The origin as declared. Only meaningful once [`Self::declared`] has
    /// accepted it, which construction guarantees.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Write the normalized form of `uri` into `out`; its length, or `None` when
/// `uri` is not a well-formed `http`/`https` URI or either side exceeds
/// [`MAX_URI`].
#[must_use]
pub fn normalize(uri: &[u8], out: &mut [u8; MAX_URI]) -> Option<usize> {
    if uri.len() > MAX_URI {
        return None;
    }
    // The query and the fragment are not part of the comparison.
    let end = uri
        .iter()
        .position(|&c| c == b'?' || c == b'#')
        .unwrap_or(uri.len());
    let uri = &uri[..end];

    let mut w = Out::new(out);
    let path_at = authority_form(uri, &mut w)?;
    let path = &uri[path_at..];
    if path.is_empty() {
        w.push(b'/')?;
        return Some(w.len);
    }

    // Percent-encoding normalized first, then dot-segments removed: a
    // `%2E` that decodes to `.` is a dot-segment like any other.
    let mut decoded = [0u8; MAX_URI];
    let mut d = Out::new(&mut decoded);
    let mut i = 0usize;
    while i < path.len() {
        i = pct_char(path, i, &mut d, PATH_CHAR, false)?;
    }
    let decoded_len = d.len;
    remove_dot_segments(&decoded[..decoded_len], &mut w)?;
    Some(w.len)
}

/// Parse and normalize `scheme "://" authority` from the front of `uri` into
/// `w`; the index where the path begins.
fn authority_form(uri: &[u8], w: &mut Out<'_>) -> Option<usize> {
    // scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
    let colon = uri.iter().position(|&c| c == b':')?;
    let scheme = &uri[..colon];
    let default_port: u32 = if scheme.eq_ignore_ascii_case(b"https") {
        443
    } else if scheme.eq_ignore_ascii_case(b"http") {
        80
    } else {
        return None;
    };
    for &c in scheme {
        w.push(c.to_ascii_lowercase())?;
    }
    if uri.get(colon + 1..colon + 3) != Some(&b"//"[..]) {
        return None;
    }
    w.extend(b"://")?;

    let start = colon + 3;
    let auth_end = uri[start..]
        .iter()
        .position(|&c| c == b'/')
        .map_or(uri.len(), |p| start + p);
    let authority = &uri[start..auth_end];
    // RFC 9110 §4.2.4: an http(s) URI carries no userinfo.
    if has_byte(authority, b'@') {
        return None;
    }

    // host = IP-literal / IPv4address / reg-name
    let mut i = 0usize;
    let host_start = w.len;
    if authority.first() == Some(&b'[') {
        let close = authority.iter().position(|&c| c == b']')?;
        let literal = &authority[1..close];
        if literal.is_empty()
            || !literal
                .iter()
                .all(|&c| c.is_ascii_hexdigit() || c == b':' || c == b'.')
        {
            return None;
        }
        w.push(b'[')?;
        for &c in literal {
            w.push(c.to_ascii_lowercase())?;
        }
        w.push(b']')?;
        i = close + 1;
    } else {
        while i < authority.len() && authority[i] != b':' {
            i = pct_char(authority, i, w, HOST_CHAR, true)?;
        }
        if w.len == host_start {
            return None;
        }
    }

    // port = *DIGIT, dropped when empty or the scheme's default.
    if i < authority.len() {
        if authority[i] != b':' {
            return None;
        }
        let digits = &authority[i + 1..];
        if !digits.is_empty() {
            let mut port: u32 = 0;
            for &c in digits {
                if !c.is_ascii_digit() {
                    return None;
                }
                port = port * 10 + u32::from(c - b'0');
                if port > 65_535 {
                    return None;
                }
            }
            if port != default_port {
                w.push(b':')?;
                w.decimal(port)?;
            }
        }
    }
    Some(auth_end)
}

/// Whether `bytes` holds `byte`. A loop rather than `<[u8]>::contains`,
/// which lowers to a `memchr` a module does not link.
fn has_byte(bytes: &[u8], byte: u8) -> bool {
    for &c in bytes {
        if c == byte {
            return true;
        }
    }
    false
}

/// Characters a path may carry unencoded: `pchar` and `/`.
const PATH_CHAR: u8 = 1;
/// Characters a reg-name may carry unencoded: unreserved and sub-delims.
const HOST_CHAR: u8 = 2;

const fn allowed(c: u8, class: u8) -> bool {
    let unreserved = c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~');
    let sub_delim = matches!(
        c,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    );
    match class {
        PATH_CHAR => unreserved || sub_delim || matches!(c, b':' | b'@' | b'/'),
        HOST_CHAR => unreserved || sub_delim,
        _ => false,
    }
}

const fn is_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

const fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Normalize the one character (or percent-encoded octet) of `s` at `i`
/// into `w`; the index after it. A percent-encoded unreserved character is
/// decoded; any other encoding is kept with uppercase hex. `lowercase` folds
/// the case of letters, decoded or not (a host is case-insensitive).
fn pct_char(s: &[u8], i: usize, w: &mut Out<'_>, class: u8, lowercase: bool) -> Option<usize> {
    let c = s[i];
    if c == b'%' {
        let hi = hex_value(*s.get(i + 1)?)?;
        let lo = hex_value(*s.get(i + 2)?)?;
        let octet = (hi << 4) | lo;
        if is_unreserved(octet) {
            w.push(if lowercase {
                octet.to_ascii_lowercase()
            } else {
                octet
            })?;
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            w.push(b'%')?;
            w.push(HEX[usize::from(hi)])?;
            w.push(HEX[usize::from(lo)])?;
        }
        return Some(i + 3);
    }
    if !allowed(c, class) {
        return None;
    }
    w.push(if lowercase { c.to_ascii_lowercase() } else { c })?;
    Some(i + 1)
}

/// RFC 3986 §5.2.4 over an absolute path (one beginning with `/`), appending
/// the result to `w`. The output's own segments are popped in place, so it
/// needs no second buffer.
fn remove_dot_segments(path: &[u8], w: &mut Out<'_>) -> Option<()> {
    let base = w.len;
    let mut i = 0usize;
    while i < path.len() {
        let rest = &path[i..];
        if rest.starts_with(b"/./") {
            // B: "/./" → "/"
            i += 2;
        } else if rest == b"/." {
            // B: "/." → "/"
            w.push(b'/')?;
            i = path.len();
        } else if rest.starts_with(b"/../") {
            // C: "/../" → "/", and drop the last output segment.
            w.pop_segment(base);
            i += 3;
        } else if rest == b"/.." {
            // C: "/.." → "/", and drop the last output segment.
            w.pop_segment(base);
            w.push(b'/')?;
            i = path.len();
        } else {
            // E: move the first segment, "/" included, to the output.
            let seg_end = rest[1..]
                .iter()
                .position(|&c| c == b'/')
                .map_or(rest.len(), |p| p + 1);
            w.extend(&rest[..seg_end])?;
            i += seg_end;
        }
    }
    Some(())
}

/// A bounded writer: a byte that does not fit refuses the whole write.
struct Out<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Out<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    fn push(&mut self, c: u8) -> Option<()> {
        *self.buf.get_mut(self.len)? = c;
        self.len += 1;
        Some(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Option<()> {
        for &c in bytes {
            self.push(c)?;
        }
        Some(())
    }

    fn decimal(&mut self, mut n: u32) -> Option<()> {
        let mut digits = [0u8; 5];
        let mut at = digits.len();
        loop {
            at -= 1;
            digits[at] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        self.extend(&digits[at..])
    }

    /// Drop the last `/segment` written after `base`.
    fn pop_segment(&mut self, base: usize) {
        let written = &self.buf[base..self.len];
        self.len = base + written.iter().rposition(|&c| c == b'/').unwrap_or(0);
    }
}

// ── the JSON the proof is made of ─────────────────────────────────────────

/// One top-level JSON object, read member by member.
///
/// The proof's header nests the `jwk` object inside it, and a reader that
/// scanned for `"kty"` anywhere would take it from wherever it appeared
/// first. This walks members at depth one only, skipping nested values
/// whole, and refuses a member named twice: RFC 7515 leaves duplicates to
/// the parser, and two parsers choosing differently is how one proof comes
/// to mean two things.
struct Object<'a> {
    json: &'a [u8],
}

/// A member's value: a string's raw content (escapes not decoded — every
/// value compared here is an escape-free token, so an escaped one compares
/// unequal), an object's bytes, or any other value's bytes.
#[derive(Clone, Copy)]
enum Value<'a> {
    Str(&'a [u8]),
    Object(&'a [u8]),
    Other(&'a [u8]),
}

const fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

impl<'a> Object<'a> {
    /// Check `json` is one well-formed object, its members walkable.
    fn parse(json: &'a [u8]) -> Result<Self, DpopError> {
        let object = Self { json };
        object.find(b"")?;
        Ok(object)
    }

    fn string(&self, key: &[u8]) -> Result<Option<&'a [u8]>, DpopError> {
        match self.find(key)? {
            Some(Value::Str(s)) => Ok(Some(s)),
            Some(_) => Err(DpopError::Malformed),
            None => Ok(None),
        }
    }

    fn object(&self, key: &[u8]) -> Result<Option<&'a [u8]>, DpopError> {
        match self.find(key)? {
            Some(Value::Object(o)) => Ok(Some(o)),
            Some(_) => Err(DpopError::Malformed),
            None => Ok(None),
        }
    }

    fn has(&self, key: &[u8]) -> Result<bool, DpopError> {
        Ok(self.find(key)?.is_some())
    }

    /// A non-negative integer member: digits only, no sign, fraction or
    /// exponent.
    fn integer(&self, key: &[u8]) -> Result<Option<u64>, DpopError> {
        let Some(value) = self.find(key)? else {
            return Ok(None);
        };
        let Value::Other(digits) = value else {
            return Err(DpopError::Malformed);
        };
        if digits.is_empty() {
            return Err(DpopError::Malformed);
        }
        let mut n: u64 = 0;
        for &c in digits {
            if !c.is_ascii_digit() {
                return Err(DpopError::Malformed);
            }
            n = n
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(c - b'0')))
                .ok_or(DpopError::Malformed)?;
        }
        Ok(Some(n))
    }

    /// Walk every member; the value of `key`, if present once. An empty
    /// `key` matches nothing, which makes this the well-formedness check.
    fn find(&self, key: &[u8]) -> Result<Option<Value<'a>>, DpopError> {
        let json = self.json;
        let mut i = skip_ws(json, 0);
        if json.get(i) != Some(&b'{') {
            return Err(DpopError::Malformed);
        }
        i = skip_ws(json, i + 1);
        let mut found: Option<Value<'a>> = None;
        if json.get(i) == Some(&b'}') {
            return trailing(json, i + 1, found);
        }
        loop {
            let (name, after) = string_at(json, i)?;
            i = skip_ws(json, after);
            if json.get(i) != Some(&b':') {
                return Err(DpopError::Malformed);
            }
            i = skip_ws(json, i + 1);
            let (value, after) = value_at(json, i)?;
            if !key.is_empty() && name == key {
                if found.is_some() {
                    return Err(DpopError::Malformed);
                }
                found = Some(value);
            }
            i = skip_ws(json, after);
            match json.get(i) {
                Some(b',') => i = skip_ws(json, i + 1),
                Some(b'}') => return trailing(json, i + 1, found),
                _ => return Err(DpopError::Malformed),
            }
        }
    }
}

fn skip_ws(json: &[u8], mut i: usize) -> usize {
    while i < json.len() && is_ws(json[i]) {
        i += 1;
    }
    i
}

/// Nothing but whitespace may follow the closing brace.
fn trailing<'a>(
    json: &[u8],
    i: usize,
    found: Option<Value<'a>>,
) -> Result<Option<Value<'a>>, DpopError> {
    if skip_ws(json, i) == json.len() {
        Ok(found)
    } else {
        Err(DpopError::Malformed)
    }
}

/// The raw content of the string starting at `json[i]`, and the index after
/// its closing quote.
fn string_at(json: &[u8], i: usize) -> Result<(&[u8], usize), DpopError> {
    if json.get(i) != Some(&b'"') {
        return Err(DpopError::Malformed);
    }
    let start = i + 1;
    let mut j = start;
    while j < json.len() {
        match json[j] {
            b'\\' => j += 2,
            b'"' => return Ok((&json[start..j], j + 1)),
            c if c < 0x20 => return Err(DpopError::Malformed),
            _ => j += 1,
        }
    }
    Err(DpopError::Malformed)
}

/// The value starting at `json[i]`, and the index after it. A nested object
/// or array is skipped whole, by depth, without recursion.
fn value_at(json: &[u8], i: usize) -> Result<(Value<'_>, usize), DpopError> {
    match json.get(i) {
        Some(b'"') => {
            let (s, after) = string_at(json, i)?;
            Ok((Value::Str(s), after))
        }
        Some(&open @ (b'{' | b'[')) => {
            let mut depth = 0usize;
            let mut j = i;
            while j < json.len() {
                match json[j] {
                    b'"' => {
                        j = string_at(json, j)?.1;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            let raw = &json[i..=j];
                            let value = if open == b'{' {
                                Value::Object(raw)
                            } else {
                                Value::Other(raw)
                            };
                            return Ok((value, j + 1));
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            Err(DpopError::Malformed)
        }
        Some(_) => {
            let mut j = i;
            while j < json.len() && !matches!(json[j], b',' | b'}' | b']') && !is_ws(json[j]) {
                j += 1;
            }
            if j == i {
                return Err(DpopError::Malformed);
            }
            Ok((Value::Other(&json[i..j]), j))
        }
        None => Err(DpopError::Malformed),
    }
}

// ── replay ────────────────────────────────────────────────────────────────

/// The outcome of offering a proof to the replay window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Replay {
    /// New, and recorded.
    Recorded,
    /// Already seen inside its freshness window.
    Seen,
    /// The window is full of entries that are all still fresh.
    ///
    /// A refusal, and a DIFFERENT one from `Seen`: the caller refuses either
    /// way, but an operator needs to tell "somebody replayed a proof" from
    /// "the window is saturated", because the second means the deployment is
    /// under a load its window cannot cover and the first does not.
    Full,
}

/// A bounded replay window over `jti` digests.
///
/// # Why this fails closed instead of evicting
///
/// A ring that overwrote its oldest entry when full would be safe only if
/// its coverage exceeded the proof freshness window, so that an evicted
/// entry's proof was already too old to reuse. At any fixed size that
/// argument fails to an attacker who sends more distinct proofs inside the
/// freshness window than the ring holds: the earliest entry is evicted while
/// its proof is still fresh, and that proof can then be replayed.
///
/// So a slot is reusable only once the proof it holds has aged past its own
/// freshness window, at which point `check_proof` would refuse that proof
/// anyway and forgetting it costs nothing. When no slot has aged out, the
/// window answers [`Replay::Full`] and the caller refuses. An eviction under
/// load is an admission under load, so the load has to be what breaks.
pub struct ReplayWindow<const N: usize> {
    digests: [[u8; 32]; N],
    /// When each entry stops mattering: the first second at which
    /// `check_proof` refuses the proof as stale
    /// ([`ProofFacts::replayable_until`]). `0` marks a free slot.
    ///
    /// Held per entry rather than derived, because the window a proof was
    /// checked under is a property of the policy that admitted it, and a
    /// policy change must not retroactively shorten what is remembered.
    expires_at: [u64; N],
}

impl<const N: usize> ReplayWindow<N> {
    pub const fn new() -> Self {
        Self {
            digests: [[0u8; 32]; N],
            expires_at: [0u64; N],
        }
    }

    /// Offer `digest` to the window.
    ///
    /// `expires_at` is when this proof stops being replayable —
    /// [`ProofFacts::replayable_until`]. `now` is the current time in
    /// seconds.
    pub fn offer(&mut self, digest: &[u8; 32], now: u64, expires_at: u64) -> Replay {
        let mut free: Option<usize> = None;
        for i in 0..N {
            let live = self.expires_at[i] != 0 && now < self.expires_at[i];
            if live {
                if self.digests[i] == *digest {
                    return Replay::Seen;
                }
            } else if free.is_none() {
                // A free slot, or one whose proof has aged past the point
                // where `check_proof` would accept it anyway.
                free = Some(i);
            }
        }
        match free {
            Some(i) => {
                self.digests[i] = *digest;
                self.expires_at[i] = expires_at;
                Replay::Recorded
            }
            None => Replay::Full,
        }
    }

    /// How many entries are still live at `now`.
    ///
    /// For an operator gauge: a window sitting near `N` is one about to
    /// start refusing, which is worth knowing before it does.
    #[must_use]
    pub fn live(&self, now: u64) -> usize {
        (0..N)
            .filter(|&i| self.expires_at[i] != 0 && now < self.expires_at[i])
            .count()
    }
}

impl<const N: usize> Default for ReplayWindow<N> {
    fn default() -> Self {
        Self::new()
    }
}

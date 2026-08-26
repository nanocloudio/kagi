//! Wire format for kagi inter-module channel messages.
//!
//! Every message uses Kagi's 3-byte envelope over Fluxor byte-stream ports:
//!   `[msg_type: u8] [len: u16 LE] [payload: len bytes]`
//!
//! ## Stability
//!
//! This is v1. There is one layout per message and it is the one below.
//!
//! It is changed in place when it needs to change: every producer,
//! consumer, fixture and graph moves in the same commit, and no
//! higher-numbered surface, compatibility shim, dual decoder or retained
//! opcode is left behind. Nothing here is provisional, and no id is
//! reserved against a promotion that might never come: a surface nobody
//! may depend on is a surface whose encodings drift.
//!
//! Consumers still go through the encode/decode helpers rather than raw
//! offsets — not because the layout is unstable, but because the helpers
//! are where the length and range checks live.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

#[path = "suite.rs"]
pub mod suite_mod;
pub use suite_mod as suite;

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

// ── Keyset lifecycle ────────────────────────────────────────────────────
//
// Rotation needs two live keys at once. A latest-wins key delivery cannot
// express that: the instant a new key arrives every credential signed
// under the old one stops verifying, there is no way to load a key before
// making it active, and no way to keep verifying a retired key while its
// credentials age out.
//
// A keyset is indexed by `(issuer, profile_id, kid)` and holds more than
// one live entry. The verbs below are the whole lifecycle, in the order a
// rotation uses them: ADD (loaded, not yet signing), ACTIVATE (signs new
// credentials), RETIRE (still verifies, no longer signs), REMOVE (gone).

/// Add a key to a keyset without making it active. See [`KeyRecord`].
///
/// Loading and activating are separate because they are separate decisions
/// with a deliberate gap between them: every verifier must hold the key
/// before anything signs with it, or the first credential minted under it
/// is unverifiable everywhere that has not caught up.
pub const MSG_KEY_ADD: u8 = 0x22;
/// Make an added key the one new credentials are signed under.
/// Payload: `[issuer f8][profile_id u16 LE][kid f8][generation u32 LE]`.
pub const MSG_KEY_ACTIVATE: u8 = 0x23;
/// Stop signing with a key; keep verifying it.
/// Payload: `[issuer f8][profile_id u16 LE][kid f8][remove_after_unix u64 LE]`.
///
/// `remove_after_unix` is the deadline past which a verifier drops the key
/// — it must outlast the longest credential the key ever signed, or a
/// credential that is still inside its own validity window stops verifying.
pub const MSG_KEY_RETIRE: u8 = 0x24;
/// Drop a key entirely. Payload: `[issuer f8][profile_id u16 LE][kid f8]`.
///
/// Immediate and unconditional: this is the revocation path, for a key
/// believed compromised, where credentials signed under it are supposed to
/// stop verifying.
pub const MSG_KEY_REMOVE: u8 = 0x25;
/// The whole keyset, as one message: `[count u16 LE]` then `count`
/// [`KeyRecord`] payloads.
///
/// How a verifier that just started reaches current state. Without it a
/// restarting verifier holds nothing until the next rotation, which may be
/// months away — it would reject every credential in the system and call
/// it an unknown kid.
pub const MSG_KEYSET_SNAPSHOT: u8 = 0x26;

// token_mint
pub const MSG_MINT_REQ: u8 = 0x31;
pub const MSG_MINT_RESP: u8 = 0x32;

// admission
/// Ask admission whether a presenter may mint, and for whom.
pub const MSG_ADMIT_REQ: u8 = 0x35;
/// Admission's typed verdict.
pub const MSG_ADMIT_RESP: u8 = 0x36;
/// Ask admission to admit AND mint in one exchange: the /oauth/token slice.
pub const MSG_GRANT_REQ: u8 = 0x37;
/// The grant's answer: a token, or a typed refusal.
pub const MSG_GRANT_RESP: u8 = 0x38;
/// OIDC /authorize: authenticate a subject and issue an authorization code.
pub const MSG_AUTHORIZE_REQ: u8 = 0x39;
/// The authorize answer: a code + the state to echo, or a typed refusal.
pub const MSG_AUTHORIZE_RESP: u8 = 0x3A;
/// OIDC token code-exchange: redeem a code for an access + ID token.
pub const MSG_CODE_EXCHANGE_REQ: u8 = 0x3B;
/// The exchange answer: an access token + an ID token, or a typed refusal.
pub const MSG_CODE_EXCHANGE_RESP: u8 = 0x3C;

// token_verify
/// Verify request: a [`VerifyRequest`] — the credential AND the policy it
/// must satisfy.
///
/// The policy travels with the request because the alternative is the
/// caller checking it afterwards, which is the arrangement that put an
/// audience check in five places and got it slightly different in each.
/// An OPERATOR asks the issuer to authorise one enrolment.
///
/// `[corr u32][purpose u8][ttl_seconds u32][audience f16]`
///
/// This is what a QR ceremony rests on. Enrolment normally proves control of
/// a mailbox — a code is mailed and must come back. A device being enrolled
/// from a QR code proves no such thing, so something else has to carry the
/// authorisation, and this is it: a single-use, short-lived secret the
/// ISSUER minted and an operator carried to the device out of band.
///
/// **It travels on the control plane, and that is not a widening.** The
/// control socket already pushes [`MSG_KEY_ADD`] into the mint, so anyone
/// holding an operator credential can already install a signing key of their
/// choosing and mint anything the deployment can mint. Permission to
/// authorise one enrolment is strictly less than that, so siting it here
/// adds no authority the credential did not already carry — where a separate
/// listener would have added a second credential and a second trust anchor
/// to gate something the first already implied.
pub const MSG_ENROL_AUTH_REQ: u8 = 0x53;

/// The issuer's answer: the transaction and its code, once.
///
/// `[corr u32][status u8][auth_id f8][secret f8][expires_at u64]`
///
/// `auth_id` is the transaction's NONCE and `secret` is its CODE — the same
/// two values the mail path produces, delivered to an operator instead of to
/// a mailbox. That is the whole of the QR ceremony: **one delivery channel
/// swapped for another, over an unchanged transaction.** A separate
/// authorisation object was drafted and dropped; it would have been a second
/// single-use secret guarding a first, and `/redeem` would have had to know
/// which kind it was looking at.
///
/// **The code is returned exactly once and never stored.** What the ledger
/// holds is `HMAC-SHA256(k, nonce ‖ code)`, as for a mailed code: a read of
/// the store must not yield a working credential. An operator who loses it
/// mints another; there is deliberately no way to ask for it again.
///
/// A refusal carries an empty `auth_id` and `secret`, so a caller that
/// ignored `status` has nothing that looks like an authorisation.
pub const MSG_ENROL_AUTH_RESP: u8 = 0x54;

/// A device id the issuer no longer stands behind.
///
/// `[id f8]`. It travels the control plane and reaches `wellknown_endpoint`,
/// which records it in the ledger and then in the published filter.
///
/// Declared here rather than in the module that reads it, so the number is
/// visible to everything else choosing one. A control channel is fanned to
/// several modules and each takes only its own type, which holds exactly as
/// long as no two types share a number.
pub const MSG_REVOKE: u8 = 0x51;

pub const MSG_VERIFY_REQ: u8 = 0x42;
/// Verify response: a typed [`VerifiedIdentity`], not claims JSON.
///
/// It used to hand back the decoded JWS payload so the caller could
/// authorize on `iss`/`aud`/`scope`. That meant every consumer re-parsed
/// attacker-controlled JSON to make an authorization decision, and each one
/// had its own parser, its own idea of a missing claim, and its own
/// behaviour on a duplicate key. The module verified the token and then
/// handed the hard part back.
///
/// The fields a decision is made on are now extracted once, by the module
/// that already had to parse them to check the signature, and delivered as
/// typed values. Application claims outside the reserved set stay opaque —
/// they travel as bytes and are not authorization inputs.
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
/// `security_state`: a conditional write lost its race. A `put_if_absent`
/// found the key present, or a `compare_and_swap` was handed a stale etag.
/// The caller did not win, and must not act as though it had.
pub const ST_CONFLICT: u8 = 8;
/// `security_state`: there is no durable store to answer from.
///
/// Distinct from `ST_NOT_FOUND` on purpose, and the distinction is the whole
/// fail-closed contract: "the ledger says no such device" and "there is no
/// ledger" must never look the same to a caller deciding whether to issue a
/// credential.
pub const ST_UNAVAILABLE: u8 = 9;

// ── Envelope ────────────────────────────────────────────────────────────

pub const ENVELOPE: usize = 3;
pub const MAX_PAYLOAD: usize = u16::MAX as usize;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireError {
    BufferTooSmall,
    Truncated,
    FieldTooLong,
    /// A reply's status and its payload contradict each other: a refusal
    /// carrying a token, or an OK carrying none. Distinct from a length
    /// error because nothing about it is a size — the message is internally
    /// inconsistent, and a caller that ignored `status` must not be handed
    /// something token-shaped.
    Inconsistent,
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

    pub fn u16(&mut self, v: u16) -> Result<(), WireError> {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u32(&mut self, v: u32) -> Result<(), WireError> {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u64(&mut self, v: u64) -> Result<(), WireError> {
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

    pub fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
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

/// What is being asked of the issuer.
///
/// Separate from `profile_id`, which says what the credential IS. A
/// re-issue and a first issue of the same profile take the same inputs and
/// produce the same shape, but only one of them may be asked for without a
/// prior credential — so the issuer has to be told which, and cannot infer
/// it from the profile.
pub mod request_type {
    /// Issue a fresh credential.
    pub const MINT: u8 = 1;
    /// Re-issue against a credential the caller already holds, carried in
    /// the request's extra claims. The subject is not re-chosen.
    pub const REISSUE: u8 = 2;
    /// Sign a challenge that is not itself a credential — it authorises
    /// nothing and is only ever presented back to this issuer.
    pub const SIGN_CHALLENGE: u8 = 3;
}

/// Ask whether a presenter may mint, and for whom: payload of
/// [`MSG_ADMIT_REQ`].
///
/// ```text
/// [corr u32 LE]
/// [method f8][uri f16]
/// [credential f16][proof f16]
/// ```
///
/// `method` and `uri` are the request the DPoP proof must be bound to, and
/// they travel because the proof's binding is checked against the request
/// that actually arrived — not one the admitter assumes.
///
/// **Nothing here names a subject, an audience or a key binding.** That is
/// why this message exists: admission derives them from the credential, and
/// a caller that could suggest them would be choosing what it is asking
/// permission for.
pub struct AdmitRequest<'a> {
    pub corr: u32,
    pub method: &'a [u8],
    pub uri: &'a [u8],
    pub credential: &'a [u8],
    pub proof: &'a [u8],
}

impl<'a> AdmitRequest<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut payload = [0u8; 4096];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.corr)?;
        w.field8(self.method)?;
        w.field16(self.uri)?;
        w.field16(self.credential)?;
        w.field16(self.proof)?;
        let n = w.len();
        write_envelope(MSG_ADMIT_REQ, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let corr = r.u32()?;
        let method = r.field8()?;
        let uri = r.field16()?;
        let credential = r.field16()?;
        let proof = r.field16()?;
        // An empty credential or proof is refused at DECODE rather than
        // handed to the authenticator as "absent". The authenticator judges
        // a presentation; nothing was presented here, and a module that has
        // to decide what an empty presentation means is one that can decide
        // wrongly.
        if credential.is_empty() || proof.is_empty() || method.is_empty() {
            return Err(WireError::FieldTooLong);
        }
        Ok(Self {
            corr,
            method,
            uri,
            credential,
            proof,
        })
    }
}

/// What admission decided: payload of [`MSG_ADMIT_RESP`].
///
/// ```text
/// [corr u32 LE]
/// [status u8]            // admit_err::*
/// [sub f16][device_id f16][thumbprint_alg u8][jkt f8]
/// ```
///
/// **A refusal carries none of them**, checked at decode. The fields say who
/// the presenter turned out to be; a refusal established nobody, and a reply
/// carrying a subject anyway would let a caller that ignored `status` mint
/// for whoever it named.
pub struct AdmitResponse<'a> {
    pub corr: u32,
    pub status: u8,
    pub sub: &'a [u8],
    pub device_id: &'a [u8],
    pub thumbprint_alg: u8,
    pub jkt: &'a [u8],
}

impl<'a> AdmitResponse<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        if self.status != admit_err::OK
            && !(self.sub.is_empty() && self.device_id.is_empty() && self.jkt.is_empty())
        {
            return Err(WireError::FieldTooLong);
        }
        let mut payload = [0u8; 1024];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.corr)?;
        w.u8(self.status)?;
        w.field16(self.sub)?;
        w.field16(self.device_id)?;
        w.u8(self.thumbprint_alg)?;
        w.field8(self.jkt)?;
        let n = w.len();
        write_envelope(MSG_ADMIT_RESP, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let corr = r.u32()?;
        let status = r.u8()?;
        let sub = r.field16()?;
        let device_id = r.field16()?;
        let thumbprint_alg = r.u8()?;
        let jkt = r.field8()?;
        // A refusal that carries an identity is rejected rather than
        // trusted-and-ignored: the rule `MintResponse` and
        // `VerifiedIdentity` already enforce on their own wires.
        if status != admit_err::OK && !(sub.is_empty() && device_id.is_empty() && jkt.is_empty()) {
            return Err(WireError::FieldTooLong);
        }
        // And an admission that establishes nobody is not an admission.
        if status == admit_err::OK && (sub.is_empty() || device_id.is_empty() || jkt.is_empty()) {
            return Err(WireError::FieldTooLong);
        }
        if !jkt.is_empty() && jkt.len() != suite::thumbprint::len(thumbprint_alg) {
            return Err(WireError::FieldTooLong);
        }
        Ok(Self {
            corr,
            status,
            sub,
            device_id,
            thumbprint_alg,
            jkt,
        })
    }
}

/// Ask admission to admit a presenter AND mint it a token, in one exchange:
/// payload of [`MSG_GRANT_REQ`], the /oauth/token slice.
///
/// ```text
/// [corr u32 LE]
/// [method f8][uri f16]
/// [credential f16][proof f16]
/// ```
///
/// **This is `AdmitRequest` plus nothing.** It carries no subject, no
/// audience, no scope, no lifetime — a client presenting a device credential
/// gets a token whose subject and key binding come from the credential
/// (established by admission) and whose audience, scope and lifetime are the
/// deployment's policy (params on the admitter). A client cannot ASK for a
/// wider audience or a longer life because there is no field to ask in, which
/// is how the widening `token_mint` would otherwise sign verbatim is closed
/// at the source.
///
/// Unlike [`AdmitRequest`], an empty credential DECODES (the correlation is
/// intact and must be answered): a `GET /oauth/token`, a wrong path, or an
/// empty body has to receive a refusal, not vanish. The emptiness is refused
/// in the handler, not at decode.
pub struct GrantRequest<'a> {
    pub corr: u32,
    pub method: &'a [u8],
    pub uri: &'a [u8],
    pub credential: &'a [u8],
    pub proof: &'a [u8],
}

impl<'a> GrantRequest<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut payload = [0u8; 4096];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.corr)?;
        w.field8(self.method)?;
        w.field16(self.uri)?;
        w.field16(self.credential)?;
        w.field16(self.proof)?;
        let n = w.len();
        write_envelope(MSG_GRANT_REQ, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let corr = r.u32()?;
        let method = r.field8()?;
        let uri = r.field16()?;
        let credential = r.field16()?;
        let proof = r.field16()?;
        Ok(Self {
            corr,
            method,
            uri,
            credential,
            proof,
        })
    }
}

/// The grant's answer: payload of [`MSG_GRANT_RESP`].
///
/// ```text
/// [corr u32 LE]
/// [status u8]        // grant_err::* — OK carries the token, refusals nothing
/// [token f16]
/// ```
///
/// A refusal carrying a token is rejected at decode, the rule every other
/// reply on this wire enforces: a caller that ignored `status` must not end
/// up holding something token-shaped.
pub struct GrantResponse<'a> {
    pub corr: u32,
    pub status: u8,
    pub token: &'a [u8],
}

impl<'a> GrantResponse<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        if self.status != grant_err::OK && !self.token.is_empty() {
            return Err(WireError::Inconsistent);
        }
        let mut payload = [0u8; MAX_INLINE_CREDENTIAL + 16];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.corr)?;
        w.u8(self.status)?;
        w.field16(self.token)?;
        let n = w.len();
        write_envelope(MSG_GRANT_RESP, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let corr = r.u32()?;
        let status = r.u8()?;
        let token = r.field16()?;
        if status != grant_err::OK && !token.is_empty() {
            return Err(WireError::Inconsistent);
        }
        if status == grant_err::OK && token.is_empty() {
            return Err(WireError::Inconsistent);
        }
        Ok(Self {
            corr,
            status,
            token,
        })
    }
}

/// OIDC /authorize request: the client's ask, plus the subject's device
/// presentation. Payload of [`MSG_AUTHORIZE_REQ`].
///
/// ```text
/// [corr u32][method f8][uri f16]
/// [credential f16][proof f16]        // the subject's dc+jwt + DPoP
/// [client_id f8][redirect_uri f16][scope f16][state f16]
/// [code_challenge f8][nonce f16]     // PKCE S256; nonce may be empty
/// ```
///
/// The subject is established from the credential (kagi), never named. The
/// client's `scope` is a REQUEST — authcode clamps it against the registered
/// client before anything is signed, because `token_mint` signs scope
/// verbatim. An empty credential decodes (its corr must be answered).
pub struct AuthorizeRequest<'a> {
    pub corr: u32,
    pub method: &'a [u8],
    pub uri: &'a [u8],
    pub credential: &'a [u8],
    pub proof: &'a [u8],
    pub client_id: &'a [u8],
    pub redirect_uri: &'a [u8],
    pub scope: &'a [u8],
    pub state: &'a [u8],
    pub code_challenge: &'a [u8],
    pub nonce: &'a [u8],
}

impl<'a> AuthorizeRequest<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut payload = [0u8; 4096];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.corr)?;
        w.field8(self.method)?;
        w.field16(self.uri)?;
        w.field16(self.credential)?;
        w.field16(self.proof)?;
        w.field8(self.client_id)?;
        w.field16(self.redirect_uri)?;
        w.field16(self.scope)?;
        w.field16(self.state)?;
        w.field8(self.code_challenge)?;
        w.field16(self.nonce)?;
        let n = w.len();
        write_envelope(MSG_AUTHORIZE_REQ, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let corr = r.u32()?;
        let method = r.field8()?;
        let uri = r.field16()?;
        let credential = r.field16()?;
        let proof = r.field16()?;
        let client_id = r.field8()?;
        let redirect_uri = r.field16()?;
        let scope = r.field16()?;
        let state = r.field16()?;
        let code_challenge = r.field8()?;
        let nonce = r.field16()?;
        Ok(Self {
            corr,
            method,
            uri,
            credential,
            proof,
            client_id,
            redirect_uri,
            scope,
            state,
            code_challenge,
            nonce,
        })
    }
}

/// The /authorize answer: payload of [`MSG_AUTHORIZE_RESP`].
///
/// ```text
/// [corr u32][status u8]
/// [code f16][redirect_uri f16][state f16]
/// ```
///
/// On OK the reply carries the single-use code, the kagi-APPROVED
/// redirect_uri (so the pipeline builds the 302 from a kagi verdict, not the
/// client's raw input), and the state to echo. A refusal carries none of the
/// three, checked at decode.
pub struct AuthorizeResponse<'a> {
    pub corr: u32,
    pub status: u8,
    pub code: &'a [u8],
    pub redirect_uri: &'a [u8],
    pub state: &'a [u8],
}

impl<'a> AuthorizeResponse<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        if self.status != authz_err::OK
            && !(self.code.is_empty() && self.redirect_uri.is_empty() && self.state.is_empty())
        {
            return Err(WireError::Inconsistent);
        }
        let mut payload = [0u8; 1024];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.corr)?;
        w.u8(self.status)?;
        w.field16(self.code)?;
        w.field16(self.redirect_uri)?;
        w.field16(self.state)?;
        let n = w.len();
        write_envelope(MSG_AUTHORIZE_RESP, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let corr = r.u32()?;
        let status = r.u8()?;
        let code = r.field16()?;
        let redirect_uri = r.field16()?;
        let state = r.field16()?;
        if status != authz_err::OK
            && !(code.is_empty() && redirect_uri.is_empty() && state.is_empty())
        {
            return Err(WireError::Inconsistent);
        }
        if status == authz_err::OK && code.is_empty() {
            return Err(WireError::Inconsistent);
        }
        Ok(Self {
            corr,
            status,
            code,
            redirect_uri,
            state,
        })
    }
}

/// Token code-exchange request: payload of [`MSG_CODE_EXCHANGE_REQ`].
///
/// ```text
/// [corr u32]
/// [code f16][redirect_uri f16][client_id f8][code_verifier f16]
/// ```
///
/// No subject credential: the code (single-use) plus the PKCE verifier ARE
/// the proof, and the code carries the subject authcode established at
/// /authorize.
pub struct CodeExchangeRequest<'a> {
    pub corr: u32,
    pub code: &'a [u8],
    pub redirect_uri: &'a [u8],
    pub client_id: &'a [u8],
    pub code_verifier: &'a [u8],
}

impl<'a> CodeExchangeRequest<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut payload = [0u8; 2048];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.corr)?;
        w.field16(self.code)?;
        w.field16(self.redirect_uri)?;
        w.field8(self.client_id)?;
        w.field16(self.code_verifier)?;
        let n = w.len();
        write_envelope(MSG_CODE_EXCHANGE_REQ, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let corr = r.u32()?;
        let code = r.field16()?;
        let redirect_uri = r.field16()?;
        let client_id = r.field8()?;
        let code_verifier = r.field16()?;
        Ok(Self {
            corr,
            code,
            redirect_uri,
            client_id,
            code_verifier,
        })
    }
}

/// The exchange answer: payload of [`MSG_CODE_EXCHANGE_RESP`].
///
/// ```text
/// [corr u32][status u8][access_token f16][id_token f16]
/// ```
///
/// OK carries both tokens; a refusal carries neither, checked at decode.
pub struct CodeExchangeResponse<'a> {
    pub corr: u32,
    pub status: u8,
    pub access_token: &'a [u8],
    pub id_token: &'a [u8],
}

impl<'a> CodeExchangeResponse<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        if self.status != authz_err::OK
            && !(self.access_token.is_empty() && self.id_token.is_empty())
        {
            return Err(WireError::Inconsistent);
        }
        let mut payload = [0u8; MAX_INLINE_CREDENTIAL + 16];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.corr)?;
        w.u8(self.status)?;
        w.field16(self.access_token)?;
        w.field16(self.id_token)?;
        let n = w.len();
        write_envelope(MSG_CODE_EXCHANGE_RESP, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let corr = r.u32()?;
        let status = r.u8()?;
        let access_token = r.field16()?;
        let id_token = r.field16()?;
        if status != authz_err::OK && !(access_token.is_empty() && id_token.is_empty()) {
            return Err(WireError::Inconsistent);
        }
        if status == authz_err::OK && (access_token.is_empty() || id_token.is_empty()) {
            return Err(WireError::Inconsistent);
        }
        Ok(Self {
            corr,
            status,
            access_token,
            id_token,
        })
    }
}

/// Typed reasons for [`AuthorizeResponse`] and [`CodeExchangeResponse`].
///
/// `OK` shares 0 with the other reply families so one status map serves all.
/// The /authorize reasons and the exchange reasons live in one namespace
/// because both are the authorization-code flow, and a reader tracing a
/// flow reads them together.
pub mod authz_err {
    pub const OK: u8 = 0;
    /// /authorize: the subject's credential did not authenticate.
    pub const UNAUTHENTICATED: u8 = 1;
    /// /authorize: no such registered client.
    pub const UNKNOWN_CLIENT: u8 = 2;
    /// /authorize: the redirect_uri is not one the client registered.
    pub const BAD_REDIRECT: u8 = 3;
    /// /authorize: no PKCE code_challenge (S256 is mandatory).
    pub const NO_PKCE: u8 = 4;
    /// exchange: the code is unknown, expired, or already redeemed.
    pub const INVALID_GRANT: u8 = 5;
    /// exchange: the code_verifier does not match the code_challenge.
    pub const PKCE_FAILED: u8 = 6;
    /// exchange: client_id or redirect_uri does not match the code's binding.
    pub const MISMATCH: u8 = 7;
    /// The ledger could not be reached — enrolment/registry/code all unknown.
    pub const STATE_UNAVAILABLE: u8 = 8;
    /// No trustworthy clock, so no window can be judged.
    pub const NO_CLOCK: u8 = 9;
    /// No verification keyset (authorize) or no signing key (exchange).
    pub const NO_KEY: u8 = 10;
    /// The request did not decode, or a required field was empty.
    pub const MALFORMED: u8 = 11;
    /// /authorize: the DPoP proof was seen before, or the replay window is
    /// saturated. Both refuse — an eviction under load would be an
    /// admission under load.
    pub const REPLAY: u8 = 12;
    /// Admitted and redeemed, but a token mint failed. Always a 5xx.
    pub const MINT_FAILED: u8 = 20;
}

/// Typed reasons for [`GrantResponse`].
///
/// For refusals this MIRRORS [`admit_err`] numerically — a grant refusal at
/// the admission stage is an admission refusal, and reusing the numbers lets
/// one mapping serve both. `MINT_FAILED` is the one reason admission cannot
/// give: the presenter was admitted and the SIGNING then failed (a bad key, a
/// vault refusal, a credential too large for an inline token). It is a 5xx to
/// the client, never a 4xx — nothing about the presenter was wrong.
pub mod grant_err {
    pub const OK: u8 = super::admit_err::OK;
    pub const UNAUTHENTICATED: u8 = super::admit_err::UNAUTHENTICATED;
    pub const UNKNOWN_DEVICE: u8 = super::admit_err::UNKNOWN_DEVICE;
    pub const REVOKED: u8 = super::admit_err::REVOKED;
    pub const NOT_PERMITTED: u8 = super::admit_err::NOT_PERMITTED;
    pub const STALE_PROOF: u8 = super::admit_err::STALE_PROOF;
    pub const REPLAY: u8 = super::admit_err::REPLAY;
    pub const STATE_UNAVAILABLE: u8 = super::admit_err::STATE_UNAVAILABLE;
    pub const NO_CLOCK: u8 = super::admit_err::NO_CLOCK;
    pub const NO_KEY: u8 = super::admit_err::NO_KEY;
    pub const MALFORMED: u8 = super::admit_err::MALFORMED;
    /// Admitted, but the mint refused. Always a 5xx.
    pub const MINT_FAILED: u8 = 20;
}

/// Typed refusal reasons for [`AdmitResponse`].
///
/// Separate from `mint_err` because they answer a different question. A mint
/// refusal is about the credential being ASKED FOR; these are about the
/// presenter's right to ask. Collapsing them would put "your proof was
/// replayed" and "that lifetime is too long" in one namespace, and an
/// operator reading a log could not tell which layer refused.
pub mod admit_err {
    /// Admitted. The reply carries the subject, device and key binding the
    /// credential established.
    pub const OK: u8 = 0;
    /// No credential, no proof, or one that did not verify against the key
    /// its own header names.
    pub const UNAUTHENTICATED: u8 = 1;
    /// Authenticated, but the ledger holds no such device.
    pub const UNKNOWN_DEVICE: u8 = 2;
    /// The ledger holds the device as revoked.
    pub const REVOKED: u8 = 3;
    /// Authenticated and enrolled, but not permitted what was asked.
    pub const NOT_PERMITTED: u8 = 4;
    /// The proof is outside its freshness window.
    pub const STALE_PROOF: u8 = 5;
    /// The proof was seen before, or the replay window is saturated. Both
    /// refuse; an eviction under load would be an admission under load.
    pub const REPLAY: u8 = 6;
    /// The ledger could not be reached, so enrolment and revocation are both
    /// unknown. Fails closed: issuing here would mean issuing without
    /// knowing whether the device is revoked.
    pub const STATE_UNAVAILABLE: u8 = 7;
    /// No trustworthy clock, so no window can be checked.
    pub const NO_CLOCK: u8 = 8;
    /// No verification keyset is loaded, so no credential can be checked.
    pub const NO_KEY: u8 = 9;
    /// The request did not decode.
    pub const MALFORMED: u8 = 10;
}

/// Typed refusal reasons for `MintResponse`.
///
/// A separate enum from the `ST_*` codes, which mix secret-store and
/// token-verify semantics: `ST_NOT_FOUND` on a mint reply had to mean
/// something, and whatever a reader decided it meant was a guess. These
/// say what the issuer actually refused.
pub mod mint_err {
    /// Minted.
    pub const OK: u8 = 0;
    /// The request did not decode, or a field was out of range.
    pub const MALFORMED: u8 = 1;
    /// No signing key is loaded for the requested profile.
    pub const NO_KEY: u8 = 2;
    /// The named `kid` is not in the keyset, or is past its removal
    /// deadline.
    pub const UNKNOWN_KID: u8 = 3;
    /// The suite is not one this build can sign in.
    pub const UNSUPPORTED_SUITE: u8 = 4;
    /// The suite is implemented but the requested profile does not permit
    /// it.
    pub const SUITE_NOT_PERMITTED: u8 = 5;
    /// The profile id is unknown, or the caller may not mint it.
    pub const UNSUPPORTED_PROFILE: u8 = 6;
    /// The credential does not fit the reply and no object store was
    /// available to hand it over through. `required_len` says how big it
    /// would have been.
    pub const TOO_LARGE: u8 = 7;
    /// Signing itself failed — a bad key, or a vault that refused.
    pub const SIGN_FAILED: u8 = 8;
    /// The requested lifetime exceeds what the profile allows. Refused
    /// rather than clamped, so a caller is never told it got what it asked
    /// for when it did not.
    pub const TTL_TOO_LONG: u8 = 9;
}

/// How a `MintResponse` carries the credential.
pub mod delivery {
    /// `body` is the credential itself.
    pub const INLINE: u8 = 0;
    /// `body` is a `storage.object` key the credential was written to.
    ///
    /// The envelope's `u16` length caps a message at 64 KiB, which an
    /// ML-DSA-signed credential or a full chain can exceed. A handle adds
    /// one read; chunking would add a reassembly state machine to every
    /// module on this wire, and each one would be a place to get
    /// reassembly wrong.
    pub const OBJECT_HANDLE: u8 = 1;
}

/// Largest credential returned inline. Above this the issuer writes the
/// credential to the object store and returns a handle.
///
/// Set below the envelope's 64 KiB ceiling with room for the rest of the
/// reply, so a credential at exactly the bound still encodes.
pub const MAX_INLINE_CREDENTIAL: usize = 32 * 1024;

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

/// `MSG_MINT_REQ` payload. This is the sole v1 layout:
/// ```text
/// [corr u32 LE]
/// [request_type u8]          // request_type::*
/// [suite u16 LE]             // suite::*
/// [profile_id u16 LE]        // suite::profile::*
/// [kid f8]                   // which key of the profile's keyset; may be empty
/// [ttl_seconds u32 LE]
/// [iss f16][sub f16][aud f16][scope f16]
/// [thumbprint_alg u8][jkt f8]
/// [extra_count u8]           // 0..=MAX_EXTRA_CLAIMS
/// ( [key f8][valtype u8][value f16] ) * extra_count
/// ```
///
/// `iss`/`sub`/`aud`/`scope` are `f16` rather than `f8`: a SPIFFE ID with a
/// real trust domain and path, or a scope list of any size, passes 255
/// bytes routinely, and an `f8` did not refuse those — `field8` returns
/// `FieldTooLong`, so the request simply failed to encode with nothing
/// saying why at the call site.
///
/// `jkt` is length-checked against `thumbprint_alg` rather than against a
/// fixed 43. The old layout hard-coded the base64url length of a SHA-256
/// digest, so a SHA-384 thumbprint could not be expressed at all and a
/// 43-byte value of any other kind was accepted as one.
///
/// An empty `kid` means "the profile's active key" — which is a real
/// request, not a missing field: a caller minting a fresh credential
/// should not have to know which key is active, and pinning one would
/// defeat rotation.
pub struct MintRequest<'a> {
    pub correlation: u32,
    pub request_type: u8,
    pub suite: u16,
    pub profile_id: u16,
    pub kid: &'a [u8],
    pub ttl_seconds: u32,
    pub iss: &'a [u8],
    pub sub: &'a [u8],
    pub aud: &'a [u8],
    pub scope: &'a [u8],
    pub thumbprint_alg: u8,
    pub jkt: Option<&'a [u8]>,
    pub extra: ExtraClaims<'a>,
}

impl<'a> MintRequest<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        if self.extra.len() > MAX_EXTRA_CLAIMS {
            return Err(WireError::FieldTooLong);
        }
        let mut payload = [0u8; 4096];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.correlation)?;
        w.u8(self.request_type)?;
        w.u16(self.suite)?;
        w.u16(self.profile_id)?;
        w.field8(self.kid)?;
        w.u32(self.ttl_seconds)?;
        w.field16(self.iss)?;
        w.field16(self.sub)?;
        w.field16(self.aud)?;
        w.field16(self.scope)?;
        w.u8(self.thumbprint_alg)?;
        match self.jkt {
            Some(jkt) => {
                // A thumbprint whose length disagrees with its algorithm is
                // refused at encode, not carried and puzzled over later.
                if jkt.len() != suite::thumbprint::len(self.thumbprint_alg) {
                    return Err(WireError::FieldTooLong);
                }
                w.field8(jkt)?;
            }
            None => {
                if self.thumbprint_alg != suite::thumbprint::NONE {
                    return Err(WireError::FieldTooLong);
                }
                w.field8(&[])?;
            }
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
        let correlation = r.u32()?;
        let request_type = r.u8()?;
        let suite = r.u16()?;
        let profile_id = r.u16()?;
        let kid = r.field8()?;
        let ttl_seconds = r.u32()?;
        let iss = r.field16()?;
        let sub = r.field16()?;
        let aud = r.field16()?;
        let scope = r.field16()?;
        let thumbprint_alg = r.u8()?;
        let jkt_slice = r.field8()?;
        // The length must be exactly what the named algorithm produces.
        // Exactly, not at most: base64url of a fixed-size digest has one
        // length, and a shorter value is a truncated digest.
        let jkt = if jkt_slice.is_empty() {
            if thumbprint_alg != suite::thumbprint::NONE {
                return Err(WireError::Truncated);
            }
            None
        } else {
            let want = suite::thumbprint::len(thumbprint_alg);
            if want == 0 || jkt_slice.len() != want {
                return Err(WireError::FieldTooLong);
            }
            Some(jkt_slice)
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
            request_type,
            suite,
            profile_id,
            kid,
            ttl_seconds,
            iss,
            sub,
            aud,
            scope,
            thumbprint_alg,
            jkt,
            extra,
        })
    }
}

/// `MSG_MINT_RESP` payload. This is the sole v1 layout:
/// ```text
/// [corr u32 LE]
/// [status u8]          // mint_err::*
/// [delivery u8]        // delivery::*
/// [required_len u32 LE]
/// [body f16]
/// ```
///
/// `status` is a `mint_err` code, not an `ST_*` one. The `ST_*` codes are
/// shared with the secret store and the token verifier, so a mint reply
/// carrying `ST_NOT_FOUND` said nothing a reader could act on — every
/// consumer had to decide for itself what a not-found mint meant.
///
/// `required_len` is the credential's true length whatever the delivery,
/// so a caller sizing a buffer never has to infer it from `body`. On
/// `TOO_LARGE` it is the only thing that says how much was needed.
pub struct MintResponse<'a> {
    pub correlation: u32,
    pub status: u8,
    pub delivery: u8,
    pub required_len: u32,
    /// The credential, or the object key it was written to. Empty on any
    /// non-OK status: a refusal never carries a partial credential, because
    /// a caller that ignored the status would then be holding something
    /// that looks like one.
    pub body: &'a [u8],
}

impl<'a> MintResponse<'a> {
    /// A successful inline reply.
    #[must_use]
    pub fn inline(correlation: u32, body: &'a [u8]) -> Self {
        Self {
            correlation,
            status: mint_err::OK,
            delivery: delivery::INLINE,
            #[expect(
                clippy::cast_possible_truncation,
                reason = "a credential over 4 GiB is not reachable through this wire"
            )]
            required_len: body.len() as u32,
            body,
        }
    }

    /// A successful reply handing over an object key.
    #[must_use]
    pub fn handle(correlation: u32, key: &'a [u8], required_len: u32) -> Self {
        Self {
            correlation,
            status: mint_err::OK,
            delivery: delivery::OBJECT_HANDLE,
            required_len,
            body: key,
        }
    }

    /// A refusal. `required_len` is meaningful only for
    /// [`mint_err::TOO_LARGE`]; it is zero otherwise.
    #[must_use]
    pub fn refused(correlation: u32, status: u8, required_len: u32) -> Self {
        Self {
            correlation,
            status,
            delivery: delivery::INLINE,
            required_len,
            body: &[],
        }
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut payload = [0u8; MAX_INLINE_CREDENTIAL + 64];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.correlation)?;
        w.u8(self.status)?;
        w.u8(self.delivery)?;
        w.u32(self.required_len)?;
        w.field16(self.body)?;
        let n = w.len();
        write_envelope(MSG_MINT_RESP, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let correlation = r.u32()?;
        let status = r.u8()?;
        let delivery = r.u8()?;
        let required_len = r.u32()?;
        let body = r.field16()?;
        // A refusal carrying a body would let a caller that skipped the
        // status act on something credential-shaped.
        if status != mint_err::OK && !body.is_empty() {
            return Err(WireError::FieldTooLong);
        }
        Ok(Self {
            correlation,
            status,
            delivery,
            required_len,
            body,
        })
    }
}

// ── Keyset records ──────────────────────────────────────────────────────

/// Lifecycle state of a key within its keyset.
pub mod key_state {
    /// Loaded and verifiable, but nothing signs with it yet.
    pub const ADDED: u8 = 0;
    /// New credentials are signed under it.
    pub const ACTIVE: u8 = 1;
    /// Still verifies; no longer signs. Selectable until its removal
    /// deadline.
    pub const RETIRED: u8 = 2;
}

/// What a key may be used for. Checked per operation, so a verification
/// key delivered to a mint cannot become a signing key by being present.
pub mod key_use {
    pub const VERIFY: u8 = 0x01;
    pub const SIGN: u8 = 0x02;
}

/// Longest vault label a signing record may name.
///
/// Mirrors fluxor `key_vault::MAX_LABEL`. A label longer than the vault can
/// hold would be silently truncated there, and two labels sharing a prefix
/// would then be ONE key — which is how an issuer signs under a key it did
/// not mean to.
pub const MAX_KEY_LABEL: usize = 64;

/// Is `len` a plausible `key_ref` for this use and suite?
///
/// The two arms measure genuinely different things, which is why this is one
/// function rather than a bound: a VERIFY record carries a public key and is
/// bounded by the SUITE, while a SIGN record carries a label and is bounded
/// by the VAULT. Sizing a label against a suite's key length is how a
/// perfectly good label becomes unrepresentable the day a suite with short
/// keys arrives.
///
/// An EMPTY `key_ref` is refused in both directions. For a label that
/// matters most: the vault refuses an empty label, so a record carrying one
/// would be a signing record that can never open a key — accepted on the
/// wire and dead at first use, which is the failure that gets diagnosed
/// last.
fn key_ref_len_ok(usage: u8, suite_id: u16, len: usize) -> bool {
    if len == 0 {
        return false;
    }
    if usage == key_use::SIGN {
        return len <= MAX_KEY_LABEL;
    }
    let want = suite::max_public_key_len(suite_id);
    want != 0 && len <= want
}

/// One key in a keyset. Payload of [`MSG_KEY_ADD`], and the repeated
/// element of [`MSG_KEYSET_SNAPSHOT`]:
/// ```text
/// [issuer f8][profile_id u16 LE][kid f8]
/// [suite u16 LE][state u8][key_use u8]
/// [generation u32 LE]
/// [activate_after_unix u64 LE][remove_after_unix u64 LE]
/// [material f16]
/// ```
///
/// `key_ref` is the public key for a VERIFYING record and the **vault
/// label** for a SIGNING one — which of those it is follows from
/// `key_use`, and a record carrying both bits is refused rather than
/// guessed at.
///
/// **A signing record never carries key material, and that is the whole
/// point of the field being named a reference.** The predecessor put a raw
/// private scalar on this wire, which made key distribution and key
/// COMPROMISE the same operation: anyone who could reach the control plane
/// could hand the issuer a signing key of their choosing, and anyone who
/// could observe it held the issuer's key. Naming a label instead, the
/// control plane can ask that a key EXIST and can never supply it or learn
/// it — the private half is generated inside the vault on first open and
/// leaves it only as signatures.
///
/// This shape was not available until labelled keys survived a process
/// restart. While they did not, a raw key on the wire was the only way an
/// issuer could hold the SAME key across a restart, and an issuer whose key
/// changes at every restart invalidates every credential it ever issued.
///
/// `generation` is the keyset's lifecycle counter, and it is what a hybrid
/// binds both of its proofs to: two signatures that name different
/// generations are not two halves of one credential, and treating them as
/// such is how an attacker strips the half they cannot forge.
pub struct KeyRecord<'a> {
    pub issuer: &'a [u8],
    pub profile_id: u16,
    pub kid: &'a [u8],
    pub suite: u16,
    pub state: u8,
    pub key_use: u8,
    pub generation: u32,
    /// Not valid for signing before this. `0` means "as soon as activated".
    pub activate_after_unix: u64,
    /// Dropped by a verifier after this. `0` means "no deadline set",
    /// which is only meaningful before the key is retired.
    pub remove_after_unix: u64,
    pub key_ref: &'a [u8],
}

impl<'a> KeyRecord<'a> {
    /// Write the record body (no envelope), returning bytes written.
    pub fn write(&self, w: &mut PayloadWriter<'_>) -> Result<(), WireError> {
        // A key that is both a signing and a verifying key is a category
        // error: the material can only be one of the two, so a record
        // claiming both would have a reader pick which.
        if self.key_use != key_use::SIGN && self.key_use != key_use::VERIFY {
            return Err(WireError::FieldTooLong);
        }
        if !key_ref_len_ok(self.key_use, self.suite, self.key_ref.len()) {
            return Err(WireError::FieldTooLong);
        }
        w.field8(self.issuer)?;
        w.u16(self.profile_id)?;
        w.field8(self.kid)?;
        w.u16(self.suite)?;
        w.u8(self.state)?;
        w.u8(self.key_use)?;
        w.u32(self.generation)?;
        w.u64(self.activate_after_unix)?;
        w.u64(self.remove_after_unix)?;
        w.field16(self.key_ref)
    }

    /// Read one record body from `r`.
    pub fn read(r: &mut PayloadReader<'a>) -> Result<Self, WireError> {
        let issuer = r.field8()?;
        let profile_id = r.u16()?;
        let kid = r.field8()?;
        let suite_id = r.u16()?;
        let state = r.u8()?;
        let usage = r.u8()?;
        let generation = r.u32()?;
        let activate_after_unix = r.u64()?;
        let remove_after_unix = r.u64()?;
        let key_ref = r.field16()?;
        if usage != key_use::SIGN && usage != key_use::VERIFY {
            return Err(WireError::FieldTooLong);
        }
        if !key_ref_len_ok(usage, suite_id, key_ref.len()) {
            return Err(WireError::FieldTooLong);
        }
        Ok(Self {
            issuer,
            profile_id,
            kid,
            suite: suite_id,
            state,
            key_use: usage,
            generation,
            activate_after_unix,
            remove_after_unix,
            key_ref,
        })
    }

    /// Encode as a complete [`MSG_KEY_ADD`] message.
    pub fn encode_add(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut payload = [0u8; 8192];
        let mut w = PayloadWriter::new(&mut payload);
        self.write(&mut w)?;
        let n = w.len();
        write_envelope(MSG_KEY_ADD, &payload[..n], out)
    }

    /// Decode a [`MSG_KEY_ADD`] payload.
    pub fn decode_add(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        Self::read(&mut r)
    }
}

/// Which key a lifecycle verb refers to: the payload shared by
/// [`MSG_KEY_ACTIVATE`], [`MSG_KEY_RETIRE`] and [`MSG_KEY_REMOVE`].
///
/// `arg` is the verb's one parameter — the generation for ACTIVATE, the
/// removal deadline for RETIRE, and unused for REMOVE. One shape rather
/// than three near-identical ones, because the selector is the part every
/// consumer has to get right.
pub struct KeyRef<'a> {
    pub issuer: &'a [u8],
    pub profile_id: u16,
    pub kid: &'a [u8],
    pub arg: u64,
}

impl<'a> KeyRef<'a> {
    pub fn encode(&self, msg_type: u8, out: &mut [u8]) -> Result<usize, WireError> {
        let mut payload = [0u8; 512];
        let mut w = PayloadWriter::new(&mut payload);
        w.field8(self.issuer)?;
        w.u16(self.profile_id)?;
        w.field8(self.kid)?;
        w.u64(self.arg)?;
        let n = w.len();
        write_envelope(msg_type, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        Ok(Self {
            issuer: r.field8()?,
            profile_id: r.u16()?,
            kid: r.field8()?,
            arg: r.u64()?,
        })
    }
}

// ── Verified identity (C2) ──────────────────────────────────────────────

/// Assurance levels: how strongly the subject was authenticated.
///
/// Ordered, so a policy can say "at least this" rather than enumerate.
pub mod assurance {
    /// Nothing was proved. Never the result of a successful verification;
    /// present so a policy floor of "any" is expressible.
    pub const NONE: u8 = 0;
    /// A single factor — possession of one key.
    pub const SINGLE_FACTOR: u8 = 1;
    /// Possession plus a proof bound to this request (DPoP).
    pub const PROOF_OF_POSSESSION: u8 = 2;
    /// Two independent factors.
    pub const MULTI_FACTOR: u8 = 3;
    /// A hardware-backed authenticator.
    pub const HARDWARE_BACKED: u8 = 4;
}

/// Authentication methods, as a bitmask (`amr`, RFC 8176).
pub mod auth_method {
    pub const PASSWORD: u16 = 0x0001;
    pub const OTP: u16 = 0x0002;
    pub const HARDWARE_KEY: u16 = 0x0004;
    pub const MAIL_PROOF: u16 = 0x0008;
    pub const PROOF_OF_POSSESSION: u16 = 0x0010;
    pub const DEVICE_CERTIFICATE: u16 = 0x0020;
}

/// How long an enrolment authorisation may live, at most.
///
/// Five minutes: a QR is scanned in front of the person who displayed it, so
/// a longer window buys nothing for the honest ceremony and everything for a
/// photograph of a screen. A request asking for more is CLAMPED rather than
/// refused — an operator who asks for an hour should get a working
/// authorisation that expires in five minutes, not an error they work around
/// by asking again.
pub const MAX_ENROL_AUTH_TTL_SECS: u32 = 300;

/// The transaction nonce an operator-minted enrolment is filed under, in
/// bytes before base64url. The code is drawn by the endpoint's existing
/// `draw_code`, so its length is that of a mailed code and not restated here.
pub const ENROL_AUTH_ID_BYTES: usize = 8;

/// What an enrolment authorisation is FOR.
///
/// Named rather than free text, because the purpose is an input to what the
/// ceremony is allowed to produce, and a string would let an operator invent
/// a purpose no policy has a rule for.
pub mod enrol_purpose {
    /// A device being enrolled from a displayed QR code.
    pub const QR_DEVICE: u8 = 1;
}

/// [`MSG_ENROL_AUTH_REQ`] — an operator asking for one authorisation.
pub struct EnrolAuthRequest<'a> {
    pub correlation: u32,
    pub purpose: u8,
    /// Requested lifetime; clamped to [`MAX_ENROL_AUTH_TTL_SECS`].
    pub ttl_seconds: u32,
    /// The audience the resulting credential will be for. Empty means the
    /// deployment's default — a statement the operator makes by writing it.
    pub audience: &'a [u8],
}

impl<'a> EnrolAuthRequest<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut payload = [0u8; 1024];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.correlation)?;
        w.u8(self.purpose)?;
        w.u32(self.ttl_seconds)?;
        w.field16(self.audience)?;
        let n = w.len();
        write_envelope(MSG_ENROL_AUTH_REQ, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let correlation = r.u32()?;
        let purpose = r.u8()?;
        let ttl_seconds = r.u32()?;
        let audience = r.field16()?;
        // An unknown purpose is refused at DECODE, not carried to a handler
        // that would have to decide what to do with it. There is one purpose
        // today; a build that does not know a purpose must not act on it.
        if purpose != enrol_purpose::QR_DEVICE {
            return Err(WireError::FieldTooLong);
        }
        Ok(Self {
            correlation,
            purpose,
            ttl_seconds,
            audience,
        })
    }
}

/// [`MSG_ENROL_AUTH_RESP`] — the authorisation, once.
pub struct EnrolAuthResponse<'a> {
    pub correlation: u32,
    /// `ST_OK`, or `ST_UNAVAILABLE` when the ledger could not record it.
    pub status: u8,
    pub auth_id: &'a [u8],
    pub secret: &'a [u8],
    pub expires_at: u64,
}

impl<'a> EnrolAuthResponse<'a> {
    /// A refusal, carrying nothing that looks like an authorisation.
    #[must_use]
    pub fn refused(correlation: u32, status: u8) -> Self {
        Self {
            correlation,
            status,
            auth_id: &[],
            secret: &[],
            expires_at: 0,
        }
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut payload = [0u8; 512];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.correlation)?;
        w.u8(self.status)?;
        w.field8(self.auth_id)?;
        w.field8(self.secret)?;
        w.u64(self.expires_at)?;
        let n = w.len();
        write_envelope(MSG_ENROL_AUTH_RESP, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let me = Self {
            correlation: r.u32()?,
            status: r.u8()?,
            auth_id: r.field8()?,
            secret: r.field8()?,
            expires_at: r.u64()?,
        };
        // A refusal that carried a secret would let a caller who skipped the
        // status walk away holding something spendable.
        if me.status != ST_OK && (!me.auth_id.is_empty() || !me.secret.is_empty()) {
            return Err(WireError::FieldTooLong);
        }
        Ok(me)
    }
}

/// What a verifier was asked to check.
///
/// Every field is an input to the decision, not a hint. An empty
/// `expected_*` means "no rule for this", which is a deliberate statement a
/// caller makes — not an accident, because the caller had to write it.
pub struct VerifyRequest<'a> {
    pub correlation: u32,
    /// The compact JWS to check.
    pub credential: &'a [u8],
    /// Required profile, or `profile::NONE` for no rule.
    pub expected_profile: u16,
    /// Required issuer, or empty.
    pub expected_issuer: &'a [u8],
    /// Required audience, or empty.
    ///
    /// A token minted for one audience and accepted at another is the
    /// confused-deputy shape this exists to stop, and it was previously
    /// the caller's job in five places.
    pub expected_audience: &'a [u8],
    /// The method and URI a proof must be bound to. Empty when the
    /// credential is not presented with a proof.
    pub method: &'a [u8],
    pub uri: &'a [u8],
    /// Minimum assurance the subject must have been authenticated to.
    pub min_assurance: u8,
    /// Seconds since the Unix epoch, and what may be concluded from it.
    /// `time_source_class` and `time_flags` mirror fluxor's
    /// `trusted_time`, so a verifier can refuse a validity decision
    /// rather than make one against a clock that says 1970.
    pub now_unix_secs: u64,
    pub time_source_class: u8,
    pub time_flags: u8,
}

impl<'a> VerifyRequest<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut payload = [0u8; 8192];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.correlation)?;
        w.field16(self.credential)?;
        w.u16(self.expected_profile)?;
        w.field16(self.expected_issuer)?;
        w.field16(self.expected_audience)?;
        w.field8(self.method)?;
        w.field16(self.uri)?;
        w.u8(self.min_assurance)?;
        w.u64(self.now_unix_secs)?;
        w.u8(self.time_source_class)?;
        w.u8(self.time_flags)?;
        let n = w.len();
        write_envelope(MSG_VERIFY_REQ, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        Ok(Self {
            correlation: r.u32()?,
            credential: r.field16()?,
            expected_profile: r.u16()?,
            expected_issuer: r.field16()?,
            expected_audience: r.field16()?,
            method: r.field8()?,
            uri: r.field16()?,
            min_assurance: r.u8()?,
            now_unix_secs: r.u64()?,
            time_source_class: r.u8()?,
            time_flags: r.u8()?,
        })
    }
}

/// Typed refusal reasons for a verification.
///
/// Distinct from the `ST_*` codes for the same reason `mint_err` is: those
/// are shared with the secret store, so `ST_NOT_FOUND` on a verify reply
/// meant whatever each reader decided it meant.
pub mod verify_err {
    pub const OK: u8 = 0;
    /// The credential did not parse as a compact JWS.
    pub const MALFORMED: u8 = 1;
    /// No key is loaded at all.
    pub const NO_KEY: u8 = 2;
    /// The credential names a `kid` this verifier does not hold.
    pub const UNKNOWN_KID: u8 = 3;
    /// The signature did not verify.
    pub const BAD_SIGNATURE: u8 = 4;
    /// Outside its validity window.
    pub const EXPIRED: u8 = 5;
    /// The header's `alg` disagreed with the key's suite.
    pub const SUITE_MISMATCH: u8 = 6;
    /// The credential is for a different audience.
    pub const WRONG_AUDIENCE: u8 = 7;
    /// The credential was issued by somebody else.
    pub const WRONG_ISSUER: u8 = 8;
    /// The credential is not of the required profile.
    pub const WRONG_PROFILE: u8 = 9;
    /// The subject was not authenticated to the required assurance.
    pub const INSUFFICIENT_ASSURANCE: u8 = 10;
    /// A validity decision was required and no trustworthy clock was
    /// available. Distinct from `EXPIRED`: "we cannot tell" and "we can
    /// tell, and it has" must never look the same.
    pub const NO_CLOCK: u8 = 11;
}

/// What a verifier established. The reply to a [`VerifyRequest`].
///
/// Typed fields, not claims JSON — see [`MSG_VERIFY_RESP`]. `application`
/// carries the non-reserved claims for a consumer that needs them; nothing
/// in it is an authorization input, and a consumer treating it as one has
/// stepped back outside the property this type exists to hold.
pub struct VerifiedIdentity<'a> {
    pub correlation: u32,
    pub status: u8,
    pub profile_id: u16,
    pub issuer: &'a [u8],
    pub kid: &'a [u8],
    pub suite: u16,
    /// The subject, as the credential names it — a device id, a SPIFFE ID.
    pub subject: &'a [u8],
    /// Thumbprint of the key the credential is bound to, with the
    /// algorithm that produced it. Empty for a bearer credential.
    pub thumbprint_alg: u8,
    pub key_thumbprint: &'a [u8],
    pub audience: &'a [u8],
    pub scope: &'a [u8],
    pub issued_at: u64,
    pub expires_at: u64,
    /// When the subject actually authenticated, which is not when the
    /// credential was issued: a re-issue carries a fresh `iat` over an old
    /// authentication, and a policy that wants recency needs the latter.
    pub auth_time: u64,
    pub assurance: u8,
    pub auth_methods: u16,
    /// A stable id for this credential (`jti`), for revocation and audit.
    pub credential_id: &'a [u8],
    /// The replay id the proof was recorded under, empty when unbound.
    pub replay_id: &'a [u8],
    /// Non-reserved claims, opaque. NOT an authorization input.
    pub application: &'a [u8],
}

impl<'a> VerifiedIdentity<'a> {
    /// A refusal. Carries no identity: every field a consumer might
    /// authorize on is empty, so one that ignored the status has nothing
    /// to act on.
    #[must_use]
    pub fn refused(correlation: u32, status: u8) -> Self {
        Self {
            correlation,
            status,
            profile_id: 0,
            issuer: &[],
            kid: &[],
            suite: 0,
            subject: &[],
            thumbprint_alg: 0,
            key_thumbprint: &[],
            audience: &[],
            scope: &[],
            issued_at: 0,
            expires_at: 0,
            auth_time: 0,
            assurance: assurance::NONE,
            auth_methods: 0,
            credential_id: &[],
            replay_id: &[],
            application: &[],
        }
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut payload = [0u8; 8192];
        let mut w = PayloadWriter::new(&mut payload);
        w.u32(self.correlation)?;
        w.u8(self.status)?;
        w.u16(self.profile_id)?;
        w.field16(self.issuer)?;
        w.field8(self.kid)?;
        w.u16(self.suite)?;
        w.field16(self.subject)?;
        w.u8(self.thumbprint_alg)?;
        w.field8(self.key_thumbprint)?;
        w.field16(self.audience)?;
        w.field16(self.scope)?;
        w.u64(self.issued_at)?;
        w.u64(self.expires_at)?;
        w.u64(self.auth_time)?;
        w.u8(self.assurance)?;
        w.u16(self.auth_methods)?;
        w.field8(self.credential_id)?;
        w.field8(self.replay_id)?;
        w.field16(self.application)?;
        let n = w.len();
        write_envelope(MSG_VERIFY_RESP, &payload[..n], out)
    }

    pub fn decode(payload: &'a [u8]) -> Result<Self, WireError> {
        let mut r = PayloadReader::new(payload);
        let me = Self {
            correlation: r.u32()?,
            status: r.u8()?,
            profile_id: r.u16()?,
            issuer: r.field16()?,
            kid: r.field8()?,
            suite: r.u16()?,
            subject: r.field16()?,
            thumbprint_alg: r.u8()?,
            key_thumbprint: r.field8()?,
            audience: r.field16()?,
            scope: r.field16()?,
            issued_at: r.u64()?,
            expires_at: r.u64()?,
            auth_time: r.u64()?,
            assurance: r.u8()?,
            auth_methods: r.u16()?,
            credential_id: r.field8()?,
            replay_id: r.field8()?,
            application: r.field16()?,
        };
        // A refusal that carried a subject would let a consumer that
        // skipped the status authorize somebody.
        if me.status != verify_err::OK && (!me.subject.is_empty() || !me.scope.is_empty()) {
            return Err(WireError::FieldTooLong);
        }
        Ok(me)
    }
}

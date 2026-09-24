//! Enrolment endpoint — the issuer's front door, as a module.
//!
//! Two paths behind wave's `foundation/http`:
//!
//! * `POST /start` takes an email, a device public key and a PKCE code
//!   challenge, and answers with a **challenge token**: a JWS this endpoint
//!   signed, binding those three together with a nonce and a short life.
//! * `POST /redeem` takes that token back with the PKCE verifier and a
//!   possession proof over it, and answers with a **device certificate** —
//!   the durable enrolment anchor every later token rests on.
//!
//! The two halves are one module because they are two halves of one
//! agreement. `/redeem` verifies exactly what `/start` signed, over the same
//! canonicalisation and under the same key; splitting them across modules
//! would put a wire format between two functions that must never disagree,
//! and give the format nowhere to live.
//!
//! **What the challenge token is for.** Not secrecy — it is handed to the
//! caller. It exists so `/redeem` needs no server-side session: everything
//! `/redeem` must know was signed at `/start` and comes back with the
//! request. A device cannot alter it without breaking the signature, and
//! cannot replay it past its expiry.
//!
//! **What is proved by the end.** That whoever redeemed holds the private
//! half of the device key named at `/start` (the possession proof), and that
//! they are the same party that started (PKCE). Neither proves the email was
//! controlled — that is the mail gate's job, upstream of here, and the
//! certificate records what it was told rather than what it checked.

#![no_std]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in target/fluxor/fluxor-abi/sdk/"
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "see file-level allow: SDK surface is shared across modules"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha384.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/hmac.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/p256.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/ed25519.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/sha3.rs");
// ml_dsa.rs needs sha3.rs's SHAKE in scope; sdk_bridge.rs needs both, plus
// ed25519.rs. Order matters for all four.
include!("../../../target/fluxor/fluxor-abi/sdk/crypto/ml_dsa.rs");
include!("../../common/sdk_bridge.rs");

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/b64.rs"]
mod b64;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/device_auth.rs"]
mod device_auth;
#[path = "../../common/dpop.rs"]
mod dpop;
#[path = "../../common/ids.rs"]
mod ids;
#[path = "../../common/issuer_key.rs"]
mod issuer_key;
#[path = "../../common/jose.rs"]
mod jose;
#[path = "../../common/jwk.rs"]
mod jwk;
#[path = "../../../target/fluxor/fluxor-abi/sdk/contracts/key_vault.rs"]
mod key_vault;
#[path = "../../common/pkce.rs"]
mod pkce;
#[path = "../../common/state_wire.rs"]
mod state_wire;
#[path = "../../common/time_policy.rs"]
mod time_policy;
#[path = "../../common/totp.rs"]
mod totp;
#[path = "../../common/verify_keyset.rs"]
mod verify_keyset;

// wave's SMTP connector wire, mounted from the materialised `wave-common`
// tree. A second copy of a layout is how two repos come to disagree about
// one neither can check for the other.
#[path = "../../../target/fluxor/wave-common/smtp_wire.rs"]
mod smtp_wire;

use auth_wire::PayloadReader;

const STEP_DID_WORK: i32 = 2;

/// `HttpRequest`  `[conn u16][stream u16][method u8][flags u8][path_len u16][hdr_len u16][body_len u16]`
const REQ_HDR: usize = 12;
/// `HttpResponse` `[conn u16][stream u16][status u16][flags u8][ct_len u8][hdr_len u16][body_len u16]`
const RESP_HDR: usize = 12;

/// wave's `wire::method::METHOD_POST`.
const METHOD_POST: u8 = 3;

/// The `cty` a challenge token carries.
///
/// Pinned on both sides. Another artefact this same key signed — an access
/// token, a device certificate — must not be redeemable as a challenge, and
/// the type is what stops it.
const CHALLENGE_CTY: &[u8] = b"challenge+jwt";

/// The `cty` a device certificate carries.
const CERTIFICATE_CTY: &[u8] = b"dc+jwt";

/// How long a challenge stays redeemable, in seconds.
///
/// Short. It exists to carry one exchange across one round trip, and a
/// long-lived one is a bearer artefact sitting in a caller's logs.
const CHALLENGE_TTL_SECS: u64 = 600;

/// How long a device certificate lives, in seconds.
const CERTIFICATE_TTL_SECS: u64 = 30 * 24 * 3600;

/// Tolerated clock skew, in seconds.
const CLOCK_SKEW_SECS: u64 = 60;

/// Longest value read out of a JSON body.
const MAX_FIELD: usize = 256;
/// Longest token this endpoint composes or reads.
const MAX_TOKEN: usize = 2048;
/// The PKCE challenge is a base64url SHA-256: 43 characters.
const CODE_CHALLENGE_LEN: usize = 43;
/// RFC 7636 §4.1 bounds on a verifier.
const MIN_VERIFIER: usize = 43;
const MAX_VERIFIER: usize = 128;
/// Nonce bytes, rendered as base64url in the claims.
const NONCE_BYTES: usize = 16;

const MAX_REQS_PER_STEP: usize = 2;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    out_responses: i32,
    in_key: i32,
    /// Operator requests for enrolment authorisations, and the replies.
    /// Both ride the control plane — see `MSG_ENROL_AUTH_REQ`.
    in_auth: i32,
    out_auth: i32,
    out_state: i32,
    in_state: i32,
    out_mail: i32,
    in_mail: i32,

    /// The envelope sender enrolment mail is submitted from.
    mail_from: [u8; MAX_FIELD],
    mail_from_len: u16,

    /// The Ed25519 seed. Signing and verifying are the same key here because
    /// this endpoint is the only party on either end of a challenge token.
    /// out[4]: this signer's public half, as a VERIFY KEY_ADD.
    out_key_announce: i32,
    /// The challenge signing key, held in the vault under the label the
    /// keyset record names. This module never holds a private key.
    key: issuer_key::IssuerKey,
    /// The HMAC key that binds an enrolment code to its transaction.
    ///
    /// Derived from the signing key at open (see `derive_code_key`) rather
    /// than held as a separate secret, so there is exactly one thing to
    /// provision, and it is STABLE across restarts.
    code_key: [u8; 32],
    /// Proof replay for the authenticator routes, so one DPoP proof admits
    /// one operation.
    ///
    /// Time-bounded and fail-closed: an entry is remembered until the proof
    /// it came from would be refused as stale anyway, and a saturated window
    /// refuses rather than evicting — an eviction under load is an admission
    /// under load.
    replay: dpop::ReplayWindow<128>,
    /// Scratch for one vault SIGN, kept in module state rather than on the
    /// PIC stack.
    sign_scratch: [u8; MAX_TOKEN + issuer_key::SIGN_SCRATCH_OVERHEAD],
    kid: [u8; 32],
    kid_len: u8,

    /// The deployment's issuer identity, and the secret tenant ids derive
    /// from. Graph parameters: a caller that could name its own issuer could
    /// mint an enrolment claiming to come from somebody else, and one that
    /// could name the tenant seed could collide two tenants deliberately.
    iss: [u8; MAX_FIELD],
    iss_len: u16,
    tenant_seed: [u8; 64],
    tenant_seed_len: u16,

    enrol_started: u32,
    enrol_redeemed: u32,
    enrol_no_key: u32,
    enrol_malformed: u32,
    enrol_bad_challenge: u32,
    enrol_pkce_mismatch: u32,
    enrol_bad_possession: u32,
    enrol_recorded: u32,
    enrol_replayed: u32,
    enrol_state_unavailable: u32,
    enrol_totp_registered: u32,
    enrol_totp_confirmed: u32,
    enrol_totp_conflict: u32,
    enrol_totp_bad_code: u32,
    enrol_mail_submitted: u32,
    enrol_mail_failed: u32,
    enrol_code_bad: u32,
    enrol_txn_burned: u32,

    /// The nonce of the challenge currently being redeemed, captured during
    /// verification so the consume can key on it without re-parsing.
    redeem_nonce: [u8; MAX_NONCE],
    redeem_nonce_len: u8,
    /// The challenge's own expiry, so the consume marker outlives exactly the
    /// window in which a replay would otherwise be possible and no longer.
    redeem_exp: u64,
    /// The code the client presented at `/redeem`.
    redeem_code: [u8; CODE_DIGITS],
    /// The device record this redemption will commit: its id, and the
    /// certificate's own claims. What is enrolled is exactly what was
    /// attested, with no second rendering to disagree with the first.
    redeem_device_id: [u8; 4 + ids::DEVICE_ID_LENGTH],
    redeem_claims: [u8; 1024],
    redeem_claims_len: u16,

    /// True when `/start` ADOPTED an operator-minted transaction rather than
    /// creating one — the QR ceremony. It decides two things: no transaction
    /// is written (one already exists) and no mail is submitted (there is no
    /// mailbox).
    start_adopted: bool,
    /// What `/start` produced and is about to commit: the transaction's
    /// nonce, the code mailed against it, and the address it goes to.
    start_nonce: [u8; MAX_NONCE],
    start_nonce_len: u8,
    start_code: [u8; CODE_DIGITS],
    start_email: [u8; MAX_FIELD],
    start_email_len: u16,
    /// The challenge's expiry, so the transaction outlives exactly the window
    /// the challenge itself is good for.
    start_exp: u64,

    /// Redemptions waiting on the ledger.
    pending: [Pending; MAX_PENDING],
    next_corr: u32,

    buf: [u8; abi::CHANNEL_BUFFER_SIZE],
    out: [u8; abi::CHANNEL_BUFFER_SIZE],
}

/// The longest base64url nonce a challenge carries.
const MAX_NONCE: usize = 48;

/// The exact length of an OPERATOR-minted transaction nonce, base64url.
///
/// `ENROL_AUTH_ID_BYTES` (8) unpadded is 11 characters, where a mailed
/// transaction's `NONCE_BYTES` (16) is 22. `/start` will only adopt a nonce
/// of this length, and that check is load-bearing rather than cosmetic.
///
/// **What it stops.** `/redeem` takes its nonce from the challenge token, so
/// before adoption existed the only way to spend attempts against
/// transaction N was to hold the token naming N — which only the client that
/// started it had. Adoption lets any caller mint a token for any nonce, and
/// without this check somebody who learned a MAILED transaction's nonce
/// could burn its five attempts and lock out the person waiting on that
/// mail. They still could not redeem it, having no code; they could deny it.
///
/// Length rather than a marker character because base64url is `A-Za-z0-9-_`
/// and a prefix drawn from that alphabet would collide with real nonces at
/// one in sixty-four. Two lengths cannot collide at all.
const OPERATOR_NONCE_LEN: usize = 11;
/// Redemptions in flight at once. Each holds a signed certificate, so this is
/// bounded by memory rather than by throughput; a fifth concurrent redemption
/// is refused rather than queued.
const MAX_PENDING: usize = 4;

/// A redemption that has been verified and is waiting for the ledger.
///
/// The certificate is already signed and held here. That ordering is
/// deliberate: signing is deterministic and cheap, and holding the result
/// means the answer sent on success is exactly the one the verification
/// produced, rather than something re-derived after an await.
#[derive(Clone, Copy)]
struct Pending {
    live: bool,
    /// `STAGE_CONSUME` while the nonce is being spent, `STAGE_COMMIT` while
    /// the device record is being written.
    stage: u8,
    conn: u16,
    stream: u16,
    corr: u32,
    cert: [u8; MAX_TOKEN],
    cert_len: u16,
    device_id: [u8; 4 + ids::DEVICE_ID_LENGTH],
    claims: [u8; 1024],
    claims_len: u16,
    /// The transaction's nonce, and the code the client presented against it.
    nonce: [u8; MAX_NONCE],
    nonce_len: u8,
    code: [u8; CODE_DIGITS],
    /// The CALLER's correlation, for a stage that answers on a channel.
    /// Distinct from `corr`, which correlates this module's own request to
    /// the state adapter — confusing the two would reply to the operator
    /// with the ledger's correlation and to the ledger with the operator's.
    caller_corr: u32,
    /// When the authorisation being minted expires, echoed to the operator.
    auth_exp: u64,
    /// The authenticator secret, base32, held only for the reply that returns
    /// it once at registration.
    totp_secret: [u8; TOTP_SECRET_B32],
    totp_secret_len: u8,
    /// The code presented at confirmation.
    totp_code: [u8; totp::MAX_DIGITS as usize],
    totp_code_len: u8,
    /// True while confirming an authenticator, false while registering one.
    totp_confirming: bool,
    /// Proof replay, so one DPoP proof admits one authenticator operation.
    ///
    /// Time-bounded and fail-closed: an entry is remembered until the proof
    /// it came from would be refused as stale anyway, and a full window
    /// refuses rather than evicting — an eviction under load is an admission
    /// under load.
    /// The etag the transaction was read at, so the consume can compare and
    /// swap against exactly the revision the code was checked on.
    etag: [u8; state_wire::MAX_ETAG],
    etag_len: u8,
    attempts: u32,
}

/// Writing the transaction `/start` created.
const STAGE_START: u8 = 0;
/// Reading the transaction back at `/redeem`, to check the code against it.
const STAGE_LOOKUP: u8 = 1;
/// Spending the transaction.
const STAGE_CONSUME: u8 = 2;
/// Committing the device record.
const STAGE_COMMIT: u8 = 3;
/// Writing an operator-minted enrolment AUTHORISATION — the thing a QR
/// carries. Unlike every other stage this one answers on a CHANNEL rather
/// than an HTTP connection, because the operator asked over the control
/// plane and there is no request socket to reply on.
const STAGE_AUTH_MINT: u8 = 4;
/// Reading the device record to attach or check an authenticator.
const STAGE_TOTP_READ: u8 = 5;
/// Writing the authenticator back, conditional on the revision it was read
/// at — so two registrations racing produce one winner, and a confirmation
/// cannot advance a counter another confirmation already advanced.
const STAGE_TOTP_WRITE: u8 = 6;

impl Pending {
    const fn zero() -> Self {
        Self {
            live: false,
            stage: STAGE_START,
            totp_secret: [0; TOTP_SECRET_B32],
            totp_secret_len: 0,
            totp_code: [0; totp::MAX_DIGITS as usize],
            totp_code_len: 0,
            totp_confirming: false,
            caller_corr: 0,
            auth_exp: 0,
            conn: 0,
            stream: 0,
            corr: 0,
            cert: [0u8; MAX_TOKEN],
            cert_len: 0,
            device_id: [0u8; 4 + ids::DEVICE_ID_LENGTH],
            claims: [0u8; 1024],
            claims_len: 0,
            nonce: [0u8; MAX_NONCE],
            nonce_len: 0,
            code: [0u8; CODE_DIGITS],
            etag: [0u8; state_wire::MAX_ETAG],
            etag_len: 0,
            attempts: 0,
        }
    }
}

/// The enrolment code's length, in decimal digits.
///
/// Eight, not six: the code is the only secret standing between somebody who
/// has intercepted a challenge token and an enrolled device, and 10^8 with a
/// five-attempt cap and a ten-minute window is a different proposition from
/// 10^6.
const CODE_DIGITS: usize = 8;

/// How many wrong codes a transaction tolerates before it is burned.
const MAX_CODE_ATTEMPTS: u32 = 5;
/// The key-announcement buffer, sized from the REGISTRY like every store
/// that receives the announcement (`verify_keyset`, `wellknown`): the
/// widest implemented public key plus the record's field overhead.
///
/// A literal here fails silently rather than loudly. A buffer too small
/// for the key in use makes `rec.write` fail, the announcement never
/// leave, and every verifier stay ignorant of a key the issuer is
/// actively signing under — while the issuer itself reports nothing
/// wrong. The assertion below is what makes that unrepresentable: naming
/// a suite in the registry refuses to build until every buffer between
/// the vault and the verifiers fits it.
const ANNOUNCE_BUF: usize = auth_wire::suite::MAX_IMPLEMENTED_PUBLIC_KEY_LEN + 192;
/// Mirrors the `key_announce` port's `max_record` in manifest.toml — the
/// channel-side half of the same fit guarantee.
const ANNOUNCE_MAX_RECORD: usize = 4096;
const _: () = assert!(
    ANNOUNCE_BUF <= ANNOUNCE_MAX_RECORD,
    "a key announcement must fit the key_announce port's max_record"
);

/// Derive the key the code hash is taken under.
///
/// HMAC and not a bare digest: a stored `sha256(nonce‖code)` would let anyone
/// who could read the ledger enumerate a 10^8 space offline in seconds. Under
/// a key they do not have, the stored value says nothing.
///
/// Emit this signer's public half as a VERIFY [`auth_wire::MSG_KEY_ADD`].
///
/// **This edge exists because the operator cannot supply it.** The signing
/// record names a vault LABEL, so the private half is generated inside the
/// vault and whoever distributed the record never sees the public half
/// either. This module is the only component that does.
///
/// # Safety
///
/// Caller holds an exclusive `&mut ModuleState` and a live `SyscallTable`.
unsafe fn announce_public_key(
    s: &ModuleState,
    sys: &SyscallTable,
    issuer: &[u8],
    kid: &[u8],
    profile_id: u16,
) {
    if s.out_key_announce < 0 || !s.key.is_open() {
        return;
    }
    let rec = auth_wire::KeyRecord {
        issuer,
        profile_id,
        kid,
        suite: s.key.suite(),
        state: auth_wire::key_state::ACTIVE,
        key_use: auth_wire::key_use::VERIFY,
        generation: 0,
        activate_after_unix: 0,
        remove_after_unix: 0,
        key_ref: s.key.public_key(),
    };
    let mut payload = [0u8; ANNOUNCE_BUF];
    let mut w = auth_wire::PayloadWriter::new(&mut payload);
    if rec.write(&mut w).is_err() {
        return;
    }
    let n = w.len();
    chan::channel_write_msg(
        sys,
        s.out_key_announce,
        auth_wire::MSG_KEY_ADD,
        &payload[..n],
    );
}

/// Derive the code-HMAC key from the vault-held signing key, once, at open.
///
/// **The derived key must survive a restart**, or a restart before
/// redemption invalidates every outstanding code — fail-closed, but a real
/// outage for anyone mid-enrolment. What makes that possible is a vault
/// that can reopen a key by name: the key material never has to be held in
/// module RAM or re-delivered.
///
/// The construction is `SHA-256(Sign_k(domain))`. Two properties make it
/// work, and both are load-bearing:
///
/// - **Ed25519 signing is deterministic BY SPECIFICATION** — RFC 8032
///   derives the nonce from the key and message, and admits no other
///   construction — so the same key over the same domain string yields the
///   same signature on every boot, on every backend. That is what makes
///   the derived key stable across restarts, and it is why this module
///   accepts Ed25519 keys ONLY. Determinism that a backend merely happens
///   to provide is not enough: ECDSA's is RFC 6979's convention and a
///   hardware token may use a random nonce instead, and FIPS 204 admits a
///   hedged ML-DSA alongside the deterministic one. Either would yield a
///   different signature per boot and silently invalidate every
///   outstanding code.
/// - **The signature is unavailable without the key**, which the vault never
///   exports — so the derived key is no weaker than the signing key itself.
///
/// The domain string is separate from anything the module ever signs for a
/// caller, so the derivation cannot be induced by asking for a challenge.
fn derive_code_key(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    const CODE_KEY_DOMAIN: &[u8] = b"kagi/enrolment/code-hmac/v1";
    let key = s.key;
    // SAFETY: `sys` is the module's own table; `sign_scratch` does not alias
    // the domain constant.
    let mut sig = [0u8; auth_wire::suite::MAX_IMPLEMENTED_SIGNATURE_LEN];
    let Some(sig_len) = (unsafe { key.sign(sys, &mut s.sign_scratch, CODE_KEY_DOMAIN, &mut sig) })
    else {
        return false;
    };
    s.code_key = sha256(&sig[..sig_len]);
    true
}

/// `HMAC-SHA256(k, nonce ‖ code)`, base64url.
///
/// The nonce is bound in so a code is only ever valid for the transaction it
/// was issued against — otherwise a code observed once would open any
/// transaction that happened to draw the same digits.
fn code_hash(key: &[u8; 32], nonce: &[u8], code: &[u8]) -> [u8; 43] {
    let mut message = [0u8; MAX_NONCE + CODE_DIGITS];
    let n = nonce.len().min(MAX_NONCE);
    message[..n].copy_from_slice(&nonce[..n]);
    let end = n + code.len().min(CODE_DIGITS);
    message[n..end].copy_from_slice(&code[..end - n]);
    let mut mac = [0u8; 32];
    hmac(HashAlg::Sha256, key, &message[..end], &mut mac);
    b64::encode_digest32(&mac)
}

/// Compare two code hashes without leaking where they first differ.
fn hashes_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Draw a decimal code from the platform CSPRNG.
///
/// Rejection sampling, not modulo. `byte % 10` maps 256 values onto ten
/// digits unevenly — 0 through 5 come up more often than 6 through 9 — and a
/// biased code is a smaller search space than its digit count claims.
///
/// # Safety
///
/// Caller supplies a live `SyscallTable`.
unsafe fn draw_code(sys: &SyscallTable, out: &mut [u8; CODE_DIGITS]) -> Result<(), Refusal> {
    let mut filled = 0usize;
    // Bounded: each round draws a full code's worth of bytes and keeps the
    // usable ones, so the expected number of rounds is a little over one and
    // the loop cannot run away.
    for _ in 0..16 {
        let mut raw = [0u8; CODE_DIGITS * 2];
        if (sys.provider_call)(-1, 0x0C3C, raw.as_mut_ptr(), raw.len()) < 0 {
            return Err(Refusal::NoEntropy);
        }
        for byte in raw {
            if filled == CODE_DIGITS {
                return Ok(());
            }
            // 250 is the largest multiple of 10 that fits a byte; anything
            // above it is discarded rather than folded.
            if byte < 250 {
                out[filled] = b'0' + (byte % 10);
                filled += 1;
            }
        }
        if filled == CODE_DIGITS {
            return Ok(());
        }
    }
    Err(Refusal::NoEntropy)
}

/// Submit the enrolment mail carrying `code` to `to`.
///
/// Fire-and-forget by design: the connector is a lockstep, single-submission
/// machine, and blocking `/start` on a delivery round trip would serialise
/// enrolment at one mailbox per RTT. The answer to `/start` is therefore not
/// a delivery claim — it says a code was issued and a submission was made.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn submit_mail(s: &mut ModuleState, sys: &SyscallTable, to: &[u8], code: &[u8], cid: u32) {
    if s.out_mail < 0 || !chan::can_write(sys, s.out_mail) {
        s.enrol_mail_failed = s.enrol_mail_failed.saturating_add(1);
        return;
    }
    let mut body = [0u8; 512];
    let mut at = 0usize;
    let put_str = |buf: &mut [u8], at: &mut usize, text: &[u8]| {
        let end = (*at + text.len()).min(buf.len());
        buf[*at..end].copy_from_slice(&text[..end - *at]);
        *at = end;
    };
    put_str(&mut body, &mut at, b"From: ");
    put_str(
        &mut body,
        &mut at,
        &s.mail_from[..usize::from(s.mail_from_len)],
    );
    put_str(&mut body, &mut at, b"\r\nTo: ");
    put_str(&mut body, &mut at, to);
    put_str(
        &mut body,
        &mut at,
        b"\r\nSubject: Your enrolment code\r\nContent-Type: text/plain\r\n\r\nEnrolment code: ",
    );
    put_str(&mut body, &mut at, code);
    put_str(&mut body, &mut at, b"\r\n");

    let mut frame = [0u8; 1024];
    let Some(n) = smtp_wire::write_smtp_request(
        smtp_wire::SMTP_OP_SUBMIT,
        cid,
        0,
        &s.mail_from[..usize::from(s.mail_from_len)],
        to,
        &body[..at],
        &mut frame,
    ) else {
        s.enrol_mail_failed = s.enrol_mail_failed.saturating_add(1);
        return;
    };
    if (sys.channel_write)(s.out_mail, frame.as_ptr(), n) > 0 {
        s.enrol_mail_submitted = s.enrol_mail_submitted.saturating_add(1);
    } else {
        s.enrol_mail_failed = s.enrol_mail_failed.saturating_add(1);
    }
}

/// Drain delivery results, so a refused submission is counted rather than
/// silently forgotten.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn drain_mail(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_mail < 0 {
        return;
    }
    while chan::can_read(sys, s.in_mail) {
        let mut buf = [0u8; 1024];
        let n = (sys.channel_read)(s.in_mail, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        let Some(head) = smtp_wire::parse_smtp_result(&buf[..n as usize]) else {
            continue;
        };
        if head.outcome != smtp_wire::SMTP_OUT_ACCEPTED {
            // The code will never arrive. The transaction is left to expire
            // rather than burned here: burning it would need the nonce this
            // result does not carry, and an expiry is the same outcome a few
            // minutes later.
            s.enrol_mail_failed = s.enrol_mail_failed.saturating_add(1);
        }
    }
}

/// This module's client id on the ledger's shared reply port.
const STATE_CLIENT: u8 = 1;

define_params! {
    ModuleState;

    1, iss, str, 0 => |s, d, len| {
        let n = if len > MAX_FIELD { MAX_FIELD } else { len };
        let mut i = 0usize;
        while i < n {
            s.iss[i] = *d.add(i);
            i += 1;
        }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_FIELD above")]
        {
            s.iss_len = n as u16;
        }
    };

    3, mail_from, str, 0 => |s, d, len| {
        let n = if len > MAX_FIELD { MAX_FIELD } else { len };
        let mut i = 0usize;
        while i < n {
            s.mail_from[i] = *d.add(i);
            i += 1;
        }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_FIELD above")]
        {
            s.mail_from_len = n as u16;
        }
    };

    2, tenant_seed, str, 0 => |s, d, len| {
        let n = if len > 64 { 64 } else { len };
        let mut i = 0usize;
        while i < n {
            s.tenant_seed[i] = *d.add(i);
            i += 1;
        }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to 64 above")]
        {
            s.tenant_seed_len = n as u16;
        }
    };
}

/// Why a request was refused.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Refusal {
    NoKey,
    NoEntropy,
    Malformed,
    BadChallenge,
    PkceMismatch,
    BadPossession,
    /// The presentation did not authenticate as an enrolled device.
    Unauthenticated,
    /// The device already holds an authenticator of this kind. Registering a
    /// second silently would leave the first unusable and unmentioned.
    AlreadyRegistered,
    /// No authenticator to confirm or verify against.
    NoAuthenticator,
    /// The code did not match any step in the window, or named a step at or
    /// below one already used.
    BadCode,
}

// ── TOTP profile ────────────────────────────────────────────────────────
//
// HMAC-SHA256, not the SHA-1 of RFC 6238's examples. RFC 6238 §1.2 admits
// SHA-256 and SHA-512, and the SDK's MAC surface offers SHA-256 and SHA-384:
// serving this one caller would mean adding an arm to a construction eleven
// modules share, for no security kagi gains — HMAC-SHA1 is not broken, it is
// simply not what anything else here computes.
//
// The `algorithm=SHA256` parameter is how the otpauth URI says so. An
// authenticator that ignores it computes SHA-1 codes, which fail at
// confirmation — in front of the person who just scanned it, rather than
// silently at the first mint that needed a second factor.

/// Bytes of secret drawn per authenticator.
///
/// 32, matching the HMAC's block-relevant digest size: a secret shorter than
/// the digest is the ceiling on the construction's strength, and one longer
/// is hashed down to it by HMAC anyway.
const TOTP_SECRET_BYTES: usize = 32;
/// Digits in a code. Six is what every authenticator shows.
const TOTP_DIGITS: u8 = 6;
/// Seconds per step.
const TOTP_PERIOD: u64 = 30;
/// Steps either side of the current one that are accepted.
///
/// One, so a code is live for at most 90 seconds. The window exists for
/// clock drift between the issuer and a phone, not for a user who took a
/// minute to type — and every step it widens is a step an attacker who
/// observed a code gets to reuse it in.
const TOTP_SKEW: u64 = 1;
/// Longest base32 secret this module will read back out of a record.
const TOTP_SECRET_B32: usize = totp::base32_encoded_len(TOTP_SECRET_BYTES);

impl Refusal {
    const fn status(self) -> u16 {
        match self {
            // The endpoint's own fault, not the caller's.
            Self::NoKey => 503,
            // Distinct from a missing key: both are the endpoint's own
            // fault, but one is a graph that has not been fed yet and the
            // other is a platform that cannot produce randomness — and an
            // operator seeing them merged would chase the wrong one.
            Self::NoEntropy => 500,
            Self::Malformed => 400,
            // A device already holding an authenticator is a conflict about
            // state, not a failed credential: the caller authenticated fine
            // and asked for something the ledger already answers.
            Self::AlreadyRegistered => 409,
            // Nothing to confirm or verify against. 404, because the
            // authenticator the request names does not exist.
            Self::NoAuthenticator => 404,
            // Everything else is a credential that did not hold up.
            Self::BadChallenge
            | Self::PkceMismatch
            | Self::BadPossession
            | Self::Unauthenticated
            | Self::BadCode => 401,
        }
    }

    /// The body a refusal answers with.
    ///
    /// PKCE and possession failures are told apart here because a legitimate
    /// client debugging its own integration cannot make progress otherwise,
    /// and neither reveals anything an attacker did not already supply: both
    /// are statements about material the caller itself sent.
    const fn body(self) -> &'static [u8] {
        match self {
            Self::NoKey => br#"{"error":"temporarily_unavailable"}"#,
            Self::NoEntropy => br#"{"error":"server_error","detail":"entropy"}"#,
            Self::Malformed => br#"{"error":"invalid_request"}"#,
            Self::BadChallenge => br#"{"error":"invalid_grant","detail":"challenge"}"#,
            Self::PkceMismatch => br#"{"error":"invalid_grant","detail":"pkce"}"#,
            Self::BadPossession => br#"{"error":"invalid_grant","detail":"possession"}"#,
            Self::Unauthenticated => br#"{"error":"invalid_client"}"#,
            Self::AlreadyRegistered => br#"{"error":"conflict","detail":"authenticator_exists"}"#,
            Self::NoAuthenticator => br#"{"error":"not_found","detail":"no_authenticator"}"#,
            // Deliberately the same shape as a bad possession proof: a code
            // that did not match and a code already used are the same answer
            // to whoever is guessing.
            Self::BadCode => br#"{"error":"invalid_grant","detail":"code"}"#,
        }
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[expect(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "fluxor module ABI entry point: the runtime owns these pointers \
              and the signature is fixed by the contract"
)]
#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs), the
    // kernel passes a valid, exclusively-borrowed `state` of at least
    // `module_state_size()` bytes, and a `syscalls` table whose function
    // pointers reach live kernel routines.
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<ModuleState>() {
            return -2;
        }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;

        s.in_requests = in_chan;
        s.out_responses = out_chan;
        s.in_key = dev_channel_port(sys, 0, 1);
        s.out_state = dev_channel_port(sys, 1, 1);
        s.in_state = dev_channel_port(sys, 0, 2);
        s.out_mail = dev_channel_port(sys, 1, 2);
        s.in_mail = dev_channel_port(sys, 0, 3);
        s.in_auth = dev_channel_port(sys, 0, 4);
        s.out_auth = dev_channel_port(sys, 1, 3);
        s.out_key_announce = dev_channel_port(sys, 1, 4);

        s.key = issuer_key::IssuerKey::empty();
        s.replay = dpop::ReplayWindow::new();
        s.code_key = [0; 32];
        s.kid = [0; 32];
        s.kid_len = 0;
        s.iss = [0; MAX_FIELD];
        s.iss_len = 0;
        s.tenant_seed = [0; 64];
        s.tenant_seed_len = 0;
        s.start_adopted = false;
        s.enrol_started = 0;
        s.enrol_redeemed = 0;
        s.enrol_no_key = 0;
        s.enrol_malformed = 0;
        s.enrol_bad_challenge = 0;
        s.enrol_pkce_mismatch = 0;
        s.enrol_bad_possession = 0;
        s.enrol_recorded = 0;
        s.enrol_replayed = 0;
        s.enrol_state_unavailable = 0;
        s.enrol_totp_registered = 0;
        s.enrol_totp_confirmed = 0;
        s.enrol_totp_conflict = 0;
        s.enrol_totp_bad_code = 0;
        s.enrol_mail_submitted = 0;
        s.enrol_mail_failed = 0;
        s.enrol_code_bad = 0;
        s.enrol_txn_burned = 0;
        s.redeem_nonce = [0u8; MAX_NONCE];
        s.redeem_nonce_len = 0;
        s.redeem_exp = 0;
        s.redeem_device_id = [0u8; 4 + ids::DEVICE_ID_LENGTH];
        s.redeem_claims = [0u8; 1024];
        s.redeem_claims_len = 0;
        s.redeem_code = [0u8; CODE_DIGITS];
        s.start_nonce = [0u8; MAX_NONCE];
        s.start_nonce_len = 0;
        s.start_code = [0u8; CODE_DIGITS];
        s.start_email = [0u8; MAX_FIELD];
        s.start_email_len = 0;
        s.start_exp = 0;
        s.mail_from = [0u8; MAX_FIELD];
        s.mail_from_len = 0;
        s.pending = [Pending::zero(); MAX_PENDING];
        s.next_corr = 1;

        parse_tlv(s, params, params_len);

        dev_log(sys, 3, b"[enrol] init".as_ptr(), 12);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: as `module_new`.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        drain_key(s, sys);
        drain_auth(s, sys);
        // Ledger replies before new requests, so a redemption that can be
        // completed this step is completed rather than held for another.
        drain_state(s, sys);
        drain_mail(s, sys);

        let mut worked = false;
        for _ in 0..MAX_REQS_PER_STEP {
            if !chan::can_read(sys, s.in_requests) || !chan::can_write(sys, s.out_responses) {
                break;
            }
            let n = (sys.channel_read)(s.in_requests, s.buf.as_mut_ptr(), s.buf.len());
            if n < REQ_HDR as i32 {
                break;
            }
            handle_request(s, sys, n as usize);
            worked = true;
        }

        if worked {
            STEP_DID_WORK
        } else {
            0
        }
    }
}

/// Take this profile's signing key from a `MSG_KEY_ADD`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn drain_key(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_key < 0 {
        return;
    }
    for _ in 0..4 {
        if !chan::can_read(sys, s.in_key) {
            break;
        }
        let mut buf = [0u8; 256];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_key, &mut buf);
        // The key lifecycle, not a single raw-key delivery. This endpoint
        // signs one artefact shape and holds one key for it, so it takes
        // the ADD for its own profile and ignores everything else on the
        // channel — the channel carries the whole issuer keyset.
        let payload = &buf[..plen as usize];
        if msg_type != auth_wire::MSG_KEY_ADD {
            continue;
        }
        let Ok(rec) = auth_wire::KeyRecord::decode_add(payload) else {
            continue;
        };
        if rec.key_use != auth_wire::key_use::SIGN
            || rec.profile_id != auth_wire::suite::profile::ENROLMENT_CHALLENGE
        {
            continue;
        }

        // Ed25519 only, and not merely for tidiness: `derive_code_key`
        // needs a signature that is the same on every boot, which RFC 8032
        // guarantees and no other suite here does. A graph that hands this
        // module a key of another suite has made a mistake worth failing
        // on rather than quietly not signing.
        let (kid, label) = (rec.kid, rec.key_ref);
        if rec.suite != auth_wire::suite::ED25519
            || label.is_empty()
            || label.len() > auth_wire::MAX_KEY_LABEL
            || kid.is_empty()
            || kid.len() > s.kid.len()
        {
            continue;
        }
        // A REDELIVERED record for the key already open is a no-op.
        //
        // Not an optimisation: closing and reopening releases the vault
        // handle and takes a new one, and any challenge already issued under
        // the old handle is then being verified across that seam. A control
        // plane that sends the same record twice — which is ordinary, since
        // records are idempotent by design — would otherwise invalidate
        // enrolments in flight.
        if s.key.is_open() && s.key.label() == label {
            continue;
        }
        // The record names a LABEL; the key is generated inside the vault on
        // first open and never travels.
        s.key.close(sys);
        if !s.key.open(sys, rec.suite, label) || !derive_code_key(s, sys) {
            s.key.close(sys);
            continue;
        }
        // Announced under DEVICE_CERTIFICATE, not under the profile the
        // signing record named. This key signs BOTH the enrolment challenge
        // (which only this module verifies, from its own copy) and the
        // device certificate (which `mint_admission` verifies, and looks up
        // under the profile the certificate belongs to). A verifier finds a
        // key by the profile of the credential it is checking, so the
        // announcement is filed where that lookup will go.
        announce_public_key(
            s,
            sys,
            rec.issuer,
            kid,
            auth_wire::suite::profile::DEVICE_CERTIFICATE,
        );
        s.kid = [0; 32];
        s.kid[..kid.len()].copy_from_slice(kid);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "bounded by kid.len() check"
        )]
        {
            s.kid_len = kid.len() as u8;
        }
    }
}

/// Route one request.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn handle_request(s: &mut ModuleState, sys: &SyscallTable, plen: usize) {
    if plen < REQ_HDR {
        return;
    }
    let conn = u16::from_le_bytes([s.buf[0], s.buf[1]]);
    let stream = u16::from_le_bytes([s.buf[2], s.buf[3]]);
    let method = s.buf[4];
    let path_len = u16::from_le_bytes([s.buf[6], s.buf[7]]) as usize;
    let hdr_len = u16::from_le_bytes([s.buf[8], s.buf[9]]) as usize;
    let body_len = u16::from_le_bytes([s.buf[10], s.buf[11]]) as usize;

    let Some(body_at) = REQ_HDR
        .checked_add(path_len)
        .and_then(|at| at.checked_add(hdr_len))
    else {
        return;
    };
    let Some(body_end) = body_at.checked_add(body_len) else {
        return;
    };
    if body_end > plen {
        refuse(s, sys, conn, stream, Refusal::Malformed);
        return;
    }

    let path = &s.buf[REQ_HDR..(REQ_HDR + path_len).min(plen)];
    let confirming = path.starts_with(b"/authenticators/totp/confirm");
    let registering = !confirming && path.starts_with(b"/authenticators/totp");
    let path_start = if path.starts_with(b"/start") {
        Some(true)
    } else if path.starts_with(b"/redeem") {
        Some(false)
    } else {
        None
    };
    if path_start.is_none() && !registering && !confirming {
        respond(s, sys, conn, stream, 404, br#"{"error":"not_found"}"#);
        return;
    }
    if method != METHOD_POST {
        respond(s, sys, conn, stream, 405, br#"{"error":"invalid_request"}"#);
        return;
    }
    if registering || confirming {
        totp_route(
            s, sys, conn, stream, confirming, path_len, body_at, body_end,
        );
        return;
    }
    let Some(is_start) = path_start else {
        respond(s, sys, conn, stream, 404, br#"{"error":"not_found"}"#);
        return;
    };
    if !s.key.is_open() {
        s.enrol_no_key = s.enrol_no_key.saturating_add(1);
        refuse(s, sys, conn, stream, Refusal::NoKey);
        return;
    }

    let outcome = if is_start {
        start(s, sys, body_at, body_end)
    } else {
        redeem(s, sys, body_at, body_end)
    };

    match outcome {
        Ok(len) => {
            if is_start {
                s.enrol_started = s.enrol_started.saturating_add(1);
            } else {
                s.enrol_redeemed = s.enrol_redeemed.saturating_add(1);
            }
            // The token was left at the front of `s.out`; copy it clear
            // before the response is written over the same buffer.
            let mut token = [0u8; MAX_TOKEN];
            token[..len].copy_from_slice(&s.out[..len]);
            if is_start {
                // The transaction has to exist before the client is told the
                // enrolment started: a challenge whose code the ledger never
                // recorded could never be redeemed, and the client would be
                // waiting on a mail that opens nothing.
                begin_start(s, sys, conn, stream, &token[..len]);
            } else {
                // A verified redemption is not yet a successful one. The
                // challenge's nonce has to be consumed in the ledger first,
                // and the certificate is only handed over if this redemption
                // is the one that consumed it. Everything below happens when
                // the ledger answers.
                begin_lookup(s, sys, conn, stream, &token[..len]);
            }
        }
        Err(refusal) => {
            match refusal {
                Refusal::Malformed => s.enrol_malformed = s.enrol_malformed.saturating_add(1),
                Refusal::BadChallenge => {
                    s.enrol_bad_challenge = s.enrol_bad_challenge.saturating_add(1);
                }
                Refusal::PkceMismatch => {
                    s.enrol_pkce_mismatch = s.enrol_pkce_mismatch.saturating_add(1);
                }
                Refusal::BadPossession => {
                    s.enrol_bad_possession = s.enrol_bad_possession.saturating_add(1);
                }
                Refusal::NoKey | Refusal::NoEntropy => {
                    s.enrol_no_key = s.enrol_no_key.saturating_add(1);
                }
                // The authenticator refusals have their own counters, raised
                // where the decision is made rather than here: this arm sees
                // only the refusals `/start` and `/redeem` produce.
                Refusal::Unauthenticated
                | Refusal::AlreadyRegistered
                | Refusal::NoAuthenticator
                | Refusal::BadCode => {}
            }
            refuse(s, sys, conn, stream, refusal);
        }
    }
}

/// Authenticate a device presenting its certificate and a DPoP proof.
///
/// Verified against THIS module's own key. It signed the certificate, so it
/// holds the public half already — which is why registering an authenticator
/// needs no verification-key edge of its own. A module that took one would
/// be trusting an operator to deliver the public half of a key it generated
/// itself.
///
/// # Safety
///
/// As `handle_request`.
unsafe fn authenticate_device(
    s: &mut ModuleState,
    presented: &Presented<'_>,
    now: u64,
) -> Result<Authenticated, Refusal> {
    let Presented {
        credential,
        proof,
        method,
        uri,
    } = *presented;
    if credential.is_empty() || proof.is_empty() || !s.key.is_open() {
        return Err(Refusal::Unauthenticated);
    }
    let mut claims_buf = [0u8; device_auth::MAX_SEGMENT];
    let claims_out = &mut claims_buf;
    let verifiers = device_auth::Verifiers {
        sha256: sha256_into,
        ecdsa_verify,
        ed25519_verify: ed25519_verify_slice,
        ml_dsa_verify: ml_dsa_verify_suite,
    };
    let policy = device_auth::Policy {
        proof_max_age_secs: PROOF_WINDOW_SECS,
        clock_skew_secs: 60,
        expected_cty: Some(b"dc+jwt"),
    };
    let public = s.key.public_key();
    let mut pubkey = [0u8; 65];
    let pubkey_len = public.len().min(pubkey.len());
    pubkey[..pubkey_len].copy_from_slice(&public[..pubkey_len]);
    let suite = s.key.suite();

    let mut replayed = false;
    let admitted = {
        let seen = &mut replayed;
        let mut offer = |jti: &[u8; 32]| match s.replay.offer(jti, now, now + PROOF_WINDOW_SECS) {
            dpop::Replay::Recorded => true,
            dpop::Replay::Seen | dpop::Replay::Full => {
                *seen = true;
                false
            }
        };
        device_auth::authenticate(
            &verifiers,
            &device_auth::IssuerKey {
                suite,
                public: &pubkey[..pubkey_len],
            },
            &device_auth::Presentation { credential, proof },
            &device_auth::Request { method, uri, now },
            &policy,
            claims_out,
            &mut offer,
        )
    };
    let Ok(admitted) = admitted else {
        return Err(Refusal::Unauthenticated);
    };
    let Some(id) = jose::claim_str(admitted.claims, b"device_id") else {
        return Err(Refusal::Unauthenticated);
    };
    let mut device_id = [0u8; MAX_FIELD];
    let device_id_len = id.len().min(MAX_FIELD);
    device_id[..device_id_len].copy_from_slice(&id[..device_id_len]);
    Ok(Authenticated {
        thumbprint: admitted.thumbprint,
        device_id,
        device_id_len,
    })
}

/// What a device presented, and the request it presented it for.
struct Presented<'a> {
    credential: &'a [u8],
    proof: &'a [u8],
    method: &'a [u8],
    uri: &'a [u8],
}

/// What authenticating a presentation established.
struct Authenticated {
    /// The device key's JWK thumbprint, base64url.
    thumbprint: [u8; 43],
    device_id: [u8; MAX_FIELD],
    device_id_len: usize,
}

/// How long a DPoP proof presented to this module stays fresh.
const PROOF_WINDOW_SECS: u64 = 300;

/// HMAC-SHA256 in the shape the TOTP fragment takes.
///
/// The fragment is algorithm-agnostic by design — it takes the MAC as a
/// function — which is what lets one implementation serve the RFC's SHA-1
/// vectors in the host suite and this profile's SHA-256 on target.
fn hmac_sha256_into(key: &[u8], message: &[u8], out: &mut [u8]) -> usize {
    let n = out.len().min(32);
    hmac(HashAlg::Sha256, key, message, &mut out[..n]);
    n
}

/// `/start`: bind an email, a device key and a PKCE challenge into a token.
///
/// Leaves the token at the front of `s.out` and returns its length.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn start(
    s: &mut ModuleState,
    sys: &SyscallTable,
    body_at: usize,
    body_end: usize,
) -> Result<usize, Refusal> {
    let mut email = [0u8; MAX_FIELD];
    let mut challenge = [0u8; MAX_FIELD];
    let mut canonical = [0u8; jwk::MAX_CANONICAL];
    let mut adopt = [0u8; MAX_FIELD];
    let (email_len, challenge_len, canonical_len, adopt_len) = {
        let body = &s.buf[body_at..body_end];
        let email_len = json_string(body, b"email", &mut email);
        let challenge_len = json_string(body, b"code_challenge", &mut challenge);
        let canonical_len = canonical_device_jwk(body, &mut canonical).unwrap_or(0);
        // The QR ceremony: `"transaction"` names a transaction an OPERATOR
        // already minted, in place of the mailbox this device cannot prove.
        let adopt_len = json_string(body, b"transaction", &mut adopt);
        (email_len, challenge_len, canonical_len, adopt_len)
    };
    // Exactly one delivery channel. A body carrying BOTH an email and a
    // transaction is refused rather than resolved: the two authorise by
    // different means, and a request that names both has not said which it
    // is claiming — while an implementation that picked one would be picking
    // for an attacker who supplied the other.
    if (email_len == 0) == (adopt_len == 0) {
        return Err(Refusal::Malformed);
    }
    if canonical_len == 0 || challenge_len != CODE_CHALLENGE_LEN {
        return Err(Refusal::Malformed);
    }
    // Only an operator-minted nonce may be adopted — see
    // `OPERATOR_NONCE_LEN`. A mailed transaction's nonce is a different
    // length and is refused here, so adoption cannot be turned against the
    // mail path.
    if adopt_len > 0 && adopt_len != OPERATOR_NONCE_LEN {
        return Err(Refusal::Malformed);
    }

    // Hashes, not the values: the token is handed to the caller, and an
    // email address in it would travel through every log the caller keeps.
    // An adopted ceremony hashes the empty string — there is no mailbox, and
    // a stand-in value would assert one.
    let email_hash = b64::encode_digest32(&sha256(&email[..email_len]));
    let pubkey_hash = b64::encode_digest32(&sha256(&canonical[..canonical_len]));

    let mut nonce = [0u8; 32];
    let nonce_len;
    let mut code = [0u8; CODE_DIGITS];
    if adopt_len > 0 {
        // QR ceremony: ADOPT the operator's transaction rather than creating
        // one. The nonce is theirs, and the code is already recorded against
        // it — this endpoint never learns the code and does not need to. The
        // device proves it holds the code at `/redeem`, exactly as a mailed
        // one does, so the redemption path is unchanged and cannot tell the
        // two ceremonies apart.
        //
        // What this branch does NOT do is check the transaction exists. That
        // is deliberate: `/start` here only binds a device key and a PKCE
        // challenge to a nonce, and a challenge token naming a transaction
        // that never existed is worthless — `/redeem` looks the nonce up and
        // refuses. Verifying here would add a round trip to learn something
        // the next step establishes anyway, and would answer a prober's
        // question about which nonces are live.
        nonce_len = adopt_len.min(nonce.len());
        nonce[..nonce_len].copy_from_slice(&adopt[..nonce_len]);
        s.start_code = [0u8; CODE_DIGITS];
    } else {
        let mut nonce_bytes = [0u8; NONCE_BYTES];
        // Only a negative result is a failure. The SDK's two descriptions of
        // `RANDOM_FILL` disagree — `kernel_abi.rs` says it returns the byte
        // count and `runtime/net.rs`'s own wrapper says it returns zero — so
        // this accepts either and refuses only the errno both agree on. A
        // predictable nonce is worse than no answer.
        if (sys.provider_call)(-1, 0x0C3C, nonce_bytes.as_mut_ptr(), NONCE_BYTES) < 0 {
            return Err(Refusal::NoEntropy);
        }
        nonce_len = b64::encode(&nonce_bytes, &mut nonce).ok_or(Refusal::Malformed)?;

        // The code that proves control of the mailbox. It never enters the
        // challenge token — the token goes to the client, and a client that
        // could read its own code would be proving nothing.
        draw_code(sys, &mut code)?;
        s.start_code = code;
    }
    s.start_adopted = adopt_len > 0;
    s.start_nonce = [0u8; MAX_NONCE];
    s.start_nonce[..nonce_len].copy_from_slice(&nonce[..nonce_len]);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_NONCE")]
    {
        s.start_nonce_len = nonce_len as u8;
    }
    s.start_email = [0u8; MAX_FIELD];
    s.start_email[..email_len].copy_from_slice(&email[..email_len]);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_FIELD")]
    {
        s.start_email_len = email_len as u16;
    }

    // The enrolment ceremony is the one place a device legitimately has no
    // clock of its own — it is being enrolled precisely because it is new.
    // That exception belongs to the DEVICE, not to this issuer: the issuer
    // is stamping a challenge's window and still needs a real reading, so
    // `EnrolmentCeremony` here means "an issuer-signed observation is what
    // the device may present back", not "this side may guess".
    let obs = dev_trusted_unix(sys);
    let now = time_policy::now_for(time_policy::Decision::EnrolmentCeremony, &obs).unwrap_or(0);
    if now == 0 {
        // A challenge dated from nothing is one `/redeem` cannot check.
        return Err(Refusal::NoKey);
    }

    let mut claims = [0u8; 1024];
    let mut at = 0usize;
    put(&mut claims, &mut at, br#"{"aud":"#)?;
    put_json_string(&mut claims, &mut at, &s.iss[..usize::from(s.iss_len)])?;
    put(&mut claims, &mut at, br#","code_challenge":"#)?;
    put_json_string(&mut claims, &mut at, &challenge[..challenge_len])?;
    put(
        &mut claims,
        &mut at,
        br#","code_challenge_method":"S256","email_hash":"#,
    )?;
    put_json_string(&mut claims, &mut at, &email_hash)?;
    put(&mut claims, &mut at, br#","exp":"#)?;
    put_u64(&mut claims, &mut at, now + CHALLENGE_TTL_SECS)?;
    s.start_exp = now + CHALLENGE_TTL_SECS;
    put(&mut claims, &mut at, br#","iat":"#)?;
    put_u64(&mut claims, &mut at, now)?;
    put(&mut claims, &mut at, br#","iss":"#)?;
    put_json_string(&mut claims, &mut at, &s.iss[..usize::from(s.iss_len)])?;
    put(&mut claims, &mut at, br#","nbf":"#)?;
    put_u64(&mut claims, &mut at, now)?;
    put(&mut claims, &mut at, br#","nonce":"#)?;
    put_json_string(&mut claims, &mut at, &nonce[..nonce_len])?;
    put(&mut claims, &mut at, br#","pubkey_hash":"#)?;
    put_json_string(&mut claims, &mut at, &pubkey_hash)?;
    put(&mut claims, &mut at, b"}")?;

    sign_jws(s, CHALLENGE_CTY, &claims[..at])
}

/// `/redeem`: check what `/start` signed, then issue the certificate.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn redeem(
    s: &mut ModuleState,
    sys: &SyscallTable,
    body_at: usize,
    body_end: usize,
) -> Result<usize, Refusal> {
    let mut token = [0u8; MAX_TOKEN];
    let mut verifier = [0u8; MAX_VERIFIER];
    let mut signature_b64 = [0u8; 128];
    let mut canonical = [0u8; jwk::MAX_CANONICAL];
    let mut code = [0u8; CODE_DIGITS];
    let (token_len, verifier_len, sig_len, canonical_len, code_len) = {
        let body = &s.buf[body_at..body_end];
        (
            json_string(body, b"challenge_token", &mut token),
            json_string(body, b"code_verifier", &mut verifier),
            json_string(body, b"pop_sig", &mut signature_b64),
            canonical_device_jwk(body, &mut canonical).unwrap_or(0),
            json_string(body, b"code", &mut code),
        )
    };
    // The mailed code is required. Everything else in this request proves
    // continuity with the client that started and possession of the device
    // key; none of it says anything about the mailbox.
    if code_len != CODE_DIGITS || !code.iter().all(u8::is_ascii_digit) {
        return Err(Refusal::Malformed);
    }
    s.redeem_code = code;
    if token_len == 0 || canonical_len == 0 || sig_len == 0 {
        return Err(Refusal::Malformed);
    }
    if !(MIN_VERIFIER..=MAX_VERIFIER).contains(&verifier_len) {
        return Err(Refusal::Malformed);
    }
    let token = &token[..token_len];

    // ── the challenge is ours, is a challenge, and is live ───────────────
    let jws = jose::Jws::split(token).ok_or(Refusal::BadChallenge)?;
    let mut header = [0u8; 256];
    let header_len = b64::decode(jws.header_b64, &mut header).ok_or(Refusal::BadChallenge)?;
    match jose::claim_str(&header[..header_len], b"cty") {
        Some(cty) if cty == CHALLENGE_CTY => {}
        _ => return Err(Refusal::BadChallenge),
    }
    let mut sig = [0u8; 64];
    if b64::decode(jws.signature_b64, &mut sig) != Some(64) {
        return Err(Refusal::BadChallenge);
    }
    // The public half as the vault exported it: there is no scalar here to
    // derive it from any more, which is the point.
    let mut pk = [0u8; 32];
    if s.key.public_key().len() != 32 {
        return Err(Refusal::BadChallenge);
    }
    pk.copy_from_slice(s.key.public_key());
    if !ed25519_verify(&pk, jws.signing_input, &sig) {
        return Err(Refusal::BadChallenge);
    }
    let mut claims = [0u8; 1024];
    let claims_len = b64::decode(jws.payload_b64, &mut claims).ok_or(Refusal::BadChallenge)?;
    let claims = &claims[..claims_len];

    // Checking the challenge's own window. A clock reading 0 makes
    // `now >= exp` false for every challenge ever issued, so an expired one
    // would be redeemed — the exact shape this migration exists to close.
    let obs = dev_trusted_unix(sys);
    let now = time_policy::now_for(time_policy::Decision::CredentialWindow, &obs)
        .ok_or(Refusal::BadChallenge)?;
    let exp = jose::claim_u64(claims, b"exp").ok_or(Refusal::BadChallenge)?;
    let nbf = jose::claim_u64(claims, b"nbf").ok_or(Refusal::BadChallenge)?;
    if now >= exp || nbf > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(Refusal::BadChallenge);
    }

    // The nonce identifies this exchange, and identifies it uniquely: it is
    // 32 CSPRNG bytes chosen at `/start`, and `/start` refuses outright
    // rather than answer with a predictable one. Consuming it is therefore
    // what makes a redemption single-use, and it is captured here — after
    // the signature has been checked, so an attacker cannot burn an honest
    // client's nonce by presenting a forged token that names it.
    let nonce = jose::claim_str(claims, b"nonce").ok_or(Refusal::BadChallenge)?;
    if nonce.is_empty() || nonce.len() > MAX_NONCE {
        return Err(Refusal::BadChallenge);
    }
    s.redeem_nonce = [0u8; MAX_NONCE];
    s.redeem_nonce[..nonce.len()].copy_from_slice(nonce);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by MAX_NONCE above"
    )]
    {
        s.redeem_nonce_len = nonce.len() as u8;
    }
    s.redeem_exp = exp;

    // ── the same party that started is redeeming ─────────────────────────
    let stored_challenge =
        jose::claim_str(claims, b"code_challenge").ok_or(Refusal::BadChallenge)?;
    match jose::claim_str(claims, b"code_challenge_method") {
        Some(method) if method == b"S256" => {}
        _ => return Err(Refusal::BadChallenge),
    }
    if !pkce::verify_s256(sha256_into, &verifier[..verifier_len], stored_challenge) {
        return Err(Refusal::PkceMismatch);
    }

    // ── the key redeeming is the key that started ────────────────────────
    let presented_hash = b64::encode_digest32(&sha256(&canonical[..canonical_len]));
    let bound_hash = jose::claim_str(claims, b"pubkey_hash").ok_or(Refusal::BadChallenge)?;
    if bound_hash != presented_hash {
        return Err(Refusal::BadPossession);
    }

    // ── and whoever redeems holds its private half ───────────────────────
    // The proof covers the whole challenge token, so it cannot be lifted onto
    // another exchange: a signature over a nonce alone would verify against
    // any challenge that happened to carry the same nonce.
    let mut pop = [0u8; 64];
    if b64::decode(&signature_b64[..sig_len], &mut pop) != Some(64) {
        return Err(Refusal::BadPossession);
    }
    if !verify_device_possession(&canonical[..canonical_len], token, &pop) {
        return Err(Refusal::BadPossession);
    }

    // ── the certificate ──────────────────────────────────────────────────
    let email_hash = jose::claim_str(claims, b"email_hash").ok_or(Refusal::BadChallenge)?;
    let mut device_id = [0u8; ids::DEVICE_ID_LENGTH];
    ids::device_id_from_canonical(sha256_into, &canonical[..canonical_len], &mut device_id);

    let mut tenant = [0u8; ids::TENANT_ID_LENGTH];
    ids::tenant_id(
        hkdf_into,
        &s.tenant_seed[..usize::from(s.tenant_seed_len)],
        email_hash,
        &mut tenant,
    )
    .map_err(|_| Refusal::Malformed)?;

    let mut out = [0u8; 1024];
    let mut at = 0usize;
    put(&mut out, &mut at, br#"{"cnf":{"jkt":"#)?;
    let thumbprint = jwk::thumbprint_from_canonical(sha256_into, &canonical[..canonical_len]);
    put_json_string(&mut out, &mut at, &thumbprint)?;
    put(&mut out, &mut at, br#"},"device_id":"#)?;
    put(&mut out, &mut at, b"\"dev_")?;
    put(&mut out, &mut at, &device_id)?;
    put(&mut out, &mut at, b"\"")?;
    put(&mut out, &mut at, br#","email_hash":"#)?;
    put_json_string(&mut out, &mut at, email_hash)?;
    // What the enrolment PROVED, recorded so admission can score it later.
    // The level is not stored: it is derived from these facts by the shared
    // fragment at mint time, so a record written today scores correctly under
    // a ladder that gains a rung tomorrow.
    //
    // `email` is the channel that proved control — the mailed code came back,
    // or an operator carried one for the QR ceremony. `key_binding` is
    // software because the device generated its own key and this issuer has
    // seen no attestation saying otherwise; recording anything stronger would
    // be claiming evidence nobody produced.
    put(
        &mut out,
        &mut at,
        br#","amr":["email","pop"],"key_binding":"#,
    )?;
    put_json_string(&mut out, &mut at, b"software")?;
    put(&mut out, &mut at, br#","exp":"#)?;
    put_u64(&mut out, &mut at, now + CERTIFICATE_TTL_SECS)?;
    put(&mut out, &mut at, br#","iat":"#)?;
    put_u64(&mut out, &mut at, now)?;
    put(&mut out, &mut at, br#","iss":"#)?;
    put_json_string(&mut out, &mut at, &s.iss[..usize::from(s.iss_len)])?;
    put(&mut out, &mut at, br#","sub":"#)?;
    put(&mut out, &mut at, b"\"tenant_")?;
    put(&mut out, &mut at, &tenant)?;
    put(&mut out, &mut at, b"\"}")?;

    let certificate_len = sign_jws(s, CERTIFICATE_CTY, &out[..at])?;

    // Record the device before answering. A certificate handed out for a
    // device the directory never learned about is a certificate nothing can
    // later revoke — and revocation is the only thing that makes a long-lived
    // enrolment anchor safe to issue at all.
    //
    // The record is the certificate's own claims: what was enrolled is
    // exactly what was attested, with no second rendering to disagree.
    // Held, not written. The record is committed by the staged path below,
    // after the challenge has been consumed and before the certificate is
    // released — so a device the ledger never heard of cannot be handed a
    // working credential.
    s.redeem_device_id = [0u8; 4 + ids::DEVICE_ID_LENGTH];
    s.redeem_device_id[..4].copy_from_slice(b"dev_");
    s.redeem_device_id[4..].copy_from_slice(&device_id);
    let claims_len = at.min(s.redeem_claims.len());
    s.redeem_claims[..claims_len].copy_from_slice(&out[..claims_len]);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by the buffer above"
    )]
    {
        s.redeem_claims_len = claims_len as u16;
    }

    Ok(certificate_len)
}

/// A helper that sends one ledger request and records the pending entry.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn dispatch(
    s: &mut ModuleState,
    sys: &SyscallTable,
    msg_type: u8,
    request: &state_wire::StateRequest<'_>,
    mut entry: Pending,
) -> bool {
    let mut frame = [0u8; 2048];
    let Ok(n) = state_wire::encode_request(&mut frame, msg_type, request) else {
        return false;
    };
    let Ok((wire_type, payload)) = auth_wire::read_envelope(&frame[..n]) else {
        return false;
    };
    if s.out_state < 0 || chan::channel_write_msg(sys, s.out_state, wire_type, payload) <= 0 {
        return false;
    }
    let Some(slot) = s.pending.iter().position(|p| !p.live) else {
        return false;
    };
    entry.live = true;
    entry.corr = request.correlation;
    s.pending[slot] = entry;
    true
}

/// Take the next correlation id.
fn next_corr(s: &mut ModuleState) -> u32 {
    let corr = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);
    corr
}

/// Commit the transaction `/start` created, then answer and mail the code.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn begin_start(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    token: &[u8],
) {
    if s.out_state < 0 || s.start_nonce_len == 0 {
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, conn, stream, 503, UNAVAILABLE_BODY);
        return;
    }
    if s.start_adopted {
        // The QR ceremony. The transaction already exists — an operator
        // minted it — so there is nothing to write and no mail to send, and
        // the challenge token can go back immediately.
        //
        // Writing it again would be worse than redundant: `put_if_absent`
        // would lose to the operator's own record and this would answer 503
        // for a ceremony that is perfectly valid.
        s.enrol_started = s.enrol_started.saturating_add(1);
        respond_token(s, sys, conn, stream, token);
        return;
    }
    let nonce_len = usize::from(s.start_nonce_len);
    let mut nonce = [0u8; MAX_NONCE];
    nonce[..nonce_len].copy_from_slice(&s.start_nonce[..nonce_len]);
    let hash = code_hash(&s.code_key, &nonce[..nonce_len], &s.start_code);

    // `{"attempts":0,"code_hash":"…","state":"pending"}` — the record the
    // redemption reads back. The code itself is never stored.
    let mut value = [0u8; 128];
    let mut at = 0usize;
    let _ = put(&mut value, &mut at, br#"{"attempts":0,"code_hash":""#);
    let _ = put(&mut value, &mut at, &hash);
    let _ = put(&mut value, &mut at, br#"","state":"pending"}"#);

    let corr = next_corr(s);
    let request = state_wire::put_if_absent(
        corr,
        STATE_CLIENT,
        state_wire::NS_ENROL_TXN,
        &nonce[..nonce_len],
        &value[..at],
        s.start_exp,
    );

    let mut entry = Pending::zero();
    entry.stage = STAGE_START;
    entry.conn = conn;
    entry.stream = stream;
    entry.nonce = nonce;
    entry.nonce_len = s.start_nonce_len;
    entry.code = s.start_code;
    let len = token.len().min(MAX_TOKEN);
    entry.cert[..len].copy_from_slice(&token[..len]);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_TOKEN")]
    {
        entry.cert_len = len as u16;
    }
    entry.claims_len = s.start_email_len;
    entry.claims[..usize::from(s.start_email_len)]
        .copy_from_slice(&s.start_email[..usize::from(s.start_email_len)]);

    if !dispatch(s, sys, state_wire::MSG_STATE_PUT_ABS, &request, entry) {
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, conn, stream, 503, UNAVAILABLE_BODY);
    }
}

/// Answer one operator request on the control plane.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn drain_auth(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_auth < 0 {
        return;
    }
    for _ in 0..2 {
        if !chan::can_read(sys, s.in_auth) {
            break;
        }
        let mut buf = [0u8; 512];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_auth, &mut buf);
        if msg_type != auth_wire::MSG_ENROL_AUTH_REQ {
            continue;
        }
        let Ok(req) = auth_wire::EnrolAuthRequest::decode(&buf[..plen as usize]) else {
            continue;
        };
        mint_authorisation(s, sys, req.correlation, req.ttl_seconds);
    }
}

/// Draw an authorisation and stage its durable record.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn mint_authorisation(s: &mut ModuleState, sys: &SyscallTable, corr: u32, ttl: u32) {
    // No signing key means no ceremony can be completed, so an authorisation
    // would be something that cannot be spent.
    if !s.key.is_open() || s.out_state < 0 {
        reply_auth_refused(s, sys, corr, auth_wire::ST_UNAVAILABLE);
        return;
    }

    // The transaction's nonce, drawn exactly as `/start` draws it.
    let mut nonce_bytes = [0u8; auth_wire::ENROL_AUTH_ID_BYTES];
    if (sys.provider_call)(-1, 0x0C3C, nonce_bytes.as_mut_ptr(), nonce_bytes.len()) < 0 {
        reply_auth_refused(s, sys, corr, auth_wire::ST_UNAVAILABLE);
        return;
    }
    let mut nonce = [0u8; 32];
    let Some(nonce_len) = b64::encode(&nonce_bytes, &mut nonce) else {
        reply_auth_refused(s, sys, corr, auth_wire::ST_UNAVAILABLE);
        return;
    };

    // And the code, by the same rejection sampling the mail path uses. This
    // is the one the operator will show; nothing else ever sees it.
    let mut code = [0u8; CODE_DIGITS];
    if draw_code(sys, &mut code).is_err() {
        reply_auth_refused(s, sys, corr, auth_wire::ST_UNAVAILABLE);
        return;
    }

    let obs = dev_trusted_unix(sys);
    let now = time_policy::now_for(time_policy::Decision::EnrolmentCeremony, &obs).unwrap_or(0);
    if now == 0 {
        // A transaction dated from nothing is one nothing can expire.
        reply_auth_refused(s, sys, corr, auth_wire::ST_UNAVAILABLE);
        return;
    }
    // CLAMPED, not refused: an operator who asks for an hour should get a
    // working authorisation that expires in five minutes, not an error they
    // work around by asking again.
    let ttl = if ttl == 0 || ttl > auth_wire::MAX_ENROL_AUTH_TTL_SECS {
        auth_wire::MAX_ENROL_AUTH_TTL_SECS
    } else {
        ttl
    };
    let exp = now + u64::from(ttl);

    // Byte-for-byte the record `/start` writes. That is the point: a
    // QR-delivered transaction and a mail-delivered one are the same object,
    // so `/redeem` needs no idea which it is looking at and cannot get that
    // question wrong.
    let hash = code_hash(&s.code_key, &nonce[..nonce_len], &code);
    let mut value = [0u8; 128];
    let mut at = 0usize;
    let _ = put(&mut value, &mut at, br#"{"attempts":0,"code_hash":""#);
    let _ = put(&mut value, &mut at, &hash);
    let _ = put(&mut value, &mut at, br#"","state":"pending"}"#);

    let state_corr = next_corr(s);
    let request = state_wire::put_if_absent(
        state_corr,
        STATE_CLIENT,
        state_wire::NS_ENROL_TXN,
        &nonce[..nonce_len],
        &value[..at],
        exp,
    );

    let mut entry = Pending::zero();
    entry.stage = STAGE_AUTH_MINT;
    entry.caller_corr = corr;
    entry.auth_exp = exp;
    entry.nonce[..nonce_len].copy_from_slice(&nonce[..nonce_len]);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_NONCE")]
    {
        entry.nonce_len = nonce_len as u8;
    }
    entry.code = code;

    if !dispatch(s, sys, state_wire::MSG_STATE_PUT_ABS, &request, entry) {
        reply_auth_refused(s, sys, corr, auth_wire::ST_UNAVAILABLE);
    }
}

/// The ledger answered the authorisation write.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn auth_mint_done(s: &mut ModuleState, sys: &SyscallTable, entry: &Pending, status: u8) {
    if status != auth_wire::ST_OK {
        // Including `ST_CONFLICT`: an id that already exists is not an
        // authorisation this call created, and answering OK would hand the
        // operator a secret that opens somebody else's record — or nothing.
        reply_auth_refused(s, sys, entry.caller_corr, auth_wire::ST_UNAVAILABLE);
        return;
    }
    let id_len = usize::from(entry.nonce_len);
    let resp = auth_wire::EnrolAuthResponse {
        correlation: entry.caller_corr,
        status: auth_wire::ST_OK,
        auth_id: &entry.nonce[..id_len],
        secret: &entry.code,
        expires_at: entry.auth_exp,
    };
    let mut out = [0u8; 256];
    if let Ok(n) = resp.encode(&mut out) {
        if s.out_auth >= 0 {
            let _ = (sys.channel_write)(s.out_auth, out.as_ptr(), n);
        }
    }
}

/// Tell the operator no, carrying nothing spendable.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn reply_auth_refused(s: &mut ModuleState, sys: &SyscallTable, corr: u32, status: u8) {
    if s.out_auth < 0 {
        return;
    }
    let resp = auth_wire::EnrolAuthResponse::refused(corr, status);
    let mut out = [0u8; 128];
    if let Ok(n) = resp.encode(&mut out) {
        let _ = (sys.channel_write)(s.out_auth, out.as_ptr(), n);
    }
}

/// Read the transaction back so the presented code can be checked against it.
///
/// The lookup comes before anything is spent. A redemption carrying the wrong
/// code must cost an attempt and nothing else — spending the transaction on a
/// wrong guess would hand an attacker a denial of service against the very
/// mailbox they failed to prove control of.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn begin_lookup(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    certificate: &[u8],
) {
    if s.out_state < 0 || s.redeem_nonce_len == 0 {
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, conn, stream, 503, UNAVAILABLE_BODY);
        return;
    }
    let nonce_len = usize::from(s.redeem_nonce_len);
    let mut nonce = [0u8; MAX_NONCE];
    nonce[..nonce_len].copy_from_slice(&s.redeem_nonce[..nonce_len]);

    let corr = next_corr(s);
    let request = state_wire::get(
        corr,
        STATE_CLIENT,
        state_wire::NS_ENROL_TXN,
        &nonce[..nonce_len],
    );

    let mut entry = Pending::zero();
    entry.stage = STAGE_LOOKUP;
    entry.conn = conn;
    entry.stream = stream;
    entry.nonce = nonce;
    entry.nonce_len = s.redeem_nonce_len;
    entry.code = s.redeem_code;
    entry.device_id = s.redeem_device_id;
    entry.claims = s.redeem_claims;
    entry.claims_len = s.redeem_claims_len;
    let len = certificate.len().min(MAX_TOKEN);
    entry.cert[..len].copy_from_slice(&certificate[..len]);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_TOKEN")]
    {
        entry.cert_len = len as u16;
    }

    if !dispatch(s, sys, state_wire::MSG_STATE_GET, &request, entry) {
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, conn, stream, 503, UNAVAILABLE_BODY);
    }
}

/// One header's value, by lowercase name.
fn header_value<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut at = 0usize;
    while at < headers.len() {
        let end = headers[at..]
            .iter()
            .position(|b| *b == b'\n')
            .map_or(headers.len(), |p| at + p);
        let line = &headers[at..end];
        if let Some(colon) = line.iter().position(|b| *b == b':') {
            let (key, value) = line.split_at(colon);
            if key.len() == name.len()
                && key
                    .iter()
                    .zip(name)
                    .all(|(a, b)| a.to_ascii_lowercase() == *b)
            {
                return Some(trim_ws(&value[1..]));
            }
        }
        at = end + 1;
    }
    None
}

/// The credential out of a `DPoP <token>` authorization header.
///
/// The scheme is required rather than tolerated: a `Bearer` in this position
/// is a caller presenting a token it expects to be taken on its own, and
/// answering it as though it had proved possession would be answering a
/// different request.
fn strip_dpop_scheme(value: &[u8]) -> Option<&[u8]> {
    let scheme = b"DPoP ";
    if value.len() > scheme.len() && value[..scheme.len()].eq_ignore_ascii_case(scheme) {
        Some(trim_ws(&value[scheme.len()..]))
    } else {
        None
    }
}

/// Copy what fits, reporting nothing when it does not.
///
/// A truncated credential is not a credential: it would fail to verify with
/// a reason that points at the signature rather than at the size.
fn copy_into(value: &[u8], out: &mut [u8]) -> usize {
    if value.len() > out.len() {
        return 0;
    }
    out[..value.len()].copy_from_slice(value);
    value.len()
}

fn trim_ws(value: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut end = value.len();
    while start < end && (value[start] == b' ' || value[start] == b'\t' || value[start] == b'\r') {
        start += 1;
    }
    while end > start
        && (value[end - 1] == b' ' || value[end - 1] == b'\t' || value[end - 1] == b'\r')
    {
        end -= 1;
    }
    &value[start..end]
}

/// Authenticate the presentation, then run whichever authenticator route the
/// path named.
///
/// The two share everything up to the point they differ: both are a device
/// proving who it is before touching its own record.
///
/// # Safety
///
/// As `handle_request`.
#[expect(
    clippy::too_many_arguments,
    reason = "the request's own framing (path, body bounds) plus the route;               grouping it would move the same fields through one more type"
)]
unsafe fn totp_route(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    confirming: bool,
    path_len: usize,
    body_at: usize,
    body_end: usize,
) {
    let obs = dev_trusted_unix(sys);
    let Some(now) = time_policy::now_for(time_policy::Decision::CredentialWindow, &obs) else {
        respond(s, sys, conn, stream, 503, UNAVAILABLE_BODY);
        return;
    };

    let mut credential = [0u8; MAX_TOKEN];
    let mut proof = [0u8; MAX_TOKEN];
    let mut uri = [0u8; MAX_FIELD];
    let (credential_len, proof_len, uri_len) = {
        let path = &s.buf[REQ_HDR..REQ_HDR + path_len];
        let headers = &s.buf[REQ_HDR + path_len..body_at];
        let uri_len = path.len().min(uri.len());
        uri[..uri_len].copy_from_slice(&path[..uri_len]);
        (
            header_value(headers, b"authorization")
                .and_then(strip_dpop_scheme)
                .map_or(0, |v| copy_into(v, &mut credential)),
            header_value(headers, b"dpop").map_or(0, |v| copy_into(v, &mut proof)),
            uri_len,
        )
    };

    let who = {
        let presented = Presented {
            credential: &credential[..credential_len],
            proof: &proof[..proof_len],
            method: b"POST",
            uri: &uri[..uri_len],
        };
        match authenticate_device(s, &presented, now) {
            Ok(who) => who,
            Err(refusal) => {
                refuse(s, sys, conn, stream, refusal);
                return;
            }
        }
    };

    if confirming {
        // JSON, as `/start` and `/redeem` take: one body shape for one
        // endpoint, rather than a second parser for one field.
        let mut code = [0u8; totp::MAX_DIGITS as usize];
        let code_len = {
            let body = &s.buf[body_at..body_end];
            jose::claim_str(body, b"code").map_or(0, |value| copy_into(value, &mut code))
        };
        begin_totp_confirm(s, sys, conn, stream, &who, &code[..code_len]);
    } else {
        begin_totp_register(s, sys, conn, stream, &who);
    }
}

/// `POST /authenticators/totp` — attach a TOTP authenticator to a device.
///
/// A second factor has to be something the device does not already have. The
/// device key it authenticates with is possession; a code from an
/// authenticator app is knowledge, and the two together are what moves a
/// deployment off `aal1`.
///
/// The secret is drawn HERE, from the platform CSPRNG, not supplied by the
/// caller. A client-chosen secret is a client-chosen factor: whoever picked
/// it can compute its codes, so a device could enrol a factor it does not
/// have to hold.
///
/// It is returned exactly once, in this response, and never again. The record
/// keeps it because verifying a code needs it, and there is deliberately no
/// route that reads it back out.
///
/// # Safety
///
/// As `handle_request`.
unsafe fn begin_totp_register(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    who: &Authenticated,
) {
    if s.out_state < 0 {
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, conn, stream, 503, UNAVAILABLE_BODY);
        return;
    }
    let mut raw = [0u8; TOTP_SECRET_BYTES];
    if (sys.provider_call)(-1, 0x0C3C, raw.as_mut_ptr(), raw.len()) < 0 {
        refuse(s, sys, conn, stream, Refusal::NoEntropy);
        return;
    }
    let mut secret = [0u8; TOTP_SECRET_B32];
    let Ok(secret_len) = totp::base32_encode(&raw, &mut secret) else {
        refuse(s, sys, conn, stream, Refusal::NoEntropy);
        return;
    };

    let mut entry = Pending::zero();
    entry.stage = STAGE_TOTP_READ;
    entry.conn = conn;
    entry.stream = stream;
    entry.totp_confirming = false;
    entry.totp_secret = secret;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by TOTP_SECRET_B32"
    )]
    {
        entry.totp_secret_len = secret_len as u8;
    }
    stage_device_read(s, sys, conn, stream, who, entry);
}

/// `POST /authenticators/totp/confirm` — prove the authenticator works.
///
/// Registration is not adoption. A device that stored the secret wrongly, or
/// an authenticator that ignored `algorithm=SHA256` and computed SHA-1
/// codes, produces an authenticator that exists and cannot be used — and the
/// first anyone would learn of it is a device locked out of the factor it
/// was told it had. Confirmation is where that fails instead, in front of
/// the person who just scanned it.
///
/// Until it is confirmed the authenticator contributes no evidence, so an
/// unconfirmed registration cannot raise a token's assurance.
///
/// # Safety
///
/// As `handle_request`.
unsafe fn begin_totp_confirm(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    who: &Authenticated,
    code: &[u8],
) {
    if s.out_state < 0 {
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, conn, stream, 503, UNAVAILABLE_BODY);
        return;
    }
    if code.is_empty() || code.len() > usize::from(totp::MAX_DIGITS) {
        refuse(s, sys, conn, stream, Refusal::Malformed);
        return;
    }
    let mut entry = Pending::zero();
    entry.stage = STAGE_TOTP_READ;
    entry.conn = conn;
    entry.stream = stream;
    entry.totp_confirming = true;
    entry.totp_code[..code.len()].copy_from_slice(code);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_DIGITS")]
    {
        entry.totp_code_len = code.len() as u8;
    }
    stage_device_read(s, sys, conn, stream, who, entry);
}

/// Read the device record both authenticator routes act on.
///
/// # Safety
///
/// As `handle_request`.
unsafe fn stage_device_read(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    who: &Authenticated,
    mut entry: Pending,
) {
    let corr = next_corr(s);
    let key = &who.device_id[..who.device_id_len];
    let request = state_wire::get(corr, STATE_CLIENT, state_wire::NS_DEVICE, key);

    let n = key.len().min(entry.device_id.len());
    entry.device_id[..n].copy_from_slice(&key[..n]);
    if !dispatch(s, sys, state_wire::MSG_STATE_GET, &request, entry) {
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, conn, stream, 503, UNAVAILABLE_BODY);
    }
}

/// Answer redemptions whose consume has come back.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn drain_state(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_state < 0 {
        return;
    }
    while chan::can_read(sys, s.in_state) {
        let mut frame = [0u8; 512];
        let (msg_type, plen) = chan::channel_read_msg(sys, s.in_state, &mut frame);
        if msg_type == 0 {
            break;
        }
        let Ok(reply) = state_wire::StateReply::decode(msg_type, &frame[..plen as usize]) else {
            continue;
        };
        // The ledger's reply port fans out to every consumer, so a reply
        // addressed to another module is not this module's to act on.
        if reply.client != STATE_CLIENT {
            continue;
        }
        let Some(slot) = s
            .pending
            .iter()
            .position(|p| p.live && p.corr == reply.correlation)
        else {
            continue;
        };
        let entry = s.pending[slot];
        s.pending[slot] = Pending::zero();
        let mut value = [0u8; 256];
        let vlen = reply.value.len().min(value.len());
        value[..vlen].copy_from_slice(&reply.value[..vlen]);
        let mut etag = [0u8; state_wire::MAX_ETAG];
        let elen = reply.etag.len().min(etag.len());
        etag[..elen].copy_from_slice(&reply.etag[..elen]);
        complete(s, sys, &entry, reply.status, &value[..vlen], &etag[..elen]);
    }
}

/// Turn a ledger verdict into the next step, or the client's answer.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn complete(
    s: &mut ModuleState,
    sys: &SyscallTable,
    entry: &Pending,
    status: u8,
    value: &[u8],
    etag: &[u8],
) {
    match entry.stage {
        STAGE_START => start_done(s, sys, entry, status),
        STAGE_LOOKUP => lookup_done(s, sys, entry, status, value, etag),
        STAGE_CONSUME => consume_done(s, sys, entry, status),
        STAGE_AUTH_MINT => auth_mint_done(s, sys, entry, status),
        STAGE_TOTP_READ => totp_read_done(s, sys, entry, status, value, etag),
        STAGE_TOTP_WRITE => totp_write_done(s, sys, entry, status),
        _ => commit_done(s, sys, entry, status),
    }
}

/// Rewrite a device record with its authenticator fields set.
///
/// The record is rebuilt from the one that was read rather than patched: the
/// reader takes the FIRST match for a key, so appending a second `totp_secret`
/// would leave the old one winning every read. Everything the ledger held is
/// carried across; only the authenticator fields are this function's.
fn write_device_record(
    out: &mut [u8],
    held: &[u8],
    secret: &[u8],
    confirmed: bool,
    counter: u64,
) -> Option<usize> {
    if !jose::is_record_safe(secret) {
        return None;
    }
    let mut at = 0usize;
    let carry = |out: &mut [u8], at: &mut usize, key: &[u8], value: &[u8]| -> bool {
        if value.is_empty() || !jose::is_record_safe(value) {
            return true;
        }
        put(out, at, b"\"").is_ok()
            && put(out, at, key).is_ok()
            && put(out, at, br#"":""#).is_ok()
            && put(out, at, value).is_ok()
            && put(out, at, br#"","#).is_ok()
    };

    put(out, &mut at, b"{").ok()?;
    for key in [
        &b"cnf"[..],
        b"device_id",
        b"email_hash",
        b"iss",
        b"sub",
        b"status",
        b"key_binding",
    ] {
        let value = jose::claim_str(held, key).unwrap_or(b"");
        if !carry(out, &mut at, key, value) {
            return None;
        }
    }
    // `cnf` is an object in the record, not a string; its `jkt` is what a
    // reader wants and what `claim_str` finds either way.
    for key in [&b"exp"[..], b"iat"] {
        if let Some(value) = jose::claim_u64(held, key) {
            put(out, &mut at, b"\"").ok()?;
            put(out, &mut at, key).ok()?;
            put(out, &mut at, br#"":"#).ok()?;
            put_u64(out, &mut at, value).ok()?;
            put(out, &mut at, b",").ok()?;
        }
    }
    if let Some(amr) = jose::claim_array_raw(held, b"amr") {
        put(out, &mut at, br#""amr":"#).ok()?;
        put(out, &mut at, amr).ok()?;
        put(out, &mut at, b",").ok()?;
    }
    put(out, &mut at, br#""totp_secret":""#).ok()?;
    put(out, &mut at, secret).ok()?;
    // A string, not a JSON boolean: the shared reader takes string claims,
    // and a field written in a shape it cannot read is a field that always
    // reads as absent — which for a confirmation flag means an authenticator
    // that never counts.
    put(out, &mut at, br#"","totp_confirmed":""#).ok()?;
    put(out, &mut at, if confirmed { b"true" } else { b"false" }).ok()?;
    put(out, &mut at, b"\"").ok()?;
    put(out, &mut at, br#","totp_counter":"#).ok()?;
    put_u64(out, &mut at, counter).ok()?;
    put(out, &mut at, b"}").ok()?;
    Some(at)
}

/// Replace the device record, conditional on the revision it was read at.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn cas_device(
    s: &mut ModuleState,
    sys: &SyscallTable,
    entry: &mut Pending,
    etag: &[u8],
    value: &[u8],
) -> bool {
    let corr = next_corr(s);
    let key_len = entry
        .device_id
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(entry.device_id.len());
    let mut key = [0u8; 4 + ids::DEVICE_ID_LENGTH];
    key.copy_from_slice(&entry.device_id);
    let request = state_wire::StateRequest {
        correlation: corr,
        client: STATE_CLIENT,
        namespace: state_wire::NS_DEVICE,
        key: &key[..key_len],
        etag,
        value,
        // Device membership does not expire; revocation ends it.
        expiry_unix: 0,
    };
    dispatch(s, sys, state_wire::MSG_STATE_CAS, &request, *entry)
}

/// The device record came back: attach the authenticator, or check a code.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn totp_read_done(
    s: &mut ModuleState,
    sys: &SyscallTable,
    entry: &Pending,
    status: u8,
    value: &[u8],
    etag: &[u8],
) {
    if status != auth_wire::ST_OK {
        // The certificate verified but the ledger holds no such device: a
        // certificate outliving its enrolment. The same refusal minting
        // gives it.
        let refusal = if status == auth_wire::ST_NOT_FOUND {
            Refusal::Unauthenticated
        } else {
            s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
            respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
            return;
        };
        refuse(s, sys, entry.conn, entry.stream, refusal);
        return;
    }

    let held = jose::claim_str(value, b"totp_secret").unwrap_or(b"");
    if entry.totp_confirming {
        confirm_against(s, sys, entry, value, etag, held);
    } else if held.is_empty() {
        attach_authenticator(s, sys, entry, value, etag);
    } else {
        // Replacing one silently would leave the device holding an
        // authenticator whose codes no longer verify, with nothing having
        // said so. Removing an authenticator is its own decision.
        s.enrol_totp_conflict = s.enrol_totp_conflict.saturating_add(1);
        refuse(s, sys, entry.conn, entry.stream, Refusal::AlreadyRegistered);
    }
}

/// Write the drawn secret into the device record, unconfirmed.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn attach_authenticator(
    s: &mut ModuleState,
    sys: &SyscallTable,
    entry: &Pending,
    value: &[u8],
    etag: &[u8],
) {
    let secret = &entry.totp_secret[..usize::from(entry.totp_secret_len)];
    let mut record = [0u8; 1536];
    let Some(len) = write_device_record(&mut record, value, secret, false, 0) else {
        refuse(s, sys, entry.conn, entry.stream, Refusal::Malformed);
        return;
    };

    let mut next = *entry;
    next.stage = STAGE_TOTP_WRITE;
    if !cas_device(s, sys, &mut next, etag, &record[..len]) {
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
    }
}

/// Check a presented code and, if it holds, confirm the authenticator.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn confirm_against(
    s: &mut ModuleState,
    sys: &SyscallTable,
    entry: &Pending,
    value: &[u8],
    etag: &[u8],
    held: &[u8],
) {
    if held.is_empty() {
        refuse(s, sys, entry.conn, entry.stream, Refusal::NoAuthenticator);
        return;
    }
    let obs = dev_trusted_unix(sys);
    let Some(now) = time_policy::now_for(time_policy::Decision::CredentialWindow, &obs) else {
        // A code is a statement about the current step, so a window cannot
        // be judged without a clock this deployment trusts.
        respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        return;
    };
    let Some(matched) = verify_presented_code(entry, held, value, now) else {
        s.enrol_totp_bad_code = s.enrol_totp_bad_code.saturating_add(1);
        refuse(s, sys, entry.conn, entry.stream, Refusal::BadCode);
        return;
    };

    let mut record = [0u8; 1536];
    let Some(len) = write_device_record(&mut record, value, held, true, matched) else {
        refuse(s, sys, entry.conn, entry.stream, Refusal::Malformed);
        return;
    };
    let mut next = *entry;
    next.stage = STAGE_TOTP_WRITE;
    if !cas_device(s, sys, &mut next, etag, &record[..len]) {
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
    }
}

/// Verify the presented code against the record's secret and counter.
///
/// Returns the step it matched, which becomes the record's new floor.
fn verify_presented_code(entry: &Pending, held: &[u8], record: &[u8], now: u64) -> Option<u64> {
    let code = totp::parse_code(&entry.totp_code[..usize::from(entry.totp_code_len)]).ok()?;
    let mut secret = [0u8; totp::MAX_SECRET];
    let secret_len = totp::base32_decode(held, &mut secret).ok()?;
    // The floor a code must beat. Absent on the first verification, which is
    // the confirmation itself.
    let last = jose::claim_u64(record, b"totp_counter");
    let matched = totp::verify_totp(
        hmac_sha256_into,
        &secret[..secret_len],
        code,
        now,
        0,
        TOTP_PERIOD,
        TOTP_DIGITS,
        TOTP_SKEW,
        last,
    )
    .ok()??;
    Some(matched.counter)
}

/// The authenticator write came back.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn totp_write_done(s: &mut ModuleState, sys: &SyscallTable, entry: &Pending, status: u8) {
    if status != auth_wire::ST_OK {
        // The record moved under the write. Two registrations racing, or a
        // confirmation against a revision another confirmation already
        // advanced — either way this one did not happen, and saying so is
        // the only honest answer.
        s.enrol_totp_conflict = s.enrol_totp_conflict.saturating_add(1);
        refuse(s, sys, entry.conn, entry.stream, Refusal::AlreadyRegistered);
        return;
    }
    if entry.totp_confirming {
        s.enrol_totp_confirmed = s.enrol_totp_confirmed.saturating_add(1);
        respond(
            s,
            sys,
            entry.conn,
            entry.stream,
            200,
            br#"{"confirmed":true}"#,
        );
        return;
    }

    // The one time the secret is readable. There is no route that reads it
    // back, so a client that loses it registers again after removing this
    // one rather than asking.
    s.enrol_totp_registered = s.enrol_totp_registered.saturating_add(1);
    let mut body = [0u8; 256];
    let mut at = 0usize;
    let secret = &entry.totp_secret[..usize::from(entry.totp_secret_len)];
    let ok = put(&mut body, &mut at, br#"{"secret":""#).is_ok()
        && put(&mut body, &mut at, secret).is_ok()
        && put(
            &mut body,
            &mut at,
            br#"","algorithm":"SHA256","digits":6,"period":30,"confirmed":false}"#,
        )
        .is_ok();
    if ok {
        respond(s, sys, entry.conn, entry.stream, 200, &body[..at]);
    } else {
        respond(s, sys, entry.conn, entry.stream, 500, UNAVAILABLE_BODY);
    }
}

/// The transaction is recorded: answer `/start` and mail the code.
///
/// The mail goes out only now. Submitting before the record existed would
/// send somebody a code that opens nothing.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn start_done(s: &mut ModuleState, sys: &SyscallTable, entry: &Pending, status: u8) {
    if status != auth_wire::ST_OK {
        // A nonce collision is not a thing that happens with 32 CSPRNG bytes,
        // so a conflict here means the ledger is answering about something
        // else. Either way there is no transaction, so there is no enrolment.
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        return;
    }
    let email_len = usize::from(entry.claims_len);
    let mut email = [0u8; MAX_FIELD];
    email[..email_len].copy_from_slice(&entry.claims[..email_len]);
    let cid = entry.corr;
    submit_mail(s, sys, &email[..email_len], &entry.code, cid);

    s.enrol_started = s.enrol_started.saturating_add(1);
    let len = usize::from(entry.cert_len);
    let mut token = [0u8; MAX_TOKEN];
    token[..len].copy_from_slice(&entry.cert[..len]);
    respond_token(s, sys, entry.conn, entry.stream, &token[..len]);
}

/// Hand back the challenge token — the answer to a successful `/start`,
/// whichever ceremony produced it.
///
/// One writer for both paths on purpose: a mailed ceremony and an adopted
/// one must be indistinguishable from outside, and two response builders is
/// how they would drift apart.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn respond_token(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    token: &[u8],
) {
    let mut body = [0u8; MAX_TOKEN + 64];
    let n = write_json_field(&mut body, b"challenge_token", token);
    respond(s, sys, conn, stream, 200, &body[..n]);
}

/// The transaction came back: check the code, then spend it.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn lookup_done(
    s: &mut ModuleState,
    sys: &SyscallTable,
    entry: &Pending,
    status: u8,
    value: &[u8],
    etag: &[u8],
) {
    if status == auth_wire::ST_NOT_FOUND {
        // No transaction: either it expired, or it was burned by too many
        // wrong codes. Answered exactly as a wrong code is, so probing for
        // which one it was tells an attacker nothing.
        s.enrol_code_bad = s.enrol_code_bad.saturating_add(1);
        respond(s, sys, entry.conn, entry.stream, 401, CODE_BODY);
        return;
    }
    if status != auth_wire::ST_OK {
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        return;
    }
    // A transaction that is not `pending` has already been spent.
    match jose::claim_str(value, b"state") {
        Some(state) if state == b"pending" => {}
        _ => {
            s.enrol_replayed = s.enrol_replayed.saturating_add(1);
            respond(s, sys, entry.conn, entry.stream, 409, CONSUMED_BODY);
            return;
        }
    }
    let attempts = jose::claim_u64(value, b"attempts").unwrap_or(0);
    let Some(stored) = jose::claim_str(value, b"code_hash") else {
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        return;
    };

    let nonce_len = usize::from(entry.nonce_len);
    let presented = code_hash(&s.code_key, &entry.nonce[..nonce_len], &entry.code);
    if !hashes_equal(stored, &presented) {
        s.enrol_code_bad = s.enrol_code_bad.saturating_add(1);
        let mut kept = [0u8; 43];
        let keep = stored.len().min(kept.len());
        kept[..keep].copy_from_slice(&stored[..keep]);
        burn_or_count(s, sys, entry, etag, attempts, &kept[..keep]);
        return;
    }

    // The code is right. Spend the transaction, conditional on the revision
    // the code was checked against — so two redemptions racing the same
    // correct code cannot both win.
    let corr = next_corr(s);
    let request = state_wire::compare_and_swap(
        corr,
        STATE_CLIENT,
        state_wire::NS_ENROL_TXN,
        &entry.nonce[..nonce_len],
        etag,
        br#"{"attempts":0,"code_hash":"","state":"consumed"}"#,
        0,
    );
    let mut next = *entry;
    next.stage = STAGE_CONSUME;
    if !dispatch(s, sys, state_wire::MSG_STATE_CAS, &request, next) {
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
    }
}

/// Record a wrong guess, burning the transaction once the cap is reached.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn burn_or_count(
    s: &mut ModuleState,
    sys: &SyscallTable,
    entry: &Pending,
    etag: &[u8],
    attempts: u64,
    stored_hash: &[u8],
) {
    let nonce_len = usize::from(entry.nonce_len);
    let next_attempts = attempts.saturating_add(1);
    let burned = next_attempts >= u64::from(MAX_CODE_ATTEMPTS);
    if burned {
        s.enrol_txn_burned = s.enrol_txn_burned.saturating_add(1);
    }
    let mut value = [0u8; 128];
    let mut at = 0usize;
    let _ = put(&mut value, &mut at, br#"{"attempts":"#);
    let _ = put_u64(&mut value, &mut at, next_attempts);
    if burned {
        let _ = put(&mut value, &mut at, br#","code_hash":"","state":"burned"}"#);
    } else {
        // The hash is carried through unchanged. Rewriting the record
        // without it would make every later correct code fail — a wrong
        // guess would lock the transaction rather than cost an attempt.
        let _ = put(&mut value, &mut at, br#","code_hash":""#);
        let _ = put(&mut value, &mut at, stored_hash);
        let _ = put(&mut value, &mut at, br#"","state":"pending"}"#);
    }

    // Best effort, and deliberately so: the answer to the client is the same
    // either way, and a counter that failed to increment costs an attempt of
    // slack rather than a security property. Refusing the request because the
    // counter could not be written would turn a storage hiccup into an
    // enrolment nobody can complete.
    let corr = next_corr(s);
    let request = state_wire::compare_and_swap(
        corr,
        STATE_CLIENT,
        state_wire::NS_ENROL_TXN,
        &entry.nonce[..nonce_len],
        etag,
        &value[..at],
        0,
    );
    let mut frame = [0u8; 512];
    if let Ok(n) = state_wire::encode_request(&mut frame, state_wire::MSG_STATE_CAS, &request) {
        if let Ok((wire_type, payload)) = auth_wire::read_envelope(&frame[..n]) {
            let _ = chan::channel_write_msg(sys, s.out_state, wire_type, payload);
        }
    }
    respond(s, sys, entry.conn, entry.stream, 401, CODE_BODY);
}

/// The transaction is spent: commit the device.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn consume_done(s: &mut ModuleState, sys: &SyscallTable, entry: &Pending, status: u8) {
    match status {
        auth_wire::ST_OK => begin_commit(s, sys, entry),
        auth_wire::ST_CONFLICT => {
            // Somebody else spent it between the read and the swap.
            s.enrol_replayed = s.enrol_replayed.saturating_add(1);
            respond(s, sys, entry.conn, entry.stream, 409, CONSUMED_BODY);
        }
        _ => {
            s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
            respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        }
    }
}

/// The body a wrong or unusable code is answered with. Identical for a wrong
/// code, an expired transaction and a burned one, so probing cannot
/// distinguish them.
const CODE_BODY: &[u8] = br#"{"error":"invalid_grant","detail":"code"}"#;
/// The body a spent transaction is answered with.
const CONSUMED_BODY: &[u8] = br#"{"error":"invalid_grant","detail":"consumed"}"#;

/// Commit the device record, with the answer still held.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn begin_commit(s: &mut ModuleState, sys: &SyscallTable, entry: &Pending) {
    let Some(slot) = s.pending.iter().position(|p| !p.live) else {
        // The nonce is already spent, so this enrolment cannot be retried
        // with the same challenge — but a spent challenge is recoverable by
        // starting a new one, where a device issued a certificate and never
        // recorded is not. Refusing is the safe direction.
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        return;
    };

    let corr = s.next_corr;
    s.next_corr = s.next_corr.wrapping_add(1).max(1);

    let claims_len = usize::from(entry.claims_len);
    let request = state_wire::put_if_absent(
        corr,
        STATE_CLIENT,
        state_wire::NS_DEVICE,
        &entry.device_id,
        &entry.claims[..claims_len],
        // Device membership does not expire with the challenge that created
        // it; revocation, not a timer, is what ends it.
        0,
    );
    let mut frame = [0u8; 2048];
    let Ok(n) = state_wire::encode_request(&mut frame, state_wire::MSG_STATE_PUT_ABS, &request)
    else {
        respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        return;
    };
    let Ok((msg_type, payload)) = auth_wire::read_envelope(&frame[..n]) else {
        respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        return;
    };
    if chan::channel_write_msg(sys, s.out_state, msg_type, payload) <= 0 {
        s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
        respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        return;
    }

    let mut next = *entry;
    next.live = true;
    next.stage = STAGE_COMMIT;
    next.corr = corr;
    s.pending[slot] = next;
}

/// Release the certificate once the device is durably recorded.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn commit_done(s: &mut ModuleState, sys: &SyscallTable, entry: &Pending, status: u8) {
    match status {
        // `ST_CONFLICT` means the record is already there, which is what a
        // device re-enrolling with the same key looks like: the device id is
        // derived from that key, so the row it would write is the row that
        // exists. The invariant this step protects — the device is in the
        // ledger before the certificate is released — holds either way.
        auth_wire::ST_OK | auth_wire::ST_CONFLICT => {
            s.enrol_redeemed = s.enrol_redeemed.saturating_add(1);
            s.enrol_recorded = s.enrol_recorded.saturating_add(1);
            let len = usize::from(entry.cert_len);
            let mut body = [0u8; MAX_TOKEN + 64];
            let n = write_json_field(&mut body, b"device_certificate", &entry.cert[..len]);
            respond(s, sys, entry.conn, entry.stream, 200, &body[..n]);
        }
        _ => {
            // The write did not land. The challenge is spent and no
            // certificate is issued — an enrolment that has to be restarted,
            // rather than a device holding a credential nothing can revoke.
            s.enrol_state_unavailable = s.enrol_state_unavailable.saturating_add(1);
            respond(s, sys, entry.conn, entry.stream, 503, UNAVAILABLE_BODY);
        }
    }
}

/// The body a refusal caused by an unreachable ledger carries.
const UNAVAILABLE_BODY: &[u8] = br#"{"error":"temporarily_unavailable","detail":"durability"}"#;

fn put_u32_le(out: &mut [u8], at: &mut usize, value: u32) -> Result<(), Refusal> {
    put(out, at, &value.to_le_bytes())
}

fn put_field8(out: &mut [u8], at: &mut usize, value: &[u8]) -> Result<(), Refusal> {
    let len = u8::try_from(value.len()).map_err(|_| Refusal::Malformed)?;
    put(out, at, &[len])?;
    put(out, at, value)
}

fn put_field16(out: &mut [u8], at: &mut usize, value: &[u8]) -> Result<(), Refusal> {
    let len = u16::try_from(value.len()).map_err(|_| Refusal::Malformed)?;
    put(out, at, &len.to_le_bytes())?;
    put(out, at, value)
}

/// Verify a possession proof under the device's own key.
///
/// The algorithm comes from the key's `kty`, never from anything the caller
/// wrote: letting a caller name the verifier is the algorithm-confusion path.
fn verify_device_possession(canonical_jwk: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
    let Some(kty) = jose::claim_str(canonical_jwk, b"kty") else {
        return false;
    };
    match kty {
        b"OKP" => {
            let Some(x) = jose::claim_str(canonical_jwk, b"x") else {
                return false;
            };
            let mut key = [0u8; 32];
            if b64::decode(x, &mut key) != Some(32) {
                return false;
            }
            ed25519_verify(&key, message, signature)
        }
        b"EC" => {
            let (Some(x), Some(y)) = (
                jose::claim_str(canonical_jwk, b"x"),
                jose::claim_str(canonical_jwk, b"y"),
            ) else {
                return false;
            };
            let mut point = [0u8; 65];
            point[0] = 0x04;
            if b64::decode(x, &mut point[1..33]) != Some(32)
                || b64::decode(y, &mut point[33..65]) != Some(32)
            {
                return false;
            }
            ecdsa_verify(&point, &sha256(message), signature)
        }
        _ => false,
    }
}

/// Sign `claims` as a JWS typed `cty`, leaving it at the front of `s.out`.
fn sign_jws(s: &mut ModuleState, cty: &[u8], claims: &[u8]) -> Result<usize, Refusal> {
    let mut header = [0u8; 192];
    let mut at = 0usize;
    put(&mut header, &mut at, br#"{"alg":"EdDSA","cty":"#)?;
    put_json_string(&mut header, &mut at, cty)?;
    put(&mut header, &mut at, br#","kid":"#)?;
    put_json_string(&mut header, &mut at, &s.kid[..usize::from(s.kid_len)])?;
    put(&mut header, &mut at, br#","typ":"JWT"}"#)?;

    let mut token = [0u8; MAX_TOKEN];
    let mut n = 0usize;
    let header_len = b64::encode(&header[..at], &mut token).ok_or(Refusal::Malformed)?;
    n += header_len;
    put(&mut token, &mut n, b".")?;
    let claims_len = b64::encode(claims, &mut token[n..]).ok_or(Refusal::Malformed)?;
    n += claims_len;

    // SAFETY: `s.syscalls` is the table handed to `module_new`;
    // `sign_scratch` does not alias `token`.
    let sys = unsafe { &*s.syscalls };
    let key = s.key;
    // Sized from the registry rather than from ES256's 64 bytes: what the
    // issuer key's suite signs in is what this has to hold.
    let mut signature = [0u8; auth_wire::suite::MAX_IMPLEMENTED_SIGNATURE_LEN];
    let signature_len = unsafe { key.sign(sys, &mut s.sign_scratch, &token[..n], &mut signature) }
        .ok_or(Refusal::Malformed)?;
    put(&mut token, &mut n, b".")?;
    let sig_len =
        b64::encode(&signature[..signature_len], &mut token[n..]).ok_or(Refusal::Malformed)?;
    n += sig_len;

    if n > s.out.len() {
        return Err(Refusal::Malformed);
    }
    s.out[..n].copy_from_slice(&token[..n]);
    Ok(n)
}

/// The device key from a request body, in canonical member order.
///
/// Canonical because two spellings of one key must produce one hash: the
/// `pubkey_hash` written at `/start` is compared against the one computed at
/// `/redeem`, and a caller that reordered its JSON between the two would
/// otherwise be told its key had changed.
fn canonical_device_jwk(body: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut record = jwk::JwkRecord::new();
    let mut found = false;
    for (name, field) in [
        (&b"crv"[..], 0u8),
        (&b"kty"[..], 1),
        (&b"x"[..], 2),
        (&b"y"[..], 3),
    ] {
        if let Some(value) = jose::claim_str(body, name) {
            let set = jwk::Field::set(value).ok()?;
            match field {
                0 => record.crv = set,
                1 => {
                    record.kty = set;
                    found = true;
                }
                2 => record.x = set,
                _ => record.y = set,
            }
        }
    }
    if !found {
        return None;
    }
    record.canonical_json(out).ok()
}

/// A JSON string member's value, into `out`. `0` when absent or over-long.
///
/// The same flat scan the shared claim reader uses: it finds `"<key>"` as a
/// member and reads the quoted value after it. Escapes are not interpreted,
/// which is why every field this endpoint reads is one whose alphabet has no
/// escapable character — base64url, an email address, a compact JWS.
fn json_string(body: &[u8], key: &[u8], out: &mut [u8]) -> usize {
    let Some(value) = jose::claim_str(body, key) else {
        return 0;
    };
    if value.is_empty() || value.len() > out.len() {
        return 0;
    }
    out[..value.len()].copy_from_slice(value);
    value.len()
}

/// `{"<field>":"<value>"}`.
fn write_json_field(out: &mut [u8], field: &[u8], value: &[u8]) -> usize {
    let mut at = 0usize;
    let _ = put(out, &mut at, b"{");
    let _ = put_json_string(out, &mut at, field);
    let _ = put(out, &mut at, b":");
    let _ = put_json_string(out, &mut at, value);
    let _ = put(out, &mut at, b"}");
    at
}

fn put(out: &mut [u8], at: &mut usize, bytes: &[u8]) -> Result<(), Refusal> {
    let end = at.checked_add(bytes.len()).ok_or(Refusal::Malformed)?;
    out.get_mut(*at..end)
        .ok_or(Refusal::Malformed)?
        .copy_from_slice(bytes);
    *at = end;
    Ok(())
}

fn put_json_string(out: &mut [u8], at: &mut usize, value: &[u8]) -> Result<(), Refusal> {
    // A value that could end its own string could introduce a key, and the
    // reader takes the FIRST match anywhere in the record — see
    // `jose::is_record_safe`. Every value written here is a thumbprint, a
    // hash or a deployment parameter today, and the guard is what keeps that
    // a fact rather than a habit.
    if !jose::is_record_safe(value) {
        return Err(Refusal::Malformed);
    }
    put(out, at, b"\"")?;
    put(out, at, value)?;
    put(out, at, b"\"")
}

fn put_u64(out: &mut [u8], at: &mut usize, mut value: u64) -> Result<(), Refusal> {
    if value == 0 {
        return put(out, at, b"0");
    }
    let mut digits = [0u8; 20];
    let mut n = 0usize;
    while value > 0 && n < digits.len() {
        digits[n] = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
        n += 1;
    }
    let mut ordered = [0u8; 20];
    for i in 0..n {
        ordered[i] = digits[n - 1 - i];
    }
    put(out, at, &ordered[..n])
}

/// The `Sha256Fn` shape the fragments take.
fn sha256_into(data: &[u8], out: &mut [u8; 32]) {
    *out = sha256(data);
}

/// The `HkdfSha256Fn` shape `ids` takes.
fn hkdf_into(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8; 32]) {
    let mut prk = [0u8; 32];
    hkdf_extract(HashAlg::Sha256, salt, ikm, &mut prk);
    hkdf_expand(HashAlg::Sha256, &prk, info, okm);
}

/// Answer a refusal.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn refuse(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    refusal: Refusal,
) {
    respond(s, sys, conn, stream, refusal.status(), refusal.body());
}

/// Emit one `HttpResponse` carrying `body` as JSON.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn respond(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    status: u16,
    body: &[u8],
) {
    const CT: &[u8] = b"application/json";
    let total = RESP_HDR + CT.len() + body.len();
    if total > s.out.len() {
        return;
    }
    s.out[0..2].copy_from_slice(&conn.to_le_bytes());
    s.out[2..4].copy_from_slice(&stream.to_le_bytes());
    s.out[4..6].copy_from_slice(&status.to_le_bytes());
    s.out[6] = 0;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "CT is a 16-byte literal, so the length fits a u8"
    )]
    {
        s.out[7] = CT.len() as u8;
    }
    s.out[8..10].copy_from_slice(&0u16.to_le_bytes());
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by the `total > s.out.len()` check above"
    )]
    {
        s.out[10..12].copy_from_slice(&(body.len() as u16).to_le_bytes());
    }
    s.out[RESP_HDR..RESP_HDR + CT.len()].copy_from_slice(CT);
    s.out[RESP_HDR + CT.len()..total].copy_from_slice(body);

    (sys.channel_write)(s.out_responses, s.out.as_ptr(), total);
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

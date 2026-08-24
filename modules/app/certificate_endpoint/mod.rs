//! Certificate endpoint — an X.509 client certificate for a device key.
//!
//! kagi's device identities are signed JWTs, which suit bearer flows and
//! cannot drive a TLS client-certificate bootstrap. `POST /pki/certificate`
//! closes that gap: it takes a subject public key and a SPIFFE identity, and
//! answers with a DER-encoded end-entity certificate this CA signed.
//!
//! **Its own deployment, not the issuer's.** A PKI authority is a different
//! thing from a token issuer — a different key, a different blast radius,
//! plausibly a different machine — so it gets its own graph (`configs/
//! pki.yaml`) rather than sharing the issuer's. The issuer graph is also
//! already at `LINUX_NET_MAX_INBOUND`, the provider's eight producer lanes,
//! so a ninth `http` module there would get no lane and never bind.
//!
//! The SPIFFE identity goes in the `subjectAltName`, not the subject `CN`.
//! Relying parties authorize on the SAN URI; an identity written only into
//! the `CN` is a certificate that authorizes nothing.
//!
//! Both the CA key and the subject key may be Ed25519 or P-256, because the
//! carriers need different ones. A device bootstrapping mTLS presents
//! whichever key it holds; a JWT-SVID is ES256-signed by a P-256 leaf key and
//! its relying party requires a P-256 trust root, so an Ed25519-only
//! authority could not serve that carrier at all.
//!
//! `GET /pki/ca` answers with the authority's own self-signed certificate —
//! the trust root a relying party chains to. Serving it is not a convenience:
//! a CA whose certificate had to be copied out of band is a CA whose
//! certificate goes stale somewhere.

#![no_std]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in target/fluxor/fluxor-abi/sdk/"
)]
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "the fluxor module ABI entry points (module_init/module_new/module_step): the \
              runtime owns these pointers and their validity is the ABI's contract, and the \
              signature is fixed by that contract rather than chosen here. The same allow \
              wave's and lattice's PIC modules carry."
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

#[path = "../../common/auth_wire.rs"]
mod auth_wire;
#[path = "../../common/b64.rs"]
mod b64;
#[path = "../../common/chan.rs"]
mod chan;
#[path = "../../common/der.rs"]
mod der;
#[path = "../../common/jose.rs"]
mod jose;
#[path = "../../common/spiffe.rs"]
mod spiffe;

use auth_wire::PayloadReader;

const STEP_DID_WORK: i32 = 2;
const REQ_HDR: usize = 12;
const RESP_HDR: usize = 12;
const METHOD_POST: u8 = 3;

/// How long an issued certificate is valid, in seconds.
const CERTIFICATE_TTL_SECS: u64 = 30 * 24 * 3600;
/// How long the authority's own certificate is valid. Longer than a leaf,
/// because rotating a trust root is a deployment-wide event.
const CA_TTL_SECS: u64 = 3650 * 24 * 3600;
/// Longest value read from a request.
const MAX_FIELD: usize = 256;
/// The DER a certificate occupies. A leaf with one SAN is a few hundred
/// bytes; 2 KiB is room for a long SPIFFE path and no room for a surprise.
const MAX_DER: usize = 2048;
const MAX_REQS_PER_STEP: usize = 2;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,
    out_responses: i32,
    in_key: i32,

    /// The CA's private key: an Ed25519 seed, or a P-256 scalar.
    seed: [u8; 32],
    /// `auth_wire::MINT_ALG_*` of the loaded key.
    key_alg: u8,
    has_key: bool,

    /// The CA's own name, and the trust domain its SPIFFE ids belong to.
    /// Graph parameters: a caller that could name its own issuer could get a
    /// certificate claiming to come from another authority.
    issuer_cn: [u8; MAX_FIELD],
    issuer_cn_len: u16,
    trust_domain: [u8; MAX_FIELD],
    trust_domain_len: u16,

    /// Serial numbers, monotonic. Two certificates from one CA sharing a
    /// serial is what makes revocation ambiguous.
    next_serial: u64,

    certificate_issued: u32,
    certificate_no_key: u32,
    certificate_malformed: u32,

    buf: [u8; abi::CHANNEL_BUFFER_SIZE],
    out: [u8; abi::CHANNEL_BUFFER_SIZE],
}

define_params! {
    ModuleState;

    1, issuer_cn, str, 0 => |s, d, len| {
        let n = if len > MAX_FIELD { MAX_FIELD } else { len };
        let mut i = 0usize;
        while i < n {
            s.issuer_cn[i] = *d.add(i);
            i += 1;
        }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_FIELD above")]
        {
            s.issuer_cn_len = n as u16;
        }
    };

    2, trust_domain, str, 0 => |s, d, len| {
        let n = if len > MAX_FIELD { MAX_FIELD } else { len };
        let mut i = 0usize;
        while i < n {
            s.trust_domain[i] = *d.add(i);
            i += 1;
        }
        #[expect(clippy::cast_possible_truncation, reason = "clamped to MAX_FIELD above")]
        {
            s.trust_domain_len = n as u16;
        }
    };
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

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
    // SAFETY: per the module ABI, the kernel passes a valid, exclusively
    // borrowed `state` of at least `module_state_size()` bytes and a live
    // syscall table.
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
        s.seed = [0; 32];
        s.key_alg = 0;
        s.has_key = false;
        s.issuer_cn = [0; MAX_FIELD];
        s.issuer_cn_len = 0;
        s.trust_domain = [0; MAX_FIELD];
        s.trust_domain_len = 0;
        s.next_serial = 1;
        s.certificate_issued = 0;
        s.certificate_no_key = 0;
        s.certificate_malformed = 0;

        parse_tlv(s, params, params_len);

        dev_log(sys, 3, b"[pki] init".as_ptr(), 10);
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

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a live syscall table.
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
        if msg_type != auth_wire::MSG_MINT_KEY {
            continue;
        }
        let mut r = PayloadReader::new(&buf[..plen as usize]);
        let (Ok(alg), Ok(_kid)) = (r.u8(), r.field8()) else {
            continue;
        };
        let seed = r.rest();
        if (alg != auth_wire::MINT_ALG_ED25519 && alg != auth_wire::MINT_ALG_ES256)
            || seed.len() < 32
        {
            continue;
        }
        s.seed.copy_from_slice(&seed[..32]);
        s.key_alg = alg;
        s.has_key = true;
    }
}

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
        respond(
            s,
            sys,
            conn,
            stream,
            400,
            b"application/json",
            br#"{"error":"invalid_request"}"#,
        );
        return;
    }
    let path = &s.buf[REQ_HDR..REQ_HDR + path_len];
    let issuing = path == b"/pki/certificate";
    let root = path == b"/pki/ca";
    if !issuing && !root {
        respond(
            s,
            sys,
            conn,
            stream,
            404,
            b"application/json",
            br#"{"error":"not_found"}"#,
        );
        return;
    }
    if root {
        serve_ca(s, sys, conn, stream);
        return;
    }
    if method != METHOD_POST {
        respond(
            s,
            sys,
            conn,
            stream,
            405,
            b"application/json",
            br#"{"error":"invalid_request"}"#,
        );
        return;
    }
    if !s.has_key {
        s.certificate_no_key = s.certificate_no_key.saturating_add(1);
        respond(
            s,
            sys,
            conn,
            stream,
            503,
            b"application/json",
            br#"{"error":"temporarily_unavailable"}"#,
        );
        return;
    }

    let mut subject = [0u8; MAX_FIELD];
    let mut tenant = [0u8; MAX_FIELD];
    let mut device = [0u8; MAX_FIELD];
    let mut ed25519_key = [0u8; 32];
    let mut p256_point = [0u8; 65];
    let (subject_len, tenant_len, device_len, key_bytes) = {
        let body = &s.buf[body_at..body_end];
        let subject_len = json_string(body, b"subject", &mut subject);
        let tenant_len = json_string(body, b"tenant", &mut tenant);
        let device_len = json_string(body, b"device", &mut device);
        let mut encoded = [0u8; 192];
        let encoded_len = json_string(body, b"public_key", &mut encoded);
        // The key's own length says which kind it is: 32 bytes is Ed25519, 65
        // is an uncompressed SEC1 point. No `alg` field, because a caller
        // that named its key's type separately could name one the bytes are
        // not.
        let mut scratch = [0u8; 65];
        let key_bytes = if encoded_len == 0 {
            0
        } else {
            b64::decode(&encoded[..encoded_len], &mut scratch).unwrap_or(0)
        };
        match key_bytes {
            32 => ed25519_key.copy_from_slice(&scratch[..32]),
            65 => p256_point.copy_from_slice(&scratch),
            _ => {}
        }
        (subject_len, tenant_len, device_len, key_bytes)
    };
    let subject_key = match key_bytes {
        32 => der::SubjectKey::Ed25519(&ed25519_key),
        // An uncompressed point starts 0x04; a compressed one would need the
        // curve arithmetic to recover Y, which this does not do.
        65 if p256_point[0] == 0x04 => der::SubjectKey::P256(&p256_point),
        _ => {
            s.certificate_malformed = s.certificate_malformed.saturating_add(1);
            respond(
                s,
                sys,
                conn,
                stream,
                400,
                b"application/json",
                br#"{"error":"invalid_request"}"#,
            );
            return;
        }
    };

    if subject_len == 0 || tenant_len == 0 || device_len == 0 {
        s.certificate_malformed = s.certificate_malformed.saturating_add(1);
        respond(
            s,
            sys,
            conn,
            stream,
            400,
            b"application/json",
            br#"{"error":"invalid_request"}"#,
        );
        return;
    }

    // The SPIFFE id is composed here from the deployment's trust domain and
    // the tenant and device the caller named — never taken whole from the
    // request, because a caller that could write its own SPIFFE id could
    // write one in somebody else's trust domain.
    let mut san = [0u8; spiffe::MAX_NAME];
    let Some(san_len) = spiffe::write_device(
        &mut san,
        &s.trust_domain[..usize::from(s.trust_domain_len)],
        &tenant[..tenant_len],
        &device[..device_len],
    ) else {
        s.certificate_malformed = s.certificate_malformed.saturating_add(1);
        respond(
            s,
            sys,
            conn,
            stream,
            400,
            b"application/json",
            br#"{"error":"invalid_request"}"#,
        );
        return;
    };

    let now = dev_unix_millis(sys) / 1000;
    let serial = s.next_serial;

    let mut tbs = [0u8; MAX_DER];
    let tbs_len = {
        let mut w = der::Writer::new(&mut tbs);
        if w.tbs_certificate(
            &serial.to_be_bytes(),
            &s.issuer_cn[..usize::from(s.issuer_cn_len)],
            &subject[..subject_len],
            subject_key,
            algorithm(s.key_alg),
            now,
            now + CERTIFICATE_TTL_SECS,
            &san[..san_len],
        )
        .is_err()
        {
            respond(
                s,
                sys,
                conn,
                stream,
                500,
                b"application/json",
                br#"{"error":"server_error"}"#,
            );
            return;
        }
        w.len()
    };

    let mut certificate = [0u8; MAX_DER];
    let Some(cert_len) = seal(s, &tbs[..tbs_len], &mut certificate) else {
        respond(
            s,
            sys,
            conn,
            stream,
            500,
            b"application/json",
            br#"{"error":"server_error"}"#,
        );
        return;
    };

    s.next_serial = s.next_serial.saturating_add(1);
    s.certificate_issued = s.certificate_issued.saturating_add(1);

    // The DER goes back base64'd inside JSON rather than as
    // `application/pkix-cert`, so one response shape covers the refusals too
    // and a caller parses one thing.
    let mut encoded = [0u8; MAX_DER * 2];
    let Some(encoded_len) = b64::encode(&certificate[..cert_len], &mut encoded) else {
        respond(
            s,
            sys,
            conn,
            stream,
            500,
            b"application/json",
            br#"{"error":"server_error"}"#,
        );
        return;
    };
    let mut body = [0u8; MAX_DER * 2 + 128];
    let mut at = 0usize;
    let _ = put(&mut body, &mut at, br#"{"certificate":""#);
    let _ = put(&mut body, &mut at, &encoded[..encoded_len]);
    let _ = put(&mut body, &mut at, br#"","spiffe_id":""#);
    let _ = put(&mut body, &mut at, &san[..san_len]);
    let _ = put(&mut body, &mut at, b"\"}");

    respond(s, sys, conn, stream, 200, b"application/json", &body[..at]);
}

/// The algorithm the loaded key signs with.
const fn algorithm(key_alg: u8) -> der::SigningAlgorithm {
    if key_alg == auth_wire::MINT_ALG_ES256 {
        der::SigningAlgorithm::P256
    } else {
        der::SigningAlgorithm::Ed25519
    }
}

/// Sign `tbs` and wrap it into a whole certificate in `out`.
fn seal(s: &ModuleState, tbs: &[u8], out: &mut [u8]) -> Option<usize> {
    let algorithm = algorithm(s.key_alg);
    let mut w = der::Writer::new(out);
    w.constructed(0x30, |cert| {
        // The TBS goes in byte for byte as it was signed. Re-encoding it from
        // its fields could produce a different — still valid — encoding, and
        // the signature would not verify over that one.
        cert.raw(tbs)?;
        cert.signature_algorithm(algorithm)?;
        match algorithm {
            der::SigningAlgorithm::Ed25519 => cert.bit_string(&ed25519_sign(&s.seed, tbs)),
            der::SigningAlgorithm::P256 => {
                let raw =
                    ecdsa_sign(&s.seed, &sha256(tbs), &[0u8; 32]).ok_or(der::DerError::TooLong)?;
                let (encoded, len) = encode_der_signature(&raw);
                cert.ecdsa_signature(encoded.get(..len).ok_or(der::DerError::TooLong)?)
            }
        }
    })
    .ok()?;
    Some(w.len())
}

/// The authority's own certificate: self-signed, and a CA.
///
/// # Safety
///
/// As `drain_key`.
unsafe fn serve_ca(s: &mut ModuleState, sys: &SyscallTable, conn: u16, stream: u16) {
    if !s.has_key {
        s.certificate_no_key = s.certificate_no_key.saturating_add(1);
        respond(
            s,
            sys,
            conn,
            stream,
            503,
            b"application/json",
            br#"{"error":"temporarily_unavailable"}"#,
        );
        return;
    }
    let now = dev_unix_millis(sys) / 1000;
    let public = ca_public_key(s);
    let cn_len = usize::from(s.issuer_cn_len);

    let mut tbs = [0u8; MAX_DER];
    let tbs_len = {
        let mut w = der::Writer::new(&mut tbs);
        let subject_key = match &public {
            CaPublicKey::Ed25519(key) => der::SubjectKey::Ed25519(key),
            CaPublicKey::P256(point) => der::SubjectKey::P256(point),
        };
        // Issuer and subject are the same name: that is what self-signed
        // means, and a verifier reads the pair to decide it is a root.
        if w.ca_certificate(
            &1u64.to_be_bytes(),
            &s.issuer_cn[..cn_len],
            subject_key,
            algorithm(s.key_alg),
            now,
            now + CA_TTL_SECS,
        )
        .is_err()
        {
            respond(
                s,
                sys,
                conn,
                stream,
                500,
                b"application/json",
                br#"{"error":"server_error"}"#,
            );
            return;
        }
        w.len()
    };

    let mut certificate = [0u8; MAX_DER];
    let Some(cert_len) = seal(s, &tbs[..tbs_len], &mut certificate) else {
        respond(
            s,
            sys,
            conn,
            stream,
            500,
            b"application/json",
            br#"{"error":"server_error"}"#,
        );
        return;
    };

    // PEM, because a trust root is pasted into configuration by people.
    let mut pem = [0u8; MAX_DER * 3];
    let Some(pem_len) = write_pem(&certificate[..cert_len], &mut pem) else {
        respond(
            s,
            sys,
            conn,
            stream,
            500,
            b"application/json",
            br#"{"error":"server_error"}"#,
        );
        return;
    };
    respond(
        s,
        sys,
        conn,
        stream,
        200,
        b"application/x-pem-file",
        &pem[..pem_len],
    );
}

/// The CA's public half, derived from the private key it holds.
enum CaPublicKey {
    Ed25519([u8; 32]),
    P256([u8; 65]),
}

fn ca_public_key(s: &ModuleState) -> CaPublicKey {
    if s.key_alg == auth_wire::MINT_ALG_ES256 {
        // `ecdh_keygen` multiplies the base point by the scalar it is given,
        // which is how a signing key's public half is derived too.
        CaPublicKey::P256(ecdh_keygen(&s.seed).1)
    } else {
        CaPublicKey::Ed25519(ed25519_public_key(&s.seed))
    }
}

/// Standard base64 in 64-column lines, between the PEM markers.
fn write_pem(der_bytes: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut encoded = [0u8; MAX_DER * 2];
    let encoded_len = b64::encode_standard(der_bytes, &mut encoded)?;
    let mut at = 0usize;
    put(out, &mut at, b"-----BEGIN CERTIFICATE-----\n")?;
    let mut offset = 0usize;
    while offset < encoded_len {
        let end = (offset + 64).min(encoded_len);
        put(out, &mut at, encoded.get(offset..end)?)?;
        put(out, &mut at, b"\n")?;
        offset = end;
    }
    put(out, &mut at, b"-----END CERTIFICATE-----\n")?;
    Some(at)
}

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

fn put(out: &mut [u8], at: &mut usize, bytes: &[u8]) -> Option<()> {
    let end = at.checked_add(bytes.len())?;
    out.get_mut(*at..end)?.copy_from_slice(bytes);
    *at = end;
    Some(())
}

/// # Safety
///
/// As `drain_key`.
unsafe fn respond(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn: u16,
    stream: u16,
    status: u16,
    content_type: &[u8],
    body: &[u8],
) {
    let total = RESP_HDR + content_type.len() + body.len();
    if total > s.out.len() {
        return;
    }
    s.out[0..2].copy_from_slice(&conn.to_le_bytes());
    s.out[2..4].copy_from_slice(&stream.to_le_bytes());
    s.out[4..6].copy_from_slice(&status.to_le_bytes());
    s.out[6] = 0;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "content types here are short literals"
    )]
    {
        s.out[7] = content_type.len() as u8;
    }
    s.out[8..10].copy_from_slice(&0u16.to_le_bytes());
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by the `total > s.out.len()` check above"
    )]
    {
        s.out[10..12].copy_from_slice(&(body.len() as u16).to_le_bytes());
    }
    s.out[RESP_HDR..RESP_HDR + content_type.len()].copy_from_slice(content_type);
    s.out[RESP_HDR + content_type.len()..total].copy_from_slice(body);

    (sys.channel_write)(s.out_responses, s.out.as_ptr(), total);
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    0
}

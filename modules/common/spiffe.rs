//! Canonical SPIFFE identity naming for the nanocloud trust domain.
//!
//! Every identity kagi issues is `spiffe://<trust-domain>/<class>/<path>` with
//! a reserved first-segment **class** so the identity kinds never collide and
//! relying parties can write prefix-scoped authorization policy. See
//! `docs/identity-provisioning.md` §2 for the frozen contract.
//!
//! - `device/<tenant>/<device>` — email-bound device enrollment
//! - `ns/<namespace>/sa/<name>` — Kubernetes / workload service accounts
//!   (the SPIFFE-on-Kubernetes convention)
//! - `svc/<service>/<id>` — platform nodes / services
//!
//! Pure `no_std` fragment: the names are built into a caller's buffer, because
//! a device composing its own identity has no allocator to build a string
//! with. A name that does not fit is refused rather than truncated — a
//! truncated SPIFFE id is a different, probably valid-looking identity, and
//! handing one out is worse than handing out nothing.
//!
//! The SVID (the key-pinning proof relying parties actually compare) is
//! `SHA-256(raw subjectPublicKey)` and is not a naming question: it lives with
//! the certificate types on the host, where the certificate does.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

/// Reserved class segment for email-bound device identities.
pub const CLASS_DEVICE: &[u8] = b"device";
/// Reserved class segment for Kubernetes / workload service accounts.
pub const CLASS_NAMESPACE: &[u8] = b"ns";
/// Reserved class segment for platform nodes / services.
pub const CLASS_SERVICE: &[u8] = b"svc";

/// The reserved class words. A service/tenant/etc. path segment may not equal
/// one of these at the class position.
pub const RESERVED_CLASSES: [&[u8]; 3] = [CLASS_DEVICE, CLASS_NAMESPACE, CLASS_SERVICE];

/// The scheme every name begins with.
const SCHEME: &[u8] = b"spiffe://";

/// The longest name this fragment builds.
///
/// A trust domain is a hostname, the tenant and device ids are 22 characters
/// each, and a namespace or service name is bounded by what a cluster will
/// accept. 512 is comfortably above every one of those together and still
/// small enough to sit on a module's stack.
pub const MAX_NAME: usize = 512;

/// `spiffe://<trust_domain>/device/<tenant>/<device>` — an email-bound device
/// identity. `tenant` is the HKDF tenant id, `device` the key-thumbprint id.
///
/// Returns how many bytes were written, or `None` if the name does not fit.
pub fn write_device(
    out: &mut [u8],
    trust_domain: &[u8],
    tenant: &[u8],
    device: &[u8],
) -> Option<usize> {
    join(out, trust_domain, &[CLASS_DEVICE, tenant, device])
}

/// `spiffe://<trust_domain>/ns/<namespace>/sa/<name>` — a Kubernetes service
/// account identity (the SPIFFE-on-Kubernetes registration path).
pub fn write_service_account(
    out: &mut [u8],
    trust_domain: &[u8],
    namespace: &[u8],
    name: &[u8],
) -> Option<usize> {
    join(
        out,
        trust_domain,
        &[CLASS_NAMESPACE, namespace, b"sa", name],
    )
}

/// `spiffe://<trust_domain>/svc/<service>/<id>` — a platform node / service
/// identity (e.g. `svc/sector/node-abc`).
pub fn write_service(
    out: &mut [u8],
    trust_domain: &[u8],
    service: &[u8],
    id: &[u8],
) -> Option<usize> {
    join(out, trust_domain, &[CLASS_SERVICE, service, id])
}

/// Whether `id` is a syntactically well-formed SPIFFE id in `trust_domain`
/// using one of the reserved classes. A cheap structural check — not a policy
/// decision.
pub fn belongs_to(id: &[u8], trust_domain: &[u8]) -> bool {
    let Some(rest) = strip_prefix(id, SCHEME) else {
        return false;
    };
    let Some(rest) = strip_prefix(rest, trust_domain) else {
        return false;
    };
    let Some(rest) = strip_prefix(rest, b"/") else {
        return false;
    };
    let class = match rest.iter().position(|&byte| byte == b'/') {
        Some(at) => &rest[..at],
        None => rest,
    };
    RESERVED_CLASSES.contains(&class)
}

/// Write `spiffe://<trust_domain>` and then each segment behind a `/`.
fn join(out: &mut [u8], trust_domain: &[u8], segments: &[&[u8]]) -> Option<usize> {
    let mut at = 0usize;
    put(out, &mut at, SCHEME)?;
    put(out, &mut at, trust_domain)?;
    for segment in segments {
        put(out, &mut at, b"/")?;
        put(out, &mut at, segment)?;
    }
    Some(at)
}

/// Append `bytes`, refusing rather than writing a prefix of them.
fn put(out: &mut [u8], at: &mut usize, bytes: &[u8]) -> Option<()> {
    let end = at.checked_add(bytes.len())?;
    out.get_mut(*at..end)?.copy_from_slice(bytes);
    *at = end;
    Some(())
}

fn strip_prefix<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if bytes.len() < prefix.len() || &bytes[..prefix.len()] != prefix {
        return None;
    }
    Some(&bytes[prefix.len()..])
}

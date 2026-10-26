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
//! - `host/<host_id>` — a physical or virtual host of the control plane: the
//!   id is a 16-byte identity the deployment assigns once, rendered as 32
//!   lowercase hex digits, and it survives every boot incarnation of the
//!   host (a boot nonce is not an identity)
//! - `operator/<operator_id>` — a human or automation operator of the control
//!   plane, a 16-byte id rendered the same way
//!
//! Host and operator classes exist because the control plane's
//! ownership-changing acts (`control_act.rs`) name their actor by class and
//! a fixed 16-byte id, and a name whose id is a hash of free text could not
//! be compared to a fixed id without the text. [`parse`] reads any class
//! back to `(class, id)`; for the three older classes the id is the SHA-256
//! of the whole name, truncated, so every class has one 16-byte id.
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
/// Reserved class segment for control-plane hosts.
pub const CLASS_HOST: &[u8] = b"host";
/// Reserved class segment for control-plane operators.
pub const CLASS_OPERATOR: &[u8] = b"operator";

/// The reserved class words. A service/tenant/etc. path segment may not equal
/// one of these at the class position.
pub const RESERVED_CLASSES: [&[u8]; 5] = [
    CLASS_DEVICE,
    CLASS_NAMESPACE,
    CLASS_SERVICE,
    CLASS_HOST,
    CLASS_OPERATOR,
];

/// A fixed identity id: 16 bytes, rendered as 32 lowercase hex digits in a
/// host or operator name.
pub const ID_LEN: usize = 16;
/// The hex rendering of an [`ID_LEN`] id.
pub const ID_HEX_LEN: usize = 2 * ID_LEN;

/// The class of a parsed identity. The numbers are the ones a control act
/// carries in its actor-class byte, so they are stable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Class {
    Device = 1,
    Workload = 2,
    Service = 3,
    Host = 4,
    Operator = 5,
}

impl Class {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The class a code names, if any.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Device),
            2 => Some(Self::Workload),
            3 => Some(Self::Service),
            4 => Some(Self::Host),
            5 => Some(Self::Operator),
            _ => None,
        }
    }

    /// The class word a name begins with.
    #[must_use]
    pub const fn word(self) -> &'static [u8] {
        match self {
            Self::Device => CLASS_DEVICE,
            Self::Workload => CLASS_NAMESPACE,
            Self::Service => CLASS_SERVICE,
            Self::Host => CLASS_HOST,
            Self::Operator => CLASS_OPERATOR,
        }
    }

    /// Whether the class carries a fixed id in its path rather than a name
    /// the id is derived from.
    #[must_use]
    pub const fn fixed_id(self) -> bool {
        matches!(self, Self::Host | Self::Operator)
    }
}

/// A parsed identity: its class and its 16-byte id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Identity {
    pub class: Class,
    pub id: [u8; ID_LEN],
}

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

/// `spiffe://<trust_domain>/host/<host_id hex>` — a control-plane host.
///
/// `host_id` is the deployment's boot-incarnation-independent identity for
/// the host, rendered as 32 lowercase hex digits.
pub fn write_host(out: &mut [u8], trust_domain: &[u8], host_id: &[u8; ID_LEN]) -> Option<usize> {
    let mut hex = [0u8; ID_HEX_LEN];
    hex_into(host_id, &mut hex);
    join(out, trust_domain, &[CLASS_HOST, &hex])
}

/// `spiffe://<trust_domain>/operator/<operator_id hex>` — a control-plane
/// operator.
pub fn write_operator(
    out: &mut [u8],
    trust_domain: &[u8],
    operator_id: &[u8; ID_LEN],
) -> Option<usize> {
    let mut hex = [0u8; ID_HEX_LEN];
    hex_into(operator_id, &mut hex);
    join(out, trust_domain, &[CLASS_OPERATOR, &hex])
}

/// The class word and the path after it, when `id` is a name in
/// `trust_domain`. Structural only.
fn split<'a>(id: &'a [u8], trust_domain: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    let rest = strip_prefix(id, SCHEME)?;
    let rest = strip_prefix(rest, trust_domain)?;
    let rest = strip_prefix(rest, b"/")?;
    Some(match rest.iter().position(|&byte| byte == b'/') {
        Some(at) => (&rest[..at], &rest[at + 1..]),
        None => (rest, &[]),
    })
}

/// Whether `id` is a syntactically well-formed SPIFFE id in `trust_domain`
/// using one of the reserved classes. A cheap structural check — not a policy
/// decision.
///
/// A host or operator name must also carry a well-formed id: 32 lowercase
/// hex digits and nothing after them. A name of those classes whose path is
/// anything else names no fixed id and is not well formed.
pub fn belongs_to(id: &[u8], trust_domain: &[u8]) -> bool {
    let Some((class, path)) = split(id, trust_domain) else {
        return false;
    };
    if class == CLASS_HOST || class == CLASS_OPERATOR {
        return fixed_id(path).is_some();
    }
    RESERVED_CLASSES.contains(&class)
}

/// Parse a well-formed name in `trust_domain` to its class and 16-byte id.
///
/// A host or operator id is the hex in the path. A device, workload or
/// service id is the first 16 bytes of `SHA-256(name)` — injected, because a
/// module wires the SDK's digest and a host suite wires its own — so every
/// class has one id of one length. `None` when the name is not well formed
/// (the same rule as [`belongs_to`]).
pub fn parse(sha: fn(&[u8], &mut [u8; 32]), id: &[u8], trust_domain: &[u8]) -> Option<Identity> {
    let (class, path) = split(id, trust_domain)?;
    if class == CLASS_HOST || class == CLASS_OPERATOR {
        let fixed = fixed_id(path)?;
        return Some(Identity {
            class: if class == CLASS_HOST {
                Class::Host
            } else {
                Class::Operator
            },
            id: fixed,
        });
    }
    let class = if class == CLASS_DEVICE {
        Class::Device
    } else if class == CLASS_NAMESPACE {
        Class::Workload
    } else if class == CLASS_SERVICE {
        Class::Service
    } else {
        return None;
    };
    let mut digest = [0u8; 32];
    sha(id, &mut digest);
    let mut out = [0u8; ID_LEN];
    out.copy_from_slice(&digest[..ID_LEN]);
    Some(Identity { class, id: out })
}

/// The id a host or operator path carries: exactly 32 lowercase hex digits.
fn fixed_id(path: &[u8]) -> Option<[u8; ID_LEN]> {
    if path.len() != ID_HEX_LEN {
        return None;
    }
    let mut out = [0u8; ID_LEN];
    for (slot, pair) in out.iter_mut().zip(path.chunks_exact(2)) {
        *slot = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(out)
}

/// Lowercase only: an id has one spelling, so one name.
const fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn hex_into(id: &[u8; ID_LEN], out: &mut [u8; ID_HEX_LEN]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in id.iter().enumerate() {
        out[2 * i] = DIGITS[usize::from(b >> 4)];
        out[2 * i + 1] = DIGITS[usize::from(b & 0x0F)];
    }
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

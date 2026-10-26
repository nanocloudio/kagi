//! Values derived from a stored secret for one context
//! (`secret_store`'s `MSG_SECRET_DERIVE`).
//!
//! A secret item that several hosts must hold alike — Wormhole's route seed
//! secret, which every director's flow hash for a route is keyed by — is
//! provisioned into each host's store once (`MSG_SECRET_PUT`, the same
//! value everywhere) and never read back whole: a consumer asks for the
//! value it needs for one context and gets
//! `HMAC-SHA256(secret, DOMAIN ‖ context)`. The same secret and context
//! give the same value on every host; a consumer that learns one value
//! learns nothing of the secret or of any other context's value.
//!
//! Pure `no_std`; the HMAC is injected so the host tests and the module run
//! the same derivation.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

/// The derivation's domain, ahead of every context.
pub const DOMAIN: &[u8] = b"kagi/secret-derive.v1";
/// The longest context a derivation takes.
pub const CONTEXT_MAX: usize = 256;
/// Bytes a derived value has.
pub const DERIVED_LEN: usize = 32;

/// `HMAC-SHA256(key, message) -> [u8; 32]`.
pub type HmacFn = fn(&[u8], &[u8]) -> [u8; DERIVED_LEN];

/// The value `secret` gives for `context`, or `None` for an empty secret
/// or a context past [`CONTEXT_MAX`].
#[must_use]
pub fn derive(hmac: HmacFn, secret: &[u8], context: &[u8]) -> Option<[u8; DERIVED_LEN]> {
    if secret.is_empty() || context.len() > CONTEXT_MAX {
        return None;
    }
    let mut msg = [0u8; DOMAIN.len() + CONTEXT_MAX];
    msg[..DOMAIN.len()].copy_from_slice(DOMAIN);
    msg[DOMAIN.len()..DOMAIN.len() + context.len()].copy_from_slice(context);
    Some(hmac(secret, &msg[..DOMAIN.len() + context.len()]))
}

/// The secret item Wormhole's route builders share: provisioned under this
/// id on every host that builds a route's table.
pub const ROUTE_SEED_ID: &[u8] = b"wormhole/route-seed";

/// The context a route's seed secret is derived for:
/// `"wh-route-seed.v1" ‖ service_id ‖ hash_seed_ref` — the route's service
/// and the seed reference its record names, so two routes never share a
/// seed and a reference rotated in the catalogue rotates the seed.
#[must_use]
pub fn route_seed_context(service_id: &[u8; 16], hash_seed_ref: &[u8; 16]) -> [u8; 48] {
    let mut c = [0u8; 48];
    c[..16].copy_from_slice(b"wh-route-seed.v1");
    c[16..32].copy_from_slice(service_id);
    c[32..48].copy_from_slice(hash_seed_ref);
    c
}

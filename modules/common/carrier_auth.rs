//! Who asked: a control-plane caller authenticated from its cert-bound
//! identity carrier, bound to the link's verified SVID, and replay-checked.
//!
//! The typed operations that act for a host or operator — transfer grants,
//! attachment authorisation — take no actor field. The caller signs a
//! short-lived carrier (`cert_bound_identity.rs`) with the leaf key its
//! SPIFFE certificate names; the leaf chains to the authority's key (a
//! chain of one, `x509_leaf.rs`); the leaf's SPIFFE name in this trust
//! domain gives the class and 16-byte id (`spiffe::parse`); and when the
//! exchange arrived over mTLS its verified SVID must be the carrier's key.
//! A carrier presented twice inside its life is refused.
//!
//! [`identity_leaf_key`] answers the related question for a party that is
//! named rather than present — a transfer's destination host: its leaf
//! chains to the authority, is inside its window, and names that identity.
//!
//! The including module provides `cert_bound_identity`, `spiffe` and
//! `x509_leaf` at its root.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

use crate::cert_bound_identity as cbi;
use crate::spiffe;
use crate::x509_leaf;

/// An SVID's length.
pub const SVID_LEN: usize = 32;
const REPLAY_ID_MAX: usize = cbi::CARRIER_JTI_MAX;

/// Why a caller is not authenticated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthError {
    /// No authority key to chain a leaf to.
    NoAnchor,
    /// The carrier did not verify.
    Carrier,
    /// The carrier's key is not the link's verified SVID.
    PeerMismatch,
    /// The leaf's name is not a well-formed identity in this trust domain.
    Name,
    /// Presented before, inside its life.
    Replayed,
}

/// An authenticated caller.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Caller {
    pub class: u8,
    pub id: [u8; 16],
    pub svid: [u8; SVID_LEN],
}

#[derive(Clone, Copy)]
struct Seen {
    id: [u8; REPLAY_ID_MAX],
    len: u8,
    expires_at: u64,
}

const EMPTY: Seen = Seen {
    id: [0; REPLAY_ID_MAX],
    len: 0,
    expires_at: 0,
};

/// The verifier and its replay window, `N` carriers wide.
pub struct Authenticator<const N: usize> {
    seen: [Seen; N],
}

/// What a deployment authenticates callers against.
#[derive(Clone, Copy)]
pub struct Trust<'a> {
    /// The authority's key, as `x509_leaf::anchor` reads it.
    pub anchor: &'a [u8],
    /// The audience a carrier must name.
    pub audience: &'a [u8],
    /// The one trust domain callers belong to.
    pub trust_domain: &'a [u8],
}

impl<const N: usize> Authenticator<N> {
    #[must_use]
    pub const fn new() -> Self {
        Self { seen: [EMPTY; N] }
    }

    /// Authenticate `carrier`, at `now_secs`, over a link whose verified
    /// SVID is `peer` (`None` when nothing authenticated the link).
    pub fn authenticate(
        &mut self,
        v: &cbi::CarrierVerifiers,
        trust: &Trust<'_>,
        carrier: &[u8],
        peer: Option<&[u8; SVID_LEN]>,
        now_secs: u64,
    ) -> Result<Caller, AuthError> {
        if trust.anchor.is_empty() {
            return Err(AuthError::NoAnchor);
        }
        let policy = cbi::CarrierPolicy {
            anchor_der: trust.anchor,
            audience: trust.audience,
            now_unix_secs: now_secs,
            require_clock: true,
        };
        let identity = cbi::verify(v, carrier, &policy).map_err(|_| AuthError::Carrier)?;
        if peer.is_some_and(|svid| *svid != identity.svid) {
            return Err(AuthError::PeerMismatch);
        }
        let who = spiffe::parse(v.sha256, identity.spiffe(), trust.trust_domain)
            .ok_or(AuthError::Name)?;
        if self.replayed(identity.replay_id(), identity.expires_at, now_secs) {
            return Err(AuthError::Replayed);
        }
        Ok(Caller {
            class: who.class.code(),
            id: who.id,
            svid: identity.svid,
        })
    }

    /// Whether `id` was seen inside its window; records it if not. A full
    /// window evicts the entry closest to expiry.
    fn replayed(&mut self, id: &[u8], expires_at: u64, now_secs: u64) -> bool {
        if id.is_empty() || id.len() > REPLAY_ID_MAX {
            return true;
        }
        for slot in &mut self.seen {
            if slot.len != 0 && slot.expires_at <= now_secs {
                *slot = EMPTY;
            }
        }
        if self
            .seen
            .iter()
            .any(|slot| slot.len != 0 && slot.id.get(..usize::from(slot.len)) == Some(id))
        {
            return true;
        }
        if let Some(slot) =
            self.seen
                .iter_mut()
                .min_by_key(|slot| if slot.len == 0 { 0 } else { slot.expires_at })
        {
            *slot = EMPTY;
            for (d, s) in slot.id.iter_mut().zip(id) {
                *d = *s;
            }
            slot.len = u8::try_from(id.len()).unwrap_or(0);
            slot.expires_at = expires_at;
        }
        false
    }
}

impl<const N: usize> Default for Authenticator<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// The `(suite, public)` of `leaf` when it chains to `trust.anchor`, is
/// valid at `now_secs`, and its SPIFFE name in `trust.trust_domain` is
/// `(class, id)`. The key is copied into `out`; the answer is its suite and
/// length.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one independently established fact"
)]
pub fn identity_leaf_key(
    verify: x509_leaf::VerifyFn,
    sha: fn(&[u8], &mut [u8; 32]),
    trust: &Trust<'_>,
    leaf: &[u8],
    class: u8,
    id: &[u8; 16],
    now_secs: u64,
    out: &mut [u8; 65],
) -> Option<(u16, usize)> {
    let parsed = x509_leaf::parse(leaf)?;
    let (anchor_suite, anchor_public) = x509_leaf::anchor(trust.anchor)?;
    if !x509_leaf::signed_by(&parsed, verify, anchor_suite, anchor_public) {
        return None;
    }
    if now_secs < parsed.not_before || now_secs >= parsed.not_after {
        return None;
    }
    let who = spiffe::parse(sha, parsed.san_uri, trust.trust_domain)?;
    if who.class.code() != class || who.id != *id {
        return None;
    }
    let n = parsed.public.len();
    if n > out.len() {
        return None;
    }
    for (d, s) in out.iter_mut().zip(parsed.public) {
        *d = *s;
    }
    Some((parsed.suite, n))
}

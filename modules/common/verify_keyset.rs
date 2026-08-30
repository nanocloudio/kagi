//! A verification keyset: the consumer half of the key lifecycle.
//!
//! Five modules verify kagi-issued credentials without being the token
//! verifier — `resource_gate`, `wellknown_endpoint`, `keypackage_endpoint`,
//! `e2ee_state_endpoint` and `token_endpoint`. All five hold the whole
//! keyset here rather than a single key, and index it by `kid`.
//!
//! Both properties are load-bearing. A module holding one key and
//! overwriting it on delivery makes rotation destructive: the instant a
//! replacement arrives, every credential signed under the outgoing key
//! stops verifying. And a module that discards the `kid` has nothing to
//! index by, so a credential naming a key it has never held is checked
//! against whichever key is loaded instead of being refused — a `kid`
//! nothing indexes by is decorative, and a decorative `kid` is worse than
//! none, because it reads like a binding.
//!
//! Five copies of the same twenty lines would also be five places for the
//! ordering to drift, which is why this is a fragment rather than a
//! pattern.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface"
)]

// `auth_wire` comes from the host module rather than being mounted here:
// a PIC module `#[path]`-mounts each fragment once, and a fragment that
// mounted its own copy would load the same file twice in the same crate.
use super::auth_wire;

/// Longest public key a slot holds, from the registry: the widest key
/// this build can verify under.
pub const MAX_PUBKEY_LEN: usize = auth_wire::suite::MAX_IMPLEMENTED_PUBLIC_KEY_LEN;
pub const MAX_KID_LEN: usize = 64;
pub const MAX_ISSUER_LEN: usize = 64;
/// Keys held at once. Matches the mint's keyset: a verifier holding fewer
/// keys than the issuer can sign under refuses live credentials and calls
/// it an unknown kid.
pub const MAX_KEYS: usize = 8;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Key {
    pub live: bool,
    pub issuer: [u8; MAX_ISSUER_LEN],
    pub issuer_len: u8,
    pub profile_id: u16,
    pub kid: [u8; MAX_KID_LEN],
    pub kid_len: u8,
    pub suite: u16,
    pub state: u8,
    pub generation: u32,
    pub remove_after_unix: u64,
    pub pubkey: [u8; MAX_PUBKEY_LEN],
    /// A `u16`: an ML-DSA-87 key is 2592 bytes, and a `u8` would keep
    /// only its low byte of length, which reads as a short key rather
    /// than as an error.
    pub pubkey_len: u16,
}

impl Key {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            live: false,
            issuer: [0; MAX_ISSUER_LEN],
            issuer_len: 0,
            profile_id: 0,
            kid: [0; MAX_KID_LEN],
            kid_len: 0,
            suite: 0,
            state: auth_wire::key_state::ADDED,
            generation: 0,
            remove_after_unix: 0,
            pubkey: [0; MAX_PUBKEY_LEN],
            pubkey_len: 0,
        }
    }

    #[must_use]
    pub fn kid_bytes(&self) -> &[u8] {
        &self.kid[..usize::from(self.kid_len)]
    }

    #[must_use]
    pub fn pubkey_bytes(&self) -> &[u8] {
        &self.pubkey[..usize::from(self.pubkey_len)]
    }
}

/// The keyset itself.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Keyset {
    pub keys: [Key; MAX_KEYS],
}

impl Keyset {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            keys: [Key::empty(); MAX_KEYS],
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.keys.iter().any(|k| k.live)
    }

    fn find(&self, issuer: &[u8], profile_id: u16, kid: &[u8]) -> Option<usize> {
        self.keys.iter().position(|k| {
            k.live
                && k.profile_id == profile_id
                && &k.issuer[..usize::from(k.issuer_len)] == issuer
                && k.kid_bytes() == kid
        })
    }

    /// The key a credential names, by the `kid` in its JOSE header.
    ///
    /// An unknown `kid` is `None` and the credential is refused. It is NOT
    /// checked against some other key: falling back to "whatever is
    /// loaded" is what makes the `kid` decorative, and it lets a
    /// credential signed by a key this module never trusted be accepted
    /// whenever the header is ignored.
    ///
    /// A key past its removal deadline is not selectable even while it is
    /// still in the table, so an operator who set a deadline gets it.
    #[must_use]
    pub fn select(&self, kid: &[u8], now_unix_secs: u64) -> Option<&Key> {
        self.keys.iter().find(|k| {
            k.live
                && !(k.remove_after_unix != 0 && now_unix_secs >= k.remove_after_unix)
                && k.kid_bytes() == kid
        })
    }

    /// The active key for a profile, for callers that must pick one
    /// without a credential to read a `kid` from.
    #[must_use]
    pub fn active(&self, profile_id: u16) -> Option<&Key> {
        self.keys.iter().find(|k| {
            k.live && k.profile_id == profile_id && k.state == auth_wire::key_state::ACTIVE
        })
    }

    /// Apply one lifecycle message. Returns true if it changed the keyset.
    ///
    /// A message this keyset does not recognise is ignored rather than
    /// treated as an error: these channels carry the whole lifecycle and a
    /// consumer subscribing to it need not care about every verb.
    pub fn apply(&mut self, msg_type: u8, payload: &[u8]) -> bool {
        match msg_type {
            auth_wire::MSG_KEY_ADD => {
                let Ok(rec) = auth_wire::KeyRecord::decode_add(payload) else {
                    return false;
                };
                // Re-adding the same (issuer, profile, kid) replaces it in
                // place, so a redelivered record is idempotent rather than
                // consuming a second slot.
                let Some(i) = self
                    .find(rec.issuer, rec.profile_id, rec.kid)
                    .or_else(|| self.keys.iter().position(|k| !k.live))
                else {
                    // A full keyset refuses rather than evicting: whichever
                    // key it evicted would be one some live credential
                    // still needs.
                    return false;
                };
                let mut slot = Key::empty();
                if !fill(&mut slot, &rec) {
                    return false;
                }
                self.keys[i] = slot;
                true
            }
            auth_wire::MSG_KEYSET_SNAPSHOT => {
                let mut r = auth_wire::PayloadReader::new(payload);
                let Ok(count) = r.u16() else { return false };
                if usize::from(count) > MAX_KEYS {
                    return false;
                }
                let mut fresh = [Key::empty(); MAX_KEYS];
                for slot in fresh.iter_mut().take(usize::from(count)) {
                    match auth_wire::KeyRecord::read(&mut r) {
                        Ok(rec) if fill(slot, &rec) => {}
                        // All or nothing: a half-applied snapshot leaves a
                        // set neither end believes in, and the keys it
                        // dropped are the ones live credentials need.
                        _ => return false,
                    }
                }
                self.keys = fresh;
                true
            }
            auth_wire::MSG_KEY_ACTIVATE => match auth_wire::KeyRef::decode(payload) {
                Ok(kr) => match self.find(kr.issuer, kr.profile_id, kr.kid) {
                    Some(i) => {
                        self.keys[i].state = auth_wire::key_state::ACTIVE;
                        true
                    }
                    None => false,
                },
                Err(_) => false,
            },
            auth_wire::MSG_KEY_RETIRE => match auth_wire::KeyRef::decode(payload) {
                Ok(kr) => match self.find(kr.issuer, kr.profile_id, kr.kid) {
                    Some(i) => {
                        // A retired key keeps VERIFYING — that is the whole
                        // point of the state. It stops signing new
                        // credentials while the ones it already signed age
                        // out.
                        self.keys[i].state = auth_wire::key_state::RETIRED;
                        self.keys[i].remove_after_unix = kr.arg;
                        true
                    }
                    None => false,
                },
                Err(_) => false,
            },
            auth_wire::MSG_KEY_REMOVE => match auth_wire::KeyRef::decode(payload) {
                Ok(kr) => match self.find(kr.issuer, kr.profile_id, kr.kid) {
                    Some(i) => {
                        self.keys[i] = Key::empty();
                        true
                    }
                    None => false,
                },
                Err(_) => false,
            },
            _ => false,
        }
    }
}

impl Default for Keyset {
    fn default() -> Self {
        Self::new()
    }
}

/// Copy a decoded record into a slot. False if it does not fit, or names
/// something this build cannot verify.
fn fill(slot: &mut Key, rec: &auth_wire::KeyRecord<'_>) -> bool {
    if rec.key_use != auth_wire::key_use::VERIFY {
        return false;
    }
    // A suite this build cannot verify is refused at load, not at the first
    // credential: a key that is present but unusable looks like a
    // configured issuer right up until someone presents a credential.
    if !auth_wire::suite::is_implemented(rec.suite) {
        return false;
    }
    let ok_len = auth_wire::suite::public_key_len_ok(rec.suite, rec.key_ref.len());
    if !ok_len
        || rec.key_ref.len() > MAX_PUBKEY_LEN
        || rec.issuer.is_empty()
        || rec.issuer.len() > MAX_ISSUER_LEN
        || rec.kid.is_empty()
        || rec.kid.len() > MAX_KID_LEN
    {
        return false;
    }
    *slot = Key::empty();
    slot.live = true;
    slot.issuer[..rec.issuer.len()].copy_from_slice(rec.issuer);
    slot.kid[..rec.kid.len()].copy_from_slice(rec.kid);
    slot.pubkey[..rec.key_ref.len()].copy_from_slice(rec.key_ref);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "all three lengths bounded immediately above"
    )]
    {
        slot.issuer_len = rec.issuer.len() as u8;
        slot.kid_len = rec.kid.len() as u8;
        slot.pubkey_len = rec.key_ref.len() as u16;
    }
    slot.profile_id = rec.profile_id;
    slot.suite = rec.suite;
    slot.state = rec.state;
    slot.generation = rec.generation;
    slot.remove_after_unix = rec.remove_after_unix;
    true
}

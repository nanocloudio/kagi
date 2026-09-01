// The kagi conformance corpus — vectors as DATA.
//
// LIVES HERE — in `modules/common/` — because this is the tree
// `fluxor publish` ships as `kagi-common`, and a corpus is only published
// with `kagi-common` if it is inside the one directory that source
// artifact is built from. A corpus anywhere else is reachable by kagi's
// own suite and by nobody else, which makes "the vectors ship" an
// aspiration rather than a fact. `tests/conformance/vectors.rs` is an
// include shim onto this file, so kagi mounts the corpus exactly as a
// consumer does.
//
// Mounted by `tests/harness/tests/conformance.rs` here and by the
// equivalent suite in each consumer repo (tools/conformance/README.md
// is the runner recipe), so a downstream that drifts fails its own CI
// rather than being caught later by someone reading two implementations
// side by side.
//
// `//` rather than `//!`, and no inner attributes: consumers `include!` this
// flat, where inner attributes are illegal.

/// What a vector expects to happen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Accepted, and the identity it establishes is usable.
    Accept,
    /// Refused. The corpus does not pin WHICH refusal code: those are
    /// per-surface, and a vector that pinned one would fail a consumer that
    /// was right for a reason it spelled differently. What it pins is that
    /// the answer is not acceptance.
    Refuse,
}

/// One vector.
pub struct Vector {
    /// Stable id, for a consumer to skip or report by.
    pub id: &'static str,
    /// Which of the five `C16` classes.
    pub class: Class,
    pub verdict: Verdict,
    /// Why. Not decoration — a vector whose reason nobody can state is a
    /// vector nobody can tell is still testing the right thing.
    pub reason: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    Negative,
    Concurrency,
    Restart,
    Rotation,
    Capacity,
}

/// The corpus.
///
/// Every entry corresponds to an executable check in the consuming suite.
/// The table is the agreement; the suite is the execution. Keeping them
/// apart is what lets a consumer report "I do not implement this class"
/// visibly, instead of silently implementing the check differently.
pub const VECTORS: &[Vector] = &[
    // ── negative ────────────────────────────────────────────────────────
    Vector {
        id: "neg.carrier.no_jti",
        class: Class::Negative,
        verdict: Verdict::Refuse,
        reason: "a carrier with no jti leaves the replay cache keyed on an \
                 empty value, so either every such carrier collides or none does",
    },
    Vector {
        id: "neg.carrier.no_iat",
        class: Class::Negative,
        verdict: Verdict::Refuse,
        reason: "without iat nothing bounds how old a carrier is, or how far \
                 ahead it was stamped",
    },
    Vector {
        id: "neg.carrier.long_lifetime",
        class: Class::Negative,
        verdict: Verdict::Refuse,
        reason: "the short lifetime IS the compensating control for a key a \
                 browser cannot protect; without it the carrier is a bearer \
                 credential with extra steps",
    },
    Vector {
        id: "neg.carrier.future_iat",
        class: Class::Negative,
        verdict: Verdict::Refuse,
        reason: "a carrier stamped ahead verifies now and keeps verifying",
    },
    Vector {
        id: "neg.chain.expired_anchor",
        class: Class::Negative,
        verdict: Verdict::Refuse,
        reason: "a bare signature check cannot see an expired CA; a path \
                 validation must",
    },
    Vector {
        id: "neg.chain.wrong_eku",
        class: Class::Negative,
        verdict: Verdict::Refuse,
        reason: "a leaf issued for TLS serving is not a client identity",
    },
    Vector {
        id: "neg.suite.unimplemented",
        class: Class::Negative,
        verdict: Verdict::Refuse,
        reason: "a suite this build cannot verify is refused as unsupported, \
                 not reported as malformed",
    },
    Vector {
        id: "neg.audience.mismatch",
        class: Class::Negative,
        verdict: Verdict::Refuse,
        reason: "a credential minted for one audience and accepted at another \
                 is the confused-deputy shape",
    },
    Vector {
        id: "neg.audience.empty_policy",
        class: Class::Negative,
        verdict: Verdict::Refuse,
        reason: "an empty audience rule is not 'no rule' — it is a rule no \
                 credential can be checked against",
    },
    Vector {
        id: "neg.thumbprint.length_mismatch",
        class: Class::Negative,
        verdict: Verdict::Refuse,
        reason: "a 43-byte value labelled SHA-384 is a truncated digest \
                 wearing the wrong label",
    },
    Vector {
        id: "neg.state.unavailable_is_not_absent",
        class: Class::Negative,
        verdict: Verdict::Refuse,
        reason: "'there is no ledger' must never look like 'the ledger says \
                 no such device' — the second admits a credential",
    },
    Vector {
        id: "neg.identity.refusal_carries_nothing",
        class: Class::Negative,
        verdict: Verdict::Refuse,
        reason: "a refusal carrying a subject lets a consumer that skipped the \
                 status authorize somebody",
    },
    // ── concurrency ─────────────────────────────────────────────────────
    Vector {
        id: "conc.put_if_absent.one_winner",
        class: Class::Concurrency,
        verdict: Verdict::Accept,
        reason: "two creators race; exactly one wins and the loser is told it \
                 lost rather than told the store is broken",
    },
    Vector {
        id: "conc.cas.one_winner",
        class: Class::Concurrency,
        verdict: Verdict::Accept,
        reason: "two consumers race a live→consumed CAS; exactly one credential \
                 issues",
    },
    // ── concurrency, REPLICA scope ──────────────────────────────────────
    // Process-scope single-use is not single-use once the deployment has a
    // second process. These vectors pin the same properties across a
    // replicated store: the state the winner claimed is the state every
    // process sees.
    Vector {
        id: "conc.replica.commit_readable_elsewhere",
        class: Class::Concurrency,
        verdict: Verdict::Accept,
        reason: "a record committed through one process is read back by a \
                 DIFFERENT process — the claim lives in the store, not in \
                 the winner's memory",
    },
    Vector {
        id: "conc.replica.stale_witness_refuses",
        class: Class::Concurrency,
        verdict: Verdict::Refuse,
        reason: "a CAS against a witness superseded by another writer \
                 refuses — you did not win, whichever process you are",
    },
    Vector {
        id: "restart.replica.survives_voter_loss",
        class: Class::Restart,
        verdict: Verdict::Accept,
        reason: "a committed revocation outlives the death of a voter that \
                 held it — losing a node must never un-revoke a device",
    },
    Vector {
        id: "conc.consume.is_terminal",
        class: Class::Concurrency,
        verdict: Verdict::Refuse,
        reason: "a consumed grant is terminal — re-issuing would mean a fresh \
                 iat/exp and effectively unbounded reuse",
    },
    // ── restart ─────────────────────────────────────────────────────────
    Vector {
        id: "restart.record.survives",
        class: Class::Restart,
        verdict: Verdict::Accept,
        reason: "distinguishes durable from cached, which is what A2, A5 and \
                 C2 exist to pass",
    },
    Vector {
        id: "restart.consumed.stays_consumed",
        class: Class::Restart,
        verdict: Verdict::Refuse,
        reason: "single-use across restarts, not once per live module instance",
    },
    // ── rotation ────────────────────────────────────────────────────────
    Vector {
        id: "rot.added_does_not_sign",
        class: Class::Rotation,
        verdict: Verdict::Refuse,
        reason: "the ADDED state is the gap that lets every verifier hold a key \
                 before the first credential is issued under it",
    },
    Vector {
        id: "rot.retired_still_verifies",
        class: Class::Rotation,
        verdict: Verdict::Accept,
        reason: "a keyset that cannot overlap makes every rotation an outage: \
                 the old key's credentials die the instant the new one arrives",
    },
    Vector {
        id: "rot.unknown_kid_fails_closed",
        class: Class::Rotation,
        verdict: Verdict::Refuse,
        reason: "an unknown kid must not fall through to whatever key is loaded \
                 — that is what makes a kid decorative",
    },
    Vector {
        id: "rot.two_keys_live_at_once",
        class: Class::Rotation,
        verdict: Verdict::Accept,
        reason: "each credential verifies under the key its own kid names",
    },
    Vector {
        id: "rot.signer_announces_its_public_half",
        class: Class::Rotation,
        verdict: Verdict::Accept,
        reason: "a signing record names a vault LABEL and carries no key material, \
                 so the operator who distributed it never sees the public half \
                 either — the signer is the only component that can tell a \
                 verifier what to trust, and a rotation nobody is told about is \
                 an outage at the next credential",
    },
    // ── capacity ────────────────────────────────────────────────────────
    Vector {
        id: "cap.replay.overflow_fails_closed",
        class: Class::Capacity,
        verdict: Verdict::Refuse,
        reason: "an eviction under load is an admission under load",
    },
    Vector {
        id: "cap.keyset.full_refuses_add",
        class: Class::Capacity,
        verdict: Verdict::Refuse,
        reason: "whichever key a full keyset evicted would be one some live \
                 credential still needs",
    },
    Vector {
        id: "cap.field.overflow_refuses",
        class: Class::Capacity,
        verdict: Verdict::Refuse,
        reason: "a truncated identifier collides with every other sharing its \
                 prefix, which is a denial of service against the honest holder",
    },
];

/// Vectors in one class.
#[must_use]
pub fn in_class(class: Class) -> impl Iterator<Item = &'static Vector> {
    VECTORS.iter().filter(move |v| v.class == class)
}

/// Look one up by id, so a suite's check and its vector cannot drift apart
/// silently: a renamed vector fails to resolve rather than going unchecked.
#[must_use]
pub fn vector(id: &str) -> Option<&'static Vector> {
    VECTORS.iter().find(|v| v.id == id)
}

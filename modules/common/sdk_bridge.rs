// Adapters between the fluxor SDK's crypto primitives and the verifier
// pointers the shared fragments take.
//
// `include!`d flat rather than mounted with `#[path]`, because this is
// the one file that has to see both sides by bare name: the SDK sources
// are flat-included (`ed25519_verify`, `ml_dsa_verify`, `MlDsaSet`) and
// the fragments are modules (`crate::auth_wire::suite`). A module that
// mounts it MUST also have included `crypto/ed25519.rs`, `crypto/sha3.rs`
// and `crypto/ml_dsa.rs`, in that order.
//
// Two adapters, and each exists for a reason worth stating:
//
// - **Shape.** `device_auth::Ed25519VerifyFn` carries slices because the
//   caller decodes a signature whose length comes from a suite it learns
//   at runtime; the SDK's `ed25519_verify` takes fixed arrays because
//   RFC 8032 signatures are 64 bytes and always will be. The narrowing
//   happens here rather than in the fragment, where it would have to
//   succeed for suites that are not 64 bytes wide.
//
// - **Scratch.** An ML-DSA verification needs about 13 KB of polynomial
//   working space. A position-independent module has no `.bss` — its
//   state arrives as a pointer from the kernel — so that space cannot be
//   a static, and it is a local here, dimensioned per parameter set so an
//   ML-DSA-44 credential does not reserve ML-DSA-87's columns.

/// Verify an Ed25519 signature, narrowing the fragment's slices to the
/// fixed arrays the primitive takes.
fn ed25519_verify_slice(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match (public_key.try_into(), signature.try_into()) {
        (Ok(pk), Ok(sig)) => ed25519_verify(pk, message, sig),
        _ => false,
    }
}

/// The ML-DSA parameter set a kagi CREDENTIAL suite names.
///
/// Written out rather than passed through to the primitive's own
/// `from_suite`, which reads fluxor's KEY-VAULT registry. The two happen
/// to agree on 4, 5 and 6 today and are not the same registry — one names
/// what a JWS is signed with, the other what a vault slot holds — so the
/// crossing between them is one named function with both in view, and not
/// an assumption spread across call sites.
fn ml_dsa_set_for_credential(credential_suite: u16) -> Option<MlDsaSet> {
    match credential_suite {
        auth_wire::suite::ML_DSA_44 => Some(MlDsaSet::MlDsa44),
        auth_wire::suite::ML_DSA_65 => Some(MlDsaSet::MlDsa65),
        auth_wire::suite::ML_DSA_87 => Some(MlDsaSet::MlDsa87),
        _ => None,
    }
}

/// Verify an ML-DSA signature over a JOSE signing input.
///
/// The context string is empty, which RFC 9964 requires of every ML-DSA
/// algorithm used with JOSE: a JWS is already domain-separated by its own
/// protected header, and a context that is part of the signature but not
/// part of the credential is a second place for the two ends to disagree.
fn ml_dsa_verify_suite(
    credential_suite: u16,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let Some(set) = ml_dsa_set_for_credential(credential_suite) else {
        return false;
    };
    let p = set.params();
    if public_key.len() != p.pk_len || signature.len() != p.sig_len {
        return false;
    }
    match set {
        MlDsaSet::MlDsa44 => {
            let mut ws: VerifyWorkspace<4> = VerifyWorkspace::new();
            ml_dsa_verify(set, public_key, &[], message, signature, &mut ws)
        }
        MlDsaSet::MlDsa65 => {
            let mut ws: VerifyWorkspace<5> = VerifyWorkspace::new();
            ml_dsa_verify(set, public_key, &[], message, signature, &mut ws)
        }
        MlDsaSet::MlDsa87 => {
            let mut ws: VerifyWorkspace<7> = VerifyWorkspace::new();
            ml_dsa_verify(set, public_key, &[], message, signature, &mut ws)
        }
    }
}

# Identifier helpers

`modules/common/ids.rs` derives kagi's three deterministic identifiers —
tenant id, device id and workload subject — so no component has to
reimplement the hashing or the normalisation. The rules are the ones in
`docs/specification.md`; this is the fragment that implements them.

All three are 22 base64url characters, and crypto is injected as a
function pointer, so the same code runs in a PIC module and in a host
test.

## Tenant IDs

- Inputs:
  - `secret`: an opaque byte string configured per deployment.
  - `email`: the address collected during registration.
- Processing:
  1. Trim leading/trailing ASCII whitespace and lowercase the email.
  2. HKDF-SHA256 with the email as the salt, the secret as keying
     material, and `"tenant-id"` as the info label.
  3. Base64url-encode and truncate to 22 characters.
- Guarantees:
  - Case- and whitespace-insensitive email handling.
  - Stable output for identical inputs and secrets.
  - Reproducible across processes and deployments sharing the secret.

```rust
let mut tenant = [0u8; ids::TENANT_ID_LENGTH];
ids::tenant_id(hkdf_sha256, secret, b"Alice@example.com", &mut tenant)?;
```

## Device IDs

- Input: the device public key as a JWK.
- Processing:
  1. Canonicalise the JWK — RFC 7638 members, sorted, no whitespace.
  2. SHA-256 the canonical bytes.
  3. Base64url-encode and truncate to 22 characters.
- Guarantees:
  - Independent of the member order in the JWK as received.
  - Distinct device keys produce distinct identifiers with overwhelming
    probability.

```rust
let mut device = [0u8; ids::DEVICE_ID_LENGTH];
ids::device_id(sha256, &jwk_record, &mut device)?;
```

`device_id` takes a fixed-shape [`JwkRecord`], which is what a module
has. A JWK of arbitrary shape needs an allocator to canonicalise, so a
host canonicalises it first and calls
`ids::device_id_from_canonical(sha256, &canonical, &mut device)` — the
hashing half is shared, which is what keeps the two paths agreeing.

## Workload subjects

The same HKDF shape as the tenant id, with the identity in the salt and
`"kagi-workload-subject"` as the info label. The identity is trimmed but
**not** lowercased: a workload identity is a path
(`<namespace>/<serviceaccount>`), and folding its case would merge two
workloads a cluster keeps apart.

```rust
let mut subject = [0u8; ids::WORKLOAD_SUBJECT_LENGTH];
ids::workload_subject(hkdf_sha256, secret, b"prod/checkout", &mut subject)?;
```

The differing `info` label is the whole reason a workload subject cannot
collide with a tenant id derived from the same secret, which is why the
two derivations sit in one file.

## Errors

`IdError` distinguishes an empty secret, an empty or over-long email, an
empty or over-long identity, and a malformed JWK. Every one is a caller
error, and none depends on the secret's value, so reporting which one
occurred leaks nothing.

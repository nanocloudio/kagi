# The module surface

How kagi's pieces fit together: the shared `no_std` core, the PIC modules,
the wire protocol between them, and how downstream projects embed them.

## Layered design

```
modules/common/*.rs      pure no_std fragments (crypto injected as fn pointers)
        │
        ├── modules/app/*          PIC mounts; the fluxor SDK supplies
        │                          sha256 / hmac-hkdf / aes_gcm / p256 / ed25519
        └── tests/harness/src      host mount; sha2/hkdf/aes-gcm/p256 crates
```

The fragment layer is the compatibility contract. A token minted by
`token_mint` is indistinguishable from one any conforming implementation
mints for identical inputs, and a secret sealed on a Pi opens in any other
backend implementing the same AEAD. The host mount is how that is checked:
the suites run each fragment beside crates written by other people and
compare.

## Wire protocol

`modules/common/auth_wire.rs`. A 3-byte envelope carried over fluxor
byte-stream ports:

```
[msg_type u8][len u16 LE][payload]
```

Field encodings are `f8` = `[len u8][bytes]` and `f16` = `[len u16 LE][bytes]`.
Every request carries a `u32 LE` correlation id echoed in its reply.

This is v1. There is one layout per message, changed in place when it needs
to change, with every producer, consumer, fixture and graph moving with it.
Consume through the encode/decode helpers rather than raw offsets — that is
where the length and range checks live.

### Secrets

| msg | dir | payload |
|---|---|---|
| `SECRET_GET` 0x01 | → store | `[corr][id f8]` |
| `SECRET_PUT` 0x02 | → store | `[corr][id f8][ver f8][value f16]` |
| `SECRET_LIST` 0x03 | → store | `[corr][prefix f8]` |
| `SECRET_ROTATE` 0x04 | → store | `[corr][id f8]` |
| `SECRET_VALUE` 0x11 | store → | `[corr][status][id f8][ver f8][value f16]` |
| `SECRET_ACK` 0x12 | store → | `[corr][status]` |
| `SECRET_LIST_PAGE` 0x13 | store → | `[corr][count u8][{id f8}…][more u8]` |
| `KEY_EPOCH` 0x21 | → store | `[epoch u32][kek 32B]` |

### Key lifecycle

A keyset is indexed by `(issuer, profile_id, kid)` and holds more than one
live entry, because rotation needs two keys at once. The verbs are the whole
lifecycle, in the order a rotation uses them.

| msg | payload |
|---|---|
| `KEY_ADD` 0x22 | a `KeyRecord`: loaded, not yet signing |
| `KEY_ACTIVATE` 0x23 | `[issuer f8][profile_id u16][kid f8][generation u32]` |
| `KEY_RETIRE` 0x24 | `[issuer f8][profile_id u16][kid f8][remove_after_unix u64]` |
| `KEY_REMOVE` 0x25 | `[issuer f8][profile_id u16][kid f8]` |
| `KEYSET_SNAPSHOT` 0x26 | `[count u16]` then `count` `KeyRecord`s |

A `KeyRecord` is `[issuer f8][profile_id u16][kid f8][suite u16][state u8]
[key_use u8][generation u32][activate_after_unix u64][remove_after_unix u64]
[key_ref f8]`. For a signing record `key_ref` is a vault label, never key
material.

Loading and activating are separate decisions with a deliberate gap between
them: every verifier must hold a key before anything signs with it, or the
first credential minted under it is unverifiable everywhere that has not
caught up. `RETIRE` stops signing and keeps verifying; its
`remove_after_unix` must outlast the longest credential the key ever signed.
`REMOVE` is the compromise path — immediate and unconditional.
`KEYSET_SNAPSHOT` is how a verifier that just started reaches current state.

### Minting and verification

| msg | dir | payload |
|---|---|---|
| `MINT_REQ` 0x31 | → mint | see below |
| `MINT_RESP` 0x32 | mint → | `[corr][status][delivery u8][required_len u32][body f16]` |
| `VERIFY_REQ` 0x42 | → verify | the credential and the policy it must satisfy |
| `VERIFY_RESP` 0x43 | verify → | a typed `VerifiedIdentity` |

```text
MINT_REQ:
[corr u32][request_type u8][suite u16][profile_id u16][kid f8]
[ttl_seconds u32][iss f16][sub f16][aud f16][scope f16]
[thumbprint_alg u8][jkt f8][extra_count u8]
( [key f8][valtype u8][value f16] ) * extra_count
```

An empty `kid` selects the profile's active key, which is what a caller
minting a fresh credential should ask for: pinning one would defeat
rotation. `jkt` is length-checked against `thumbprint_alg`, so a thumbprint
of any supported digest is expressible and only the right length is
accepted. An empty `jkt` omits the `cnf` claim, which is how a token with no
DPoP binding is minted. Up to `MAX_EXTRA_CLAIMS` (32) custom claims travel
with the request (valtype 1=Str, 2=U64, 3=Bool, 4=Raw JSON) and reach
`jose::write_access_claims_ext`, so the emitted claim set matches what any
other consumer of that fragment emits.

A mint reply's `status` is a `mint_err` code rather than a shared `ST_*` one,
because a reader has to know what a refusal meant for a mint specifically.
`required_len` is the credential's true length whatever the delivery, so a
caller sizing a buffer never has to infer it from `body`.

`VERIFY_RESP` carries a typed identity rather than claims JSON. The policy
travels with the request, so the audience check happens in one place instead
of once per caller.

### Admission and the OAuth surface

| msg | dir | payload |
|---|---|---|
| `ADMIT_REQ` 0x35 | → admission | the credential and DPoP proof, with the request they were made for |
| `ADMIT_RESP` 0x36 | admission → | subject, device, key binding and the evidence established, or a typed refusal |
| `GRANT_REQ` 0x37 | → admission | as `ADMIT_REQ`; admission mints as well |
| `GRANT_RESP` 0x38 | admission → | `[corr][status][token f16]` |
| `AUTHORIZE_REQ` 0x39 | → authcode | the client's ask plus the subject's presentation |
| `AUTHORIZE_RESP` 0x3A | authcode → | `[corr][status][code f16][redirect_uri f16][state f16]` |
| `CODE_EXCHANGE_REQ` 0x3B | → authcode | `[corr][code f16][redirect_uri f16][client_id f8][code_verifier f16]` |
| `CODE_EXCHANGE_RESP` 0x3C | authcode → | `[corr][status][access_token f16][id_token f16]` |

A grant request carries no subject, audience, scope or lifetime. The subject
and key binding come from the credential admission established; the audience,
scope and lifetime are deployment params on the admitter. A client cannot ask
for a wider audience or a longer life because there is no field to ask in.

Every reply in this family refuses at decode to carry both a refusal status
and a payload: a caller that ignored `status` cannot end up holding something
token-shaped.

### Assurance

Admission is the only stage that sees both what the enrolment record says
was proved and what the request in front of it just proved, so it is where
the two are combined. `ADMIT_RESP` carries the result as a fixed-width
`assurance::EvidenceWire` — a method bitset, a key binding, two flags and
the time of the proof — and both minters render it into the `amr`, `acr`
and `auth_time` claims through the same fragment a relying party scores
with. The bitset is the fragment's own, so a method added there needs no
change to any wire that carries one.

`VERIFY_RESP` reports the same shape, read out of the credential's own
claims rather than inferred from its form: a `cnf` binding says a
credential is non-bearer, which is one fact among the several a level is
scored from.

### Replay

A DPoP proof admits once. Each module keeps a time-bounded, fail-closed
window in its own memory: an entry lives until the proof it came from would
be refused as stale anyway, and a saturated window refuses rather than
evicting, because an eviction under load is an admission under load.

That window is memory, so it answers for one process. The modules whose
decisions rest on the shared ledger — `mint_admission` and `authcode` —
additionally claim the proof's replay identifier under `NS_REPLAY`, as a
create-only write: the first caller records it and every other gets a
conflict, at one linearization point, whichever replica they reached and
whether or not a process has restarted since. A claim that cannot be made
refuses, because the ledger's absence must not become a way to replay.

The key is a digest of the proof, not the client's own `jti`, which is
whatever the client wrote. The entry expires with the proof: one outside its
freshness window is refused before it is ever offered, so remembering it
longer would be paying to store what nothing can present.

Modules whose state is their own memory — `e2ee_state_endpoint`,
`keypackage_endpoint` — keep only the local window, and correctly: a proof
replayed at another replica reaches a different pool of state and can take
nothing this one holds.

### Control plane

| msg | payload |
|---|---|
| `REVOKE` 0x51 | `[id f8]` |
| `ENROL_AUTH_REQ` 0x53 | `[corr][purpose u8][ttl_seconds u32][audience f16]` |
| `ENROL_AUTH_RESP` 0x54 | `[corr][status][auth_id f8][secret f8][expires_at u64]` |

Statuses: `OK=0, NOT_FOUND=1, DECRYPT_FAILED=2, MALFORMED=3, NO_KEY=4,
FULL=5, BAD_SIGNATURE=6, EXPIRED=7, CONFLICT=8, UNAVAILABLE=9`. The
admission and OAuth families carry their own typed reasons (`admit_err`,
`grant_err`, `authz_err`) so a refusal says which question was answered.

## Ledger protocol

`modules/common/state_wire.rs` carries the durable side: conditional writes
and reads against `security_state`, keyed by a namespace byte. Namespaces
declare what they need — `requires_linearized` for the ones where a stale
read is a security answer, and a minimum durability fence per namespace, so
a deployment cannot quietly serve identity decisions from a volatile tier.
Its message ids start at `0x60`, above everything `auth_wire` has claimed.

## secret_store

Encrypted store with one KEK, delivered as `KEY_EPOCH`; every request
answers `ST_NO_KEY` until it arrives. Records are sealed with AES-256-GCM in
the `secret_record.rs` envelope — AAD binds `id ‖ 0x00 ‖ version_id`, so
ciphertext cannot be swapped between identities, and nonces are
`epoch u32 ‖ counter u64` with the counter seeded from wall-clock millis so
a restart never reuses a nonce under the same key.

Persistence is a single file `secrets/store.bin` through the fs contract:
`["KSF1"][body_len u32]` then concatenated records, full-file rewrite and
fsync on PUT and ROTATE. `E_AGAIN` from a provider still initialising holds
and retries; a hard error degrades to memory-only with one log line.

The format is the portable part: a store sealed by a Pi module opens
unchanged wherever the same KEK and the same AEAD are available. secret_store
builds for `bcm2712` and `wasm`. The wasm build is the browser backend: with
no fs provider there it runs memory-only, and the AES-256-GCM sealing uses the
SDK's portable code path. It exports the fluxor module ABI and imports only
the declared host capability surface.

## token_mint

Stateless ES256 / EdDSA JWS minting, WCET-bounded at four signs per step.
Token assembly is the `jose.rs` fragment — the same fragment every other
minting path mounts, which is what makes their output identical. Both
signature schemes are deterministic (RFC 6979 ECDSA, RFC 8032 EdDSA), so no
runtime entropy is needed.

Signing goes through the fluxor `key_vault` capability surface. A `KeyRecord`
names a label; the private half is generated inside the vault on first open
and leaves it only as signatures. The public half is announced back out on
`key_announce`, which is how verifiers come to hold it. With no vault
registered the module signs in-module through the SDK's deterministic
implementations; the software vault backend is the same deterministic core,
so vault-backed and fallback tokens are byte-identical, while a device HSM
produces its own valid ECDSA signatures.

## token_verify

The on-target counterpart: stateless JWS verification for ES256 and EdDSA,
WCET-bounded at four verifies per step, `bcm2712` only. The verifying keys
arrive as the same keyset lifecycle. A `VERIFY_REQ` splits the compact JWS
with `jose.rs`, recomputes the signature with the SDK's `ecdsa_verify` /
`ed25519_verify`, and only then range-checks `iat`/`exp` against a 60-second
skew. The reply is a typed identity, so the caller authorises on fields it
did not have to parse.

## Embedding elsewhere

kagi publishes to the local OCI store (`fluxor publish` → the `kagi-common`
source tree plus the module artefacts), so any fluxor-native project can add
`[dependencies] kagi = "0.0.1"`, run `fluxor sync`, and wire `token_mint`
into its graph: feed `MINT_REQ` frames from the stage that needs outbound
credentials, deliver key material from the deployment's key source, and treat
`MINT_RESP` `ST_OK` payloads as bearer tokens for the egress leg. Validation
on the receiving side is `token_verify`, or `resource_gate` if the receiving
surface wants the DPoP binding checked too.

Step by step: [../guides/embedding-token-mint.md](../guides/embedding-token-mint.md).

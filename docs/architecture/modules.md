# Kagi module surface

How kagi's fluxor-native pieces fit together: the shared `no_std` core, the
PIC modules, their wire protocol, and how downstream projects embed them.

## Layered design

```
modules/common/*.rs      pure no_std fragments (crypto injected as fn pointers)
        │
        ├── modules/app/*          PIC mounts; the fluxor SDK supplies
        │                          sha256 / hmac-hkdf / aes_gcm / p256
        └── tests/harness/src      host mount; sha2/hkdf/aes-gcm/p256 crates
```

The fragment layer is the compatibility contract. A token minted by the
`token_mint` module is indistinguishable from one any conforming
implementation mints for identical inputs, and a secret sealed on a Pi
opens in any other backend that implements the same AEAD. The host mount
is how that is checked: the suites run each fragment beside crates
written by other people and compare.

Fragments cross-reference each other as `crate::<mod>` — every consumer
(each PIC `mod.rs`, and the harness lib) mounts the fragments it needs
at the crate root under the same names. PIC modules build at edition 2021
(`edition = "2021"` in each manifest).

## Wire protocol (`modules/common/auth_wire.rs`) — DRAFT

3-byte envelope carried over Fluxor byte-stream ports:
`[msg_type u8][len u16 LE][payload]`.
Field encodings: `f8` = `[len u8][bytes]`, `f16` = `[len u16 LE][bytes]`.
Every request carries a `u32 LE` correlation id echoed in the reply.

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
| `MINT_KEY` 0x22 | → mint | `[alg u8][kid f8][key 32B]` (ES256: P-256 scalar BE; Ed25519: RFC 8032 seed) |
| `MINT_REQ` 0x31 | → mint | `[ver u8=2][corr][alg u8][ttl_s u32][iss f8][sub f8][aud f8][scope f8][jkt f8][extra_count u8]([key f8][valtype u8][value f16])*` |
| `MINT_RESP` 0x32 | mint → | `[corr][status][token f16]` |

Statuses: `OK=0, NOT_FOUND=1, DECRYPT_FAILED=2, MALFORMED=3, NO_KEY=4, FULL=5`.
Numeric ids and layouts are draft until promoted to v1 — consume through the
published common-source helpers, never raw offsets.

## secret_store

Encrypted store with one KEK (delivered as `KEY_EPOCH`; `ST_NO_KEY` until it
arrives). Records are sealed with AES-256-GCM in the `secret_record.rs`
envelope — AAD binds `id ‖ 0x00 ‖ version_id`, so ciphertext can't be swapped
between identities; nonces are `epoch u32 ‖ counter u64` (counter seeded from
wall-clock millis so restarts never reuse a nonce under the same key).

Persistence: single file `secrets/store.bin` via the fs contract —
`["KSF1"][body_len u32]` header, then concatenated records; full-file rewrite
+ fsync on PUT/ROTATE. `E_AGAIN` (provider still initialising) holds and
retries; a hard fs error degrades to memory-only with one log line. The same
record format is the target for browser (wasm/OPFS) and HSM backends: only
the AEAD/persistence providers change, never the envelope.

The format is the portable part: a store sealed by a Pi module opens
unchanged wherever the same KEK and the same AEAD are available — one
format, every backend.

### Targets

secret_store builds for `bcm2712` and `wasm` (`hardware_targets` in its
manifest; both in `[ci].targets`). The wasm build is the browser backend:
with no fs provider in the browser it runs memory-only (the same graceful
degrade as a Pi with no FS provider), and the AES-256-GCM sealing uses the
SDK's portable (non-aarch64) code path. Durable browser storage
(OPFS/IndexedDB) is a future fs-provider concern, not a module change.
The wasm build exports the Fluxor module ABI and imports only the declared
host capability surface.

## token_mint

Stateless ES256 JWT minting. The signing key arrives on `key_material`
(`MINT_KEY`, latest wins) — in the demo graph it flows from secret_store's
`replies`, in production from any key-manager module. Token assembly is the
`jose.rs` fragment — the same fragment every other minting path here
mounts, which is what makes their output identical. WCET-bounded at 4
signs per step.

Signing goes through the Fluxor `key_vault` capability surface when present.
At init the module
`PROBE`s the contract, and each delivered `MINT_KEY` is `STORE`d into the
vault — after which the module wipes its in-module copy of the private key,
so the scalar lives only inside the backend. Minting then calls `key_vault`
`SIGN` (P-256 signs the SHA-256 digest; Ed25519 signs the message itself,
per the contract). With no vault present — e.g. a bare graph with no
backend registered — the module falls back to signing in-module via the
SDK's RFC 6979 deterministic ECDSA / `ed25519.rs` (no runtime entropy). The
software `key_vault` backend is the same deterministic core, so vault-backed
and fallback tokens are byte-identical; a device HSM backend produces its own
(non-deterministic but valid) ECDSA signatures.

EdDSA mints on-target too using the SDK's deterministic RFC 8032
implementation. Requests carry `alg` (`MINT_ALG_ES256` /
`MINT_ALG_ED25519`) and must match the loaded key's algorithm, else
`ST_NO_KEY`.

Optional cnf + custom claims (W1/P1): `MINT_REQ` is a versioned,
forward-compatible layout (`MINT_REQ_VERSION = 2`; `decode` rejects other
versions). Its `jkt` field is now optional — an empty `jkt` omits the `cnf`
claim entirely, minting ServiceAccount / id-token-shaped tokens with no DPoP
binding — and it carries up to `MAX_EXTRA_CLAIMS` (32) custom claims
(`[key f8][valtype u8][value f16]`; valtype 1=Str, 2=U64 as 8-byte LE,
3=Bool as one 0/1 byte, 4=Raw JSON). The module forwards these to
`jose::write_access_claims_ext`, so the emitted claim set matches what any
other consumer of that fragment emits; any jose error (too many claims, duplicate/reserved
key, buffer) replies `ST_MALFORMED`. The token buffer and `tokens`
`max_record` are sized to 4096 to admit a realistically claim-laden token.

## token_verify

The on-target counterpart to `token_mint`: stateless JWS verification for
ES256 and EdDSA. The verifying key arrives on `verify_key` (`VERIFY_KEY`,
latest wins) as `[alg][kid][pubkey]` — the SEC1 public point for ES256
(33/65 bytes), the 32-byte public key for Ed25519. A `VERIFY_REQ`
(`[corr][token]`) splits the compact JWS with the `jose.rs` fragment,
recomputes the signature with the SDK's `ecdsa_verify` / `ed25519_verify`,
and — only on a valid signature — range-checks the `iat`/`exp` claims (60s
skew) before replying `VERIFY_RESP` `[corr][status][claims f16]`. On `ST_OK`
the reply **carries the decoded claims JSON**, so a caller (e.g. a chronicle
Decision stage) authorises on `iss`/`aud`/`scope`/custom claims — the module
verifies the token, the caller owns the policy decision. Reason statuses
(empty claims): `ST_NO_KEY` (no key yet), `ST_MALFORMED` (not a compact
JWS), `ST_BAD_SIGNATURE` (crypto rejection), `ST_EXPIRED` (outside the
window, or a payload larger than the module's 1 KiB claims bound).
WCET-bounded at 4 verifies per step; `bcm2712`-only.

## Embedding elsewhere (e.g. chronicle egress proxies)

kagi publishes to the local OCI store (`fluxor publish` → `kagi-common`
source + `token_mint`/`token_verify`/`secret_store` fmods), so any
fluxor-native project can add
`[dependencies] kagi = "0.0.1"`, `fluxor sync`, and wire `token_mint` into
its graph: feed `MINT_REQ` frames from the pipeline stage that needs
outbound credentials, deliver key material from the deployment's key source,
and treat `MINT_RESP` `ST_OK` payloads as bearer tokens for the egress leg.
Validation on the receiving side is `token_verify`, or `resource_gate`
if the receiving surface wants the DPoP binding checked too.

Step-by-step recipe: `docs/guides/embedding-token-mint.md`.

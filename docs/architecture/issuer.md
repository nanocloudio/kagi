# Kagi architecture

Kagi is a **fluxor-native** project, and it is modules and nothing else.
Its cryptographic core is written once as dependency-free `no_std`
fragments; the PIC modules mount those fragments, the host test suites
mount the same files, and (for the secret store) so does a browser wasm
build. This document describes how the pieces fit together as the system
exists today. For the protocol itself (flows, identifiers,
anti-phishing) see `docs/specification.md`; for the module wire surface
see `docs/architecture/modules.md`.

## Guiding principles

- **Stateless** request handling: no user database. Trust derives from
  cryptographic proofs plus proven email control; security comes from short
  TTLs and an optional revocation feed, not stored sessions.
- **One core, every substrate.** The tenant/device id derivation, JWS
  assembly/verification, PKCE, DER emission and the encrypted-record format
  live in `modules/common/*.rs` with crypto injected as function pointers,
  so a module and an independent implementation produce byte-identical
  output.
- **Deterministic signing.** ES256 (RFC 6979) and `EdDSA` (RFC 8032) need no
  runtime entropy, which is what makes minting viable inside a PIC module.
- **No host binary.** There is no crate to link and no process to run
  besides `fluxor run` over a graph. What used to be an axum service is
  the endpoint modules below.

## Layout

```
fluxor.toml / fluxor.lock   project manifest + pinned deps (fluxor CLI)
Makefile                    lifecycle entry points (the fluxor CLI)
modules/common/*.rs         the portable core (b64, jwk, ids, jose, pkce,
                            dpop, der, spiffe, assurance, recovery,
                            e2ee_credential, secret_record, auth_wire,
                            chan, totp, cbor, webauthn)
modules/app/                the eleven PIC modules
configs/                    deployment graphs: issuer.yaml, pki.yaml
tests/harness/              a standalone cargo workspace: the host suites
docs/                       this
```

`modules/common` is a **source tree, not a crate**. Modules mount it by
`#[path]`, and so does `tests/harness/src/lib.rs` — one source, two
compilations. That is what makes the suites meaningful: they pin the
fragments against `sha2`, `hkdf`, `hmac`, `aes-gcm`, `p256` and
`ed25519-dalek`, which were written by other people.

Conclave mounts `e2ee_credential.rs` from the published `kagi-common`
source tree, so the credential contract has exactly one definition
across the two repositories.

## The issuer graph

`configs/issuer.yaml` is the issuer. Eight `http` listeners sit in front
of the endpoint modules — `LINUX_NET_MAX_INBOUND` is eight, which bounds
how many modules may drive the network, so eight is the ceiling for one
graph:

| listener | what answers |
|---|---|
| `enrol_http` | `POST /start`, `POST /redeem` → `enrollment_endpoint` |
| `token_http` | `POST /token` → `token_endpoint` → `token_mint` |
| `gate_http` | the protected surface → `resource_gate` |
| `e2ee_http` | `POST /e2ee/credential` → `e2ee_credential_endpoint` |
| `keypkg_http` | `/e2ee/keypackages[/claim]` → `keypackage_endpoint` |
| `state_http` | `/e2ee/state/{load,commit}` → `e2ee_state_endpoint` |
| `wellknown_http` | `/.well-known/jwks.json`, `/.well-known/revocations.json` → `wellknown_endpoint` |
| `control_http` | the operator websocket (below) |

Key material and revocations arrive over one `remote_channel` mux,
which carries exactly four logical channels. Four is enough because an
edge can fan to several modules and a channel can carry several frame
types:

```
ch0 → token_mint.key_material                (MSG_MINT_KEY)
ch1 → wellknown_endpoint.control             (MSG_VERIFY_KEY)
    → resource_gate.verify_key               — the same edge
ch2 → enrollment_endpoint.signing_key        (MSG_MINT_KEY)
    → e2ee_credential_endpoint.signing_key   — the same edge
ch3 → wellknown_endpoint.control             (MSG_REVOKE)
    → secret_store.key_update                (MSG_KEY_EPOCH)
```

So an operator delivers the signing seed once and every module that
needs a key gets it, and a revocation and a KEK epoch travel the same
way.

`configs/pki.yaml` is a **separate deployment**: `certificate_endpoint`
and its control chain. A CA is a different key and a different blast
radius from a token issuer, and the issuer graph has no lane left
anyway.

## The modules

Built with `fluxor modules build` into `.fmod` artefacts, consuming the
fluxor SDK's crypto (sha256, hmac/hkdf, aes_gcm, p256, ed25519). See
`docs/architecture/modules.md` for the wire protocol.

- **enrollment_endpoint** — challenge issuance with PKCE, then `/redeem`
  proof-of-possession → device certificate.
- **token_endpoint** — the HTTP shape of a token request; it translates,
  and `token_mint` mints.
- **token_mint** — stateless ES256/`EdDSA` JWT minting; key delivered on a
  port.
- **token_verify** — the verification counterpart; validates the
  signature, then the `iat`/`exp` window.
- **resource_gate** — DPoP-bound admission for a protected surface.
- **wellknown_endpoint** — the JWKS and the revocation set.
- **secret_store** — embeddable encrypted store (AES-256-GCM sealed
  records, KEK epochs, fs-contract persistence). Targets `bcm2712` and
  `wasm`; the browser build runs memory-only.
- **e2ee_credential_endpoint**, **keypackage_endpoint**,
  **e2ee_state_endpoint** — the messaging half; see
  `docs/specification.md`.
- **certificate_endpoint** — X.509 leaves, in the PKI graph.

## Secrets & keys

A signing seed reaches `token_mint` over the control channel, and
`secret_store` holds everything durable in its `store.bin` format — the
same bytes in the browser, on a Pi and on a server. Rotating the KEK is
a `MSG_KEY_EPOCH` on ch3; rotating a signing key is a fresh
`MSG_MINT_KEY` with the public half following on ch1 so verifiers
overlap.

There is no `SecretProvider` trait and no `.env`: a deployment's
parameters are module params and template variables in the graph, and
`fluxor.toml`'s `[ci.templates] vars` carries render-only defaults so
the template gate can prove every placeholder is substituted.

## Testing

`tests/harness` is its own cargo workspace, outside `modules/**` as the
module standard requires. Two kinds of suite live there:

- **fragment suites** — mount `modules/common/*.rs` and check them
  against independent crates.
- **e2e suites** — render a graph from `configs/`, launch it with
  `fluxor run`, and drive it over HTTP. `KAGI_REQUIRE_E2E=1` turns a
  graph that will not launch from a skip into a failure.

`mls.rs` is deliberately not a module: it is a thin `openmls` adapter,
and reimplementing TreeKEM and the MLS key schedule against the SDK
would buy nothing the credential contract does not already give. It
stays a conformance fixture.

## Observability

Each data-moving module declares an `[observability]` block in its
manifest (metrics/spans), enforced by `fluxor ci`'s observability gate;
on-target signals travel as fixed-layout telemetry records.

## Design targets, not wired

- OIDC discovery at `/.well-known/openid-configuration`, and `id_token`
  assembly (`at_hash`, `nonce`, `auth_time`) over the existing minting path.
- The OAuth2 authorisation-code surface: client registry, consent, and
  `/userinfo`. Deferred until a concrete relying party needs it.
- A delivery backend for the `Email` enrollment gate. The gate exists and
  the admission decision is wired; nothing in this repository sends mail.
- Durable browser storage for the wasm secret store, which needs an
  OPFS or IndexedDB filesystem provider on the fluxor side.
- Per-key access policy and a tamper-evident audit log. Both own durable
  state, so neither belongs in `secret_store`, which full-rewrites its
  backing file and degrades to memory on error.

# The issuer

Kagi is a fluxor-native project: modules, and nothing else. Its
cryptographic core is written once as dependency-free `no_std` fragments;
the PIC modules mount those fragments, the host test suites mount the same
files, and the secret store also builds for the browser as wasm. There is
no host binary in any request path — `fluxor run` over a graph is the whole
program.

For the protocol see [../specification.md](../specification.md); for the
module surface and its wire protocol see [modules.md](modules.md).

## Principles

- **Stateless request handling.** Trust derives from cryptographic proofs
  and from a durable identity ledger, not from sessions. Security comes
  from short TTLs and a published revocation set.
- **One core, every substrate.** Identifier derivation, JWS assembly and
  verification, PKCE, DER emission and the encrypted-record format live in
  `modules/common/*.rs` with crypto injected as function pointers, so a
  module and an independent implementation produce byte-identical output.
- **Deterministic signing.** ES256 (RFC 6979) and EdDSA (RFC 8032) need no
  runtime entropy, which is what makes minting viable inside a PIC module.
- **Keys by label.** A signing record names a vault label. The private half
  is generated inside the vault, leaves it only as signatures, and cannot
  be supplied or observed on the control plane.

## Layout

```
fluxor.toml / fluxor.lock   project manifest and pinned dependencies
Makefile                    lifecycle entry points, delegating to the CLI
modules/common/*.rs         the portable core, mounted by every consumer
modules/app/                the PIC modules, one directory each
configs/                    deployment graphs and the e2e fixtures
tests/harness/              a standalone cargo workspace: the host suites
docs/                       this
```

`modules/common` is a source tree, not a crate. Modules mount it with
`#[path]`, and so does `tests/harness/src/lib.rs` — one source, two
compilations. That is what makes the suites meaningful: they pin the
fragments against `sha2`, `hkdf`, `hmac`, `aes-gcm`, `p256` and
`ed25519-dalek`, which were written by other people. Fragments reach each
other as `crate::<mod>`, so every consumer mounts what it needs at the
crate root under the same names. Modules build at edition 2021.

Conclave mounts `e2ee_credential.rs` from the published `kagi-common`
source tree, so the credential contract has one definition across both
repositories.

## The issuer graph

`configs/issuer.yaml` wires the issuer. Six `http` listeners sit in front
of the endpoint modules:

| listener | what answers |
|---|---|
| `enrol_http` | `POST /start`, `POST /redeem` → `enrollment_endpoint` |
| `token_http` | `POST /token` → `token_endpoint` → `mint_admission` → `token_mint` |
| `gate_http` | the protected surface → `resource_gate` |
| `e2ee_http` | the `/e2ee/` family → `e2ee_router` → the three E2EE endpoints |
| `wellknown_http` | `/.well-known/jwks.json`, `/.well-known/revocations.json` → `wellknown_endpoint` |
| `control_http` | the operator WebSocket, behind `control_tls` and `control_admission` |

Six against a ceiling of eight. `LINUX_NET_MAX_INBOUND` is eight distinct
inbound command lanes, one per producer module, so a flood on one cannot
serialise ahead of latency-critical traffic on another. It bounds modules
driving the network, not ports: one `http` module serving many routes costs
one lane whatever the route count, and `linux_net` holds 128 connection
slots. A ninth `http` module gets no lane and never issues its bind — the
port simply never accepts, with nothing in the log to say why.

The way to fit is a module owning a path family. `wellknown_endpoint` owns
both public documents; `e2ee_router` owns `/e2ee/` and fans to the three
endpoints behind it, because wave's `http` has exactly one `req_out` and an
application behind it is one module. Static documents — `/healthz`,
`/.well-known/ca.pem` — are routes on `http` itself and cost nothing.

## The control plane

One WebSocket, terminated by `control_tls` and admitted by
`control_admission`: a caller presents a client certificate under the
deployment CA whose key hash is allowlisted, or gets a 403 at the upgrade.
Behind it a `remote_channel` mux carries four logical channels:

```
ch0 → token_mint.key_material                (MSG_KEY_ADD)
ch1 → wellknown_endpoint.control             (MSG_KEY_ADD, VERIFY records)
    → resource_gate.verify_key               — the same edge
    → mint_admission.verify_key
    → keypackage_endpoint.verify_key
ch2 → enrollment_endpoint.signing_key        (MSG_KEY_ADD)
    → e2ee_credential_endpoint.signing_key   — the same edge
ch3 → wellknown_endpoint.control             (MSG_REVOKE)
    → enrollment_endpoint.auth_requests      (MSG_ENROL_AUTH_REQ)
ch3 ← enrollment_endpoint.auth_replies       (MSG_ENROL_AUTH_RESP)
```

Nothing secret travels on it. A signing record on ch0 or ch2 names a vault
label; the public half comes back out of the signer on its own
`key_announce` edge, because with the private half generated inside the
vault the signer is the only component that can say what its public half
is. An operator delivers one record and the graph works out the rest.

Two mechanisms make four channels enough. One edge fans to several modules,
so modules that must agree about a key are fed by the same edge rather than
by an operator remembering to send twice — the key set and the gate share
ch1 for exactly that reason, since a gate refusing tokens the published set
calls good is the worst kind of outage. And one channel carries several
frame types, each module taking its own and ignoring the rest, which is why
ch3 serves both revocation and the operator enrolment ceremony.

An admitted operator is not harmless. Distributing verification keys is
what this socket is for, so an operator can push a VERIFY record naming a
key they hold and make `resource_gate` and `wellknown_endpoint` trust
credentials they mint themselves. What key custody removes is the issuer's
own key leaving the machine: a compromised control plane cannot produce
credentials that outlive the compromise or that an audit cannot tell from
genuine ones.

`configs/pki.yaml` is a separate deployment carrying `certificate_endpoint`
and its control chain. A CA is a different key and a different blast radius
from a token issuer.

## The modules

Built with `fluxor modules build` into `.fmod` artefacts, consuming the
fluxor SDK's crypto (sha256, hmac/hkdf, aes_gcm, p256, ed25519).

**Enrolment and identity**

- `enrollment_endpoint` — `/start` binds an email, a device key and a PKCE
  challenge into a signed token; `/redeem` takes it back with the verifier,
  a possession proof and the delivered code, and returns a device
  certificate. `/authenticators/totp` attaches a second factor to an
  enrolled device, verified against this module's own signing key: it signed
  the certificate, so it already holds the public half and needs no
  verification-key edge of its own.
- `security_state` — the durable identity ledger over `storage.object`:
  create-if-absent, replace-if-unchanged, and read. Enrolment transactions,
  device membership and revocation live here. It refuses everything until the
  graph declares which authority it is — `single-node` or `replicated` —
  because that is what decides whether a `LocalDurable` acknowledgement counts
  as a commit, and both defaults are silently wrong for half of the
  deployments that would take one.
- `certificate_endpoint` — an X.509 client certificate for a device key,
  in the PKI graph.

**Tokens**

- `token_endpoint` — the HTTP shape of a token request. It translates; it
  decides nothing.
- `mint_admission` — may this presenter mint, and for whom. One question,
  answered once, for whoever asks. It claims the proof's replay identifier in
  the ledger before looking anything up, checks a presented one-time code
  against the device's authenticator, and scores what was proved. In grant
  mode it drives the mint itself, so a subject established here never passes
  back through the pipeline.
- `token_mint` — ES256 / EdDSA JWS minting from a keyset indexed by
  `(issuer, profile_id, kid)`.
- `token_verify` — the verification counterpart: signature first, then the
  `iat`/`exp` window, replying with a typed identity.
- `authcode` — the OIDC authorization-code flow: `/authorize` issues a
  single-use code bound to a client and a PKCE challenge, and the exchange
  redeems it for an access token and an ID token.
- `resource_gate` — DPoP-bound admission for a protected surface.
- `wellknown_endpoint` — the key set, the revocation filter, and the OIDC
  discovery document. Discovery is served only where the deployment declares
  its four URLs, because this module owns one listener and cannot know where
  the others answer; a deployment that wires no authorization-code surface
  advertises none.

**Messaging**

- `e2ee_router` — one listener for the whole `/e2ee/` family.
- `e2ee_credential_endpoint` — binds a device's messaging keys to its
  enrolled identity.
- `keypackage_endpoint` — publication and one-time claiming of key
  packages.
- `e2ee_state_endpoint` — endpoint state for an encrypted group, held so
  that recovery cannot reuse a message generation or roll an epoch back.

**Supporting**

- `secret_store` — sealed secret records behind a channel request API.
  Targets `bcm2712` and `wasm`; the browser build runs memory-only.
- `control_admission` — who may open the control socket.

## Testing

`tests/harness` is its own cargo workspace, outside `modules/**` as the
module standard requires. Two kinds of suite live there:

- **fragment suites** mount `modules/common/*.rs` and check them against
  independent crates.
- **e2e suites** render a graph from `configs/`, launch it with
  `fluxor run`, and drive it over HTTP or the control socket.
  `KAGI_REQUIRE_E2E=1` turns a graph that will not launch from a skip into
  a failure.

`mls.rs` is a conformance fixture rather than a module: it is a thin
`openmls` adapter, and reimplementing TreeKEM and the MLS key schedule
against the SDK would buy nothing the credential contract does not already
give.

## Observability

Each data-moving module declares an `[observability]` block in its
manifest, enforced by `fluxor ci`'s observability gate. On-target signals
travel as fixed-layout telemetry records.

## What this repository does not provide

- A mail transport. The enrolment gate and its admission decision are
  wired; delivery is the deployment's.
- Durable browser storage for the wasm secret store, which needs an OPFS
  or IndexedDB filesystem provider on the fluxor side.
- Per-key access policy and a tamper-evident audit log. Both own durable
  state, so neither belongs in `secret_store`, which full-rewrites its
  backing file and degrades to memory on error.

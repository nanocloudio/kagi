# kagi

Kagi is the enrollment and token authority for the nanocloud trust
domain. It turns proofs — control of an inbox, a device key held in a
secure enclave, a passkey, an operator-issued bootstrap token — into
short-lived SPIFFE identities, and every relying party verifies those
identities without calling kagi back.

That last property is the design centre. A key management service is an
online oracle: every operation round-trips to it, and it has to be
running for anything else to work. Kagi issues and gets out of the way.
Verification needs a published key set, a pinned CA certificate, or a
32-byte identity hash, all of which a relying party can hold locally. It
is why the same core runs in a server issuer, inside a position-
independent module on a Pi, and in a browser.

Kagi holds roots, not other people's secrets: an issuing CA key, a
key-encryption key, a signing key. It has no user database. Tenant and
device identifiers are derived, not stored:

```
tenant_id = HKDF(issuer_secret, "tenant-id", lower(email))[..22]
device_id = b64url(sha256(canonical_device_jwk))[..22]
```

## Layout

```
fluxor.toml            Fluxor project manifest; fluxor.lock pins artefacts
Makefile               lifecycle entry points delegated to the Fluxor CLI
modules/common/        pure no_std fragments — the portable core
modules/app/           Fluxor PIC modules — the whole issuer
configs/               deployment graphs (issuer.yaml, pki.yaml)
tests/harness/         host suites that mount the fragments and drive graphs
docs/                  documentation; docs/overview.md indexes it
```

## Quick start

```
make -C ../fluxor install     # once, to get the fluxor CLI
fluxor sync                   # materialise the lockfile-pinned SDK
make build
```

Then follow [docs/guides/running.md](docs/guides/running.md), which
brings the issuer up with the `Direct` enrollment gate and enrolls a
device with curl.

## The portable core

`modules/common/*.rs` are dependency-free `no_std` fragments with crypto
primitives injected as function pointers, so the same bytes-in,
bytes-out logic runs everywhere:

- **host** — mounted by `tests/harness`, with crypto from `sha2`,
  `sha1`, `hkdf`, `hmac`, `aes-gcm`, `p256` and `ed25519-dalek`, so the
  suites pin the fragments against independent implementations
- **fluxor modules** — mounted by path, with crypto from the fluxor SDK
- **wasm** — the `secret_store` wasm build uses the same core

The fragments are `b64`, `jwk`, `jose`, `ids`, `pkce`, `dpop`,
`secret_record`, `auth_wire`, `totp`, `cbor`, `webauthn`, `spiffe`,
`der`, `assurance`, `recovery` and `e2ee_credential`. Conclave mounts
`e2ee_credential` too, which is how both sides agree on one contract.

## What it issues

- **Access tokens** — short-lived, DPoP-bound (`cnf.jkt`), carrying the
  assurance the authentication reached (`amr`, `acr`, `auth_time`).
- **Device certificates** — the durable enrollment anchor, presented only
  to `/token`.
- **SPIFFE identities** — a P-256 mTLS leaf and the cert-bound JWT-SVID
  that pairs with it. See
  [docs/identity-provisioning.md](docs/identity-provisioning.md).
- **Workload tokens** — audience-scoped, no proof-of-possession binding,
  for service accounts.
- **Wrapped data keys** — kagi holds the key-encryption key and hands
  back wrapped data keys, so a caller envelope-encrypts its own keyspace
  and stores only the wrapped form. Kagi never sees the data, and this is
  as far into key management as it goes: there is no per-key-handle
  crypto-as-a-service API. Source: `modules/app/secret_store`.

## Authentication

The inbox is a bootstrap, not a credential. A tenant holds a set of
authenticators, and an enrolled device vouches for the next one by
signing a cross-attestation, so replacing a device does not fall back to
the weakest proof available. Authenticator apps (RFC 6238) and passkeys
are both supported, and every token states which factors backed it, so a
relying party can serve ordinary requests on a cheap proof and demand a
stronger one for a privileged operation.

[docs/guides/authenticators.md](docs/guides/authenticators.md) covers the
factors, the assurance levels, and the step-up contract.

## Modules

The issuer is modules and nothing else — `configs/issuer.yaml` wires them
behind wave's `foundation/http`, and `configs/pki.yaml` is the separate
CA deployment.

- **enrollment_endpoint** — `/start` and `/redeem`: the front door, and
  the device certificate every later token rests on.
- **token_endpoint** — the HTTP shape of a token request, in front of
  `token_mint`. It translates; it does not mint.
- **token_mint** — stateless ES256 and `EdDSA` JWT minting. The signing key
  arrives on a port, and signing is deterministic (RFC 6979 and RFC
  8032), so no runtime entropy is needed. See
  [docs/guides/embedding-token-mint.md](docs/guides/embedding-token-mint.md).
- **token_verify** — stateless verification with validity-window checks,
  returning the decoded claims to the calling graph stage. The module
  verifies; the caller decides.
- **resource_gate** — the middleware a resource server runs: admit a
  DPoP-bound request, or say why not.
- **wellknown_endpoint** — the two public documents, `/jwks.json` and the
  revocation set.
- **secret_store** — embeddable encrypted secret store. AES-256-GCM
  sealed records with id- and version-bound additional data, key-epoch
  rotation on a control port, and a request/reply wire protocol. Builds
  for `bcm2712` and `wasm`; the browser build runs memory-only.
- **e2ee_credential_endpoint** — binds a device's messaging keys to its
  enrolled identity. Conclave verifies what this signs.
- **keypackage_endpoint** — publish and one-time-claim key packages, so a
  device can be added to a group while offline.
- **e2ee_state_endpoint** — endpoint state that can only move forward, so
  a restore or a failover cannot reuse a generation.
- **certificate_endpoint** — an X.509 leaf for a subject key, in the PKI
  deployment.

## Status

Working: the enrollment flow and its gates, device certificates, DPoP,
access and workload tokens, X.509 and SPIFFE issuance, the encrypted
secret store on Pi and in the browser, data-key wrapping, and the
assurance, TOTP, passkey, device-set and recovery machinery described
above.

Built but deliberately unwired in the reference issuer graph: the OAuth2
authorization-code surface (`authcode`, proved by `configs/e2e-authcode.yaml`)
and OIDC discovery (`wellknown_endpoint` serves the document when a
deployment declares its URLs; `configs/e2e-wellknown.yaml` proves it).
`configs/issuer.yaml` wires neither, and says so in place — a deployment
that adds `authcode` declares the four discovery URLs beside it. The
`Email` enrollment gate is wired: `/start` submits through wave's SMTP
connector (`smtp` in the issuer graph), and the enrolment code arrives by
mail.

`auth_wire` is DRAFT until its whole surface is promoted.

## Documentation

[docs/overview.md](docs/overview.md) indexes the doc set.

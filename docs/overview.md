# Kagi documentation

Kagi is the enrollment and token authority for the nanocloud trust
domain; the [README](../README.md) is the front door. This page indexes
the doc set.

## Start here

- [guides/running.md](guides/running.md) — the smallest validated
  bring-up: `fluxor run` over the issuer graph, feeding it key material,
  smoke checks, and a device enrollment driven with curl.
- [specification.md](specification.md) — the protocol: challenge
  issuance, PKCE and proof-of-possession, device certificates, DPoP,
  access-token claims, and the deterministic identifier scheme.
- [identity-provisioning.md](identity-provisioning.md) — the identity
  contract the rest of the family builds against: the SPIFFE naming
  scheme, the two carriers (a P-256 mTLS leaf and a cert-bound JWT-SVID),
  and the enrollment tiers.
- [guides/authenticators.md](guides/authenticators.md) — the
  authenticators kagi accepts, how they combine into an assurance level,
  and how a relying party demands a stronger one.

## Architecture

- [architecture/issuer.md](architecture/issuer.md) — the issuer as a
  graph: the listeners, the control channel that carries key material,
  and the stateless design that keeps kagi off the critical path of
  verification.
- [architecture/modules.md](architecture/modules.md) — the portable
  core and the eleven PIC modules built on it, and how a fragment runs
  byte-identically on-target, in wasm, and in the host suites that pin
  it.

## Guides

- [guides/running.md](guides/running.md) — bring-up and smoke checks.
- [guides/authenticators.md](guides/authenticators.md) — factors,
  assurance levels, step-up, and the device set.
- [guides/embedding-token-mint.md](guides/embedding-token-mint.md) —
  consuming `token_mint` from a downstream fluxor graph.
- [clients/sdk-guide.md](clients/sdk-guide.md) — what a client has to
  generate and sign to complete an enrollment.
- [development/identifiers.md](development/identifiers.md) — the
  deterministic tenant and device identifier derivations.
- [development/resource-server-integration.md](development/resource-server-integration.md) —
  validating kagi tokens and DPoP proofs in a resource server.

## Operations

- [operations/rotation-revocation-runbook.md](operations/rotation-revocation-runbook.md) —
  signing-key rotation with overlapping validity, and how device
  revocation behaves at the mint points.
- [analytics/schema.md](analytics/schema.md) — the signed-event schema a
  deployment's analytics feed should follow. A schema, not a feature:
  nothing here emits it.

## Security

- [security/threat-model.md](security/threat-model.md) — assets,
  adversaries, and the mitigations each mechanism provides.
- [security/tls.md](security/tls.md) — transport posture and headers.

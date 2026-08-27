# Kagi documentation

Kagi is the enrolment and token authority for the nanocloud trust domain. It
is a fluxor-native project: a graph of position-independent modules with no
host process in any request path. The [README](../README.md) is the front
door; this page indexes the doc set.

## Start here

- [guides/running.md](guides/running.md) — the smallest validated bring-up:
  `fluxor run` over the issuer graph, feeding it key material, smoke checks,
  and a device enrolment driven with curl.
- [specification.md](specification.md) — the protocol: challenge issuance,
  PKCE and proof-of-possession, device certificates, DPoP, access-token
  claims, and the deterministic identifier scheme.
- [identity-provisioning.md](identity-provisioning.md) — the identity
  contract the rest of the family builds against: the SPIFFE naming scheme,
  the two carriers, and the enrolment tiers.
- [guides/authenticators.md](guides/authenticators.md) — the authenticators
  kagi accepts, how they combine into an assurance level, and how a relying
  party demands a stronger one.

## Architecture

- [architecture/issuer.md](architecture/issuer.md) — the issuer as a graph:
  the listeners, the control plane that distributes key material, the
  modules, and how the whole thing is tested.
- [architecture/modules.md](architecture/modules.md) — the portable core,
  the wire protocol between modules, the key lifecycle, and how a fragment
  runs byte-identically on-target, in wasm, and in the host suites.
- [architecture/messaging.md](architecture/messaging.md) — the E2EE surface:
  device credentials, key packages and their one-time claim, and the endpoint
  state that keeps a ratchet from going backwards.

## Guides

- [guides/running.md](guides/running.md) — bring-up and smoke checks.
- [guides/authenticators.md](guides/authenticators.md) — factors, assurance
  levels, step-up, and the device set.
- [guides/oidc.md](guides/oidc.md) — the authorization-code flow: what
  logs in, the scope clamp, and how a code is bound and consumed.
- [guides/embedding-token-mint.md](guides/embedding-token-mint.md) —
  consuming `token_mint` from a downstream fluxor graph.
- [clients/sdk-guide.md](clients/sdk-guide.md) — what a client has to
  generate and sign to complete an enrolment.
- [development/identifiers.md](development/identifiers.md) — the
  deterministic tenant and device identifier derivations.
- [development/resource-server-integration.md](development/resource-server-integration.md) —
  validating kagi tokens and DPoP proofs in a resource server.

## Operations

- [operations/rotation-revocation-runbook.md](operations/rotation-revocation-runbook.md) —
  the signing-key lifecycle with overlapping validity, and how device
  revocation behaves at the mint gate.
- [analytics/schema.md](analytics/schema.md) — the signed-event schema a
  deployment's analytics feed follows. A schema, not a feature: nothing here
  emits it.

## Security

- [security/threat-model.md](security/threat-model.md) — assets,
  adversaries, and the mitigations each mechanism provides.
- [security/tls.md](security/tls.md) — transport posture and headers.

## Modules

Module documentation is colocated with each module under
[modules/](../modules/). Each `mod.rs` is the authoritative source for its
parameters, channel hints and capability flags, and each `manifest.toml` for
its ports, targets and observability.

# Kagi Threat Model

## Assets

- Issuer signing keys (Ed25519)
- Email challenge flow integrity
- Device certificates and access tokens
- Analytics data pipeline

## Adversaries

1. **Network attacker** intercepting traffic between clients and issuer.
2. **Malicious client** attempting to reuse challenges or impersonate a device.
3. **Compromised queue/analytics consumer** modifying events.
4. **Operational insider** with infrastructure access.

## Attack Surfaces

- HTTPS endpoints (`/start`, `/redeem`, `/token`, JWKS, revocations).
- Message queues for email/analytics.
- Stored secrets (signing keys, analytics HMAC secret).
- Mobile/CLI clients storing device keys locally.

## Mitigations

| Threat | Mitigation |
|--------|------------|
| Network downgrade | Enforce TLS + HSTS, reject plain HTTP, strong cipher suites. |
| Replay of challenges | PKCE + POP signature + short TTL enforced in issuer. |
| Device impersonation | POP signatures tied to device key, deterministic tenant/device IDs. |
| Signing key compromise | Keys stored in AWS KMS/Secrets Manager, rotation documented, JWKS cache held short. |
| Queue tampering | Analytics/email payloads signed with HMAC, consumers verify signatures. |
| Insider misuse | Per-module metrics (each manifest's `[observability]` block) and revocation. A tamper-evident audit log is a design target, not built — see `architecture/issuer.md`. |

## Residual Risks

- Device key material stored on client devices remains subject to local compromise.
- Email-based identity proofing susceptible to inbox takeover; mitigated via short TTL and cancellation UX.

## Next Steps

- Automate threat model review every release.
- Integrate external penetration testing results and update mitigations accordingly.

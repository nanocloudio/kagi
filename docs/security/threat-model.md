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
| Forged or replayed control-plane act (route publish, VIP claim, fence confirm) | Each act is a `KCAC` record signed under its own profile key for an actor authenticated from its host/operator leaf (cert-bound carrier, bound to the mTLS SVID when present, `jti` replay window); bounded to 10 minutes, bound to its declaring payload by digest; the traffic fabric verifies at ingestion and stores the digest as provenance. See `architecture/control-acts.md`. |
| Live TLS secrets moved to an unattested or wrong standby | A transfer grant (`KTGR`) is issued only to the authenticated source host, for a destination leaf naming the destination host whose `ATTEST_KEY` evidence meets the custody policy (possession-bound refused by default); 30 s, single-use by ledger CAS, voided by an unsafe-recovery generation advance; its key is `PROCESS_HW` in production. The primary vault's host wraps only the transfer the grant names field for field (`Record::authorize_wrap`), under a key looked up by the grant's own profile (`Keyset::record_key`). |
| A grant, scope or projection checked under another profile's key | Every record's `(issuer, kid)` is looked up under the one profile it belongs to (`Keyset::record_key`); a key announced for access tokens under the same issuer and kid verifies no grant, and no profile key signs another profile's records. |
| A forged or redirected `service_dns` answer | Kagi signs a projection (`KSDN`) only for the publisher pinned to its service, only for a window of at most an hour with a TTL inside it; the consumer verifies offline and fails closed (`dns_answers`). Staleness against generations already seen is the consumer's check. |
| An actor exceeding its authority over fences, DR, prefixes, chains or failure domains | A scope (`KSCP`) holds one kind, never more operations than the actor's class may hold (a host only its zone's fence, an operator no fence at all, a controller no recovery mark or import), at the levels the kind may sit at, for at most an hour; the ceilings are re-checked at every verify, and a scope covers only its own actor and object. |
| Cross-tenant attachment by wildcard, spoofed tenant or unpinned federation | Publications refuse `*` domains, zero tenants and empty sets; a consumer must authenticate in an accepted domain — this instance's or one pinned by keyset record, never fetched — and name an accepted tenant; quotas bounded by the publication; revocation generation in `kagi/attachments/`. |
| Unauthenticated storage-key control verbs | When the control link is mTLS the audited actor is the verified SVID (`svid:<hex>`), not the caller-written name; the verbs themselves still belong behind control-plane admission. |
| Insider misuse | Per-module metrics (each manifest's `[observability]` block) and revocation. A tamper-evident audit log is a design target, not built — see `architecture/issuer.md`. |

## Residual Risks

- Device key material stored on client devices remains subject to local compromise.
- Email-based identity proofing susceptible to inbox takeover; mitigated via short TTL and cancellation UX.

## Next Steps

- Automate threat model review every release.
- Integrate external penetration testing results and update mitigations accordingly.

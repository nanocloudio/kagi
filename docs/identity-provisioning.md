# Kagi identity provisioning — the enrollment authority for the nanocloud trust domain

Kagi is the **provisioner** and **token issuer** for the nanocloud identity
fabric. It is the writer that sector's PKI contract names as
invisible-but-authoritative, and the onboarding flow that sector's surface
authentication defers to a provisioner: a one-time bootstrap, after which the
provisioner signs a short-lived certificate for the device's key. This doc
freezes kagi's half of that contract so every relying party in the family
(sector, clustor, chronicle) has a concrete, unchanging identity target.

Decision in one line: **kagi mints one SPIFFE identity that resolves through
two carriers** — a P-256 mTLS leaf and a cert-bound JWT-SVID — issued by one
core that runs either **embedded** (a fluxor module inside nanocloud) or
**standalone** (the HTTP issuer, for scale). Relying parties authorise on the
same `svid` / `spiffe_id` regardless of which shape issued it.

## 1. Trust domain (config-driven)

The trust domain is not hard-coded; it is set per deployment and roots every
identity kagi issues:

| Deployment | Trust domain | Enrollment gate (see §5) |
| --- | --- | --- |
| Managed cloud | `nanocloud.io` | `Email` / federated IdP |
| Local / dev | `nanocloud.local` | `Direct` |
| Self-hosted | operator-set, e.g. `id.acme-corp.com` | `BootstrapToken` |

Config key: `identity.trust_domain` (issuer config / module param). A single
kagi instance owns exactly one trust domain; cross-domain trust is a
federation concern, out of scope here.

## 2. SPIFFE naming scheme (the contract)

Every identity is `spiffe://<trust-domain>/<class>/<path>`, with a reserved
first-segment **class** so the three identity kinds can never collide and so
relying parties can write prefix-scoped authorisation policy:

| Class | SPIFFE ID | Issued for | Derivation in kagi |
| --- | --- | --- | --- |
| `device` | `spiffe://<td>/device/<tenant>/<device>` | email-bound device enrollment | `tenant` = `generate_tenant_id` (HKDF over trimmed/lowercased email); `device` = `derive_device_id` (RFC 7638 thumbprint of the device key) |
| `ns` | `spiffe://<td>/ns/<namespace>/sa/<name>` | Kubernetes / workload service accounts (H4) | `identifiers::workload::generate_workload_subject` (domain-separated HKDF); matches the SPIFFE-on-k8s convention and the existing `CN=system:serviceaccount:<ns>:<sa>` DN |
| `svc` | `spiffe://<td>/svc/<service>/<id>` | platform nodes / services | assigned by the provisioner at admission (e.g. `svc/sector/node-abc`) |

`ns` follows the established SPIRE k8s registration path verbatim, so nanocloud
interops with off-the-shelf SPIFFE tooling. `device` and `svc` are reserved
class words; a service may not be named `device`, `ns`, or `svc`.

### SVID — the pinning proof

For **every** carrier the verified identity is:

```
svid      = SHA-256(leaf certificate's raw subjectPublicKey)   // 32 bytes
spiffe_id = the leaf's SAN URI (== the token iss/sub)
```

This is byte-identical to what sector's `tls` module already emits on
`peer_identity`, so kagi-issued identities flow into sector's authz layer with
zero new code on the relying-party side.

## 3. The two carriers (both issued by kagi)

One identity, two ways to present it — mirroring sector's "one identity, two
carriers" exactly, because kagi issues both.

### Carrier A — P-256 mTLS leaf

An X.509 leaf the client drives an mTLS handshake with (native clients, iOS
Secure Enclave, cluster nodes). Hard constraints, set by the fluxor `tls`
module:

- Curve `prime256v1` / secp256r1 (**P-256 only**), signature `ecdsa-with-SHA256`.
- Encoding DER; key PKCS#8 or SEC1 DER.
- `subjectAltName = URI:spiffe://<td>/<class>/<path>` — the SVID SAN.
- CA-signed by the kagi issuing CA; relying parties trust that CA
  (`trust_cert_file` / `ca_pubkey`).

**The issuing CA must be P-256 / ECDSA-SHA256.** fluxor's `tls` module
validates the leaf with `ecdsa_verify(ca_pubkey, tbs_hash, sig)` against the
pinned CA key (`validate_and_extract_peer_cert`), so a leaf signed by an
Ed25519 CA would not chain there. The leaf's *own* subject key may be P-256 or
Ed25519 (the module only requires the raw `subjectPublicKey` be ≤ 65 bytes and
hashes it for the SVID); only the CA signature must be ECDSA. `configs/pki.yaml` deploys this CA.

`certificate_endpoint` issues this leaf. It is the cohesive successor to
today's `dc+jwt` device certificate.

This is **built**: `modules/common/spiffe.rs` names the identity,
`modules/common/der.rs` emits the certificate, and
`modules/app/certificate_endpoint` is the endpoint — `POST
/pki/certificate` takes a subject public key and a SPIFFE identity and
answers with the DER leaf plus its `spiffe_id`. It is its own deployment
(`configs/pki.yaml`), not part of the issuer graph: a CA is a different
key and a different blast radius. The CA certificate is served at `GET
/.well-known/ca.pem`. Enrollment accepts **both**
device key types — Ed25519 (`kty=OKP`) and **P-256** (`kty=EC`, ES256
proof-of-possession and `DPoP`) — so a browser's WebCrypto P-256 key can enroll
and receive a P-256 leaf usable for the browser ES256 / client-driven-mTLS
paths.

### Carrier B — cert-bound JWT-SVID

For clients that hold a key but cannot drive a TLS handshake with it (a plain
browser: WebCrypto can hold a non-extractable P-256 key and sign ES256, but no
Web API binds a WebCrypto key to a `wss` handshake). The client signs a
short-lived JWT with the **leaf key**, carrying the leaf so it *is* the
platform identity, not a side door:

```
header  { "alg":"ES256", "typ":"JWT", "x5c":[<base64 DER leaf>] }
claims  { "iss": "spiffe://<td>/<class>/<path>",   // == the cert SAN
          "sub": "spiffe://<td>/<class>/<path>",
          "aud": "<relying-party audience>",        // rejects reuse elsewhere
          "iat": <now>, "exp": <now+60s>,           // short-lived
          "jti": "<128-bit nonce>" }                // replay guard
signature = ES256 over header.claims with the leaf's private key
```

This is sector's JWT-SVID format verbatim. The token is **client-signed** (the
holder signs with the leaf key it controls) — kagi does **not** mint it; kagi
issues the leaf (Carrier A); the *verifier* a relying party runs is the
direction the modules do not cover, and lives as a conformance
implementation in `tests/harness/src/jwt_svid.rs`: chain the `x5c` leaf to the trusted CA, verify the
`ES256` signature with the leaf key, check `aud`/`exp`/`iat`, require
`iss == sub == leaf SAN`, and derive the same `svid`. This mirrors sector's
`jwt_gate`, so a kagi-issued leaf's JWT-SVID and a kagi verifier agree.

kagi also mints the **issuer-signed** SPIFFE JWT-SVID (the SPIRE workload-API
shape — `jwt_svid::issue_issuer_signed`/`verify_issuer_signed`): a JWT kagi
signs with its own key for a workload (`sub` = SPIFFE id, `aud` = audiences),
verified against kagi's JWKS rather than an `x5c` chain, for workloads that do
not hold a leaf key. Distinct from the client-signed cert-bound token above.

## 4. Deployment shapes — one core, two substrates

The enrollment gate, cert issuance, and token minting are one core. Only the
substrate that carries requests and delivers material differs:

- **Embedded** (fluxor module in nanocloud): the Device-CR controller path. On
  CR admission the module issues the P-256 SPIFFE leaf and **writes** it to the
  stable PKI path `/var/lib/<service>/pki/<id>/{leaf.der,leaf.key.der,ca.der}`
  (the constraint sector's PKI contract sets). Rotation is a file rewrite. Simplicity;
  no HTTP surface.
- **Standalone** (the HTTP issuer): `/start` → `/redeem` → `/token`.
  `/redeem` **returns** the leaf to the client (which stores it), `/token` mints
  JWT-SVIDs. Horizontal scale; the tier for onboarding many untrusted clients.

Both derive identities by the §2 scheme and produce the §3 carriers, so a node
provisioned embedded and a browser onboarded standalone are indistinguishable
to a relying party.

## 5. Enrollment gate — the admission boundary

`/start` (or CR admission) does not "send email." It hands the minted challenge
to a configured **gate** that answers two questions — *authorise* (may this
caller bind this identity?) and *deliver* (get the challenge to the authorised
party). The gate is the trust anchor of the entire enrollment; everything
downstream inherits its assurance from this one step.

| Gate | Tier | Trust anchor | Sector equivalent |
| --- | --- | --- | --- |
| `Direct` | dev (`nanocloud.local`) | single trusted operator; challenge returned in-band | `ensure_dev_pki` / dev-cert enrollment |
| `BootstrapToken` | self-hosted | operator-provisioned join token (kubeadm-style) or existing OIDC/mTLS identity; challenge returned in-band once admitted | provisioner admission |
| `Email` | managed (`nanocloud.io`) | inbox possession (out-of-band delivery), pluggable to a federated IdP | the "existing session / OAuth" tier sector defers |

Self-hosted deliberately does **not** depend on email: its anchor is
provisioner/Device-CR admission, which is stronger than inbox possession for
machine identities and needs no SMTP. Email earns its place only in the managed
tier, onboarding untrusted humans at scale.

## 6. Revocation and credential lifetime

kagi follows the SPIFFE short-TTL doctrine: **short-lived presented credentials
plus revocation at the mint gate — no CRL, no OCSP, no per-certificate
revocation distribution.** Relying parties never check revocation; they trust a
short expiry.

- **Anchor vs. presented.** The device certificate (`dc+jwt`) is the durable
  enrolment *anchor*, presented only to kagi's `/token`, so it is longer-lived
  — 30 days, `CERTIFICATE_TTL_SECS` in `enrollment_endpoint` — and gated by the
  mint-time revocation check rather than by a short expiry. Everything
  presented to a relying party is short-lived: the access token defaults to
  five minutes (`DEFAULT_TTL_SECS` in `token_endpoint`), and the X.509 leaf
  `certificate_endpoint` issues carries its own bound.
- **Rotation, not re-enrolment.** The device refreshes its access token by
  re-calling `/token` with its device certificate and a fresh DPoP proof — no
  repeat of the enrolment challenge.
- **Revocation = the mint gate.** Revoking a device records it in the ledger
  and publishes it in the filter `wellknown_endpoint` serves. Admission reads
  the ledger on every mint, so a revoked device is refused there; the published
  filter is what relying parties fetch. Short TTLs age out whatever the device
  already holds within one window, so a directly-presented leaf a relying party
  cannot revoke simply expires.

The device *key* — not any certificate — is the identity anchor a hostile holder
must be denied; the registry denies it once, at the source.

## 7. What kagi issues

| Piece | Where |
| --- | --- |
| Device certificate | JWT-form `cty=dc+jwt`, `sub=tenant_<id>` — `enrollment_endpoint` |
| X.509 leaf with a SPIFFE SAN | `certificate_endpoint`, under a P-256 CA, with `modules/common/der.rs` emitting the profile |
| Identity naming | `modules/common/spiffe.rs` |
| Access token | `cnf`/DPoP bound — `token_endpoint` → `mint_admission` → `token_mint` |
| Trust domain | `__TRUST_DOMAIN__` in `configs/pki.yaml` |

The CA certificate is served at `GET /.well-known/ca.pem` for relying-party
pinning. Carrier B is client-signed, so kagi's part is the leaf plus P-256
device-key enrolment, leaving the client holding a usable leaf key; the
verifier belongs to the relying party, and `tests/harness/src/jwt_svid.rs` is
the conformance implementation of it.

The writing primitive an embedded provisioner needs — generate a node key,
obtain the leaf, write `leaf.der`/`leaf.key.der`/`ca.der` to a PKI path — is a
client of `certificate_endpoint` rather than something kagi runs. The
Kubernetes Device-CR watch loop that calls it per admission is nanocloud
control-plane work.

## 8. Naming across the family

kagi is the authority that defines the trust domain, so every other project in
the family names identities by the §2 scheme: a sector workload is
`spiffe://nanocloud.local/svc/sector/<id>`, not `spiffe://nanocloud/sector/<id>`.
The SVID is derived from the leaf public key rather than from the SAN string, so
a name that disagrees is a documentation error rather than a verification
failure — which is exactly why the scheme has one definition.

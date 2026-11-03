# Control acts, transfer grants, attachments, DNS projections and scopes

Kagi's half of a traffic fabric's load-balancer RFC (§9.4, §11.10, §11.12,
§12.5.5, §13.6, §15.1, §15.4, §22). Five signed
records and the typed operations that decide them:

| Record | Magic | Profile | Decides | Operation |
|---|---|---|---|---|
| Control act | `KCAC` | `CONTROL_ACT` (8) | an ownership-changing control-plane request | `control_act_mint`, `control_act_verify` |
| Transfer grant | `KTGR` | `TRANSFER_GRANT` (9) | moving one connection's live TLS secrets to one standby | `transfer_grant` |
| Attachment publication / grant | `KATT` | `ATTACHMENT_GRANT` (10) | a private producer/consumer service attachment | `attachment_authorize` |
| Service DNS projection | `KSDN` | `SERVICE_DNS` (11) | the regional answers a resolver may give for a service | `service_dns_sign` |
| Operation scope | `KSCP` | `OPERATION_SCOPE` (12) | one actor's least-privilege authority over traffic-dial, failure-domain, prefix, chain, DR or fence operations | `scope_mint` |

The charter these keep, from `.context/rfc_extensions.md` §7 and
the traffic fabric's reply to its §7.2:

- **Kagi initiates no fetch.** Every key a decision rests on — the issuer
  keysets, the CA that issued an actor's leaf, a federated trust domain's
  CA — arrives as a control-plane keyset record. Everything below verifies
  offline.
- **Kagi is never the state store** for route, fence, ownership or
  attachment acts. A control act travels with the request it authorises and
  is held by whoever ingests that request; the only state Kagi keeps is what
  makes its own decisions single-use or revocable: a transfer grant's
  issued/consumed state and recovery generation (`kagi/transfer-grants/`),
  and an attached service's revocation generation (`kagi/attachments/`).
- **Every record is fixed binary, little-endian, magic-separated**, parsed
  structure-only (trailing bytes refused) and then verified with the
  verifier pinning the key's suite: a record naming another suite than the
  key it claims is refused, never verified under the suite it names. Each
  profile has its own signing key, so no key signs two kinds of record.

The byte layouts are in each fragment's module docs
(`modules/common/control_act.rs`, `transfer_grant.rs`,
`attachment_grant.rs`, `service_dns.rs`, `operation_scope.rs`); the wire of
each operation is in [typed-operations.md](typed-operations.md).
`control_act.rs`, `service_dns.rs` and `operation_scope.rs` mount nothing but
themselves, so a relying party verifies with the one file.

## Who asks: actors

Ownership-changing acts are made by hosts, operators and workloads, so the
SPIFFE naming contract ([identity-provisioning.md](../identity-provisioning.md)
§2) gains two classes: `host/<host_id>` and `operator/<operator_id>`, each a
fixed 16-byte id in 32 lowercase hex digits. `spiffe::parse` reads every
class to `(class, 16-byte id)` — the actor a record names. A host id is the
deployment's boot-incarnation-independent identity for the host.
`certificate_endpoint` issues host and operator leaves when its graph's
`issue_classes` admits them (devices alone by default).

No operation here takes an actor field. A caller presents a **cert-bound
identity carrier** (`cert_bound_identity.rs`): a JWS of at most five minutes
it signed with the leaf key its certificate names, carrying the leaf in
`x5c` and naming the operation's `audience`. `carrier_auth.rs` checks it:

1. the leaf chains to the authority's key — a chain of one, which is the
   only chain `certificate_endpoint` issues (`x509_leaf.rs` reads the leaf;
   the anchor arrives on the module's `ca_key` port as the VERIFY
   `MSG_KEY_ADD` the CA announces);
2. the carrier's signature is the leaf key's, and the leaf's SPIFFE URI is
   the carrier's `iss`;
3. the leaf's name parses to a class and id in the expected trust domain;
4. **over mTLS**, the exchange's `peer` — the client leaf's SVID that wave's
   `http` reports when fluxor's `tls` authenticated it
   (`exchange_peer.rs`) — is the carrier's key: a carrier lifted onto
   another operator's connection is refused;
5. its `jti` has not been seen inside its life.

The same exchange `peer` now reaches `storage_key`, whose control verbs carry
a caller-written `actor` string: when an SVID is present the audit entry
names the actor `svid:<hex>` instead, the switch is counted
(`Stats::authenticated_actor`) and logged once.

## Control acts (`KCAC`) — §15.1, §9.4

RFC §15.1: *every ownership-changing request carries actor, scope,
operation ID, target, expected epoch and signed/auditable provenance.* A
control act is that provenance:

| Field | Meaning |
|---|---|
| act kind | `ROUTE_PUBLISH` 1, `ENDPOINT_DECLARE` 2, `VIP_CLAIM` 3, `FENCE_CONFIRM` 4, `FAILOVER` 5, `EVACUATE` 6, `DIAL` 7, `ATTACHMENT_PUBLISH` 8, `ATTACHMENT_REQUEST` 9 |
| actor class, actor id | from the actor's verified leaf: workload, service, host or operator (a device may not act) |
| scope | tenant id, service id |
| target kind, target id | route generation, VIP, fault domain, host, flow, tunnel, attachment |
| operation id | the request's idempotency id |
| expected epoch | the epoch the act is conditional on |
| issued, expiry | at most `MAX_WINDOW_MS` (10 min); `SKEW_MS` (1 min) of issue-time skew |
| declaration digest | SHA-256 of the declaring payload — the `WHR1` route record, the fence confirmation — so the act cannot be lifted onto another |
| policy digest | the policy the actor was admitted under, for the audit trail |

**Minting.** `control_act_mint` authenticates the actor (above), builds the
act from the request's scope, target, operation id, epoch, window and
digests, and signs it in the vault under the `CONTROL_ACT` key. One `KCAA`
audit entry per decision — minted or refused, with the actor's SVID —
leaves on `audit_out`. Kagi keeps neither.

**Verifying.** `control_act_verify` verifies offline against the
`CONTROL_ACT` keyset (the same `ADD`/`ACTIVATE`/`RETIRE`/`REMOVE` lifecycle
as `token_verify`), checks the window against its trusted clock and, when
the declaring payload is presented, its digest; it answers a typed verdict
`{status, kind, actor, scope, target, operation id, expected epoch, record
digest}`. The traffic fabric may equally link `control_act.rs` and verify in-process:
the fragment injects SHA-256 and the signature check and mounts nothing.

**Provenance digest.** `record_digest` — SHA-256 of the whole record, 32
bytes — is what the traffic fabric's route record stores as `provenance_digest`
(§9.4). It names the act exactly: the record is deterministic for Ed25519,
and `tests/harness/tests/control_act.rs` pins a digest vector so a layout or
signing-input change is visible as a wire change. Per §9.4, a materialised
record that retains the digest is not fresh authority: the traffic fabric verifies the
act at ingestion and keeps its digest thereafter.

What Kagi does not decide: whether the actor may act on that scope —
whether this host is the admitted fence provider for that fault domain,
whether this publisher owns that tenant's route. Those are the traffic fabric's and
Lattice's policies over the authenticated actor, scope and target the act
binds. Kagi's guarantee is that the act names who really asked and for
exactly what.

Graph: [`configs/control-act.yaml`](../../configs/control-act.yaml).

## Transfer grants (`KTGR`) — §12.5.5, §15.4

A paired-anchor standby receives the minimum live TLS continuity secrets of
one connection from the primary's vault (`KEY_WRAP`, destination-bound
`FXKW` blobs). The primary's vault host wraps only against a committed
transfer grant naming the destination host, anchor, service, flow and target
epoch; §15.4 is explicit that the grant authorises that state alone and
never general use of the service key. `transfer_grant` issues one when:

1. **the requester is the source host**: an authenticated `host` actor whose
   id is the grant's `source_host`;
2. **the destination is the destination host, attested**: its leaf chains
   to the authority and names `host/<destination_host>`, and its
   `ATTEST_KEY` (`FXHA`) evidence for the standby's fresh recipient key —
   signed by that leaf's key, over the transfer's own challenge (see below)
   — meets the policy's custody, decided by the storage-key profile's
   `admit_custody`. A possession-bound recipient is refused unless the
   graph sets `allow_possession`; hardware evidence must report at least
   `min_tier` (default `PROCESS_HW`);
3. **the nonce is claimed**: a fresh 16-byte nonce's state is created in
   `kagi/transfer-grants/<flow>-<nonce>` as `ISSUED`, create-if-absent.

The grant carries service, flow, session, source and destination host,
destination anchor, target epoch, traffic epoch, algorithm, use, direction,
the recipient thumbprint, the nonce, the recovery generation, the custody
established, and a policy digest. It is good for at most
`TRANSFER_GRANT_TTL_MS` (30 s).

**Single use.** The source host consumes its grant before its vault wraps:
the grant must verify under this issuer's key, name the caller as source,
carry the current recovery generation and be `ISSUED`; a compare-and-swap
moves it to `CONSUMED`, or to `EXPIRED` past its expiry. A second consume is
`Replayed`.

**Unsafe recovery.** `transfer_grants_invalidate(recovery_generation)` is an
operator's act. It advances the generation in the ledger, and every grant
issued under an earlier one is refused from then on (`Invalidated`) — every
outstanding grant voided at once, without the ledger enumerating them —
forcing the reconnect the RFC requires rather than risking duplicate key or
counter use.

**In the provider's graph: `custody_authority`.** A Fluxor
`TRANSPORT_CONTINUITY` provider asks its authority, before its vault wraps
a flow's continuity key to the standby's attested recipient, on its
`auth_req` port: `0xC4 [flow 16][epoch u32][challenge 32][evidence]`, the
evidence Fluxor's (`[FXHA record 148][recipient 65][signer 65][sig_len]
[sig]`) over the challenge the transfer chose (the traffic fabric's paired anchors
derive it from the flow, the pairing and both anchors). `custody_authority`
is that authority as a module of the provider's graph: the source is the
graph's own host (`host`), the standby hosts it may move a key to are
enrolled by identity key (`dest0`..`dest7`), and
`transfer_grant::decide_custody_check` grants the transfer when the
evidence's signer is an enrolled host other than the source and the
evidence, over the provider's challenge, meets the policy's custody
(`admit_custody`, as above). The grant's nonce is the challenge's, so one
transfer is one grant: its state is written `CONSUMED` (the provider wraps
on the verdict) create-if-absent under the same ledger keys and recovery
generation as `transfer_grant`'s, and the same evidence again is
`Replayed`. Only then is the provider answered `0xC5 [flow][sha256
(evidence)][0]`; any refusal is `0x80 | code`, and a silent ledger refuses
at the stage deadline. The signed `KTGR` leaves on `grant_out` (`0x4B`).
The provider's token checks (`0xC2`, the per-flow emission token) are
relayed whole to Clustor's session directory and its verdicts (`0xC3`)
back, so one module is the provider's whole authority.

Before a transfer is planned, the same module answers `CUSTODY_READY`
(REQUEST 0xA0 / REPLY 0xA1, a typed operation on `request_in` /
`response_out`): per host, whether it is enrolled, the tier its own
evidence last proved here, whether a grant is issuable now (key, clock,
posture, and the ledger answering a read made for the question) and
whether it holds a live host certificate from the CA on `ca_key`
(delivered on `cert_in`). Layout and every field's rule:
[typed-operations.md](typed-operations.md#custody_authority-custody_ready).

The grant key's custody role is `KeyRole::TransferGrant`, issuer-grade:
`PROCESS_HW` in production, refused at construction below it.

**What the vault host checks.** Before it wraps, the primary vault's host
runs `Record::authorize_wrap`: the grant verifies under the
`TRANSFER_GRANT` key, is live, and names exactly the wrap it is asked for —
service, flow, session, traffic epoch and algorithm of the connection; the
source host (itself), destination host, anchor and target epoch; the
recipient key's thumbprint; the use — field for field, with no wildcard
(`NotThisTransfer` otherwise). Direction is the one containment: a `BOTH`
grant covers a wrap of either side's secrets. The check does not consume
the grant; the source host consumes it at Kagi (`op::CONSUME`) before the
wrap, which is what makes it single use.

**The requester is the source host**, not the coordinator that decided the
takeover. The host whose vault holds the secrets is the one that asks for
the authority to move them and consumes it; a coordinator directs the
transfer and never holds a grant.

## Private attachments (`KATT`) — §11.12

The attachment identity is `(producer_tenant, service_id, consumer_tenant,
attachment_id, attachment_generation)`. Kagi authorises the producer's
declaration and the consumer's request; Lattice stores the desired
attachment and Clustor commits its generations. Two records carry Kagi's
decisions so it stores neither:

- **Publication** (`PUBLISH`): the producer tenant and service, direction
  (consumer-to-producer, or a declared bidirectional), source-identity
  disclosure (none, tenant, identity), quota ceilings (connections, bytes/s,
  flows, mirror credits), and the exact consumer tenants and trust domains
  accepted — at most eight of each, a domain named by the SHA-256 of its
  lowercase name. **Wildcards are refused**: a `*` anywhere in a domain, a
  zero tenant, or an empty set is `Wildcard`. A producer must be a workload,
  service or operator of this instance's own domain. The producer hands the
  publication to Lattice beside its declaration.
- **Grant** (`REQUEST`): the consumer presents the publication, the exact
  producer tenant and service, its consumer tenant, the attachment
  generation and the quotas it wants. It must be a workload or operator of
  an accepted domain, its tenant an accepted tenant, each quota nonzero and
  within the ceiling; the grant carries the whole identity, a fresh
  attachment id, the consumer actor and domain, the quotas granted and the
  publication's digest, and never outlives the publication (at most a day).

**Trust-domain acceptance** means tenants of this instance's trust domain,
or of a federated domain **pinned via control-plane keyset records** — a
VERIFY `MSG_KEY_ADD` on `federation_key` whose `issuer` is the domain's
name and whose key is that domain's CA key (`MSG_KEY_REMOVE` unpins it).
This is option 1 of the traffic fabric's reply to §7.2, "pinned": no discovery,
no JWKS retrieval, nothing fetched, rotation a deployment action. A
consumer proves membership by a leaf chaining to that domain's CA and
naming a SPIFFE id in it; a leaf naming the domain from any other CA proves
nothing.

**Revocation.** `attachment_revoke` — the producer side's act — advances the
service's revocation generation in `kagi/attachments/<producer>-<service>`.
Every publication and grant carries the generation it was signed under; a
request under an earlier publication is `Revoked`, and the traffic fabric compares a
grant's generation with the revocation boundary Clustor commits so new
connections stop at the new generation. What happens to existing
connections (drain, reset, migrate; fail closed when undeclared) is
the traffic fabric's policy.

**What the broker checks.** `Record::verify_as(kind::GRANT, …)`: the
record verifies under the `ATTACHMENT_GRANT` key and is a grant. A
publication verifies under the same key and must never stand in for one
(`WrongKind`). A record dated more than `SKEW_MS` (5 s) ahead of the
verifier's clock is refused (`WindowInvalid`), as a transfer grant is.

## Signed `service_dns` projections (`KSDN`) — §11.10, §21 Phase 9

For a service without global anycast, the traffic fabric's region controller
publishes a `service_dns` projection: the regional addresses, health and
weights a DNS front end may answer with, bound to the global and DR
generations it was derived under (`region_ctl.v1` record 0xB6, 224 bytes,
`upstream_core.rs`). Nanocloud's `service_dns` composes answers from it only
under a signature it trusts, and fails closed otherwise. `service_dns_sign`
is that signature:

1. **the publisher is authenticated and pinned**: a `service` or `host`
   identity, from its carrier as above, that a `publisher_N` param pins to
   the projection's service id — a controller signs for its own service and
   no other;
2. **the projection is one a resolver may act on**: the traffic fabric's layout
   exactly (reserved bytes and unused answers zero, families 4 or 6 with a
   canonical v4 address, health healthy or draining, a generation and a
   TTL), its trailing 32 bytes zero, valid for at most `MAX_VALID_MS`
   (one hour) with the TTL ending inside the validity, issued within
   `SKEW_MS` (one minute) of Kagi's clock.

The record carries the 224 bytes **verbatim** after an 8-byte header, then
the signer and signature: there is one encoding of a projection and it is
the producer's, and the consumer hands the bytes `Record::verify` returned to
the traffic fabric's `dns_answers`. Which regions it names is the controller's
decision; staleness against a generation the consumer has already seen is
the consumer's check. Kagi keeps no per-service state.

## Operation scopes (`KSCP`) — §22, §15.1

§22 asks Kagi to authorise imported-prefix, service-chain and
failure-domain operations with least-privilege scopes, and route, fence and
ownership acts without becoming their state store. A scope is one actor's
authority for **one kind** of operation on **one object**:

| Kind | Operations | Levels |
|---|---|---|
| `DIAL` 1 | `START`, `PAUSE`, `RESUME`, `REVERT`, `ABORT` (a service's traffic dial, run by the traffic fabric's `dial_controller`) | cell, region |
| `CHAIN` 3 | `DECLARE`, `REPLACE`, `DRAIN_STAGE`, `FAILOVER_STAGE` | cell, region |
| `PREFIX` 5 | `IMPORT`, `ALLOCATE`, `ADVERTISE`, `WITHDRAW`, `RDNS` | region, global |
| `FAILURE_DOMAIN` 6 | `EVACUATE`, `PRACTICE`, `RESTORE`, `AUTOMATIC`, `ABORT` | cell, region |
| `DR_INTENT` 7 | `FAILOVER`, `DRAIN`, `RESTORE`, `RECOVERY_MARK`, `ADMIT_POLICY` | global |
| `FENCE` 8 | `CONFIRM` (a zone's or host's) or `REGIONAL_CONFIRM`, never both | cell or region; global |

The **class ceiling** is the most a member of a class may ever hold,
whatever policy says, and is checked at mint and again at every verify:

| Class | May hold |
|---|---|
| operator | every dial operation; evacuate, practice, restore and abort intents; every prefix operation; every chain operation; every DR intent; **no fence** — confirmation comes only from the admitted fence provider |
| service (a controller) | every dial operation (a scheduled one); automatic evacuation on evidence and abort; allocate, advertise, withdraw and reverse DNS inside admitted space (never an import); every chain operation; DR failover and drain (never a recovery mark, restore or policy); both fence confirmations, as a fence provider |
| host | its own zone's fence confirmation, nothing else |
| workload | declaring and replacing its own tenant's chains, nothing else |
| device | nothing |

The record's object, level, region, cell, data locality and recovery
generation are exactly the fields of the traffic fabric's `ScopedGrant`
(`scope_core.rs`) and its kind uses that file's `scoped_kind` numbers, so a
verified scope becomes a `ScopedGrant` field for field and goes through
`scope_admit` like every other portfolio object: a region removed by DR, or
an unsafe-recovery mark, voids it at once. A relying party runs
`Record::authorize` — verify, then `Scope::authorizes`: the same kind,
every operation asked among the scope's, the presenting actor the scope's
actor, the same tenant, service and object. A scope is not a bearer token.

Which actor holds which scope for which object is the deployment's policy
(Lattice), named in the scope by digest as a control act names its policy.
The recovery generation is the requester's statement, checked by the traffic fabric
against the global manifest. A scope stands at most `MAX_WINDOW_MS` (one
hour); a controller re-mints.

## Relying parties: keys by profile

Every record names its signer `(issuer, kid)`. A relying party that holds
keys for several profiles — a vault host that also verifies access tokens,
a broker beside its control-act verifier — looks the signer up with
`verify_keyset::Keyset::record_key(issuer, profile, kid, now)`, confined to
the profile the record belongs to. `Keyset::select` reads a JOSE
`(iss, kid)` across profiles and would check a `KTGR` under the issuer's
token key sharing its kid; the profile is the whole of what separates a
grant from a token.

## What is not here

- **Fence-provider admission, prefix allow-lists, route-leak limits**
  (§15.1, §15.5) are the traffic fabric's policy over the authenticated act, not
  Kagi's. A scope bounds what a class may ever hold; which provider is
  admitted for which fault domain is still the deployment's.
- **Prefix ownership evidence.** Whether a tenant holds an imported prefix
  is a fact about resource certificates and registries — RPKI relying-party
  validation, Nanocloud's — not about Kagi's identities. Kagi authorises
  *who may import* (`PREFIX`/`IMPORT`, an operator's alone); it does not
  vouch for ownership, and does not issue the traffic fabric's `OwnershipEvidence`.
- **Continuity-secret custody** is Fluxor's vault: Kagi never sees a TLS
  secret, and a grant is the only thing it adds to a wrap.
- **The attachment directory** — which attachments exist, their accounting
  — is Lattice's and Clustor's.

## Deviations from the brief, and why

- **The actor is never an mTLS-only SVID.** A bare SVID is a key hash: it
  names no class and no id without a directory mapping key hashes to
  identities, which would make Kagi the store it must not be. The actor is
  established from the leaf (carrier), and the SVID, when the link has one,
  must match it.
- **Evidence is bound to the transfer, not to a Kagi-issued challenge.** A
  standby arming for a target epoch creates a fresh recipient handle for
  it, so a challenge round trip would add a stateful step for no freshness
  the transfer's own context (`attestation_challenge`) does not already
  give: evidence is good for exactly one transfer of one connection to one
  epoch.
- **Invalidation is a generation, not an enumeration.** The ledger has no
  listing; advancing a generation voids every outstanding grant with one
  write and is checked on every consume.
- **A consumer's tenant is asserted, then bound.** Kagi cannot prove a
  workload belongs to a tenant without a directory it does not hold; the
  grant binds the asserted consumer tenant to the authenticated actor and
  domain, and the producer's accepted-tenant list bounds what may be
  asserted.

# Storage-key grants and attachment bundles

Kagi decides who may reconstruct an encrypted volume's key; it never holds
the key. A volume key lives only behind Fluxor `KEY_VAULT` handles: it is
split 2-of-3 in the provisioning vault (`SHARE_SPLIT`), each share sealed to
one recovery custodian; a custodian releases its share only by resealing it
inside its own vault (`SHARE_REWRAP`); the attaching node reconstructs it
directly into a handle (`SHARE_COMBINE`). What Kagi issues is the signed
decision each of those steps rests on.

| Piece | Where |
| --- | --- |
| Records, proofs, envelope checks, vault argument blocks | `modules/common/storage_key.rs` |
| The service state machine (sans-IO) | `modules/common/storage_key_service.rs` |
| The service module | `modules/app/storage_key` |
| A recovery custodian | `modules/app/storage_custodian` |
| The network edge, routing and module | `modules/common/storage_key_endpoint.rs`, `modules/app/storage_key_endpoint` |
| Tests | `tests/harness/tests/storage_key.rs`, `storage_key_renew.rs`, `storage_key_erase.rs` |

## The record

One signed layout for every decision, `KSKG`. All integers little-endian.

| Off | Len | Field |
| --- | --- | --- |
| 0 | 4 | magic `KSKG` |
| 4 | 1 | kind: 1 grant, 2 attachment release, 3 recovery release, 4 recovery set, 5 creation, 6 recovery ticket, 7 renewal, 8 erasure |
| 5 | 1 | resource kind: 1 volume, 2 Clustor partition, 3 snapshot |
| 6 | 1 | envelope purpose: 1 attachment, 2 recovery custody |
| 7 | 1 | custody: 0 possession-bound, 1 hardware-bound (required on a grant, proven on a release) |
| 8 | 1 | minimum vault tier |
| 9 | 1 | proven vault tier, `0xFF` when no evidence was admitted |
| 10 | 1 | minimum enrolment assurance (NIST AAL 1–3, 0 = none) |
| 11 | 1 | flags: bit 0 revoked, bit 1 ticket consumed |
| 12 | 2 | KEM suite |
| 14 | 2 | AEAD suite |
| 16 | 4 | key epoch |
| 20 | 4 | grant generation |
| 24 | 4 | handle lifetime, seconds (maximum on a grant, granted on a release) |
| 28 | 4 | retained epochs: on a grant, how many earlier epochs it still admits; 0 on every other kind |
| 32 | 8 | lease fence token |
| 40 | 8 | issued at, Unix ms |
| 48 | 8 | expiry, Unix ms (on a release: the envelopes' expiry; on a renewal: the attachment's) |
| 56 | 8 | revoked at, Unix ms |
| 64 | 16 | protected resource id |
| 80 | 16 | grant id (a ticket's own id on a ticket) |
| 96 | 16 | recovery set id |
| 112 | 16 | anti-replay id of the request decided |
| 128 | 32 | policy digest |
| 160 | 32 | recipient thumbprint: SHA-256 of the fresh `FXRK` public key |
| 192 | 32 | request nonce: the challenge this issuer issued |
| 224 | | `issuer f8`, `tenant f8`, `device f8`, `count u8`, `count × item f16`, `signature suite u16`, `signature f16` |

The signature covers every byte before the signature field. Items: on a
grant none, or one listing its retained epochs (`u32` each, ascending, below
the current epoch, as many as offset 28 says); none on a ticket or an
erasure; the three custodians' public keys on a creation; the three custody
envelopes on a recovery set; none on a release on its way to the
custodians, and the two attachment envelopes once they are back; on a
renewal the attachment id (16) and the digest of the record renewed (32),
never an envelope. Signing suites are Ed25519 and ES256 under the
`STORAGE_GRANT` key profile.

The policy digest is
`SHA-256("KSKG policy" ‖ issuer f8 ‖ tenant f8 ‖ resource kind ‖ resource ‖ grant id ‖ set id ‖ epoch)`:
stable across grant rotation, new with every key epoch.

## The attach proof

A node proves one attach with its enrolled device key over

```text
"KSKP" ‖ record kind ‖ resource kind ‖ resource(16) ‖ epoch ‖ fence(8)
‖ lifetime(4) ‖ request expiry ms(8) ‖ anti-replay id(16) ‖ challenge(32)
‖ ticket(16) ‖ "FXRK" ‖ recipient public(65) ‖ device f8 ‖ issuer f8
```

Ed25519 signs it whole; ES256 signs its SHA-256. For a hardware-bound grant
the request also carries `ATTEST_KEY` evidence for the recipient key over
the same challenge, signed by the device key: a PKCS#11 backend at or above
the grant's tier, P-256, uses exactly `AGREE | EXPORT_PUBLIC`, not
persisted. Kernel-backend evidence proves a tier but never hardware custody.

## Operations

The `storage_key` module is a PROVIDER of the workspace exchange contract on
`request_in` / `response_out`: a request body is one
`storage_key_service::msg::REQUEST` envelope, `[0x80][len u16 LE]` then
`[op u8][resource kind u8][resource 16][body]`, and its answer body one
`msg::REPLY` envelope; the exchange id is the correlation, so neither carries
one of its own. The exchange rules — `POST`, response credit, statuses — are
those of every typed operation
([typed-operations.md](typed-operations.md)).

| op | Body after the head | Record replied |
| --- | --- | --- |
| 1 challenge | `device f8` | none; `extra` = challenge(32) ‖ expiry ms(8) |
| 2 create | `tenant f8`, policy, `aead u16`, three custodian public keys, actor | creation (epoch 1) |
| 3 record set | `epoch u32`, three envelopes `f16`, actor | recovery set |
| 4 grant | `device f8`, policy, actor | grant |
| 5 attach | see `write_attach_body` | release + `FXSB` bundle |
| 6 revoke | actor | grant |
| 7 replace device | `old f8`, `new f8`, actor | grant |
| 8 rotate grant | `device f8`, policy, actor | grant |
| 9 rotate key | three custodian public keys, actor | creation (next epoch) |
| 10 retire epoch | `epoch u32` (a retained epoch), actor | grant |
| 11 authorise recovery | `epoch u32`, `device f8`, `ttl secs u32`, actor | ticket |
| 12 recover | as attach, naming the ticket | release + `FXSB` bundle |
| 13 renew attachment | as attach, `ticket` = attachment id, then the record renewed `f16` | renewal |
| 14 erase | `epoch u32` (the current epoch the pin scan covered), `pins u32`, actor | erasure |

Policy is `[custody u8][min tier u8][min assurance u8][lifetime secs u32]`,
and the AEAD a creation names is ChaCha20-Poly1305 or AES-256-GCM.

Op 2 claims the resource: it writes the resource's grant create-if-absent —
epoch 1, generation 1, no device yet — so a second creation of the same id
stops there, and it replies with the creation authorisation a provisioning
vault runs `SHARE_SPLIT` under. Op 4 is what names the device.

The reply payload is `[op u8][status u8][refusal u8][audited u8][record f16]
[bundle f16][extra f16]`; refusal codes are `storage_key::Refusal`, and a
refusal is still a 200 exchange.

A release is decided in full — grant, directory record, ticket, recovery
set, proof and evidence — before its anti-replay id is claimed; then two
custodians are ordered to rewrap, the third standing in for one that
refuses; then the record is signed over both envelopes and audited, and only
then answered. The bundle is `"FXSB"`, count 2, three zero bytes, then the
lower-index envelope and the higher, 528 bytes.

## The network edge

`storage_key_endpoint` serves `POST /storage-key`: the body is one
`REQUEST` payload (`[op u8][resource kind u8][resource 16][body]`, no
envelope) and the response is the `REPLY` payload. Only the four operations
that carry their own proof are admitted there — challenge, attach, recover,
renew. The control verbs are refused 403: they authenticate nothing at the
service, so they belong on an edge inside the control plane's own graph.

Behind wave's `http` the endpoint is a provider; toward the service it is a
requester, opening one exchange of its own per admitted request on
`service_out` / `service_in`. The service's `response_out` fans out to every
requester wired to it, and each answer names the exchange its requester
opened — a requester's ids carry its own request port, so two never collide —
so the endpoint answers only the exchanges it opened, to the HTTP stream that
asked. A status the service raised itself (503 busy, 413 too large) reaches
the node verbatim. Sixteen requests are in flight at once, and one unanswered
for `timeout_ms` — 30 seconds by default — is answered 504 and its slot
released.

## Renewal

An attachment holds for its `lifetime` from the release decision. Before it
ends, the node renews it: a fresh challenge, then op 13 carrying the attach
fields under kind 7 (renewal) — the same epoch, fence and `FXRK` recipient
announcement, the requested lifetime, a fresh anti-replay id, the
attachment id in `ticket` — the device's proof over them, and the record
being renewed: the release itself the first time, the latest renewal after.
The attachment id is the release's anti-replay id.

Decided in order, every refusal audited:

| Check | Refusal |
| --- | --- |
| challenge issued here, to this device and volume, unexpired, unspent | 7 challenge unknown |
| record is a completed release or a renewal signed by this issuer, for this resource and attachment id | 26 bad signature, 28 unknown attachment |
| grant is this resource's and the attachment's, not revoked | 2 unknown resource, 3 grant revoked |
| attachment not expired; request inside its window | 30 attachment expired, 8 request expired |
| device active, in tenant, key the directory bound, assurance; the device the grant and the attachment name | 5, 27, 6, 4 |
| recipient thumbprint is the attachment's | 11 wrong recipient |
| lease fence is the attachment's (a changed fence is a new writer: detach and attach again) | 29 fence changed, 23 fence invalid |
| epoch is the attachment's and still admitted | 10 wrong epoch |
| lifetime within the grant's and one week | 12 lifetime exceeded |
| proof by the device key | 6 bad proof |
| custody evidence over this challenge, as the grant requires now (hardware-bound: again) | 13, 14, 15 |
| record is the chain head in `NS_STORAGE_ATTACHMENT` | 19 conflict |
| anti-replay id claimed once | 9 replayed |

On success the renewal record (kind 7) copies the attachment's resource,
epoch, fence, recipient, set, policy and suites; states the custody just
proven, the grant's current floors and generation, the lifetime granted,
issued at now and expiry = now + lifetime; and carries the renewal's own
anti-replay id and challenge. It advances the chain head, is audited, and is
returned with no bundle. No custodian is asked and no key material moves: the
node keeps the handle it reconstructed at attach.

## Retained epochs

A data-key rotation (op 9) moves the grant to the next epoch and adds the one
it left to the grant's retained epochs. Every retained epoch stays admitted
for attach, renewal and recovery until op 10 retires it by name; the current
epoch is never retired, and the service never retires one on its own —
which epoch a retained snapshot or clone still needs is the control plane's
knowledge. Retiring an epoch deletes its recovery set.

| Refusal | When |
| --- | --- |
| 25 rotation in progress | the current epoch's recovery set is not yet recorded (op 3) |
| 33 retained epochs full | the grant already retains `MAX_RETAINED_EPOCHS` (8) epochs |
| 10 wrong epoch | op 10 names the current epoch, a retired one, or one never issued |

A recovery set (op 3) is recorded only for an epoch the grant admits.

## Erasure

Op 14 erases a resource's key custody, for secure deletion. This service
cannot see snapshots or clones, so the pin check is the caller's: the
request states the current epoch its scan covered and how many pins it
found. What the service decides on is its own records:

| Check | Refusal |
| --- | --- |
| a grant or erasure is held for the resource | 2 unknown resource |
| the scan found no pin | 32 epoch pinned |
| the scan covered the grant's current epoch (no rotation since) | 10 wrong epoch |

Then, in order:

1. The erasure record (kind 8) replaces the grant by compare-and-swap: revoked,
   no device, no retained epochs, the last epoch in `epoch`, the next
   generation. From this write on, every operation on the resource is refused
   31 erased, and a creation of the same id conflicts: ids are not reused.
2. Every recovery set from epoch 1 through the one after the last is deleted,
   catching a set whose retirement did not land and a creation from a
   rotation that raced the erasure.
3. All three custodians are sent `ERASE_ORDER`, `[corr][custodian][erasure f16]`,
   and each must confirm (`ERASE_RESULT`, the rewrap result's layout with no
   envelope); a refusal or silence answers 16 custodian refused.
4. Audited, and answered with the erasure record.

A retry after any partial run finds the erasure record, keeps it, and runs
steps 2–4 again; a retry after a complete one does the same and answers the
same record. Every attempt, refused or allowed, is audited, the actor named.

A custodian admits an erase order only when `storage_key::admit_erase` holds:
signed under its pinned storage-grant verification key, kind erasure, no
items. It then refuses every later rewrap of a custody envelope for that
resource (`storage_key::refuse_erased`, refusal 31), even one the issuer
signed. A custodian's recovery key serves every resource, so there is no
per-resource key for it to destroy; the custody envelopes are the ledger's
set records, which step 2 deletes.

## State

| Ledger namespace | Key | Holds |
| --- | --- | --- |
| `NS_STORAGE_GRANT` (9) | resource | the grant, or once erased the erasure |
| `NS_STORAGE_SET` (10) | resource, epoch | the creation, then the recovery set |
| `NS_STORAGE_TICKET` (11) | resource, ticket | a recovery ticket |
| `NS_STORAGE_AUDIT` (12) | resource, time, id | one `KSKA` entry per decision |
| `NS_STORAGE_ATTACHMENT` (13) | resource, attachment id | the latest renewal, expiring with it |
| `NS_REPLAY` (6) | `sk-` anti-replay id | release and renewal anti-replay claims |

Every record read back is verified against the issuer key before it is
used. Challenges are held in the service's memory and spent by first use.

## Custodians

Orders fan out on `custodian_out` as
`[corr][custodian u8][release f16][recipient f8][custody envelope f16]`.
A custodian answers only its own index, and releases only when
`storage_key::admit_order` holds: signed under the storage-grant
verification key it was given, a release with no items, unexpired, naming
this recipient, over this custodian's own custody envelope for the same set,
resource, epoch and AEAD, not a release it already made, and not of a
resource it was ordered to erase (see Erasure).

The verification key reaches the custodians from the service itself: once
the signing key named on `signing_key` is open, `storage_key` announces its
public half on `key_announce` as a VERIFY `MSG_KEY_ADD`, wired to every
custodian's `verify_key`. Nothing else can: a vault label is the opening
module's own, so only the service reads its key's public half.

## Limits

- One live grant per resource; its device policy names one device.
- A grant retains at most `storage_key::MAX_RETAINED_EPOCHS` = 8 earlier
  epochs; the ninth rotation waits for a retirement.
- Erasure rests on the caller's pin assertion; the record and audit entry
  are its trace, not a check this service can make.
- Erasure cannot reach what it cannot list: recovery tickets and renewal
  chain heads stay in the ledger until they expire, refused because their
  grant is gone. Copies of deleted sets outside the ledger (backups,
  replicas) are not reached either; the custodians' refusal is what covers
  them.
- A custodian's erased list is in memory, 64 resources, oldest forgotten
  first, and a restart forgets it; it keys by the 16-byte resource id alone,
  as the envelope header names no resource kind.
- Records carry no key id: rotating the storage-grant signing key needs the
  held grants, sets and tickets re-signed before the new key is used.
- A renewal proves the device by its name and the key the directory binds
  now; the release does not record which key signed the attach.
- Revoking a grant stops renewal; granting the same device again re-admits
  renewal of its attachments that have not yet expired.
- A renewal whose audit entry cannot be written is withheld after the chain
  head has advanced: the node's next renewal is refused as superseded, and
  it attaches again.
- `crypt_block` does not emit `ATTEST_KEY` evidence, so a node running it
  today attaches only under a possession-bound grant.
- No graph in `configs/` wires these three modules. What is proven is the
  decisions: the suites above drive the service state machine and the
  custodians' order admission against modelled vaults and a modelled ledger.
  Standing the service up — the ports above, a vault label per custodian,
  and `key_announce` reaching every `verify_key` — is a deployment's own
  wiring.

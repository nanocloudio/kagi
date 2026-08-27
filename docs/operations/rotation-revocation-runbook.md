# Signing-key rotation and device revocation

How to roll the issuer's signing key without invalidating credentials
already in flight, and how device revocation behaves.

Source: `modules/app/token_mint`, `modules/app/wellknown_endpoint`,
`modules/app/mint_admission`, `modules/common/auth_wire.rs`.

## 0. The control channel

Both operations are messages on the graph's control chain — the mutually
authenticated WebSocket on `__WS_PORT__` → `remote_channel` → the module
that needs them. There is no config file to edit and no process to restart.

| message | channel | reaches |
| --- | --- | --- |
| the key lifecycle | ch0 | `token_mint` |
| the key lifecycle | ch1 | `wellknown_endpoint`, `resource_gate`, `mint_admission`, `keypackage_endpoint` |
| the key lifecycle | ch2 | `enrollment_endpoint`, `e2ee_credential_endpoint` |
| `MSG_REVOKE` | ch3 | `wellknown_endpoint` |

A signing record names a vault label. The private half is generated inside
the vault, never travels this socket, and the public half comes back out of
the signer on its own `key_announce` edge — so distributing a key and
compromising one are different operations.

Deliveries are not persisted, and that is the point: a graph restarted
without its key material mints nothing and admits nothing, rather than
falling back to something stale.

## 1. Signing keys

A keyset is indexed by `(issuer, profile_id, kid)` and holds more than one
live entry, because a rotation needs two keys at once. Four verbs are the
whole lifecycle, and the order is the procedure.

`wellknown_endpoint` publishes up to four keys at once: the key being
retired, the one replacing it, and room for a third while a third-party
cache catches up. Four is room for a rotation and no room for a leak — a
module accumulating every key it had ever seen would keep publishing one
whose private half is gone.

### Before you start

Note the longest lifetime any credential in circulation has. The retiring
key must stay published until the longest of those has elapsed; read the
TTLs from the module params in your rendered graph.

### Add

`MSG_KEY_ADD` with the incoming key's record, on every channel that must
know it. The key is loaded and does not sign. Confirm both `kid`s are in the
published set before going further:

```
curl -s https://issuer.example/.well-known/jwks.json | jq '.keys | map(.kid)'
```

Adding and activating are separate steps because every verifier must hold a
key before anything signs with it. Skip the gap and the first credential
minted under the new key is unverifiable everywhere that has not caught up.

### Activate

`MSG_KEY_ACTIVATE` naming the same `(issuer, profile_id, kid)`. New
credentials carry the new `kid`; there is exactly one active key per
`(issuer, profile)`. Credentials signed by the outgoing key still verify,
because it is still in the set.

### Retire

`MSG_KEY_RETIRE` with a `remove_after_unix` past the longest credential
lifetime noted above. The key stops signing and keeps verifying. A retired
key stays in the published set: dropping it would make every credential
still inside its own validity window unverifiable to a relying party that
refetches.

### Remove

`MSG_KEY_REMOVE`, once the deadline has passed. It unpublishes the key and
credentials signed under it stop verifying. This is also the compromise
path, where that is the intended effect — immediate and unconditional.

### Rollback

Before the outgoing key is removed, `MSG_KEY_ACTIVATE` naming it again.
Both public halves are published throughout, so credentials minted at any
point during the rotation continue to verify and a rollback costs one
message.

## 2. Device revocation

Send `MSG_REVOKE` with the device identifier on ch3.

`wellknown_endpoint` writes the revocation to the ledger first and publishes
it second. The ledger is the authority: admission reads the device record on
every mint, so a revoked device is refused at the next mint rather than at
the next token expiry. The published document is the projection relying
parties fetch. Publishing second means the two cannot disagree in the
dangerous direction — a revocation the document claims but the mint has
never seen. When the ledger cannot be reached the bits are still set, because
dropping a revocation is the unsafe direction, and the divergence is counted
as `revocation_uncommitted` rather than hidden.

The published filter is a Bloom filter at
`/.well-known/revocations.json`, its shape fixed in the module rather than
configured, because the document's shape is what clients parse:

| field | value |
| --- | --- |
| `bitmap_bits` | 16 384 (2 KiB) |
| `hash_functions` | 3 |
| `capacity` | 1 000, at roughly a 1% false-positive rate |

The bitmap is bounded by what one response can carry: the document must fit
a single `HttpResponse` envelope, since a larger body needs `MORE_BODY`
chunking and a document arriving in pieces needs a resumption story for the
client fetching it. A document fetched on every cold start should be small.

The snapshot also carries `bitmap`, `salt`, `inserted` and `updated_at`. The
salt is why one deployment's document says nothing about another's.

Two consequences of the filter's shape:

- **It is append-only.** An entry cannot be withdrawn. The published filter
  is rebuilt from what the graph is given, so correcting a mistaken
  revocation means correcting the ledger record and replaying a corrected
  feed.
- **False positives are possible**, at roughly one in a hundred at capacity
  and climbing past it. Watch `inserted` against `capacity`; the module also
  counts `revocation_saturated`. Past capacity a revocation is still
  recorded, because dropping one would be the unsafe direction.

### Checking a publication

```
curl -s -H 'Cache-Control: no-cache' \
  https://issuer.example/.well-known/revocations.json | jq
```

`inserted` should have grown by one and `updated_at` should be close to the
current time.

## 3. What to watch

- `inserted` against `capacity`, and `revocation_saturated`.
- `revocation_uncommitted`, which is non-zero exactly when the published
  document claims a revocation the ledger did not take.
- `wellknown_endpoint`'s published `kid` set, which is the ground truth for
  what a relying party will accept.
- `resource_gate`'s `gate_no_key`, non-zero exactly when the gate has been
  given nothing to verify against.
- Probes against `/healthz`, `/.well-known/jwks.json` and
  `/.well-known/revocations.json`.

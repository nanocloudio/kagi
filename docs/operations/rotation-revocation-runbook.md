# Signing-key rotation and device revocation

How to roll the issuer's signing key without invalidating tokens already
in flight, and how device revocation behaves.

Source: `modules/app/token_mint`, `modules/app/wellknown_endpoint`,
`modules/common/auth_wire.rs`.

## 0. The control channel

Both operations are messages on the graph's control chain — the
websocket on `__WS_PORT__` → `ws_stream` → `remote_channel` → the module
that needs them. There is no config file to edit and no process to
restart: a module's key material is whatever was last delivered to it.

| message | channel | reaches |
| --- | --- | --- |
| `MSG_MINT_KEY` | ch0 | `token_mint` — the private seed |
| `MSG_VERIFY_KEY` | ch1 | `wellknown_endpoint`, `resource_gate` — the public half |
| `MSG_MINT_KEY` | ch2 | `enrollment_endpoint`, `e2ee_credential_endpoint` |
| `MSG_REVOKE` | ch3 | `wellknown_endpoint` |

That a delivery is not persisted is the point: a graph restarted without
its key material mints nothing and admits nothing, rather than falling
back to something stale.

## 1. Signing keys

`wellknown_endpoint` publishes up to **four** keys at once. A set exists
to carry a rotation — the key being retired, the one replacing it, and
briefly a third while a third-party cache catches up. Four is room for
that and no room for a leak: a module that accumulated every key it had
ever seen would keep publishing one whose private half was destroyed.

Only `token_mint` signs, and it holds one seed: the last `MSG_MINT_KEY`
it received. So the overlap that makes rotation a non-event lives
entirely in the published set.

### Before you start

Note the longest lifetime any credential in circulation has. The
retiring key must stay published until the longest of those has elapsed
— read the TTLs from the module params in your rendered graph.

### Stage

Deliver the incoming key's **public half only**, on ch1. Both keys now
appear in the set; the original still signs.

```
curl -s https://issuer.example/.well-known/jwks.json | jq '.keys | map(.kid)'
```

Both `kid`s must be present before going further. Mint a token and read
its header `kid` to confirm the original key is still the one signing.

### Promote

Deliver the incoming key's seed on ch0. `token_mint` replaces its seed
and new tokens carry the new `kid`. Tokens signed by the outgoing key
still validate, because its public half is still in the set.

### Retire

Once the longest credential lifetime noted above has elapsed, restart
the graph and deliver only the current key. The set is rebuilt from what
it is given, so a key not delivered is a key not published.

### Rollback

Deliver the previous seed on ch0. Because both public halves stay
published throughout, tokens minted at any point during the rotation
continue to validate, so a rollback costs one message.

## 2. Device revocation

`wellknown_endpoint` holds a Bloom filter published at
`/.well-known/revocations.json`. Its shape is fixed in the module rather
than configured, because the document's shape is what clients parse and
a deployment that could change it would change the document under them:

| field | value |
| --- | --- |
| `bitmap_bits` | 16 384 (2 KiB) |
| `hash_functions` | 3 |
| `capacity` | 1 000, at roughly a 1% false-positive rate |

The bitmap is bounded by what one response can carry: the document must
fit a single `HttpResponse` envelope, since a larger body needs
`MORE_BODY` chunking and a document that arrives in pieces needs a
resumption story for the client that fetches it. That bound is not a
limitation to work around — a document a client fetches on every cold
start should be small.

The snapshot also carries `bitmap`, `salt`, `inserted` and `updated_at`.
The salt is why one deployment's document says nothing about another's.

Two consequences of the filter's shape are worth stating outright:

- **It is append-only.** An entry cannot be withdrawn. Revoking the
  wrong device is corrected by restarting the graph and replaying a
  corrected feed, not by removing the entry.
- **False positives are possible**, at roughly one in a hundred at
  capacity, climbing as the filter fills past it. Watch `inserted`
  against `capacity`; the module also counts `revocation_saturated`.
  Past capacity a revocation is still recorded, because dropping one
  would be the unsafe direction.

### Revoking a device

Send `MSG_REVOKE` with the device identifier on ch3.

The filter is in memory, so restarting the graph clears it. Any
deployment relying on revocation must replay its revocation feed before
the graph takes traffic.

### Checking a publication

```
curl -s -H 'Cache-Control: no-cache' \
  https://issuer.example/.well-known/revocations.json | jq
```

`inserted` should have grown by one and `updated_at` should be close to
the current time.

### Who checks it

Nothing in the graph does. The document is published for relying
parties, and a revoked device keeps working until its current access
token expires — which is why access tokens are short: their lifetime is
the revocation delay.

## 3. What to watch

- `inserted` against `capacity`, and the `revocation_saturated` metric.
- `wellknown_endpoint`'s published `kid` set, which is the ground truth
  for what a relying party will accept.
- `resource_gate`'s `gate_no_key`, which is non-zero exactly when the
  gate has been given nothing to verify against.
- Probes against `/healthz`, `/.well-known/jwks.json` and
  `/.well-known/revocations.json`.

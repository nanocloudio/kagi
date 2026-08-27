# The OIDC authorization-code flow

`modules/app/authcode` runs the two halves of the authorization-code flow:
`/authorize` issues a single-use code, and the token code-exchange redeems it
for an access token and an ID token. `configs/e2e-authcode.yaml` is the graph
that drives it, and `tests/harness/tests/authcode_e2e.rs` exercises it end to
end.

## What logs in

Kagi authenticates devices and workloads, not passwords. The subject who
"logs in" at `/authorize` is the device presenting its `dc+jwt` certificate
and a DPoP proof. The subject is established inside kagi from that
certificate and is never named by the caller — a request that named its own
subject would be a request choosing who it is.

## /authorize

The client sends its `client_id`, `redirect_uri`, requested `scope`, `state`,
a PKCE `code_challenge` and an optional `nonce`, alongside the subject's
certificate and proof. The endpoint:

1. Authenticates the subject from the certificate, refusing a replayed proof
   as a replay rather than as a bad credential.
2. Requires PKCE. S256 only, and a challenge of the right length — `plain` is
   a downgrade a client can force, and a code with no challenge is a code
   with no client binding.
3. Reads the client from the registry. An unregistered `client_id` is
   refused.
4. Verifies `redirect_uri` against the registered one byte for byte. No
   wildcards, no normalisation — this is the open-redirect guard.
5. **Clamps the requested scope to the client's registered scope.**
   `token_mint` signs scope verbatim, so the clamp is here or nowhere.
6. Mints a single-use code, bound to the subject, the device, the key
   thumbprint, the client, the redirect URI, the challenge, the nonce, the
   clamped scope and the authentication time.

The reply carries the code, the kagi-approved `redirect_uri` — so the
pipeline builds its redirect from a kagi verdict rather than from the
client's raw input — and the `state` to echo. A refusal carries none of the
three.

Every value the code record will carry from the client is refused unless it
can be a JSON string value unescaped. The record is read back with a scanner
that returns the first match anywhere in the bytes, so a value carrying a
quote could place a claim of its own ahead of the real one and win the read.

## The exchange

The client presents the code, the PKCE verifier, its `client_id` and the
redirect URI. No subject credential: the code plus the verifier are the
proof, and the code carries the subject `/authorize` established.

1. Read the code. Unknown, expired, or already redeemed is an invalid grant.
2. Check `client_id` and `redirect_uri` against the code's binding — the
   confused-deputy guard.
3. Check PKCE: `base64url(SHA256(verifier))` against the stored challenge.
4. Read the device record and refuse a revoked device. A valid code is not a
   licence to mint for a device the ledger no longer stands behind.
5. Consume the code, conditionally on the revision read in step 1. A second
   exchange loses the race and gets an invalid grant.
6. Mint the access token, bound to the thumbprint stored in the code, so the
   DPoP sender-constraint survives the code.
7. Mint the ID token: audience the client, with `nonce` and `auth_time` where
   the code carried them, and no `cnf` — an ID token is not
   sender-constrained.

Verification before consumption, in that order: a code consumed by a request
that then fails a check is a code the legitimate holder can no longer use.

## Keys

The two tokens are signed under different profiles —
`suite::profile::ACCESS_TOKEN` and `suite::profile::ID_TOKEN` — so
`token_mint` selects a different key for each from its keyset. A profile says
what a credential is for and therefore which key domain may sign it, which is
what stops an ID token and an access token sharing a key because they happen
to use the same algorithm.

## The client registry

Registered clients live in the ledger under `NS_OAUTH_CLIENT`, holding the
allowed `redirect_uri` and the registered `scope`; codes live under
`NS_OAUTH_CODE` with a bounded TTL. Both namespaces require a linearized
read and a replicated-durable fence: a stale read here is a security answer,
not a performance trade.

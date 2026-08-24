# Resource server integration

A resource server must validate access tokens and DPoP proofs before
fulfilling a request. There are two ways to do it: put `resource_gate` in
front of your surface, or implement the checks yourself against the
issuer's JWKS. Both enforce the same contract.

## Validation requirements

Every protected handler must reject a request unless **all** of the
following hold:

1. The access token's signature verifies against the issuer JWKS, `iss`
   and `aud` match your API, and the token is inside its `exp` window.
2. A matching DPoP proof accompanies the request: `Authorization: DPoP
   <access_token>` plus a `DPoP` header carrying the signed proof.
3. The proof's JWK thumbprint equals the token's `cnf.jkt` — that is the
   binding, and a token presented without it is a bearer token.
4. The proof's `htm`/`htu` match the method and the absolute request URI,
   and its `iat` is recent.
5. The proof's `jti` has not been seen for at least five minutes.

## `resource_gate`

`resource_gate` is those five checks as a module. It sits behind wave's
`foundation/http` as an application: an `HttpRequest` arrives on
`request_in` and exactly one `HttpResponse` goes back on `response_out`.
Each check is decided by the fragment that owns it — `jose` for the
signature and window, `dpop` for the proof, `jwk` for the thumbprint —
so the gate and the issuer cannot drift apart.

Wire it behind its own listener (`gate_http` in `configs/issuer.yaml`)
and deliver the issuer's public key on `verify_key`, in the same
`MSG_VERIFY_KEY` shape `token_verify` takes. **Until a key arrives every
request is refused**: a gate that admitted while it had nothing to verify
against would be a gate in name only.

Two params tune the floor:

| param | meaning |
|---|---|
| `min_acr` | the minimum assurance as its `acr` word (e.g. `aal2`) |
| `max_auth_age` | seconds since `auth_time`; `0` means no limit |

A request that falls short of `min_acr` is answered `401` with an RFC
9470 `WWW-Authenticate` challenge naming the level required, so a client
knows to step up rather than to give up. See
[../guides/authenticators.md](../guides/authenticators.md).

The gate emits `gate_admitted`, `gate_no_key`, `gate_bad_token`,
`gate_bad_proof`, `gate_not_bound` and `gate_assurance`, so a refusal is
attributable to which check refused it.

## Doing it yourself

Any language with a JOSE library can implement the same five checks. The
sketch below is Node with `jose`; the structure is what matters, not the
language.

```js
import { createLocalJWKSet, jwtVerify, calculateJwkThumbprint } from 'jose';

const jwks = createLocalJWKSet(await (await fetch(`${ISSUER}/.well-known/jwks.json`)).json());
const seen = new Map(); // jti -> expiry; use a shared store across replicas

export async function requireAuth(req, res, next) {
  try {
    const token = req.headers.authorization?.replace(/^DPoP\s+/i, '');
    const proof = req.headers.dpop;
    if (!token || !proof) throw new Error('token and proof are both required');

    // 1. the access token
    const { payload } = await jwtVerify(token, jwks, {
      issuer: ISSUER,
      audience: AUDIENCE,
    });

    // 2-4. the proof, verified under its own embedded key
    const header = JSON.parse(Buffer.from(proof.split('.')[0], 'base64url'));
    const { payload: dpop } = await jwtVerify(proof, await importJWK(header.jwk));
    const htu = `${BASE_URI}${req.originalUrl.split('?')[0]}`;
    if (dpop.htm !== req.method || dpop.htu !== htu) throw new Error('proof is for another request');
    if (Math.abs(Date.now() / 1000 - dpop.iat) > 300) throw new Error('proof is stale');
    if (await calculateJwkThumbprint(header.jwk) !== payload.cnf?.jkt) {
      return res.status(403).json({ error: 'not_bound' });
    }

    // 5. replay
    if (seen.has(dpop.jti)) throw new Error('proof replayed');
    seen.set(dpop.jti, Date.now() + 300_000);

    req.auth = payload;
    return next();
  } catch (err) {
    res.status(401).json({ error: 'unauthorised', detail: err.message });
  }
}
```

Two things this sketch gets right that are easy to get wrong:

- **`htu` is the absolute URI without the query**, rebuilt from your own
  origin rather than from a `Host` header a caller controls.
- **A thumbprint mismatch is `403`, not `401`.** The token was valid; it
  was presented by the wrong holder, and retrying with fresh credentials
  will not help.

The replay cache above is per-process. Behind more than one replica it
must be shared, or a proof replayed against a different replica is
accepted.

## Assurance

`acr`, `amr` and `auth_time` travel in every access token, so a single
route can demand more than the surface's floor: read them off the
validated claims and answer `401` with an RFC 9470 challenge when they
fall short. The ladder is described in
[../guides/authenticators.md](../guides/authenticators.md).

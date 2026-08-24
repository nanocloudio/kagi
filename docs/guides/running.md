# Running the issuer graph

The smallest bring-up that issues a real credential: `fluxor run` over
`configs/issuer.yaml`, with no mail infrastructure needed.

> **This is a wiring reference, not a deployment.** The header of
> `configs/issuer.yaml` lists what it does not enforce — no admission
> gate on `/token`, no mail gate on enrollment, challenges not consumed
> on redemption, and a control WebSocket carrying signing keys with
> neither TLS nor authentication. Read it before deriving anything
> production-shaped from this page.

## 1. Build

```
make -C ../fluxor install     # once, to get the fluxor CLI
fluxor sync                   # materialise the lockfile-pinned SDK
make build
```

`make build` produces the `.fmod` artefacts under `target/fluxor/` for
the targets `fluxor.toml`'s `[ci] targets` names. There is no host binary
to build: every request path is a module.

## 2. Render the graph

`configs/issuer.yaml` is a template. Substitute a port for each
`__*_PORT__` placeholder, and the deployment's identity and seed:

```
mkdir -p /tmp/issuer/secrets && cd /tmp/issuer
sed -e 's/__WS_PORT__/9700/'          -e 's/__TOKEN_PORT__/8081/' \
    -e 's/__ENROL_PORT__/8082/'       -e 's/__GATE_PORT__/8083/' \
    -e 's/__E2EE_PORT__/8084/'        -e 's/__KEYPKG_PORT__/8085/' \
    -e 's/__STATE_PORT__/8086/'       -e 's/__WELLKNOWN_PORT__/8080/' \
    -e 's|__ISSUER__|http://localhost:8080|' \
    -e 's/__TENANT_SEED__/dev-tenant-seed/' \
    -e 's/__CA_PEM__/none/' \
    "$KAGI/configs/issuer.yaml" > issuer.yaml
```

`__TENANT_SEED__` is the HKDF input behind every tenant identifier;
changing it later changes every tenant id the deployment has ever
issued. `__ISSUER__` is what minted tokens claim as `iss`, so a
placeholder left in place would produce tokens claiming to come from
`__ISSUER__`.

`fluxor run` finds the project by walking up for `fluxor.toml` and reads
artefacts through `fluxor.lock`, so give the rendered graph a root of its
own — copy both files next to it and symlink `target`. `secret_store`
persists to `secrets/store.bin` under the runtime's CWD, and the FS
provider creates files, not directories, so `secrets/` must exist first
(the `mkdir -p` above).

## 3. Run

```
fluxor run issuer.yaml
```

The log reports each listener as it binds. Eight ports come up; the
graph is ready when all of them accept.

## 4. Feed it key material

Nothing mints until a key arrives. Keys travel over the control
WebSocket on `__WS_PORT__` at `/ws`, framed as
`[mux magic][channel][len u16 LE]` around one `auth_wire` envelope
(`[msg_type u8][len u16 LE][payload]`), inside one binary WebSocket
frame:

| channel | message | payload | reaches |
| --- | --- | --- | --- |
| 0 | `MSG_MINT_KEY` `0x22` | `[alg u8][kid f8][seed 32]` | `token_mint` |
| 1 | `MSG_VERIFY_KEY` `0x41` | `[alg u8][kid f8][pubkey f8]` | `wellknown_endpoint`, `resource_gate` |
| 2 | `MSG_MINT_KEY` `0x22` | as ch0 | `enrollment_endpoint`, `e2ee_credential_endpoint` |
| 3 | `MSG_REVOKE` `0x51` | `[id f8]` | `wellknown_endpoint` |

`tests/harness/tests/support/mod.rs`'s `WsClient` is a working client
for exactly this, and `issuer_e2e.rs`'s `distribute_keys` is the
smallest complete example.

## 5. Smoke checks

Liveness — a static route on `http` itself, so it answers before any key
is delivered:

```
curl -s http://localhost:8080/healthz
ok
```

The published key set, which is empty until step 4 and then carries what
was delivered. `kid` is whatever the `MSG_VERIFY_KEY` frame named:

```
curl -s http://localhost:8080/.well-known/jwks.json
{"keys":[{"alg":"EdDSA","crv":"Ed25519","kid":"…","kty":"OKP","x":"…"}]}
```

The revocation snapshot answers 200 with an empty filter on a fresh
graph:

```
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/.well-known/revocations.json
200
```

`/.well-known/ca.pem` serves whatever `__CA_PEM__` rendered to. X.509
issuance is not in this graph at all: it is `configs/pki.yaml`, a
separate deployment with its own key — see
[../identity-provisioning.md](../identity-provisioning.md).

## 6. Enroll a device

A client generates a device key and a PKCE verifier, then calls
`/start`. The challenge comes back in the response:

```
openssl genpkey -algorithm ed25519 -out device.pem
DEV_X=$(openssl pkey -in device.pem -pubout -outform DER | tail -c 32 | basenc --base64url | tr -d '=')
VERIFIER="dev-code-verifier-0123456789abcdef"
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | basenc --base64url | tr -d '=')

curl -s -X POST http://localhost:8082/start \
  -H 'content-type: application/json' \
  -d "{\"email\":\"dev@example.com\",
       \"device_pubkey\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"$DEV_X\"},
       \"code_challenge\":\"$CHALLENGE\"}"
```

The response carries the signed challenge:

```json
{"challenge_token":"eyJhbGciOiJFZERTQSIsImN0eSI6ImNoYWxsZW5nZStqd3QiLC…","expires_at":1787408071}
```

`/redeem` then takes that token, the PKCE verifier, and a
proof-of-possession signature from the device key, and returns the
device certificate. `/token` (port 8081) exchanges the certificate plus
a DPoP proof for an access token. Both steps need the client to sign, so
they are driven from a client rather than from a shell;
[../clients/sdk-guide.md](../clients/sdk-guide.md) describes what a
client has to produce, and [../specification.md](../specification.md)
gives the exact signing inputs. `tests/harness/tests/issuer_e2e.rs`
performs the whole flow end to end.

## 7. Stop

Ctrl-C. `fluxor run` spawns `fluxor-linux` as a child, so a script
stopping it should signal the process group rather than the `fluxor run`
process alone — otherwise the runtime survives and keeps the ports.

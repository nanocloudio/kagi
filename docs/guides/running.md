# Running the issuer graph

The smallest bring-up that issues a real credential: `fluxor run` over
`configs/issuer.yaml`.

> **A wiring reference, not a deployment.** The header of
> `configs/issuer.yaml` says what a deployment must decide for itself —
> operator-certificate lifetimes, the durability tier of a replicated
> deployment, and key custody on a host with no device-unique sealing key.
> Read it before deriving anything production-shaped from this page.

## 1. Build

```
make -C ../fluxor install     # once, to get the fluxor CLI
fluxor sync                   # materialise the lockfile-pinned SDK
make build
```

`make build` produces the `.fmod` artefacts under `target/fluxor/` for the
targets `fluxor.toml`'s `[ci] targets` names. There is no host binary: every
request path is a module.

## 2. Render the graph

`configs/issuer.yaml` is a template. Substitute a port for each `__*_PORT__`
placeholder, the deployment's identity, and the control-plane material:

```
mkdir -p /tmp/issuer/secrets && cd /tmp/issuer
sed -e 's/__WS_PORT__/9700/'          -e 's/__TOKEN_PORT__/8081/' \
    -e 's/__ENROL_PORT__/8082/'       -e 's/__GATE_PORT__/8083/' \
    -e 's/__E2EE_PORT__/8084/'        -e 's/__WELLKNOWN_PORT__/8080/' \
    -e 's|__ISSUER__|http://localhost:8080|' \
    -e 's/__TENANT_SEED__/dev-tenant-seed/' \
    -e 's/__CA_PEM__/none/' \
    "$KAGI/configs/issuer.yaml" > issuer.yaml
```

The control listener also needs `__CONTROL_CERT__`, `__CONTROL_KEY__`,
`__CONTROL_TRUST__` and `__CONTROL_SVID__` — the issuer's own certificate
and key, the trust anchor operator certificates are checked against, and the
allowlisted operator identity. The enrolment mail path needs
`__SMTP_ENDPOINT__`, `__MAIL_FROM__` and `__MAIL_HELO__`.

`__TENANT_SEED__` is the HKDF input behind every tenant identifier; changing
it later changes every tenant id the deployment has ever issued. `__ISSUER__`
is what minted tokens claim as `iss`, so a placeholder left in place produces
tokens claiming to come from `__ISSUER__`.

`fluxor run` finds the project by walking up for `fluxor.toml` and reads
artefacts through `fluxor.lock`, so give the rendered graph a root of its
own — copy both files next to it and symlink `target`. `secret_store`
persists to `secrets/store.bin` under the runtime's CWD, and the FS provider
creates files rather than directories, so `secrets/` must exist first.

## 3. Run

```
fluxor run issuer.yaml
```

The log reports each listener as it binds. Six ports come up; the graph is
ready when all of them accept.

## 4. Feed it key material

Nothing mints until a key arrives. Records travel over the control
WebSocket on `__WS_PORT__` at `/ws`, framed as
`[mux magic][channel][len u16 LE]` around one `auth_wire` envelope
(`[msg_type u8][len u16 LE][payload]`), inside one binary WebSocket frame.
The socket is mutually authenticated: the client presents a certificate
under `__CONTROL_TRUST__` whose key hash matches `__CONTROL_SVID__`, or the
upgrade is refused with a 403.

| channel | message | reaches |
| --- | --- | --- |
| 0 | `MSG_KEY_ADD` `0x22` | `token_mint` |
| 1 | `MSG_KEY_ADD` `0x22` (VERIFY records) | `wellknown_endpoint`, `resource_gate`, `mint_admission`, `keypackage_endpoint` |
| 2 | `MSG_KEY_ADD` `0x22` | `enrollment_endpoint`, `e2ee_credential_endpoint` |
| 3 | `MSG_REVOKE` `0x51` | `wellknown_endpoint` |
| 3 | `MSG_ENROL_AUTH_REQ` `0x53` | `enrollment_endpoint` |

A signing record on channel 0 or 2 names a vault label and carries no key
material: the private half is generated inside the vault and the public half
comes back out of the signer on its own `key_announce` edge, which is how
every verifier in the graph comes to hold it. A verification record on
channel 1 carries a public key, which was never secret.

`tests/harness/tests/support/mod.rs`'s `WsClient` is a working client for
exactly this, and `issuer_e2e.rs`'s `distribute_keys` is the smallest
complete example.

## 5. Smoke checks

Liveness — a static route on `http` itself, so it answers before any key is
delivered:

```
curl -s http://localhost:8080/healthz
ok
```

The published key set, which carries what was delivered in step 4:

```
curl -s http://localhost:8080/.well-known/jwks.json
{"keys":[{"alg":"EdDSA","crv":"Ed25519","kid":"…","kty":"OKP","x":"…"}]}
```

The revocation snapshot, a Bloom filter with its own salt and parameters so
a relying party can test membership from the document alone:

```
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/.well-known/revocations.json
200
```

`/.well-known/ca.pem` serves whatever `__CA_PEM__` rendered to. X.509
issuance is not in this graph: it is `configs/pki.yaml`, a separate
deployment with its own key — see
[../identity-provisioning.md](../identity-provisioning.md).

## 6. Enroll a device

A client generates a device key and a PKCE verifier, then calls `/start`:

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

`/redeem` then takes that token, the PKCE verifier, a proof-of-possession
signature from the device key, and the code that was delivered out of band,
and returns the device certificate. `/token` on 8081 exchanges the
certificate plus a DPoP proof for an access token. Both steps need the client
to sign, so they are driven from a client rather than from a shell:
[../clients/sdk-guide.md](../clients/sdk-guide.md) describes what a client
has to produce, [../specification.md](../specification.md) gives the exact
signing inputs, and `tests/harness/tests/issuer_e2e.rs` performs the whole
flow end to end.

## 7. Stop

Ctrl-C. `fluxor run` spawns `fluxor-linux` as a child, so a script stopping
it should signal the process group rather than the `fluxor run` process
alone — otherwise the runtime survives and keeps the ports.

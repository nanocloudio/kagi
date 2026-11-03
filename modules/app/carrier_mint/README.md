# carrier_mint

The holder's half of a certificate-bound identity carrier
(`modules/common/cert_bound_identity.rs` is the relying party's). A graph that
must authenticate to a Kagi relying party which cannot see its TLS identity —
the traffic fabric's `dns_sign_relay` calling `service_dns_sign`, for one — presents a
carrier: an ES256 compact JWS signed with its leaf's own key, the leaf in
`x5c`, naming that relying party for at most five minutes. This module mints
them from a key born in its own vault and keeps the consumer stocked.

## Ports

| Port | Dir | Index | Frame | Wire to |
|---|---|---|---|---|
| `identity_cert` | in | 0 | `[0x5C][len u16 LE][leaf DER ‖ issuer DER ‖ …]` | the enrolment path's answer |
| `carrier_out` | out | 0 | `[len u16 LE][compact JWS]`, ≤ 4608 bytes | the requester (`dns_sign_relay.carrier_in`) |
| `identity_req` | out | 1 | `[0x5B][len u16 LE = 65][SEC1 point]` | the enrolment path |

All three are required; construction is refused without a key vault.

## Params

| Tag | Name | Type | Default | Meaning |
|---|---|---|---|---|
| 1 | `identity_label` | str | — | the vault label of this module's P-256 key (≤ 64 bytes), opened or generated (`OPEN_OR_GENERATE`, `SIGN \| EXPORT_PUBLIC \| PERSIST`) |
| 2 | `audience` | str | — | the relying party's `audience` (`kagi:service-dns` for `service_dns_sign`); printable, no `"` or `\`, ≤ 128 |
| 3 | `lifetime_s` | u32 | 60 | `exp − iat`, 1..=300 (the verifier's bound); never past the leaf's notAfter |
| 4 | `period_ms` | u32 | 15000 | between carriers, 1000..=300000 |
| 5 | `spiffe` | str | — | optional: the one SAN a taken leaf must name |

## Behaviour

**Key.** Vault keys are namespaced by module type and owner-only, so the
minter cannot sign with `tls`'s key; it holds its own under
`identity_label`. Two instances with one label conflict (`-EBUSY`). A vault
whose store is not readable yet (`EAGAIN`) is retried every 100 ms and
nothing is generated in the meantime.

**Certificate.** The key's public point goes out on `identity_req` every
second until a chain is taken, and again once two thirds of the taken leaf's
lifetime have passed (monotonic, as Fluxor's `tls`). A chain is taken only
when its leaf is a P-256 leaf certifying this key, with a `spiffe://` URI SAN
of at most 96 bytes (and equal to `spiffe` when set); anything else is
dropped and counted. The issuer certificates in the frame are not kept: the
relying party checks the leaf against its own anchor.

**Carrier.** `{"alg":"ES256","typ":"JWT","x5c":[leaf]}` and
`{"iss":SAN,"sub":SAN,"aud":audience,"iat","exp","jti"}` (`jti` 16 CSPRNG
bytes, base64url), signed in the vault: `SIGN` in DIGEST mode over SHA-256 of
`b64url(header).b64url(claims)`, the 64-byte low-S `r‖s` the third segment.
`x5c` carries the leaf only — Kagi's verifier validates a chain of one.

**Supply.** One carrier as soon as a chain is taken, then one every
`period_ms`. A carrier the port will not take is retried until half its life
is gone, then dropped and replaced. With `dns_sign_relay` (holds four, drops
each after `carrier_ttl_ms`): `carrier_ttl_ms` ≤ `lifetime_s` × 1000 and
`period_ms` ≤ `carrier_ttl_ms` / 4. No demand input: the relay has no demand
output, and the bounded period keeps it stocked.

**Time.** Minted only under a trusted wall clock (`dev_trusted_unix`,
`time_policy::Decision::CredentialWindow`) and inside the leaf's window;
otherwise nothing is minted and, outside the window, a renewal is asked for
at once.

Metrics: `minted`, `chains_taken`, `chains_refused`, `no_clock`,
`outside_window`, `stale`, `sign_failed`.

## Wiring it for a traffic fabric

```yaml
- name: controller_carriers
  type: carrier_mint
  identity_label: "fabric/region-controller/identity"
  audience: "kagi:service-dns"         # = service_dns_sign's audience
  lifetime_s: 60
  period_ms: 15000
# carrier_mint.carrier_out   → dns_sign_relay.carrier_in   (carrier_ttl_ms ≤ 60000)
# carrier_mint.identity_req  → the cell's enrolment path (the CA that certifies hosts)
# enrolment path             → carrier_mint.identity_cert
```

and on Kagi's `service_dns_sign`, pin the leaf's identity to the service:
`publisher_N: "host:<host id 32 hex>:<service 32 hex>"` for a leaf named
`spiffe://<td>/host/<host id>`, or `service:<id>:<service>` for a
`spiffe://<td>/svc/…` leaf, `<id>` the first 16 bytes of SHA-256 of the whole
name. The certifying CA's key goes to `service_dns_sign.ca_key`.

Proven by `tests/harness/tests/carrier_mint.rs` (fragment against the real
verifier fragments and `service_dns::decide_sign`) and
`tests/harness/tests/carrier_mint_e2e.rs` (`configs/e2e-carrier-mint.yaml`:
certified over the seam, signed for by the real `service_dns_sign`).

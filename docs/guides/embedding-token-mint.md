# Embedding token_mint in another pipeline

`token_mint` is a stateless fluxor module that signs JWTs on demand. Any
fluxor-native project (e.g. a chronicle egress-proxy pipeline) can pull it
from the local OCI store and wire it into a graph — no kagi source needed.

This is the concrete realization of kagi's purpose: mint short-lived,
device-/key-bound tokens at the edge, right where a pipeline needs outbound
credentials, using the exact same module the issuer graph runs.

## 1. Publish kagi (once, from the kagi repo)

```sh
cd kagi
make build         # build the PIC modules
fluxor publish     # publishes kagi-common + the secret_store/token_mint fmods
```

This lands in the local OCI store as digest-addressed, epoch-annotated
artefacts:
- `kagi/src/kagi-common:<ver>` — the `modules/common` source tree (the no_std wire/crypto fragments)
- `<target>/token_mint:<ver>` and `<target>/secret_store:<ver>` — the module artefacts

## 2. Depend on kagi (in the consumer project)

```toml
# consumer fluxor.toml
[dependencies]
fluxor = "0.0.1"
kagi   = "0.0.1"
```

```sh
fluxor sync        # pins token_mint/secret_store by digest in fluxor.lock and
                   # materialises the .fmods under target/fluxor/<target>/modules/
                   # (`fluxor update` later advances the pins to a new kagi publish)
```

The consumer's module code can mount the staged common source directly, for
example `#[path = "../../../target/fluxor/kagi-common/auth_wire.rs"]`. This
keeps the wire helpers pinned to the same digest as the resolved fmods and
avoids a separate Cargo dependency.

## 3. Wire it into a graph

`token_mint` has three ports (see `docs/architecture/modules.md` for the
full wire protocol):

| port | dir | carries |
|---|---|---|
| `mint_requests` | in | `MINT_REQ` = `[corr u32][alg u8][iss f8][sub f8][aud f8][scope f8][jkt 43B][ttl u32]` |
| `key_material` | in | `MINT_KEY` = `[alg u8][kid f8][key 32B]` (ES256 P-256 scalar / Ed25519 seed) |
| `tokens` | out | `MINT_RESP` = `[corr u32][status u8][token f16]` |

Egress-proxy shape: the pipeline stage that needs an outbound credential
sends a `MINT_REQ` to `mint_requests`; the deployment's key source (a key
manager module, or kagi's `secret_store`) feeds `key_material`; the stage
treats each `MINT_RESP` with `status == ST_OK` as a bearer token for the
egress leg.

```yaml
# consumer graph excerpt
modules:
  - name: keysrc          # secret_store, a key_manager, or a params-seeded source
  - name: token_mint
  - name: egress          # the pipeline stage needing credentials

wiring:
  - from: keysrc.replies
    to:   token_mint.key_material
  - from: egress.mint_out
    to:   token_mint.mint_requests
  - from: token_mint.tokens
    to:   egress.token_in
```

## 4. Signing algorithms

Both are deterministic (no runtime entropy):
- `MINT_ALG_ES256` (1) — P-256 ECDSA (RFC 6979).
- `MINT_ALG_ED25519` (2) — Ed25519 (RFC 8032).

The `alg` in `MINT_REQ` must match the loaded key's algorithm, else the
module replies `ST_NO_KEY` (the right key may still arrive on
`key_material`). Tokens are byte-identical to what the issuer graph mints
for the same claims — verify them against the issuer's JWKS, with
`token_verify`, or with `resource_gate` if the receiving surface wants the
DPoP binding checked too.

## Note on workspace mode

If kagi's checkout is listed in the workspace file
(`~/.fluxor/workspace.toml`), `fluxor sync` resolves kagi's artefacts to
`:latest` — the most recently published digest — and writes that digest
through the consumer's `fluxor.lock`. Publish stays explicit: edits to
kagi's modules reach consumers only after `fluxor publish` in kagi, and
sync warns per artefact whose inputs changed since the last publish.
Outside the workspace, consumers stay on their pinned digests and adopt a
new kagi publish with `fluxor update`.

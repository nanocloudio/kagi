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
| `mint_requests` | in | `MSG_MINT_REQ` — a `MintRequest`: correlation, suite, profile, `kid`, TTL, the claims, and an optional `jkt` |
| `key_material` | in | `MSG_KEY_ADD` — a `KeyRecord`, whose `key_ref` is a **vault label** for a signing key |
| `tokens` | out | `MSG_MINT_RESP` = `[corr u32][status u8][token f16]` |

`modules/common/auth_wire.rs` is the encoder and the only definition of
either layout; a consumer builds them through it rather than by hand.

A signing record carries a label and never key material. The private half
is generated inside the vault on first open, leaves it only as signatures,
and cannot be supplied or observed on the control plane — so a consumer
graph feeding `key_material` is asking that a key EXIST under a name, not
handing one over.

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

## 4. Signing suites

The `suite` in a `MintRequest` names what the credential is signed with;
`modules/common/suite.rs` is the registry, and
`docs/architecture/issuer.md` lists what this build implements. Every one
of them is deterministic and needs no runtime entropy: RFC 6979 ECDSA, RFC
8032 EdDSA, and FIPS 204 ML-DSA in its deterministic variant.

The suite must match the loaded key's, else the module replies `ST_NO_KEY`
(the right key may still arrive on `key_material`). A suite this build
cannot sign in is refused when the key is loaded rather than at the first
request. Tokens are byte-identical to what the issuer graph mints
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

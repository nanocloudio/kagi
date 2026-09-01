# Running the kagi conformance corpus in a consumer repo

The corpus is DATA — `conformance_vectors.rs`, shipped inside the
`kagi-common` source artifact — and a consumer runs it from its own CI so
drift fails where it starts. This is the runner recipe; ~20 lines of
consumer code, no new dependency.

## 1. Depend and sync

```toml
# fluxor.toml
[dependencies]
kagi = "0.0.1"
```

`fluxor sync` materialises the pinned tree at
`target/fluxor/kagi-common/`, `conformance_vectors.rs` included. The pin
in `fluxor.lock` is what makes C16's "same fluxor pin" meaningful: the
corpus version is recorded next to every other artifact's.

## 2. Mount the corpus

In the consumer's host test crate:

```rust
#[path = "../../target/fluxor/kagi-common/conformance_vectors.rs"]
mod vectors;
```

(or `include!` it flat — the file deliberately carries no inner
attributes.)

## 3. Answer the classes you implement

Each vector names an input, a `Verdict` (`Accept`/`Refuse`) and a reason.
The consumer maps each vector id it can answer onto ITS OWN
implementation and asserts the verdict. A class the consumer cannot yet
satisfy is declared by not mounting it — visible in the suite, rather
than quietly implemented differently:

```rust
#[test]
fn negative_class() {
    for v in vectors::VECTORS.iter().filter(|v| v.class == vectors::Class::Negative) {
        let got = my_verifier_under_test(v);   // the consumer's half
        assert_eq!(got, v.verdict, "{}: {}", v.id, v.reason);
    }
}
```

## 4. Gate it

```toml
# fluxor.toml
[ci.test]
scripts = ["tools/ci-conformance.sh"]
```

where the script is one line of `cargo test --test conformance` in the
consumer's harness. `fluxor ci` then fails the consumer the moment its
reading of a kagi protocol drifts from the corpus. Without that, a
consumer's divergence surfaces only when someone reads two
implementations side by side, which is to say long after it shipped.

## Why this file exists

A shared corpus has two halves and kagi owns one of them. It cannot wire
sector's or nanocloud's CI from here; what it can do is make the corpus
genuinely published — it lives in `modules/common/`, the tree
`fluxor publish` builds `kagi-common` from — and make the consumer's cost
a copy-paste. This README is that second part.

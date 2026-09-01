#!/usr/bin/env bash
# Documentation-coherence gate.
#
# A sweep without a gate is a one-time fix of the class it claims to be
# gating. Each check below ties a PROSE claim to a machine-checkable fact
# about the tree, so the claim fails the moment the tree moves without the
# prose. The class is claims a reader cannot check by reading: which
# surfaces a graph wires, and which artefacts a claim of proof rests on.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0

# ── README: the authorization-code surface is built but unwired ────────
if grep -q "deliberately unwired" README.md; then
  if grep -q "name: authcode" configs/issuer.yaml; then
    echo "docs-coherence: README says authcode is unwired in issuer.yaml," >&2
    echo "  but issuer.yaml wires it. Update README's Status section." >&2
    fail=1
  fi
  [ -f configs/e2e-authcode.yaml ] || {
    echo "docs-coherence: README claims authcode is BUILT (proved by" >&2
    echo "  e2e-authcode.yaml) but the proving config is gone." >&2
    fail=1
  }
fi

# ── README: the Email gate is wired ────────────────────────────────────
if grep -q "The \`Email\` enrollment gate is wired" README.md; then
  grep -q "name: smtp" configs/issuer.yaml || {
    echo "docs-coherence: README says the Email gate is wired, but" >&2
    echo "  issuer.yaml carries no smtp node." >&2
    fail=1
  }
fi

# ── The state document cannot contradict itself ────────────────────────
# A progress table and a priority order in one document are two readings
# of the same facts, and a reader who stops at the first gets a different
# system from one who reads on. Gate: no "| Unfixed |" row may survive in
# a document whose priority order declares a "**Closed.**" section.
#
# `.context/` is untracked, so this covers a working copy and is skipped
# in a fresh clone. That is the right scope: the document it gates is
# untracked too.
CS=.context/current_state.md
if [ -f "$CS" ] && grep -q '^\*\*Closed\.\*\*' "$CS"; then
  if grep -q '| Unfixed |' "$CS"; then
    echo "docs-coherence: $CS carries '| Unfixed |' progress rows while its" >&2
    echo "  priority order declares items Closed. Re-derive the table" >&2
    echo "  (it is dated by construction; that is a reason to re-derive" >&2
    echo "  it, not to leave it)." >&2
    fail=1
  fi
fi

# ── The corpus really ships ────────────────────────────────────────────
# "Published as part of kagi-common" is true only while the vectors live
# in modules/common/ — the one tree `fluxor publish` builds the source
# artifact from.
[ -f modules/common/conformance_vectors.rs ] || {
  echo "docs-coherence: the conformance corpus is not in modules/common/," >&2
  echo "  so it is not in the kagi-common artifact and consumers cannot" >&2
  echo "  run it (tools/conformance/README.md)." >&2
  fail=1
}

if [ "$fail" -ne 0 ]; then
  echo >&2
  echo "docs-coherence gate FAILED" >&2
  exit 1
fi
echo "docs-coherence: ok"

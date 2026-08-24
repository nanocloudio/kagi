#!/usr/bin/env bash
# Shadow-checkout guard: tests/ and configs/ are shadow-tracked
# (.git-shadow/), so a runner holding only the primary repo has neither the
# test suite nor deployable graph templates. Hard-fail instead of reporting a
# green gate over an incomplete checkout. Wired as `[ci.test] scripts` in
# fluxor.toml.
set -euo pipefail
cd "$(dirname "$0")/.."
for tier in tests configs; do
  if [ -z "$(ls -A "$tier" 2>/dev/null)" ]; then
    echo "ci-shadow-guard: $tier/ is empty or absent — the shadow-tracked tree" >&2
    echo "is not materialised on this machine." >&2
    exit 1
  fi
done

#!/usr/bin/env bash
# Make the e2e suites REQUIRED, not optional.
#
# Every `*_e2e.rs` suite here soft-skips when its graph will not launch:
# `launch_or_skip` returns `None` and the test passes. That is right for a
# developer without a built runtime, and it is exactly wrong for CI —
# a graph that cannot load reports GREEN, over a suite that ran nothing.
#
# It is not hypothetical. A wiring edit that named a module the issuer graph
# does not contain sat in `configs/issuer.yaml` through several full CI runs
# reported as green, because every suite that would have caught it skipped:
# the graph failed to launch, and failing to launch is what the skip is FOR.
#
# `KAGI_REQUIRE_E2E=1` turns each skip into a failure that names the launch
# error. Set here rather than in the Makefile so `fluxor ci` carries it too,
# which is what actually runs in CI.
set -euo pipefail

export KAGI_REQUIRE_E2E=1
cd "$(dirname "$0")/.."

# The full output goes to a log; only the FAILURES are re-printed on the way
# out. `fluxor ci` keeps a bounded tail of a failing script's output, and a
# `--no-fail-fast` run across ~25 targets scrolls the actual failure clean
# out of that tail, leaving `Running tests/...` banners and an
# `error: 1 target failed` with no test name attached.
LOG="$(mktemp /tmp/kagi-e2e-required-XXXXXX.log)"
if cargo test --release --target aarch64-unknown-linux-gnu \
     --manifest-path tests/harness/Cargo.toml --no-fail-fast >"$LOG" 2>&1; then
  rm -f "$LOG"
  exit 0
fi
echo "== e2e-required FAILED; the failing tests and their panics: =="
grep -E "^test .* FAILED|panicked at|assertion" "$LOG" | head -40
grep -E "error: .* target.* failed|^  +\`--test" "$LOG" | head -10
echo "== full log: $LOG =="
exit 1

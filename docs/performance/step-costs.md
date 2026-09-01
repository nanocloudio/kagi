# Step costs, measured

What one credential operation costs inside a fluxor step, per implemented
suite, measured by `modules/app/suite_bench` (one operation per step,
`dev_micros` around exactly the operation, 16-sample windows reported as
recurring beats). This table is what every WCET constant in the tree is
checked against; a constant that disagrees with it is wrong, not the table.

Method: `configs/bench-suites.yaml` under `fluxor-linux` for the Linux
column; `tests/hardware/pi5_kagi_bench.toml` (via
`configs/bench-suites-pi5.yaml`) for the bcm2712 column — same module, same
bytes. Vault = the kernel software backend on both (an HSM deployment
re-measures with its own backend: PKCS#11 calls block inline). "sign" is a
vault SIGN round trip; "verify" is the in-module SDK verifier; "hash" is
one SHA-256 over the suite's public key (the thumbprint shape).

## Linux (aarch64, Cortex-A76, fluxor-linux, 2026-09-01)

~600 samples per cell, microseconds.

| Suite | sign avg | sign max | verify avg | verify max | hash avg |
| --- | ---: | ---: | ---: | ---: | ---: |
| ES256 | 1 747 | 11 046 | 1 242 | 9 680 | 0 |
| Ed25519 | 3 952 | 18 828 | 724 | 4 021 | 0 |
| ML-DSA-44 | 1 145 | 4 890 | 519 | 5 159 | 9 |
| ML-DSA-65 | 6 868 | 26 086 | 815 | 3 599 | 12 |
| ML-DSA-87 | 4 675 | 15 383 | 1 484 | 14 103 | 16 |

The maxima carry host-scheduling noise (fluxor-linux shares the CPU with
the OS); the bcm2712 column below is the number a step guard actually
meets.

ML-DSA's spread is real rather than noise, and it is not randomness:
signing here is the deterministic FIPS 204 variant, so a given key and
message always take the same number of rejection-loop iterations. What
varies is the message. That also explains -87 averaging under -65 —
the parameter sets have different expected iteration counts, and -87's is
the lower of the two — so the ordering is the algorithm's, not an error.

Two orderings here are recorded rather than rationalised: Ed25519
signing above ES256, and ML-DSA-44 signing below both classical suites.
Both reproduce on bare metal (below), so they are not host artefacts —
see the bcm2712 section for what that does and does not establish.

## bcm2712 (Pi 5 bare-metal, 2026-09-12)

Measured by `pi5_kagi_bench` on rig `pi5-a`: netbooted, one operation per
step, 16-sample windows off UDP telemetry. Ranges are min-to-max across
every window the run completed, with the window count — a suite the bench
cycled twice is reported across both.

| Suite | sign | verify | hash |
| --- | ---: | ---: | ---: |
| ES256 | 1 697 – 2 725 (2w) | 1 304 – 2 105 (2w) | 1 – 2 |
| Ed25519 | 4 498 – 4 509 (1w) | 809 – 824 (1w) | 0 – 1 |
| ML-DSA-44 | 1 831 – 1 848 (1w) | 542 – 554 (1w) | 9 – 10 |
| ML-DSA-65 | 3 904 – 3 919 (1w) | 912 – 923 (1w) | — |
| ML-DSA-87 | 16 118 – 38 378 (2w) | 1 545 – 2 486 (2w) | 18 – 30 |

Within a window the spread is a few microseconds — 38 357 to 38 378 for
the widest signature in the table. That is what deterministic signing
looks like when the host is not sharing the CPU: one key over one message
does the same work every time, and none of the Linux column's maxima
survive here.

ACROSS windows is a different matter, and two suites show it. ML-DSA-87's
two windows differ by 2.4× (16 118 against 38 361 average), which is the
rejection loop: a different input takes a different number of iterations,
and that is the one thing about this scheme that is genuinely
input-dependent. ES256's differ by 1.6× (1 697 against 2 716) and that is
NOT explained — RFC 6979 is deterministic too, and a vault round trip
should not vary with the message. It is recorded, not rationalised.

`ML-DSA-65 hash` is empty because the run's pass rules require a verify
window per suite and the board was released once they were met; the hash
window for that suite had not come round.

**Both orderings the Linux column could not explain reproduce here**, so
neither is host noise: Ed25519 signing costs more than ES256 (4 498
against 1 697 – 2 725), and ML-DSA-44 signing costs less than either
classical suite (1 831). Every column is a vault SIGN round trip, so the
primitive is only part of what is timed; the cause is still open, but the
effect is a property of these implementations on this silicon.

## What the silicon decides

Against the 2 000 µs default deadline, and the 12 000 µs ceiling a single
module may hold (8× burst under the scheduler's 100 ms absolute cap):

- **No suite's vault SIGN fits the default deadline**, confirming the
  Linux column on hardware. ES256 fits at its fastest window and not at
  its slowest; everything else exceeds it outright.
- **ML-DSA-87 cannot sign inside a step at all** under the current
  ceiling: 38 378 µs is more than three times the widest deadline a
  module may declare. It is expressible only as a burst overrun, which is
  what the bench graph's `fault_policy: tolerate` records. A deployment
  wanting post-quantum issuance on this silicon needs the sign off the
  step path, not a larger number.
- **Per-step op counts have a per-suite ceiling.** `token_mint` serves
  four signs a step: at ES256's slowest that is 10 900 µs and fits the
  12 ms ceiling; at Ed25519's it is 18 036 µs and does not. Four is an
  ES256 budget.
- **Verification is cheap by comparison** — 542 to 2 486 µs across every
  suite — so `resource_gate`'s two requests a step, priced at two
  verifications each, come to 8 420 µs at ES256's slowest and fit.

### What a target deployment has to do with that

The declared deadline has a ceiling of its own: the config validator
refuses a module whose 8× burst exceeds 16 × `tick_us`, so a graph's tick
bounds every deadline in it at `tick_us × 2`. `configs/issuer.yaml` ticks
at 500 µs, which caps each module at 1 000 µs — under the cheapest
signature in the table. Raising the tick to admit an 11 ms budget also
re-prices every edge's sustained bandwidth (a 2 KB ring at 6 250 µs
sustains 327 KB/s where the same ring at 500 µs sustains 4 MB/s), so it
is a graph designed for the target rather than a parameter changed on
this one.

That is why the reference graph declares no deadlines: it targets Linux,
where the hooks are inert, and it now names this as its third
DO-NOT-DEPLOY reason instead of carrying numbers that would be both
unenforced and wrong for the tick they sit on.

## What the Linux column already decides

Even before the silicon numbers, with the default step deadline at
2 000 µs (`DEFAULT_STEP_DEADLINE_US`, inert on Linux, ENFORCED on target):

- **No suite's vault SIGN fits the default deadline** at average, ES256
  included. `token_mint` signing in-step is over budget the moment the
  guard is real.
- **`resource_gate`'s `MAX_REQS_PER_STEP = 2` does not fit.** Its own
  comment prices a request at two signature verifications; two ES256
  requests ≈ 4 × ~1 240 µs ≈ 5 ms of verification in one step, 2.5× the
  default deadline — on Linux, before target slowdown.
- **A green e2e says nothing about any of this.** The Linux guard hooks
  are inert, so every kagi e2e passes whatever the budgets are. A gate
  that cannot fail reports green over an untested property, and this
  table is the only thing that reads it.

What follows: the issuer-path modules need declared `step_deadline_us`
values justified by this table, or per-step op budgets sized down to the
deadline. The choice is per module and lives in its graph, where it is
reviewable.

## The gate envelope's first ceiling (Linux, 2026-09-01)

The open-loop ladder (`gate_load`, scheduled-send latencies, driver CPU
attributed) hit its first ceiling at the FIRST rung, and it is not a
latency: at 25 req/s the gate admits exactly 128 requests (p50 4.0 ms,
p99 4.8 ms, driver 1%) and then refuses everything — the process-local
replay window (`REPLAY_DEPTH = 128`, entries retained for the 300 s
proof window) saturating and failing closed, precisely as designed ("an
eviction under load is an admission under load").

So the measured sustained ceiling of an UNWIRED gate is **128 proofs per
300 s ≈ 0.43 req/s** — a correctness posture, not a throughput one. Any
deployment with real traffic needs the durable replay lane
(`state_requests`/`state_replies` to `security_state`), which moves
spent-proof state to the ledger; `configs/e2e-gate-ledger.yaml` is that
graph, and its envelope is a separate measurement from this one.

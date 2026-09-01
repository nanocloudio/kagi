#!/usr/bin/env bash
# Rig build recipe for the pi5 target — what `fluxor rig test` runs before
# deploying. Invoked from the machine-local profile
# ($XDG_CONFIG_HOME/fluxor/projects/kagi/rig.toml) as:
#
#   command = ["bash", "tools/rig/build.sh", "${scenario.config}"]
#
# In the repo rather than inlined in the profile, because the profile is
# machine-local and unversioned: knowledge put there does not travel and
# cannot be reviewed. The two rules below are the ones that decide whether
# a deploy is real, and both fail silently when broken:
#
#  - ALWAYS rebuild the firmware, never "only if absent" — the kernel embeds
#    an ABI-surface expectation, and a stale kernel refuses fresh modules at
#    load, which presents as a board with nothing listening.
#  - NO mtime filters on the image — `fluxor build` does not rewrite an
#    up-to-date .img, so a freshness filter deploys yesterday's image.
#
# Kagi carries no deps/ vendoring; the fluxor checkout is the sibling tree,
# same as chronicle's and lattice's recipes.
set -euo pipefail

FLUXOR=../fluxor
[ -d "$FLUXOR" ] || { echo "rig build: no fluxor checkout at $FLUXOR" >&2; exit 1; }

make -C "$FLUXOR" firmware TARGET=pi5
mkdir -p target/pi5/images
if ! cmp -s "$FLUXOR/target/pi5/firmware.bin" target/pi5/firmware.bin 2>/dev/null; then
  cp "$FLUXOR/target/pi5/firmware.bin" target/pi5/firmware.bin
fi

fluxor modules build --target bcm2712
fluxor build "$1"

# Surface the image at the stable path the deploy stage reads. `fluxor build`
# mirrors the config's subdirectory under images/, so locate by stem.
STEM="$(basename "$1" .yaml)"
SRC="$(find target/pi5/images -name "${STEM}.img" | head -1)"
[ -n "$SRC" ] || { echo "rig build: no image for ${STEM}" >&2; exit 1; }
DST=target/pi5/images/kagi-pi5.img
[ "$SRC" -ef "$DST" ] || cp "$SRC" "$DST"

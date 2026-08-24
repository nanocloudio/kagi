# kagi Makefile — the lifecycle only: help / build / test / lint / ci /
# publish / clean. Anything else is the `fluxor` CLI invoked directly (`fluxor modules build`, `fluxor run`,
# `fluxor update`, `fluxor sync`, `fluxor build --check …`) — a make
# target that merely renames one CLI command is bloat, not convenience.
#
# Every lifecycle recipe is one delegation. The CLI verb reads the
# project's shape (root Cargo.toml, modules/ + [ci].targets, [ci.test]
# scripts, the fluxor.toml gates) and does what that shape implies — so
# there is no per-repo recipe body left to hand-write, and `make help`
# is generated (`fluxor help --make`). This is gate-enforced by
# `fluxor ci`'s `makefile` phase.
#
# One-time setup: make -C ../fluxor install

SHELL       := /bin/bash
.SHELLFLAGS := -euo pipefail -c

.DEFAULT_GOAL := build

.PHONY: help build test lint ci publish clean

help:
	@fluxor help --make

build:
	fluxor build

test:
	fluxor test

lint:
	fluxor lint

ci:
	fluxor ci

publish:
	fluxor publish

clean:
	fluxor clean

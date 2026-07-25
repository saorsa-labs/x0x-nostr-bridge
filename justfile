# x0x-nostr-bridge justfile — standard Saorsa Labs Rust recipes.
#
# Run `just --list` to see every recipe.

set shell := ["bash", "-uc"]
set dotenv-load := false

default:
    @just --list

# ── Core Rust checks ──────────────────────────────────────────────────────

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Hermetic test suite. Excludes the #[ignore]-gated e2e (see `test-e2e`),
# which boots real x0xd daemons and joins a live network.
test:
    cargo nextest run --all-features

test-verbose:
    cargo nextest run --all-features --no-capture

build:
    cargo build --all-features

build-release:
    cargo build --release --all-features

doc:
    cargo doc --all-features --no-deps

clean:
    cargo clean

quick-check: fmt-check lint test

check: fmt-check lint build test doc

# ── e2e (non-hermetic) ────────────────────────────────────────────────────

# Two-bridge cross-mesh convergence over live x0xd daemons (#[ignore] — needs
# a built x0xd binary and spawns real daemons, so it cannot run under `test`).
# Requires the sibling x0x checkout built (`cargo build --release --bin x0xd`
# there) and the binary staged where the test's resolver looks:
# `cp ../x0x/target/release/x0xd target/release/x0xd` here first.
test-e2e:
    cargo nextest run --all-features --test e2e_convergence --run-ignored all

# x0x-nostr-bridge

A Nostr relay facade (NIP-01 subset + NIP-11/16/42/50) backed **purely by the
x0x gossip fabric** — no Postgres, no Redis, no central relay. Point any
NIP-29-compatible client (e.g. an unmodified Buzz desktop, `nak`) at
`ws://127.0.0.1:3300`; events are verified (Schnorr), stored in local SQLite
(+ FTS5), and distributed as signed JSON over per-channel x0x gossip topics
(`buzz.v1.global`, `buzz.v1.ch.<channel>`). Run unmodified Nostr clients on
post-quantum, serverless infrastructure.

## Status

**Graduated spike.** Originated as a 2026-07-22 spike inside the x0x checkout,
independently reviewed, and promoted to this standalone repository. It has **no
dependency on the `x0x` crate** — it talks to a local `x0xd` daemon over its
REST + WebSocket API.

- **182 active tests** (unit + integration) pass hermetically, plus
  **2 `#[ignore]`-gated e2e** tests that boot real `x0xd` daemons.
- Two-bridge cross-mesh convergence **observed live** (single spike run,
  2026-07; the test prints but does not assert or record latency): two `x0xd`
  daemons, two bridges, kind-9 events converging A→B in **45.75 ms** and B→A
  in **36.42 ms**, with SQLite history served before EOSE on the receiving
  side (`tests/e2e_convergence.rs`). Nightly re-verification is the job of
  `.github/workflows/e2e-mesh.yml`.

## What M1a proves — and what it does not

M1a is a **single-bridge** milestone. Read this section before quoting any
result from it.

**Proven — the Nostr dialect.** The stock, unmodified Buzz desktop client
(0.4.24) runs against ONE bridge fronting ONE x0xd: the M1a acceptance gate
(`docs/design/m1a.md` §1) is reported passing 24/24 across three consecutive
runs. That gate is the Playwright suite in the tic-tac-toe repo — its
artifacts live there, not here — and it covers a selected set of workflows,
explicitly excluding media, invites/join-policy, huddles, and presence. The
bridge serves Buzz's extended relay dialect — HTTP
`/events`/`/query`/`/count`, WS NIP-01/42, the thread read-model, the demo
seed — faithfully **for the workflows the gate exercises**; the gate cannot
evidence indistinguishability across the whole client.

**Not proven — distribution.**

- Per design decision **D1, one bridge = one community = the serialized
  writer**. There is no shared cross-bridge state in M1a: each bridge's
  local SQLite is authoritative for its own community (**D3**).
- **Kind-9 channel messages converge** across bridges over the x0x mesh —
  the `e2e_convergence` suite proves delivery A→B and B→A, live and from
  SQLite history (it constructs kind-9 events only; other kinds are
  unproven). **Thread counters do not converge.** The 39005 reply/descendant
  counts a bridge serves are computed from its own SQLite, so two bridges
  watching the same channel can legitimately serve different counters.
  Cross-bridge thread-counter convergence is **deliberately deferred to
  Stage 3** (substrate: x0x#275/#276); it is a design decision, not a bug.
- Known gate flake, with an attribution caveat: `stream.spec.ts:477`
  (scroll-pinning under live fan-out) keys on an unread count that Buzz
  derives **client-side** from array lengths (`useUnreadChannels.ts`) — the
  relay protocol carries no unread count. The current diagnosis is a
  stock-Buzz timing race rather than a bridge defect, but note what that
  does not establish: bridge delivery timing, duplication, or ordering feed
  those arrays, so the client-side derivation is evidence, not exoneration.
  The failure analysis lives with the gate artifacts in the tic-tac-toe
  repo, not here.

If a claim sounds stronger than "stock Buzz passes the gate's workflows
against one bridge, and kind-9 events converge between bridges", it is
overstated.

This repository is the base for **bridge v2**, whose scope is Buzz's extended
relay dialect — see the fork plan in the tic-tac-toe repo,
`docs/design/buzz-fork-plan.md`. The spike's pre-deploy gaps below were
closed in bridge-v2 milestone **M1a**.

## Run

```bash
x0x start                                  # daemon must be running
cargo run                                  # ws on 127.0.0.1:3300
```

Config (env): `BRIDGE_BIND` (default `127.0.0.1:3300`), `BRIDGE_DB`
(default `./nostr-bridge.db`), `X0X_API` / `X0X_TOKEN` (else auto-discovered
from the x0x data dir).

## Test

```bash
just test                                  # 182 hermetic tests (nextest)
just check                                 # fmt + clippy + build + test + doc

# e2e (non-hermetic): boots real x0xd daemons on a localhost mesh.
# Build x0xd from a sibling x0x checkout first (`cargo build --release
# --bin x0xd` there), then stage it where the test's resolver looks —
# `target/{debug,release}/x0xd` under THIS crate — and run serialized
# (--test-threads 1 is load-bearing: nextest forks per test, so the
# suite's process-local TEST_MUTEX cannot serialize the daemon meshes):
mkdir -p target/release
cp /path/to/x0x/target/release/x0xd target/release/x0xd
cargo nextest run --test e2e_convergence --run-ignored all --test-threads 1
```

`tests/adversarial_{relay,transport}.rs` encode the red-team findings
(auth/REQ abuse, gossip topic confusion, oversize payloads, subscription
multiplication, filter DoS) — each fails against the pre-fix code.

The e2e suite pulls in a vendored copy of the x0x cluster harness at
`tests/harness/cluster.rs` (it drives real daemons over localhost).

## Security posture

Verified safe by review: no EVENT/REQ without per-connection NIP-42 (uuid
challenge, single-use, asymmetric time window); no pubkey substitution;
parameterized SQL only; sanitized FTS5 MATCH; 64 KiB frames; per-conn sub cap;
result cardinality cap. Hardened after red team: gossip payloads are
topic-bound (event `#h` must match arrival topic), size-capped before
verification, ephemeral/auth kinds are never persisted, daemon subscriptions
are leak-free across reconnects (DELETE+re-POST, one forwarder per topic),
`ensure_topic` is race-free, REQ `#h`/filter cardinalities are capped and
channel ids validated, replaceable ties resolve to lowest id, REQ sub-replace
at cap conforms to NIP-01.

## Spike pre-deploy gaps — closed in M1a (WP3)

The independent spike review (verified 2026-07-22) listed four issues that
had to close before any non-loopback deployment. All four are closed on the
current tree:

1. **NIP-11 info document had no active unit test** — `src/nip11.rs` now
   carries active tests (NIP-43/98 `supported_nips` gating, `self` value).
2. **No cap on concurrent WebSocket connections** — a global semaphore caps
   connections (default 256, `BRIDGE_MAX_CONNECTIONS`); tested by
   `global_connection_cap_enforced` (`src/relay.rs`).
3. **NIP-42 relay-tag check skipped** — the relay tag is verified when
   `enforce_relay_tag` is set, which `Settings::from_env` defaults ON for
   production (`BRIDGE_ENFORCE_RELAY_TAG`); tested by
   `relay_tag_accepted_when_matching` / `relay_tag_rejected_when_mismatched`.
4. **Per-topic transport mutex map never pruned** —
   `GossipTransport::remove_topic` tears down the daemon forwarder and prunes
   the tracking maps on last unsubscribe (`src/transport.rs`, issue #4).

Other accepted limitations (documented, not bugs): slow-consumer drop is
silent; kind-5 deletions are soft-applied on ingest (target marked
`deleted`, parent/root counters decremented in the same transaction —
`delete_flow` in `src/history/engine.rs`); no id/author prefix matching; no cross-bridge history catch-up (a bridge sees only events
gossiped while it runs + its own DB); NIP-42 is proof-of-key, not access
control — do not bind non-loopback without a real authz layer.

## Follow-ups (bridge v2)

Buzz desktop + `buzz-conformance` as acceptance; history anti-entropy on
join (bulk catch-up over x0x byte streams); Blossom media over x0x streams;
NIP-17 DM inbox persistence; MLS-encrypted private channels (x0x multi-member
TreeKEM works). Git hosting and huddles are out of scope (no x0x equivalents).

## License

Dual-licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

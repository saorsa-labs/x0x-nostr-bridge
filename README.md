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
- Two-bridge cross-mesh convergence **verified live**: two `x0xd` daemons, two
  bridges, kind-9 events converging A→B in **45.75 ms** and B→A in **36.42 ms**,
  with SQLite history served before EOSE on the receiving side
  (`tests/e2e_convergence.rs`).

## What M1a proves — and what it does not

M1a is a **single-bridge** milestone. Read this section before quoting any
result from it.

**Proven — the Nostr dialect.** The stock, unmodified Buzz desktop client
(0.4.24) runs against ONE bridge fronting ONE x0xd, with the M1a acceptance
gate (`docs/design/m1a.md` §1) passing 24/24 across three consecutive runs.
The bridge serves Buzz's extended relay dialect — HTTP
`/events`/`/query`/`/count`, WS NIP-01/42, the thread read-model, the demo
seed — faithfully enough that Buzz cannot tell it from `buzz-relay`.

**Not proven — distribution.**

- Per design decision **D1, one bridge = one community = the serialized
  writer**. There is no shared cross-bridge state in M1a: each bridge's
  local SQLite is authoritative for its own community (**D3**).
- **Raw events converge** across bridges over the x0x mesh — the
  `e2e_convergence` suite proves delivery A→B and B→A, live and from SQLite
  history. **Thread counters do not.** The 39005 reply/descendant counts a
  bridge serves are computed from its own SQLite, so two bridges watching
  the same channel can legitimately serve different counters. Cross-bridge
  thread-counter convergence is **deliberately deferred to Stage 3**
  (substrate: x0x#275/#276); it is a design decision, not a bug.
- Known gate limitation: `stream.spec.ts:477` (scroll-pinning under live
  fan-out) keys on an unread count that Buzz derives **client-side** from
  array lengths (`useUnreadChannels.ts`) — the relay supplies nothing to
  it. A failure there is a stock-Buzz timing race, not a bridge defect.

If a claim sounds stronger than "stock Buzz works against one bridge, and
raw events converge between bridges", it is overstated.

This repository is the base for **bridge v2**, whose scope is Buzz's extended
relay dialect — see the fork plan in the tic-tac-toe repo,
`docs/design/buzz-fork-plan.md`. The pre-deploy gaps listed below are scheduled
to land in bridge-v2 milestone **M1a**.

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
just test                                  # 60 hermetic tests (nextest)
just check                                 # fmt + clippy + build + test + doc

# e2e (non-hermetic): boots real x0xd daemons on a localhost mesh.
# Build x0xd from a sibling x0x checkout first (`cargo build --release
# --bin x0xd` there), then stage it where the test's resolver looks —
# `target/{debug,release}/x0xd` under THIS crate — and run:
cp /path/to/x0x/target/release/x0xd target/release/x0xd
cargo nextest run --test e2e_convergence --run-ignored all
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

## Known pre-deploy gaps (tracked as issues)

These are the independent review's pre-deploy findings (verified 2026-07-22).
They are safe under a loopback bind but **must be closed before any
non-loopback deployment**. Fixes are scheduled for bridge-v2 **M1a**:

1. **NIP-11 info document has no active unit test** — the endpoint exists
   (`src/relay.rs`) but no non-ignored test exercises it.
2. **No cap on concurrent WebSocket connections** — resource exhaustion risk
   on a non-loopback bind (`src/relay.rs`).
3. **NIP-42 relay-tag check skipped** — AUTH is replayable across bridges
   within the validity window; currently only a warning on non-loopback bind
   (`src/proto.rs`, `src/relay.rs`).
4. **Per-topic transport mutex map is never pruned** — unbounded growth under
   topic churn (`src/transport.rs`).

Other accepted spike limitations (documented, not bugs): slow-consumer drop is
silent; kind-5 deletions stored but not applied; no id/author prefix matching;
no cross-bridge history catch-up (a bridge sees only events gossiped while it
runs + its own DB); NIP-42 is proof-of-key, not access control — do not bind
non-loopback without a real authz layer.

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

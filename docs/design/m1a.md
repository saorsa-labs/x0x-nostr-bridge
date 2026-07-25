# Bridge v2 — M1a design: stock Buzz desktop on the x0x mesh

**Status:** Accepted for implementation — Codex external review 2026-07-24:
`VERDICT: SOUND-WITH-CHANGES` (all 6 BLOCKING findings folded in below; see
§6 review log)
**Date:** 2026-07-24
**Inputs:** four recon reports at Buzz anchor `710ed9ff` (0.4.24) — `dialect.md`
(wire contract), `thread.md` + `thread-fixtures.json` (thread semantics +
vectors), `tests.md` (conformance gate), `spike.md` (reuse matrix). This doc is
the synthesis; the recon docs are the normative detail and ship in
`docs/recon/` alongside it.
**Parent plan:** tic-tac-toe `docs/design/buzz-fork-plan.md` (M1a row table).

## 1. Goal and acceptance

Goal: Block's stock Buzz desktop client (0.4.24), in relay mode, works against
`x0x-nostr-bridge` instead of `buzz-relay` — no Postgres, no Redis, no Block
infrastructure; durable state in bridge SQLite, live propagation over the x0x
mesh.

**Acceptance (the gate):** with one bridge on `http://localhost:3000` (+ WS
same port) and one x0xd:

1. `assertRelaySeeded()` passes (kind-39000 for `general` served within the
   seed deadline, `X-Pubkey` honored, `Host: localhost:3000` not 404'd).
2. These tic-tac-toe relay-config specs green, run via
   `pnpm test:e2e:integration`:
   `integration.spec.ts`, `stream.spec.ts`, `dm-double-notification.spec.ts`,
   `parity-ancestor-island.spec.ts`.
3. Thread conformance unit suite green against the mined vectors
   (`thread-fixtures.json`, 8–15 scenarios incl. only-root, orphan-reject,
   depth-cap, same-second keyset ties).
4. The four graduated-spike hardening issues closed (NIP-11 test, connection
   cap, NIP-42 relay-tag, mutex pruning).

Explicitly **out of M1a**: media/Blossom, invites/join-policy, huddle, git,
pairing, two-relay live gate, 1012 graceful-drain spec (skip-by-default
upstream; we implement 1012 as a cheap stretch, see WP3), presence synthesis
(gate never queries it; return empty), multi-tenant Host maps, 429
*enforcement* (grammar implemented, limiter off by default).

## 2. Architecture decisions

- **D1 — One bridge instance = one community = the serialized writer.** This
  mirrors Buzz's own model (one relay per community) and is what makes the
  transactional thread-counter semantics implementable without CRDT counters
  in M1a. Cross-bridge convergence of thread metadata is deliberately deferred
  (Stage 3 moves thread computation into x0xd's ADR-0023 store; x0x#275/#276
  are the tracked substrate issues). The spike's two-bridge e2e stays
  ignore-gated with a doc note: raw events converge; thread counters are
  per-bridge until Stage 3.
- **D2 — Two-door ingest.** Local door (HTTP `/events` + WS `EVENT`): strict
  Buzz semantics — orphan replies REJECTED (`invalid: reply parent not found`),
  root verified server-side, depth cap 100, counters bumped in the same SQLite
  transaction. Mesh door (events arriving from x0x gossip): park orphans in a
  pending table, attach + recompute when the parent lands, quarantine (don't
  hard-reject) ancestry mismatches. The doors share one validation core.
- **D3 — Bridge-local SQLite stays authoritative for M1a** (per fork plan).
  x0xd `/history/*` exists in 0.34.3 but is scope-keyed for x0x payloads, not
  Nostr filter/window queries; the bridge schema below is purpose-built and
  becomes the migration spec for Stage 3.
- **D4 — Relay identity: a persisted secp256k1 keypair** (Nostr wire
  requirement) supplying the NIP-11 `self` value and signing all
  relay-authored events (39005/39006 overlays, kind-13534 membership list;
  a NIP-11 doc itself is not a signed event). This is a loopback-dialect
  artifact per the Stage-2 identity rules — it authenticates nothing in x0x
  terms.
- **D5 — Auth: both doors of Buzz's HTTP auth.** `require_auth_token=false`
  (default for the gate): accept `X-Pubkey`. `=true`: full NIP-98 verification
  incl. u/method/payload tags and a TTL replay cache — required before any
  "stock production client" claim, cheap to build now against dialect.md §0.
- **D6 — Frozen `proto.rs` gets a v2 module, not edits.** The spike's WS core
  (dispatch, EOSE-always, FTS) is reused; the new HTTP dialect, window
  read-model, and thread engine land as new modules behind the existing seams
  (`handle_event`, `store.insert`, `fts_match_expr`).

## 3. Schema (replaces the flat spike table)

```sql
events(id TEXT PK, pubkey TEXT, created_at INTEGER, kind INTEGER,
       tags JSON, content TEXT, sig TEXT, raw JSON,
       channel_id TEXT,           -- resolved #h
       deleted INTEGER DEFAULT 0)
  INDEX (channel_id, created_at DESC, id ASC)   -- window keyset
  INDEX (kind, created_at DESC)
thread_metadata(event_id TEXT PK, event_created_at INTEGER,
       channel_id TEXT, parent_event_id TEXT, root_event_id TEXT,
       depth INTEGER, reply_count INTEGER DEFAULT 0,
       descendant_count INTEGER DEFAULT 0, last_reply_at INTEGER,
       broadcast INTEGER DEFAULT 0)
  INDEX (root_event_id, event_created_at ASC, event_id ASC)  -- thread keyset
pending_orphans(event_id TEXT PK, parent_event_id TEXT, raw JSON,
       received_at INTEGER)                      -- mesh door only
members(channel_id TEXT, pubkey TEXT, role TEXT, PRIMARY KEY(channel_id,pubkey))
nip98_seen(event_id TEXT PK, expires_at INTEGER) -- replay cache (D5)
fts5(content) unchanged from spike
```

Single-community deployment ⇒ no `community_id` column; the community is the
process. `(community_id, created_at, id)` partition semantics collapse to
`(created_at, id)` keyset + PK addressing, preserving Buzz's tie-safe cursor
contract exactly (`created_at DESC, id ASC` window order; `ASC, ASC` thread
order).

**Schema invariants (review findings 2, 7, 8):**
- A `meta(community_fingerprint)` row is written at DB creation; startup
  REFUSES a DB whose fingerprint differs from the configured community
  (accidental scope-reuse guard). Every window/thread/aux/membership/
  parent-validation query is constrained by `channel_id`.
- Event ids are canonicalized to lowercase 64-hex on every ingest/cursor
  input (reject non-hex; lowercase before compare/store) so TEXT binary
  collation matches Buzz's id ordering.
- **Keyset predicates are normative**, not derivable from the indexes alone:
  - window (DESC walk):
    `created_at < :ts OR (created_at = :ts AND id > :id)`
  - thread (ASC walk):
    `event_created_at > :ts OR (event_created_at = :ts AND event_id > :id)`
- **Exhaustion probe**: window/thread pages SELECT `limit + 1` rows; the
  39006 `has_more` is `count == limit + 1` (an exact-multiple final page must
  yield `has_more:false` — `rows < limit` proves nothing, per dialect.md §1).

## 4. Work packages

**WP1 — storage + thread engine** (the redesign; hardest, first):
schema above; ingest transaction implementing thread.md §1 verbatim (marked
NIP-10 only; marker table incl. only-root→top-level; parent-must-exist reject
[local door]; server-verified root; depth cap 100 [Some-branch only];
lazy parent/root stub rows; reply_count/descendant_count bumps; `last_reply_at`
= wall-clock on local door, `max(created_at)` on mesh door; participants
derived at read as `DISTINCT pubkey` over the subtree `ORDER BY
MAX(created_at) DESC LIMIT 10` [finding 5, thread.md §1.5]; reactions on
the separate NIP-25 branch, never threaded). Conformance vectors from
`thread-fixtures.json` are the unit gate.

*Delete workflow is ONE flow (finding 6, vector V15):* soft-delete marks
`events.deleted`, decrements parent `reply_count` / root `descendant_count`
(floored at 0) in the same transaction — guarded so a duplicate delete cannot
double-decrement — then post-commit emits the recomputed 39005 for the root
(zero-or-reduced counts), same emit path as replies.

*Orphan lifecycle (finding 1) — the two-door invariant is: parked and
quarantined events are INVISIBLE to every served surface* — never in
`events`, FTS, counters, HTTP/WS results, or mesh republish. Mesh-door
events whose parent is missing go to `pending_orphans`; on ANY parent
arrival (either door), attachment runs atomically: validate ancestry →
insert event + metadata → bump counters → recursively drain pending
descendants of the newly attached event. Ancestry mismatch at attachment →
`quarantine` state (kept, invisible, logged), never a hard reject of an
event peers already hold. `pending_orphans` gets a TTL reap (config,
default 24h). The window read-model SQL and the exhaustion probe are part
of THIS work package's vertical slice (schema → ingest → keyset SQL →
39006 → vectors), not deferred to WP2 integration.

**WP2 — HTTP dialect** (`axum` routes on the spike's server):
`POST /events` (single event; `{event_id,accepted,message}` 200 envelope;
error taxonomy per dialect.md §2); `POST /query` (filter array; raw-value
extension extraction — `top_level`, `include_summaries`, `include_aux`,
`until`+`before_id` both-or-neither, `thread_cursor(_id)`, `page`,
`depth_limit`; window read-model assembling rows→aux closure→39005
overlays→exactly-one 39006 bounds; search routing with
mixed-filter 400; p-gated/engram/author-only read authorization; limits
50/200); `POST /count`; `GET /info` NIP-11 (supported_nips advertising 43 only
when membership enforced; `self` = D4 pubkey); 1 MiB body cap; `{"error":msg}`
envelope; 429 grammar `retry in <N>s` (limiter default-off); auth per D5.

*Aux closure is two hops (finding 4, dialect.md §1):* reactions (7),
deletions (5 / NIP-29 delete), edits targeting the rows, PLUS deletions
targeting those aux events themselves; aux never consumes the row budget.

*Filter parity (finding 3):* tag matching (`#h`, `#p`, `#e`, authors, kinds,
ids) and the access classes (p-gated / engram / author-only / channel
access) live in ONE shared filter-match module used by BOTH the HTTP
`/query` historical path and the WS live-dispatch path — integration.spec's
mention refetch depends on stored-query and live-match agreeing exactly.

*Presence filters (finding 11):* detected explicitly (kinds only
presence-update/snapshot) → return `[]`; never touch SQLite.

**WP3 — WS + auth hardening** (closes the 4 graduated-spike issues):
NIP-42 relay-tag validation (issue #3); connection-first challenge, 5s auth
timeout, REQ-before-auth → CLOSED `auth-required:`; global connection cap
(issue #2); NIP-11 active test (issue #1); per-topic forwarder pruning
(issue #4); relay-authored kinds guard (39000-39003/39005/39006/13534 client
submissions rejected); live 39005 fan-out post-commit (fire-and-forget,
replaceable on `d=root`); kind-13534 membership list emission. Stretch: 1012
drain on SIGTERM + 503 during drain (contract known, spec not in gate).

**WP4 — seed + gate harness**:
`--seed-demo` (or config): four channels — `general` (stream), `random`
(stream), `watercooler` (forum) and the `alice-tyler` DM — each a kind-39000
(tags incl. `["name",…]`) plus a kind-39002 naming its members;
members tyler/alice/bob/charlie (pubkeys in tests.md §3), the DM being
tyler+alice only.

**Every seeded channel id is uuid5-derived**, not just the DM:
`uuid5(DNS,"buzz.channel.<name>")` for a normal channel and
`uuid5(DNS,"buzz.channel.dm.<name>")` for a DM. This rule was previously stated
for the DM alone, and `general` was seeded as the literal string `"general"` —
which put every row the specs seed into a channel the client never opens, since
`parity-ancestor-island.spec.ts:33-34` addresses it as
`9f28288a-d724-587a-9709-92dc7f967110` = `uuid5(DNS,"buzz.channel.general")`.
The bridge accepts events for an `h` channel that does not exist, so a
mis-keyed seed fails silently rather than loudly;
Host acceptance for `localhost:3000` (any Host in single-community mode);
tic-tac-toe justfile recipe `bridge-gate`: build bridge, launch x0xd
(isolated config, `[update] enabled=false`, no prod bootstraps) + bridge,
run `pnpm test:e2e:integration`, teardown. CI job in the bridge repo running
the thread-vector suite; the Playwright gate runs in tic-tac-toe CI (nightly,
not per-PR, until stable).

**WP5 — mesh binding review**: the spike already maps `#h`→topic and
pubs/subs via x0xd (5 endpoints, all in 0.34.3). Verify accepted local events
publish post-commit, mesh-door events route through WP1 parking, and dedupe
by event id survives gossip redelivery. No new x0xd endpoints required.

Ordering: WP1 ∥ WP2-skeleton → WP2 window model (needs WP1) → WP3 ∥ WP4 →
gate. WP1 is the critical path.

## 5. Risks

| Risk | Mitigation |
|---|---|
| Window read-model fidelity (39006-only pagination; aux closure; ordering) | tests.md §4a is byte-exact; `parity-ancestor-island` + vectors gate ties |
| Thread semantics divergence | thread-fixtures.json mined from Buzz's own interop tests; two surprising rules (only-root, orphan-reject) documented and vectored |
| Client never reaches `connected` (NIP-42 nuance) | dialect.md §4 full flow incl. terminal-on-22242-NAK rule; relay-tag fix in WP3 |
| Spike WS regressions while grafting | spike's 60 tests stay green in CI throughout |
| Scope creep toward M1b | out-list in §1 is explicit; anything not exercised by the 4 specs + vectors defers |
| Late backdated mesh insert lands behind a consumed cursor | Documented limitation (no stateless keyset gives snapshot isolation — Buzz's own doesn't either); only a late broadcast depth-1 reply can add a window row; gate seeds before paging so unaffected |

## 6. Review log

External Codex review 2026-07-24 (gpt-5.6-sol, read-only over the recon
pack + this doc): `VERDICT: SOUND-WITH-CHANGES`. 6 BLOCKING findings —
(1) orphan lifecycle invisibility/atomicity/recursive drain, (2) normative
keyset WHERE clauses + limit+1 probe, (3) HTTP/WS shared filter-match
module, (4) aux-closure second hop, (5) exact participants derivation,
(6) delete = decrement + 39005 recompute as one flow — all verified against
the recon docs and folded into §3/§4 above. 6 ADVISORY: community
fingerprint + id canonicalization adopted (§3 invariants); NIP-98 (D5)
stays in scope but explicitly OFF the four-spec critical path; 1012 drain
stays a stretch — M1a release is described as *gate-conformant*, not fully
restart-conformant; presence explicit-empty adopted; D4 wording fixed.
Full transcript: `docs/recon/codex-review-m1a.txt`.

# M1a recon: x0x-nostr-bridge spike vs bridge-v2 M1a surface

Read-only audit, 2026-07-24. Source: `/Users/davidirvine/Desktop/Devel/projects/x0x/x0x-nostr-bridge/`
(src 4.7 KLOC across 7 files; 40 unit + 8 integration test fns). Nothing modified.

**One-line finding:** the spike is a **WS-only, generic-Nostr relay facade** with a
flat generic-Nostr SQLite schema. M1a rows 1–2 are essentially done; rows 3–8 (the
Buzz **HTTP** dialect + server-side thread machinery) are absent, and the store schema
does not anticipate keyset cursors, thread_metadata, or summaries. The single HTTP
route on the whole bridge is `/` (WS upgrade, or NIP-11 doc on `Accept: application/nostr+json`).

---

## 1. Coverage matrix

| # | M1a surface | Status | Evidence | What exists |
|---|---|---|---|---|
| 1 | Nostr WS dialect (REQ/EVENT/EOSE/CLOSE + NIP-29) | **COVERED** | `relay.rs:296-342` dispatch; EOSE `relay.rs:490`; CLOSE→unregister `relay.rs:331`; NIP-29 `#h`→topic `proto.rs:29-58` | Full AUTH/EVENT/REQ/CLOSE + OK/NOTICE/CLOSED/EOSE. COUNT/NEG answered `"unsupported"`. NIP-29 group id = `#h` tag mapped to a per-channel gossip topic. |
| 2 | NIP-42 AUTH over WS (+ relay-tag validation) | **PARTIAL** | challenge on connect `relay.rs:259`; verify `proto.rs:91`; relay-tag skip `proto.rs:89-90` | uuid challenge, single-use, asymmetric time window (`AUTH_MAX_AGE_SECS=600`, future skew 60). **`relay` tag NOT checked** — the exact gap row 2 names; documented spike limitation. |
| 3 | `POST /events` HTTP ingest | **MISSING** | only route is `/` `relay.rs:192`; no axum POST route | Ingest today is WS `EVENT` (`handle_event` `relay.rs:346`) + gossip inbox (`ingest.rs:21`). No HTTP ingest endpoint at all. |
| 4 | `POST /query` + Buzz ext (top_level, include_summaries, include_aux, keyset cursor) | **MISSING** | no HTTP query route; `store.rs:281` query is Nostr-filter only | Read path is WS `REQ`→`store.query()`. Zero support for the four extensions. Ordering is `created_at DESC, id ASC LIMIT` (`store.rs:374`) — no keyset WHERE, no scope/community column. |
| 5 | NIP-50 search via `/query` | **PARTIAL** | FTS5 `store.rs:107-122`, `fts_match_expr` `store.rs:446`, applied `store.rs:325-338` | Search **engine** works (sanitized FTS5 MATCH over `content`) but only via WS `REQ filter.search`. No HTTP `/query` to route it through. |
| 6 | `thread_metadata` at ingest | **MISSING** | grep: 0 hits anywhere | No parent-exists check, no ancestry walk, no depth cap, no counters, no `(community,created_at,id)` partition keys. Insert path is fire-and-forget, no FK/ancestry (`store.rs:143-164`). |
| 7 | `GET /info` membership gate | **MISSING** | no `/info` route | No membership concept in the bridge. Only NIP-11 doc served at `/` (`relay.rs:225`). |
| 8 | Live thread-summary emits (post-commit, fan-out kind) | **MISSING** | live dispatch `relay.rs:131` exists, no summary logic | `hub.dispatch` fans live events to matching REQ subs, but no post-commit summary recompute and no fan-out summary kind. |

**Cross-cutting**

| Item | Status | Evidence |
|---|---|---|
| HTTP 429 rate-limit | **MISSING** | 0 grep hits; no HTTP surface to rate-limit yet |
| 1012 restart-close on shutdown | **MISSING** | 0 hits; disconnect just breaks the read loop (`relay.rs:269`), no graceful 1012 |
| Connection cap | **PARTIAL** | per-conn **sub** cap `MAX_SUBS_PER_CONN=1024` (`relay.rs:96`); **global connection cap absent** (the fork-plan review fix) |
| Per-topic mutex pruning | **PARTIAL** | per-topic forwarder mgmt in transport (DashMap `topics`/`inflight`, one forwarder/topic, DELETE+re-POST on reconnect, race-free `ensure_topic`) — related, not the exact "mutex prune" item |

---

## 2. Architecture map

**Modules**
- `proto.rs` (181, **FROZEN** — header says "Do not edit"): the Nostr contract. Topic
  mapping `buzz.v1.global` + `buzz.v1.ch.<channel>` from `#h` tags; kind classes
  (NIP-16); NIP-01 verify + NIP-42 auth verify; limits (64 KiB frame, 1024 subs/conn,
  500 filter limit).
- `relay.rs` (892): axum server. `router()` = **one route** `/`. `root_handler`
  branches WS-upgrade vs NIP-11 doc vs `426 UPGRADE_REQUIRED`. Per-conn task issues
  AUTH challenge, runs read loop through gates: AUTH→EVENT (verify, store.insert,
  publish to topics)→REQ (auth-gate, sanitize filters, register sub, backfill from
  SQLite, EOSE)→CLOSE. `Hub` holds subscriptions and does live `dispatch`.
- `store.rs` (955): SQLite. **Schema = flat `events(id,pubkey,created_at,kind,tags
  JSON,content,sig,raw)`** + `replaceable_addrs(pubkey,kind,d_tag→event_id)` +
  `events_fts` (FTS5 on content, trigger-synced). Indexes: kind, pubkey, created_at.
  No thread/summary/scope columns. Query builds parameterized WHERE from a Nostr
  `Filter`, `ORDER BY created_at DESC, id ASC LIMIT`. Replaceable/parameterized-
  replaceable resolution, `#h` case-insensitive.
- `transport.rs` (892): the x0xd client. `X0xTransport::connect` (GET /health) +
  SSE supervisor. Consumes gossip via POST /subscribe, DELETE /subscribe/:id,
  POST /publish, GET /events (SSE). Reconnect = DELETE+re-POST all topics
  (leak-free). Routes seen at 735-836 are `#[cfg(test)]` **mock daemon** servers,
  not bridge routes.
- `ingest.rs` (65): `ingest_one` — gossip inbox message → verify → store → dispatch.
- `config.rs` (44), `main.rs` (84): API discovery / wiring / loopback bind.

**WS session model:** subscription = (ConnId, sub_id, filters) in `Hub`. REQ registers
first (so live events interleave), then backfills from SQLite per filter, then EOSE.
Backfill-from-SQLite path = `store.query()`. No cross-bridge history catch-up (a bridge
only sees events gossiped while running + its own DB — documented limitation).

**Auth model:** NIP-42 proof-of-key only; every EVENT/REQ requires prior AUTH on the
connection. Explicitly "not access control" and loopback-only. No membership/ACL.

**Shutdown path:** none graceful. Read loop breaks on `Message::Close`/error, drops tx,
unregisters conn, awaits writer. A 1012 restart-close would hook into `handle_connection`
(`relay.rs:242-277`) with a shared shutdown signal driving the writer to emit a close frame.

---

## 3. Reuse verdict per M1a row

| # | Verdict | Seam it bolts onto |
|---|---|---|
| 1 | **extend-in-place** | `relay.rs:handle_text` dispatch — dialect done; only NIP-29 nuance work if any |
| 2 | **extend-in-place** | `proto.rs:verify_auth_event` — add expected relay-URL param + check |
| 3 | **build-new** | new `POST /events` route in `relay.rs:router()`; reuse `handle_event`/`store.insert`/`publish_to_topics` for the body |
| 4 | **extend-with-refactor** | `store.rs:migrate()` + `query()` (add scope/thread cols, keyset cursor WHERE) **and** new `POST /query` route; this is the schema-touching one |
| 5 | **extend-in-place** | route NIP-50 through the new `/query`; `store.rs:fts_match_expr` reused as-is |
| 6 | **build-new** | ingest path (`handle_event` + `ingest.rs`) + `store` insert transaction + `migrate()` — ancestry walk, counters, partition keys |
| 7 | **build-new** | `router()` + a membership provider (from x0xd groups or bridge config) |
| 8 | **build-new** | post-insert hook in `handle_event` → recompute → `hub.dispatch` a fan-out summary kind |

**Design decisions that actively FIGHT M1a:**
1. **`proto.rs` is frozen and deliberately generic-Nostr.** Rows 4/6/8 need Buzz-specific
   per-kind logic and new limits/kinds; the frozen contract must be unfrozen and extended.
2. **Flat `events` schema with no scope/community/thread columns and `ORDER BY
   created_at DESC, id ASC`** — keyset-cursor pagination (row 4) is a schema+index+query
   **redesign**, not a parameter add. The fork plan's `(community_id, event_created_at,
   event_id)` partition key does not exist.
3. **Fire-and-forget, no-FK insert** (`store.rs:143`) fights `thread_metadata`'s
   "parent-must-exist-at-ingest + transactional counters + server-verified ancestry"
   (row 6). Ingest must become a real transaction that reads ancestry and updates counters.
4. **WS-only surface.** Rows 3/4/5/7 are all HTTP; the bridge has no HTTP router beyond
   `/`. Adding them is additive (axum makes this cheap) but it is genuinely new surface,
   not a tweak.

---

## 4. x0xd API dependencies

Everything the spike consumes is **released in x0x 0.34.x** (`docs/api-reference.md`):

| x0xd endpoint (spike use) | api-reference | Notes |
|---|---|---|
| `GET /health` | line 42 | liveness on connect (`transport.rs:218`) |
| `POST /subscribe {topic}→{subscription_id}` | line 229 | per-topic forwarder (`transport.rs:149`) |
| `DELETE /subscribe/:id` | line 230 | teardown, 404-tolerant (`transport.rs:178`) |
| `POST /publish` (base64 payload) | line 228 | event fan-out to gossip (`transport.rs:281`) |
| `GET /events` (SSE `{type:"message",data:{topic,payload}}`) | line 231 + shape at 242 | inbox feed (`transport.rs:362`) |

Auth = `Authorization: Bearer <token>` (`transport.rs:205`); base URL + token discovered
from `~/.x0x` or `X0X_API`/`X0X_TOKEN` env.

**No unreleased x0xd dependency for M1a.** The spike uses its **own SQLite**, not
`/history/*`. `/history/*` (ADR-0023) does **not** exist in the API reference — and M1a
does not need it: thread_metadata is computed **in-bridge** for M1a. ADR-0023 history +
thread columns are a **Stage-3** concern (move thread_metadata server-side into x0xd), not
an M1a ask.

**Future x0xd ask (Stage 3, not M1a):** if/when thread_metadata + search move server-side,
x0xd needs the ADR-0023 history store with thread columns + a `/history/search` endpoint.

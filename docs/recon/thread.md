# Buzz server-side thread metadata — exact semantics @ v0.4.24

Anchor: `block/buzz` commit `710ed9fff57878a1d69f809b80a6ee0416c53fc4` (Buzz Desktop 0.4.24).

All file:line refs below are at that commit. Three files carry the whole system:

- `crates/buzz-relay/src/handlers/ingest.rs` — ancestry resolution + reject/accept gate (`resolve_nip10_thread_meta`, L563-716).
- `crates/buzz-db/src/thread.rs` — storage, counters, read queries.
- `crates/buzz-relay/src/handlers/side_effects.rs` — live 39005 fan-out (`emit_live_thread_summary`, L724-810).
- `crates/buzz-relay/src/api/bridge.rs` — `include_summaries` query overlay (L534-556).
- `crates/buzz-core/src/kind.rs` — kind constants.

---

## 1. thread_metadata computation at ingest

### 1.1 Where and when it runs

For every event whose kind is in `requires_h_channel_scope(...)` (ingest.rs L455-484 — the stream-message family kinds 9 / 40002-40008, canvas, forum post/vote/comment, most NIP-29 admin kinds, huddle lifecycle kinds; NOT reactions, NOT create-group) **and** that carries a resolvable channel, ingest calls `resolve_nip10_thread_meta(community, event, channel_id, state)` (ingest.rs L2220-2230). The result is threaded into the same DB transaction as the event insert via `insert_event_with_thread_metadata` (L2392-2399).

Reactions (kind 7) are handled on a **separate** branch (L2245+, NIP-25 last-e-tag target) and do **not** go through the NIP-10 reply-ancestry path — they never create reply thread rows.

### 1.2 Which tags exactly (marked NIP-10 only)

`resolve_nip10_thread_meta` scans `event.tags` and only considers a tag when `parts.len() >= 4 && parts[0] == "e"` and `parts[3]` (the marker) is `"root"` or `"reply"`, and `parts[1]` is exactly 64 lowercase-or-mixed hex chars (ingest.rs L573-586). Marker `"mention"` and any other value are ignored. **Positional / bare `["e", <id>]` tags (len < 4, no marker) are entirely ignored.** Buzz does NOT implement the NIP-10 positional convention.

Consequence: an event whose only e-tags are positional (or `mention`, or only a `root` marker — see below) is treated as **non-threaded** — `resolve_nip10_thread_meta` returns `Ok(None)`, the event is stored as an ordinary top-level channel message (`depth IS NULL`, no thread_metadata row). It is **not** rejected.

### 1.3 Marker combination → (root, parent) resolution (L588-596)

| root marker | reply marker | outcome |
|---|---|---|
| absent | absent | `Ok(None)` — top-level, no metadata |
| present | absent | **`Ok(None)` — top-level** (only-root is NOT treated as a reply) |
| absent | present | parent = reply-id, **root = reply-id** (direct reply to a root) |
| present | present | parent = reply-id, root = root-id |

The only-root arm (`(Some(_), None) => return Ok(None)`, L595) is a genuine surprise: a client that tags only `["e", root, "", "root"]` gets a flat top-level message, not a thread reply.

### 1.4 Parent-must-exist + server-verified ancestry (L598-695)

Once (root_hex, parent_hex) is chosen:

1. **Parent must exist** — `get_event_by_id(community, parent_bytes)` → `.ok_or("reply parent not found")` (L608-610). Missing parent ⇒ `Err` ⇒ ingest maps to `IngestError::Rejected("invalid: reply parent not found")` (L2224). **Orphan / out-of-order replies are REJECTED, not stored flat.**
2. **Parent channel match** — parent must belong to the same channel; parent in a different channel ⇒ reject `"parent event belongs to a different channel"`; parent with no channel ⇒ reject `"parent event has no channel association"` (L612-618).
3. **Server-verified root** — the client-supplied root must equal the server-derived effective root, else reject `"root tag does not match thread ancestry"` (L633-635, L677-679). The client cannot lie about the root.
   - If the parent has a thread_metadata row (`Some(meta)`, L630-651): `effective_root = meta.root_event_id ?? parent_bytes`; `depth = meta.depth + 1`.
   - If the parent has no row (`None`, L652-694 — parent is itself a root, since roots get no row until their first reply): server re-derives the parent's own root by scanning the parent's `root`-then-`reply` e-tags, defaulting to the parent id. `depth = 1` if that derived root == parent, else `2` (clamped — this branch never yields depth > 2).
4. **Depth cap 100** — in the `Some(meta)` branch only, `if depth > 100 { return Err("thread depth limit exceeded") }` (L646-649). Depth 100 is allowed; the 101st level is rejected. (The `None` branch tops out at 2, so no cap needed there.)
5. **broadcast flag** — set true iff the event carries `["broadcast","1"]` (L697-700).

Timestamps `parent_event_created_at` / `root_event_created_at` are derived from the referenced events' `created_at` (needed as partition-key components for the counter UPDATEs), falling back to `parent_created` / `Utc::now()` when the row can't be fetched.

### 1.5 Storage layout (`crates/buzz-db/src/thread.rs`)

`thread_metadata` primary key = **`(community_id, event_created_at, event_id)`** — the partition key the fork plan names. Parent and root are stored *with their own created_at* (`parent_event_created_at`, `root_event_created_at`) so the increment UPDATEs can address the parent/root rows by their partition key (L134-150).

`ThreadMetadataRecord` (L84-108) columns: `event_id`, `event_created_at`, `community_id`(implied), `channel_id`, `parent_event_id` (Option), `root_event_id` (Option), `depth` (i32, root = 0), `reply_count` (i32), `descendant_count` (i32).

**Two counters, different meaning:**
- `reply_count` = number of **direct** children of that node.
- `descendant_count` = number of **all** nested descendants (the whole subtree). Lives on the root.

Roots get **no** thread_metadata row on first insert (a plain depth-0 message). The row is created lazily as a *stub* the first time a reply needs to bump it (L158-205): `insert_thread_metadata` INSERTs the reply's own row, then `INSERT ... ON CONFLICT DO NOTHING` a stub row for the parent and (if different) the root, then `UPDATE reply_count = reply_count + 1, last_reply_at = NOW()` on the parent (L205-217) and `UPDATE descendant_count = descendant_count + 1` on the root (L219-230). A direct reply to a root bumps BOTH: parent.reply_count and root.descendant_count — and when root == parent both UPDATEs address the same row.

**`last_reply_at = NOW()`** — server wall-clock at ingest, **not** the reply's `event.created_at` (L210). This is a LWW-ish "freshness" stamp keyed on receive time.

**`participants` is NOT stored.** It is derived at read time (get_thread_summary L517-540; get_channel_window batch L698-737): `DISTINCT pubkey` over the subtree, ordered by `MAX(created_at) DESC`, **capped at 10**.

Counter reversal on delete: `decrement_reply_count` (L292-322) mirrors the increment exactly — `reply_count = GREATEST(reply_count - 1, 0)` on parent, `descendant_count - 1` on root, floored at 0. `get_thread_metadata_by_event` (L755-810) is used by the delete path to look up parent/root before decrementing.

### 1.6 Read surface + `include_summaries`

- `get_thread_replies(community, root, depth_limit, limit, cursor)` (L345-486) — all rows under a root, keyset-paginated on `(event_created_at ASC, event_id ASC)` (the tie-safe composite cursor — a timestamp-only cursor silently drops same-second ties, L339). Bridge exposes this via `POST /query` with a `depth_limit` extension field.
- `get_channel_window(...)` (L565-751) — the top-level timeline. **Top-level predicate (L597-600): `tm.depth IS NULL OR tm.depth = 0 OR (tm.depth = 1 AND tm.broadcast = true)`.** i.e. roots, non-reply messages, and *broadcast* depth-1 replies are rows; ordinary replies never are. Each row carries an optional `thread_summary` (reply_count / descendant_count / last_reply_at + batch-filled participants).
- `POST /query` with `include_summaries` (bridge.rs L534-556): for each window row that has a summary, the relay appends one relay-signed **kind 39005** overlay event (same shape as §2). Rows without replies get no overlay. A single **kind 39006** window-bounds overlay (`has_more` / `next_cursor`) is always appended (L559-575).

---

## 2. Live thread-summary emits (kind 39005)

`emit_live_thread_summary(tenant, state, channel_id, root_id)` (side_effects.rs L724-810), called fire-and-forget from ingest *after* the reply commits (ingest.rs L2448-2455), only when the event produced thread_meta (i.e. it was an accepted reply).

- **Kind: 39005** (`KIND_THREAD_SUMMARY`, kind.rs L299) — an addressable/parameterized-replaceable kind (30000-39999).
- **Recompute:** re-reads `get_thread_summary(community, root_id)` (exact, because counters were committed in the reply's transaction). If the root row is gone (`Ok(None)`) it silently returns.
- **Payload (content = JSON string):**
  ```json
  {"reply_count": <i32>, "descendant_count": <i32>,
   "last_reply_at": <unix_seconds|null>, "participants": ["<hex_pubkey>", ...]}
  ```
- **Tags:** `["e", root_hex]`, `["d", root_hex]`, `["h", channel_id]`. The `d = root_hex` makes it replaceable per (relay-pubkey, root) — newest wins.
- **Signed by the relay keypair** (`state.relay_keypair`), not the author.
- **Fan-out:** published to Redis `EventTopic::Channel(channel_id)` first (cross-pod), then to local WS subscribers via `fan_out_event_to_local_subscribers`. So it reaches any REQ subscription matching the channel's `h`-tag (kind 39005).
- **Idempotency / ordering (client-side):** because 39005 is addressable on `d=root` and relay-signed, clients keep only the newest `created_at` per root; the emit is fan-out-only and best-effort (a dropped one is corrected by the next reply's emit or by a page's `include_summaries` overlay — "one contract, two doors", side_effects.rs L752-753). Client-submitted 39005/39006 are **rejected at ingest** (only the relay may author them).

---

## 3. NIP-29 enforcement at ingest (what's enforced vs passed through)

The relay is a NIP-29-style managed relay; "group" == channel == `h`-tag == a `community`/`channel_id`.

Enforced at ingest (ingest.rs):
- **`h`-tag scoping:** channel-scoped kinds (`requires_h_channel_scope`, L455) MUST carry an `h` tag; missing ⇒ reject `"channel-scoped events must include an h tag"` (L1715). The `h` value resolves the `channel_id`/community; token channel must match (`check_token_channel_access`).
- **Membership:** for channel-scoped writes, `check_channel_membership` (L493-523) requires the author to be a cached member **OR** the channel to have `visibility == "open"`; else reject `"restricted: not a channel member"`. Skipped for join (9021) and create-group (9007) — see `skip_membership` L1770-1776.
- **Admin kinds:** NIP-29 admin kinds (9000 put-user, 9001 remove-user, 9002 edit-metadata, 9005 delete-event, 9008 delete-group, 9009 create-invite, 9022 leave; 9007 create-group creates the channel) run per-kind role/authority checks (`validate_admin_event`). Group-state kinds 39000-39003 (metadata/admins/members/roles) and 39005 thread-summary are **relay-authored only** — client submissions rejected.
- **Relay-admin kinds** (NIP-43, 9030-9032) must use a **global** token, not a channel-scoped one (L1512-1514).
- **Kind range / numeric bounds:** created_at / kind numeric sanity (0..=MAX_SAFE_INTEGER, L1220); freshness ±120s when relay-membership mode is on (L1827).

Passed through (not semantically enforced): ordinary message content, arbitrary non-marker tags, `broadcast` (recorded, not authorized), positional e-tags (ignored, not rejected).

---

## 4. Does ingest assume a single serialized writer? — YES.

The counter maintenance is a classic transactional read-modify-write:

- `insert_thread_metadata` performs INSERT(reply row) + `INSERT ... ON CONFLICT DO NOTHING`(parent/root stubs) + `UPDATE ... reply_count + 1` + `UPDATE ... descendant_count + 1` **inside the same Postgres transaction as the event insert** (ingest.rs L2392-2399 comment "updated in the same transaction as the insert"; thread.rs L109-114 "crash between them cannot leave reply_count/descendant_count inconsistent … (F9)"). Idempotency is provided by "only bump if the row was actually inserted (not a duplicate)" (thread.rs L155-157).
- **Ancestry resolution reads committed state** (`get_event_by_id`, `get_thread_metadata_by_event`) and *rejects* when the parent isn't yet present. This is only correct under a serialized, read-your-writes store.

An eventually-consistent gossip backend (x0x) must emulate three things the SQL layer gets for free:
1. **Counters → CRDTs.** `reply_count` / `descendant_count` must become idempotent, commutative counters (PN-Counter or an OR-Set of contributing event-ids reduced to a count) keyed by event-id so a replayed reply can't double-count. The insert-guard dedup must survive re-delivery.
2. **Orphan / out-of-order arrival.** The "parent must exist at ingest ⇒ reject" rule cannot hold when a reply can gossip ahead of its parent. Bridge v2 must **park orphans and backfill depth/ancestry when the parent lands**, or accept-and-recompute — not reject.
3. **`last_reply_at = NOW()`** is receive-wall-clock and thus non-deterministic across replicas; a convergent emulation should prefer `max(reply.event.created_at)` as an LWW register so all replicas agree. `participants` is already an OR-Set-shaped derivation (distinct pubkeys, recency-capped at 10) and ports cleanly.

Server-verified ancestry (client root must match derived root) also needs re-expression: with deferred parents, verification must run at backfill time, and a mismatch should quarantine rather than hard-reject a gossiped event that peers already hold.

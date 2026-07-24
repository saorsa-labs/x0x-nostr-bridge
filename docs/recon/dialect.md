# Buzz relay HTTP/WS dialect — wire contract for x0x-nostr-bridge (M1a)

Anchor: `block/buzz` @ `710ed9fff57878a1d69f809b80a6ee0416c53fc4` (Buzz Desktop v0.4.24).
Clone root in this recon: `scratchpad/buzz-dialect/`. All `file:line` below are relative to that root.

Server route table: `crates/buzz-relay/src/router.rs:61-125`. The public Nostr surface is:
`GET /` (NIP-11 doc OR WS upgrade, content-negotiated), `GET /info` (NIP-11 doc),
`POST /events`, `POST /query`, `POST /count`, plus health probes. Everything is
**per-tenant, bound by the HTTP `Host` header** via `crate::tenant::bind_community(db, host)`
(`bridge.rs:625`, and identically at the WS door). An unmapped Host → generic `404 "relay: no
community is configured for this host"`. A bridge that serves one community can ignore multi-tenancy,
but MUST still accept whatever Host the client sends (the desktop derives it from the relay URL).

Global request body cap: **1 MiB** (`RequestBodyLimitLayer`, `router.rs:~118`). Over that → 413.

---

## 0. Auth model (applies to /events, /query, /count)

All three HTTP bridge endpoints require **NIP-98** auth (`bridge.rs:1-11`, `verify_bridge_auth*`
`bridge.rs:70-160`):

- Header: `Authorization: Nostr <base64(kind-27235 event JSON)>`. The kind:27235 event's `u` tag
  MUST equal the tenant-expected URL (`nip98_expected_url(relay_url, tenant, "/events"|"/query")`,
  `bridge.rs:178`), `method` tag MUST match, and for writes the `payload` tag (sha256 of body)
  is checked when `require_payload`.
- **Replay protection**: event id is recorded in a shared community-scoped seen-set with TTL
  (`check_nip98_replay`, `bridge.rs:~120`). A replayed id → `401 "NIP-98: replay detected"`;
  guard unavailable → `401 "NIP-98: replay check unavailable"` (fail-closed).
- **Dev fallback**: `X-Pubkey: <hex>` is accepted **only** when `require_auth_token=false`
  (`bridge.rs:~150`). Zero event-id, no replay check. Do not rely on this for prod.
- Missing/!valid auth → `401 "missing Nostr auth"`.
- **Rate limit** runs before replay/parse: `enforce_http_admission` (`bridge.rs:30-66`), see §5.
- **Membership gate** runs after auth: `enforce_relay_membership(state, community, pubkey_bytes,
  x-auth-tag)` (`bridge.rs:~995`, `bridge.rs:~900` for query). Optional `X-Auth-Tag` header carries a
  NIP-OA delegation tag (owner-delegation fallback on closed relays).

Error envelope for every 4xx/5xx on these routes is `api_error(status, msg)` →
`{"error": "<msg>"}` as JSON with that status (helper in `crates/buzz-relay/src/api/mod.rs`,
used everywhere as `api_error`/`internal_error`/`not_found`).

---

## 1. POST /query — channel-timeline read path (THE critical one)

Handler: `bridge.rs:880 query_events` → `bridge.rs:~940 query_events_authed`.

### Request
Body is a **JSON array of Nostr filters** (standard REQ filter objects), same as a WS `REQ`'s
filter list. Two-pass parse (`bridge.rs:~1000`): raw JSON is kept because `nostr::Filter` silently
drops unknown fields, and Buzz's extension fields live outside the standard schema. Extensions are
read off the **raw** filter Value, not the typed Filter:

| Field | Type | Meaning | Extractor |
|-------|------|---------|-----------|
| `top_level` | bool | Opt into the channel-window read-model (see below) | `extension_flag` `bridge.rs:283` |
| `include_summaries` | bool | Append 39005 thread-summary overlays | `extension_flag` |
| `include_aux` | bool | Append reaction/deletion/edit closure | `extension_flag` |
| `before_id` | 64-hex | Keyset cursor tiebreak (event id); pairs with `until` | `extract_before_id` `bridge.rs:~305` |
| `until` | unix secs | Keyset cursor timestamp; pairs with `before_id` | standard Filter field |
| `page` | u64 (>1) | Offset paging for non-window directory (kind:0) queries | `extract_page_offset` `bridge.rs:~250` |
| `thread_cursor`/`threadCursor` (+`thread_cursor_id`/`threadCursorId`) | i64 secs + hex | Thread-reply keyset cursor | `extract_thread_cursor` `bridge.rs:304` |
| `depth_limit`, `feed_types` | u32 / list | Thread/feed shaping (thread agent's area) | `extract_depth_limit` etc. |

Client build site (initial channel-window load) — `commands/channel_window.rs:19-35`:
```
{ "#h": [channelId], "kinds": TIMELINE_KINDS, "limit": cap,      // cap = min(rows,200), default 50
  "top_level": true, "include_summaries": true, "include_aux": true }   // + "until"/"before_id" only when paginating
```
- **(a) Initial load**: no `until`/`before_id` (head request). `limit` = `min(requested,200)`, default 50.
- **(b) Pagination**: adds `"until": cursor.created_at` AND `"before_id": cursor.event_id`
  (`channel_window.rs:32-33`). Both-or-neither is enforced; a lone `until` or lone `before_id` is a
  `400`, NOT a demote to head. Client derives the cursor from the 39006 bounds overlay it received
  (see response).
- **(c) NIP-50 search**: any filter with a `search` field routes to `handle_bridge_search`
  (`bridge.rs:~1020`). Mixing search and non-search filters in one request → `400 "mixed search and
  non-search filters not supported"`.

### Channel-window semantics (`top_level: true`) — `handle_channel_window_filter` bridge.rs:~410-585
- Requires exactly one `#h` channel or → `400 "top_level requires exactly one #h channel"`.
- Inaccessible channel → **empty result, 200** (access-scope skip, not an error).
- `before_id` present-but-malformed → `400 "top_level: before_id must be a 64-hex event id"`.
- Half cursor → `400 "top_level cursor requires both until and before_id, or neither"`.
- Row budget: default 50, max 200 (`BRIDGE_WINDOW_DEFAULT/MAX_LIMIT`). Overlays + aux do NOT
  consume the budget.

### Response — **bare JSON array of Nostr events** (`Json(Value::Array(...))`, `bridge.rs:~1025`)
There is **NO envelope object**. The array is heterogeneous and the client demultiplexes by `kind`.
For a `top_level` request the relay appends, in this order (`bridge.rs:~470-585`):
1. **Row events**: the actual channel messages, in keyset order (server's `created_at DESC, id ASC`).
2. **Aux closure** (if `include_aux`): reactions (7), deletions (5 / NIP-29 delete), edits, plus
   deletions-of-aux (second hop). Real stored events.
3. **Thread-summary overlays** (if `include_summaries`): one **relay-signed synthetic kind 39005**
   per row that has replies. `content` = `{reply_count, descendant_count, last_reply_at,
   participants:[hex...]}`; tags `["e",root],["d",root],["h",channel]`.
4. **Window-bounds overlay**: **exactly one relay-signed synthetic kind 39006** — the sole authority
   on exhaustion. `content` = `{"has_more": bool, "next_cursor": {"created_at": secs, "id": hex} | null}`;
   `d` tag = `"{channel}:{ts}:{id}"` or `"{channel}:head"`. The client reads `next_cursor` from this
   event to build the next page's `until`+`before_id`. **`rows < limit` proves nothing** — the final
   exact-multiple page still needs the 39006 to say `has_more:false`.

Non-window paths (feed/thread/catchall) and search return the same bare-array shape but without the
39005/39006 overlays. Presence filters (kinds = only `KIND_PRESENCE_UPDATE`/`_SNAPSHOT`) are
**synthesized from Redis**, returned as relay-built ephemeral events, never DB-queried
(`synthesize_presence` `bridge.rs:1920`).

### Read-path authorization (mirror of WS REQ; `bridge.rs:~975-990`)
- P-gated kinds (gift wraps, member notifications, observer frames): filter MUST carry `#p` = caller
  pubkey → else `403 "restricted: p-gated kinds require #p tag matching your pubkey"`.
- Agent-engram kinds: require `authors=[self]` or `#p=[self]` → else `403`.
- Author-only kinds: require `authors=[self]` → else `403`.
- Results are always filtered to channels the caller can access
  (`get_accessible_channel_ids_cached`).

---

## 2. POST /events — HTTP event ingest

Handler: `bridge.rs:613 submit_event` → `bridge.rs:~750 submit_event_authed`.

### Request
Body = **a single Nostr event JSON object** (not an array). Order of checks: admission (429) →
replay (401) → body parse → membership → ingest.

### Response
- **Accepted / duplicate / soft-reject-with-message**: `200` with
  `{"event_id": "<hex>", "accepted": <bool>, "message": "<string>"}` (`bridge.rs:~810`). Note a
  stored duplicate is still `accepted:true`-ish via the ingest result; the `accepted` bool is the
  ingest verdict, `message` is human text. **The client does not get a NIP-20 `OK` tuple over HTTP —
  it gets this object.**
- **Parse failure**: `400 {"error":"invalid event JSON: <serde msg>"}` (`bridge.rs:~770`).
- **Ingest rejected** (`IngestError::Rejected`): `400 {"error":"<full reason>"}` (`bridge.rs:~830`).
- **Auth failed at ingest** (`IngestError::AuthFailed`): `403 {"error":<msg>}`.
- **Internal**: `500 {"error":<msg>}`.
- Admission/replay/membership failures surface as their §0/§5 codes (429/401/403).

Desktop call sites: HTTP submit path in `desktop/src-tauri/src/relay.rs` and `relay/submit.rs`
(publish, command events, membership writes, snapshot/archive import). WS publish uses `["EVENT",...]`
+ `OK` instead; the HTTP path is used where a synchronous ack is wanted.

---

## 3. GET /info — NIP-11 doc & membership gate

Handler: `nip11.rs:172 relay_info_handler` → `nip11.rs:~300 nip11_document`. **Unauthenticated**,
served to unmapped hosts too. Returns a NIP-11 `RelayInfo` JSON. Key fields the client keys off:
- `supported_nips`: array of ints. **NIP-43 (relay membership) is advertised ONLY when membership
  is actually enforced AND the relay has a stable signing key** (`nip11_facts` `nip11.rs:~296`,
  `advertise_nip43 = has_stable_key && require_relay_membership`).
- `self` (`relay_self`): relay's stable signing pubkey hex, present whenever a stable key exists.
  Consumed by NIP-29/NIP-43 verification. Absent on ephemeral-key relays.
- `software`, `version`, `icon`, `limitation{...}`, `supported_extensions:["nip-er"]`, optional `push`.

Client decision (`commands/relay_members.rs:20-35`):
```
GET {base}/info → if !status.is_success() → error;
member-required := info.supported_nips.contains(43)
```
So the client's "does this relay require membership?" test is literally **"is 43 in supported_nips"**.
"Am I a member" is a **separate** step: the client reads the relay's replaceable **kind:13534
membership list** event (`KIND_NIP43_MEMBERSHIP_LIST`) via a normal query and checks if its pubkey is
in it (`get_my_relay_membership`, `relay_members.rs:57-88`) → `{"member": <role|null>}`.
`/info` itself returns no per-user membership. A non-200 from `/info` is treated as a hard error by
the client (no membership assumption).

---

## 4. WebSocket dialect

WS upgrade on `GET /` (content-negotiated against NIP-11). Verbs parsed in `protocol.rs:16-168`
(`ClientMessage`) and emitted in `protocol.rs:178-210` (`RelayMessage`). It's **vanilla Nostr relay
NIP-01 + NIP-42**, no Buzz-only verbs on the wire:

Client→relay: `["EVENT",<event>]`, `["REQ",<subId>,<filter>...]`, `["COUNT",<subId>,<filter>...]`,
`["CLOSE",<subId>]`, `["AUTH",<event>]`.
Relay→client: `["EVENT",<subId>,<event>]`, `["EOSE",<subId>]`, `["OK",<id>,<bool>,<msg>]`,
`["CLOSED",<subId>,<msg>]`, `["NOTICE",<msg>]`, `["AUTH",<challenge>]`.

### NIP-42 AUTH flow (mandatory, connection-first)
1. On connect the relay **immediately sends `["AUTH", <challenge>]`** before anything else
   (`connection.rs:157-191`, `RelayMessage::auth_challenge` = `["AUTH", challenge]`). It also acquires
   a connection semaphore permit first.
2. Client has **`AUTH_TIMEOUT` = 5s server-side** (`connection.rs:27`) to return a signed AUTH event,
   else the connection is dropped. Client-side auth timeout is **25s** (`relayClientSession.ts:63`).
3. Client builds a kind:22242 AUTH event with `createAuthEvent({challenge, relayUrl})`
   (`relayClientSession.ts:856-871`) — the **`relay` tag = the client's own relay WS URL**. Sends
   `["AUTH", event]`.
4. Server (`handlers/auth.rs:handle_auth`) verifies: challenge matches the pending one, signature
   valid, and the event's `relay` tag matches the tenant-expected relay URL (NIP-42 standard). Pure
   crypto — no tokens/JWT/DB. On closed relays it also runs `enforce_relay_membership` (with NIP-OA
   `auth` tag delegation extracted from the signed event, `extract_auth_tag_json` `auth.rs:~30`;
   **>1 `auth` tag ⇒ treated as none**, fail-closed).
5. Success → `["OK", <authEventId>, true, ""]`, connection state → Authenticated.
   Failure → `["OK", <authEventId>, false, "auth-required: verification failed"]` and state → Failed.
   A banned principal → `["OK",id,false,<reason>]` then immediate socket close.
   Already-authed / already-failed AUTH → `["OK",id,false,"auth-required: already ..."]`.
6. **REQ before auth** → the subscription is refused with `["CLOSED",subId,"auth-required:
   authenticate before subscribing"]` / `"auth-required: not authenticated"` (`req.rs:78-82`).

**Client-side terminal rule**: a `kind:22242` `OK=false` marks the session **terminal — no reconnect**
until the user re-engages (community switch / explicit preconnect) (`relayReconnectPolicy.ts` doc +
`relayClientSession.ts:921 resetConnection(err,{reconnect:false})`). This is the ONLY thing that
makes a session non-reconnecting.

### REQ → EOSE
`req.rs:43`: register subscription, deliver historical events (`["EVENT",subId,ev]` each), then
**always** `["EOSE",subId]` (`req.rs:408`, and every early-return path also EOSEs — empty/no-access →
immediate EOSE, `req.rs:523/730`). Live events stream as `["EVENT",subId,ev]` after EOSE. NIP-50
search REQ hits Postgres FTS then EOSEs (`req.rs:418`).

### What triggers re-AUTH
There's no periodic re-AUTH. Re-auth happens **only on reconnect** (new socket → new challenge). The
client caches `relayUrl` and re-runs `handleAuthChallenge` on each fresh connection. A `["CLOSED",
subId, "auth-required: ..."]` on a live sub triggers `handleRelayClosed` which re-sends the REQ (with
reconnect-retry) rather than a bare re-auth (`relayClientSession.ts:832-843`).

---

## 5. Rate limiting (HTTP 429)

Server (`bridge.rs:30-66 enforce_http_admission`): per-principal quota
`rate_limits.human_api_calls_per_min` over a 60s window. On exceed →
**`429 {"error":"rate-limited: quota exceeded; retry in <N>s"}`**. No `Retry-After` header — the
retry hint is **embedded in the body string** in the canonical form `... retry in <N>s`. Shared
admission unavailable → `503 {"error":"rate-limited: shared admission unavailable"}`. The same
`retry in Ns` grammar is also used in WS `CLOSED`/`NOTICE` messages.

Client (`desktop/src-tauri/src/relay.rs:233-295`, `relay_admission.rs`):
- `extract_retry_in_hint(body)` finds `"retry in "` and parses the integer seconds (`relay.rs:237`).
  Overflow/garbage → `None`.
- On 429 → `activate_rate_limit(capped_hint)` arms a **process-wide shared gate**; all relay HTTP
  calls `wait_for_rate_limit()` before `.send()`. Hint-less 429 → **10s default**
  (`DEFAULT_RATE_LIMIT_SECONDS`); hint is capped at a max; overlapping 429s extend, never shorten,
  the window. Gate is reset per-community switch so community A's 429 can't stall B.
- WS `NOTICE` starting `"rate-limited:"` also arms the TS gate (`relayClientSession.ts:846-852`).

**Contract for the bridge**: emit `429` with body `{"error":"rate-limited: ... retry in <N>s"}` (or
omit the hint to get the client's 10s default). A `Retry-After` header is ignored.

---

## 6. Reconnect / shutdown contract (v0.4.24)

Server graceful shutdown (`main.rs:1099-1150`, `state.rs:336-372`):
- On SIGTERM: set `shutting_down`, start **30s graceful drain**, and call
  `conn_manager.drain_all()` which sends **every live WS connection a Close frame with code
  `1012` (Service Restart), reason `"relay restarting"`** (`state.rs:368 restart_close_frame`,
  `CloseFrame{ code:1012, reason:"relay restarting" }`), then cancels each connection.
  Late-registering connections during the drain window also get the 1012 (`state.rs:236`).
- During the pre-drain grace window, **new** HTTP/WS hits on `/` get
  `503 "relay restarting"` (`router.rs:306-310`).

Client keys off the close code (`relayReconnectPolicy.ts:45-66`, `relayClientSession.ts:772-776`):
- The Tauri WS plugin delivers a message `{type:"Close", data:{code, reason}}`. `isWebSocketClose`
  = `message.type === "Close"`. `isServiceRestartClose` = that **AND `data.code === 1012`**.
- On a **1012** close → **reset reconnect backoff to base (1s)** = fast-track reconnect (#2579):
  `if (isServiceRestartClose(message)) this.reconnectDelayMs = RECONNECT_BASE_DELAY_MS`
  (`relayClientSession.ts:773-774`), then `resetConnection`. Any other close code → normal exponential
  backoff (base 1s, ×2, cap 30s, ±25% jitter — `relayClientSession.ts:985-993`,
  `RECONNECT_BASE_DELAY_MS=1000`, `RECONNECT_MAX_DELAY_MS=30000`).
- Backoff only resets to base after a connection stays **stable for `BACKOFF_RESET_STABLE_MS`**
  post-AUTH (`relayClientSession.ts:589-592`) — flapping doesn't erase backoff. 1012 is the exception
  that resets immediately.
- `shouldScheduleReconnect` (`relayReconnectPolicy.ts:32-39`): reconnect only if NOT terminal, NOT
  already pending, NO live socket, AND (keepAlive requested OR live subscriptions). Failed initial
  dial (#2564) still schedules via the `ensureConnected().catch(scheduleReconnect)` loop
  (`relayClientSession.ts:995-1000, 1090`).

**Contract for the bridge**: on graceful shutdown/restart, send WS Close **1012 "relay restarting"**
to every connection (so clients fast-reconnect instead of eating full backoff), and answer new
requests with `503` during drain. A plain TCP reset / 1006 works but costs the client full backoff.

---

## 7. Kind passthrough — what's opaque vs special-cased

Kind constants live in `buzz_core::kind` (the 59 `KIND_*`). The relay stores+serves **most kinds
opaquely** (standard NIP-01 insert + filter match). Special-case server logic is limited to:

**Ingest side-effects** (`handlers/side_effects.rs:148,292` `match kind`):
- `9000..=9022` — NIP-29 group moderation commands (execute an action, not just store).
- `9002`, `9007` — archive / unarchive requests (`side_effects.rs:266,283`).
- `0` (metadata), `KIND_AGENT_PROFILE` → `handle_agent_profile`; `KIND_GIT_REPO_ANNOUNCEMENT` →
  `handle_git_repo_announcement`; `41001..=41003`, `40099` — replaceable/thread-meta special paths.
- Relay **emits** (relay-signed, not client-writable): `KIND_MEMBER_ADDED/REMOVED_NOTIFICATION`,
  `KIND_NIP29_GROUP_METADATA/ADMINS/MEMBERS`, `KIND_NIP43_MEMBERSHIP_LIST` (kind:13534, single
  replaceable member list), `KIND_THREAD_SUMMARY` (39005), `40099`.

**Read/query special-casing** (`bridge.rs` + `req.rs`):
- `KIND_PRESENCE_UPDATE` / `KIND_PRESENCE_SNAPSHOT` — **synthesized from Redis**, never persisted or
  DB-queried (`synthesize_presence` `bridge.rs:1920`); ephemeral.
- `KIND_THREAD_SUMMARY` (39005) + `KIND_WINDOW_BOUNDS` (39006) — **synthetic relay-signed overlays
  injected into /query results**, never stored (thread agent covers 39005 detail).
- Aux closure kinds: `KIND_DELETION`(5), `KIND_REACTION`(7), `KIND_NIP29_DELETE_EVENT`,
  `KIND_STREAM_MESSAGE_EDIT` (`req.rs:385-393`).
- Access-gated read classes: **P-gated** (gift wraps, member notifications, observer frames — need
  `#p`=self), **engram** (need self authors/#p), **author-only** (`AUTHOR_ONLY_KINDS` — need
  authors=self). Enforced identically on WS REQ and HTTP /query.
- Ingest validation kinds (`event.rs:1141-1197`): `KIND_AGENT_OBSERVER_FRAME`, `KIND_CANVAS`,
  `KIND_FORUM_POST/VOTE/COMMENT`, `KIND_STREAM_MESSAGE/_DIFF`, `KIND_PRESENCE_UPDATE`,
  `KIND_DM_VISIBILITY` get structural validation beyond generic event checks.

Everything else = opaque store + filter-serve.

---

## Skipped (M1b / cut) — location pointers
- Media/Blossom: `api/media.rs`, `/upload` `/media/upload` (`router.rs:38-41`).
- Invites/join-policy: `api/invites.rs`, `/api/invites*`, `/api/join-policy` (`router.rs:95-111`).
- Huddle audio: `/huddle/{channel_id}/audio` WS (`router.rs:~120`), `audio/`.
- Git smart-HTTP: `api/git/*`.
- Pairing / NIP-11 push descriptor detail: `nip11.rs:push_descriptor` (APNs), `pairing_relay_url`.
- Operator/moderation admin: `/operator/*`, `/moderation/*`, `/api/admin/v1/*`.

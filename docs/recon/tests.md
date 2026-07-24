# M1a Relay-Mode Conformance Gate — Recon

Read-only recon of `/Users/davidirvine/Desktop/Devel/projects/tic-tac-toe/desktop/`.
Nothing modified. All paths absolute. File:line refs against the working tree
as of the session (imported Buzz upstream 0.4.24).

Scope: define the exact contract a drop-in x0x-nostr-bridge must satisfy so
Buzz's relay-mode Playwright suites pass with our bridge in place of Block's
`buzz-relay`.

---

## 0. The single most important structural fact

There are **THREE distinct test execution modes**, not one, and only ONE of
them is the M1a gate:

| Mode | How a spec selects it | Talks to a real relay? | Provisioning |
|------|----------------------|------------------------|--------------|
| **Mock** | `installMockBridge(page, …)` (default) | No | none — `e2eBridge.ts` fakes all Tauri IPC |
| **Relay (config) mode** | `installRelayBridge(page, user)` → `installBridge({mode:"relay"})` | **YES — this is M1a** | external relay at `BUZZ_E2E_RELAY_URL` (default `http://localhost:3000`), pre-seeded out-of-band |
| **Live gate** | `TwoRelayHarness` spawns a real `buzz-relay` binary | Yes, but **skip-by-default** | spawns `BUZZ_E2E_RELAY_BIN` + needs Postgres + Redis; gated behind `BUZZ_E2E_*=1` |

**M1a = "Relay (config) mode".** The five-minute demo runs the relay-mode
specs (`installRelayBridge`) against our bridge listening on the
`BUZZ_E2E_RELAY_URL` endpoint. "Zero relay servers" in the plan means zero
**Block** relay servers — our bridge is the only server. It does NOT mean the
`TwoRelayHarness` live gate (that spawns Block's binary and is out of M1a — it
needs the real Rust relay + Postgres + Redis and is skipped unless explicitly
enabled).

---

## 1. Playwright topology

Three config files at `desktop/`:

### `playwright.config.ts` (the default; `pnpm test:e2e`)
- `testDir: ./tests/e2e`, `timeout: 30_000`, `workers: 1`, `retries: CI?2:0`.
- `use.baseURL: http://127.0.0.1:4173`.
- `webServer.command: "python3 -m http.server 4173 -d dist"` — serves the
  **static** `dist` produced by `pnpm build:e2e` (`tsc && vite build --mode
  e2e`). **No relay is started by Playwright.** `reuseExistingServer: !CI`.
- **Two projects**:
  - **`smoke`** (`playwright.config.ts:19-123`) — ~115 explicit `testMatch`
    globs. All **mock mode**. Includes the deceptively-named
    `relay-reconnect.spec.ts`, `relay-reconnect-affordance.spec.ts`,
    `relay-connectivity.spec.ts` — these use the **mock websocket seam**, not a
    real relay (see §6).
  - **`integration`** (`playwright.config.ts:124-150`) — 16 `testMatch` globs,
    `expect.timeout: CI?15000:10000`. **Mixed**: some specs are mock, four are
    the real relay-mode M1a specs, two are skip-by-default live specs.

### `playwright.live.config.ts` (13 lines, `agents-everywhere` live gate only)
```ts
testDir: "./tests/e2e",
testMatch: "**/agents-everywhere.live.spec.ts",
timeout: 90_000, workers: 1, reporter: "list",
```
No `webServer` (the live spec spawns its own relay via harness). Out of M1a.

### `playwright.perf.config.ts` (perf profiling)
- `testMatch: ["**/*.perf.ts"]`, `timeout: 60_000`, same static `dist`
  webServer. Picks up `scrollback-buzzbugs.perf.ts` (which IS relay-mode) and
  `cold-switch-longtask.perf.ts` (mock). Perf, not a correctness gate — treat
  as adjacent to M1a, not part of it.

### package.json scripts (`desktop/package.json`)
```
test:e2e             = pnpm build:e2e && playwright test
test:e2e:smoke       = pnpm build:e2e && playwright test --project=smoke
test:e2e:integration = pnpm build:e2e && playwright test --project=integration
```
There is **no dedicated relay-mode script and no globalSetup**. Relay-mode
specs live inside `--project=integration` and self-provision via each spec
calling `assertRelaySeeded()` in `beforeAll` (see §2). Running
`test:e2e:integration` with no relay up will fail the four relay-mode specs at
`assertRelaySeeded()` and pass the mock ones.

---

## 2. Relay provisioning — the seam our bridge slots into

There is **no fixture that spawns a relay for config-mode specs**. The relay is
**external and pre-seeded**. Two helpers define the contract:

### 2a. Client wiring — `tests/helpers/bridge.ts`
```ts
const DEFAULT_RELAY_HTTP_URL = process.env.BUZZ_E2E_RELAY_URL ?? "http://localhost:3000";
const DEFAULT_RELAY_WS_URL   = DEFAULT_RELAY_HTTP_URL.replace(/^http/, "ws");

export async function installRelayBridge(page, user="tyler", options?) {
  await installBridge(page, {
    mode: "relay",
    user,
    relayHttpUrl: DEFAULT_RELAY_HTTP_URL,   // both transports threaded explicitly
    relayWsUrl:   DEFAULT_RELAY_WS_URL,
    seedPreviewFeatures: options?.seedPreviewFeatures,
  });
}
```
`installBridge` (bridge.ts) does three localStorage seeds via
`page.addInitScript` before app boot: `seedDefaultCommunity` (stamps a
community with the active identity's pubkey so onboarding is skipped),
`seedOnboardingCompletionForKnownIdentities`, `seedPreviewFeaturesEnabled`; then
sets `window.__BUZZ_E2E__ = { mode, identity, relayHttpUrl, relayWsUrl, … }`.
In relay mode the identity is `TEST_IDENTITIES[user]`.

### 2b. Readiness gate — `tests/helpers/seed.ts::assertRelaySeeded()`
Every relay-mode spec calls this in `beforeAll`:
- callers: `integration.spec.ts:180`, `stream.spec.ts:189`,
  `dm-double-notification.spec.ts:67`, `parity-ancestor-island.spec.ts:43`.
- It polls `POST http://localhost:3000/query` with header `X-Pubkey:
  <tyler>` and body `[{ kinds:[39000], limit:200 }]` until it sees a
  kind-39000 channel-metadata event whose tags contain `["name","general"]`.
- Timeout: `BUZZ_E2E_SEED_TIMEOUT_MS` (CI 60s / local 25s), per-request
  `BUZZ_E2E_SEED_REQUEST_TIMEOUT_MS` (CI 5s / local 2s), retry 1s.
- **HOST MATTERS**: the relay is multi-tenant and resolves tenant from the
  `Host` header against a communities host-map, failing closed with **404** on
  an unmapped host. The seed maps host `localhost:3000`, and `localhost` !=
  `127.0.0.1` under `normalize_host`. So the whole suite MUST hit
  `localhost:3000`, never `127.0.0.1:3000`. Our bridge must (a) accept a
  `Host: localhost:3000` and treat it as the demo community, and (b) either
  serve kind-39000 for `general` from startup or reconcile seeded data into
  39000/39002 emits.
- Failure message literally says: *"Start the relay and run
  scripts/setup-desktop-test-data.sh."*

### 2c. Out-of-band seed scripts — REFERENCED BUT ABSENT FROM THE TREE
`start-relay-for-tests.sh` and `setup-desktop-test-data.sh` are **not present**
anywhere under `tic-tac-toe/` (find returns nothing; only comment references
exist in `seed.ts:77`, `seedRelay.ts:20,25`, `dm-double-notification.spec.ts:14`).
They live in the upstream Buzz `buzz-relay` repo, which was **not imported** into
`desktop/`. What they establish (from the comments):
- `start-relay-for-tests.sh` runs the relay with `BUZZ_REQUIRE_AUTH_TOKEN=false`
  so `POST /events` accepts a plain `X-Pubkey` header (dev-auth fallback in
  `bridge.rs verify_bridge_auth`); the event body is still fully signed, only the
  per-request NIP-98 envelope is skipped.
- `setup-desktop-test-data.sh` inserts DB rows the relay reconciles at startup
  into kind:39000 (channel metadata) / 39002 events, and seeds **tyler, alice,
  bob, charlie as members of `general`** (required because
  `enforce_relay_membership` rejects events from non-members). It also creates
  the DM channel `alice-tyler` with a deterministic id =
  `uuid5(NAMESPACE_DNS, "buzz.channel.dm.alice-tyler")`.

**Process contract a drop-in bridge must provide (config mode / M1a):**
1. HTTP endpoint on `http://localhost:3000` (or `BUZZ_E2E_RELAY_URL`) +
   matching WS on `ws://localhost:3000`.
2. `POST /query` — accepts a JSON array of Nostr filters (+ Buzz extensions,
   §4), returns a JSON array of raw Nostr events. Honors `X-Pubkey` as the
   requester identity. Tenant-resolves on `Host` and does NOT 404 for
   `localhost:3000`.
3. `POST /events` — accepts ONE signed Nostr event per request, header
   `X-Pubkey`, `BUZZ_REQUIRE_AUTH_TOKEN=false` dev-auth path; returns
   `{ event_id, accepted, message }`.
4. NIP-42 AUTH over WS (§3) + REQ/EVENT/EOSE/CLOSE (§3).
5. Pre-seeded community `general` with members tyler/alice/bob/charlie, plus
   whatever a given spec seeds live via `seedScenario` (§4b). Must serve
   kind-39000 for `general` on startup so `assertRelaySeeded()` passes.
6. Channel-window read-model: assemble 39005 summaries + 39006 bounds (§4a) —
   the single hardest requirement.

The `TwoRelayHarness` (`tests/e2e/helpers/twoRelayHarness.ts`) is a **separate**
provisioning path used ONLY by the two live specs — it is the closest thing to
a "process contract" reference and worth mirroring even though it's out of M1a:
- `startRelays(binary = BUZZ_E2E_RELAY_BIN)` spawns with env:
  `DATABASE_URL`, `REDIS_URL`, `RELAY_URL=ws://127.0.0.1:{main}`,
  `BUZZ_BIND_ADDR=127.0.0.1:{main}`, `BUZZ_HEALTH_PORT`, `BUZZ_METRICS_PORT`,
  `BUZZ_REQUIRE_AUTH_TOKEN=false`, `BUZZ_RECONCILE_CHANNELS=true`.
- Readiness: `GET http://127.0.0.1:{health}/_readiness` until 200, 30s deadline.
- Teardown: SIGTERM → 5s → SIGKILL → 2s; process-group kill (`detached`).
- `terminateRelayGracefully()` SIGTERMs and waits (never SIGKILL) — exercises
  the graceful drain: readiness 503 → 5s grace → 1012 close broadcast →
  listener drain. `restartRelay()` re-spawns on the same ports.

---

## 3. Identity / auth in relay mode

### Identities — `tests/helpers/bridge.ts::TEST_IDENTITIES`
Hardcoded hex keypairs (private + public), shared by client wiring AND
`seedRelay.ts` signing:
| user | pubkey (hex) |
|------|--------------|
| tyler | `e5ebc6cdb579be112e336cc319b5989b4bb6af11786ea90dbe52b5f08d741b34` |
| alice | `953d3363262e86b770419834c53d2446409db6d918a57f8f339d495d54ab001f` |
| bob | `bb22a5299220cad76ffd46190ccbeede8ab5dc260faa28b6e5a2cb31b9aff260` |
| charlie | `554cef57437abac34522ac2c9f0490d685b72c80478cf9f7ed6f9570ee8624ea` |
(a 5th `df8e91…` identity also exists.) These pubkeys are baked into seeded
state, so the bridge's membership/ACL must recognise exactly these keys.

### HTTP auth (config-mode reads/writes go through `e2eBridge.ts`)
`relayJsonRequest`/`relayQuery`/`submitSignedEvent` set header **`X-Pubkey:
<identity.pubkey>`** and `Content-Type: application/json`. Writes are fully
signed via `signWithIdentity` (nostr-tools `finalizeEvent`) then `POST /events`.
There is **no NIP-98 / bearer token** in config mode — the dev-auth fallback
(`BUZZ_REQUIRE_AUTH_TOKEN=false`) is assumed. Our bridge must accept `X-Pubkey`
as the caller identity on `/query` and `/events`.

### WS auth — NIP-42 (production client, `src/shared/api/relayClientSession.ts`)
The **real app** (not the bridge) opens the WS in relay mode and runs NIP-42:
- `AUTH_TIMEOUT_MS = 25_000` (relayClientSession.ts:63); connection must stay
  stable a while post-AUTH.
- On `["AUTH", <challenge>]` (line 805) → `handleAuthChallenge` (line 856) →
  `createAuthEvent({ challenge, relayUrl })` → `sendRaw(["AUTH", <signed event>])`
  (line 871). Standard NIP-42 kind-22242 client-auth event.
- Also handles `CLOSED` (restores subscriptions), `NOTICE rate-limited:` (back-pressure gate).
- The connection state the tests poll (`__BUZZ_E2E_GET_RELAY_CONNECTION_STATE__`
  → `relayClient.getConnectionState()`) reaches `"connected"` only after a
  successful AUTH.
=> **Our bridge MUST implement the full NIP-42 challenge/response over WS**, or
the client never reaches `connected` and every relay-mode spec times out.

### Membership
Established **out-of-band** by `setup-desktop-test-data.sh` (tyler/alice/bob/
charlie in `general`) plus per-spec `seedScenario` writes. No in-test invite
flow, no admin HTTP call — invites are M1b. The bridge just has to honour the
pre-seeded membership set and `enforce_relay_membership` semantics (reject
non-member authors on `/events`).

---

## 4. The `/query` + `/events` contract (exactly what the client sends)

All from `src/testing/e2eBridge.ts` relay-mode ("Config mode") branches.

### 4a. Channel window read-model — `handleGetChannelWindow` (HARDEST)
Relay-mode filter sent to `POST /query` (mirrors server `build_channel_window_filter`):
```json
{ "#h": ["<channelId>"], "kinds": [<TIMELINE_KINDS>], "limit": <=200 default 50,
  "top_level": true, "include_summaries": true, "include_aux": true,
  "until": <cursor.created_at>, "before_id": <cursor.event_id> }   // until+before_id both-or-neither
```
Expected response = a **flat event array the relay assembles**:
1. top-level rows, **newest first**;
2. the **aux closure** (ancestor/related events needed to render);
3. relay-signed **kind-39005 thread summaries**;
4. **exactly one kind-39006 bounds event** carrying `has_more` + `next_cursor`.

The client derives cursor + exhaustion **solely from the 39006 bounds event**,
never from the rows. Doc comment: *"without it the relay-mode bridge has no
handler and the timeline renders empty."* This is the primary read path — the
whole timeline depends on it.

### 4b. Thread pane keyset — `get_channel_messages_before` / thread window
```json
{ "#h": ["<channelId>"], "kinds": [<TIMELINE_KINDS>], "until": <before>,
  "limit": <=500 default 200, "before_id": <beforeId?> }
```
and the thread-cursor variant adds `thread_cursor` / `thread_cursor_id`
(composite `(created_at, event_id)` keyset). Client computes `next_cursor` from
the last row when `page.length >= cap`. Gap-free `(created_at, event_id)` keyset
paging — same-second ties must not be skipped or double-served (the exact defect
`parity-ancestor-island` and `scrollback-buzzbugs.perf` guard).

### 4c. NIP-50 search — `search_messages`
```json
{ "kinds": [9, 40002], "search": "<query>", "limit": <default 20> }
```
Client maps hits → `{event_id, pubkey, content, created_at, kind, tags, sig,
channel_id (from "h" tag), channel_name:null, score:1.0}`. So the bridge must
support the `search` filter field over `/query` for kinds 9 (channel message)
and 40002.

### 4d. Single event by id — `get_event`
```json
{ "ids": ["<eventId>"], "limit": 1 }
```

### 4e. Writes — `submitSignedEvent` → `POST /events`
Body = one signed event `{kind, content, tags, id, pubkey, sig, created_at}`;
returns `{event_id, accepted, message}`. Canonical Buzz tag shapes (from
`seedRelay.ts`, mirroring `buzz-sdk builders.rs`):
- top-level: `["h", channelId]` (no e-tag → thread depth NULL)
- direct reply: `["e", parentId, "", "reply"]`
- nested reply: `["e", rootId, ...]` + reply marker

### 4f. p-gated filter authorization
`relayQuery` refuses to send a filter unless `isPGatedFilterAuthorized(filter,
identity.pubkey)` — i.e. any `#p`-scoped query must include the caller's own
pubkey. Client-side guard; the bridge just needs to behave consistently for
p-tag scoped reads (DM inbox).

---

## 5. Multi-relay / multi-community

**M1a is single-relay, single-community, multi-client.** The four config-mode
specs use up to two browser contexts (`installRelayBridge(pageOne,"tyler")` +
`installRelayBridge(pageTwo,"alice")`) but both point at the **same**
`BUZZ_E2E_RELAY_URL` and the same `general` community. Cross-user delivery is
tested by two clients on one relay, not two relays.

Only `agents-everywhere.live.spec.ts` uses **two relays** (`TwoRelayHarness`
with two `RelaySpec`s) — and that is a skip-by-default live gate, not M1a.

=> **Bridge v2 does NOT need multi-instance or multi-community-per-instance for
the M1a gate.** One bridge instance serving one community (host `localhost:3000`)
with multiple authenticated clients is sufficient. (Multi-relay-per-community is
Buzz's model = one relay per community anyway; M1a never exercises >1.)

---

## 6. The 0.4.24 reconnect additions & the e2eBridge seam

### `relay-reconnect.spec.ts` / `relay-reconnect-affordance.spec.ts` — MOCK, not real relay
These are in the **smoke** project and drive the **mock websocket seam** in
`e2eBridge.ts`, NOT a real relay:
- `window.__BUZZ_E2E_DISCONNECT_MOCK_WEBSOCKETS__()` — disconnects mock sockets.
- `window.__BUZZ_E2E_RESTART_MOCK_WEBSOCKETS__()` — sends `sendWsClose(handler,
  1012, "relay restarting")` to each mock socket (synthesises the 1012 the
  reconnect UI reacts to).
- `window.__BUZZ_E2E_SET_RELAY_CONNECTION_STATE__(state)` — pokes the production
  `relayClient.connectionStateEmitter` directly to drive degraded UI without a
  real ~10s auth-timeout/reconnect cycle.
So the client's 1012 handling is proven **against a mock**, and these specs need
**nothing from our bridge** — they pass in mock mode regardless.

### `relay-restart.live.spec.ts` — real relay, skip-by-default (NOT M1a)
Gated `test.skip(BUZZ_E2E_RELAY_RESTART !== "1")`. Boots a real relay via
`TwoRelayHarness`, `installBridge({mode:"relay", user:"tyler", relayHttpUrl,
relayWsUrl})`, waits for `connectionState === "connected"`, SIGTERMs the relay
(graceful drain: readiness 503 → 5s grace → **1012 close broadcast** → listener
drain), restarts on the same port, asserts the client returns to `"connected"`.
This is the only test that requires the **server** to emit a real 1012 on
graceful shutdown + accept a fresh dial on the same port. Needs
`BUZZ_E2E_RELAY_BIN` + `BUZZ_E2E_DATABASE_URL` + Redis. **Out of M1a** unless we
choose to also make our bridge honour SIGTERM→1012→restart (a later milestone).

### The "Relay state seam is not installed" flake
`connectionState(page)` reads `window.__BUZZ_E2E_GET_RELAY_CONNECTION_STATE__?.()
?? "uninstalled"`. That seam is wired at the **end** of `e2eBridge.ts install()`
(`installed = true`), which runs when the app bootstraps the mocked
`__TAURI_INTERNALS__`. The flake = the spec calls `connectionState()` /
`__BUZZ_E2E_SET_RELAY_CONNECTION_STATE__` **before** `install()` has completed
(before `page.goto("/")` has booted the app + constructed the `relayClient`
singleton). The seam exposes the production `relayClient`'s connection state
(`getConnectionState()`), so it only exists once the app module graph has run.
It is a client-side ordering issue, **not a bridge requirement** — but any M1a
spec that polls connection state must `await page.goto("/")` and poll with a
timeout (the live spec uses `expect.poll(..., {timeout:60_000})`).

---

## 7. Relay-mode spec inventory (the M1a gate)

Config-mode specs (`installRelayBridge`, need our bridge on `localhost:3000`),
all in `--project=integration` except the perf one:

| Spec | Purpose | Assertion focus |
|------|---------|-----------------|
| `tests/e2e/integration.spec.ts` | Core relay round-trips: create channel, two users see same channel, message delivery across users, live mention refetch of home feed, DM channel appears + send DM, forum channel | channel list from `/query`, cross-client delivery via WS live REQ, home-feed/inbox live update, DM path, `message-timeline` contains text |
| `tests/e2e/stream.spec.ts` | Relay-backed streaming/timeline: loads channels + home feed from relay, sends through real relay, real-time delivery to 2nd context, scroll-pinning (bottom-pin, pin after send+remote reply, composer growth, arrivals above fold) | live EVENT fan-out, timeline pinning/scroll under real relay latency |
| `tests/e2e/dm-double-notification.spec.ts` | An incoming DM produces exactly ONE desktop notification | DM delivery + notification dedupe; DM channel id = `uuid5(DNS,"buzz.channel.dm.alice-tyler")` |
| `tests/e2e/parity-ancestor-island.spec.ts` | Thread history frontier: an ancestor island does not strand the frontier (Dawn/Wren cursor-poisoning root cause) | thread `/query` keyset, gap-free paging, `seen.size > GAP_COUNT*0.9` |
| `tests/e2e/scrollback-buzzbugs.perf.ts` | (perf, not correctness) scroll-back latency of the read-model window | one 50-row page per trigger, composite `(until,before_id)` keyset, 39006 bounds — perf profile |

Skip-by-default live specs (real binary, **NOT M1a**):
`agents-everywhere.live.spec.ts` (two-relay agent gate,
`BUZZ_E2E_AGENTS_EVERYWHERE=1`), `relay-restart.live.spec.ts`
(`BUZZ_E2E_RELAY_RESTART=1`).

Relay-*named* but mock (NOT relay-mode, pass without our bridge):
`relay-reconnect.spec.ts`, `relay-reconnect-affordance.spec.ts`,
`relay-connectivity.spec.ts`, `sidebar-relay-card.spec.ts`,
`relay-restart` mock paths.

### What M1a explicitly does NOT need
Media/Blossom (`PUT /upload`, `GET /media/*`, `buzz-media://`) is **M1b**.
Invites, git/project history kinds, huddle, and the two-relay/agents-everywhere
live gate are all outside M1a. The mock-mode bulk (screenshots, onboarding,
channel UI, reactions, reminders, etc.) needs nothing from the bridge.

---

## 8. Showstoppers / risks for a drop-in bridge

1. **The 39005/39006 channel-window assembly (§4a)** is the make-or-break. The
   client renders an empty timeline unless `POST /query` with
   `top_level+include_summaries+include_aux` returns rows + aux + kind-39005
   summaries + exactly one kind-39006 bounds with `has_more`/`next_cursor`. This
   is a server-side read-model, not plain Nostr filtering — the bridge must
   compute `thread_metadata` at ingest and emit relay-signed 39005/39006. This
   is the "riskiest coupling" the plan itself flags.
2. **NIP-42 AUTH over WS is mandatory** — no `connected`, no tests. Plus
   REQ/EVENT/EOSE/CLOSE live subscriptions with `#h` and `#p` filters, and
   CLOSED-subscription restoration.
3. **Host-based tenant resolution** — the bridge must treat `Host:
   localhost:3000` as the demo community and NOT 404. `localhost` != `127.0.0.1`.
4. **Pre-seeded state** — the two absent scripts
   (`start-relay-for-tests.sh`, `setup-desktop-test-data.sh`) are NOT in the
   tree; we must reproduce their effect: `general` channel (kind-39000) +
   tyler/alice/bob/charlie membership + the `alice-tyler` DM channel with the
   deterministic uuid5 id, served before `assertRelaySeeded()` deadlines.
5. **Composite keyset paging fidelity** — `(created_at, event_id)` with correct
   same-second tiebreak (id ASC forward-walk), or `parity-ancestor-island` and
   the perf scrollback break. The client trusts the relay's ordering exactly.

No spec hardcodes Block-relay-only behaviour that a conforming Nostr+bridge
cannot satisfy: everything routes through `X-Pubkey` + `/query` + `/events` +
WS NIP-42. The coupling is to the **Buzz query dialect** (window read-model,
thread_metadata, keyset), not to Block infrastructure.

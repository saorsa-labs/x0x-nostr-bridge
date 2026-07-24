//! History store — durable Nostr window/thread read model (bridge-v2 M1a). Owner: WP1.
//!
//! `HistoryStore` is the public entry point the HTTP/WS lane (WP2/WP3) calls. It
//! owns a single `rusqlite::Connection` behind a `std::sync::Mutex`/`Arc` and
//! offloads every (synchronous) DB unit onto `spawn_blocking`, mirroring the
//! spike's `store.rs`. The whole ingest-plus-recursive-drain is one SQLite
//! transaction.
//!
//! Module layout (design §4 WP1):
//! - `schema` — the §3 schema + community-fingerprint guard.
//! - [`engine`] — the thread engine (`thread_engine.rs` in the design; kept as
//!   `history::engine` so it can share the store's connection/transaction type
//!   without leaking it publicly).
//! - `read` — the window/thread/summary read surface.
//! - [`types`] — the public request/response types.

pub mod engine;
mod query;
mod read;
mod schema;
pub mod types;

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use nostr::{Event, Filter};

pub use engine::{canonical_event_id, is_relay_authored_kind};
pub use types::{
    Door, FilterSpec, IngestEffects, LocalIngest, MeshIngest, RelayStoreOutcome, ThreadCursor,
    ThreadEmit, ThreadPage, ThreadSummary, WindowBounds, WindowCursor, WindowPage,
};

use engine::CoreOutcome;

/// Durable history store for one community.
pub struct HistoryStore {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl HistoryStore {
    /// Open (or create) the store at `path`, bound to `community_fingerprint`.
    /// Refuses to open a DB whose stored fingerprint differs (§3 scope guard).
    pub fn open(path: &Path, community_fingerprint: &str) -> Result<Self> {
        let conn = rusqlite::Connection::open(path)
            .with_context(|| format!("failed to open history db at {}", path.display()))?;
        Self::init(conn, community_fingerprint)
    }

    /// In-memory store (tests / ephemeral use).
    pub fn open_in_memory(community_fingerprint: &str) -> Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()
            .context("failed to open in-memory history db")?;
        Self::init(conn, community_fingerprint)
    }

    fn init(conn: rusqlite::Connection, community_fingerprint: &str) -> Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
        schema::migrate(&conn)?;
        schema::check_or_write_fingerprint(&conn, community_fingerprint)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    // ---- two-door ingest ---------------------------------------------------

    /// Strict local door (HTTP `/events`, WS `EVENT`): orphan replies REJECTED,
    /// root verified server-side, depth cap enforced.
    pub async fn ingest_local(&self, ev: &Event) -> Result<LocalIngest> {
        let out = self.ingest(ev.clone(), Door::Local).await?;
        Ok(match out {
            CoreOutcome::Accepted(e) => LocalIngest::Accepted(e),
            CoreOutcome::Rejected(r) => LocalIngest::Rejected(r),
            // The local door never parks/quarantines; treat as a hard reject
            // if the engine ever returns one (defensive; unreachable).
            CoreOutcome::Parked => {
                LocalIngest::Rejected("invalid: reply parent not found".to_string())
            }
            CoreOutcome::Quarantined(r) => LocalIngest::Rejected(r),
        })
    }

    /// Tolerant mesh door (x0x gossip): missing parent -> park, ancestry
    /// mismatch -> quarantine. Parked/quarantined events are invisible to every
    /// served surface.
    pub async fn ingest_mesh(&self, ev: &Event) -> Result<MeshIngest> {
        let out = self.ingest(ev.clone(), Door::Mesh).await?;
        Ok(match out {
            CoreOutcome::Accepted(e) => MeshIngest::Accepted(e),
            CoreOutcome::Parked => MeshIngest::Parked,
            CoreOutcome::Quarantined(r) => MeshIngest::Quarantined(r),
            // The mesh door only "rejects" relay-authored kinds, which the
            // engine already quarantines; map defensively.
            CoreOutcome::Rejected(r) => MeshIngest::Quarantined(r),
        })
    }

    async fn ingest(&self, ev: Event, door: Door) -> Result<CoreOutcome> {
        let now = now_unix();
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<CoreOutcome> {
            let mut guard = lock(&conn)?;
            let tx = guard.transaction()?;
            let out = engine::ingest_event(&tx, &ev, door, now)?;
            tx.commit()?;
            Ok(out)
        })
        .await
        .map_err(|e| anyhow!("history ingest task failed: {e}"))?
    }

    /// Persist a relay-authored event (seed kind-39000, kind-13534 membership
    /// list, group state 39000-39003), bypassing the client relay-authored
    /// guard. Applies replaceable dedup (latest per `(pubkey, kind, d-tag)`).
    /// The caller must have signed `ev` with the relay keypair.
    pub async fn store_relay_authored(&self, ev: &Event) -> Result<RelayStoreOutcome> {
        let ev = ev.clone();
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<RelayStoreOutcome> {
            let mut guard = lock(&conn)?;
            let tx = guard.transaction()?;
            let out = engine::store_relay_authored(&tx, &ev)?;
            tx.commit()?;
            Ok(out)
        })
        .await
        .map_err(|e| anyhow!("store_relay_authored task failed: {e}"))?
    }

    // ---- general read surface ----------------------------------------------

    /// General NIP-01 filter read over stored (non-deleted) events: the seed
    /// poll (`kinds:[39000]`), get-event-by-ids, kind:0 directory (`offset`
    /// paging), and aux-closure lookups. Order `created_at DESC, id ASC`;
    /// `limit` capped at `proto::MAX_FILTER_LIMIT`.
    pub async fn query(&self, f: &FilterSpec, limit: usize, offset: usize) -> Result<Vec<Event>> {
        let f = f.clone();
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<Vec<Event>> {
            let guard = lock(&conn)?;
            query::query(&guard, &f, limit, offset)
        })
        .await
        .map_err(|e| anyhow!("query task failed: {e}"))?
    }

    /// Count matching (non-deleted) events for a filter, ignoring limit/offset
    /// (`POST /count`).
    pub async fn count(&self, f: &FilterSpec) -> Result<u64> {
        let f = f.clone();
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<u64> {
            let guard = lock(&conn)?;
            query::count(&guard, &f)
        })
        .await
        .map_err(|e| anyhow!("count task failed: {e}"))?
    }

    /// NIP-50 FTS search over event content. `kinds` narrows (empty = any),
    /// `channel` scopes to a `#h`, `exclude_kinds` removes kinds that must stay
    /// unsearchable (WP2's p-gated set). Order `created_at DESC, id ASC`.
    pub async fn search(
        &self,
        text: &str,
        kinds: &[u32],
        channel: Option<&str>,
        exclude_kinds: &[u32],
        limit: usize,
    ) -> Result<Vec<Event>> {
        let (text, kinds, channel, exclude_kinds) = (
            text.to_string(),
            kinds.to_vec(),
            channel.map(str::to_string),
            exclude_kinds.to_vec(),
        );
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<Vec<Event>> {
            let guard = lock(&conn)?;
            query::search(
                &guard,
                &text,
                &kinds,
                channel.as_deref(),
                &exclude_kinds,
                limit,
            )
        })
        .await
        .map_err(|e| anyhow!("search task failed: {e}"))?
    }

    /// Fetch stored (non-deleted) events by id. Thin convenience over
    /// [`Self::query`] with an `ids` filter.
    pub async fn events_by_ids(&self, ids: &[String]) -> Result<Vec<Event>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let f = FilterSpec {
            ids: ids.to_vec(),
            ..FilterSpec::default()
        };
        self.query(&f, ids.len(), 0).await
    }

    // ---- read surface ------------------------------------------------------

    /// Top-level channel timeline page (keyset `created_at DESC, id ASC`).
    pub async fn channel_window(
        &self,
        channel_id: &str,
        limit: usize,
        cursor: Option<WindowCursor>,
    ) -> Result<WindowPage> {
        let channel_id = channel_id.to_string();
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<WindowPage> {
            let guard = lock(&conn)?;
            read::channel_window(&guard, &channel_id, limit, cursor)
        })
        .await
        .map_err(|e| anyhow!("channel_window task failed: {e}"))?
    }

    /// Thread replies under `root` (keyset `event_created_at ASC, event_id ASC`).
    pub async fn thread_replies(
        &self,
        root: &str,
        depth_limit: Option<u32>,
        limit: usize,
        cursor: Option<ThreadCursor>,
    ) -> Result<ThreadPage> {
        let root = canonical_event_id(root)?;
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<ThreadPage> {
            let guard = lock(&conn)?;
            read::thread_replies(&guard, &root, depth_limit, limit, cursor)
        })
        .await
        .map_err(|e| anyhow!("thread_replies task failed: {e}"))?
    }

    /// Thread summary payload for `root` (drives the 39005 overlay/emit).
    pub async fn thread_summary(&self, root: &str) -> Result<Option<ThreadSummary>> {
        let root = canonical_event_id(root)?;
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<Option<ThreadSummary>> {
            let guard = lock(&conn)?;
            read::thread_summary(&guard, &root)
        })
        .await
        .map_err(|e| anyhow!("thread_summary task failed: {e}"))?
    }

    /// General Nostr-filter read (WP2 seam): the plain `/query` paths (ids,
    /// directory, NIP-50 search, the `kinds:[39000]` seed check), `/count`, and
    /// aux-closure resolution. Reads the SAME store as `channel_window`, so the
    /// WS REQ backfill and HTTP `/query` cannot diverge. `max_limit` is WP2's
    /// per-request cap.
    pub async fn query(&self, filter: &Filter, max_limit: usize) -> Result<Vec<Event>> {
        let filter = filter.clone();
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<Vec<Event>> {
            let guard = lock(&conn)?;
            read::query(&guard, &filter, max_limit)
        })
        .await
        .map_err(|e| anyhow!("history query task failed: {e}"))?
    }

    /// Distinct non-null channel ids present in the store (startup topic
    /// pre-subscribe).
    pub async fn known_channels(&self) -> Result<Vec<String>> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let guard = lock(&conn)?;
            let mut stmt = guard
                .prepare("SELECT DISTINCT channel_id FROM events WHERE channel_id IS NOT NULL")
                .context("prepare known_channels failed")?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .context("known_channels query failed")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("known_channels row failed")?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| anyhow!("known_channels task failed: {e}"))?
    }

    // ---- maintenance -------------------------------------------------------

    /// Reap parked orphans older than `ttl` (default 24h in callers). Returns
    /// the number reaped. `now` is injected for testability.
    pub async fn reap_orphans(&self, ttl: Duration, now: i64) -> Result<usize> {
        let cutoff = now - i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<usize> {
            let guard = lock(&conn)?;
            let n = guard
                .execute(
                    "DELETE FROM pending_orphans WHERE received_at < ?1",
                    rusqlite::params![cutoff],
                )
                .context("reap_orphans delete failed")?;
            Ok(n)
        })
        .await
        .map_err(|e| anyhow!("reap_orphans task failed: {e}"))?
    }

    /// NIP-98 replay guard (D5, consumed by WP2 auth): record `event_id` if
    /// unseen and unexpired. Returns `true` when accepted (fresh), `false` on a
    /// replay. Expired rows are opportunistically purged.
    pub async fn nip98_check_and_record(
        &self,
        event_id: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool> {
        let event_id = canonical_event_id(event_id)?;
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut guard = lock(&conn)?;
            let tx = guard.transaction()?;
            tx.execute(
                "DELETE FROM nip98_seen WHERE expires_at < ?1",
                rusqlite::params![now],
            )
            .context("nip98 purge failed")?;
            let inserted = tx
                .execute(
                    "INSERT OR IGNORE INTO nip98_seen(event_id, expires_at) VALUES(?1, ?2)",
                    rusqlite::params![event_id, expires_at],
                )
                .context("nip98 insert failed")?;
            tx.commit()?;
            Ok(inserted == 1)
        })
        .await
        .map_err(|e| anyhow!("nip98 task failed: {e}"))?
    }

    /// Upsert a channel member (membership writes are owned by WP2/WP3; this is
    /// the minimal accessor over the `members` table).
    pub async fn upsert_member(&self, channel_id: &str, pubkey: &str, role: &str) -> Result<()> {
        let (channel_id, pubkey, role) =
            (channel_id.to_string(), pubkey.to_string(), role.to_string());
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<()> {
            let guard = lock(&conn)?;
            guard
                .execute(
                    "INSERT INTO members(channel_id, pubkey, role) VALUES(?1, ?2, ?3) \
                     ON CONFLICT(channel_id, pubkey) DO UPDATE SET role = excluded.role",
                    rusqlite::params![channel_id, pubkey, role],
                )
                .context("upsert_member failed")?;
            Ok(())
        })
        .await
        .map_err(|e| anyhow!("upsert_member task failed: {e}"))?
    }

    /// Role of a channel member, if any.
    pub async fn member_role(&self, channel_id: &str, pubkey: &str) -> Result<Option<String>> {
        let (channel_id, pubkey) = (channel_id.to_string(), pubkey.to_string());
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<Option<String>> {
            let guard = lock(&conn)?;
            guard
                .query_row(
                    "SELECT role FROM members WHERE channel_id = ?1 AND pubkey = ?2",
                    rusqlite::params![channel_id, pubkey],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .context("member_role query failed")
        })
        .await
        .map_err(|e| anyhow!("member_role task failed: {e}"))?
    }
}

fn lock(
    conn: &Mutex<rusqlite::Connection>,
) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>> {
    conn.lock()
        .map_err(|e| anyhow!("history db mutex poisoned: {e}"))
}

/// Current wall-clock unix seconds (local-door `last_reply_at`).
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

use rusqlite::OptionalExtension;

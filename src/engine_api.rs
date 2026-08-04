//! The read/write surface the HTTP dialect depends on. Owner: wp2-http.
//!
//! `HistoryEngine` is the seam between the HTTP layer (this PR, WP2/WP3) and the
//! storage + thread engine (WP1, branch `feat/m1a-wp1-thread-engine`). The
//! signatures are drawn from design §4 WP1's read-surface description
//! (`channel_window` / `thread_replies` / `thread_summary` / `ingest_local` /
//! `ingest_mesh`). [`StubEngine`] is a temporary in-memory implementation so the
//! whole HTTP surface compiles and is testable before WP1 merges.
//!
//! M1a-WIRING: [`StubEngine`] is replaced by the thread-engine impl at WP1 merge.
//! The trait is the stable contract; the stub is throwaway.

use std::collections::HashMap;

use async_trait::async_trait;
use nostr::{Event, Filter, JsonUtil};
use tokio::sync::Mutex;

use crate::filter_match;

/// Keyset cursor: `(created_at, event_id)` — the tie-safe composite Buzz uses
/// for both window (DESC) and thread (ASC) paging (design §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub created_at: u64,
    pub id: String,
}

/// Channel-window read request (dialect.md §1 `top_level` path).
#[derive(Debug, Clone)]
pub struct WindowQuery {
    pub channel_id: String,
    pub kinds: Vec<u16>,
    pub limit: usize,
    pub cursor: Option<Cursor>,
    pub include_aux: bool,
    pub include_summaries: bool,
    pub caller_pubkey: Option<String>,
}

/// Thread-reply keyset page (dialect.md §1 `thread_cursor` path).
#[derive(Debug, Clone)]
pub struct ThreadQuery {
    pub channel_id: String,
    pub root_id: String,
    pub limit: usize,
    pub cursor: Option<Cursor>,
    pub depth_limit: Option<u32>,
    pub caller_pubkey: Option<String>,
}

/// Thread summary for one root — the data the HTTP layer synthesizes a
/// relay-signed 39005 from (thread.md §1.5/§2). `participants` is already capped
/// at 10 and recency-ordered by the engine.
#[derive(Debug, Clone)]
pub struct ThreadSummary {
    pub root_id: String,
    pub channel_id: String,
    pub reply_count: i64,
    pub descendant_count: i64,
    pub last_reply_at: Option<u64>,
    pub participants: Vec<String>,
}

/// Window exhaustion — the data the HTTP layer synthesizes the single 39006
/// bounds overlay from (dialect.md §1). `rows < limit` proves nothing; this is
/// the sole authority.
#[derive(Debug, Clone)]
pub struct WindowBounds {
    pub has_more: bool,
    pub next_cursor: Option<Cursor>,
}

/// Everything the HTTP layer needs to assemble a `top_level` /query response:
/// rows, the aux closure, per-root summaries, and the bounds. Synthesis of the
/// relay-signed 39005/39006 overlays happens in the HTTP layer (it owns the
/// relay identity), not here.
#[derive(Debug, Clone)]
pub struct ChannelWindow {
    pub rows: Vec<Event>,
    pub aux: Vec<Event>,
    pub summaries: Vec<ThreadSummary>,
    pub bounds: WindowBounds,
}

/// A root whose relay-signed 39005 summary should be re-emitted post-commit
/// (mirror of WP1's `ThreadEmit`; kept here so the trait has no history-crate
/// dependency). `channel_id: None` → skip the emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emit {
    pub root_id: String,
    pub channel_id: Option<String>,
}

/// Verdict of a single ingest (dialect.md §2 response taxonomy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    /// Stored fresh (or replaced). 200 `accepted:true`. `emits` drive the
    /// post-commit 39005 fan-out (empty for a non-thread event).
    Stored { event_id: String, emits: Vec<Emit> },
    /// Already stored. 200 `accepted:true`, message `"duplicate:"`.
    Duplicate { event_id: String },
    /// Soft reject — 200 `accepted:false` with a human message.
    SoftReject { event_id: String, message: String },
    /// Hard reject (`IngestError::Rejected`) — 400 `{"error": reason}`.
    Rejected { reason: String },
    /// Mesh-door orphan parked, invisible until its parent lands. Never a
    /// hard reject of an event peers already hold (design D2 / finding 1).
    Parked { event_id: String },
    /// Mesh-door ancestry mismatch — kept, invisible, logged (design §4).
    Quarantined { reason: String },
}

/// Channel visibility for the membership gate (thread.md §3: `open` channels
/// skip membership).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Open,
    Closed,
}

/// The storage + thread-engine surface the HTTP dialect consumes.
#[async_trait]
pub trait HistoryEngine: Send + Sync {
    /// Local door (HTTP `/events`, WS `EVENT`): strict Buzz semantics.
    async fn ingest_local(&self, ev: &Event) -> anyhow::Result<IngestOutcome>;
    /// Mesh door (events arriving from x0x gossip): parks orphans.
    async fn ingest_mesh(&self, ev: &Event) -> anyhow::Result<IngestOutcome>;
    /// Plain Nostr-filter query (feed / ids / directory / search paths).
    async fn query(&self, filter: &Filter) -> anyhow::Result<Vec<Event>>;
    /// NIP-50 search with an optional prefix mode (Buzz `search_mode`) and a row
    /// `offset` ((page-1)*limit, applied at storage as SQL OFFSET). `prefix ==
    /// false` is whole-token phrase semantics; `prefix == true` makes each term a
    /// token PREFIX (`term*`). The search ANDs every nonempty filter dimension
    /// conjunctively. The default delegates to [`HistoryEngine::query`] (prefix
    /// and offset ignored) so an engine with no FTS surface need not implement it.
    async fn search(
        &self,
        filter: &Filter,
        _prefix: bool,
        _offset: usize,
    ) -> anyhow::Result<Vec<Event>> {
        self.query(filter).await
    }
    /// Channel-window read-model (dialect.md §1 `top_level`).
    async fn channel_window(&self, q: &WindowQuery) -> anyhow::Result<ChannelWindow>;
    /// Thread-reply keyset page.
    async fn thread_replies(&self, q: &ThreadQuery) -> anyhow::Result<Vec<Event>>;
    /// Thread summary for one root (`None` if it has no replies).
    async fn thread_summary(
        &self,
        channel_id: &str,
        root_id: &str,
    ) -> anyhow::Result<Option<ThreadSummary>>;
    /// COUNT support (`POST /count`).
    async fn count(&self, filter: &Filter) -> anyhow::Result<usize>;
    /// Membership gate input (dialect.md §0 / thread.md §3).
    async fn is_member(&self, channel_id: &str, pubkey_hex: &str) -> anyhow::Result<bool>;
    /// Channel visibility (`open` skips the membership gate).
    async fn visibility(&self, channel_id: &str) -> anyhow::Result<Visibility>;
    /// Seed a channel member (WP4). Default no-op so an engine that derives
    /// membership from ingested 39002/13534 events need not implement it.
    async fn seed_member(&self, _channel_id: &str, _pubkey_hex: &str) -> anyhow::Result<()> {
        Ok(())
    }
    /// Seed a channel's visibility (WP4). Default no-op.
    async fn seed_visibility(&self, _channel_id: &str, _vis: Visibility) -> anyhow::Result<()> {
        Ok(())
    }
    /// Store a relay-authored event (kind-39000 metadata / kind-13534 membership
    /// list) directly, bypassing the client-submission guard the two doors apply
    /// (WP4 seed / relay-authored group state). Default no-op.
    async fn seed_event(&self, _ev: &Event) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Keyset DESC-walk predicate (design §3): keep rows strictly before the cursor
/// under `created_at DESC, id ASC`.
fn window_before(ev: &Event, cursor: &Cursor) -> bool {
    let ts = ev.created_at.as_secs();
    let id = ev.id.to_hex();
    ts < cursor.created_at || (ts == cursor.created_at && id > cursor.id)
}

/// In-memory `HistoryEngine`. M1a-WIRING: replaced by the thread-engine impl at
/// WP1 merge. It is intentionally simple — it exists so the HTTP layer compiles,
/// serves the seed, and can be unit-tested; it does NOT implement thread
/// counters, orphan parking, or the aux closure (those are WP1). It treats every
/// stored event as a top-level row.
pub struct StubEngine {
    events: Mutex<Vec<Event>>,
    members: Mutex<HashMap<(String, String), ()>>,
    visibility: Mutex<HashMap<String, Visibility>>,
}

impl StubEngine {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            members: Mutex::new(HashMap::new()),
            visibility: Mutex::new(HashMap::new()),
        }
    }

    /// Seed a member (used by the demo seeder, WP4 slice).
    pub async fn add_member(&self, channel_id: &str, pubkey_hex: &str) {
        self.members
            .lock()
            .await
            .insert((channel_id.to_string(), pubkey_hex.to_string()), ());
    }

    /// Seed a channel's visibility (used by the demo seeder).
    pub async fn set_visibility(&self, channel_id: &str, vis: Visibility) {
        self.visibility
            .lock()
            .await
            .insert(channel_id.to_string(), vis);
    }

    async fn store(&self, ev: &Event) -> IngestOutcome {
        let mut events = self.events.lock().await;
        if events.iter().any(|e| e.id == ev.id) {
            return IngestOutcome::Duplicate {
                event_id: ev.id.to_hex(),
            };
        }
        events.push(ev.clone());
        IngestOutcome::Stored {
            event_id: ev.id.to_hex(),
            emits: Vec::new(),
        }
    }
}

impl Default for StubEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HistoryEngine for StubEngine {
    async fn ingest_local(&self, ev: &Event) -> anyhow::Result<IngestOutcome> {
        Ok(self.store(ev).await)
    }

    async fn ingest_mesh(&self, ev: &Event) -> anyhow::Result<IngestOutcome> {
        Ok(self.store(ev).await)
    }

    async fn query(&self, filter: &Filter) -> anyhow::Result<Vec<Event>> {
        let events = self.events.lock().await;
        let mut out: Vec<Event> = events
            .iter()
            .filter(|e| filter_match::matches(filter, e))
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.to_hex().cmp(&b.id.to_hex()))
        });
        Ok(out)
    }

    async fn channel_window(&self, q: &WindowQuery) -> anyhow::Result<ChannelWindow> {
        let events = self.events.lock().await;
        let mut rows: Vec<Event> = events
            .iter()
            .filter(|e| {
                let in_channel = crate::proto::event_channels(e)
                    .iter()
                    .any(|c| c == &q.channel_id.to_lowercase());
                let kind_ok = q.kinds.is_empty() || q.kinds.contains(&e.kind.as_u16());
                in_channel && kind_ok
            })
            .filter(|e| {
                q.cursor
                    .as_ref()
                    .map(|c| window_before(e, c))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.to_hex().cmp(&b.id.to_hex()))
        });
        // limit+1 exhaustion probe (design §3).
        let has_more = rows.len() > q.limit;
        rows.truncate(q.limit);
        let next_cursor = if has_more {
            rows.last().map(|e| Cursor {
                created_at: e.created_at.as_secs(),
                id: e.id.to_hex(),
            })
        } else {
            None
        };
        Ok(ChannelWindow {
            rows,
            aux: Vec::new(),
            summaries: Vec::new(),
            bounds: WindowBounds {
                has_more,
                next_cursor,
            },
        })
    }

    async fn thread_replies(&self, q: &ThreadQuery) -> anyhow::Result<Vec<Event>> {
        // Stub: return events carrying #e = root_id in the channel, ASC keyset.
        let events = self.events.lock().await;
        let mut out: Vec<Event> = events
            .iter()
            .filter(|e| {
                e.tags.iter().any(|t| {
                    let s = t.as_slice();
                    s.first().map(String::as_str) == Some("e")
                        && s.get(1).map(String::as_str) == Some(q.root_id.as_str())
                })
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.to_hex().cmp(&b.id.to_hex()))
        });
        out.truncate(q.limit);
        Ok(out)
    }

    async fn thread_summary(
        &self,
        _channel_id: &str,
        _root_id: &str,
    ) -> anyhow::Result<Option<ThreadSummary>> {
        // Stub carries no thread counters (WP1 owns them).
        Ok(None)
    }

    async fn count(&self, filter: &Filter) -> anyhow::Result<usize> {
        Ok(self.query(filter).await?.len())
    }

    async fn is_member(&self, channel_id: &str, pubkey_hex: &str) -> anyhow::Result<bool> {
        Ok(self
            .members
            .lock()
            .await
            .contains_key(&(channel_id.to_string(), pubkey_hex.to_string())))
    }

    async fn visibility(&self, channel_id: &str) -> anyhow::Result<Visibility> {
        Ok(self
            .visibility
            .lock()
            .await
            .get(channel_id)
            .copied()
            .unwrap_or(Visibility::Open))
    }

    async fn seed_member(&self, channel_id: &str, pubkey_hex: &str) -> anyhow::Result<()> {
        self.add_member(channel_id, pubkey_hex).await;
        Ok(())
    }

    async fn seed_visibility(&self, channel_id: &str, vis: Visibility) -> anyhow::Result<()> {
        self.set_visibility(channel_id, vis).await;
        Ok(())
    }

    async fn seed_event(&self, ev: &Event) -> anyhow::Result<()> {
        self.store(ev).await;
        Ok(())
    }
}

/// Serialize an event to its canonical Nostr JSON `Value` (row assembly helper
/// for the bare heterogeneous `/query` array).
pub fn event_to_value(ev: &Event) -> serde_json::Value {
    serde_json::from_str(&ev.as_json()).unwrap_or(serde_json::Value::Null)
}

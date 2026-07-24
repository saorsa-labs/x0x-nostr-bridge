//! Adapters binding WP1's concrete `history::HistoryStore` to the two seams the
//! WP2/WP3 lane depends on. Owner: wp2-http (integration pass).
//!
//! - [`HistoryStoreEngine`] implements the HTTP layer's `HistoryEngine` trait.
//! - [`HistoryStoreEventStore`] implements the WS layer's `EventStore` trait.
//!
//! Both wrap the SAME `Arc<HistoryStore>`, so in production the HTTP `/query`,
//! `/events`, `/count`, the WS REQ backfill, and the WS `EVENT` door all read
//! and write ONE store (design §4 WP5 slice / integration step 3).
//!
//! Reads go through WP1b's backend-agnostic [`FilterSpec`] surface
//! (`query`/`count`/`search`). The nostr→FilterSpec mapping honours the critical
//! semantic that an empty `Some`-set in a nostr `Filter` (matches nothing) maps
//! to an EARLY EMPTY RETURN, never to an empty `FilterSpec` vec (UNCONSTRAINED).
//!
//! The two-hop aux closure (dialect.md §1) is built HERE from WP1's
//! `WindowPage.aux_targets` (row ids): reactions(7) + deletions(5) targeting the
//! rows, then deletions targeting those aux events.

use std::sync::Arc;

use async_trait::async_trait;
use nostr::{Event, Filter};

use crate::engine_api::{
    ChannelWindow, Cursor, Emit, HistoryEngine, IngestOutcome, ThreadQuery, ThreadSummary,
    Visibility, WindowBounds, WindowQuery,
};
use crate::history::{self, FilterSpec, HistoryStore};
use crate::kinds;
use crate::proto;
use crate::store::{EventStore, InsertOutcome};

/// Per-request read cap for the general filter query paths.
const QUERY_MAX_LIMIT: usize = proto::MAX_FILTER_LIMIT;

fn map_emits(emits: Vec<history::ThreadEmit>) -> Vec<Emit> {
    emits
        .into_iter()
        .map(|e| Emit {
            root_id: e.root_event_id,
            channel_id: e.channel_id,
        })
        .collect()
}

fn map_summary(s: history::ThreadSummary) -> ThreadSummary {
    ThreadSummary {
        root_id: s.root_event_id,
        channel_id: s.channel_id.unwrap_or_default(),
        reply_count: s.reply_count,
        descendant_count: s.descendant_count,
        last_reply_at: s.last_reply_at.map(|v| v.max(0) as u64),
        participants: s.participants,
    }
}

fn to_window_cursor(c: Option<Cursor>) -> Option<history::WindowCursor> {
    c.map(|c| history::WindowCursor {
        created_at: i64::try_from(c.created_at).unwrap_or(i64::MAX),
        id: c.id,
    })
}

fn from_window_bounds(b: history::WindowBounds) -> WindowBounds {
    WindowBounds {
        has_more: b.has_more,
        next_cursor: b.next_cursor.map(|c| Cursor {
            created_at: c.created_at.max(0) as u64,
            id: c.id,
        }),
    }
}

/// Map a nostr `Filter` onto WP1b's `FilterSpec`. Returns `None` when the filter
/// carries an empty `Some`-set (matches nothing) — the caller must return an
/// empty result rather than an unconstrained query (FilterSpec empty vec =
/// UNCONSTRAINED).
fn to_filter_spec(f: &Filter) -> Option<FilterSpec> {
    if f.ids.as_ref().is_some_and(|s| s.is_empty())
        || f.authors.as_ref().is_some_and(|s| s.is_empty())
        || f.kinds.as_ref().is_some_and(|s| s.is_empty())
        || f.generic_tags.values().any(|s| s.is_empty())
    {
        return None;
    }
    let mut spec = FilterSpec::default();
    if let Some(ids) = &f.ids {
        spec.ids = ids.iter().map(|i| i.to_hex()).collect();
    }
    if let Some(authors) = &f.authors {
        spec.authors = authors.iter().map(|a| a.to_hex()).collect();
    }
    if let Some(kinds) = &f.kinds {
        spec.kinds = kinds.iter().map(|k| u32::from(k.as_u16())).collect();
    }
    for (tag, values) in &f.generic_tags {
        match tag.as_str() {
            "h" => spec.h = values.iter().map(|v| v.to_lowercase()).collect(),
            "e" => spec.e = values.iter().cloned().collect(),
            "p" => spec.p = values.iter().cloned().collect(),
            _ => {} // FilterSpec only models #h/#e/#p.
        }
    }
    spec.since = f
        .since
        .map(|t| i64::try_from(t.as_secs()).unwrap_or(i64::MAX));
    spec.until = f
        .until
        .map(|t| i64::try_from(t.as_secs()).unwrap_or(i64::MAX));
    Some(spec)
}

fn e_kinds_spec(e: Vec<String>, kinds: Vec<u32>) -> FilterSpec {
    FilterSpec {
        e,
        kinds,
        ..FilterSpec::default()
    }
}

/// Route a filter through WP1b's `query`/`search`, honoring the
/// empty-`Some`-set-means-nothing rule. `exclude_kinds` is the p-gated set,
/// enforced at the STORE layer for NIP-50 search (Buzz nulls their search
/// vector) — the HTTP layer keeps its own post-filter as belt-and-braces.
async fn run_query(
    store: &HistoryStore,
    filter: &Filter,
    exclude_kinds: &[u32],
) -> anyhow::Result<Vec<Event>> {
    let limit = filter.limit.unwrap_or(QUERY_MAX_LIMIT).min(QUERY_MAX_LIMIT);
    if let Some(search) = &filter.search {
        let kinds: Vec<u32> = filter
            .kinds
            .as_ref()
            .map(|k| k.iter().map(|k| u32::from(k.as_u16())).collect())
            .unwrap_or_default();
        let channel = proto::filter_channels(filter).into_iter().next();
        return store
            .search(search, &kinds, channel.as_deref(), exclude_kinds, limit)
            .await;
    }
    let Some(spec) = to_filter_spec(filter) else {
        return Ok(Vec::new());
    };
    store.query(&spec, limit, 0).await
}

/// HTTP-lane engine over the durable history store.
pub struct HistoryStoreEngine {
    store: Arc<HistoryStore>,
    /// p-gated kinds excluded from NIP-50 search at the store layer.
    p_gated: Vec<u32>,
}

impl HistoryStoreEngine {
    pub fn new(store: Arc<HistoryStore>, p_gated: Vec<u32>) -> Self {
        Self { store, p_gated }
    }

    /// Build the two-hop aux closure for a set of row ids (dialect.md §1 step 2).
    async fn aux_closure(&self, row_ids: &[String]) -> Vec<Event> {
        if row_ids.is_empty() {
            return Vec::new();
        }
        let del = u32::from(kinds::KIND_DELETION);
        let react = u32::from(kinds::KIND_REACTION);
        // Hop 1: reactions/deletions targeting the rows.
        let hop1 = e_kinds_spec(row_ids.to_vec(), vec![del, react]);
        let mut out = self
            .store
            .query(&hop1, QUERY_MAX_LIMIT, 0)
            .await
            .unwrap_or_default();

        // Hop 2: deletions targeting the aux events themselves.
        let aux_ids: Vec<String> = out.iter().map(|e| e.id.to_hex()).collect();
        if !aux_ids.is_empty() {
            let hop2 = e_kinds_spec(aux_ids, vec![del]);
            if let Ok(h2) = self.store.query(&hop2, QUERY_MAX_LIMIT, 0).await {
                out.extend(h2);
            }
        }
        // Dedupe by id (a deletion can appear in both hops).
        let mut seen = std::collections::HashSet::new();
        out.retain(|e| seen.insert(e.id));
        out
    }
}

#[async_trait]
impl HistoryEngine for HistoryStoreEngine {
    async fn ingest_local(&self, ev: &Event) -> anyhow::Result<IngestOutcome> {
        Ok(match self.store.ingest_local(ev).await? {
            history::LocalIngest::Accepted(e) if e.duplicate => IngestOutcome::Duplicate {
                event_id: ev.id.to_hex(),
            },
            history::LocalIngest::Accepted(e) => IngestOutcome::Stored {
                event_id: ev.id.to_hex(),
                emits: map_emits(e.emits),
            },
            history::LocalIngest::Rejected(reason) => IngestOutcome::Rejected { reason },
        })
    }

    async fn ingest_mesh(&self, ev: &Event) -> anyhow::Result<IngestOutcome> {
        Ok(match self.store.ingest_mesh(ev).await? {
            history::MeshIngest::Accepted(e) if e.duplicate => IngestOutcome::Duplicate {
                event_id: ev.id.to_hex(),
            },
            history::MeshIngest::Accepted(e) => IngestOutcome::Stored {
                event_id: ev.id.to_hex(),
                emits: map_emits(e.emits),
            },
            history::MeshIngest::Parked => IngestOutcome::Parked {
                event_id: ev.id.to_hex(),
            },
            history::MeshIngest::Quarantined(reason) => IngestOutcome::Quarantined { reason },
        })
    }

    async fn query(&self, filter: &Filter) -> anyhow::Result<Vec<Event>> {
        run_query(&self.store, filter, &self.p_gated).await
    }

    async fn channel_window(&self, q: &WindowQuery) -> anyhow::Result<ChannelWindow> {
        let page = self
            .store
            .channel_window(&q.channel_id, q.limit, to_window_cursor(q.cursor.clone()))
            .await?;

        // WP1 runs the depth-only top-level predicate on a kind-agnostic set;
        // WP2 applies the request's kind filter on top (WP1 report note).
        let mut rows = page.rows;
        if !q.kinds.is_empty() {
            rows.retain(|e| q.kinds.contains(&e.kind.as_u16()));
        }

        let aux = if q.include_aux {
            self.aux_closure(&page.aux_targets).await
        } else {
            Vec::new()
        };
        let summaries = if q.include_summaries {
            page.summaries.into_iter().map(map_summary).collect()
        } else {
            Vec::new()
        };

        Ok(ChannelWindow {
            rows,
            aux,
            summaries,
            bounds: from_window_bounds(page.bounds),
        })
    }

    async fn thread_replies(&self, q: &ThreadQuery) -> anyhow::Result<Vec<Event>> {
        let cursor = q.cursor.clone().map(|c| history::ThreadCursor {
            created_at: i64::try_from(c.created_at).unwrap_or(i64::MAX),
            id: c.id,
        });
        let page = self
            .store
            .thread_replies(&q.root_id, q.depth_limit, q.limit, cursor)
            .await?;
        Ok(page.rows)
    }

    async fn thread_summary(
        &self,
        _channel_id: &str,
        root_id: &str,
    ) -> anyhow::Result<Option<ThreadSummary>> {
        Ok(self.store.thread_summary(root_id).await?.map(map_summary))
    }

    async fn count(&self, filter: &Filter) -> anyhow::Result<usize> {
        let Some(spec) = to_filter_spec(filter) else {
            return Ok(0);
        };
        Ok(usize::try_from(self.store.count(&spec).await?).unwrap_or(usize::MAX))
    }

    async fn is_member(&self, channel_id: &str, pubkey_hex: &str) -> anyhow::Result<bool> {
        Ok(self
            .store
            .member_role(channel_id, pubkey_hex)
            .await?
            .is_some())
    }

    async fn visibility(&self, _channel_id: &str) -> anyhow::Result<Visibility> {
        // WP1 has no channel-visibility column; treat all channels as open
        // (membership gate is default-off for the M1a gate).
        Ok(Visibility::Open)
    }

    async fn seed_member(&self, channel_id: &str, pubkey_hex: &str) -> anyhow::Result<()> {
        self.store
            .upsert_member(channel_id, pubkey_hex, "member")
            .await
    }

    async fn seed_event(&self, ev: &Event) -> anyhow::Result<()> {
        // ingest_local rejects relay-authored kinds from clients; the seeder
        // stores its own relay-signed 39000/13534 through this door.
        let _outcome = self.store.store_relay_authored(ev).await?;
        Ok(())
    }
}

/// WS-lane `EventStore` over the SAME history store, so REQ backfill reads what
/// `/query` reads. Ingest goes through the strict local door.
///
/// M1a-WIRING deviations (flagged in the report): a WS-door reply rejection
/// surfaces as a generic store error rather than the Buzz reason — the HTTP
/// `/events` door returns the exact reason. Live 39005 fan-out for WS-submitted
/// replies is handled on the gossip/HTTP doors, not here.
pub struct HistoryStoreEventStore {
    store: Arc<HistoryStore>,
    p_gated: Vec<u32>,
}

impl HistoryStoreEventStore {
    pub fn new(store: Arc<HistoryStore>, p_gated: Vec<u32>) -> Self {
        Self { store, p_gated }
    }
}

#[async_trait]
impl EventStore for HistoryStoreEventStore {
    async fn insert(&self, ev: &Event) -> anyhow::Result<InsertOutcome> {
        match self.store.ingest_local(ev).await? {
            history::LocalIngest::Accepted(e) if e.duplicate => Ok(InsertOutcome::Duplicate),
            history::LocalIngest::Accepted(_) => Ok(InsertOutcome::Inserted),
            history::LocalIngest::Rejected(reason) => Err(anyhow::anyhow!(reason)),
        }
    }

    async fn query(&self, filter: &Filter) -> anyhow::Result<Vec<Event>> {
        run_query(&self.store, filter, &self.p_gated).await
    }

    async fn known_channels(&self) -> anyhow::Result<Vec<String>> {
        // Topics are ensured on demand (REQ / publish); WP1b exposes no channel
        // listing and no startup enumeration is required.
        Ok(Vec::new())
    }
}

//! Adapters binding WP1's concrete `history::HistoryStore` to the two seams the
//! WP2/WP3 lane depends on. Owner: wp2-http (integration pass).
//!
//! - [`HistoryStoreEngine`] implements the HTTP layer's `HistoryEngine` trait.
//! - [`HistoryStoreEventStore`] implements the WS layer's `EventStore` trait.
//!
//! Both wrap the SAME `Arc<HistoryStore>`, so in production the HTTP `/query`,
//! `/events`, `/count`, the WS REQ backfill, and the WS `EVENT` door all read
//! and write ONE store (design §4 WP5 slice / team-lead integration step 3).
//!
//! The two-hop aux closure (dialect.md §1) is built HERE from WP1's
//! `WindowPage.aux_targets` (row ids): reactions(7) + deletions(5) targeting the
//! rows, then deletions targeting those aux events.

use std::sync::Arc;

use async_trait::async_trait;
use nostr::{Event, EventId, Filter, Kind};

use crate::engine_api::{
    ChannelWindow, Cursor, Emit, HistoryEngine, IngestOutcome, ThreadQuery, ThreadSummary,
    Visibility, WindowBounds, WindowQuery,
};
use crate::history::{self, HistoryStore};
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

/// HTTP-lane engine over the durable history store.
pub struct HistoryStoreEngine {
    store: Arc<HistoryStore>,
}

impl HistoryStoreEngine {
    pub fn new(store: Arc<HistoryStore>) -> Self {
        Self { store }
    }

    /// Build the two-hop aux closure for a set of row ids (dialect.md §1 step 2).
    async fn aux_closure(&self, row_ids: &[String]) -> Vec<Event> {
        let row_event_ids: Vec<EventId> = row_ids
            .iter()
            .filter_map(|id| EventId::parse(id).ok())
            .collect();
        if row_event_ids.is_empty() {
            return Vec::new();
        }
        // Hop 1: reactions/deletions targeting the rows.
        let hop1_filter = Filter::new()
            .kinds([
                Kind::from(kinds::KIND_DELETION),
                Kind::from(kinds::KIND_REACTION),
            ])
            .events(row_event_ids);
        let mut out = self
            .store
            .query(&hop1_filter, QUERY_MAX_LIMIT)
            .await
            .unwrap_or_default();

        // Hop 2: deletions targeting the aux events themselves.
        let aux_ids: Vec<EventId> = out.iter().map(|e| e.id).collect();
        if !aux_ids.is_empty() {
            let hop2_filter = Filter::new()
                .kind(Kind::from(kinds::KIND_DELETION))
                .events(aux_ids);
            if let Ok(hop2) = self.store.query(&hop2_filter, QUERY_MAX_LIMIT).await {
                out.extend(hop2);
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
        self.store.query(filter, QUERY_MAX_LIMIT).await
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
        Ok(self.store.query(filter, QUERY_MAX_LIMIT).await?.len())
    }

    async fn is_member(&self, channel_id: &str, pubkey_hex: &str) -> anyhow::Result<bool> {
        Ok(self.store.member_role(channel_id, pubkey_hex).await?.is_some())
    }

    async fn visibility(&self, _channel_id: &str) -> anyhow::Result<Visibility> {
        // WP1 has no channel-visibility column; treat all channels as open
        // (membership gate is default-off for the M1a gate).
        Ok(Visibility::Open)
    }

    async fn seed_member(&self, channel_id: &str, pubkey_hex: &str) -> anyhow::Result<()> {
        self.store.upsert_member(channel_id, pubkey_hex, "member").await
    }
}

/// WS-lane `EventStore` over the SAME history store, so REQ backfill reads what
/// `/query` reads. Ingest goes through the strict local door.
///
/// M1a-WIRING deviations (flagged in the report): the local door does NOT do
/// NIP-16 replaceable resolution (HistoryStore is id-PK), and a WS-door reply
/// rejection surfaces as a generic store error rather than the Buzz reason —
/// the HTTP `/events` door returns the exact reason. Live 39005 fan-out for
/// WS-submitted replies is handled on the gossip/HTTP doors, not here.
pub struct HistoryStoreEventStore {
    store: Arc<HistoryStore>,
}

impl HistoryStoreEventStore {
    pub fn new(store: Arc<HistoryStore>) -> Self {
        Self { store }
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
        self.store.query(filter, QUERY_MAX_LIMIT).await
    }

    async fn known_channels(&self) -> anyhow::Result<Vec<String>> {
        self.store.known_channels().await
    }
}

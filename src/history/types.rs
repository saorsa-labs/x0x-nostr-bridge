//! Public data types for the history store's two-door ingest and read surface.
//! Owner: WP1. The HTTP/WS lane (WP2/WP3) consumes these; it synthesizes the
//! kind-39005 / kind-39006 overlay events from the `ThreadSummary` /
//! `WindowBounds` payloads returned here (event synthesis + signing is NOT WP1).

use std::collections::BTreeMap;

use nostr::Event;

/// Which door an event entered through. Local = strict Buzz semantics (HTTP
/// `/events`, WS `EVENT`); Mesh = park/quarantine tolerant (x0x gossip).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Door {
    Local,
    Mesh,
}

/// A backend-agnostic NIP-01 filter for the general read surface (`query` /
/// `count`). Deliberately NOT `nostr::Filter`: the HTTP/WS lane owns the
/// two-pass raw-JSON filter parse (extension fields, unknown-field handling) and
/// maps its typed filters onto this precise struct.
///
/// **Semantics:** every field is a conjunction (AND) across fields; within a
/// list field, membership is a disjunction (OR). An **empty `Vec` means the
/// field is UNCONSTRAINED** (not "match nothing") — the caller must map a
/// nostr empty-`Some`-set (which matches nothing) to an early return, never to
/// an empty vec here. Ids/authors are lowercase hex; `#h` is lowercased on
/// match (channel ids are stored lowercase). Deleted rows and parked/quarantined
/// events are never returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterSpec {
    pub ids: Vec<String>,
    pub kinds: Vec<u32>,
    pub authors: Vec<String>,
    /// Tag constraints keyed by tag NAME (`"h"`, `"e"`, `"p"`, `"d"`, `"a"`, …)
    /// — i.e. NIP-01 `#<name>` less the `#`. One map rather than per-tag fields
    /// so a tag dimension cannot be silently dropped on the way in: dropping one
    /// WIDENS the result set (over-match), it does not narrow it.
    pub tags: BTreeMap<String, Vec<String>>,
    pub since: Option<i64>,
    pub until: Option<i64>,
}

impl FilterSpec {
    /// Constrain `#<name>` to `values` (OR within the list, AND against every
    /// other dimension). An empty `values` is UNCONSTRAINED and is not recorded
    /// — callers map a nostr empty-`Some`-set to an early empty return instead.
    pub fn with_tag<I, S>(mut self, name: &str, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let values: Vec<String> = values.into_iter().map(Into::into).collect();
        if !values.is_empty() {
            self.tags.insert(name.to_string(), values);
        }
        self
    }
}

/// A request to (re)emit a relay-signed kind-39005 thread summary for a root,
/// post-commit. The caller resolves the current [`ThreadSummary`] and signs the
/// overlay. Empty for events that produced no thread mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadEmit {
    pub root_event_id: String,
    pub channel_id: Option<String>,
}

/// Side effects of an accepted ingest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestEffects {
    /// True when the event id was already stored (idempotent redelivery); no
    /// counters were touched.
    pub duplicate: bool,
    /// True when this was a stale replaceable/parameterized-replaceable event
    /// (older `created_at`, or tie with a higher id, than the stored winner):
    /// the event was NOT stored, counters were untouched, and there are no
    /// emits. Distinct from `duplicate` (an idempotent redelivery of THIS id).
    /// Adapters must surface it as a stale/soft-reject so neither door
    /// gossip-publishes, dispatches, nor fan-outs a non-stored event.
    pub stale: bool,
    /// Roots whose 39005 summary should be re-emitted post-commit (dedup by
    /// root is the caller's job — 39005 is replaceable on `d=root`).
    pub emits: Vec<ThreadEmit>,
}

/// Outcome of persisting a relay-authored event (seed 39000, kind-13534
/// membership list, group state 39000-39003) via
/// [`crate::history::HistoryStore::store_relay_authored`]. Replaceable and
/// parameterized-replaceable kinds keep only the latest per `(pubkey, kind,
/// d-tag)` (NIP-01 tie-break: equal `created_at` keeps the lowest event id).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayStoreOutcome {
    Inserted,
    Duplicate,
    Replaced,
    StaleRejected,
}

/// Outcome of the strict local door.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalIngest {
    Accepted(IngestEffects),
    /// Full Buzz reason string (e.g. `"invalid: reply parent not found"`).
    Rejected(String),
}

/// Outcome of the tolerant mesh door. Parked and quarantined events are
/// INVISIBLE to every served surface (design §4 two-door invariant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshIngest {
    Accepted(IngestEffects),
    /// Reply whose parent has not arrived; held in `pending_orphans`.
    Parked,
    /// Ancestry mismatch on an event peers already hold; kept invisible + logged.
    Quarantined(String),
}

/// Keyset cursor for the channel window (`created_at DESC, id ASC` walk).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowCursor {
    pub created_at: i64,
    pub id: String,
}

/// Keyset cursor for thread replies (`event_created_at ASC, event_id ASC` walk).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadCursor {
    pub created_at: i64,
    pub id: String,
}

/// The sole authority on window exhaustion (mirrors the kind-39006 overlay).
/// `has_more` comes from the `limit + 1` probe, NOT from `rows < limit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowBounds {
    pub has_more: bool,
    pub next_cursor: Option<WindowCursor>,
}

/// One page of the top-level channel timeline.
#[derive(Debug, Clone)]
pub struct WindowPage {
    /// Top-level rows in keyset order (`created_at DESC, id ASC`).
    pub rows: Vec<Event>,
    /// Event ids of the returned rows — the targets the aux closure
    /// (reactions/deletions/edits) should resolve against. Aux resolution and
    /// the second-hop closure are WP2's job; these never consume the row budget.
    pub aux_targets: Vec<String>,
    /// One summary per returned row that has replies (drives the 39005 overlays).
    pub summaries: Vec<ThreadSummary>,
    pub bounds: WindowBounds,
}

/// One page of thread replies under a root (`event_created_at ASC` keyset).
#[derive(Debug, Clone)]
pub struct ThreadPage {
    pub rows: Vec<Event>,
    pub has_more: bool,
    pub next_cursor: Option<ThreadCursor>,
}

/// The payload behind a kind-39005 thread-summary overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadSummary {
    pub root_event_id: String,
    pub channel_id: Option<String>,
    pub reply_count: i64,
    pub descendant_count: i64,
    /// Wall-clock (local door) or `max(reply.created_at)` (mesh door). `None`
    /// only when no reply has ever landed.
    pub last_reply_at: Option<i64>,
    /// DISTINCT reply pubkeys over the subtree, `ORDER BY MAX(created_at) DESC`,
    /// capped at 10 (design finding 5).
    pub participants: Vec<String>,
}

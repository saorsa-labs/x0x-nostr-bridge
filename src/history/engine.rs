//! Thread engine — the ingest transaction. Owner: WP1.
//!
//! Implements `docs/recon/thread.md` §1 verbatim: marked NIP-10 tags only, the
//! 4-row marker table (incl. only-root => top-level), local-door
//! parent-must-exist rejects, server-verified root with the parent-has-no-row
//! re-derivation branch, depth cap 100, lazy parent/root stub rows, and the two
//! transactional counters. Both doors share one validation core
//! (`resolve_reply`); the doors differ only in how they treat a missing parent
//! (local reject vs mesh park) and an ancestry mismatch (local reject vs mesh
//! quarantine).
//!
//! Every function here runs INSIDE a single `rusqlite::Transaction` supplied by
//! `mod.rs`; the read-modify-write counter maintenance and the recursive orphan
//! drain are atomic per the design's serialized-writer model (D1).

use anyhow::{anyhow, Context, Result};
use nostr::{Event, JsonUtil};
use rusqlite::{OptionalExtension, Transaction};

use crate::history::types::{Door, IngestEffects, RelayStoreOutcome, ThreadEmit};
use crate::proto;

/// NIP-25 reaction — stored opaque, never threaded.
const KIND_REACTION: u16 = 7;
/// NIP-09 deletion.
const KIND_DELETION: u16 = 5;
/// NIP-29 delete-event.
const KIND_NIP29_DELETE: u16 = 9005;
/// Thread depth cap: depth 100 allowed, 101 rejected (thread.md §1.4).
pub(crate) const DEPTH_CAP: i64 = 100;
/// Recency-capped participant list size (thread.md §1.5).
pub(crate) const PARTICIPANT_CAP: i64 = 10;

/// Kinds only the relay may author; client submissions are rejected (thread.md
/// §2, §3, vector V10). The HTTP guard in WP2 reuses this helper.
pub fn is_relay_authored_kind(kind: u16) -> bool {
    matches!(kind, 39000..=39003 | 39005 | 39006 | 13534)
}

/// Kinds that carry NIP-10 thread ancestry in M1a: the stream-message family.
/// Buzz's full `requires_h_channel_scope` set also covers canvas/forum/huddle
/// kinds; those are deferred (not exercised by the M1a vectors). Reactions and
/// relay-authored kinds are handled on their own branches, never here.
fn is_thread_scoped_kind(kind: u16) -> bool {
    kind == 9 || matches!(kind, 40002..=40008)
}

fn is_deletion_kind(kind: u16) -> bool {
    kind == KIND_DELETION || kind == KIND_NIP29_DELETE
}

/// Canonicalize an event id to lowercase 64-hex; reject anything else. Applied
/// to every ingest/cursor id so TEXT binary collation matches Buzz's ordering
/// (§3 invariant).
pub fn canonical_event_id(s: &str) -> Result<String> {
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(anyhow!("invalid event id (expected 64-hex): {s:?}"))
    }
}

/// Non-erroring 64-hex predicate used while scanning marker tags: an e-tag whose
/// value is not 64-hex is simply not treated as a marker (thread.md §1.2).
fn is_64hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The door-agnostic outcome of ingesting one event. `mod.rs` narrows this to
/// [`crate::history::types::LocalIngest`] / [`crate::history::types::MeshIngest`].
pub(crate) enum CoreOutcome {
    Accepted(IngestEffects),
    Parked,
    Quarantined(String),
    Rejected(String),
}

// ---- entry point -----------------------------------------------------------

/// Ingest a single event through `door`, inside `tx`. `now` is the wall-clock
/// unix seconds used for local-door `last_reply_at`.
pub(crate) fn ingest_event(
    tx: &Transaction<'_>,
    ev: &Event,
    door: Door,
    now: i64,
) -> Result<CoreOutcome> {
    let id = canonical_event_id(&ev.id.to_hex())?;

    // Idempotent by event id: a redelivery touches no counters.
    if event_exists(tx, &id)? {
        return Ok(CoreOutcome::Accepted(IngestEffects {
            duplicate: true,
            emits: Vec::new(),
        }));
    }

    let channel_id = resolve_channel(ev);
    let kind = ev.kind.as_u16();

    // Relay-authored kinds: client submissions rejected; a mesh copy is kept
    // invisible (quarantined) rather than re-broadcast.
    if is_relay_authored_kind(kind) {
        let reason = format!("invalid: kind {kind} is relay-authored");
        return Ok(match door {
            Door::Local => CoreOutcome::Rejected(reason),
            Door::Mesh => {
                quarantine(tx, ev, &id, &reason, now)?;
                CoreOutcome::Quarantined(reason)
            }
        });
    }

    // Delete is ONE flow (finding 6, V15): store the deletion event, then
    // soft-delete + guarded-decrement each target in the same transaction.
    if is_deletion_kind(kind) {
        return delete_flow(tx, ev, &id, channel_id.as_deref(), now);
    }

    // Reactions never create thread rows (NIP-25 branch).
    if kind == KIND_REACTION {
        insert_event_row(tx, ev, &id, channel_id.as_deref())?;
        let mut emits = Vec::new();
        drain_pending(tx, &id, now, &mut emits)?;
        return Ok(CoreOutcome::Accepted(IngestEffects {
            duplicate: false,
            emits,
        }));
    }

    if is_thread_scoped_kind(kind) {
        let tags = tag_vecs(ev);
        match resolve_markers(&tags) {
            Markers::TopLevel => {
                insert_event_row(tx, ev, &id, channel_id.as_deref())?;
                let mut emits = Vec::new();
                drain_pending(tx, &id, now, &mut emits)?;
                Ok(CoreOutcome::Accepted(IngestEffects {
                    duplicate: false,
                    emits,
                }))
            }
            Markers::Reply { parent, root_hint } => {
                match resolve_reply(tx, channel_id.as_deref(), &parent, &root_hint)? {
                    ReplyResolution::ParentMissing => Ok(match door {
                        Door::Local => {
                            CoreOutcome::Rejected("invalid: reply parent not found".to_string())
                        }
                        Door::Mesh => {
                            park(tx, ev, &id, &parent, now)?;
                            CoreOutcome::Parked
                        }
                    }),
                    ReplyResolution::Mismatch(reason) => Ok(match door {
                        Door::Local => CoreOutcome::Rejected(reason),
                        Door::Mesh => {
                            quarantine(tx, ev, &id, &reason, now)?;
                            CoreOutcome::Quarantined(reason)
                        }
                    }),
                    ReplyResolution::Ok(rr) => {
                        let emit =
                            insert_reply(tx, ev, &id, channel_id.as_deref(), &rr, door, now)?;
                        let mut emits = vec![emit];
                        drain_pending(tx, &id, now, &mut emits)?;
                        Ok(CoreOutcome::Accepted(IngestEffects {
                            duplicate: false,
                            emits,
                        }))
                    }
                }
            }
        }
    } else {
        // Every other kind is stored opaquely (with replaceable dedup for
        // replaceable client kinds) as a top-level channel message.
        let outcome = insert_deduped(tx, ev, &id, channel_id.as_deref())?;
        let mut emits = Vec::new();
        if outcome != RelayStoreOutcome::StaleRejected {
            drain_pending(tx, &id, now, &mut emits)?;
        }
        Ok(CoreOutcome::Accepted(IngestEffects {
            duplicate: false,
            emits,
        }))
    }
}

/// Persist a relay-authored event (seed 39000, kind-13534 membership list,
/// group state 39000-39003), bypassing the client relay-authored guard — the
/// caller (WP2) has signed it with the relay keypair. Applies replaceable /
/// parameterized-replaceable dedup so re-seeding keeps only the latest per
/// `(pubkey, kind, d-tag)`. NOT a thread-engine path: relay-authored kinds are
/// never thread-scoped, so no ancestry/counter work.
pub(crate) fn store_relay_authored(tx: &Transaction<'_>, ev: &Event) -> Result<RelayStoreOutcome> {
    let id = canonical_event_id(&ev.id.to_hex())?;
    if event_exists(tx, &id)? {
        return Ok(RelayStoreOutcome::Duplicate);
    }
    let channel_id = resolve_channel(ev);
    insert_deduped(tx, ev, &id, channel_id.as_deref())
}

/// Insert an event that is already known to be new (caller dup-checked),
/// applying NIP-01 replaceable / parameterized-replaceable dedup. Non-thread
/// path — used by `store_relay_authored` and by the opaque client-kind branch
/// so replaceable client kinds (0, 3, 10000-19999, 30000-39999) also collapse
/// to their latest.
fn insert_deduped(
    tx: &Transaction<'_>,
    ev: &Event,
    id: &str,
    channel_id: Option<&str>,
) -> Result<RelayStoreOutcome> {
    let kind = i64::from(ev.kind.as_u16());
    let pubkey = ev.pubkey.to_hex();
    let created_at = i64::try_from(ev.created_at.as_secs()).context("created_at out of i64")?;

    let param_repl = proto::is_parameterized_replaceable(ev.kind);
    let replaceable = proto::is_replaceable(ev.kind) || param_repl;
    let d_key = if param_repl {
        proto::d_tag(ev).unwrap_or_default()
    } else {
        String::new()
    };

    if !replaceable {
        insert_event_row(tx, ev, id, channel_id)?;
        return Ok(RelayStoreOutcome::Inserted);
    }

    let prev: Option<(i64, String)> = tx
        .query_row(
            "SELECT created_at, event_id FROM replaceable_addrs \
             WHERE pubkey = ?1 AND kind = ?2 AND d_tag = ?3",
            rusqlite::params![pubkey, kind, d_key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .context("replaceable_addrs lookup failed")?;

    match prev {
        // Stored wins if strictly newer, or equal-timestamp with a lower id
        // (NIP-01 keeps the lowest event id on a tie).
        Some((pca, pid)) if pca > created_at || (pca == created_at && pid.as_str() < id) => {
            Ok(RelayStoreOutcome::StaleRejected)
        }
        Some(_) => {
            tx.execute(
                "DELETE FROM events WHERE id = (SELECT event_id FROM replaceable_addrs \
                 WHERE pubkey = ?1 AND kind = ?2 AND d_tag = ?3)",
                rusqlite::params![pubkey, kind, d_key],
            )
            .context("supersede delete failed")?;
            insert_event_row(tx, ev, id, channel_id)?;
            tx.execute(
                "INSERT INTO replaceable_addrs(pubkey, kind, d_tag, event_id, created_at) \
                 VALUES(?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(pubkey, kind, d_tag) DO UPDATE SET \
                 event_id = excluded.event_id, created_at = excluded.created_at",
                rusqlite::params![pubkey, kind, d_key, id, created_at],
            )
            .context("replaceable_addrs upsert failed")?;
            Ok(RelayStoreOutcome::Replaced)
        }
        None => {
            insert_event_row(tx, ev, id, channel_id)?;
            tx.execute(
                "INSERT INTO replaceable_addrs(pubkey, kind, d_tag, event_id, created_at) \
                 VALUES(?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![pubkey, kind, d_key, id, created_at],
            )
            .context("replaceable_addrs insert failed")?;
            Ok(RelayStoreOutcome::Inserted)
        }
    }
}

// ---- reply resolution (shared validation core) -----------------------------

struct ResolvedReply {
    parent: String,
    root: String,
    depth: i64,
}

enum ReplyResolution {
    ParentMissing,
    Mismatch(String),
    Ok(ResolvedReply),
}

/// Resolve a reply's ancestry against committed state. The only door-specific
/// step is what the caller does with `ParentMissing` / `Mismatch`.
fn resolve_reply(
    tx: &Transaction<'_>,
    channel_id: Option<&str>,
    parent_hex: &str,
    root_hint: &str,
) -> Result<ReplyResolution> {
    let parent = match load_event_meta(tx, parent_hex)? {
        None => return Ok(ReplyResolution::ParentMissing),
        Some(m) => m,
    };

    // Parent channel match (thread.md §1.4 step 2).
    match parent.channel_id.as_deref() {
        None => {
            return Ok(ReplyResolution::Mismatch(
                "parent event has no channel association".to_string(),
            ))
        }
        Some(pc) if Some(pc) != channel_id => {
            return Ok(ReplyResolution::Mismatch(
                "parent event belongs to a different channel".to_string(),
            ))
        }
        Some(_) => {}
    }

    // Server-verified root + depth (thread.md §1.4 step 3-4).
    let (effective_root, depth) = match load_thread_meta(tx, parent_hex)? {
        Some(pm) => {
            let er = pm.root_event_id.unwrap_or_else(|| parent_hex.to_string());
            let depth = pm.depth.unwrap_or(0) + 1;
            if depth > DEPTH_CAP {
                return Ok(ReplyResolution::Mismatch(
                    "thread depth limit exceeded".to_string(),
                ));
            }
            (er, depth)
        }
        None => {
            // Parent is itself a root (no row yet): re-derive its own root from
            // its root-then-reply markers, defaulting to the parent id. This
            // branch tops out at depth 2, so no cap needed.
            let derived = derive_own_root(&parent.tags, parent_hex);
            let depth = if derived == parent_hex { 1 } else { 2 };
            (derived, depth)
        }
    };

    if root_hint != effective_root {
        return Ok(ReplyResolution::Mismatch(
            "root tag does not match thread ancestry".to_string(),
        ));
    }

    Ok(ReplyResolution::Ok(ResolvedReply {
        parent: parent_hex.to_string(),
        root: effective_root,
        depth,
    }))
}

/// Insert an accepted reply: the event row, its own thread_metadata row, lazy
/// parent/root stubs, and the two guarded counter bumps. Returns the 39005 emit
/// request for the root. Counters bump only when the reply row was actually
/// inserted (dup-safe).
fn insert_reply(
    tx: &Transaction<'_>,
    ev: &Event,
    id: &str,
    channel_id: Option<&str>,
    rr: &ResolvedReply,
    door: Door,
    now: i64,
) -> Result<ThreadEmit> {
    insert_event_row(tx, ev, id, channel_id)?;

    let created_at = i64::try_from(ev.created_at.as_secs()).context("created_at out of i64")?;
    let broadcast = has_broadcast(ev);

    tx.execute(
        "INSERT OR IGNORE INTO thread_metadata\
         (event_id, event_created_at, channel_id, parent_event_id, root_event_id, depth, \
          reply_count, descendant_count, last_reply_at, broadcast) \
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, 0, 0, NULL, ?7)",
        rusqlite::params![
            id,
            created_at,
            channel_id,
            rr.parent,
            rr.root,
            rr.depth,
            i64::from(broadcast),
        ],
    )
    .context("thread_metadata reply insert failed")?;

    if tx.changes() != 1 {
        // Row already present (defensive; event dedup normally prevents this).
        // Do not double-count.
        return Ok(ThreadEmit {
            root_event_id: rr.root.clone(),
            channel_id: channel_id.map(str::to_string),
        });
    }

    // Lazy stubs for parent and (if different) root.
    insert_stub(tx, &rr.parent)?;
    if rr.root != rr.parent {
        insert_stub(tx, &rr.root)?;
    }

    // parent.reply_count += 1 (+ last_reply_at); root.descendant_count += 1.
    bump_parent(tx, &rr.parent, door, created_at, now)?;
    tx.execute(
        "UPDATE thread_metadata SET descendant_count = descendant_count + 1 WHERE event_id = ?1",
        rusqlite::params![rr.root],
    )
    .context("descendant_count bump failed")?;

    Ok(ThreadEmit {
        root_event_id: rr.root.clone(),
        channel_id: channel_id.map(str::to_string),
    })
}

/// `INSERT OR IGNORE` a depth-0 stub for an existing event (its row is created
/// lazily the first time a reply needs to bump it, thread.md §1.5).
fn insert_stub(tx: &Transaction<'_>, id: &str) -> Result<()> {
    let m = load_event_meta(tx, id)?.ok_or_else(|| anyhow!("stub target event {id} missing"))?;
    tx.execute(
        "INSERT OR IGNORE INTO thread_metadata\
         (event_id, event_created_at, channel_id, parent_event_id, root_event_id, depth, \
          reply_count, descendant_count, last_reply_at, broadcast) \
         VALUES(?1, ?2, ?3, NULL, NULL, 0, 0, 0, NULL, 0)",
        rusqlite::params![id, m.created_at, m.channel_id],
    )
    .context("thread_metadata stub insert failed")?;
    Ok(())
}

/// `reply_count += 1` on the parent. `last_reply_at` is wall-clock on the local
/// door (Buzz's `NOW()`), and `max(reply.created_at)` on the mesh door (a
/// convergent LWW register, thread.md §4).
fn bump_parent(
    tx: &Transaction<'_>,
    parent: &str,
    door: Door,
    created_at: i64,
    now: i64,
) -> Result<()> {
    match door {
        Door::Local => tx.execute(
            "UPDATE thread_metadata SET reply_count = reply_count + 1, last_reply_at = ?1 \
             WHERE event_id = ?2",
            rusqlite::params![now, parent],
        ),
        Door::Mesh => tx.execute(
            "UPDATE thread_metadata SET reply_count = reply_count + 1, \
             last_reply_at = MAX(COALESCE(last_reply_at, 0), ?1) WHERE event_id = ?2",
            rusqlite::params![created_at, parent],
        ),
    }
    .context("reply_count bump failed")?;
    Ok(())
}

// ---- delete flow -----------------------------------------------------------

/// Store the deletion event, then for each `e`-tag target: soft-delete + guarded
/// counter decrements in the same transaction. Returns 39005 emits for each
/// affected root. A duplicate delete cannot double-decrement (the `deleted = 0`
/// guard).
fn delete_flow(
    tx: &Transaction<'_>,
    ev: &Event,
    id: &str,
    channel_id: Option<&str>,
    now: i64,
) -> Result<CoreOutcome> {
    insert_event_row(tx, ev, id, channel_id)?;

    let mut emits = Vec::new();
    for target_raw in e_tag_targets(ev) {
        let target = match canonical_event_id(&target_raw) {
            Ok(t) => t,
            Err(_) => continue, // non-hex e-tag: ignore
        };

        // Guarded soft-delete: only proceed if the target flips 0 -> 1.
        let changed = tx
            .execute(
                "UPDATE events SET deleted = 1 WHERE id = ?1 AND deleted = 0",
                rusqlite::params![target],
            )
            .context("soft-delete failed")?;
        if changed != 1 {
            continue; // absent or already deleted — no double decrement
        }

        fts_remove(tx, &target)?;

        if let Some(tm) = load_thread_meta(tx, &target)? {
            if let Some(parent) = tm.parent_event_id.as_deref() {
                tx.execute(
                    "UPDATE thread_metadata SET reply_count = MAX(reply_count - 1, 0) \
                     WHERE event_id = ?1",
                    rusqlite::params![parent],
                )
                .context("reply_count decrement failed")?;
            }
            if let Some(root) = tm.root_event_id {
                tx.execute(
                    "UPDATE thread_metadata SET descendant_count = MAX(descendant_count - 1, 0) \
                     WHERE event_id = ?1",
                    rusqlite::params![root],
                )
                .context("descendant_count decrement failed")?;
                emits.push(ThreadEmit {
                    root_event_id: root,
                    channel_id: tm.channel_id,
                });
            }
        }
    }

    drain_pending(tx, id, now, &mut emits)?;
    Ok(CoreOutcome::Accepted(IngestEffects {
        duplicate: false,
        emits,
    }))
}

// ---- mesh door: park / quarantine / drain ----------------------------------

fn park(tx: &Transaction<'_>, ev: &Event, id: &str, parent: &str, now: i64) -> Result<()> {
    tx.execute(
        "INSERT OR REPLACE INTO pending_orphans(event_id, parent_event_id, raw, received_at) \
         VALUES(?1, ?2, ?3, ?4)",
        rusqlite::params![id, parent, ev.as_json(), now],
    )
    .context("park orphan failed")?;
    tracing::debug!(
        event_id = id,
        parent = parent,
        "mesh reply parked (parent missing)"
    );
    Ok(())
}

fn quarantine(tx: &Transaction<'_>, ev: &Event, id: &str, reason: &str, now: i64) -> Result<()> {
    tx.execute(
        "INSERT OR REPLACE INTO quarantine(event_id, raw, reason, received_at) \
         VALUES(?1, ?2, ?3, ?4)",
        rusqlite::params![id, ev.as_json(), reason, now],
    )
    .context("quarantine failed")?;
    tracing::warn!(
        event_id = id,
        reason = reason,
        "mesh event quarantined (ancestry mismatch)"
    );
    Ok(())
}

/// Drain pending orphans made attachable by the arrival of `new_id`. Attaches
/// each atomically (validate ancestry -> insert -> bump counters), then
/// recursively drains that event's own descendants. Uses mesh semantics: an
/// ancestry mismatch quarantines rather than rejects. Accumulates 39005 emits.
fn drain_pending(
    tx: &Transaction<'_>,
    new_id: &str,
    now: i64,
    emits: &mut Vec<ThreadEmit>,
) -> Result<()> {
    let mut stack = vec![new_id.to_string()];
    while let Some(pid) = stack.pop() {
        let orphans = pending_children(tx, &pid)?;
        for (oid, raw) in orphans {
            // Remove from the pending set regardless of outcome.
            tx.execute(
                "DELETE FROM pending_orphans WHERE event_id = ?1",
                rusqlite::params![oid],
            )
            .context("pending_orphans delete failed")?;

            if event_exists(tx, &oid)? {
                continue; // already attached via another path
            }

            let ev = Event::from_json(&raw).context("failed to parse parked orphan JSON")?;
            let channel_id = resolve_channel(&ev);
            let tags = tag_vecs(&ev);
            match resolve_markers(&tags) {
                Markers::TopLevel => {
                    // A parked event should have been a reply; if not, store it.
                    insert_event_row(tx, &ev, &oid, channel_id.as_deref())?;
                    stack.push(oid);
                }
                Markers::Reply { parent, root_hint } => {
                    match resolve_reply(tx, channel_id.as_deref(), &parent, &root_hint)? {
                        ReplyResolution::ParentMissing => {
                            // Parent still absent (should not happen for a child
                            // of `pid`): re-park to preserve the invariant.
                            park(tx, &ev, &oid, &parent, now)?;
                        }
                        ReplyResolution::Mismatch(reason) => {
                            quarantine(tx, &ev, &oid, &reason, now)?;
                        }
                        ReplyResolution::Ok(rr) => {
                            let emit = insert_reply(
                                tx,
                                &ev,
                                &oid,
                                channel_id.as_deref(),
                                &rr,
                                Door::Mesh,
                                now,
                            )?;
                            emits.push(emit);
                            stack.push(oid);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

// ---- low-level DB helpers --------------------------------------------------

struct EventMeta {
    created_at: i64,
    channel_id: Option<String>,
    tags: Vec<Vec<String>>,
}

struct ThreadMetaRow {
    parent_event_id: Option<String>,
    root_event_id: Option<String>,
    depth: Option<i64>,
    channel_id: Option<String>,
}

fn event_exists(tx: &Transaction<'_>, id: &str) -> Result<bool> {
    let found: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM events WHERE id = ?1 LIMIT 1",
            rusqlite::params![id],
            |_| Ok(1),
        )
        .optional()
        .context("event_exists query failed")?;
    Ok(found.is_some())
}

fn load_event_meta(tx: &Transaction<'_>, id: &str) -> Result<Option<EventMeta>> {
    let row: Option<(i64, Option<String>, String)> = tx
        .query_row(
            "SELECT created_at, channel_id, tags FROM events WHERE id = ?1",
            rusqlite::params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .context("load_event_meta query failed")?;
    match row {
        None => Ok(None),
        Some((created_at, channel_id, tags_json)) => {
            let tags: Vec<Vec<String>> =
                serde_json::from_str(&tags_json).context("failed to decode stored tags")?;
            Ok(Some(EventMeta {
                created_at,
                channel_id,
                tags,
            }))
        }
    }
}

fn load_thread_meta(tx: &Transaction<'_>, id: &str) -> Result<Option<ThreadMetaRow>> {
    tx.query_row(
        "SELECT parent_event_id, root_event_id, depth, channel_id \
         FROM thread_metadata WHERE event_id = ?1",
        rusqlite::params![id],
        |r| {
            Ok(ThreadMetaRow {
                parent_event_id: r.get(0)?,
                root_event_id: r.get(1)?,
                depth: r.get(2)?,
                channel_id: r.get(3)?,
            })
        },
    )
    .optional()
    .context("load_thread_meta query failed")
}

fn pending_children(tx: &Transaction<'_>, parent: &str) -> Result<Vec<(String, String)>> {
    let mut stmt = tx
        .prepare("SELECT event_id, raw FROM pending_orphans WHERE parent_event_id = ?1")
        .context("prepare pending_children failed")?;
    let rows = stmt
        .query_map(rusqlite::params![parent], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .context("pending_children query failed")?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.context("pending_children row failed")?);
    }
    Ok(out)
}

/// Insert a fresh event row (`deleted = 0`). Caller has already dup-checked.
pub(crate) fn insert_event_row(
    tx: &Transaction<'_>,
    ev: &Event,
    id: &str,
    channel_id: Option<&str>,
) -> Result<()> {
    let pubkey = ev.pubkey.to_hex();
    let created_at = i64::try_from(ev.created_at.as_secs()).context("created_at out of i64")?;
    let kind = i64::from(ev.kind.as_u16());
    let tags_vec: Vec<Vec<String>> = ev.tags.iter().map(|t| t.as_slice().to_vec()).collect();
    let tags_json = serde_json::to_string(&tags_vec).context("failed to encode tags")?;
    let sig = ev.sig.to_string();
    let raw = ev.as_json();

    tx.execute(
        "INSERT INTO events(id, pubkey, created_at, kind, tags, content, sig, raw, channel_id, deleted) \
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
        rusqlite::params![
            id,
            pubkey,
            created_at,
            kind,
            tags_json,
            ev.content,
            sig,
            raw,
            channel_id,
        ],
    )
    .map_err(|e| anyhow!("events insert failed: {e}"))?;
    Ok(())
}

/// Remove an event's content from the FTS index (invisibility on soft-delete).
/// The `AFTER UPDATE` trigger re-indexes on the `deleted` flip, so this runs
/// after the flip to take effect.
fn fts_remove(tx: &Transaction<'_>, id: &str) -> Result<()> {
    let row: Option<(i64, String)> = tx
        .query_row(
            "SELECT rowid, content FROM events WHERE id = ?1",
            rusqlite::params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .context("fts_remove lookup failed")?;
    if let Some((rowid, content)) = row {
        tx.execute(
            "INSERT INTO events_fts(events_fts, rowid, content) VALUES('delete', ?1, ?2)",
            rusqlite::params![rowid, content],
        )
        .context("fts delete failed")?;
    }
    Ok(())
}

// ---- pure tag helpers ------------------------------------------------------

fn tag_vecs(ev: &Event) -> Vec<Vec<String>> {
    ev.tags.iter().map(|t| t.as_slice().to_vec()).collect()
}

/// First resolvable `#h` channel of an event, lowercased (`None` = global).
pub(crate) fn resolve_channel(ev: &Event) -> Option<String> {
    proto::event_channels(ev).into_iter().next()
}

fn has_broadcast(ev: &Event) -> bool {
    ev.tags.iter().any(|t| {
        let s = t.as_slice();
        s.len() >= 2 && s[0] == "broadcast" && s[1] == "1"
    })
}

fn e_tag_targets(ev: &Event) -> Vec<String> {
    ev.tags
        .iter()
        .filter_map(|t| {
            let s = t.as_slice();
            if s.first().map(String::as_str) == Some("e") {
                s.get(1).cloned()
            } else {
                None
            }
        })
        .collect()
}

enum Markers {
    TopLevel,
    Reply { parent: String, root_hint: String },
}

/// Marked NIP-10 e-tags only: first `root` marker and first `reply` marker whose
/// value is 64-hex. `mention`, positional, and non-hex tags are ignored.
fn scan_markers(tags: &[Vec<String>]) -> (Option<String>, Option<String>) {
    let mut root = None;
    let mut reply = None;
    for t in tags {
        if t.len() >= 4 && t[0] == "e" && is_64hex(&t[1]) {
            match t[3].as_str() {
                "root" if root.is_none() => root = Some(t[1].to_ascii_lowercase()),
                "reply" if reply.is_none() => reply = Some(t[1].to_ascii_lowercase()),
                _ => {}
            }
        }
    }
    (root, reply)
}

/// The 4-row marker table (thread.md §1.3). Only-root => top-level (the surprise).
fn resolve_markers(tags: &[Vec<String>]) -> Markers {
    let (root, reply) = scan_markers(tags);
    match (root, reply) {
        (None, None) | (Some(_), None) => Markers::TopLevel,
        (None, Some(p)) => Markers::Reply {
            parent: p.clone(),
            root_hint: p,
        },
        (Some(r), Some(p)) => Markers::Reply {
            parent: p,
            root_hint: r,
        },
    }
}

/// Re-derive an event's own root from its root-then-reply markers, defaulting to
/// its own id (the parent-has-no-row branch, thread.md §1.4).
fn derive_own_root(tags: &[Vec<String>], own_id: &str) -> String {
    let (root, reply) = scan_markers(tags);
    root.or(reply).unwrap_or_else(|| own_id.to_string())
}

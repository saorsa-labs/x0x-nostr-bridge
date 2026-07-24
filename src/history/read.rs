//! Read surface — channel window, thread replies, thread summary. Owner: WP1.
//!
//! These implement the NORMATIVE keyset predicates and the `limit + 1`
//! exhaustion probe from design §3. They run under the store's connection lock
//! and return DATA (rows + summary/bounds payloads); the 39005/39006 event
//! synthesis and signing are the HTTP/WS lane's job.

use anyhow::{Context, Result};
use nostr::{Event, JsonUtil};
use rusqlite::{Connection, OptionalExtension};

use crate::history::engine::{DEPTH_CAP, PARTICIPANT_CAP};
use crate::history::types::{
    ThreadCursor, ThreadPage, ThreadSummary, WindowBounds, WindowCursor, WindowPage,
};

/// Clamp a caller-supplied page limit to a sane range. WP2 owns the Buzz
/// 50/200 policy; this only guards against 0 and pathological values (the
/// `limit + 1` probe must not overflow or select the whole table).
fn clamp_limit(limit: usize) -> usize {
    limit.clamp(1, 500)
}

/// Aux kinds are never timeline rows: reactions (7), deletions (5 / NIP-29
/// 9005) are appended as the aux closure, not as window rows. The design's
/// top-level predicate is depth-only because Buzz applies it to a kind-filtered
/// set; excluding these here keeps a reaction from surfacing as a row.
const AUX_ROW_KINDS: [i64; 3] = [5, 7, 9005];

/// Top-level channel timeline, keyset-paginated `created_at DESC, id ASC`.
pub(crate) fn channel_window(
    conn: &Connection,
    channel_id: &str,
    limit: usize,
    cursor: Option<WindowCursor>,
) -> Result<WindowPage> {
    let lim = clamp_limit(limit);
    let fetch = lim + 1;

    // NORMATIVE window keyset (DESC walk): created_at < :ts OR (== :ts AND id > :id).
    let (cursor_sql, cursor_ts, cursor_id) = match &cursor {
        Some(c) => (
            " AND (e.created_at < ?2 OR (e.created_at = ?2 AND e.id > ?3))",
            c.created_at,
            c.id.clone(),
        ),
        None => ("", 0_i64, String::new()),
    };

    let sql = format!(
        "SELECT e.raw, e.created_at, e.id \
         FROM events e LEFT JOIN thread_metadata tm ON tm.event_id = e.id \
         WHERE e.channel_id = ?1 AND e.deleted = 0 \
           AND e.kind NOT IN (5, 7, 9005) \
           AND (tm.depth IS NULL OR tm.depth = 0 OR (tm.depth = 1 AND tm.broadcast = 1)){cursor_sql} \
         ORDER BY e.created_at DESC, e.id ASC LIMIT ?4"
    );
    let _ = AUX_ROW_KINDS; // documented inline in the SQL above

    let mut stmt = conn.prepare(&sql).context("prepare channel_window failed")?;
    let rows_iter = stmt
        .query_map(
            rusqlite::params![channel_id, cursor_ts, cursor_id, i64::try_from(fetch)?],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .context("channel_window query failed")?;

    let mut raws: Vec<(String, i64, String)> = Vec::new();
    for row in rows_iter {
        raws.push(row.context("channel_window row failed")?);
    }
    drop(stmt);

    let has_more = raws.len() == fetch;
    if has_more {
        raws.truncate(lim);
    }

    let next_cursor = if has_more {
        raws.last().map(|(_, ca, id)| WindowCursor {
            created_at: *ca,
            id: id.clone(),
        })
    } else {
        None
    };

    let mut rows = Vec::with_capacity(raws.len());
    let mut aux_targets = Vec::with_capacity(raws.len());
    let mut summaries = Vec::new();
    for (raw, _ca, id) in &raws {
        aux_targets.push(id.clone());
        if let Some(summary) = thread_summary(conn, id)? {
            // Only rows that actually have replies carry a 39005 overlay.
            if summary.reply_count > 0 || summary.descendant_count > 0 {
                summaries.push(summary);
            }
        }
        rows.push(Event::from_json(raw).context("failed to deserialize window row")?);
    }

    Ok(WindowPage {
        rows,
        aux_targets,
        summaries,
        bounds: WindowBounds {
            has_more,
            next_cursor,
        },
    })
}

/// All replies under `root`, keyset-paginated `event_created_at ASC, event_id
/// ASC`. Excludes the root's own depth-0 stub and soft-deleted rows.
pub(crate) fn thread_replies(
    conn: &Connection,
    root: &str,
    depth_limit: Option<u32>,
    limit: usize,
    cursor: Option<ThreadCursor>,
) -> Result<ThreadPage> {
    let lim = clamp_limit(limit);
    let fetch = lim + 1;
    let dl = depth_limit.map_or(DEPTH_CAP, i64::from);

    // NORMATIVE thread keyset (ASC walk): created_at > :ts OR (== :ts AND id > :id).
    let (cursor_sql, cursor_ts, cursor_id) = match &cursor {
        Some(c) => (
            " AND (tm.event_created_at > ?3 OR (tm.event_created_at = ?3 AND tm.event_id > ?4))",
            c.created_at,
            c.id.clone(),
        ),
        None => ("", 0_i64, String::new()),
    };

    let sql = format!(
        "SELECT e.raw, tm.event_created_at, tm.event_id \
         FROM thread_metadata tm JOIN events e ON e.id = tm.event_id \
         WHERE tm.root_event_id = ?1 AND e.deleted = 0 \
           AND tm.depth >= 1 AND tm.depth <= ?2{cursor_sql} \
         ORDER BY tm.event_created_at ASC, tm.event_id ASC LIMIT ?5"
    );

    let mut stmt = conn.prepare(&sql).context("prepare thread_replies failed")?;
    let rows_iter = stmt
        .query_map(
            rusqlite::params![root, dl, cursor_ts, cursor_id, i64::try_from(fetch)?],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .context("thread_replies query failed")?;

    let mut raws: Vec<(String, i64, String)> = Vec::new();
    for row in rows_iter {
        raws.push(row.context("thread_replies row failed")?);
    }
    drop(stmt);

    let has_more = raws.len() == fetch;
    if has_more {
        raws.truncate(lim);
    }
    let next_cursor = if has_more {
        raws.last().map(|(_, ca, id)| ThreadCursor {
            created_at: *ca,
            id: id.clone(),
        })
    } else {
        None
    };

    let mut rows = Vec::with_capacity(raws.len());
    for (raw, _ca, _id) in &raws {
        rows.push(Event::from_json(raw).context("failed to deserialize thread reply")?);
    }

    Ok(ThreadPage {
        rows,
        has_more,
        next_cursor,
    })
}

/// Summary for a root: counters off the root's stub + participants derived at
/// read time. `None` when the root has no stub (no replies ever) or the root
/// event itself is soft-deleted (V15 note: `emit_live_thread_summary` no-ops).
pub(crate) fn thread_summary(conn: &Connection, root: &str) -> Result<Option<ThreadSummary>> {
    let row: Option<(i64, i64, Option<i64>, Option<String>)> = conn
        .query_row(
            "SELECT tm.reply_count, tm.descendant_count, tm.last_reply_at, tm.channel_id \
             FROM thread_metadata tm JOIN events e ON e.id = tm.event_id \
             WHERE tm.event_id = ?1 AND e.deleted = 0",
            rusqlite::params![root],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .context("thread_summary counters query failed")?;

    let (reply_count, descendant_count, last_reply_at, channel_id) = match row {
        None => return Ok(None),
        Some(v) => v,
    };

    // participants: DISTINCT reply pubkey over the subtree, ORDER BY
    // MAX(created_at) DESC, capped at PARTICIPANT_CAP (finding 5).
    let mut stmt = conn
        .prepare(
            "SELECT e.pubkey FROM thread_metadata tm JOIN events e ON e.id = tm.event_id \
             WHERE tm.root_event_id = ?1 AND e.deleted = 0 \
             GROUP BY e.pubkey ORDER BY MAX(e.created_at) DESC LIMIT ?2",
        )
        .context("prepare participants failed")?;
    let part_iter = stmt
        .query_map(rusqlite::params![root, PARTICIPANT_CAP], |r| {
            r.get::<_, String>(0)
        })
        .context("participants query failed")?;
    let mut participants = Vec::new();
    for p in part_iter {
        participants.push(p.context("participant row failed")?);
    }

    Ok(Some(ThreadSummary {
        root_event_id: root.to_string(),
        channel_id,
        reply_count,
        descendant_count,
        last_reply_at,
        participants,
    }))
}

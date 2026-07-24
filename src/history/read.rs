//! Read surface — channel window, thread replies, thread summary. Owner: WP1.
//!
//! These implement the NORMATIVE keyset predicates and the `limit + 1`
//! exhaustion probe from design §3. They run under the store's connection lock
//! and return DATA (rows + summary/bounds payloads); the 39005/39006 event
//! synthesis and signing are the HTTP/WS lane's job.

use anyhow::{Context, Result};
use nostr::{Event, Filter, JsonUtil};
use rusqlite::{Connection, OptionalExtension};

use crate::history::engine::{DEPTH_CAP, PARTICIPANT_CAP};
use crate::history::types::{
    ThreadCursor, ThreadPage, ThreadSummary, WindowBounds, WindowCursor, WindowPage,
};

/// Owned SQL value used to build heterogeneous parameter lists.
type SqlValue = rusqlite::types::Value;

/// Clamp a caller-supplied page limit to a sane range. WP2 owns the Buzz
/// 50/200 policy; this only guards against 0 and pathological values (the
/// `limit + 1` probe must not overflow or select the whole table).
fn clamp_limit(limit: usize) -> usize {
    limit.clamp(1, 500)
}

/// Top-level channel timeline, keyset-paginated `created_at DESC, id ASC`.
///
/// Aux kinds (reactions 7, deletions 5 / NIP-29 9005) are never timeline rows —
/// they are the aux closure, appended separately by WP2. The design's top-level
/// predicate is depth-only because Buzz applies it to a kind-filtered set;
/// excluding these here keeps a reaction from surfacing as a row.
pub(crate) fn channel_window(
    conn: &Connection,
    channel_id: &str,
    limit: usize,
    cursor: Option<WindowCursor>,
) -> Result<WindowPage> {
    let lim = clamp_limit(limit);
    let fetch = lim + 1;

    let mut params: Vec<SqlValue> = vec![SqlValue::from(channel_id.to_string())];
    // NORMATIVE window keyset (DESC walk): created_at < :ts OR (== :ts AND id > :id).
    let cursor_sql = if let Some(c) = &cursor {
        params.push(SqlValue::from(c.created_at));
        params.push(SqlValue::from(c.created_at));
        params.push(SqlValue::from(c.id.clone()));
        " AND (e.created_at < ? OR (e.created_at = ? AND e.id > ?))"
    } else {
        ""
    };
    params.push(SqlValue::from(i64::try_from(fetch)?));

    let sql = format!(
        "SELECT e.raw, e.created_at, e.id \
         FROM events e LEFT JOIN thread_metadata tm ON tm.event_id = e.id \
         WHERE e.channel_id = ? AND e.deleted = 0 \
           AND e.kind NOT IN (5, 7, 9005) \
           AND (tm.depth IS NULL OR tm.depth = 0 OR (tm.depth = 1 AND tm.broadcast = 1)){cursor_sql} \
         ORDER BY e.created_at DESC, e.id ASC LIMIT ?"
    );

    let mut raws = run_row_query(conn, &sql, params)?;

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

    let mut params: Vec<SqlValue> = vec![SqlValue::from(root.to_string()), SqlValue::from(dl)];
    // NORMATIVE thread keyset (ASC walk): created_at > :ts OR (== :ts AND id > :id).
    let cursor_sql = if let Some(c) = &cursor {
        params.push(SqlValue::from(c.created_at));
        params.push(SqlValue::from(c.created_at));
        params.push(SqlValue::from(c.id.clone()));
        " AND (tm.event_created_at > ? OR (tm.event_created_at = ? AND tm.event_id > ?))"
    } else {
        ""
    };
    params.push(SqlValue::from(i64::try_from(fetch)?));

    let sql = format!(
        "SELECT e.raw, tm.event_created_at, tm.event_id \
         FROM thread_metadata tm JOIN events e ON e.id = tm.event_id \
         WHERE tm.root_event_id = ? AND e.deleted = 0 \
           AND tm.depth >= 1 AND tm.depth <= ?{cursor_sql} \
         ORDER BY tm.event_created_at ASC, tm.event_id ASC LIMIT ?"
    );

    let mut raws = run_row_query(conn, &sql, params)?;

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

/// Run a `(raw, created_at, id)` row query and collect the results.
fn run_row_query(
    conn: &Connection,
    sql: &str,
    params: Vec<SqlValue>,
) -> Result<Vec<(String, i64, String)>> {
    let mut stmt = conn.prepare(sql).context("prepare row query failed")?;
    let rows_iter = stmt
        .query_map(rusqlite::params_from_iter(params), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .context("row query failed")?;
    let mut out = Vec::new();
    for row in rows_iter {
        out.push(row.context("row read failed")?);
    }
    Ok(out)
}

/// `?,?,…` of length `n`.
fn placeholders(n: usize) -> String {
    std::iter::repeat_n("?", n).collect::<Vec<_>>().join(",")
}

/// Quote each whitespace token of a NIP-50 `search` string as a literal FTS5
/// phrase, AND-joined — user input never becomes an FTS operator.
fn fts_match_expr(search: &str) -> String {
    search
        .split_whitespace()
        .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// General Nostr-filter read over the events table (WP2 seam for the plain
/// `/query` paths — ids / directory / search / seed-check — and `/count`, plus
/// the aux-closure resolution). Excludes soft-deleted rows; orders
/// `created_at DESC, id ASC`. An empty `Some(set)` matches nothing (NIP-01).
///
/// M1a-WIRING: added by WP2 over WP1's schema so the HTTP dialect's non-window
/// paths hit the SAME store as `channel_window`. Access classes / p-gated FTS
/// nulling are enforced in the HTTP layer, not here.
pub(crate) fn query(conn: &Connection, filter: &Filter, max_limit: usize) -> Result<Vec<Event>> {
    if filter.ids.as_ref().is_some_and(|s| s.is_empty())
        || filter.authors.as_ref().is_some_and(|s| s.is_empty())
        || filter.kinds.as_ref().is_some_and(|s| s.is_empty())
        || filter.generic_tags.values().any(|s| s.is_empty())
    {
        return Ok(Vec::new());
    }

    let limit = filter.limit.unwrap_or(max_limit).min(max_limit);
    let mut where_parts: Vec<String> = vec!["e.deleted = 0".to_string()];
    let mut params: Vec<SqlValue> = Vec::new();

    if let Some(ids) = &filter.ids {
        where_parts.push(format!("e.id IN ({})", placeholders(ids.len())));
        for v in ids {
            params.push(SqlValue::from(v.to_hex()));
        }
    }
    if let Some(authors) = &filter.authors {
        where_parts.push(format!("e.pubkey IN ({})", placeholders(authors.len())));
        for v in authors {
            params.push(SqlValue::from(v.to_hex()));
        }
    }
    if let Some(kinds) = &filter.kinds {
        where_parts.push(format!("e.kind IN ({})", placeholders(kinds.len())));
        for v in kinds {
            params.push(SqlValue::from(i64::from(v.as_u16())));
        }
    }
    if let Some(since) = filter.since {
        where_parts.push("e.created_at >= ?".to_string());
        params.push(SqlValue::from(i64::try_from(since.as_secs())?));
    }
    if let Some(until) = filter.until {
        where_parts.push("e.created_at <= ?".to_string());
        params.push(SqlValue::from(i64::try_from(until.as_secs())?));
    }
    if let Some(search) = &filter.search {
        let fts = fts_match_expr(search);
        if !fts.is_empty() {
            where_parts.push(
                "e.rowid IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)".to_string(),
            );
            params.push(SqlValue::from(fts));
        }
    }
    for (tag, values) in &filter.generic_tags {
        let name = tag.as_str();
        let ph = placeholders(values.len());
        if name == "h" {
            where_parts.push(format!(
                "EXISTS(SELECT 1 FROM json_each(e.tags) \
                 WHERE json_extract(value, '$[0]') = ? \
                   AND LOWER(json_extract(value, '$[1]')) IN ({ph}))"
            ));
            params.push(SqlValue::from("h".to_string()));
            for v in values {
                params.push(SqlValue::from(v.to_lowercase()));
            }
        } else {
            where_parts.push(format!(
                "EXISTS(SELECT 1 FROM json_each(e.tags) \
                 WHERE json_extract(value, '$[0]') = ? \
                   AND json_extract(value, '$[1]') IN ({ph}))"
            ));
            params.push(SqlValue::from(name.to_string()));
            for v in values {
                params.push(SqlValue::from(v.clone()));
            }
        }
    }

    let mut sql = String::from("SELECT e.raw FROM events e WHERE ");
    sql.push_str(&where_parts.join(" AND "));
    sql.push_str(" ORDER BY e.created_at DESC, e.id ASC LIMIT ?");
    params.push(SqlValue::from(i64::try_from(limit)?));

    let mut stmt = conn.prepare(&sql).context("prepare filter query failed")?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params), |r| r.get::<_, String>(0))
        .context("filter query failed")?;
    let mut out = Vec::new();
    for row in rows {
        let raw = row.context("row read failed")?;
        out.push(Event::from_json(&raw).context("failed to deserialize queried event")?);
    }
    Ok(out)
}

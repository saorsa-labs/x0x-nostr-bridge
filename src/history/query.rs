//! General Nostr-filter read + count over the history `events` table. Owner: WP1.
//!
//! The window/thread read model (`read.rs`) covers the channel-timeline paths;
//! the HTTP/WS lane also needs plain NIP-01 filter reads for the seed poll
//! (`kinds:[39000]`), get-event-by-ids, the kind:0 directory (offset paging),
//! NIP-50 search, `/count`, and the aux-closure lookups (reactions/deletions/
//! edits targeting window rows). This module is that primitive.
//!
//! It mirrors the spike's `store.rs::query` semantics — exact ids/authors/kinds,
//! since/until inclusive, generic `#tag` matching via `json_each` (with `#h`
//! lowercased), `search` via FTS5 MATCH, order `created_at DESC, id ASC`, limit
//! capped at `proto::MAX_FILTER_LIMIT` — with two history-store additions:
//! soft-`deleted` rows are excluded, and an `offset` supports directory paging.

use anyhow::{anyhow, Context, Result};
use nostr::{Event, Filter, JsonUtil};
use rusqlite::Connection;

use crate::proto;

type SqlValue = rusqlite::types::Value;

/// `n` comma-separated `?` placeholders. Caller guarantees `n > 0`.
fn placeholders(n: usize) -> String {
    std::iter::repeat_n("?", n).collect::<Vec<_>>().join(",")
}

/// Build a safe FTS5 MATCH expression: split on whitespace, escape inner double
/// quotes, wrap each token as a phrase (AND of the terms). "" for blank input.
fn fts_match_expr(search: &str) -> String {
    search
        .split_whitespace()
        .map(|tok| format!("\"{}\"", tok.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The shared WHERE fragment + bound params for a filter. `None` return means
/// the filter is unsatisfiable (an empty `Some(set)` matches nothing).
fn build_where(filter: &Filter) -> Option<(Vec<String>, Vec<SqlValue>)> {
    if filter.ids.as_ref().is_some_and(|s| s.is_empty())
        || filter.authors.as_ref().is_some_and(|s| s.is_empty())
        || filter.kinds.as_ref().is_some_and(|s| s.is_empty())
        || filter.generic_tags.values().any(|s| s.is_empty())
    {
        return None;
    }

    // Soft-deleted rows are invisible to every served surface.
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
        params.push(SqlValue::from(
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
        ));
    }
    if let Some(until) = filter.until {
        where_parts.push("e.created_at <= ?".to_string());
        params.push(SqlValue::from(
            i64::try_from(until.as_secs()).unwrap_or(i64::MAX),
        ));
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
    // Generic `#x` tag filters. `#h` matches case-insensitively (channel ids are
    // lowercased on ingest); all other tags match exactly per NIP-01.
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

    Some((where_parts, params))
}

/// General filter read. `offset` supports directory (kind:0) `page` paging; pass
/// 0 for head reads. Order `created_at DESC, id ASC`; limit capped at
/// `proto::MAX_FILTER_LIMIT`.
pub(crate) fn query(conn: &Connection, filter: &Filter, offset: usize) -> Result<Vec<Event>> {
    let Some((where_parts, mut params)) = build_where(filter) else {
        return Ok(Vec::new());
    };

    let limit = filter
        .limit
        .unwrap_or(proto::MAX_FILTER_LIMIT)
        .min(proto::MAX_FILTER_LIMIT);

    let sql = format!(
        "SELECT e.raw FROM events e WHERE {} \
         ORDER BY e.created_at DESC, e.id ASC LIMIT ? OFFSET ?",
        where_parts.join(" AND ")
    );
    params.push(SqlValue::from(i64::try_from(limit)?));
    params.push(SqlValue::from(i64::try_from(offset)?));

    let mut stmt = conn.prepare(&sql).context("prepare query failed")?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params), |r| {
            r.get::<_, String>(0)
        })
        .map_err(|e| anyhow!("query_map failed: {e}"))?;
    let mut out = Vec::new();
    for row in rows {
        let raw = row.map_err(|e| anyhow!("row read failed: {e}"))?;
        out.push(Event::from_json(&raw).context("failed to deserialize stored event")?);
    }
    Ok(out)
}

/// Count matching (non-deleted) events for a filter, ignoring limit/offset.
pub(crate) fn count(conn: &Connection, filter: &Filter) -> Result<usize> {
    let Some((where_parts, params)) = build_where(filter) else {
        return Ok(0);
    };
    let sql = format!(
        "SELECT COUNT(*) FROM events e WHERE {}",
        where_parts.join(" AND ")
    );
    let n: i64 = conn
        .query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
        .context("count query failed")?;
    Ok(usize::try_from(n).unwrap_or(0))
}

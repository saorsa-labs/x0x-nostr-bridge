//! General filter read (`query`/`count`) + FTS `search` over the history
//! `events` table. Owner: WP1 (WP1b follow-up).
//!
//! The window/thread read model (`read.rs`) covers the channel-timeline paths;
//! the HTTP/WS lane also needs plain NIP-01 filter reads for the seed poll
//! (`kinds:[39000]`), get-event-by-ids, the kind:0 directory (offset paging),
//! NIP-50 search, `/count`, and the aux-closure lookups (reactions/deletions/
//! edits targeting window rows, then deletions of those aux events). This module
//! is that primitive, driven by the backend-agnostic [`FilterSpec`].
//!
//! Invariants (shared with the whole served surface): soft-`deleted` rows are
//! excluded; parked/quarantined events are never in `events`, so they are
//! structurally invisible; ordering is `created_at DESC, id ASC`; `#h` matches
//! case-insensitively (channel ids are stored lowercase).

use anyhow::{anyhow, Context, Result};
use nostr::{Event, JsonUtil};
use rusqlite::Connection;

use crate::history::types::FilterSpec;
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

/// Push a `column IN (...)` clause for a non-empty list, binding each value.
fn push_in_clause(
    where_parts: &mut Vec<String>,
    params: &mut Vec<SqlValue>,
    column: &str,
    values: impl IntoIterator<Item = SqlValue>,
) {
    let vals: Vec<SqlValue> = values.into_iter().collect();
    if vals.is_empty() {
        return;
    }
    where_parts.push(format!("{column} IN ({})", placeholders(vals.len())));
    params.extend(vals);
}

/// Push a generic-tag `EXISTS(... json_each ...)` clause for a non-empty list.
/// `#h` is matched case-insensitively (both sides lowercased); other tags exact.
fn push_tag_clause(
    where_parts: &mut Vec<String>,
    params: &mut Vec<SqlValue>,
    tag: &str,
    values: &[String],
    lowercase: bool,
) {
    if values.is_empty() {
        return;
    }
    let ph = placeholders(values.len());
    let value_expr = if lowercase {
        "LOWER(json_extract(value, '$[1]'))"
    } else {
        "json_extract(value, '$[1]')"
    };
    where_parts.push(format!(
        "EXISTS(SELECT 1 FROM json_each(e.tags) \
         WHERE json_extract(value, '$[0]') = ? AND {value_expr} IN ({ph}))"
    ));
    params.push(SqlValue::from(tag.to_string()));
    for v in values {
        let v = if lowercase {
            v.to_lowercase()
        } else {
            v.clone()
        };
        params.push(SqlValue::from(v));
    }
}

/// WHERE fragment + params for a [`FilterSpec`]. An empty list field is
/// UNCONSTRAINED (contributes no clause); soft-deleted rows are always excluded.
fn build_where(f: &FilterSpec) -> (Vec<String>, Vec<SqlValue>) {
    let mut where_parts: Vec<String> = vec!["e.deleted = 0".to_string()];
    let mut params: Vec<SqlValue> = Vec::new();

    push_in_clause(
        &mut where_parts,
        &mut params,
        "e.id",
        f.ids.iter().map(|s| SqlValue::from(s.to_lowercase())),
    );
    push_in_clause(
        &mut where_parts,
        &mut params,
        "e.pubkey",
        f.authors.iter().map(|s| SqlValue::from(s.to_lowercase())),
    );
    push_in_clause(
        &mut where_parts,
        &mut params,
        "e.kind",
        f.kinds.iter().map(|k| SqlValue::from(i64::from(*k))),
    );
    if let Some(since) = f.since {
        where_parts.push("e.created_at >= ?".to_string());
        params.push(SqlValue::from(since));
    }
    if let Some(until) = f.until {
        where_parts.push("e.created_at <= ?".to_string());
        params.push(SqlValue::from(until));
    }
    push_tag_clause(&mut where_parts, &mut params, "h", &f.h, true);
    push_tag_clause(&mut where_parts, &mut params, "e", &f.e, false);
    push_tag_clause(&mut where_parts, &mut params, "p", &f.p, false);

    (where_parts, params)
}

fn collect_events(conn: &Connection, sql: &str, params: Vec<SqlValue>) -> Result<Vec<Event>> {
    let mut stmt = conn.prepare(sql).context("prepare query failed")?;
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

/// General filter read. `offset` supports directory (kind:0) `page` paging (0 for
/// head reads). `limit` is capped at `proto::MAX_FILTER_LIMIT`. Order
/// `created_at DESC, id ASC`.
pub(crate) fn query(
    conn: &Connection,
    f: &FilterSpec,
    limit: usize,
    offset: usize,
) -> Result<Vec<Event>> {
    let (where_parts, mut params) = build_where(f);
    let limit = limit.min(proto::MAX_FILTER_LIMIT);

    let sql = format!(
        "SELECT e.raw FROM events e WHERE {} \
         ORDER BY e.created_at DESC, e.id ASC LIMIT ? OFFSET ?",
        where_parts.join(" AND ")
    );
    params.push(SqlValue::from(i64::try_from(limit)?));
    params.push(SqlValue::from(i64::try_from(offset)?));
    collect_events(conn, &sql, params)
}

/// Distinct non-null `channel_id`s across stored events, for startup topic
/// pre-subscribe. Excludes soft-deleted rows.
pub(crate) fn known_channels(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT channel_id FROM events \
             WHERE channel_id IS NOT NULL AND deleted = 0 ORDER BY channel_id",
        )
        .context("prepare known_channels failed")?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .context("known_channels query failed")?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.context("known_channels row failed")?);
    }
    Ok(out)
}

/// Count matching (non-deleted) events for a filter, ignoring limit/offset.
pub(crate) fn count(conn: &Connection, f: &FilterSpec) -> Result<u64> {
    let (where_parts, params) = build_where(f);
    let sql = format!(
        "SELECT COUNT(*) FROM events e WHERE {}",
        where_parts.join(" AND ")
    );
    let n: i64 = conn
        .query_row(&sql, rusqlite::params_from_iter(params), |r| r.get(0))
        .context("count query failed")?;
    Ok(u64::try_from(n).unwrap_or(0))
}

/// NIP-50 FTS search over event content. Optional `kinds` allowlist and
/// `channel` (`#h`) scope; `exclude_kinds` removes kinds that must be
/// unsearchable (WP2 passes its p-gated set — p-gated content must never surface
/// via search, per buzz_core). Order `created_at DESC, id ASC`; limit capped.
pub(crate) fn search(
    conn: &Connection,
    text: &str,
    kinds: &[u32],
    channel: Option<&str>,
    exclude_kinds: &[u32],
    limit: usize,
) -> Result<Vec<Event>> {
    let fts = fts_match_expr(text);
    if fts.is_empty() {
        return Ok(Vec::new());
    }
    let limit = limit.min(proto::MAX_FILTER_LIMIT);

    let mut where_parts: Vec<String> = vec![
        "e.deleted = 0".to_string(),
        "e.rowid IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)".to_string(),
    ];
    let mut params: Vec<SqlValue> = vec![SqlValue::from(fts)];

    push_in_clause(
        &mut where_parts,
        &mut params,
        "e.kind",
        kinds.iter().map(|k| SqlValue::from(i64::from(*k))),
    );
    if !exclude_kinds.is_empty() {
        where_parts.push(format!(
            "e.kind NOT IN ({})",
            placeholders(exclude_kinds.len())
        ));
        for k in exclude_kinds {
            params.push(SqlValue::from(i64::from(*k)));
        }
    }
    if let Some(ch) = channel {
        push_tag_clause(
            &mut where_parts,
            &mut params,
            "h",
            std::slice::from_ref(&ch.to_string()),
            true,
        );
    }

    let sql = format!(
        "SELECT e.raw FROM events e WHERE {} \
         ORDER BY e.created_at DESC, e.id ASC LIMIT ?",
        where_parts.join(" AND ")
    );
    params.push(SqlValue::from(i64::try_from(limit)?));
    collect_events(conn, &sql, params)
}

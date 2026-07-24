//! Event store — SQLite + FTS5. Owner: StoreAgent.
//!
//! Contract (FROZEN): implement `SqliteStore` + `EventStore` exactly as
//! declared here. Semantics:
//! - `insert` is idempotent by event id (`Duplicate`).
//! - Replaceable kinds (proto::is_replaceable): keep only latest per
//!   (pubkey, kind). Older incoming → `StaleRejected`; newer replaces →
//!   `Replaced`. Equal `created_at` ties keep the LOWEST event id (NIP-01).
//! - Parameterized-replaceable (proto::is_parameterized_replaceable): same
//!   rule keyed on (pubkey, kind, d-tag).
//! - All other kinds: plain insert → `Inserted`.
//! - Kind 5 (deletion) is stored as an ordinary event; deletion semantics
//!   are NOT applied (documented spike decision).
//! - `query` translates a nostr `Filter` to SQL: exact ids/authors (hex),
//!   kinds, since/until on created_at, generic tag queries via json_each on
//!   the tags column, `search` via FTS5 MATCH on content. Result order:
//!   created_at DESC, id ASC. Limit capped at proto::MAX_FILTER_LIMIT.
//!   NIP-01 id/author PREFIX matching is out of scope (v1.1, documented).
//!   since/until use inclusive comparisons (`>=`/`<=`) to match the live
//!   fan-out semantics of `Filter::match_event` (nostr 0.44.4).
//! - `known_channels`: distinct lowercased `h` tag values across all rows.

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use nostr::JsonUtil;
use nostr::{Event, Filter};

use crate::proto;

/// Owned SQL value used to build heterogeneous parameter lists.
type SqlValue = rusqlite::types::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted,
    Duplicate,
    Replaced,
    StaleRejected,
}

#[async_trait]
pub trait EventStore: Send + Sync {
    async fn insert(&self, ev: &Event) -> Result<InsertOutcome>;
    async fn query(&self, filter: &Filter) -> Result<Vec<Event>>;
    async fn known_channels(&self) -> Result<Vec<String>>;
}

/// SQLite-backed event store. A single `rusqlite::Connection` is guarded by a
/// `std::sync::Mutex` and shared via `Arc`; every async method offloads its
/// (synchronous) DB work to `tokio::task::spawn_blocking`.
pub struct SqliteStore {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = rusqlite::Connection::open(path)
            .with_context(|| format!("failed to open sqlite at {}", path.display()))?;
        // WAL is persisted in the db header; foreign_keys is per-connection
        // and must be set on every connection we open.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
        migrate(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

/// Idempotent schema setup. Tables, indexes, an FTS5 external-content table on
/// `events.content`, and the triggers that keep it in sync. All writes go
/// through the `events` table, so the AFTER INSERT/DELETE/UPDATE triggers
/// maintain `events_fts` automatically within the same transaction.
fn migrate(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS events (
            id         TEXT PRIMARY KEY,
            pubkey     TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            kind       INTEGER NOT NULL,
            tags       TEXT NOT NULL,   -- JSON array of [name, value, ...]
            content    TEXT NOT NULL,
            sig        TEXT NOT NULL,
            raw        TEXT NOT NULL    -- full canonical event JSON
        );

        CREATE INDEX IF NOT EXISTS idx_events_kind       ON events(kind);
        CREATE INDEX IF NOT EXISTS idx_events_pubkey     ON events(pubkey);
        CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);

        -- Replaceable bookkeeping: one row per (pubkey, kind, d-tag) slot
        -- pointing at the currently-winning event. For non-parameterized
        -- replaceable kinds d_tag is always ''.
        CREATE TABLE IF NOT EXISTS replaceable_addrs (
            pubkey     TEXT NOT NULL,
            kind       INTEGER NOT NULL,
            d_tag      TEXT NOT NULL,
            event_id   TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (pubkey, kind, d_tag)
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
            content,
            content='events',
            content_rowid='rowid'
        );

        CREATE TRIGGER IF NOT EXISTS events_fts_ai AFTER INSERT ON events BEGIN
            INSERT INTO events_fts(rowid, content) VALUES (new.rowid, new.content);
        END;
        CREATE TRIGGER IF NOT EXISTS events_fts_ad AFTER DELETE ON events BEGIN
            INSERT INTO events_fts(events_fts, rowid, content) VALUES('delete', old.rowid, old.content);
        END;
        CREATE TRIGGER IF NOT EXISTS events_fts_au AFTER UPDATE ON events BEGIN
            INSERT INTO events_fts(events_fts, rowid, content) VALUES('delete', old.rowid, old.content);
            INSERT INTO events_fts(rowid, content) VALUES (new.rowid, new.content);
        END;
        "#,
    )
    .context("schema migration failed")?;
    Ok(())
}

/// Columns of one `events` row, ready to bind. Grouped so the insert helper
/// stays readable and below clippy's argument limit.
struct EventRow<'a> {
    id: &'a str,
    pubkey: &'a str,
    created_at: i64,
    kind: i64,
    tags_json: &'a str,
    content: &'a str,
    sig: &'a str,
    raw: &'a str,
}

/// Bind a fresh row into `events`. The FTS AFTER INSERT trigger indexes it.
fn insert_event(tx: &rusqlite::Transaction<'_>, row: &EventRow<'_>) -> Result<()> {
    tx.execute(
        "INSERT INTO events(id, pubkey, created_at, kind, tags, content, sig, raw) \
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            row.id,
            row.pubkey,
            row.created_at,
            row.kind,
            row.tags_json,
            row.content,
            row.sig,
            row.raw
        ],
    )
    .map_err(|e| anyhow!("events insert failed: {e}"))?;
    Ok(())
}

#[async_trait]
impl EventStore for SqliteStore {
    async fn insert(&self, ev: &Event) -> Result<InsertOutcome> {
        // Extract everything needed for binding in the async context, then move
        // owned data into the blocking task (rusqlite is synchronous).
        let id = ev.id.to_hex();
        let pubkey = ev.pubkey.to_hex();
        let created_at =
            i64::try_from(ev.created_at.as_secs()).context("created_at out of i64 range")?;
        let kind = i64::from(ev.kind.as_u16());
        let tags_vec: Vec<Vec<String>> = ev.tags.iter().map(|t| t.as_slice().to_vec()).collect();
        let tags_json = serde_json::to_string(&tags_vec).context("failed to encode tags")?;
        let content = ev.content.clone();
        let sig = ev.sig.to_string();
        let raw = ev.as_json();

        let param_repl = proto::is_parameterized_replaceable(ev.kind);
        let replaceable = proto::is_replaceable(ev.kind) || param_repl;
        // Parameterized slots key on the first `d` tag value (default "" per
        // NIP-33); plain replaceable slots always use "".
        let d_key = if param_repl {
            proto::d_tag(ev).unwrap_or_default()
        } else {
            String::new()
        };

        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<InsertOutcome> {
            let mut guard = lock(&conn)?;
            let tx = guard.transaction()?;

            // 1. Idempotent by event id.
            let dup: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM events WHERE id = ?1 LIMIT 1",
                    rusqlite::params![id],
                    |_| Ok(1_i64),
                )
                .optional()?;
            if dup.is_some() {
                // Nothing to write; commit is a no-op.
                tx.commit()?;
                return Ok(InsertOutcome::Duplicate);
            }

            let row = EventRow {
                id: id.as_str(),
                pubkey: pubkey.as_str(),
                created_at,
                kind,
                tags_json: tags_json.as_str(),
                content: content.as_str(),
                sig: sig.as_str(),
                raw: raw.as_str(),
            };

            // 2. Replaceable / parameterized-replaceable dedup.
            let outcome = if replaceable {
                let prev: Option<(i64, String)> = tx
                    .query_row(
                        "SELECT created_at, event_id FROM replaceable_addrs \
                         WHERE pubkey = ?1 AND kind = ?2 AND d_tag = ?3",
                        rusqlite::params![pubkey, kind, d_key],
                        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                    )
                    .optional()?;
                match prev {
                    // Stored wins if strictly newer, OR equal-timestamp with a
                    // lower id — NIP-01 tie-break keeps the lowest event id.
                    Some((prev_ca, prev_id))
                        if prev_ca > created_at
                            || (prev_ca == created_at && prev_id.as_str() < id.as_str()) =>
                    {
                        InsertOutcome::StaleRejected
                    }
                    Some(_) => {
                        // Incoming wins: drop the superseded event (FTS trigger
                        // fires), insert the new one, repoint the slot.
                        tx.execute(
                            "DELETE FROM events WHERE id = (\
                             SELECT event_id FROM replaceable_addrs \
                             WHERE pubkey = ?1 AND kind = ?2 AND d_tag = ?3)",
                            rusqlite::params![pubkey, kind, d_key],
                        )
                        .map_err(|e| anyhow!("supersede delete failed: {e}"))?;
                        insert_event(&tx, &row)?;
                        tx.execute(
                            "INSERT INTO replaceable_addrs(pubkey, kind, d_tag, event_id, created_at) \
                             VALUES(?1, ?2, ?3, ?4, ?5) \
                             ON CONFLICT(pubkey, kind, d_tag) DO UPDATE SET \
                             event_id = excluded.event_id, created_at = excluded.created_at",
                            rusqlite::params![pubkey, kind, d_key, id, created_at],
                        )
                        .map_err(|e| anyhow!("replaceable_addrs upsert failed: {e}"))?;
                        InsertOutcome::Replaced
                    }
                    None => {
                        insert_event(&tx, &row)?;
                        tx.execute(
                            "INSERT INTO replaceable_addrs(pubkey, kind, d_tag, event_id, created_at) \
                             VALUES(?1, ?2, ?3, ?4, ?5)",
                            rusqlite::params![pubkey, kind, d_key, id, created_at],
                        )
                        .map_err(|e| anyhow!("replaceable_addrs insert failed: {e}"))?;
                        InsertOutcome::Inserted
                    }
                }
            } else {
                insert_event(&tx, &row)?;
                InsertOutcome::Inserted
            };

            tx.commit()?;
            Ok(outcome)
        })
        .await
        .map_err(|e| anyhow!("store insert task failed: {e}"))?
    }

    async fn query(&self, filter: &Filter) -> Result<Vec<Event>> {
        // An empty `Some(set)` matches nothing.
        if filter.ids.as_ref().is_some_and(|s| s.is_empty())
            || filter.authors.as_ref().is_some_and(|s| s.is_empty())
            || filter.kinds.as_ref().is_some_and(|s| s.is_empty())
            || filter.generic_tags.values().any(|s| s.is_empty())
        {
            return Ok(Vec::new());
        }

        let limit = filter
            .limit
            .unwrap_or(proto::MAX_FILTER_LIMIT)
            .min(proto::MAX_FILTER_LIMIT);

        let mut where_parts: Vec<String> = Vec::new();
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
            // FTS5 MATCH carries its own query syntax; quote each whitespace
            // token so user input is treated as literal phrase terms (AND of
            // the terms), never as FTS operators. The whole expression is
            // still bound as a parameter.
            let fts = fts_match_expr(search);
            if !fts.is_empty() {
                where_parts.push(
                    "e.rowid IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)"
                        .to_string(),
                );
                params.push(SqlValue::from(fts));
            }
        }
        // Generic tag filters (#x): the event must carry a tag whose name is
        // the letter and whose first value is in the provided list. `#h`
        // matches case-insensitively (proto lowercases channel ids); all other
        // tags match exactly per NIP-01.
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

        let mut sql = String::from("SELECT e.raw FROM events e");
        if !where_parts.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&where_parts.join(" AND "));
        }
        sql.push_str(" ORDER BY e.created_at DESC, e.id ASC LIMIT ?");
        params.push(SqlValue::from(i64::try_from(limit)?));

        let conn = Arc::clone(&self.conn);
        let raws = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let guard = lock(&conn)?;
            let mut stmt = guard.prepare(&sql).context("prepare query failed")?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(params), |r| {
                    r.get::<_, String>(0)
                })
                .map_err(|e| anyhow!("query_map failed: {e}"))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|e| anyhow!("row read failed: {e}"))?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| anyhow!("store query task failed: {e}"))??;

        let mut events = Vec::with_capacity(raws.len());
        for raw in raws {
            let ev = Event::from_json(&raw).context("failed to deserialize stored event JSON")?;
            events.push(ev);
        }
        Ok(events)
    }

    async fn known_channels(&self) -> Result<Vec<String>> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let guard = lock(&conn)?;
            let mut stmt = guard
                .prepare(
                    "SELECT DISTINCT LOWER(json_extract(je.value, '$[1]')) AS ch \
                     FROM events AS e, json_each(e.tags) AS je \
                     WHERE json_extract(je.value, '$[0]') = 'h' \
                       AND json_array_length(je.value) >= 2 \
                     ORDER BY ch",
                )
                .context("prepare known_channels failed")?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(|e| anyhow!("known_channels query_map failed: {e}"))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|e| anyhow!("known_channels row read failed: {e}"))?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| anyhow!("store known_channels task failed: {e}"))?
    }
}

// ---- helpers ---------------------------------------------------------------

fn lock(
    conn: &Mutex<rusqlite::Connection>,
) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>> {
    conn.lock().map_err(|e| anyhow!("db mutex poisoned: {e}"))
}

/// `n` comma-separated `?` placeholders (e.g. `"?,?,?"`). Caller guarantees `n > 0`.
fn placeholders(n: usize) -> String {
    (0..n).map(|_| "?").collect::<Vec<_>>().join(",")
}

/// Build a safe FTS5 MATCH expression from free-text search input: split on
/// whitespace, escape inner double quotes (FTS doubles them), wrap each token
/// as a phrase. Returns "" for blank input so the caller can skip the clause.
fn fts_match_expr(search: &str) -> String {
    search
        .split_whitespace()
        .map(|tok| {
            let escaped = tok.replace('"', "\"\"");
            format!("\"{escaped}\"")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// Pulls in `.optional()` for `query_row` results.
use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Alphabet;
    use nostr::TagKind;
    use nostr::{EventBuilder, Filter, Kind, SingleLetterTag, Tag, Timestamp};
    use tempfile::TempDir;

    /// Fresh on-disk store in a private temp dir (kept alive for the test).
    fn open() -> (SqliteStore, TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(&dir.path().join("bridge.db")).unwrap();
        (store, dir)
    }

    fn keys() -> nostr::Keys {
        nostr::Keys::generate()
    }

    fn build(
        keys: &nostr::Keys,
        kind: u16,
        content: &str,
        created_at: u64,
        tags: Vec<Tag>,
    ) -> Event {
        let mut b = EventBuilder::new(Kind::from(kind), content)
            .custom_created_at(Timestamp::from(created_at));
        for t in tags {
            b = b.tag(t);
        }
        b.sign_with_keys(keys).unwrap()
    }

    fn t_custom(name: &str, value: &str) -> Tag {
        Tag::custom(TagKind::custom(name), [value.to_string()])
    }

    fn h(value: &str) -> Tag {
        t_custom("h", value)
    }

    fn e_tag(value: &str) -> Tag {
        t_custom("e", value)
    }

    fn d(value: &str) -> Tag {
        t_custom("d", value)
    }

    fn letter(c: Alphabet) -> SingleLetterTag {
        SingleLetterTag::lowercase(c)
    }

    #[tokio::test]
    async fn insert_duplicate_and_roundtrip() {
        let (store, _dir) = open();
        let k = keys();
        let ev = build(&k, 1, "hello world", 1_700_000_000, vec![]);

        assert_eq!(store.insert(&ev).await.unwrap(), InsertOutcome::Inserted);
        assert_eq!(store.insert(&ev).await.unwrap(), InsertOutcome::Duplicate);

        let got = store.query(&Filter::new().id(ev.id)).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, ev.id);
        assert_eq!(got[0].sig, ev.sig); // sig round-trips intact
        assert_eq!(got[0].content, "hello world");
    }

    #[tokio::test]
    async fn replaceable_newer_wins() {
        let (store, _dir) = open();
        let k = keys();

        let old = build(&k, 0, "old-profile", 1_000, vec![]);
        let new = build(&k, 0, "new-profile", 2_000, vec![]);

        assert_eq!(store.insert(&old).await.unwrap(), InsertOutcome::Inserted);
        assert_eq!(store.insert(&new).await.unwrap(), InsertOutcome::Replaced);

        let got = store
            .query(&Filter::new().author(k.public_key()))
            .await
            .unwrap();
        assert_eq!(got.len(), 1, "only the latest metadata is kept");
        assert_eq!(got[0].content, "new-profile");
        assert_eq!(got[0].created_at.as_secs(), 2_000);
    }

    #[tokio::test]
    async fn replaceable_stale_rejected() {
        let (store, _dir) = open();
        let k = keys();

        let new = build(&k, 0, "kept", 5_000, vec![]);
        let old = build(&k, 0, "rejected", 1_000, vec![]);

        assert_eq!(store.insert(&new).await.unwrap(), InsertOutcome::Inserted);
        assert_eq!(
            store.insert(&old).await.unwrap(),
            InsertOutcome::StaleRejected
        );

        let got = store
            .query(&Filter::new().author(k.public_key()))
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].content, "kept");
    }

    #[tokio::test]
    async fn replaceable_equal_timestamp_lowest_id_wins() {
        // Equal created_at is a tie: NIP-01 keeps the lowest event id,
        // regardless of insertion order.
        let (store, _dir) = open();
        let k = keys();
        let a = build(&k, 0, "aaa", 7_000, vec![]);
        let b = build(&k, 0, "bbb", 7_000, vec![]);
        let (lower, higher) = if a.id < b.id { (a, b) } else { (b, a) };

        // Insert higher-id first, then lower-id → lower-id replaces it.
        assert_eq!(
            store.insert(&higher).await.unwrap(),
            InsertOutcome::Inserted
        );
        assert_eq!(store.insert(&lower).await.unwrap(), InsertOutcome::Replaced);
        assert_eq!(
            store
                .query(&Filter::new().author(k.public_key()))
                .await
                .unwrap()[0]
                .id,
            lower.id
        );
    }

    #[tokio::test]
    async fn parameterized_isolation_per_d_tag() {
        let (store, _dir) = open();
        let k = keys();

        let a1 = build(&k, 30_000, "a-v1", 100, vec![d("a")]);
        let a2 = build(&k, 30_000, "a-v2", 200, vec![d("a")]);
        let b1 = build(&k, 30_000, "b-v1", 100, vec![d("b")]);

        assert_eq!(store.insert(&a1).await.unwrap(), InsertOutcome::Inserted);
        assert_eq!(store.insert(&a2).await.unwrap(), InsertOutcome::Replaced); // same slot
        assert_eq!(store.insert(&b1).await.unwrap(), InsertOutcome::Inserted); // different slot

        let got = store
            .query(&Filter::new().kinds([Kind::from(30_000u16)]))
            .await
            .unwrap();
        assert_eq!(got.len(), 2, "two distinct d-tag slots survive");
        let contents: Vec<_> = got.iter().map(|e| e.content.as_str()).collect();
        assert!(contents.contains(&"a-v2"));
        assert!(contents.contains(&"b-v1"));
        assert!(!contents.contains(&"a-v1"));
    }

    #[tokio::test]
    async fn parameterized_no_d_tag_collides_on_empty() {
        let (store, _dir) = open();
        let k = keys();
        let none1 = build(&k, 30_078, "no-d-1", 100, vec![]);
        let none2 = build(&k, 30_078, "no-d-2", 200, vec![]);
        assert_eq!(store.insert(&none1).await.unwrap(), InsertOutcome::Inserted);
        assert_eq!(store.insert(&none2).await.unwrap(), InsertOutcome::Replaced);
        let got = store
            .query(&Filter::new().kinds([Kind::from(30_078u16)]))
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].content, "no-d-2");
    }

    #[tokio::test]
    async fn query_kinds_and_authors() {
        let (store, _dir) = open();
        let a = keys();
        let b = keys();

        store
            .insert(&build(&a, 1, "from-a", 100, vec![]))
            .await
            .unwrap();
        store
            .insert(&build(&b, 1, "from-b", 100, vec![]))
            .await
            .unwrap();
        store
            .insert(&build(&a, 7, "reaction", 100, vec![]))
            .await
            .unwrap();

        let kind1 = store
            .query(&Filter::new().kinds([Kind::from(1u16)]))
            .await
            .unwrap();
        assert_eq!(kind1.len(), 2);

        let only_a = store
            .query(&Filter::new().author(a.public_key()))
            .await
            .unwrap();
        assert_eq!(only_a.len(), 2);
        assert!(only_a.iter().all(|e| e.pubkey == a.public_key()));

        // Author + kind narrowing.
        let narrowed = store
            .query(
                &Filter::new()
                    .author(a.public_key())
                    .kinds([Kind::from(7u16)]),
            )
            .await
            .unwrap();
        assert_eq!(narrowed.len(), 1);
    }

    #[tokio::test]
    async fn query_generic_tags_h_and_e() {
        let (store, _dir) = open();
        let k = keys();
        store
            .insert(&build(
                &k,
                1,
                "tagged",
                100,
                vec![h("Channel-One"), e_tag("deadbeef")],
            ))
            .await
            .unwrap();
        store
            .insert(&build(&k, 1, "other", 100, vec![h("channel-two")]))
            .await
            .unwrap();

        // #h is case-insensitive (proto lowercases channel ids).
        let hit = store
            .query(&Filter::new().custom_tag(letter(Alphabet::H), "channel-one"))
            .await
            .unwrap();
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].content, "tagged");

        let both = store
            .query(
                &Filter::new()
                    .custom_tag(letter(Alphabet::H), "channel-one")
                    .custom_tag(letter(Alphabet::H), "channel-two"),
            )
            .await
            .unwrap();
        assert_eq!(both.len(), 2);

        // #e exact match.
        let by_e = store
            .query(&Filter::new().custom_tag(letter(Alphabet::E), "deadbeef"))
            .await
            .unwrap();
        assert_eq!(by_e.len(), 1);

        // Miss.
        let miss = store
            .query(&Filter::new().custom_tag(letter(Alphabet::E), "cafebabe"))
            .await
            .unwrap();
        assert!(miss.is_empty());
    }

    #[tokio::test]
    async fn query_since_until() {
        let (store, _dir) = open();
        let k = keys();
        for t in [100_u64, 200, 300] {
            store
                .insert(&build(&k, 1, &format!("t-{t}"), t, vec![]))
                .await
                .unwrap();
        }

        let since = store
            .query(
                &Filter::new()
                    .since(Timestamp::from(200))
                    .author(k.public_key()),
            )
            .await
            .unwrap();
        assert_eq!(since.len(), 2, "since is inclusive (>=)");

        let until = store
            .query(
                &Filter::new()
                    .until(Timestamp::from(200))
                    .author(k.public_key()),
            )
            .await
            .unwrap();
        assert_eq!(until.len(), 2, "until is inclusive (<=)");

        let window = store
            .query(
                &Filter::new()
                    .since(Timestamp::from(200))
                    .until(Timestamp::from(200))
                    .author(k.public_key()),
            )
            .await
            .unwrap();
        assert_eq!(window.len(), 1);
    }

    #[tokio::test]
    async fn query_order_and_limit_cap() {
        let (store, _dir) = open();
        let k = keys();
        // 600 events: only 500 should ever come back.
        for t in 0..600 {
            store
                .insert(&build(&k, 1, &format!("n-{t}"), t, vec![]))
                .await
                .unwrap();
        }

        let default = store
            .query(&Filter::new().author(k.public_key()))
            .await
            .unwrap();
        assert_eq!(default.len(), proto::MAX_FILTER_LIMIT);

        let huge = store
            .query(&Filter::new().author(k.public_key()).limit(10_000))
            .await
            .unwrap();
        assert_eq!(huge.len(), proto::MAX_FILTER_LIMIT, "capped at MAX");

        let small = store
            .query(&Filter::new().author(k.public_key()).limit(5))
            .await
            .unwrap();
        assert_eq!(small.len(), 5);
        // Order is created_at DESC: newest five.
        let times: Vec<_> = small.iter().map(|e| e.created_at.as_secs()).collect();
        assert_eq!(times, vec![599, 598, 597, 596, 595]);
    }

    #[tokio::test]
    async fn fts_search_hit_and_miss() {
        let (store, _dir) = open();
        let k = keys();
        store
            .insert(&build(&k, 1, "rust async programming", 10, vec![]))
            .await
            .unwrap();
        store
            .insert(&build(&k, 1, "garden tomatoes recipe", 20, vec![]))
            .await
            .unwrap();

        let hit = store.query(&Filter::new().search("rust")).await.unwrap();
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].content, "rust async programming");

        // Multi-token search is an AND of phrase terms.
        let both = store
            .query(&Filter::new().search("async programming"))
            .await
            .unwrap();
        assert_eq!(both.len(), 1);

        let miss = store
            .query(&Filter::new().search("blockchain"))
            .await
            .unwrap();
        assert!(miss.is_empty());

        // FTS-special input must be treated literally, never as operators.
        let safe = store
            .query(&Filter::new().search("\" OR 1=1"))
            .await
            .unwrap();
        assert!(safe.is_empty());
    }

    #[tokio::test]
    async fn known_channels_lowercased_deduped() {
        let (store, _dir) = open();
        let k = keys();
        store
            .insert(&build(&k, 1, "a", 1, vec![h("ChannelA")]))
            .await
            .unwrap();
        store
            .insert(&build(&k, 1, "b", 2, vec![h("channela"), h("chan-b")]))
            .await
            .unwrap();
        store.insert(&build(&k, 1, "c", 3, vec![])).await.unwrap(); // no h tag

        let chans = store.known_channels().await.unwrap();
        // All lowercased + deduped; order is the DB's ascending sort.
        let mut sorted = chans.clone();
        sorted.sort();
        assert_eq!(sorted, vec!["chan-b".to_string(), "channela".to_string()]);
        // Distinct + lowercased: "ChannelA"/"channela" collapse to one entry.
        assert_eq!(chans.len(), 2);
    }

    #[tokio::test]
    async fn kind_five_stored_ordinarily() {
        // Kind 5 (deletion) is stored as a plain event; no deletion applied.
        let (store, _dir) = open();
        let k = keys();
        let note = build(&k, 1, "target", 100, vec![]);
        let del = build(&k, 5, "delete", 200, vec![e_tag(&note.id.to_hex())]);

        store.insert(&note).await.unwrap();
        store.insert(&del).await.unwrap();

        // The "deleted" note is still present.
        assert_eq!(
            store.query(&Filter::new().id(note.id)).await.unwrap().len(),
            1
        );
        // The kind-5 event itself is retrievable.
        assert_eq!(
            store
                .query(&Filter::new().kinds([Kind::from(5u16)]))
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn round_trip_full_fidelity() {
        let (store, _dir) = open();
        let k = keys();
        let ev = build(
            &k,
            1,
            "body with ünïcode and tags",
            1_700_000_001,
            vec![h("UPPER-Channel"), d("addr"), e_tag("feed")],
        );
        let raw = ev.as_json();
        store.insert(&ev).await.unwrap();

        let got = store.query(&Filter::new().id(ev.id)).await.unwrap();
        assert_eq!(got.len(), 1);
        let back = &got[0];
        // Deserialized event must match the original on identity fields and
        // re-serialize to the same canonical JSON.
        assert_eq!(back.id, ev.id);
        assert_eq!(back.pubkey, ev.pubkey);
        assert_eq!(back.kind, ev.kind);
        assert_eq!(back.created_at, ev.created_at);
        assert_eq!(back.content, ev.content);
        assert_eq!(back.sig, ev.sig);
        assert_eq!(back.as_json(), raw);
        // Tags survived intact.
        let names: Vec<String> = back.tags.iter().map(|t| t.as_slice()[0].clone()).collect();
        assert_eq!(names, vec!["h", "d", "e"]);
    }

    #[tokio::test]
    async fn empty_filter_sets_match_nothing() {
        let (store, _dir) = open();
        let k = keys();
        store.insert(&build(&k, 1, "x", 1, vec![])).await.unwrap();

        assert!(store
            .query(&Filter {
                ids: Some(Default::default()),
                ..Default::default()
            })
            .await
            .unwrap()
            .is_empty());
        let mut gt = std::collections::BTreeMap::new();
        gt.insert(letter(Alphabet::H), Default::default());
        assert!(store
            .query(&Filter {
                generic_tags: gt,
                ..Default::default()
            })
            .await
            .unwrap()
            .is_empty());
    }
}

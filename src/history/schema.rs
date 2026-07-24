//! History-store schema (bridge-v2 M1a design §3). Owner: WP1.
//!
//! A purpose-built SQLite schema that REPLACES the flat spike table for the
//! durable Nostr-window/thread read model. It is a *separate* database from the
//! spike's `store.rs` `SqliteStore` — the spike keeps its own schema untouched
//! so its 60 tests stay green; this schema becomes the Stage-3 migration spec.
//!
//! Tables (design §3):
//! - `events`      — full event rows + resolved `channel_id` + soft-`deleted`.
//! - `thread_metadata` — per-node ancestry + the two transactional counters.
//! - `pending_orphans` — mesh-door replies whose parent has not yet arrived.
//! - `quarantine`  — mesh-door events kept-but-invisible after an ancestry
//!   mismatch (the design §4 "kept, invisible, logged" invariant; §3's table
//!   list does not name it — see the WP1 report deviation note).
//! - `members`     — channel membership (writes owned by WP2/WP3).
//! - `nip98_seen`  — NIP-98 replay cache (D5; consumed by WP2 auth).
//! - `meta`        — single community-fingerprint row (accidental scope-reuse
//!   guard, §3 invariant).
//! - `events_fts`  — FTS5 external-content index carried over from the spike.

use anyhow::{bail, Context, Result};
use rusqlite::OptionalExtension;

/// Key under which the community fingerprint is stored in `meta`.
const FINGERPRINT_KEY: &str = "community_fingerprint";

/// Idempotent schema setup. Safe to run on every open.
pub(crate) fn migrate(conn: &rusqlite::Connection) -> Result<()> {
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
            raw        TEXT NOT NULL,   -- full canonical event JSON
            channel_id TEXT,           -- resolved #h (NULL = global / none)
            deleted    INTEGER NOT NULL DEFAULT 0
        );

        -- Window keyset: (channel_id, created_at DESC, id ASC).
        CREATE INDEX IF NOT EXISTS idx_events_window
            ON events(channel_id, created_at DESC, id ASC);
        CREATE INDEX IF NOT EXISTS idx_events_kind_created
            ON events(kind, created_at DESC);

        CREATE TABLE IF NOT EXISTS thread_metadata (
            event_id         TEXT PRIMARY KEY,
            event_created_at INTEGER NOT NULL,
            channel_id       TEXT,
            parent_event_id  TEXT,
            root_event_id    TEXT,
            depth            INTEGER,
            reply_count      INTEGER NOT NULL DEFAULT 0,
            descendant_count INTEGER NOT NULL DEFAULT 0,
            last_reply_at    INTEGER,
            broadcast        INTEGER NOT NULL DEFAULT 0
        );

        -- Thread keyset: (root_event_id, event_created_at ASC, event_id ASC).
        CREATE INDEX IF NOT EXISTS idx_thread_keyset
            ON thread_metadata(root_event_id, event_created_at ASC, event_id ASC);

        CREATE TABLE IF NOT EXISTS pending_orphans (
            event_id        TEXT PRIMARY KEY,
            parent_event_id TEXT NOT NULL,
            raw             TEXT NOT NULL,
            received_at     INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_pending_parent
            ON pending_orphans(parent_event_id);

        CREATE TABLE IF NOT EXISTS quarantine (
            event_id    TEXT PRIMARY KEY,
            raw         TEXT NOT NULL,
            reason      TEXT NOT NULL,
            received_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS members (
            channel_id TEXT NOT NULL,
            pubkey     TEXT NOT NULL,
            role       TEXT NOT NULL,
            PRIMARY KEY (channel_id, pubkey)
        );

        -- Replaceable bookkeeping for relay-authored state kinds (39000-39003
        -- group state, kind-13534 membership list) and replaceable client kinds
        -- (0, 3, 10000-19999, 30000-39999): one row per (pubkey, kind, d-tag)
        -- slot pointing at the currently-winning event. Non-parameterized
        -- replaceable kinds use d_tag ''.
        CREATE TABLE IF NOT EXISTS replaceable_addrs (
            pubkey     TEXT NOT NULL,
            kind       INTEGER NOT NULL,
            d_tag      TEXT NOT NULL,
            event_id   TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (pubkey, kind, d_tag)
        );

        CREATE TABLE IF NOT EXISTS nip98_seen (
            event_id   TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
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
    .context("history schema migration failed")?;
    Ok(())
}

/// Enforce the community-fingerprint invariant: a DB created for community A
/// must refuse to open under a different configured fingerprint B (accidental
/// scope-reuse guard, §3). Writes the row on first open.
pub(crate) fn check_or_write_fingerprint(
    conn: &rusqlite::Connection,
    configured: &str,
) -> Result<()> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            rusqlite::params![FINGERPRINT_KEY],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .context("failed to read community fingerprint")?;

    match existing {
        Some(fp) if fp != configured => bail!(
            "history DB community fingerprint mismatch: db has {fp:?}, configured {configured:?} \
             (refusing to serve a mismatched community)"
        ),
        Some(_) => Ok(()),
        None => {
            conn.execute(
                "INSERT INTO meta(key, value) VALUES(?1, ?2)",
                rusqlite::params![FINGERPRINT_KEY, configured],
            )
            .context("failed to write community fingerprint")?;
            Ok(())
        }
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable content-addressed media blob store (bridge M1b §2). Owner: WP-MS.
//!
//! `MediaStore` owns its **own** SQLite sidecar (`media.db`) and its **own**
//! blob directory — it never touches the history store's connection or schema
//! (collision-free, §14 WP-MS). It is a pure persistence/CAS leaf:
//! - Sidecar-first visibility: a blob is servable **only** when a `media_blobs`
//!   row exists for its sha256. A blob file with no sidecar row (an orphan left
//!   by a failed insert, or a partially-written upload) is invisible — the
//!   serve handler must map "no row" and "no blob file" to the **same** 404
//!   (indistinguishable; see [`MediaStore::serve_lookup`], which enforces this).
//! - Idempotent install: re-installing the same sha256 is a no-op that returns
//!   the existing record without rewriting the blob or mutating the row.
//! - Atomic blob persist: the upload handler streams the body into a staging
//!   path inside the blob directory (same filesystem ⇒ atomic `rename`); this
//!   store renames it into `{blob_dir}/{sha256}.{ext}` and then inserts the
//!   sidecar row. **No API ever reads or copies whole blob bytes** — a 500 MB
//!   video is never buffered here. (The only byte-copy is an internal
//!   cross-device `rename` fallback, documented on `persist_blob`.)
//! - All synchronous DB work is offloaded via `spawn_blocking` over **owned**
//!   inputs (`String`/`PathBuf`), never borrowed references that cross an
//!   `await`; the connection is held by this store's own `Arc<Mutex<_>>`.
//!
//! Scope guard: the sidecar carries a `meta.community_fingerprint` row, exactly
//! like the history DB; opening a sidecar whose stored fingerprint differs from
//! the configured one is refused (accidental cross-community reuse guard, §3).
//!
//! Wire descriptor assembly (§5.9 — `url`/`type`/`uploaded`/…) lives in
//! `upload.rs`; this module exposes the persisted [`MediaRecord`] only.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::OptionalExtension;

/// Key under which the community fingerprint is stored in `meta` (mirrors the
/// history store's `community_fingerprint` key so the invariant reads the same
/// across both sidecars).
const FINGERPRINT_KEY: &str = "community_fingerprint";

/// How a blob should be presented to clients on GET (§5.8 / §6.5).
///
/// Generic uploads are stored as `Attachment` (so browsers download rather than
/// render); images/video are `Inline`. `?download=1` on GET overrides to
/// attachment regardless of this value — that override is the serve handler's
/// concern, not the store's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobDisposition {
    Inline,
    Attachment,
}

impl BlobDisposition {
    /// Persisted string form (the `disposition` column value).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Attachment => "attachment",
        }
    }

    /// Parse the persisted column back into the enum. Unknown values default to
    /// `Inline` (the schema default) rather than failing a read — a corrupted
    /// disposition must not make a stored blob unservable.
    fn parse_stored(s: &str) -> Self {
        if s == Self::Attachment.as_str() {
            Self::Attachment
        } else {
            Self::Inline
        }
    }
}

/// One stored `media_blobs` row — the complete sidecar record for a blob.
///
/// Returned by lookups and installs; `upload.rs` derives the wire descriptor
/// (§5.9) from this. Field names follow the persistence schema, not the wire
/// shape (`mime_type`/`uploaded_at`, not `type`/`uploaded`).
#[derive(Debug, Clone, PartialEq)]
pub struct MediaRecord {
    /// 64 lowercase-hex sha256 — the content-addressed key and table PK.
    pub sha256: String,
    /// Blob size in bytes (stored as INTEGER; round-tripped through `i64`).
    pub size: u64,
    pub mime_type: String,
    /// Safe, lowercase, no dots/slashes (validated by [`is_valid_ext`]).
    pub ext: String,
    /// Unix seconds the blob was accepted (caller-supplied, testable).
    pub uploaded_at: i64,
    /// 64-hex uploader pubkey (membership/auth principal).
    pub uploader_pubkey: String,
    /// `"WxH"` for images/video, else `None`.
    pub dim: Option<String>,
    pub blurhash: Option<String>,
    /// sha256 of an inline thumbnail blob (server-generated for images), else
    /// `None`. The thumbnail is itself a CAS blob served at its own path.
    pub thumb_sha: Option<String>,
    /// Video only, else `None`.
    pub duration_secs: Option<f64>,
    pub disposition: BlobDisposition,
}

/// Inputs for an idempotent install ([`MediaStore::install`]) — everything the
/// store cannot derive itself. `sha256` and `size` are NOT taken here: the
/// caller supplies `sha256` separately (it is the CAS key, computed by the
/// upload pipeline while streaming), and `size` is derived from the staging
/// file's metadata so the row can never disagree with the bytes on disk.
#[derive(Debug, Clone)]
pub struct NewMediaRecord {
    pub mime_type: String,
    pub ext: String,
    pub uploaded_at: i64,
    pub uploader_pubkey: String,
    pub dim: Option<String>,
    pub blurhash: Option<String>,
    pub thumb_sha: Option<String>,
    pub duration_secs: Option<f64>,
    pub disposition: BlobDisposition,
}

impl NewMediaRecord {
    /// Assemble the full record once the key and on-disk size are known.
    fn into_record(self, sha256: String, size: u64) -> MediaRecord {
        MediaRecord {
            sha256,
            size,
            mime_type: self.mime_type,
            ext: self.ext,
            uploaded_at: self.uploaded_at,
            uploader_pubkey: self.uploader_pubkey,
            dim: self.dim,
            blurhash: self.blurhash,
            thumb_sha: self.thumb_sha,
            duration_secs: self.duration_secs,
            disposition: self.disposition,
        }
    }
}

/// Outcome of [`MediaStore::install`]. Both variants carry the authoritative
/// [`MediaRecord`] so the caller can build the same descriptor for a fresh
/// upload and an idempotent re-upload.
#[derive(Debug, Clone)]
pub enum InstallOutcome {
    /// A brand-new blob was persisted and its sidecar row committed.
    Installed(MediaRecord),
    /// A sidecar row for this sha256 already existed; nothing was written and
    /// the staging file was discarded. Re-PUT is a faithful no-op (§5.6).
    Existing(MediaRecord),
}

/// Durable content-addressed media store for one community.
///
/// Owns a single `rusqlite::Connection` (the `media.db` sidecar) behind a
/// `std::sync::Mutex`/`Arc`, plus the blob directory. Every async method
/// offloads its synchronous DB work to `tokio::task::spawn_blocking`, mirroring
/// `SqliteStore`/`HistoryStore` — but the connection is **this store's own**;
/// it never shares the history store's mutex or handle.
pub struct MediaStore {
    conn: Arc<Mutex<rusqlite::Connection>>,
    blob_dir: PathBuf,
}

impl MediaStore {
    /// Open (or create) the sidecar DB at `media_db_path` and the blob CAS
    /// directory `blob_dir`, bound to `community_fingerprint`.
    ///
    /// - WAL journal mode is set on the connection (persisted in the db header)
    ///   and `busy_timeout` is 5 s, matching the history store.
    /// - Schema creation is idempotent (`CREATE TABLE IF NOT EXISTS`); safe to
    ///   run on every open including first creation.
    /// - **Fingerprint guard:** if `meta.community_fingerprint` already holds a
    ///   value that differs from `community_fingerprint`, open is refused with
    ///   an explicit error (no row is written). On first open the row is
    ///   written. This prevents accidental cross-community reuse of a media
    ///   sidecar/dir, exactly as the history guard does for `BRIDGE_DB`.
    ///
    /// No environment variables or global state are read — both paths and the
    /// fingerprint are explicit arguments, so tests open throwaway instances
    /// under a `tempfile::tempdir()` without touching the process environment.
    pub fn open(
        media_db_path: &Path,
        blob_dir: &Path,
        community_fingerprint: &str,
    ) -> Result<Self> {
        // The blob dir is created up-front so staging paths are immediately
        // writable; `install` re-runs `create_dir_all` defensively.
        std::fs::create_dir_all(blob_dir)
            .with_context(|| format!("create media blob dir {}", blob_dir.display()))?;
        if let Some(parent) = media_db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create media db parent {}", parent.display()))?;
            }
        }

        let conn = rusqlite::Connection::open(media_db_path)
            .with_context(|| format!("open media db {}", media_db_path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        // WAL is persisted in the header; foreign_keys is per-connection.
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
        migrate(&conn)?;
        check_or_write_fingerprint(&conn, community_fingerprint)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            blob_dir: blob_dir.to_path_buf(),
        })
    }

    /// A fresh, unique staging path **inside the blob directory** (same
    /// filesystem ⇒ [`MediaStore::install`] can `rename` atomically). The
    /// upload handler streams the request body here while computing sha256;
    /// it is never read back by this store. The leading `.` hides in-progress
    /// uploads from any naive directory listing.
    pub fn staging_path(&self) -> PathBuf {
        // uuid v4 simple = 32 lowercase hex, no dashes ⇒ safe filename chars.
        self.blob_dir
            .join(format!(".staging-{}", uuid::Uuid::new_v4().simple()))
    }

    /// Sidecar-first lookup. Returns the stored record for `sha256` iff a
    /// `media_blobs` row exists. A blob file present without a row is invisible
    /// here — the row is the gate (§5.8). An ill-formed `sha256` yields `None`
    /// rather than hitting the DB (and maps to 404 in the caller).
    pub async fn get(&self, sha256: &str) -> Result<Option<MediaRecord>> {
        if !is_valid_sha256(sha256) {
            return Ok(None);
        }
        let sha = sha256.to_string();
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<Option<MediaRecord>> {
            let guard = lock(&conn)?;
            record_by_sha(&guard, &sha)
        })
        .await
        .map_err(|e| anyhow!("media get task failed: {e}"))?
    }

    /// Sidecar-first visibility gate for serving (§6.3): returns the record and
    /// the absolute blob path **only** when *both* a sidecar row exists *and*
    /// the blob file is present on disk. A missing row OR a missing/orphan blob
    /// file ⇒ `None` — the two cases are deliberately **indistinguishable** so
    /// the serve handler cannot leak "row-but-no-file" vs "no-row" (both 404).
    ///
    /// This performs a metadata existence check only; it never reads blob
    /// bytes. A tiny TOCTOU window remains between this check and the caller's
    /// `tokio::fs::File::open`: if the file vanishes in between the open fails,
    /// which the serve handler must also map to 404 (still indistinguishable).
    pub async fn serve_lookup(&self, sha256: &str) -> Result<Option<(MediaRecord, PathBuf)>> {
        let Some(rec) = self.get(sha256).await? else {
            return Ok(None);
        };
        // Use the sidecar's ext/mime on disk — never trust the URL beyond the
        // sha parse (§6.3). The path is built from the validated record.
        let path = self.blob_path(&rec.sha256, &rec.ext)?;
        if file_exists(&path).await {
            Ok(Some((rec, path)))
        } else {
            Ok(None)
        }
    }

    /// Absolute path of the on-disk blob for a validated `(sha256, ext)`. Pure
    /// path join — no IO, no existence check. `serve_lookup` is preferred for
    /// serving; this is exposed for callers that already hold a record and want
    /// the canonical CAS path (e.g. linking a thumbnail).
    pub fn blob_path(&self, sha256: &str, ext: &str) -> Result<PathBuf> {
        if !is_valid_sha256(sha256) {
            bail!("invalid sha256: expected 64 lowercase hex");
        }
        if !is_valid_ext(ext) {
            bail!(
                "invalid ext {:?}: expected 1..=16 lowercase ascii alnum",
                ext
            );
        }
        Ok(self.blob_dir.join(format!("{sha256}.{ext}")))
    }

    /// Whether the blob file for a validated `(sha256, ext)` is present on
    /// disk. Metadata-only (no byte read). `false` is also returned on
    /// metadata-access errors so a transiently unreadable file is treated as
    /// absent (404) rather than surfacing a 500.
    pub async fn blob_exists(&self, sha256: &str, ext: &str) -> Result<bool> {
        let path = self.blob_path(sha256, ext)?;
        Ok(file_exists(&path).await)
    }

    /// Atomic, idempotent install (§5.6–§5.8).
    ///
    /// 1. Validate `sha256` (64 lowercase hex) and `input.ext`; on failure the
    ///    staging file is discarded and an error is returned.
    /// 2. **Idempotency:** if a `media_blobs` row already exists for `sha256`,
    ///    discard the staging file and return [`InstallOutcome::Existing`]
    ///    with the authoritative record — no rewrite, no double-count.
    /// 3. Derive `size` from the staging file's metadata (no byte read). An
    ///    out-of-range size (`> i64::MAX`, since SQLite stores INTEGER as i64)
    ///    is **rejected with an explicit error and the staging file discarded** —
    ///    the recorded size never silently disagrees with the bytes on disk.
    /// 4. **Persist blob:** `rename(staging → {sha}.{ext})` inside the blob dir
    ///    (atomic, same filesystem). If the target already exists (an orphan
    ///    from a previously-failed sidecar insert) it is reused as-is and the
    ///    staging file is discarded — content-addressing makes this safe.
    /// 5. **Sidecar insert:** `INSERT OR IGNORE` the `media_blobs` row. The blob
    ///    is written *before* the row (contract atomicity): a descriptor is
    ///    returned ONLY when blob + row both succeed, and a row written without
    ///    its blob can never happen (the row is the last step). A primary-key
    ///    conflict from a concurrent identical-hash caller resolves to
    ///    [`InstallOutcome::Existing`] (the pre-existing row wins untouched),
    ///    **never** a 500 — the just-persisted blob is byte-identical content,
    ///    so reuse is correct. A genuine DB error (e.g. disk full) after a
    ///    successful persist leaves an invisible orphan (logged; re-PUT
    ///    self-heals) and surfaces the error.
    ///
    /// `sha256` is the authoritative CAS key (the upload pipeline computed it
    /// while streaming and already proved it equals the auth `x` tag). This
    /// method does not re-hash; it trusts the caller's key for naming and
    /// stores it as the table primary key.
    pub async fn install(
        &self,
        sha256: &str,
        input: NewMediaRecord,
        staging: PathBuf,
    ) -> Result<InstallOutcome> {
        if !is_valid_sha256(sha256) {
            let _ = tokio::fs::remove_file(&staging).await;
            bail!("invalid sha256 for install: expected 64 lowercase hex");
        }
        if !is_valid_ext(&input.ext) {
            let _ = tokio::fs::remove_file(&staging).await;
            bail!(
                "invalid ext {:?} for install: expected 1..=16 lowercase ascii alnum",
                input.ext
            );
        }

        let sha = sha256.to_string();
        let blob_dir = self.blob_dir.clone();
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<InstallOutcome> {
            let guard = lock(&conn)?;

            // (2) Idempotency pre-check under the store's single-writer mutex.
            if let Some(existing) = record_by_sha(&guard, &sha)? {
                let _ = std::fs::remove_file(&staging);
                return Ok(InstallOutcome::Existing(existing));
            }

            // (3) Size from on-disk metadata — never read the bytes.
            let size = std::fs::metadata(&staging)
                .with_context(|| format!("staging blob missing: {}", staging.display()))?
                .len();
            // Fail fast on an out-of-range size BEFORE any blob write: SQLite
            // stores INTEGER as i64, so a size > i64::MAX cannot be recorded
            // accurately. Reject explicitly (never clamp to i64::MAX, which
            // would corrupt the recorded size); discard the staging file.
            if size_to_i64(size).is_err() {
                let _ = std::fs::remove_file(&staging);
                bail!(
                    "blob size {size} bytes exceeds the i64 SQLite storage limit (>{})",
                    i64::MAX
                );
            }

            // (4) Persist blob atomically.
            std::fs::create_dir_all(&blob_dir)
                .with_context(|| format!("create blob dir {}", blob_dir.display()))?;
            let target = blob_dir.join(format!("{}.{}", sha, input.ext));
            if std::fs::exists(&target).unwrap_or(false) {
                // Orphan blob from a prior failed insert — same content by sha;
                // reuse it and drop the duplicate staging file.
                let _ = std::fs::remove_file(&staging);
            } else if let Err(e) = persist_blob(&staging, &target) {
                // Rename/copy failed; staging may still exist — discard it.
                let _ = std::fs::remove_file(&staging);
                return Err(e);
            }

            // (5) Sidecar insert — the visibility gate. INSERT OR IGNORE makes a
            // concurrent identical-hash caller (or a row that appeared between
            // our pre-check and this insert) resolve to Existing instead of a
            // constraint-violation 500; the pre-existing row wins untouched.
            let rec = input.into_record(sha.clone(), size);
            match insert_record_ignoring_conflict(&guard, &rec)? {
                true => Ok(InstallOutcome::Installed(rec)),
                false => {
                    // Lost the insert race: load the authoritative existing
                    // row. The blob we just persisted is byte-identical content
                    // (content-addressed), so reuse is correct.
                    match record_by_sha(&guard, &sha)? {
                        Some(existing) => Ok(InstallOutcome::Existing(existing)),
                        None => Err(anyhow!("media_blobs row for {sha} vanished after insert")),
                    }
                }
            }
        })
        .await
        .map_err(|e| anyhow!("media install task failed: {e}"))?
    }
}

// ---- validation ----------------------------------------------------------

/// `true` iff `s` is exactly 64 lowercase hex chars (`[0-9a-f]{64}`) — the
/// content-addressed sha256 key form stored in `media_blobs.sha256` and used in
/// blob filenames. Uppercase hex is rejected so the canonical (lowercase) form
/// is the only form that ever keys a lookup or a file.
pub fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `true` iff `ext` is 1..=16 lowercase ASCII alphanumeric chars with no dots,
/// slashes, or other separators — safe to embed in a filename
/// (`{sha256}.{ext}`). Callers derive `ext` from the sniffed MIME (never the
/// raw URL) and lower-case it before validating.
pub fn is_valid_ext(s: &str) -> bool {
    let len = s.len();
    (1..=16).contains(&len) && s.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9'))
}

// ---- schema + fingerprint -----------------------------------------------

/// Idempotent schema setup. Safe to run on every open, including first
/// creation. Matches the M1b §2 schema verbatim (no speculative indexes; the
/// `sha256` primary key already indexes the hot lookup path).
fn migrate(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS media_blobs (
            sha256           TEXT PRIMARY KEY,   -- 64 lowercase hex
            size             INTEGER NOT NULL,
            mime_type        TEXT NOT NULL,
            ext              TEXT NOT NULL,        -- safe, lowercase, no dots/slashes
            uploaded_at      INTEGER NOT NULL,
            uploader_pubkey  TEXT NOT NULL,        -- 64 hex
            dim              TEXT,                 -- "WxH" or NULL
            blurhash         TEXT,
            thumb_sha        TEXT,                 -- sha256 of thumbnail blob, or NULL
            duration_secs    REAL,                 -- video only
            disposition      TEXT NOT NULL DEFAULT 'inline'  -- 'inline'|'attachment'
        );
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        -- fingerprint row written on first open; mismatch ⇒ refuse (reuse guard)
        "#,
    )
    .context("media schema migration failed")?;
    Ok(())
}

/// Enforce the community-fingerprint invariant: a media sidecar created for
/// community A must refuse to open under a different configured fingerprint B
/// (accidental scope-reuse guard, §3). Writes the row on first open. Mirrors
/// `history::schema::check_or_write_fingerprint` so both sidecars behave
/// identically.
fn check_or_write_fingerprint(conn: &rusqlite::Connection, configured: &str) -> Result<()> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            rusqlite::params![FINGERPRINT_KEY],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .context("failed to read media community fingerprint")?;

    match existing {
        Some(fp) if fp != configured => bail!(
            "media DB community fingerprint mismatch: db has {fp:?}, configured {configured:?} \
             (refusing to serve a mismatched community)"
        ),
        Some(_) => Ok(()),
        None => {
            conn.execute(
                "INSERT INTO meta(key, value) VALUES (?1, ?2)",
                rusqlite::params![FINGERPRINT_KEY, configured],
            )
            .context("failed to write media community fingerprint")?;
            Ok(())
        }
    }
}

// ---- row helpers ---------------------------------------------------------

/// Load a `media_blobs` row by sha256, or `None` if absent. Sidecar-only —
/// never touches the blob directory.
fn record_by_sha(conn: &rusqlite::Connection, sha: &str) -> Result<Option<MediaRecord>> {
    conn.query_row(
        "SELECT sha256, size, mime_type, ext, uploaded_at, uploader_pubkey,
                dim, blurhash, thumb_sha, duration_secs, disposition
         FROM media_blobs WHERE sha256 = ?1",
        rusqlite::params![sha],
        row_to_record,
    )
    .optional()
    .context("media_blobs lookup failed")
}

/// Map a selected row into a [`MediaRecord`]. `size` is stored as INTEGER
/// (`i64`); values exceeding `i64::MAX` (~9 EiB) are clamped on write and
/// widened back lossily here — irrelevant for any real upload.
fn row_to_record(r: &rusqlite::Row<'_>) -> rusqlite::Result<MediaRecord> {
    let size_i: i64 = r.get(1)?;
    Ok(MediaRecord {
        sha256: r.get(0)?,
        size: size_i as u64,
        mime_type: r.get(2)?,
        ext: r.get(3)?,
        uploaded_at: r.get(4)?,
        uploader_pubkey: r.get(5)?,
        dim: r.get(6)?,
        blurhash: r.get(7)?,
        thumb_sha: r.get(8)?,
        duration_secs: r.get(9)?,
        disposition: BlobDisposition::parse_stored(&r.get::<_, String>(10)?),
    })
}

/// Convert a byte size to the `i64` SQLite stores for an INTEGER column.
/// Returns an explicit error (never clamps) when `size > i64::MAX`, so the
/// recorded size can never silently disagree with the bytes on disk.
fn size_to_i64(size: u64) -> Result<i64> {
    i64::try_from(size).map_err(|_| {
        anyhow!(
            "blob size {size} bytes exceeds the i64 SQLite storage limit (>{})",
            i64::MAX
        )
    })
}

/// Insert one `media_blobs` row, resolving a primary-key conflict by IGNORE
/// (the pre-existing row wins untouched). Returns `true` when a new row was
/// inserted, `false` when a row for this sha256 already existed — so a
/// concurrent identical-hash caller resolves to [`InstallOutcome::Existing`]
/// rather than surfacing a constraint-violation error. Out-of-range sizes are
/// rejected explicitly (no clamping).
fn insert_record_ignoring_conflict(conn: &rusqlite::Connection, rec: &MediaRecord) -> Result<bool> {
    let size_i = size_to_i64(rec.size)?;
    let inserted = conn
        .execute(
            "INSERT OR IGNORE INTO media_blobs
               (sha256, size, mime_type, ext, uploaded_at, uploader_pubkey,
                dim, blurhash, thumb_sha, duration_secs, disposition)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                rec.sha256,
                size_i,
                rec.mime_type,
                rec.ext,
                rec.uploaded_at,
                rec.uploader_pubkey,
                rec.dim,
                rec.blurhash,
                rec.thumb_sha,
                rec.duration_secs,
                rec.disposition.as_str(),
            ],
        )
        .context("media_blobs insert failed")?;
    Ok(inserted == 1)
}

// ---- fs helpers ----------------------------------------------------------

/// Atomically move `staging` to `target`. Same-filesystem `rename` is the fast
/// path (no byte copy — the only operation that ever touches the bytes' location
/// without reading them). On a cross-device rename (`EXDEV`), fall back to
/// `copy` + `remove_file`: this **does** read/write every byte, but only on the
/// rare misconfiguration where the staging temp file is not on the same
/// filesystem as the blob dir — `MediaStore::staging_path` always places
/// staging inside the blob dir, so the rename path is the norm.
fn persist_blob(staging: &Path, target: &Path) -> Result<()> {
    match std::fs::rename(staging, target) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::CrossesDevices => {
            std::fs::copy(staging, target).with_context(|| {
                format!(
                    "cross-device copy {} -> {}",
                    staging.display(),
                    target.display()
                )
            })?;
            // Drop the source only after a confirmed successful copy.
            let _ = std::fs::remove_file(staging);
            Ok(())
        }
        Err(e) => Err(e)
            .with_context(|| format!("rename blob {} -> {}", staging.display(), target.display())),
    }
}

/// Async existence check via `tokio::fs` (off-thread). `false` on any metadata
/// error so a transiently unreadable blob is treated as absent (404), never 500.
async fn file_exists(path: &Path) -> bool {
    match tokio::fs::metadata(path).await {
        Ok(m) => m.is_file(),
        Err(_) => false,
    }
}

/// Acquire the media DB mutex; map poison to an `anyhow` error (never panics).
fn lock(conn: &Mutex<rusqlite::Connection>) -> Result<MutexGuard<'_, rusqlite::Connection>> {
    conn.lock()
        .map_err(|e| anyhow!("media db mutex poisoned: {e}"))
}

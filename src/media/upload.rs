// SPDX-License-Identifier: MIT OR Apache-2.0
//! Blossom (BUD-01) upload pipeline — `PUT /upload` (+ alias `PUT /media/upload`).
//! Owner: WP-MS (leaf). Depends on [`crate::media::auth`] (BUD-11 verifier) and
//! [`crate::media::store`] (content-addressed blob store).
//!
//! # Streaming contract — never buffer the body
//!
//! The axum [`Body`] is consumed as a **stream** ([`Body::into_data_stream`]) and
//! written incrementally into a staging path inside the blob directory
//! ([`MediaStore::staging_path`]). While streaming we (1) feed each chunk to a
//! streaming [`Sha256`], (2) accumulate a 4 KiB sniff buffer for magic-byte MIME
//! detection, and (3) enforce the per-type byte cap, **aborting and deleting the
//! staging file the instant the cap is crossed**. There is deliberately **no**
//! `Bytes`/`String` whole-body extractor anywhere on this path — a 500 MiB video
//! is never held in RAM. Only one chunk (hyper's bounded read buffer) is in
//! memory at a time, and the overshoot past the cap is at most one chunk.
//!
//! # Ordering (the atomicity + replay contract)
//!
//! 1. **Pre-stream static auth** ([`auth::verify_blossom`], upload verb, lenient
//!    `video_auth_max_age_secs`): signature, kind 24242, verb, expiration,
//!    created_at age, optional `server` tag. Fail-closed 401 *before any body
//!    byte is touched* so an anonymous bad token cannot exhaust disk I/O.
//! 2. **Membership** (fail-fast 403 before I/O) when `require_membership`.
//! 3. **Content-Length fast-fail** (413 before I/O) when the declared length
//!    exceeds the absolute cap.
//! 4. **Bounded metadata headers** (`X-Dim`/`X-Blurhash`/`X-Thumb`/
//!    `X-Duration`) validated (400 on malformed) before I/O.
//! 5. **Stream** to staging: hash, sniff, per-type cap (413 → abort+delete).
//! 6. **Classify** MIME + canonical ext from the sniffed magic bytes (400 on a
//!    disallowed/spoofed type).
//! 7. **Hash binding** ([`auth::verify_upload`], type-specific `max_age`): the
//!    computed body sha256 must match the auth `x` tag (400 on mismatch) and the
//!    optional `X-SHA-256` header is cross-checked. This is the *last* static
//!    auth check.
//! 8. **Replay** ([`MediaReplay::check_and_record`], keyed by the verified event
//!    id): consumed **only after every static auth check and membership pass**,
//!    so a request that fails for any other reason never burns the caller's
//!    token (401 on replay).
//! 9. **Idempotent CAS install** ([`MediaStore::install`]): a sidecar row that
//!    already exists short-circuits to the existing record and returns a success
//!    descriptor — no rewrite, no double-count. On a fresh install the blob is
//!    atomically renamed into place *before* the sidecar row is committed, so a
//!    descriptor is returned only when blob + sidecar are both durable.
//!
//! MIME sniffing, the ISO-BMFF/MP4 structural check, the generic-file deny-list,
//! and `mime_to_ext` are ported from `crates/buzz-media/src/validation.rs`
//! (dual-licensed MIT OR Apache-2.0). The bridge does **not** depend on the
//! `infer` crate (see [Integration needs] below); only the five Blossom-allowed
//! media signatures are sniffed by hand, and the generic-file MIME/ext are taken
//! from the declared `Content-Type` (defence-in-depth: media types and blocked
//! active-content types are rejected even on the generic path).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::Extension;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::StreamExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tracing::warn;

use crate::media::auth::{self, BlossomAuthError, BlossomVerb};
use crate::media::store::{
    is_valid_sha256, BlobDisposition, InstallOutcome, MediaRecord, MediaStore, NewMediaRecord,
};

// ---- tunables -----------------------------------------------------------

/// Leading bytes accumulated for magic-byte sniffing. 4 KiB is the standard
/// sniff buffer and is tiny relative to the tightest per-type cap (10 MiB GIF),
/// so the true type is always known long before any cap could bind.
const SNIFF_BYTES: usize = 4096;

/// Bound on every accepted metadata header value (DoS guard; axum/hyper already
/// bound total header size, this is the storage-side cap).
const MAX_DIM_LEN: usize = 16;
const MAX_BLURHASH_LEN: usize = 256;
const MAX_MIME_LEN: usize = 128;
/// Reject durations outside `[0, 86400]` seconds (buzz-media caps video at 600s,
/// but the bound is generous for non-video metadata).
const MAX_DURATION_SECS: f64 = 86_400.0;

/// Default per-type upload caps, mirroring `crates/buzz-media/src/config.rs` and
/// the M1b contract §3.
const DEFAULT_MAX_IMAGE_BYTES: u64 = 50 * 1024 * 1024;
const DEFAULT_MAX_GIF_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_MAX_VIDEO_BYTES: u64 = 524_288_000;
const DEFAULT_MAX_FILE_BYTES: u64 = 104_857_600;
const DEFAULT_UPLOAD_AUTH_MAX_AGE_SECS: u64 = 600;
const DEFAULT_VIDEO_AUTH_MAX_AGE_SECS: u64 = 3600;

// ---- configuration ------------------------------------------------------

/// Tunables for the upload pipeline. All fields are explicit (no env reads) so
/// the module is unit-testable without touching the process environment. The
/// bridge constructs this from `Settings` (M1b §3) at startup.
#[derive(Debug, Clone)]
pub struct MediaUploadConfig {
    /// Public base URL prefixed to descriptor `url`/`thumb` (trailing `/`
    /// trimmed). Default = the relay `public_base_url`.
    pub media_public_base_url: String,
    /// `host[:port]` of the relay public base URL — the BUD-11 `server`-tag
    /// comparison target.
    pub relay_authority: String,
    pub max_image_bytes: u64,
    pub max_gif_bytes: u64,
    /// Absolute route cap (the largest per-type cap). The handler also enforces
    /// this directly during streaming so it is correct even without the route's
    /// `DefaultBodyLimit` layer wired.
    pub max_video_bytes: u64,
    pub max_file_bytes: u64,
    /// `created_at` freshness window for non-video upload auth events.
    pub upload_auth_max_age_secs: u64,
    /// `created_at` freshness window for video upload auth events (1 h — large
    /// uploads on slow links need headroom; the desktop mints video tokens with
    /// a 1 h expiry to match).
    pub video_auth_max_age_secs: u64,
    /// When true, reject callers who are not community members (403).
    pub require_membership: bool,
}

impl Default for MediaUploadConfig {
    fn default() -> Self {
        Self {
            media_public_base_url: String::new(),
            relay_authority: String::new(),
            max_image_bytes: DEFAULT_MAX_IMAGE_BYTES,
            max_gif_bytes: DEFAULT_MAX_GIF_BYTES,
            max_video_bytes: DEFAULT_MAX_VIDEO_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            upload_auth_max_age_secs: DEFAULT_UPLOAD_AUTH_MAX_AGE_SECS,
            video_auth_max_age_secs: DEFAULT_VIDEO_AUTH_MAX_AGE_SECS,
            require_membership: false,
        }
    }
}

// ---- wire descriptor ----------------------------------------------------

/// Blossom `BlobDescriptor` returned on 200 — the exact shape the desktop
/// (`desktop/.../commands/media.rs::BlobDescriptor`) parses, with the
/// server-local `image`/`filename` fields omitted (the relay is content
/// addressed and never learns them). Optional fields are skipped when `None`,
/// so a minimal upload yields `{"url","sha256","size","type","uploaded"}`.
#[derive(Debug, Clone, Serialize)]
pub struct BlobDescriptor {
    pub url: String,
    pub sha256: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub mime_type: String,
    pub uploaded: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dim: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blurhash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<f64>,
}

// ---- errors -------------------------------------------------------------

/// Upload failure. Maps to a constant `{"error": "<msg>"}` body; auth-detail is
/// never leaked (the underlying [`BlossomAuthError`] is unit-variant only and
/// already sanitized by `media::auth`).
#[derive(Debug)]
pub enum UploadError {
    /// Blossom 24242 verification failure (401, or 400 for the hash guards).
    Auth(BlossomAuthError),
    /// Caller is not a community member (403).
    NotAMember,
    /// Auth event id already used within its TTL window (401 — fail-closed,
    /// indistinguishable from any other auth failure so replay probing learns
    /// nothing).
    Replay,
    /// Body exceeded the applicable byte cap while streaming (413).
    PayloadTooLarge,
    /// Sniffed/declared MIME is disallowed or a media type was spoofed through
    /// the generic path (400).
    UnsupportedFileType,
    /// A metadata header was present but malformed/unbounded (400).
    InvalidMetadata,
    /// Staging I/O or store failure (500; details are logged, not echoed).
    Internal,
}

impl UploadError {
    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Auth(e) => (
                StatusCode::from_u16(e.status()).unwrap_or(StatusCode::UNAUTHORIZED),
                e.message(),
            ),
            Self::NotAMember => (StatusCode::FORBIDDEN, "not a community member"),
            Self::Replay => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload too large"),
            Self::UnsupportedFileType => (StatusCode::BAD_REQUEST, "unsupported file type"),
            Self::InvalidMetadata => (StatusCode::BAD_REQUEST, "invalid metadata"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        }
    }
}

impl IntoResponse for UploadError {
    fn into_response(self) -> Response {
        let (status, msg) = self.parts();
        (status, Json(ErrorBody { error: msg })).into_response()
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

// ---- composable dependencies -------------------------------------------

/// Community-membership gate. Implemented by the bridge over the history store
/// (`is_community_member(pubkey)` — exists as a `members`-table row for any
/// channel, M1b §0). The check is async because it queries the DB.
#[async_trait]
pub trait MediaMembership: Send + Sync {
    /// `true` iff `pubkey_hex` (64 lowercase hex) is a community member. A query
    /// failure should be treated as *not a member* (fail-closed → 403) by the
    /// implementation.
    async fn is_community_member(&self, pubkey_hex: &str) -> bool;
}

/// Permissive membership gate (every verified caller is a member). Useful for
/// dev/test and for the `require_membership = false` default where the gate is
/// skipped entirely.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllMembers;

#[async_trait]
impl MediaMembership for AllowAllMembers {
    async fn is_community_member(&self, _pubkey_hex: &str) -> bool {
        true
    }
}

/// Auth-event replay protection, keyed by the verified 24242 event id. The
/// contract (M1b §4) calls for reusing the existing NIP-98 `crate::auth::
/// ReplayCache`, whose `check_and_record` is currently private; this trait lets
/// the bridge wire either a dedicated [`MediaReplayCache`] or (once
/// `check_and_record` is made `pub`) an adapter over the shared cache. Returns
/// `true` when the id is fresh (and records it), `false` on replay.
pub trait MediaReplay: Send + Sync {
    fn check_and_record(&self, event_id: &str, now: u64, ttl_secs: u64) -> bool;
}

/// Default TTL replay cache — a pruned `event_id → expiry` map mirroring
/// `crate::auth::ReplayCache`. Private mutex, never shared with the history or
/// NIP-98 paths.
#[derive(Default)]
pub struct MediaReplayCache {
    seen: Mutex<HashMap<String, u64>>,
}

impl MediaReplayCache {
    pub fn new() -> Self {
        Self::default()
    }
}

impl MediaReplay for MediaReplayCache {
    fn check_and_record(&self, event_id: &str, now: u64, ttl_secs: u64) -> bool {
        // Poison is impossible in this panic-free module; recover the guard
        // anyway so a future shared use can never deadlock.
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.retain(|_, &mut exp| exp > now);
        if seen.contains_key(event_id) {
            return false;
        }
        seen.insert(event_id.to_string(), now.saturating_add(ttl_secs));
        true
    }
}

/// Bundled dependencies injected into the handler. Constructed by the bridge
/// (wp-wire) from `AppState` fields; the handler extracts it via
/// [`axum::Extension`] so it does not depend on the concrete `AppState` type
/// (and thus compiles in isolation before `AppState` grows its media fields).
#[derive(Clone)]
pub struct MediaUploadState {
    pub store: Arc<MediaStore>,
    pub config: Arc<MediaUploadConfig>,
    pub replay: Arc<dyn MediaReplay>,
    pub membership: Arc<dyn MediaMembership>,
}

impl MediaUploadState {
    pub fn new(
        store: Arc<MediaStore>,
        config: Arc<MediaUploadConfig>,
        replay: Arc<dyn MediaReplay>,
        membership: Arc<dyn MediaMembership>,
    ) -> Self {
        Self {
            store,
            config,
            replay,
            membership,
        }
    }
}

// ---- public API ---------------------------------------------------------

/// Mountable axum handler for `PUT /upload` (+ alias). Mount on the media
/// sub-router with `Extension(Arc<MediaUploadState>)`:
///
/// ```ignore
/// Router::new()
///     .route("/upload", put(media::upload::put_upload))
///     .route("/media/upload", put(media::upload::put_upload))
///     .layer(Extension(upload_state))
///     .layer(DefaultBodyLimit::max(cfg.max_video_bytes as usize));
/// ```
///
/// (The `DefaultBodyLimit` is belt-and-suspenders; this handler enforces the
/// cap itself while streaming, so it is correct even if the layer is absent.)
pub async fn put_upload(
    Extension(state): Extension<Arc<MediaUploadState>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let now = unix_now();
    handle_upload(&state, &headers, body, now).await
}

/// Composable upload core — the full pipeline against an explicit `now`
/// (testable; the handler above is a thin clock wrapper). A caller that prefers
/// `State<AppState>` over `Extension` can build a [`MediaUploadState`] borrow
/// and call this directly.
pub async fn handle_upload(
    state: &MediaUploadState,
    headers: &HeaderMap,
    body: Body,
    now: u64,
) -> Response {
    match run_upload(state, headers, body, now).await {
        Ok(descriptor) => (StatusCode::OK, Json(descriptor)).into_response(),
        Err(err) => err.into_response(),
    }
}

// ---- pipeline -----------------------------------------------------------

/// Outcome of streaming the body to the staging file.
struct Streamed {
    sha256_hex: String,
    /// The leading bytes (≤ [`SNIFF_BYTES`]); the MIME/ext are (re)derived by
    /// [`classify`] and the on-disk size by [`MediaStore::install`].
    sniff_buf: Vec<u8>,
}

async fn run_upload(
    state: &MediaUploadState,
    headers: &HeaderMap,
    body: Body,
    now: u64,
) -> Result<BlobDescriptor, UploadError> {
    // (1) Pre-stream static auth — fail-closed 401 before any body byte is read.
    // Uses the lenient video window so a valid (slightly older) video token is
    // never wrongly rejected here; the type-specific age is re-checked at (7).
    let principal = auth::verify_blossom(
        headers,
        BlossomVerb::Upload,
        state.config.video_auth_max_age_secs,
        &state.config.relay_authority,
        now,
    )
    .map_err(UploadError::Auth)?;

    // (2) Membership gate (fail-fast 403 before I/O).
    if state.config.require_membership
        && !state
            .membership
            .is_community_member(&principal.pubkey_hex)
            .await
    {
        return Err(UploadError::NotAMember);
    }

    // (3) Content-Length fast-fail (413 before I/O).
    if let Some(cl) = content_length(headers) {
        if cl > state.config.max_video_bytes {
            return Err(UploadError::PayloadTooLarge);
        }
    }

    // (4) Bounded metadata headers (fail-fast 400 before I/O).
    let dim = parse_dim(headers)?;
    let blurhash = parse_blurhash(headers)?;
    let thumb = parse_thumb(headers)?;
    let duration = parse_duration(headers)?;

    // (5) Stream → staging, hash, sniff, per-type cap (aborts+deletes on 413).
    let staging = state.store.staging_path();
    let streamed = match stream_to_staging(&staging, body, &state.config).await {
        Ok(s) => s,
        Err(e) => return Err(e), // stream_to_staging already cleaned up staging.
    };

    // (6) Classify MIME + canonical ext (400 on disallowed/spoofed type).
    let classified = match classify(&streamed.sniff_buf, content_type(headers)) {
        Ok(c) => c,
        Err(e) => {
            cleanup_staging(&staging).await;
            return Err(e);
        }
    };

    // (7) Hash binding — the LAST static auth check. Type-specific max-age:
    // video tokens get the 1 h window, everything else the 10 min window.
    let max_age = if classified.is_video {
        state.config.video_auth_max_age_secs
    } else {
        state.config.upload_auth_max_age_secs
    };
    if let Err(e) = auth::verify_upload(
        headers,
        &streamed.sha256_hex,
        max_age,
        &state.config.relay_authority,
        now,
    ) {
        cleanup_staging(&staging).await;
        return Err(UploadError::Auth(e));
    }

    // (8) Replay — consumed ONLY after every static auth check + membership.
    if !state
        .replay
        .check_and_record(&principal.event_id, now, max_age)
    {
        cleanup_staging(&staging).await;
        return Err(UploadError::Replay);
    }

    // (9) Disposition: derive from MIME; honour an explicit attachment hint.
    let disposition = derive_disposition(&classified.mime, headers);

    // (10) Idempotent CAS install — consumes staging (rename or discard). A
    // pre-existing sidecar short-circuits to the existing record → success
    // descriptor, no rewrite.
    let new_rec = NewMediaRecord {
        mime_type: classified.mime,
        ext: classified.ext,
        uploaded_at: now as i64,
        uploader_pubkey: principal.pubkey_hex.clone(),
        dim,
        blurhash,
        thumb_sha: thumb,
        duration_secs: duration,
        disposition,
    };
    let outcome = match state
        .store
        .install(&streamed.sha256_hex, new_rec, staging)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            warn!(error = %e, sha256 = %streamed.sha256_hex, "media install failed");
            return Err(UploadError::Internal);
        }
    };
    let rec = match outcome {
        InstallOutcome::Installed(r) | InstallOutcome::Existing(r) => r,
    };

    Ok(build_descriptor(&state.config, &rec))
}

/// Stream `body` into `staging` while hashing, sniffing, and enforcing the
/// per-type cap. On any error the staging file is deleted and `Err` returned;
/// on success the file is left in place for [`MediaStore::install`].
async fn stream_to_staging(
    staging: &Path,
    body: Body,
    config: &MediaUploadConfig,
) -> Result<Streamed, UploadError> {
    // MediaStore::open already created the blob dir; create_dir_all defensively
    // so a never-yet-opened store surfaces a clean 500 rather than a create
    // failure deep in the stream.
    if let Some(parent) = staging.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }

    let mut file = tokio::fs::File::create(staging).await.map_err(|e| {
        warn!(error = %e, "media staging create failed");
        UploadError::Internal
    })?;

    let mut stream = body.into_data_stream();
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut sniff: Vec<u8> = Vec::with_capacity(SNIFF_BYTES);
    // Before the true type is known, bound by the largest per-type cap. Sniff
    // completes within SNIFF_BYTES (≪ the tightest cap), so the real cap is
    // always in force before it could ever bind.
    let mut effective_cap = config.max_video_bytes;
    let mut sniffed: Option<&'static str> = None;

    while let Some(chunk_res) = stream.next().await {
        let chunk = match chunk_res {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "media body stream error");
                cleanup_staging(staging).await;
                return Err(UploadError::Internal);
            }
        };

        // Accumulate the leading bytes for sniffing (once, capped at SNIFF_BYTES).
        if sniff.len() < SNIFF_BYTES {
            let need = SNIFF_BYTES - sniff.len();
            let take = chunk.len().min(need);
            sniff.extend_from_slice(&chunk[..take]);
            if sniff.len() >= SNIFF_BYTES && sniffed.is_none() {
                sniffed = sniff_mime(&sniff);
                effective_cap = cap_for_sniff(sniffed, config);
            }
        }

        total = total.saturating_add(chunk.len() as u64);
        if total > effective_cap {
            cleanup_staging(staging).await;
            return Err(UploadError::PayloadTooLarge);
        }

        hasher.update(&chunk);
        if let Err(e) = file.write_all(&chunk).await {
            warn!(error = %e, "media staging write failed");
            cleanup_staging(staging).await;
            return Err(UploadError::Internal);
        }
    }

    if let Err(e) = file.flush().await {
        warn!(error = %e, "media staging flush failed");
        cleanup_staging(staging).await;
        return Err(UploadError::Internal);
    }
    // Best-effort fsync so the bytes are durable before the sidecar commit; a
    // failure is not fatal (the rename+insert still proceeds).
    let _ = file.sync_all().await;

    let sha256_hex = hex::encode(hasher.finalize());

    Ok(Streamed {
        sha256_hex,
        sniff_buf: sniff,
    })
}

/// Remove a staging file, ignoring "not found" (it may already be gone). Used
/// on every error path before [`MediaStore::install`] consumes the path.
async fn cleanup_staging(path: &Path) {
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(error = %e, path = %path.display(), "failed to remove media staging"),
    }
}

// ---- classification -----------------------------------------------------

struct Classified {
    mime: String,
    ext: String,
    is_video: bool,
}

/// Resolve `(mime, ext, is_video)` from the sniffed magic bytes, falling back
/// to the declared `Content-Type` for generic (non-media) files.
fn classify(sniff: &[u8], content_type: Option<String>) -> Result<Classified, UploadError> {
    // Media types are decided by magic bytes alone — never the Content-Type
    // header (buzz-media contract; prevents Content-Type spoofing).
    if let Some(media) = sniff_mime(sniff) {
        return Ok(Classified {
            mime: media.to_string(),
            ext: mime_to_ext(media).to_string(),
            is_video: media == "video/mp4",
        });
    }

    // Generic-file path: take the type/subtype from Content-Type (params
    // stripped), reject media types (they must sniff) and blocked active
    // content. Unsniffable/absent → opaque octet-stream served as a download.
    let ct_token = content_type
        .as_deref()
        .map(|s| s.split(';').next().unwrap_or("").trim());
    let (mime, ext) = match ct_token {
        Some(ct) if is_valid_mime_token(ct) => {
            if ct.starts_with("image/") || ct.starts_with("video/") || ct.starts_with("audio/") {
                // A media Content-Type whose bytes did not sniff as media is a
                // spoof; media must never fall through to exact-byte attachment.
                return Err(UploadError::UnsupportedFileType);
            }
            if is_blocked_file_mime(ct) {
                return Err(UploadError::UnsupportedFileType);
            }
            (ct.to_string(), mime_to_ext(ct).to_string())
        }
        _ => ("application/octet-stream".to_string(), "bin".to_string()),
    };

    Ok(Classified {
        mime,
        ext,
        is_video: false,
    })
}

/// Per-type byte cap from the sniffed (or absent) media type. `None` (generic)
/// → `max_file_bytes`.
fn cap_for_sniff(sniffed: Option<&str>, config: &MediaUploadConfig) -> u64 {
    match sniffed {
        Some("image/gif") => config.max_gif_bytes,
        Some("image/jpeg" | "image/png" | "image/webp") => config.max_image_bytes,
        Some("video/mp4") => config.max_video_bytes,
        _ => config.max_file_bytes,
    }
}

/// Magic-byte MIME detection for the five Blossom-allowed media types. Returns
/// `None` for anything else (the generic-file path). Ported from
/// `crates/buzz-media/src/validation.rs` (the `infer`-free ISO-BMFF check).
fn sniff_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        return Some("image/webp");
    }
    if looks_like_mp4_iso_bmff(bytes) {
        return Some("video/mp4");
    }
    None
}

/// Canonical lowercase extension for a MIME type. Media exts are fixed; generic
/// exts cover common document/archive/text formats, falling back to `bin`.
fn mime_to_ext(mime: &str) -> &'static str {
    match mime {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "video/mp4" => "mp4",
        "application/pdf" => "pdf",
        "application/zip" => "zip",
        "application/x-zip-compressed" => "zip",
        "application/x-tar" => "tar",
        "application/gzip" | "application/x-gzip" => "gz",
        "application/x-7z-compressed" => "7z",
        "application/x-bzip2" => "bz2",
        "application/x-xz" => "xz",
        "text/plain" => "txt",
        "text/csv" => "csv",
        "text/markdown" => "md",
        "text/calendar" => "ics",
        "application/json" => "json",
        "application/xml" | "text/xml" => "xml",
        "application/rtf" => "rtf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => "docx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => "xlsx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => "pptx",
        "application/vnd.ms-excel" => "xls",
        "application/msword" => "doc",
        "application/vnd.ms-powerpoint" => "ppt",
        "application/octet-stream" => "bin",
        _ => "bin",
    }
}

/// `true` iff `mime` is an active-content / executable type denied on the
/// generic path (defence in depth — generic files are served as attachments
/// with `nosniff` regardless). Mirrors `BLOCKED_FILE_MIME_TYPES`.
fn is_blocked_file_mime(mime: &str) -> bool {
    matches!(
        mime,
        "text/html"
            | "application/xhtml+xml"
            | "image/svg+xml"
            | "application/javascript"
            | "text/javascript"
            | "application/x-msdownload"
            | "application/x-executable"
            | "application/vnd.microsoft.portable-executable"
            | "application/x-mach-binary"
            | "application/x-sharedlib"
            | "application/x-elf"
            | "application/x-msi"
            | "application/vnd.android.package-archive"
            | "application/x-apple-diskimage"
    )
}

/// `true` iff `s` is a bounded `type/subtype` token (no params, ASCII token
/// chars only). Prevents storage of pathological Content-Type values.
fn is_valid_mime_token(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_MIME_LEN {
        return false;
    }
    let mut parts = s.splitn(2, '/');
    let primary = parts.next().unwrap_or("");
    let sub = parts.next();
    let valid_part = |p: &str| {
        !p.is_empty()
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'+' | b'_'))
    };
    valid_part(primary) && sub.is_some_and(valid_part)
}

/// Resolve the serve disposition: an explicit `Content-Disposition: attachment`
/// forces a download; otherwise images/video are inline and everything else is
/// an attachment (M1b §5.8 / §6.5).
fn derive_disposition(mime: &str, headers: &HeaderMap) -> BlobDisposition {
    if let Some(cd) = header_str(headers, "content-disposition") {
        let token = cd
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if token == "attachment" {
            return BlobDisposition::Attachment;
        }
        if token == "inline" {
            return BlobDisposition::Inline;
        }
    }
    if mime.starts_with("image/") || mime.starts_with("video/") {
        BlobDisposition::Inline
    } else {
        BlobDisposition::Attachment
    }
}

// ---- metadata header parsing -------------------------------------------

fn parse_dim(headers: &HeaderMap) -> Result<Option<String>, UploadError> {
    let Some(v) = header_str(headers, "x-dim") else {
        return Ok(None);
    };
    let v = v.trim();
    if v.len() > MAX_DIM_LEN || !is_valid_dim(v) {
        return Err(UploadError::InvalidMetadata);
    }
    Ok(Some(v.to_string()))
}

/// `WxH` with 1–5 ASCII digits per side, e.g. `1920x1080`.
fn is_valid_dim(s: &str) -> bool {
    let mut parts = s.splitn(2, 'x');
    let w = parts.next().unwrap_or("");
    let h = parts.next();
    let valid = |p: &str| (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit());
    valid(w) && h.is_some_and(valid)
}

fn parse_blurhash(headers: &HeaderMap) -> Result<Option<String>, UploadError> {
    let Some(v) = header_str(headers, "x-blurhash") else {
        return Ok(None);
    };
    let v = v.trim();
    if v.is_empty() || v.len() > MAX_BLURHASH_LEN || v.bytes().any(|b| b.is_ascii_control()) {
        return Err(UploadError::InvalidMetadata);
    }
    Ok(Some(v.to_string()))
}

fn parse_thumb(headers: &HeaderMap) -> Result<Option<String>, UploadError> {
    let Some(v) = header_str(headers, "x-thumb") else {
        return Ok(None);
    };
    let v = v.trim();
    if !is_valid_sha256(v) {
        return Err(UploadError::InvalidMetadata);
    }
    Ok(Some(v.to_ascii_lowercase()))
}

fn parse_duration(headers: &HeaderMap) -> Result<Option<f64>, UploadError> {
    let Some(v) = header_str(headers, "x-duration") else {
        return Ok(None);
    };
    let d: f64 = v.trim().parse().map_err(|_| UploadError::InvalidMetadata)?;
    if !d.is_finite() || !(0.0..=MAX_DURATION_SECS).contains(&d) {
        return Err(UploadError::InvalidMetadata);
    }
    Ok(Some(d))
}

// ---- ISO-BMFF / MP4 structural check -----------------------------------
//
// Ported verbatim from `crates/buzz-media/src/validation.rs` (MIT OR
// Apache-2.0). ISO-BMFF permits arbitrary major brands, so a finite brand list
// (à la `infer`) cannot recognise every valid MP4; this parses the `ftyp` box
// structurally and accepts the major brand or any listed compatible brand.

const MP4_BRANDS: &[[u8; 4]] = &[
    *b"isom", *b"iso2", *b"iso3", *b"iso4", *b"iso5", *b"iso6", *b"iso7", *b"iso8", *b"iso9",
    *b"mp41", *b"mp42", *b"avc1", *b"dash", *b"M4V ",
];

fn iso_bmff_ftyp_payload(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 16 || &bytes[4..8] != b"ftyp" {
        return None;
    }
    let compact = u32::from_be_bytes(bytes[..4].try_into().ok()?) as u64;
    let (declared_size, header_size) = if compact == 1 {
        if bytes.len() < 24 {
            return None;
        }
        (u64::from_be_bytes(bytes[8..16].try_into().ok()?), 16usize)
    } else if compact == 0 {
        (bytes.len() as u64, 8usize)
    } else {
        (compact, 8usize)
    };
    if declared_size < (header_size + 8) as u64 {
        return None;
    }
    let available_end = usize::try_from(declared_size)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    (available_end >= header_size + 8).then_some(&bytes[header_size..available_end])
}

fn looks_like_mp4_iso_bmff(bytes: &[u8]) -> bool {
    let Some(payload) = iso_bmff_ftyp_payload(bytes) else {
        return false;
    };
    let major = payload[..4].try_into().ok();
    major.is_some_and(|brand| MP4_BRANDS.contains(&brand))
        || payload[8..]
            .chunks_exact(4)
            .any(|brand| MP4_BRANDS.iter().any(|candidate| brand == candidate))
}

// ---- response assembly --------------------------------------------------

fn build_descriptor(config: &MediaUploadConfig, rec: &MediaRecord) -> BlobDescriptor {
    BlobDescriptor {
        url: media_url(&config.media_public_base_url, &rec.sha256, &rec.ext),
        sha256: rec.sha256.clone(),
        size: rec.size,
        mime_type: rec.mime_type.clone(),
        uploaded: rec.uploaded_at,
        dim: rec.dim.clone(),
        blurhash: rec.blurhash.clone(),
        // Thumbnails are stored as their own CAS blob; the contract (M1b §5.9)
        // renders the thumb URL with a `.webp` suffix.
        thumb: rec
            .thumb_sha
            .as_ref()
            .map(|sha| thumb_url(&config.media_public_base_url, sha)),
        duration: rec.duration_secs,
    }
}

fn media_url(base: &str, sha: &str, ext: &str) -> String {
    format!("{}/media/{sha}.{ext}", base.trim_end_matches('/'))
}

fn thumb_url(base: &str, thumb_sha: &str) -> String {
    format!("{}/media/{thumb_sha}.webp", base.trim_end_matches('/'))
}

// ---- small helpers ------------------------------------------------------

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn content_type(headers: &HeaderMap) -> Option<String> {
    header_str(headers, "content-type").map(|s| s.trim().to_ascii_lowercase())
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    header_str(headers, "content-length").and_then(|s| s.trim().parse::<u64>().ok())
}

/// Current unix seconds. `unwrap_or(0)` keeps it panic-free if the clock is
/// before the epoch (impossible in practice).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

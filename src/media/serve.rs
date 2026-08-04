// SPDX-License-Identifier: MIT OR Apache-2.0
//! Composable Blossom media GET/HEAD serve service (bridge M1b §6). Owner: WP-MS.
//!
//! This is the read side of the media CAS: it turns a `GET/HEAD /media/{sha}.{ext}`
//! request into a streamed, range-aware, cacheable response — without ever
//! buffering a whole blob. A 500 MiB video is seeked to the requested byte
//! offset and streamed in fixed-size chunks via `tokio::fs::File` +
//! `tokio_util::io::ReaderStream` → `axum::body::Body::from_stream`; only the
//! requested slice ever leaves disk.
//!
//! # Composition model
//!
//! [`MediaServe`] holds only a content-addressed [`MediaStore`] and a
//! [`ServeConfig`]. The two cross-cutting capabilities it needs — **replay
//! protection** and **community membership** — are injected per-call as the
//! [`ReplayGuard`] and [`MemberCheck`] traits, so this module compiles and is
//! unit-testable with zero coupling to `AppState`/`Settings` (which the wiring
//! layer, WP-W, owns). The axum route handler is a ~5-line wrapper the wiring
//! layer writes around [`MediaServe::serve`] (see "Integration needs" below).
//!
//! # Request pipeline (order is the security contract, §6)
//! 1. **Parse path** `{sha}.{ext}`: ill-formed / traversal / non-hex / bad ext ⇒
//!    **404** (hide — never 400; no path-shape detail leaks).
//! 2. **Auth + replay + membership** (only when either gate is on): Blossom
//!    kind-24242 `get` verification ⇒ 401/400; replay of the 24242 event id ⇒
//!    401; non-member ⇒ 403. Done *before* the sidecar lookup so a 401/403 can
//!    never reveal whether a blob exists.
//! 3. **Sidecar gate** ([`MediaStore::serve_lookup`]): missing row OR missing
//!    blob file ⇒ indistinguishable **404** (§6.3).
//! 4. **Conditional request**: strong `ETag` = the content-addressed sha256;
//!    matching `If-None-Match` ⇒ **304**.
//! 5. **Range**: a single satisfiable byte range ⇒ **206** +
//!    `Content-Range: bytes s-e/total`; malformed / multiple / unsatisfiable ⇒
//!    **416** + `Content-Range: bytes */total`.
//! 6. **Headers**: `Content-Type`/`Content-Length`/`Accept-Ranges`/`ETag`/
//!    `Cache-Control: public, max-age=<y>, immutable`/`Content-Disposition`
//!    (inline unless `?download=1` or the sidecar marks the blob `attachment`).
//!
//! No filesystem path, internal id, or storage detail is ever placed in a
//! response header or body. Every code path returns a sanitized [`Response`];
//! the module is panic-free (no `unwrap`/`expect`/`panic`/indexing on
//! attacker-controlled input).

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio_util::io::ReaderStream;

use crate::http::api_error;
use crate::media::auth::verify_get;
use crate::media::store::{
    is_valid_ext, is_valid_sha256, BlobDisposition, MediaRecord, MediaStore,
};

/// One year — content-addressed blobs are immutable, so the response is safely
/// cacheable for a full year (§6.5).
const DEFAULT_CACHE_MAX_AGE_SECS: u64 = 31_536_000;

/// Configuration for [`MediaServe`], wired from `Settings` by the wiring layer.
///
/// `require_get_auth` mirrors `Settings::require_media_get_auth` (default
/// **false** ⇒ fail-open, matching the desktop). `require_membership` is an
/// independent community-membership gate; when it is on, identity is required
/// to evaluate it, so [`MediaServe::serve`] treats
/// `require_get_auth || require_membership` as "auth required".
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// Require a valid Blossom kind-24242 `get` auth event (else serve open).
    pub require_get_auth: bool,
    /// Require the authenticated principal to be a community member.
    pub require_membership: bool,
    /// `created_at` freshness bound + replay-cache TTL for a `get` auth event.
    pub get_auth_max_age_secs: u64,
    /// `host[:port]` of the bridge public base URL — the BUD-11 `server`-tag
    /// match target for server-scoped get auth.
    pub relay_authority: String,
    /// `Cache-Control: public, max-age=<n>, immutable` max-age (seconds).
    pub cache_max_age_secs: u64,
}

impl Default for ServeConfig {
    fn default() -> Self {
        // Fail-open defaults (matches the desktop's require_media_get_auth=false).
        Self {
            require_get_auth: false,
            require_membership: false,
            get_auth_max_age_secs: 3600,
            relay_authority: String::new(),
            cache_max_age_secs: DEFAULT_CACHE_MAX_AGE_SECS,
        }
    }
}

/// Replay-protection capability: record that `event_id` was seen, rejecting a
/// replay within `ttl`. Injected (not coupled to `AppState`) because the
/// bridge's `auth::ReplayCache` is keyed the same way for NIP-98 and Blossom
/// 24242 (§4) but its `check_and_record` is crate-private to `auth`. The wiring
/// layer provides a blanket impl — see "Integration needs" in this module's
/// usage notes.
pub trait ReplayGuard: Send + Sync {
    /// `Ok` if first sight; `Err` if already seen within the window or the guard
    /// could not make the determination (fail-closed).
    fn check_and_record(&self, event_id: &str, now: u64, ttl: u64) -> Result<(), ReplayRejection>;
}

/// Why a replay check rejected an event id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayRejection {
    /// The event id was already accepted within its TTL window.
    Replayed,
    /// The guard could not decide (e.g. its lock is poisoned). Maps to 500.
    Unavailable,
}

/// A no-op guard that never rejects — for fail-open contexts and tests.
#[derive(Default, Debug, Clone, Copy)]
pub struct NoopReplayGuard;

impl ReplayGuard for NoopReplayGuard {
    fn check_and_record(
        &self,
        _event_id: &str,
        _now: u64,
        _ttl: u64,
    ) -> Result<(), ReplayRejection> {
        Ok(())
    }
}

/// Community-membership capability: "is `pubkey_hex` a member/owner/admin of
/// **any** channel" (community membership, §0). Injected so this module does
/// not depend on `HistoryEngine`/`AppState`. `Ok(false)` ⇒ 403; `Err` ⇒ 500
/// (a lookup failure is never silently treated as "not a member").
#[async_trait]
pub trait MemberCheck: Send + Sync {
    /// `Ok(true)` if the pubkey is a community member; `Ok(false)` otherwise.
    async fn is_community_member(&self, pubkey_hex: &str) -> anyhow::Result<bool>;
}

/// A no-op check that admits everyone — for fail-open contexts and tests.
#[derive(Default, Debug, Clone, Copy)]
pub struct NoopMemberCheck;

#[async_trait]
impl MemberCheck for NoopMemberCheck {
    async fn is_community_member(&self, _pubkey_hex: &str) -> anyhow::Result<bool> {
        Ok(true)
    }
}

/// Query string for `GET /media/{sha}.{ext}` — `?download=1` forces
/// `Content-Disposition: attachment` regardless of the sidecar disposition.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct MediaQuery {
    #[serde(default)]
    pub download: Option<bool>,
}

/// Composable GET/HEAD media serve service.
///
/// Construct once at startup with the shared [`MediaStore`] + [`ServeConfig`];
/// call [`MediaServe::serve`] from the route handler, injecting the request's
/// replay guard and membership source. Holds no per-request state.
#[derive(Clone)]
pub struct MediaServe {
    store: Arc<MediaStore>,
    config: ServeConfig,
}

impl MediaServe {
    /// Build a serve service over `store` with the given `config`.
    pub fn new(store: Arc<MediaStore>, config: ServeConfig) -> Self {
        Self { store, config }
    }

    /// Borrow the underlying store (e.g. to resolve a thumbnail's CAS path).
    pub fn store(&self) -> &MediaStore {
        &self.store
    }

    /// Borrow the serve configuration.
    pub fn config(&self) -> &ServeConfig {
        &self.config
    }

    /// Resolve one media GET/HEAD request into a fully-built [`Response`].
    ///
    /// - `method` — `GET` streams the requested bytes; `HEAD` returns the exact
    ///   same headers with an empty body (no file is opened for HEAD).
    /// - `raw_path` — the `{sha}.{ext}` tail of the URL (already percent-decoded
    ///   by the axum `Path` extractor).
    /// - `download` — `?download=1` ⇒ force attachment disposition.
    /// - `now` — injected unix seconds (deterministic; pass `relay_identity::now_secs()`).
    /// - `replay` / `members` — injected capabilities (see traits).
    ///
    /// Never panics: every branch yields a sanitized [`Response`].
    #[allow(clippy::too_many_arguments)]
    pub async fn serve<R, M>(
        &self,
        method: Method,
        raw_path: &str,
        download: bool,
        headers: &HeaderMap,
        now: u64,
        replay: &R,
        members: &M,
    ) -> Response
    where
        R: ReplayGuard,
        M: MemberCheck,
    {
        let cfg = &self.config;

        // (1) Parse {sha}.{ext} — hide every ill-formed/traversal path as 404.
        let Some((sha, _url_ext)) = parse_media_path(raw_path) else {
            return not_found();
        };

        // (2) Auth + replay + membership (before the lookup, so 401/403 cannot
        //     reveal existence). Auth is required whenever EITHER gate is on:
        //     membership needs an authenticated identity to evaluate.
        if cfg.require_get_auth || cfg.require_membership {
            let principal = match verify_get(
                headers,
                sha,
                cfg.get_auth_max_age_secs,
                &cfg.relay_authority,
                now,
            ) {
                Ok(p) => p,
                Err(e) => return api_error(e.status(), e.message()),
            };
            // Replay (fail-closed): a replayed 24242 id ⇒ 401; unavailable ⇒ 500.
            match replay.check_and_record(&principal.event_id, now, cfg.get_auth_max_age_secs) {
                Ok(()) => {}
                Err(ReplayRejection::Replayed) => return unauthorized(),
                Err(ReplayRejection::Unavailable) => return server_error(),
            }
            if cfg.require_membership {
                match members.is_community_member(&principal.pubkey_hex).await {
                    Ok(true) => {}
                    Ok(false) => return forbidden(),
                    Err(_) => return server_error(),
                }
            }
        }

        // (3) Sidecar gate: missing row OR missing blob ⇒ indistinguishable 404.
        let (rec, path) = match self.store.serve_lookup(sha).await {
            Ok(Some(rp)) => rp,
            Ok(None) => return not_found(),
            Err(_) => return server_error(),
        };

        // (4) Conditional request — strong ETag = the content-addressed sha256.
        let etag = format!("\"{}\"", rec.sha256);
        let inm = headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok());
        if etag_matches(inm, &etag) {
            return not_modified(&etag, cfg);
        }

        // (5) Range. Malformed/multiple/unsatisfiable ⇒ 416 with Content-Range */size.
        let range_hdr = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
        match parse_range(range_hdr, rec.size) {
            RangeSpec::NotSatisfiable => range_not_satisfiable(rec.size),
            RangeSpec::Full => {
                if method == Method::HEAD {
                    media_response(
                        StatusCode::OK,
                        &rec,
                        rec.size,
                        None,
                        cfg,
                        download,
                        Body::empty(),
                    )
                } else {
                    let file = match tokio::fs::File::open(&path).await {
                        Ok(f) => f,
                        // TOCTOU: vanished between serve_lookup and open ⇒ 404.
                        Err(_) => return not_found(),
                    };
                    let body = Body::from_stream(ReaderStream::new(file));
                    media_response(StatusCode::OK, &rec, rec.size, None, cfg, download, body)
                }
            }
            RangeSpec::Satisfiable { start, end } => {
                let len = end - start + 1;
                let content_range = format!("bytes {start}-{end}/{}", rec.size);
                if method == Method::HEAD {
                    return media_response(
                        StatusCode::PARTIAL_CONTENT,
                        &rec,
                        len,
                        Some(content_range),
                        cfg,
                        download,
                        Body::empty(),
                    );
                }
                let mut file = match tokio::fs::File::open(&path).await {
                    Ok(f) => f,
                    Err(_) => return not_found(),
                };
                if file.seek(SeekFrom::Start(start)).await.is_err() {
                    return server_error();
                }
                // `take(len)` bounds the read to exactly `len` bytes: no
                // over-read, no whole-file buffer — only the slice is streamed.
                let body = Body::from_stream(ReaderStream::new(file.take(len)));
                media_response(
                    StatusCode::PARTIAL_CONTENT,
                    &rec,
                    len,
                    Some(content_range),
                    cfg,
                    download,
                    body,
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (no IO, trivially auditable)
// ---------------------------------------------------------------------------

/// Split `{sha256}.{ext}` and validate both halves against the CAS key form.
/// Rejects empty input, any `/` (subpath / `..` traversal — the axum `{*path}`
/// tail may carry segments), a missing/leading dot, and non-canonical sha/ext.
/// Returns the validated `sha` (the lookup key); the URL `ext` is validated for
/// shape only — the sidecar's `mime_type`/`ext` is authoritative on the wire.
fn parse_media_path(raw: &str) -> Option<(&str, &str)> {
    if raw.is_empty() || raw.contains('/') {
        return None;
    }
    let dot = raw.rfind('.')?;
    if dot == 0 {
        return None;
    }
    let sha = &raw[..dot];
    let ext = &raw[dot + 1..];
    if !is_valid_sha256(sha) || !is_valid_ext(ext) {
        return None;
    }
    Some((sha, ext))
}

/// Outcome of parsing a `Range` header against a known total size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeSpec {
    /// No usable Range header (absent, empty, or an unsupported/unknown unit
    /// that RFC 7233 says to ignore) ⇒ serve the full representation (200).
    Full,
    /// A single, satisfiable inclusive byte range `[start, end]` (206).
    Satisfiable { start: u64, end: u64 },
    /// Header present but malformed, multi-range, or unsatisfiable (416).
    NotSatisfiable,
}

/// Parse a single `Range: bytes=…` header against `total` bytes.
///
/// Supported forms: `start-end`, `start-` (to end), `-suffix` (last N bytes).
/// The bridge serves exactly **one** range: a multi-range spec (`a-b,c-d`),
/// a missing dash, non-numeric bounds, an unsatisfiable offset
/// (`start >= total`), or `-0` ⇒ [`RangeSpec::NotSatisfiable`]. A suffix larger
/// than the file clamps to the whole file. Only the `bytes` unit is accepted
/// (case-insensitively); any other unit is ignored ⇒ [`RangeSpec::Full`].
fn parse_range(range: Option<&str>, total: u64) -> RangeSpec {
    let Some(raw) = range.map(str::trim).filter(|s| !s.is_empty()) else {
        return RangeSpec::Full;
    };

    // Only the `bytes` range unit is supported; unknown units are ignored per
    // RFC 7233 §2.3 (serve the full representation). The spec body is digits and
    // `-`/`,` only, so lower-casing to match the unit prefix is lossless.
    let lowered;
    let spec: &str = match raw.strip_prefix("bytes=") {
        Some(s) => s,
        None => {
            lowered = raw.to_ascii_lowercase();
            match lowered.strip_prefix("bytes=") {
                Some(s) => s,
                None => return RangeSpec::Full,
            }
        }
    };
    let spec = spec.trim();
    if spec.is_empty() {
        return RangeSpec::NotSatisfiable;
    }

    // Exactly one range; multiple (`a-b,c-d`) ⇒ 416.
    let mut parts = spec.split(',');
    let Some(part) = parts.next() else {
        return RangeSpec::NotSatisfiable;
    };
    if parts.next().is_some() {
        return RangeSpec::NotSatisfiable;
    }
    let part = part.trim();

    let Some((start_s, end_s)) = part.split_once('-') else {
        return RangeSpec::NotSatisfiable;
    };
    let start_s = start_s.trim();
    let end_s = end_s.trim();

    // A zero-length file satisfies no byte range.
    if total == 0 {
        return RangeSpec::NotSatisfiable;
    }

    let last = total - 1;
    let (start, end) = if start_s.is_empty() {
        // Suffix: last N bytes (`-N`).
        let suffix = match end_s.parse::<u64>() {
            Ok(n) => n,
            Err(_) => return RangeSpec::NotSatisfiable,
        };
        if suffix == 0 {
            return RangeSpec::NotSatisfiable; // `-0` ⇒ empty range
        }
        (total.saturating_sub(suffix), last)
    } else if end_s.is_empty() {
        // Open-ended (`N-`).
        let start = match start_s.parse::<u64>() {
            Ok(n) => n,
            Err(_) => return RangeSpec::NotSatisfiable,
        };
        if start >= total {
            return RangeSpec::NotSatisfiable;
        }
        (start, last)
    } else {
        // Closed (`N-M`).
        let start = match start_s.parse::<u64>() {
            Ok(n) => n,
            Err(_) => return RangeSpec::NotSatisfiable,
        };
        let end = match end_s.parse::<u64>() {
            Ok(n) => n,
            Err(_) => return RangeSpec::NotSatisfiable,
        };
        if start > end || start >= total {
            return RangeSpec::NotSatisfiable;
        }
        (start, end.min(last))
    };

    RangeSpec::Satisfiable { start, end }
}

/// Whether an `If-None-Match` value matches `etag` (the quoted strong validator).
/// Accepts `*`, a single validator, a comma-separated list, and `W/` weak
/// prefixes (weak/strong compare equal for If-None-Match per RFC 7232 §3.2).
fn etag_matches(if_none_match: Option<&str>, etag: &str) -> bool {
    let Some(list) = if_none_match else {
        return false;
    };
    let list = list.trim();
    if list.is_empty() {
        return false;
    }
    if list == "*" {
        return true;
    }
    list.split(',').any(|tok| {
        let mut t = tok.trim();
        if let Some(rest) = t.strip_prefix("W/") {
            t = rest.trim();
        }
        t == etag
    })
}

/// `Cache-Control` header value for an immutable content-addressed blob.
fn cache_control(cfg: &ServeConfig) -> String {
    format!("public, max-age={}, immutable", cfg.cache_max_age_secs)
}

/// `Content-Disposition` value: `attachment` when forced (`?download=1`) or when
/// the sidecar stored `Attachment` (generic uploads); else `inline`.
fn content_disposition(rec: &MediaRecord, download: bool) -> String {
    if download || rec.disposition == BlobDisposition::Attachment {
        // sha (hex) + ext (lowercase alnum) are filename-safe; no RFC 5987
        // encoding needed.
        format!("attachment; filename=\"{}.{}\"", rec.sha256, rec.ext)
    } else {
        "inline".to_string()
    }
}

// ---------------------------------------------------------------------------
// Response builders (panic-free: a bad header value is dropped, not panicked)
// ---------------------------------------------------------------------------

/// Insert a string header value, silently dropping it if it fails `HeaderValue`
/// construction (cannot happen for the controlled ASCII values used here, but
/// keeps the module panic-free under any input).
fn put(h: &mut HeaderMap, name: HeaderName, val: &str) {
    if let Ok(v) = HeaderValue::from_str(val) {
        h.insert(name, v);
    }
}

/// Build a 200/206 media response with the full header set (§6.5) and `body`.
/// `content_range` is set only for 206. The body is already the exact byte
/// stream (or empty for HEAD) — no further framing is applied.
#[allow(clippy::too_many_arguments)]
fn media_response(
    status: StatusCode,
    rec: &MediaRecord,
    content_length: u64,
    content_range: Option<String>,
    cfg: &ServeConfig,
    download: bool,
    body: Body,
) -> Response {
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    put(h, header::CONTENT_TYPE, &rec.mime_type);
    put(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    put(h, header::CONTENT_LENGTH, &content_length.to_string());
    put(h, header::ACCEPT_RANGES, "bytes");
    put(h, header::ETAG, &format!("\"{}\"", rec.sha256));
    put(h, header::CACHE_CONTROL, &cache_control(cfg));
    put(
        h,
        header::CONTENT_DISPOSITION,
        &content_disposition(rec, download),
    );
    if let Some(cr) = content_range {
        put(h, header::CONTENT_RANGE, &cr);
    }
    resp
}

/// 416 Range Not Satisfiable with `Content-Range: bytes */{total}` (§6.4).
fn range_not_satisfiable(total: u64) -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
    let h = resp.headers_mut();
    put(h, header::CONTENT_RANGE, &format!("bytes */{total}"));
    put(h, header::ACCEPT_RANGES, "bytes");
    put(h, header::CONTENT_LENGTH, "0");
    resp
}

/// 304 Not Modified — validators + cache directives only, no body/length.
fn not_modified(etag: &str, cfg: &ServeConfig) -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NOT_MODIFIED;
    let h = resp.headers_mut();
    put(h, header::ETAG, etag);
    put(h, header::CACHE_CONTROL, &cache_control(cfg));
    put(h, header::ACCEPT_RANGES, "bytes");
    resp
}

/// Indistinguishable 404 for a hidden/missing blob (constant body, no path).
fn not_found() -> Response {
    api_error(404, "not found")
}

/// Generic 401 (replay / sanitized Blossom identity failure fallback).
fn unauthorized() -> Response {
    api_error(401, "unauthorized")
}

/// 403 non-member.
fn forbidden() -> Response {
    api_error(403, "restricted: not a community member")
}

/// 500 internal error (storage/lookup failure; never reveals detail).
fn server_error() -> Response {
    api_error(500, "internal error")
}

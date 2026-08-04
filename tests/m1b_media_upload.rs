//! M1b Blossom upload wire-level regressions (WP-MS).
//!
//! Drives the composable upload core `handle_upload` directly with real axum
//! `Body` streams and real kind-24242 auth events (URL_SAFE_NO_PAD, signed with
//! `nostr` keys). Every response is a genuine HTTP `Response`, so status/header/
//! body assertions pin the exact wire contract: streaming PUT + SHA verification,
//! duplicate-hash idempotency, and cap/type/membership/replay rejection.
//!
//! No whole-body extractor is on the production path; the test also never reads
//! the body into a `Vec` before handing it over — `Body::from` is the same stream
//! source hyper serves.
//!
//! Run: `cargo test -p x0x-nostr-bridge --test m1b_media_upload -- --nocapture`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use base64::Engine as _;
use nostr::{EventBuilder, JsonUtil, Keys, Tag, Timestamp};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use x0x_nostr_bridge::media::store::MediaStore;
use x0x_nostr_bridge::media::upload::{
    handle_upload, AllowAllMembers, MediaMembership, MediaReplayCache, MediaUploadConfig,
    MediaUploadState,
};

const RELAY_AUTHORITY: &str = "127.0.0.1:3000";
const PUB_BASE: &str = "http://127.0.0.1:3000";
const FINGERPRINT: &str = "m1b-upload-fp";
const KIND_BLOSSOM: u16 = 24242;
/// A minimal PNG magic + payload (sniffs as image/png).
const PNG_BODY: &[u8] = b"\x89PNG\r\n\x1a\n here is some png payload data padding padding";

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

struct Ctx {
    _dir: TempDir,
    state: MediaUploadState,
    keys: Keys,
}

impl Ctx {
    /// `require_membership = false`, generous caps (overridden per-test).
    fn new() -> Self {
        Self::with_config(base_config())
    }

    fn with_config(config: MediaUploadConfig) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            MediaStore::open(
                &dir.path().join("media.db"),
                &dir.path().join("blobs"),
                FINGERPRINT,
            )
            .expect("open media store"),
        );
        let state = MediaUploadState::new(
            store,
            Arc::new(config),
            Arc::new(MediaReplayCache::default()),
            Arc::new(AllowAllMembers) as Arc<dyn MediaMembership>,
        );
        Self {
            _dir: dir,
            state,
            keys: Keys::generate(),
        }
    }

    fn now(&self) -> u64 {
        1_700_000_000
    }

    /// A valid upload auth event for `x_sha` at `now`, optionally server-tagged.
    fn upload_auth(&self, x_sha: &str, now: u64, server: bool) -> HeaderMap {
        blossom_header(&self.keys, "upload", Some(x_sha), now, now + 3600, server)
    }

    async fn put(
        &self,
        body: &[u8],
        headers: HeaderMap,
        now: u64,
    ) -> (StatusCode, Value, HeaderMap) {
        let resp = handle_upload(&self.state, &headers, Body::from(body.to_vec()), now).await;
        let status = resp.status();
        let h = resp.headers().clone();
        let bytes = to_bytes(resp.into_body(), 8 * 1024 * 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json, h)
    }
}

fn base_config() -> MediaUploadConfig {
    MediaUploadConfig {
        media_public_base_url: PUB_BASE.to_string(),
        relay_authority: RELAY_AUTHORITY.to_string(),
        max_image_bytes: 50 * 1024 * 1024,
        max_gif_bytes: 10 * 1024 * 1024,
        max_video_bytes: 524_288_000,
        max_file_bytes: 104_857_600,
        upload_auth_max_age_secs: 600,
        video_auth_max_age_secs: 3600,
        require_membership: false,
    }
}

/// Build a kind-24242 `Authorization: Nostr <url_safe_no_pad(json)>` header set.
fn blossom_header(
    keys: &Keys,
    verb: &str,
    x_sha: Option<&str>,
    created_at: u64,
    expiration: u64,
    server_tag: bool,
) -> HeaderMap {
    let mut b = EventBuilder::new(Kind::from(KIND_BLOSSOM), "blossom-auth")
        .custom_created_at(Timestamp::from(created_at))
        .tag(Tag::parse(["t", verb]).unwrap())
        .tag(Tag::parse(["expiration", &expiration.to_string()]).unwrap());
    if let Some(x) = x_sha {
        b = b.tag(Tag::parse(["x", x]).unwrap());
    }
    if server_tag {
        b = b.tag(Tag::parse(["server", RELAY_AUTHORITY]).unwrap());
    }
    let ev = b.sign_with_keys(keys).expect("sign 24242");
    let json = ev.as_json();
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Nostr {token}")).unwrap(),
    );
    headers
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Attach Content-Type + Content-Length + optional X-SHA-256 to a header set.
fn media_headers(
    mut h: HeaderMap,
    ctype: &str,
    len: usize,
    x_sha_header: Option<&str>,
) -> HeaderMap {
    h.insert("content-type", HeaderValue::from_str(ctype).unwrap());
    h.insert(
        "content-length",
        HeaderValue::from_str(&len.to_string()).unwrap(),
    );
    if let Some(x) = x_sha_header {
        h.insert("x-sha-256", HeaderValue::from_str(x).unwrap());
    }
    h
}

// ===========================================================================
// Happy path + idempotency
// ===========================================================================

#[tokio::test]
async fn put_valid_image_returns_descriptor_with_verified_sha() {
    let ctx = Ctx::new();
    let now = ctx.now();
    let sha = sha256_hex(PNG_BODY);
    let h = media_headers(
        ctx.upload_auth(&sha, now, true),
        "image/png",
        PNG_BODY.len(),
        Some(&sha),
    );

    let (status, json, _headers) = ctx.put(PNG_BODY, h, now).await;
    assert_eq!(status, StatusCode::OK);

    // Descriptor shape (§5.9): url, sha256, size, type, uploaded.
    assert_eq!(json["sha256"], sha);
    assert_eq!(json["size"], PNG_BODY.len());
    assert_eq!(json["type"], "image/png");
    assert!(json["uploaded"].as_i64().is_some());
    let url = json["url"].as_str().unwrap();
    assert!(
        url.starts_with(&format!("{PUB_BASE}/media/{sha}.")),
        "url={url}"
    );
    assert!(url.ends_with(".png"), "ext from sniffed mime, url={url}");
}

#[tokio::test]
async fn put_duplicate_hash_is_idempotent_no_second_blob() {
    let ctx = Ctx::new();
    let now = ctx.now();
    let sha = sha256_hex(PNG_BODY);

    let h = media_headers(
        ctx.upload_auth(&sha, now, true),
        "image/png",
        PNG_BODY.len(),
        Some(&sha),
    );
    let (s1, j1, _) = ctx.put(PNG_BODY, h, now).await;
    assert_eq!(s1, StatusCode::OK);

    // A second, independently-signed auth event for the SAME body hash must
    // resolve to the existing blob — no rewrite, faithful 200.
    let keys2 = Keys::generate();
    let h2 = media_headers(
        blossom_header(&keys2, "upload", Some(&sha), now, now + 3600, true),
        "image/png",
        PNG_BODY.len(),
        Some(&sha),
    );
    let (s2, j2, _) = ctx.put(PNG_BODY, h2, now).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(j2["sha256"], sha, "same descriptor sha");
    assert_eq!(j1["sha256"], j2["sha256"]);

    // Exactly one sidecar row for this hash (the CAS key is unique).
    let rec = ctx
        .state
        .store
        .get(&sha)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(rec.size, PNG_BODY.len() as u64);
    // Blob file present exactly once.
    assert!(ctx.state.store.blob_exists(&sha, "png").await.unwrap());
}

// ===========================================================================
// SHA verification (tamper / length-extension guards)
// ===========================================================================

#[tokio::test]
async fn put_wrong_x_tag_is_bad_request() {
    let ctx = Ctx::new();
    let now = ctx.now();
    let wrong = "0".repeat(64); // not the body sha
    let h = media_headers(
        ctx.upload_auth(&wrong, now, true),
        "image/png",
        PNG_BODY.len(),
        None,
    );
    let (status, json, _) = ctx.put(PNG_BODY, h, now).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "hash mismatch"); // x≠body sha ⇒ tamper guard (400)
}

#[tokio::test]
async fn put_tampered_x_sha256_header_vs_x_tag_is_bad_request() {
    let ctx = Ctx::new();
    let now = ctx.now();
    let real = sha256_hex(PNG_BODY);
    // x tag is correct (will match body), but X-SHA-256 header is wrong.
    let tampered = "f".repeat(64);
    let h = media_headers(
        ctx.upload_auth(&real, now, true),
        "image/png",
        PNG_BODY.len(),
        Some(&tampered),
    );
    let (status, _json, _) = ctx.put(PNG_BODY, h, now).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// Auth rejection
// ===========================================================================

#[tokio::test]
async fn put_missing_auth_is_unauthorized() {
    let ctx = Ctx::new();
    let now = ctx.now();
    let h = media_headers(HeaderMap::new(), "image/png", PNG_BODY.len(), None);
    let (status, json, _) = ctx.put(PNG_BODY, h, now).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "unauthorized");
}

#[tokio::test]
async fn put_expired_auth_is_unauthorized() {
    let ctx = Ctx::new();
    let now = ctx.now();
    let sha = sha256_hex(PNG_BODY);
    // expiration is in the past relative to `now`.
    let h = media_headers(
        blossom_header(&ctx.keys, "upload", Some(&sha), now, now, true),
        "image/png",
        PNG_BODY.len(),
        Some(&sha),
    );
    let (status, _, _) = ctx.put(PNG_BODY, h, now).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn put_stale_created_at_is_unauthorized() {
    let ctx = Ctx::new();
    let now = ctx.now();
    let sha = sha256_hex(PNG_BODY);
    // created_at far outside the max_age window.
    let h = media_headers(
        blossom_header(
            &ctx.keys,
            "upload",
            Some(&sha),
            now - 10_000,
            now + 3600,
            true,
        ),
        "image/png",
        PNG_BODY.len(),
        Some(&sha),
    );
    let (status, _, _) = ctx.put(PNG_BODY, h, now).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn put_wrong_verb_is_unauthorized() {
    let ctx = Ctx::new();
    let now = ctx.now();
    let sha = sha256_hex(PNG_BODY);
    // t=get (not upload) ⇒ the verb check fails.
    let h = media_headers(
        blossom_header(&ctx.keys, "get", Some(&sha), now, now + 3600, true),
        "image/png",
        PNG_BODY.len(),
        Some(&sha),
    );
    let (status, _, _) = ctx.put(PNG_BODY, h, now).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn put_bad_signature_is_unauthorized() {
    let ctx = Ctx::new();
    let now = ctx.now();
    let mut h = HeaderMap::new();
    // Garbage token — not decodable / not a valid event.
    h.insert(
        "authorization",
        HeaderValue::from_static("Nostr !!!notbase64!!!"),
    );
    h = media_headers(h, "image/png", PNG_BODY.len(), None);
    let (status, _, _) = ctx.put(PNG_BODY, h, now).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn put_server_tag_mismatch_is_unauthorized() {
    let ctx = Ctx::new();
    let now = ctx.now();
    let sha = sha256_hex(PNG_BODY);
    // server tag names a different host than the configured relay authority.
    let mut b = EventBuilder::new(Kind::from(KIND_BLOSSOM), "x")
        .custom_created_at(Timestamp::from(now))
        .tag(Tag::parse(["t", "upload"]).unwrap())
        .tag(Tag::parse(["expiration", &(now + 3600).to_string()]).unwrap())
        .tag(Tag::parse(["x", &sha]).unwrap())
        .tag(Tag::parse(["server", "evil.example:443"]).unwrap());
    let _ = &mut b;
    let ev = b.sign_with_keys(&ctx.keys).unwrap();
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ev.as_json().as_bytes());
    let mut h = HeaderMap::new();
    h.insert(
        "authorization",
        HeaderValue::from_str(&format!("Nostr {token}")).unwrap(),
    );
    h = media_headers(h, "image/png", PNG_BODY.len(), Some(&sha));
    let (status, _, _) = ctx.put(PNG_BODY, h, now).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ===========================================================================
// Cap + type rejection
// ===========================================================================

#[tokio::test]
async fn put_oversize_image_is_payload_too_large() {
    let mut cfg = base_config();
    // Per-type cap below the 4 KiB sniff threshold; max_video_bytes stays large
    // so the Content-Length fast-fail never triggers — this proves the
    // *per-type* cap is enforced during streaming once the type is sniffed.
    cfg.max_image_bytes = 5000;
    let ctx = Ctx::with_config(cfg);
    let now = ctx.now();
    let mut body = vec![0u8; 6000];
    body[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
    let sha = sha256_hex(&body);
    let h = media_headers(
        ctx.upload_auth(&sha, now, true),
        "image/png",
        body.len(),
        Some(&sha),
    );
    let (status, _, _) = ctx.put(&body, h, now).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn put_blocked_mime_generic_file_is_unsupported() {
    let ctx = Ctx::new();
    let now = ctx.now();
    // Bytes that sniff as no media type, declared as an active-content MIME.
    let body = b"<html><script>x</script></html>";
    let sha = sha256_hex(body);
    let h = media_headers(
        ctx.upload_auth(&sha, now, true),
        "text/html",
        body.len(),
        Some(&sha),
    );
    let (status, json, _) = ctx.put(body, h, now).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "unsupported file type");
}

// ===========================================================================
// Membership + replay
// ===========================================================================

#[tokio::test]
async fn put_non_member_with_require_membership_is_forbidden() {
    struct DenyAll;
    #[async_trait::async_trait]
    impl MediaMembership for DenyAll {
        async fn is_community_member(&self, _: &str) -> bool {
            false
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        MediaStore::open(&dir.path().join("m.db"), &dir.path().join("b"), FINGERPRINT).unwrap(),
    );
    let mut cfg = base_config();
    cfg.require_membership = true;
    let state = MediaUploadState::new(
        store,
        Arc::new(cfg),
        Arc::new(MediaReplayCache::default()),
        Arc::new(DenyAll) as Arc<dyn MediaMembership>,
    );
    let keys = Keys::generate();
    let now = 1_700_000_000u64;
    let sha = sha256_hex(PNG_BODY);
    let h = media_headers(
        blossom_header(&keys, "upload", Some(&sha), now, now + 3600, true),
        "image/png",
        PNG_BODY.len(),
        Some(&sha),
    );
    let resp = handle_upload(&state, &h, Body::from(PNG_BODY.to_vec()), now).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"], "not a community member");
}

#[tokio::test]
async fn put_replayed_auth_event_is_unauthorized_second_time() {
    let ctx = Ctx::new();
    let now = ctx.now();
    let sha = sha256_hex(PNG_BODY);
    let h = media_headers(
        ctx.upload_auth(&sha, now, true),
        "image/png",
        PNG_BODY.len(),
        Some(&sha),
    );

    // First use of this auth event id ⇒ success (and records the id).
    let (s1, _, _) = ctx.put(PNG_BODY, h.clone(), now).await;
    assert_eq!(s1, StatusCode::OK);

    // Reuse the SAME auth event (same event id) ⇒ replay ⇒ 401.
    let (s2, json, _) = ctx.put(PNG_BODY, h, now).await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "unauthorized");
}

// expose Kind for the header builder
use nostr::Kind;

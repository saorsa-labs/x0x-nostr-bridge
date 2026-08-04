//! M1b Blossom media-serve wire-level regressions (WP-MS).
//!
//! Drives the composable serve service `MediaServe::serve` directly against a
//! real on-disk `MediaStore`, asserting the full GET/HEAD/range/ETag/missing
//! contract (§6). Every response is a genuine HTTP `Response`; the streaming
// body is collected and compared byte-for-byte for range correctness.
//!
//! The central security property under test is **indistinguishability**: a
//! missing sidecar row and a missing blob file must produce byte-identical 404
//! responses, and auth/membership failures happen before the lookup so they
//! cannot reveal existence.
//!
//! Run: `cargo test -p x0x-nostr-bridge --test m1b_media_serve -- --nocapture`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::to_bytes;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use base64::Engine as _;
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use x0x_nostr_bridge::media::serve::{
    MediaServe, MemberCheck, NoopMemberCheck, NoopReplayGuard, ServeConfig,
};
use x0x_nostr_bridge::media::store::{BlobDisposition, MediaStore, NewMediaRecord};

const RELAY_AUTHORITY: &str = "127.0.0.1:3000";
const FINGERPRINT: &str = "m1b-serve-fp";
const KIND_BLOSSOM: u16 = 24242;
const NOW: u64 = 1_700_000_000;

// A repeatable 256-byte payload (deterministic so range offsets are stable).
fn payload() -> Vec<u8> {
    (0u32..64).flat_map(|i| i.to_le_bytes()).collect()
}

struct Serve {
    _dir: TempDir,
    store: Arc<MediaStore>,
    serve: MediaServe,
    keys: Keys,
}

impl Serve {
    fn open(config: ServeConfig) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            MediaStore::open(
                &dir.path().join("media.db"),
                &dir.path().join("blobs"),
                FINGERPRINT,
            )
            .unwrap(),
        );
        let serve = MediaServe::new(Arc::clone(&store), config);
        Self {
            _dir: dir,
            store,
            serve,
            keys: Keys::generate(),
        }
    }

    fn default() -> Self {
        Self::open(ServeConfig {
            require_get_auth: false,
            require_membership: false,
            get_auth_max_age_secs: 3600,
            relay_authority: RELAY_AUTHORITY.to_string(),
            cache_max_age_secs: 31_536_000,
        })
    }

    /// Seed a blob and return its sha256 + the bytes.
    async fn seed(&self, bytes: &[u8], disposition: BlobDisposition) -> String {
        let sha = sha256_hex(bytes);
        let staging = self.store.staging_path();
        tokio::fs::write(&staging, bytes).await.unwrap();
        let rec = NewMediaRecord {
            mime_type: "image/png".to_string(),
            ext: "png".to_string(),
            uploaded_at: NOW as i64,
            uploader_pubkey: "aa".repeat(32),
            dim: None,
            blurhash: None,
            thumb_sha: None,
            duration_secs: None,
            disposition,
        };
        let out = self.store.install(&sha, rec, staging).await.unwrap();
        assert!(matches!(
            out,
            x0x_nostr_bridge::media::store::InstallOutcome::Installed(_)
        ));
        sha
    }

    async fn get(&self, path: &str, headers: HeaderMap) -> Response {
        self.serve
            .serve(
                Method::GET,
                path,
                false,
                &headers,
                NOW,
                &NoopReplayGuard,
                &NoopMemberCheck,
            )
            .await
    }

    async fn head(&self, path: &str, headers: HeaderMap) -> Response {
        self.serve
            .serve(
                Method::HEAD,
                path,
                false,
                &headers,
                NOW,
                &NoopReplayGuard,
                &NoopMemberCheck,
            )
            .await
    }
}

use axum::response::Response;

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn get_auth(keys: &Keys, sha: &str, server_scoped: bool) -> HeaderMap {
    let mut b = EventBuilder::new(Kind::from(KIND_BLOSSOM), "get")
        .custom_created_at(Timestamp::from(NOW))
        .tag(Tag::parse(["t", "get"]).unwrap())
        .tag(Tag::parse(["expiration", &(NOW + 3600).to_string()]).unwrap());
    if server_scoped {
        b = b.tag(Tag::parse(["server", RELAY_AUTHORITY]).unwrap());
    } else {
        b = b.tag(Tag::parse(["x", sha]).unwrap());
    }
    let ev = b.sign_with_keys(keys).unwrap();
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ev.as_json().as_bytes());
    let mut h = HeaderMap::new();
    h.insert(
        "authorization",
        HeaderValue::from_str(&format!("Nostr {token}")).unwrap(),
    );
    h
}

async fn body_bytes(resp: Response) -> Vec<u8> {
    to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap()
        .to_vec()
}
/// String view of a required response header (fails the test if absent).
fn hv<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .expect("header present")
}

// ===========================================================================
// Full GET / HEAD
// ===========================================================================

#[tokio::test]
async fn full_get_returns_immutable_cacheable_stream_with_exact_bytes() {
    let s = Serve::default();
    let bytes = payload();
    let sha = s.seed(&bytes, BlobDisposition::Inline).await;

    let resp = s.get(&format!("{sha}.png"), HeaderMap::new()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hv(resp.headers(), "content-type"), "image/png");
    assert_eq!(hv(resp.headers(), "accept-ranges"), "bytes");
    assert_eq!(
        hv(resp.headers(), "cache-control"),
        "public, max-age=31536000, immutable"
    );
    assert_eq!(
        hv(resp.headers(), "content-length"),
        bytes.len().to_string().as_str()
    );
    assert_eq!(hv(resp.headers(), "etag"), format!("\"{sha}\"").as_str());
    assert_eq!(hv(resp.headers(), "content-disposition"), "inline");

    assert_eq!(body_bytes(resp).await, bytes);
}

#[tokio::test]
async fn head_returns_same_headers_with_empty_body() {
    let s = Serve::default();
    let bytes = payload();
    let sha = s.seed(&bytes, BlobDisposition::Inline).await;

    let resp = s.head(&format!("{sha}.png"), HeaderMap::new()).await;
    assert_eq!(
        hv(resp.headers(), "content-length"),
        bytes.len().to_string().as_str()
    );
    assert_eq!(hv(resp.headers(), "etag"), format!("\"{sha}\"").as_str());
    assert!(body_bytes(resp).await.is_empty(), "HEAD body must be empty");
}

// ===========================================================================
// Range
// ===========================================================================

#[tokio::test]
async fn byte_range_returns_partial_content_and_slice() {
    let s = Serve::default();
    let bytes = payload();
    let sha = s.seed(&bytes, BlobDisposition::Inline).await;
    let mut h = HeaderMap::new();
    h.insert("range", HeaderValue::from_static("bytes=10-19"));

    let resp = s.get(&format!("{sha}.png"), h).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        hv(resp.headers(), "content-range"),
        format!("bytes 10-19/{}", bytes.len())
    );
    assert_eq!(hv(resp.headers(), "content-length"), "10");
    assert_eq!(body_bytes(resp).await, &bytes[10..20]);
}

#[tokio::test]
async fn suffix_range_returns_last_n_bytes() {
    let s = Serve::default();
    let bytes = payload();
    let sha = s.seed(&bytes, BlobDisposition::Inline).await;
    let mut h = HeaderMap::new();
    h.insert("range", HeaderValue::from_static("bytes=-8"));

    let resp = s.get(&format!("{sha}.png"), h).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(body_bytes(resp).await, &bytes[bytes.len() - 8..]);
}

#[tokio::test]
async fn malformed_range_is_not_satisfiable() {
    let s = Serve::default();
    let bytes = payload();
    let sha = s.seed(&bytes, BlobDisposition::Inline).await;
    let mut h = HeaderMap::new();
    // start beyond the end of the file.
    h.insert(
        "range",
        HeaderValue::from_str(&format!("bytes={}-", bytes.len() + 10)).unwrap(),
    );

    let resp = s.get(&format!("{sha}.png"), h).await;
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        hv(resp.headers(), "content-range"),
        format!("bytes */{}", bytes.len())
    );
}

// ===========================================================================
// Conditional request (ETag)
// ===========================================================================

#[tokio::test]
async fn matching_etag_returns_not_modified() {
    let s = Serve::default();
    let bytes = payload();
    let sha = s.seed(&bytes, BlobDisposition::Inline).await;
    let mut h = HeaderMap::new();
    h.insert(
        "if-none-match",
        HeaderValue::from_str(&format!("\"{sha}\"")).unwrap(),
    );

    let resp = s.get(&format!("{sha}.png"), h).await;
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    assert!(body_bytes(resp).await.is_empty());
}

// ===========================================================================
// Missing indistinguishability (the core hiding contract)
// ===========================================================================

#[tokio::test]
async fn missing_row_and_missing_file_are_indistinguishable_404() {
    let s = Serve::default();
    let bytes = payload();

    // (a) No sidecar row at all — a sha that was never installed.
    let ghost = "c".repeat(64);
    let resp_no_row = s.get(&format!("{ghost}.png"), HeaderMap::new()).await;
    assert_eq!(resp_no_row.status(), StatusCode::NOT_FOUND);
    let body_no_row = body_bytes(resp_no_row).await;

    // (b) Sidecar row exists but the blob file was removed (orphan).
    let sha = s.seed(&bytes, BlobDisposition::Inline).await;
    let path = s.store.blob_path(&sha, "png").unwrap();
    tokio::fs::remove_file(&path).await.unwrap();
    let resp_no_file = s.get(&format!("{sha}.png"), HeaderMap::new()).await;
    assert_eq!(resp_no_file.status(), StatusCode::NOT_FOUND);
    let body_no_file = body_bytes(resp_no_file).await;

    // Byte-identical responses: an attacker cannot tell row-missing from file-missing.
    assert_eq!(
        body_no_row, body_no_file,
        "404 bodies must be indistinguishable"
    );
}

#[tokio::test]
async fn unsafe_path_shapes_are_hidden_as_404() {
    let s = Serve::default();
    let _ = s.seed(&payload(), BlobDisposition::Inline).await;

    for bad in [
        "../etc/passwd",
        "noext",
        "ZZ.not-hex",
        ".png",
        "abcd.png",
        "x.png",
    ] {
        let resp = s.get(bad, HeaderMap::new()).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "path {bad:?} must be 404 not 400"
        );
    }
}

// ===========================================================================
// Disposition
// ===========================================================================

#[tokio::test]
async fn download_query_forces_attachment_disposition() {
    let s = Serve::default();
    let bytes = payload();
    let sha = s.seed(&bytes, BlobDisposition::Inline).await;

    let resp = s
        .serve
        .serve(
            Method::GET,
            &format!("{sha}.png"),
            true,
            &HeaderMap::new(),
            NOW,
            &NoopReplayGuard,
            &NoopMemberCheck,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cd = resp
        .headers()
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        cd.starts_with("attachment"),
        "download=1 ⇒ attachment, got {cd}"
    );
    assert!(cd.contains(&sha));
}

#[tokio::test]
async fn attachment_sidecar_disposition_is_honored_without_query() {
    let s = Serve::default();
    let bytes = payload();
    let sha = s.seed(&bytes, BlobDisposition::Attachment).await;

    let resp = s.get(&format!("{sha}.png"), HeaderMap::new()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cd = resp
        .headers()
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        cd.starts_with("attachment"),
        "sidecar attachment ⇒ attachment, got {cd}"
    );
}

// ===========================================================================
// Auth + membership gates (applied before the lookup)
// ===========================================================================

struct DenyMember;
#[async_trait]
impl MemberCheck for DenyMember {
    async fn is_community_member(&self, _: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
}

fn authed_serve() -> Serve {
    Serve::open(ServeConfig {
        require_get_auth: true,
        require_membership: true,
        get_auth_max_age_secs: 3600,
        relay_authority: RELAY_AUTHORITY.to_string(),
        cache_max_age_secs: 31_536_000,
    })
}

#[tokio::test]
async fn get_without_auth_when_required_is_unauthorized() {
    let s = authed_serve();
    let sha = s.seed(&payload(), BlobDisposition::Inline).await;
    let resp = s.get(&format!("{sha}.png"), HeaderMap::new()).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_server_scoped_auth_and_member_returns_200() {
    let s = authed_serve();
    let bytes = payload();
    let sha = s.seed(&bytes, BlobDisposition::Inline).await;
    let h = get_auth(&s.keys, &sha, true); // server-scoped
    let resp = s
        .serve
        .serve(
            Method::GET,
            &format!("{sha}.png"),
            false,
            &h,
            NOW,
            &NoopReplayGuard,
            &NoopMemberCheck, // member ⇒ admitted
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, bytes);
}

#[tokio::test]
async fn get_non_member_when_membership_required_is_forbidden() {
    let s = authed_serve();
    let sha = s.seed(&payload(), BlobDisposition::Inline).await;
    let h = get_auth(&s.keys, &sha, true);
    let resp = s
        .serve
        .serve(
            Method::GET,
            &format!("{sha}.png"),
            false,
            &h,
            NOW,
            &NoopReplayGuard,
            &DenyMember,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn auth_failure_cannot_reveal_existence_of_missing_blob() {
    let s = authed_serve();
    // No blob seeded; an unauthenticated request must still be 401 (not 404),
    // proving the gate runs before the lookup.
    let ghost = "d".repeat(64);
    let resp = s.get(&format!("{ghost}.png"), HeaderMap::new()).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "auth gate precedes lookup"
    );
}

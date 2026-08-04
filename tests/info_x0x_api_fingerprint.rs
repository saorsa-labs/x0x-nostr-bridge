//! GET /info `x0x_api_fingerprint` conformance.
//!
//! Contract (locked with BridgeConformance / Main): the NIP-11 /info document
//! always carries a top-level `x0x_api_fingerprint` — the lowercase-hex SHA-256
//! of the daemon's NORMALIZED REST base URL (the value `config::resolve_api`
//! resolved, normalization via `transport::normalize_base_url`). The raw base,
//! the bearer token, and any filesystem path NEVER appear in the document —
//! only the fingerprint. When no base was resolved the value is `""` (key still
//! present, so local stacks can distinguish "unbound").
//!
//! These are new-feature tests: they compile only once Settings carries the
//! `x0x_api_fingerprint` field and `config::api_fingerprint` exists
//! (BridgeConformance-owned src/ change).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use nostr::{Event, Filter};
use serde_json::Value;
use sha2::{Digest, Sha256};

use x0x_nostr_bridge::config;
use x0x_nostr_bridge::engine_api::HistoryEngine;
use x0x_nostr_bridge::engine_api::StubEngine;
use x0x_nostr_bridge::relay::{router, AppState};
use x0x_nostr_bridge::relay_identity::RelayIdentity;
use x0x_nostr_bridge::settings::Settings;
use x0x_nostr_bridge::store::{EventStore, InsertOutcome};
use x0x_nostr_bridge::transport::{self, GossipMessage, GossipTransport};

// ---- minimal fakes ( /info touches only settings + identity) --------------

struct FakeStore;
#[async_trait]
impl EventStore for FakeStore {
    async fn insert(&self, _ev: &Event) -> anyhow::Result<InsertOutcome> {
        Ok(InsertOutcome::Inserted)
    }
    async fn insert_with_emits(
        &self,
        _ev: &Event,
    ) -> anyhow::Result<(InsertOutcome, Vec<x0x_nostr_bridge::engine_api::Emit>)> {
        Ok((InsertOutcome::Inserted, Vec::new()))
    }
    async fn query(&self, _f: &Filter) -> anyhow::Result<Vec<Event>> {
        Ok(Vec::new())
    }
    async fn known_channels(&self) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }
}

struct FakeTransport;
#[async_trait]
impl GossipTransport for FakeTransport {
    async fn ensure_topic(&self, _t: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn publish(&self, _t: &str, _p: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
    fn inbox(&self) -> tokio::sync::mpsc::Receiver<GossipMessage> {
        tokio::sync::mpsc::channel(1).1
    }
}

async fn spawn(settings: Settings) -> SocketAddr {
    let state = Arc::new(AppState::new(
        Arc::new(FakeStore),
        Arc::new(FakeTransport),
        Arc::new(StubEngine::new()) as Arc<dyn HistoryEngine>,
        Arc::new(RelayIdentity::ephemeral()),
        Arc::new(settings),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    addr
}

async fn info(addr: SocketAddr) -> Value {
    reqwest::Client::new()
        .get(format!("http://{addr}/info"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()
}

/// Lowercase-hex SHA-256 of a string's UTF-8 bytes (the fingerprint recipe).
fn hex_sha256(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

// ---- configured: exact normalized fingerprint, no raw leak ----------------

#[tokio::test]
async fn info_surfaces_normalized_x0x_api_fingerprint_without_raw_leak() {
    let raw = "127.0.0.1:12700";
    let normalized = transport::normalize_base_url(raw); // → http://127.0.0.1:12700
    assert_eq!(normalized, "http://127.0.0.1:12700");
    let expected = hex_sha256(&normalized);

    // The helper BridgeConformance adds must agree with the raw recipe.
    assert_eq!(config::api_fingerprint(&normalized), expected);

    let settings = Settings {
        x0x_api_fingerprint: expected.clone(),
        ..Default::default()
    };
    let body = info(spawn(settings).await).await;

    assert_eq!(
        body["x0x_api_fingerprint"].as_str(),
        Some(expected.as_str()),
        "/info must surface the exact configured fingerprint"
    );

    // Only the fingerprint is exposed — never the raw base, token, or a path.
    let doc = body.to_string();
    assert!(
        !doc.contains(raw) && !doc.contains("127.0.0.1"),
        "raw daemon base must not leak into /info (only its fingerprint): {doc}"
    );
    assert!(
        !doc.contains(".db") && !doc.contains("/Users/") && !doc.contains("token"),
        "/info must not leak filesystem paths or tokens: {doc}"
    );
}

// ---- normalization invariance: distinct raw forms fingerprint identically --

#[tokio::test]
async fn x0x_api_fingerprint_is_normalization_invariant() {
    let bare = config::api_fingerprint(&transport::normalize_base_url("127.0.0.1:12700"));
    let scheme_slash =
        config::api_fingerprint(&transport::normalize_base_url("http://127.0.0.1:12700/"));
    let canonical =
        config::api_fingerprint(&transport::normalize_base_url("http://127.0.0.1:12700"));
    assert_eq!(bare, canonical, "bare host:port must normalize to http://");
    assert_eq!(
        scheme_slash, canonical,
        "trailing slash must be stripped before fingerprinting"
    );
    assert_ne!(
        bare,
        config::api_fingerprint(&transport::normalize_base_url("127.0.0.1:9999")),
        "different daemons must fingerprint differently"
    );
}

// ---- default: key present + empty, leaks nothing --------------------------

#[tokio::test]
async fn info_default_fingerprint_empty_and_leaks_nothing() {
    let body = info(spawn(Settings::default()).await).await;
    // Key is always present; empty string when no daemon base was resolved.
    assert_eq!(
        body["x0x_api_fingerprint"].as_str(),
        Some(""),
        "x0x_api_fingerprint must be present and empty by default (unbound)"
    );
    let doc = body.to_string();
    assert!(
        !doc.contains("127.0.0.1") && !doc.contains(".db") && !doc.contains("/Users/"),
        "default /info must not leak a daemon base, db path, or data-dir: {doc}"
    );
}

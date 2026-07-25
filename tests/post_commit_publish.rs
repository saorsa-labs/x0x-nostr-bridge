//! WP5 property 1 — accepted local events publish to gossip POST-COMMIT.
//!
//! The HTTP `/events` door (`http::post_events`) must publish an accepted
//! event to its gossip topics only AFTER the SQLite commit has succeeded, so
//! a crash between the two can never leave the mesh holding an event the
//! local store doesn't. These tests drive the real handler against a real
//! `HistoryStore` (file-backed SQLite) with a recording `GossipTransport`
//! that, at publish time, queries the store: the row MUST already exist.
//!
//! The second test pins the failure semantics: a transport whose publish
//! fails must NOT roll back the commit (publish is best-effort) — the event
//! stays stored and the client still gets `accepted: true`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, TagKind};
use parking_lot::Mutex;
use tokio::sync::mpsc;

use x0x_nostr_bridge::history::types::FilterSpec;
use x0x_nostr_bridge::history::HistoryStore;
use x0x_nostr_bridge::history_adapter::{HistoryStoreEngine, HistoryStoreEventStore};
use x0x_nostr_bridge::http::post_events;
use x0x_nostr_bridge::relay::AppState;
use x0x_nostr_bridge::relay_identity::RelayIdentity;
use x0x_nostr_bridge::settings::Settings;
use x0x_nostr_bridge::transport::{GossipMessage, GossipTransport};

/// What the transport observed for one published payload.
#[derive(Debug)]
struct PublishObservation {
    topic: String,
    event_id: String,
    /// True when the event row was already committed to SQLite at the moment
    /// `publish` was called — the post-commit ordering assertion.
    committed_at_publish: bool,
}

/// Recording transport. On `publish` it decodes the event and queries the
/// REAL store for the event id, capturing whether the commit had landed.
struct OrderingProbeTransport {
    store: Arc<HistoryStore>,
    observations: Mutex<Vec<PublishObservation>>,
    /// When true, every `publish` errors — the failure-semantics probe.
    fail_publish: bool,
}

#[async_trait::async_trait]
impl GossipTransport for OrderingProbeTransport {
    async fn ensure_topic(&self, _topic: &str) -> anyhow::Result<()> {
        Ok(())
    }

    async fn publish(&self, topic: &str, payload: &[u8]) -> anyhow::Result<()> {
        let ev: nostr::Event = serde_json::from_slice(payload).expect("published payload is JSON");
        let event_id = ev.id.to_hex();
        let spec = FilterSpec {
            ids: vec![event_id.clone()],
            ..Default::default()
        };
        let committed_at_publish = !self.store.query(&spec, 1, 0).await?.is_empty();
        self.observations.lock().push(PublishObservation {
            topic: topic.to_string(),
            event_id,
            committed_at_publish,
        });
        if self.fail_publish {
            anyhow::bail!("probe: forced publish failure");
        }
        Ok(())
    }

    fn inbox(&self) -> mpsc::Receiver<GossipMessage> {
        // Take-once semantics don't matter here; the handler never reads it.
        let (_tx, rx) = mpsc::channel(1);
        rx
    }
}

/// Wire a real AppState (file-backed HistoryStore behind both lanes) with the
/// probe transport, mirroring `main.rs`'s construction.
fn make_state(
    transport: Arc<OrderingProbeTransport>,
    history: &Arc<HistoryStore>,
    tmp: &tempfile::TempDir,
) -> Arc<AppState> {
    let engine = Arc::new(HistoryStoreEngine::new(Arc::clone(history), vec![]));
    let store = Arc::new(HistoryStoreEventStore::new(Arc::clone(history), vec![]));
    let identity = Arc::new(
        RelayIdentity::load_or_create(&tmp.path().join("relay.key")).expect("relay identity"),
    );
    Arc::new(AppState::new(
        store,
        transport,
        engine,
        identity,
        Arc::new(Settings::default()),
    ))
}

/// POST one signed event through the real handler and return the response's
/// `(status, body_json)`.
async fn post_one(
    state: &Arc<AppState>,
    ev: &nostr::Event,
    pubkey_hex: &str,
) -> (u16, serde_json::Value) {
    let mut headers = HeaderMap::new();
    headers.insert("x-pubkey", pubkey_hex.parse().expect("header value"));
    let body = Bytes::from(ev.as_json());
    let resp = post_events(State(Arc::clone(state)), headers, body).await;
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("response body");
    let json = serde_json::from_slice(&bytes).expect("response JSON");
    (status, json)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_event_publishes_after_sqlite_commit() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let history = Arc::new(
        HistoryStore::open(&tmp.path().join("bridge.db"), "wp5-p1-ordering").expect("store"),
    );
    let transport = Arc::new(OrderingProbeTransport {
        store: Arc::clone(&history),
        observations: Mutex::new(Vec::new()),
        fail_publish: false,
    });
    let state = make_state(Arc::clone(&transport), &history, &tmp);

    let keys = Keys::generate();
    let channel = "wp5-p1-channel";
    let ev = EventBuilder::new(Kind::from(9u16), "post-commit ordering probe")
        .tag(Tag::custom(TagKind::custom("h"), [channel]))
        .sign_with_keys(&keys)
        .expect("sign");
    let ev_id = ev.id.to_hex();

    let (status, body) = post_one(&state, &ev, &keys.public_key().to_hex()).await;
    assert_eq!(status, 200, "handler status: {body}");
    assert_eq!(body["accepted"], true, "event must be accepted: {body}");
    assert_eq!(body["event_id"], serde_json::Value::from(ev_id.as_str()));

    // The event is on exactly one topic (its #h channel topic)...
    let observations = transport.observations.lock();
    assert_eq!(
        observations.len(),
        1,
        "expected exactly one gossip publish, got {observations:?}"
    );
    let obs = &observations[0];
    assert_eq!(obs.event_id, ev_id);
    assert_eq!(obs.topic, format!("buzz.v1.ch.{channel}"));
    // ...and the row existed in SQLite BEFORE the publish fired.
    assert!(
        obs.committed_at_publish,
        "gossip publish fired BEFORE the SQLite commit landed: {obs:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_publish_does_not_roll_back_the_commit() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let history = Arc::new(
        HistoryStore::open(&tmp.path().join("bridge.db"), "wp5-p1-failure").expect("store"),
    );
    let transport = Arc::new(OrderingProbeTransport {
        store: Arc::clone(&history),
        observations: Mutex::new(Vec::new()),
        fail_publish: true,
    });
    let state = make_state(Arc::clone(&transport), &history, &tmp);

    let keys = Keys::generate();
    let ev = EventBuilder::new(Kind::from(9u16), "publish-failure atomicity probe")
        .tag(Tag::custom(TagKind::custom("h"), ["wp5-p1-failchan"]))
        .sign_with_keys(&keys)
        .expect("sign");
    let ev_id = ev.id.to_hex();

    let (status, body) = post_one(&state, &ev, &keys.public_key().to_hex()).await;
    // Publish is best-effort: the client still gets accepted:true...
    assert_eq!(status, 200, "handler status: {body}");
    assert_eq!(
        body["accepted"], true,
        "commit must survive publish failure: {body}"
    );

    // ...the publish was still attempted post-commit...
    {
        let observations = transport.observations.lock();
        assert_eq!(
            observations.len(),
            1,
            "publish must be attempted: {observations:?}"
        );
        assert!(
            observations[0].committed_at_publish,
            "publish attempt must follow the commit: {:?}",
            observations[0]
        );
    }

    // ...and the event is durably stored despite the fabric never seeing it.
    let spec = FilterSpec {
        ids: vec![ev_id.clone()],
        ..Default::default()
    };
    let rows = history.query(&spec, 1, 0).await.expect("query");
    assert_eq!(rows.len(), 1, "committed row must survive publish failure");
}

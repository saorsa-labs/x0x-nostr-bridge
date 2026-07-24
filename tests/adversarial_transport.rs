//! Adversarial transport/ingest tests for x0x-nostr-bridge.
//!
//! One test per red-team finding. Each is written to FAIL against the
//! unfixed (spike) code and PASS after the fix; the report captures both.
//!
//! Findings covered (owner: TransportAgent / main.rs):
//!  1. C1/GOSSIP-EPHEMERAL-STORED  — ephemeral + AUTH kinds must not be stored.
//!  2. GOSSIP-TOPIC-BINDING        — event delivered on a non-matching topic dropped.
//!  3. GOSSIP-OVERSIZE-PREVERIFY   — oversized SSE payload skipped, session survives.
//!  4. C2 SSE-reconnect subscription multiplication.
//!  5. C3 ensure_topic check-then-act race.
//!  6. D1 X0X_API env not normalised.
//!  7. BRIDGE-BIND-EXPOSURE loopback detection.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine as _;
use nostr::{Event, EventBuilder, JsonUtil, Keys, Kind, RelayMessage, Tag, TagKind};
use parking_lot::Mutex;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::timeout;

use x0x_nostr_bridge::config;
use x0x_nostr_bridge::ingest;
use x0x_nostr_bridge::proto;
use x0x_nostr_bridge::relay::AppState;
use x0x_nostr_bridge::store::{EventStore, SqliteStore};
use x0x_nostr_bridge::transport::{GossipMessage, GossipTransport, X0xTransport};

// ===========================================================================
// Shared fakes + helpers
// ===========================================================================

/// Transport that does nothing — ingest_one never publishes on the ingest path.
struct NoopTransport;
#[async_trait]
impl GossipTransport for NoopTransport {
    async fn ensure_topic(&self, _topic: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn publish(&self, _topic: &str, _payload: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
    fn inbox(&self) -> mpsc::Receiver<GossipMessage> {
        let (_tx, rx) = mpsc::channel(1);
        rx
    }
}

/// A fresh AppState backed by a real on-disk SQLite store in a temp dir, a
/// no-op transport, and a real fan-out hub.
fn fresh_state() -> (AppState, TempDir) {
    let dir = tempfile::Builder::new().tempdir().unwrap();
    let store: Arc<dyn EventStore> =
        Arc::new(SqliteStore::open(&dir.path().join("adv.db")).unwrap());
    let state = AppState::with_defaults(store, Arc::new(NoopTransport) as Arc<dyn GossipTransport>);
    (state, dir)
}

fn signed_event(keys: &Keys, kind: u16, content: &str, h_tags: &[&str]) -> Event {
    let mut builder = EventBuilder::new(Kind::from(kind), content);
    for h in h_tags {
        builder = builder.tag(Tag::custom(TagKind::custom("h"), [*h]));
    }
    builder.sign_with_keys(keys).unwrap()
}

fn gossip_msg(topic: &str, ev: &Event) -> GossipMessage {
    GossipMessage {
        topic: topic.to_string(),
        payload: ev.as_json().into_bytes(),
    }
}

/// Bind an axum app on an ephemeral loopback port and return its address.
async fn serve(app: Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// How many stored events were signed by `keys` (author filter always matches).
async fn stored_by(state: &AppState, keys: &Keys) -> Vec<Event> {
    state
        .store
        .query(&nostr::Filter::new().author(keys.public_key()))
        .await
        .unwrap()
}

// ===========================================================================
// 1. C1 / GOSSIP-EPHEMERAL-STORED
// ===========================================================================

#[tokio::test]
async fn c1_ephemeral_and_auth_not_stored_dispatch_correct() {
    let (state, _dir) = fresh_state();
    let keys = Keys::generate();

    // Catch-all-by-author fan-out sub so we can observe dispatch counts.
    let conn = state.hub.next_conn_id();
    let (tx, mut rx) = mpsc::channel::<RelayMessage<'static>>(64);
    assert!(state.hub.register(
        conn,
        "all",
        vec![nostr::Filter::new().author(keys.public_key())],
        tx,
    ));

    // --- ephemeral kind 20001: must NOT be stored, must dispatch once ---
    let ev = signed_event(&keys, 20_001, "ephemeral hello", &[]);
    let topic = proto::topics_for_event(&ev).into_iter().next().unwrap();
    ingest::ingest_one(&state, &gossip_msg(&topic, &ev)).await;

    let stored = stored_by(&state, &keys).await;
    let present = stored.iter().any(|e| e.id == ev.id);
    assert!(!present, "F1: ephemeral event must NOT be stored");

    let dispatched = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("F1: ephemeral must dispatch exactly once")
        .is_some();
    assert!(dispatched, "F1: ephemeral must dispatch once");

    // --- AUTH kind 22242: must NOT be stored, must NOT be dispatched ---
    let auth = signed_event(&keys, proto::AUTH_KIND, "", &[]);
    let atopic = proto::topics_for_event(&auth).into_iter().next().unwrap();
    ingest::ingest_one(&state, &gossip_msg(&atopic, &auth)).await;

    let stored2 = stored_by(&state, &keys).await;
    assert!(
        stored2.iter().all(|e| e.id != auth.id),
        "F1: AUTH kind must NOT be stored from gossip"
    );
    // No further dispatch for the auth kind.
    let extra = timeout(Duration::from_millis(250), rx.recv()).await;
    assert!(
        extra.is_err() || extra.unwrap().is_none(),
        "F1: AUTH kind must not fan out to subscribers"
    );
}

// ===========================================================================
// 2. GOSSIP-TOPIC-BINDING
// ===========================================================================

#[tokio::test]
async fn gossip_topic_binding_drops_mismatched_topics() {
    let keys = Keys::generate();

    // Case A: h=channel-A delivered on channel-b topic -> dropped.
    let (state, _d) = fresh_state();
    let ev = signed_event(&keys, 9, "hi", &["channel-a"]);
    let wrong = proto::channel_topic("channel-b");
    ingest::ingest_one(&state, &gossip_msg(&wrong, &ev)).await;
    assert!(
        stored_by(&state, &keys).await.iter().all(|e| e.id != ev.id),
        "F2: mismatched-topic event must be dropped (not stored)"
    );

    // Case B: same event on channel-a topic -> accepted (stored).
    let (state, _d) = fresh_state();
    let right = proto::channel_topic("channel-a");
    ingest::ingest_one(&state, &gossip_msg(&right, &ev)).await;
    assert!(
        stored_by(&state, &keys).await.iter().any(|e| e.id == ev.id),
        "F2: matched-topic event must be accepted"
    );

    // Case C: no-h event on buzz.v1.global -> accepted.
    let (state, _d) = fresh_state();
    let g = signed_event(&keys, 9, "global hi", &[]);
    ingest::ingest_one(&state, &gossip_msg(proto::GLOBAL_TOPIC, &g)).await;
    assert!(
        stored_by(&state, &keys).await.iter().any(|e| e.id == g.id),
        "F2: no-h event on global topic must be accepted"
    );

    // Case D: no-h event on a ch.* topic -> dropped.
    let (state, _d) = fresh_state();
    ingest::ingest_one(&state, &gossip_msg(&proto::channel_topic("xyz"), &g)).await;
    assert!(
        stored_by(&state, &keys).await.iter().all(|e| e.id != g.id),
        "F2: no-h event on a ch.* topic must be dropped"
    );
}

// ===========================================================================
// 3. GOSSIP-OVERSIZE-PREVERIFY
// ===========================================================================

#[derive(Clone)]
struct OversizeState {
    body: Arc<String>,
    counter: Arc<AtomicUsize>,
}

async fn oversize_events(State(st): State<OversizeState>) -> Response {
    // Serve the canned body once; subsequent reconnects get 503 (paced backoff)
    // so the test observes exactly one delivery window.
    if st.counter.fetch_add(1, Ordering::SeqCst) > 0 {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (
        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
        (*st.body).clone(),
    )
        .into_response()
}

#[tokio::test]
async fn gossip_oversize_preverify_skips_huge_payload() {
    // A ~1MB decoded payload (base64 -> ~1.37MB on the SSE data line), far over
    // proto::MAX_FRAME_BYTES (65536). Followed by a valid tiny event.
    let big = vec![65u8; 1_000_000];
    let big_b64 = base64::engine::general_purpose::STANDARD.encode(&big);
    let oversize_line = format!(
        "data: {{\"type\":\"message\",\"data\":{{\"topic\":\"updates\",\"payload\":\"{big_b64}\"}}}}\n\n"
    );
    let valid_line =
        "data: {\"type\":\"message\",\"data\":{\"topic\":\"updates\",\"payload\":\"aGk=\"}}\n\n";
    let body = Arc::new(format!("{oversize_line}{valid_line}"));

    let app = Router::new()
        .route(
            "/health",
            get(|| async { Json(serde_json::json!({"ok": true})) }),
        )
        .route("/events", get(oversize_events))
        .with_state(OversizeState {
            body,
            counter: Arc::new(AtomicUsize::new(0)),
        });

    let addr = serve(app).await;
    let transport = X0xTransport::connect(&format!("http://{addr}"), "tok")
        .await
        .unwrap();
    let mut rx = transport.inbox();

    // Collect for a bounded window.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    let mut got: Vec<GossipMessage> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, rx.recv()).await {
            Ok(Some(m)) => got.push(m),
            Ok(None) => break, // inbox closed
            Err(_) => break,   // window elapsed
        }
    }

    // The 1MB blob must NEVER reach the inbox; only the valid "hi" may.
    assert_eq!(
        got.len(),
        1,
        "F3: oversize payload must be skipped; got {} messages",
        got.len()
    );
    assert_eq!(got[0].payload, b"hi");
    assert_eq!(got[0].topic, "updates");
}

// ===========================================================================
// 4. C2 — SSE reconnect subscription multiplication
// ===========================================================================

#[derive(Clone)]
struct C2State {
    live: Arc<Mutex<Vec<String>>>,
    posts: Arc<AtomicUsize>,
}

async fn c2_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true}))
}

async fn c2_sub(
    State(st): State<C2State>,
    Json(_b): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let id = format!("s{}", st.posts.fetch_add(1, Ordering::SeqCst));
    st.live.lock().push(id.clone());
    Json(serde_json::json!({"subscription_id": id}))
}

async fn c2_unsub(State(st): State<C2State>, Path(id): Path<String>) -> StatusCode {
    let mut g = st.live.lock();
    if let Some(pos) = g.iter().position(|x| x == &id) {
        g.remove(pos);
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// GET /events always returns 503 -> ConnectFailed -> paced (1s+) backoff, so
/// the supervisor cycles reconnects deterministically and resubscribe_all runs.
async fn c2_events(State(_st): State<C2State>) -> StatusCode {
    StatusCode::SERVICE_UNAVAILABLE
}

#[tokio::test]
async fn c2_reconnect_no_subscription_multiplication() {
    let st = C2State {
        live: Arc::new(Mutex::new(Vec::new())),
        posts: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/health", get(c2_health))
        .route("/subscribe", post(c2_sub))
        .route("/subscribe/:id", delete(c2_unsub))
        .route("/events", get(c2_events))
        .with_state(st.clone());

    let addr = serve(app).await;
    let transport = X0xTransport::connect(&format!("http://{addr}"), "tok")
        .await
        .unwrap();
    transport.ensure_topic("buzz.v1.ch.dup").await.unwrap();

    // Let several paced reconnect cycles elapse (each ~1s of backoff).
    tokio::time::sleep(Duration::from_millis(3200)).await;
    // Drop the handle so the supervisor winds down, then let it settle.
    drop(transport);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let live_count = st.live.lock().len();
    let posts = st.posts.load(Ordering::SeqCst);
    assert_eq!(
        live_count, 1,
        "F4: live sub count must stay 1 across reconnects (got {live_count}, posts={posts})"
    );
    assert!(
        posts >= 2,
        "F4: reconnects must have occurred (posts={posts})"
    );
}

/// Variant that owns the counter so the test can assert it.
#[derive(Clone)]
struct OwnedCount {
    posts: Arc<AtomicUsize>,
}

async fn owned_slow_sub(
    State(c): State<OwnedCount>,
    Json(_b): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    c.posts.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(20)).await;
    Json(serde_json::json!({"subscription_id": "mock"}))
}

#[tokio::test]
async fn c3_concurrent_ensure_topic_posts_exactly_once() {
    let counter = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/health",
            get(|| async { Json(serde_json::json!({"ok": true})) }),
        )
        .route("/subscribe", post(owned_slow_sub))
        .route("/events", get(|| async { StatusCode::SERVICE_UNAVAILABLE }))
        .with_state(OwnedCount {
            posts: Arc::clone(&counter),
        });

    let addr = serve(app).await;
    let transport = Arc::new(
        X0xTransport::connect(&format!("http://{addr}"), "tok")
            .await
            .unwrap(),
    );

    const N: usize = 64;
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let t = Arc::clone(&transport);
        handles.push(tokio::spawn(async move {
            t.ensure_topic("buzz.v1.ch.race").await
        }));
    }
    for h in handles {
        h.await.unwrap().unwrap();
    }

    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "F5: 64 concurrent ensure_topic(same) must produce exactly 1 POST"
    );
}

// ===========================================================================
// 6. D1 — X0X_API env not normalised
// ===========================================================================

#[test]
fn d1_x0x_api_env_normalised_to_scheme() {
    // Bare host:port must gain an http:// scheme, exactly like discover().
    let (api, token) = config::resolve_api_from(
        Some("127.0.0.1:9999".to_string()),
        Some("secret".to_string()),
    )
    .expect("env form must resolve");
    assert_eq!(api, "http://127.0.0.1:9999");
    assert_eq!(token, "secret");

    // Already-schemed input is preserved (no double scheme).
    let (api2, _) = config::resolve_api_from(
        Some("http://host.example:1".to_string()),
        Some("t".to_string()),
    )
    .unwrap();
    assert_eq!(api2, "http://host.example:1");

    // Trailing slash trimmed.
    let (api3, _) =
        config::resolve_api_from(Some("https://h:443/".to_string()), Some("t".to_string()))
            .unwrap();
    assert_eq!(api3, "https://h:443");
}

// ===========================================================================
// 7. BRIDGE-BIND-EXPOSURE — loopback detection
// ===========================================================================

#[test]
fn bridge_bind_exposure_loopback_detection() {
    use std::net::SocketAddr;
    let lo = |s: &str| config::is_loopback(s.parse::<SocketAddr>().unwrap());
    assert!(lo("127.0.0.1:3300"));
    assert!(lo("127.99.99.99:1"));
    assert!(lo("[::1]:3300"));
    assert!(!lo("0.0.0.0:3300"));
    assert!(!lo("192.168.1.5:3300"));
    assert!(!lo("8.8.8.8:3300"));
    assert!(!lo("[2001:db8::1]:3300"));
}

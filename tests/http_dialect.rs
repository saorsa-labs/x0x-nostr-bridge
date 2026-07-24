//! HTTP dialect conformance (WP2/WP3) against the stub engine + a canned engine.
//! Exercises the wire contract in `docs/recon/dialect.md`: status codes, error
//! strings, the `/events` envelope, `/query` extension parsing + overlay
//! synthesis, auth (X-Pubkey / NIP-98 replay), the relay-authored kind guard,
//! presence-empty, and the demo seed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use nostr::{Event, EventBuilder, Filter, JsonUtil, Keys, Kind, Tag, Timestamp};
use serde_json::{json, Value};

use x0x_nostr_bridge::engine_api::{
    ChannelWindow, Cursor, HistoryEngine, IngestOutcome, StubEngine, ThreadQuery, ThreadSummary,
    Visibility, WindowBounds, WindowQuery,
};
use x0x_nostr_bridge::filter_match::AccessPolicy;
use x0x_nostr_bridge::relay::{router, AppState};
use x0x_nostr_bridge::relay_identity::RelayIdentity;
use x0x_nostr_bridge::settings::Settings;
use x0x_nostr_bridge::store::{EventStore, InsertOutcome};
use x0x_nostr_bridge::transport::{GossipMessage, GossipTransport};

// ---- minimal fakes for the WS side of AppState (unused by HTTP tests) ----

struct FakeStore;
#[async_trait]
impl EventStore for FakeStore {
    async fn insert(&self, _ev: &Event) -> anyhow::Result<InsertOutcome> {
        Ok(InsertOutcome::Inserted)
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

/// A canned engine returning a fixed window so the overlay synthesis (rows →
/// aux → 39005 → exactly-one 39006) can be asserted byte-exactly.
struct CannedEngine {
    window: ChannelWindow,
}
#[async_trait]
impl HistoryEngine for CannedEngine {
    async fn ingest_local(&self, ev: &Event) -> anyhow::Result<IngestOutcome> {
        Ok(IngestOutcome::Stored {
            event_id: ev.id.to_hex(),
            emits: Vec::new(),
        })
    }
    async fn ingest_mesh(&self, ev: &Event) -> anyhow::Result<IngestOutcome> {
        Ok(IngestOutcome::Stored {
            event_id: ev.id.to_hex(),
            emits: Vec::new(),
        })
    }
    async fn query(&self, _f: &Filter) -> anyhow::Result<Vec<Event>> {
        Ok(Vec::new())
    }
    async fn channel_window(&self, _q: &WindowQuery) -> anyhow::Result<ChannelWindow> {
        Ok(self.window.clone())
    }
    async fn thread_replies(&self, _q: &ThreadQuery) -> anyhow::Result<Vec<Event>> {
        Ok(Vec::new())
    }
    async fn thread_summary(&self, _c: &str, _r: &str) -> anyhow::Result<Option<ThreadSummary>> {
        Ok(None)
    }
    async fn count(&self, _f: &Filter) -> anyhow::Result<usize> {
        Ok(0)
    }
    async fn is_member(&self, _c: &str, _p: &str) -> anyhow::Result<bool> {
        Ok(true)
    }
    async fn visibility(&self, _c: &str) -> anyhow::Result<Visibility> {
        Ok(Visibility::Open)
    }
}

// ---- harness ----

const TYLER: &str = "e5ebc6cdb579be112e336cc319b5989b4bb6af11786ea90dbe52b5f08d741b34";

async fn spawn(engine: Arc<dyn HistoryEngine>, settings: Settings) -> (SocketAddr, Arc<AppState>) {
    let state = Arc::new(AppState::new(
        Arc::new(FakeStore),
        Arc::new(FakeTransport),
        engine,
        Arc::new(RelayIdentity::ephemeral()),
        Arc::new(settings),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(Arc::clone(&state));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, state)
}

async fn spawn_stub(settings: Settings) -> (SocketAddr, Arc<AppState>) {
    spawn(Arc::new(StubEngine::new()), settings).await
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

fn signed_kind9(keys: &Keys, channel: &str, content: &str) -> Event {
    EventBuilder::new(Kind::from(9u16), content)
        .tag(Tag::parse(["h", channel]).unwrap())
        .sign_with_keys(keys)
        .unwrap()
}

// ---- POST /events ----

#[tokio::test]
async fn events_x_pubkey_accepts_signed_event() {
    let (addr, _s) = spawn_stub(Settings::default()).await;
    let keys = Keys::generate();
    let ev = signed_kind9(&keys, "general", "hi");
    let resp = client()
        .post(format!("http://{addr}/events"))
        .header("X-Pubkey", keys.public_key().to_hex())
        .body(ev.as_json())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["event_id"], ev.id.to_hex());
    assert_eq!(body["accepted"], true);
    assert_eq!(body["message"], "");
}

#[tokio::test]
async fn events_missing_auth_is_401() {
    let (addr, _s) = spawn_stub(Settings::default()).await;
    let keys = Keys::generate();
    let ev = signed_kind9(&keys, "general", "hi");
    let resp = client()
        .post(format!("http://{addr}/events"))
        .body(ev.as_json())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "missing Nostr auth");
}

#[tokio::test]
async fn events_invalid_json_is_400() {
    let (addr, _s) = spawn_stub(Settings::default()).await;
    let resp = client()
        .post(format!("http://{addr}/events"))
        .header("X-Pubkey", TYLER)
        .body("{ not json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .starts_with("invalid event JSON:"));
}

#[tokio::test]
async fn events_relay_authored_kind_rejected() {
    let (addr, _s) = spawn_stub(Settings::default()).await;
    let keys = Keys::generate();
    // client-submitted 39005 → 400.
    let ev = EventBuilder::new(Kind::from(39005u16), "{}")
        .tag(Tag::parse(["h", "general"]).unwrap())
        .sign_with_keys(&keys)
        .unwrap();
    let resp = client()
        .post(format!("http://{addr}/events"))
        .header("X-Pubkey", keys.public_key().to_hex())
        .body(ev.as_json())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("relay-authored"));
}

#[tokio::test]
async fn events_body_over_1mib_is_413() {
    let (addr, _s) = spawn_stub(Settings::default()).await;
    let big = vec![b'x'; 1024 * 1024 + 1];
    let resp = client()
        .post(format!("http://{addr}/events"))
        .header("X-Pubkey", TYLER)
        .body(big)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
}

// ---- POST /query ----

async fn query(addr: SocketAddr, pubkey: &str, filters: Value) -> reqwest::Response {
    client()
        .post(format!("http://{addr}/query"))
        .header("X-Pubkey", pubkey)
        .json(&filters)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn query_top_level_requires_exactly_one_h() {
    let (addr, _s) = spawn_stub(Settings::default()).await;
    let resp = query(addr, TYLER, json!([{ "top_level": true, "kinds": [9] }])).await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "top_level requires exactly one #h channel");
}

#[tokio::test]
async fn query_half_cursor_is_400() {
    let (addr, _s) = spawn_stub(Settings::default()).await;
    // until without before_id
    let resp = query(
        addr,
        TYLER,
        json!([{ "top_level": true, "#h": ["general"], "until": 100 }]),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"],
        "top_level cursor requires both until and before_id, or neither"
    );
}

#[tokio::test]
async fn query_malformed_before_id_is_400() {
    let (addr, _s) = spawn_stub(Settings::default()).await;
    let resp = query(
        addr,
        TYLER,
        json!([{ "top_level": true, "#h": ["general"], "until": 100, "before_id": "xyz" }]),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"],
        "top_level: before_id must be a 64-hex event id"
    );
}

#[tokio::test]
async fn query_mixed_search_is_400() {
    let (addr, _s) = spawn_stub(Settings::default()).await;
    let resp = query(
        addr,
        TYLER,
        json!([{ "kinds": [9], "search": "hello" }, { "kinds": [9] }]),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"],
        "mixed search and non-search filters not supported"
    );
}

#[tokio::test]
async fn query_p_gated_without_self_p_tag_is_403() {
    let (addr, _s) = spawn_stub(Settings::default()).await;
    // gift wrap (1059) without #p=self → 403 exact message.
    let resp = query(addr, TYLER, json!([{ "kinds": [1059] }])).await;
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"],
        "restricted: p-gated kinds require #p tag matching your pubkey"
    );
}

#[tokio::test]
async fn query_presence_only_returns_empty_without_storage() {
    // Configure a presence kind so the presence-only short-circuit is active.
    let settings = Settings {
        access: AccessPolicy {
            presence_kinds: [30078u16].into_iter().collect(),
            ..AccessPolicy::default()
        },
        ..Default::default()
    };
    let (addr, _s) = spawn_stub(settings).await;
    let resp = query(addr, TYLER, json!([{ "kinds": [30078] }])).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body, json!([]));
}

#[tokio::test]
async fn query_window_synthesizes_overlays_in_order() {
    // Canned window: 2 rows, 1 aux, 1 summary, has_more with a cursor.
    let author = Keys::generate();
    let row1 = signed_kind9(&author, "general", "row1");
    let row2 = signed_kind9(&author, "general", "row2");
    let aux = EventBuilder::new(Kind::from(7u16), "+")
        .tag(Tag::parse(["h", "general"]).unwrap())
        .sign_with_keys(&author)
        .unwrap();
    let window = ChannelWindow {
        rows: vec![row1.clone(), row2.clone()],
        aux: vec![aux.clone()],
        summaries: vec![ThreadSummary {
            root_id: "a".repeat(64),
            channel_id: "general".into(),
            reply_count: 1,
            descendant_count: 2,
            last_reply_at: Some(1700),
            participants: vec!["b".repeat(64)],
        }],
        bounds: WindowBounds {
            has_more: true,
            next_cursor: Some(Cursor {
                created_at: 1699,
                id: "c".repeat(64),
            }),
        },
    };
    let (addr, _s) = spawn(Arc::new(CannedEngine { window }), Settings::default()).await;
    let resp = query(
        addr,
        TYLER,
        json!([{ "top_level": true, "#h": ["general"], "kinds": [9],
                 "include_summaries": true, "include_aux": true }]),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let arr = resp.json::<Value>().await.unwrap();
    let arr = arr.as_array().unwrap();
    // rows(2) + aux(1) + 39005(1) + 39006(1) = 5, in that order.
    assert_eq!(arr.len(), 5);
    assert_eq!(arr[0]["id"], row1.id.to_hex());
    assert_eq!(arr[1]["id"], row2.id.to_hex());
    assert_eq!(arr[2]["id"], aux.id.to_hex());
    assert_eq!(arr[3]["kind"], 39005);
    assert_eq!(arr[4]["kind"], 39006);
    // exactly one 39006.
    let bounds_count = arr.iter().filter(|e| e["kind"] == 39006).count();
    assert_eq!(bounds_count, 1);
    // 39006 carries has_more + next_cursor.
    let content: Value = serde_json::from_str(arr[4]["content"].as_str().unwrap()).unwrap();
    assert_eq!(content["has_more"], true);
    assert_eq!(content["next_cursor"]["created_at"], 1699);
}

// ---- GET /info ----

#[tokio::test]
async fn info_is_nip11_with_self() {
    let (addr, state) = spawn_stub(Settings::default()).await;
    let resp = client()
        .get(format!("http://{addr}/info"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["self"], state.identity.public_key_hex());
    let nips = body["supported_nips"].as_array().unwrap();
    assert!(nips.iter().any(|v| v.as_i64() == Some(42)));
    assert!(nips.iter().any(|v| v.as_i64() == Some(11)));
}

// ---- POST /count ----

#[tokio::test]
async fn count_returns_count_object() {
    let (addr, _s) = spawn_stub(Settings::default()).await;
    let resp = client()
        .post(format!("http://{addr}/count"))
        .header("X-Pubkey", TYLER)
        .json(&json!([{ "kinds": [9] }]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["count"].is_number());
}

// ---- seed-demo ----

#[tokio::test]
async fn seed_demo_serves_kind_39000_for_general() {
    let (addr, state) = spawn_stub(Settings::default()).await;
    x0x_nostr_bridge::seed::seed_demo(&state).await.unwrap();
    // assertRelaySeeded() equivalent: query kinds:[39000] as tyler.
    let resp = query(addr, TYLER, json!([{ "kinds": [39000], "limit": 200 }])).await;
    assert_eq!(resp.status(), 200);
    let arr = resp.json::<Value>().await.unwrap();
    let arr = arr.as_array().unwrap();
    let general = arr.iter().find(|e| {
        e["tags"]
            .as_array()
            .map(|tags| tags.iter().any(|t| t[0] == "name" && t[1] == "general"))
            .unwrap_or(false)
    });
    assert!(general.is_some(), "seed must serve kind-39000 for general");
    assert_eq!(general.unwrap()["kind"], 39000);
}

// ---- NIP-98 (require_auth_token=true) ----

#[tokio::test]
async fn nip98_accept_then_replay_reject_over_http() {
    let settings = Settings {
        require_auth_token: true,
        ..Default::default()
    };
    let (addr, _s) = spawn_stub(settings).await;
    let keys = Keys::generate();
    let auth = EventBuilder::new(Kind::from(27235u16), "")
        .tag(Tag::parse(["u", "http://localhost:3000/query"]).unwrap())
        .tag(Tag::parse(["method", "POST"]).unwrap())
        .custom_created_at(Timestamp::now())
        .sign_with_keys(&keys)
        .unwrap();
    let header = format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(auth.as_json())
    );
    // first accepted
    let resp = client()
        .post(format!("http://{addr}/query"))
        .header("Authorization", &header)
        .json(&json!([{ "kinds": [9] }]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // replay rejected
    let resp = client()
        .post(format!("http://{addr}/query"))
        .header("Authorization", &header)
        .json(&json!([{ "kinds": [9] }]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "NIP-98: replay detected");
}

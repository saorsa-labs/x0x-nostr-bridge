//! End-to-end integration over the REAL `history::HistoryStore` (not the stub):
//! the WP2 HTTP dialect + WP1 thread engine wired through the
//! `HistoryStoreEngine` adapter. Proves the gate-critical paths hit one durable
//! store — the `assertRelaySeeded` 39000 poll, the channel-window rows + single
//! 39006 bounds, and a reply producing a relay-signed 39005 summary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use nostr::{Event, EventBuilder, Filter, JsonUtil, Keys, Kind, Tag};
use serde_json::{json, Value};

use x0x_nostr_bridge::engine_api::HistoryEngine;
use x0x_nostr_bridge::history::HistoryStore;
use x0x_nostr_bridge::history_adapter::{HistoryStoreEngine, HistoryStoreEventStore};
use x0x_nostr_bridge::relay::{router, AppState};
use x0x_nostr_bridge::relay_identity::RelayIdentity;
use x0x_nostr_bridge::settings::Settings;
use x0x_nostr_bridge::store::EventStore;
use x0x_nostr_bridge::transport::{GossipMessage, GossipTransport};

const TYLER: &str = "e5ebc6cdb579be112e336cc319b5989b4bb6af11786ea90dbe52b5f08d741b34";

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

async fn spawn_real() -> (SocketAddr, Arc<AppState>) {
    let settings = Settings::default();
    let p_gated: Vec<u32> = settings
        .access
        .p_gated_kinds
        .iter()
        .map(|&k| u32::from(k))
        .collect();
    let history = Arc::new(HistoryStore::open_in_memory("test-community").unwrap());
    let engine = Arc::new(HistoryStoreEngine::new(
        Arc::clone(&history),
        p_gated.clone(),
    ));
    let store: Arc<dyn EventStore> =
        Arc::new(HistoryStoreEventStore::new(Arc::clone(&history), p_gated));
    let state = Arc::new(AppState::new(
        store,
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

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

async fn post_event(addr: SocketAddr, ev: &Event, pubkey: &str) -> reqwest::Response {
    client()
        .post(format!("http://{addr}/events"))
        .header("X-Pubkey", pubkey)
        .body(ev.as_json())
        .send()
        .await
        .unwrap()
}

async fn query(addr: SocketAddr, pubkey: &str, filters: Value) -> Value {
    client()
        .post(format!("http://{addr}/query"))
        .header("X-Pubkey", pubkey)
        .json(&filters)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn kind9(keys: &Keys, channel: &str, content: &str, extra: Vec<Tag>) -> Event {
    let mut b =
        EventBuilder::new(Kind::from(9u16), content).tag(Tag::parse(["h", channel]).unwrap());
    for t in extra {
        b = b.tag(t);
    }
    b.sign_with_keys(keys).unwrap()
}

#[tokio::test]
async fn seed_39000_served_from_real_store() {
    let (addr, state) = spawn_real().await;
    x0x_nostr_bridge::seed::seed_demo(&state).await.unwrap();
    let arr = query(addr, TYLER, json!([{ "kinds": [39000], "limit": 200 }])).await;
    let arr = arr.as_array().unwrap();
    let general = arr.iter().find(|e| {
        e["tags"]
            .as_array()
            .map(|t| t.iter().any(|tag| tag[0] == "name" && tag[1] == "general"))
            .unwrap_or(false)
    });
    assert!(
        general.is_some(),
        "assertRelaySeeded path: 39000 for general must be served"
    );
    assert_eq!(general.unwrap()["kind"], 39000);
}

#[tokio::test]
async fn window_returns_row_and_single_39006() {
    let (addr, _state) = spawn_real().await;
    let author = Keys::generate();
    let root = kind9(&author, "general", "hello timeline", vec![]);
    let resp = post_event(addr, &root, &author.public_key().to_hex()).await;
    assert_eq!(resp.status(), 200);

    let arr = query(
        addr,
        TYLER,
        json!([{ "#h": ["general"], "kinds": [9], "top_level": true,
                 "include_summaries": true, "include_aux": true, "limit": 50 }]),
    )
    .await;
    let arr = arr.as_array().unwrap();
    // the row is present
    assert!(
        arr.iter().any(|e| e["id"] == root.id.to_hex()),
        "row must be in the window"
    );
    // exactly one 39006 bounds, and it is the authority (has_more false on head)
    let bounds: Vec<&Value> = arr.iter().filter(|e| e["kind"] == 39006).collect();
    assert_eq!(bounds.len(), 1, "exactly one 39006 bounds overlay");
    let content: Value = serde_json::from_str(bounds[0]["content"].as_str().unwrap()).unwrap();
    assert_eq!(content["has_more"], false);
}

#[tokio::test]
async fn reply_produces_39005_summary_in_window() {
    let (addr, _state) = spawn_real().await;
    let author = Keys::generate();
    // root (top-level, no e-tag)
    let root = kind9(&author, "general", "root msg", vec![]);
    assert_eq!(
        post_event(addr, &root, &author.public_key().to_hex())
            .await
            .status(),
        200
    );
    // direct reply (reply marker -> parent == root == root)
    let reply = kind9(
        &author,
        "general",
        "a reply",
        vec![Tag::parse(["e", &root.id.to_hex(), "", "reply"]).unwrap()],
    );
    let rresp = post_event(addr, &reply, &author.public_key().to_hex()).await;
    assert_eq!(
        rresp.status(),
        200,
        "reply to an existing parent is accepted"
    );

    let arr = query(
        addr,
        TYLER,
        json!([{ "#h": ["general"], "kinds": [9], "top_level": true,
                 "include_summaries": true, "include_aux": true, "limit": 50 }]),
    )
    .await;
    let arr = arr.as_array().unwrap();
    // root is a top-level row; the reply is NOT a top-level row (thread.md §1.6)
    assert!(
        arr.iter().any(|e| e["id"] == root.id.to_hex()),
        "root is a row"
    );
    assert!(
        !arr.iter().any(|e| e["id"] == reply.id.to_hex()),
        "an ordinary reply is not a top-level row"
    );
    // a relay-signed 39005 summary for the root, reply_count == 1
    let summary = arr.iter().find(|e| e["kind"] == 39005);
    assert!(
        summary.is_some(),
        "root with a reply must carry a 39005 summary"
    );
    let content: Value =
        serde_json::from_str(summary.unwrap()["content"].as_str().unwrap()).unwrap();
    assert_eq!(content["reply_count"], 1);
}

// ---- WP2b: p-gated kinds must be unsearchable (store layer + end-to-end) ----

/// A gift wrap (kind 1059, p-gated) with searchable content must NOT come back
/// from NIP-50 search at the STORE layer — WP1b's `search(exclude_kinds)`, wired
/// from the p-gated set, enforces this (Buzz nulls their search vector). A
/// normal kind-9 with the same word stays searchable.
#[tokio::test]
async fn p_gated_excluded_from_search_at_store_layer() {
    let history = Arc::new(HistoryStore::open_in_memory("test-community").unwrap());
    let engine = HistoryStoreEngine::new(Arc::clone(&history), vec![1059]);
    let author = Keys::generate();

    let gift_wrap = EventBuilder::new(Kind::from(1059u16), "zzsecretwordzz hidden")
        .sign_with_keys(&author)
        .unwrap();
    engine.ingest_local(&gift_wrap).await.unwrap();
    let visible = kind9(&author, "general", "zzsecretwordzz visible", vec![]);
    engine.ingest_local(&visible).await.unwrap();

    let results = engine
        .query(&Filter::new().search("zzsecretwordzz"))
        .await
        .unwrap();
    assert!(
        results.iter().all(|e| e.id != gift_wrap.id),
        "store layer: p-gated kind 1059 must be excluded from search"
    );
    assert!(
        results.iter().any(|e| e.id == visible.id),
        "store layer: a normal kind-9 with the term stays searchable"
    );
}

/// End-to-end (both layers): a stored p-gated event with matching text must not
/// appear in a NIP-50 `/query` search result.
#[tokio::test]
async fn p_gated_excluded_from_search_end_to_end() {
    let (addr, _state) = spawn_real().await;
    let author = Keys::generate();
    let gift_wrap = EventBuilder::new(Kind::from(1059u16), "qqmagicwordqq secret")
        .sign_with_keys(&author)
        .unwrap();
    assert_eq!(
        post_event(addr, &gift_wrap, &author.public_key().to_hex())
            .await
            .status(),
        200
    );
    let visible = kind9(&author, "general", "qqmagicwordqq shown", vec![]);
    assert_eq!(
        post_event(addr, &visible, &author.public_key().to_hex())
            .await
            .status(),
        200
    );

    let arr = query(addr, TYLER, json!([{ "search": "qqmagicwordqq" }])).await;
    let arr = arr.as_array().unwrap();
    assert!(
        arr.iter().all(|e| e["id"] != gift_wrap.id.to_hex()),
        "end-to-end: p-gated 1059 must not appear in search results"
    );
    assert!(
        arr.iter().any(|e| e["id"] == visible.id.to_hex()),
        "end-to-end: the normal kind-9 with the term is returned"
    );
}

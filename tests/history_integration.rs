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

/// The M1a gate failure, end to end over `/query`. Buzz resolves an addressable
/// (NIP-33/NIP-29) channel with `{kinds:[39000], "#d":[id], limit:1}`. The seed
/// stores one 39000 per seeded channel, so a bridge that drops `#d` hands back
/// whichever row sorts first for every lookup — the client takes row `[0]` and
/// renders the wrong channel.
#[tokio::test]
async fn addressable_d_query_resolves_the_right_channel() {
    let (addr, state) = spawn_real().await;
    x0x_nostr_bridge::seed::seed_demo(&state).await.unwrap();
    let dm_id = x0x_nostr_bridge::seed::dm_channel_id("alice-tyler");
    let general_id = x0x_nostr_bridge::seed::channel_id("general");

    let d_tag_of = |e: &Value| {
        e["tags"]
            .as_array()
            .and_then(|t| t.iter().find(|tag| tag[0] == "d"))
            .and_then(|tag| tag[1].as_str().map(str::to_string))
            .unwrap()
    };

    for want in [dm_id.as_str(), general_id.as_str()] {
        let arr = query(
            addr,
            TYLER,
            json!([{ "kinds": [39000], "#d": [want], "limit": 1 }]),
        )
        .await;
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 1, "#d must narrow 39000 to one row for {want}");
        assert_eq!(
            d_tag_of(&arr[0]),
            want,
            "under `limit:1` a dropped #d silently serves the wrong channel"
        );
    }

    // An unsatisfiable #d must return nothing, never fall back to everything.
    let none = query(
        addr,
        TYLER,
        json!([{ "kinds": [39000], "#d": ["no-such-channel"] }]),
    )
    .await;
    assert!(none.as_array().unwrap().is_empty());
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

/// The startup topic pre-subscribe list (`known_channels`) is empty on a fresh
/// store and lists a channel once an event for it is stored — so after a restart
/// the bridge re-subscribes the channels it already has (WP1 PR #8 wiring).
#[tokio::test]
async fn known_channels_lists_channel_after_ingest() {
    let history = Arc::new(HistoryStore::open_in_memory("test-community").unwrap());
    let store = HistoryStoreEventStore::new(Arc::clone(&history), vec![]);
    assert!(
        store.known_channels().await.unwrap().is_empty(),
        "fresh store has no channels"
    );
    let author = Keys::generate();
    let msg = kind9(&author, "general", "hi", vec![]);
    store.insert(&msg).await.unwrap();
    let chans = store.known_channels().await.unwrap();
    assert!(
        chans.iter().any(|c| c == "general"),
        "known_channels lists the channel after an event is stored"
    );
}

/// Extract the single kind-39006 bounds overlay from a window response.
fn bounds_of(arr: &[Value]) -> &Value {
    let b: Vec<&Value> = arr.iter().filter(|e| e["kind"] == 39006).collect();
    assert_eq!(b.len(), 1, "exactly one 39006 per window response");
    b[0]
}

fn d_of(ev: &Value) -> String {
    ev["tags"]
        .as_array()
        .and_then(|t| t.iter().find(|tag| tag[0] == "d"))
        .and_then(|tag| tag[1].as_str().map(str::to_string))
        .unwrap()
}

/// The 39006 `d` tag is the response's **correlation key**: the client rebuilds
/// it from the cursor it sent (`expectedBoundsKey`,
/// `channelWindowResponse.ts:74-82`) and throws the entire page away on a
/// mismatch (`:116-120`). Keying it off `next_cursor` instead agrees only for a
/// head request with no second page — so it looked correct for every channel
/// that fits in one window, and every larger channel rendered empty and never
/// paginated, with the error swallowed by React Query.
///
/// This drives both pages over HTTP because the defect had two halves: the
/// builder used the wrong cursor, and `POST /query` never passed the request
/// cursor in at all. A unit test on the builder alone would still have passed
/// with the second half unfixed.
#[tokio::test]
async fn window_bounds_d_echoes_the_request_cursor_across_two_pages() {
    let (addr, _state) = spawn_real().await;
    let author = Keys::generate();
    let pubkey = author.public_key().to_hex();
    let channel = "paging-channel";

    // 60 top-level rows against a limit of 50 — i.e. two pages.
    for i in 0..60 {
        let ev = kind9(&author, channel, &format!("row {i}"), vec![]);
        assert_eq!(post_event(addr, &ev, &pubkey).await.status(), 200);
    }

    let window = json!([{ "#h": [channel], "kinds": [9], "top_level": true,
                          "include_summaries": true, "include_aux": true, "limit": 50 }]);
    let page1 = query(addr, &pubkey, window).await;
    let page1 = page1.as_array().unwrap();
    let b1 = bounds_of(page1);

    // The head request carries no cursor, so the key is `:head` — even though a
    // second page exists. This exact pair is what the old keying got wrong.
    assert_eq!(
        d_of(b1),
        format!("{channel}:head"),
        "a head request must be answered with the head key regardless of has_more"
    );
    let content: Value = serde_json::from_str(b1["content"].as_str().unwrap()).unwrap();
    assert_eq!(content["has_more"], true, "60 rows over a limit of 50");
    let next = &content["next_cursor"];
    assert!(
        !next.is_null(),
        "the next page's address belongs in content, and the client needs it to paginate"
    );

    // Page two: send that cursor back. The key must echo what we sent, not the
    // cursor this response returns.
    let (until, before_id) = (
        next["created_at"].as_u64().unwrap(),
        next["id"].as_str().unwrap().to_string(),
    );
    let page2 = query(
        addr,
        &pubkey,
        json!([{ "#h": [channel], "kinds": [9], "top_level": true,
                 "include_summaries": true, "include_aux": true, "limit": 50,
                 "until": until, "before_id": before_id }]),
    )
    .await;
    let page2 = page2.as_array().unwrap();
    let b2 = bounds_of(page2);
    assert_eq!(
        d_of(b2),
        format!("{channel}:{until}:{before_id}"),
        "page two must be keyed on the cursor the client sent"
    );

    // And the rows actually advanced, so this is a real second page.
    let rows2: Vec<&Value> = page2.iter().filter(|e| e["kind"] == 9).collect();
    assert_eq!(rows2.len(), 10, "60 rows, 50 on page one");
    let content2: Value = serde_json::from_str(b2["content"].as_str().unwrap()).unwrap();
    assert_eq!(content2["has_more"], false);
    assert!(content2["next_cursor"].is_null());
}

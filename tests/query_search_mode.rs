//! `/query` `search_mode` conformance (NIP-50 prefix search + error contract).
//!
//! Contract (locked with BridgeConformance):
//! - `search_mode: "prefix"` → FTS5 token-prefix match, so an incomplete final
//!   token (`"prog"`) matches stored content (`"programming"`).
//! - absent (default) → unchanged whole-token phrase semantics: `"prog"` does
//!   NOT match `"programming"`, `"programming"` does.
//! - unknown string value → HTTP 400 `{"error": "unknown search_mode: <value>"}`.
//! - non-string value → HTTP 400 `{"error": "search_mode must be a string"}`.
//!
//! On the pre-change bridge the prefix + error tests fail: `search_mode` is an
//! unrecognized extension field, silently ignored, so a prefix query returns an
//! empty 200 and an unknown/non-string mode is accepted instead of rejected.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use nostr::{Event, EventBuilder, Filter, JsonUtil, Keys, Kind, Tag, Timestamp};
use serde_json::{json, Value};

use x0x_nostr_bridge::engine_api::HistoryEngine;
use x0x_nostr_bridge::history::HistoryStore;
use x0x_nostr_bridge::history_adapter::HistoryStoreEngine;
use x0x_nostr_bridge::relay::{router, AppState};
use x0x_nostr_bridge::relay_identity::RelayIdentity;
use x0x_nostr_bridge::settings::Settings;
use x0x_nostr_bridge::store::{EventStore, InsertOutcome};
use x0x_nostr_bridge::transport::{GossipMessage, GossipTransport};

/// A valid 64-hex pubkey for the dev `X-Pubkey` auth header (read principal).
const READER: &str = "e5ebc6cdb579be112e336cc319b5989b4bb6af11786ea90dbe52b5f08d741b34";
const CH: &str = "srch-0001";

// ---- minimal no-op fakes for the AppState fields /query never touches ------

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

/// Spawn a relay over a real (in-memory) history store so FTS search is
/// exercised end-to-end through the HTTP dialect.
async fn spawn() -> SocketAddr {
    let history = Arc::new(HistoryStore::open_in_memory("search-mode-fp").unwrap());
    let store: Arc<dyn EventStore> = Arc::new(FakeStore);
    let transport: Arc<dyn GossipTransport> = Arc::new(FakeTransport);
    let engine: Arc<dyn HistoryEngine> = Arc::new(HistoryStoreEngine::new(history, Vec::new()));
    let state = Arc::new(AppState::new(
        store,
        transport,
        engine,
        Arc::new(RelayIdentity::ephemeral()),
        Arc::new(Settings::default()),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    addr
}

fn kind9(keys: &Keys, channel: &str, content: &str) -> Event {
    EventBuilder::new(Kind::from(9u16), content)
        .tag(Tag::parse(["h", channel]).unwrap())
        .sign_with_keys(keys)
        .unwrap()
}

/// POST one signed kind-9 message through the real ingest door (FTS-indexes it).
async fn seed(addr: SocketAddr, keys: &Keys) {
    let pk = keys.public_key().to_hex();
    let ack = reqwest::Client::new()
        .post(format!("http://{addr}/events"))
        .header("X-Pubkey", pk)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(kind9(keys, CH, "programming rust async").as_json())
        .send()
        .await
        .unwrap();
    assert_eq!(ack.status().as_u16(), 200, "seed /events must be 200");
    let body: Value = ack.json().await.unwrap();
    assert_eq!(body["accepted"], json!(true), "seed event must be accepted");
}

async fn query(addr: SocketAddr, filters: Value) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/query"))
        .header("X-Pubkey", READER)
        .json(&filters)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.json::<Value>().await.unwrap();
    (status, body)
}

fn found_content(body: &Value, needle: &str) -> bool {
    body.as_array()
        .expect("200 /query body is a bare result array")
        .iter()
        .any(|e| e["content"].as_str() == Some(needle))
}

// ---- default semantics (regression guard: unchanged before and after) -----

#[tokio::test]
async fn default_search_keeps_whole_token_semantics() {
    let addr = spawn().await;
    let keys = Keys::generate();
    seed(addr, &keys).await;

    // Whole-token hit.
    let (st, body) = query(addr, json!([{ "search": "programming" }])).await;
    assert_eq!(st, 200);
    assert!(
        found_content(&body, "programming rust async"),
        "default whole-token search must find 'programming'"
    );

    // Incomplete token → no hit (default is whole-token phrase, NOT prefix).
    let (st2, body2) = query(addr, json!([{ "search": "prog" }])).await;
    assert_eq!(st2, 200);
    assert!(
        body2.as_array().expect("array").is_empty(),
        "default search must NOT prefix-match the incomplete token 'prog'"
    );
}

// ---- prefix mode (the gap: red on pre-change, green after) ----------------

#[tokio::test]
async fn prefix_mode_finds_incomplete_final_token() {
    let addr = spawn().await;
    let keys = Keys::generate();
    seed(addr, &keys).await;

    let (st, body) = query(addr, json!([{ "search": "prog", "search_mode": "prefix" }])).await;
    assert_eq!(st, 200, "prefix search must succeed (200)");
    assert!(
        found_content(&body, "programming rust async"),
        "search_mode=prefix must match the incomplete token 'prog' against 'programming'"
    );
}

// ---- error contract (red on pre-change, green after) ----------------------

#[tokio::test]
async fn unknown_search_mode_is_rejected() {
    let addr = spawn().await;
    let keys = Keys::generate();
    seed(addr, &keys).await;

    let (st, body) = query(addr, json!([{ "search": "prog", "search_mode": "fuzzy" }])).await;
    assert_eq!(st, 400, "an unknown search_mode must be rejected with 400");
    assert_eq!(
        body["error"].as_str(),
        Some("unknown search_mode: fuzzy"),
        "unknown search_mode must return the agreed error string"
    );
    assert!(
        !body.is_array(),
        "a 400 must be the {{error}} object, never a result array"
    );
}

#[tokio::test]
async fn non_string_search_mode_is_rejected() {
    let addr = spawn().await;
    let keys = Keys::generate();
    seed(addr, &keys).await;

    let (st, body) = query(addr, json!([{ "search": "prog", "search_mode": 123 }])).await;
    assert_eq!(
        st, 400,
        "a non-string search_mode must be rejected with 400"
    );
    assert_eq!(
        body["error"].as_str(),
        Some("search_mode must be a string"),
        "non-string search_mode must return the agreed error string"
    );
}

// ---- empty Some([]) dimensions narrow search to nothing (BridgeReview) ----
//
// A search filter carrying an empty ids/kinds/authors/generic-tag list must
// return ZERO results — the same empty-`Some`-set-narrows-to-nothing rule the
// non-search path already honours. Red on the pre-fix bridge: the search branch
// passed the empty set to the store as "unconstrained" and returned matches.

async fn assert_search_empty(addr: SocketAddr, filters: Value, label: &str) {
    let (st, body) = query(addr, filters).await;
    assert_eq!(st, 200, "{label}: status should be 200");
    let n = body.as_array().expect("200 body is a result array").len();
    assert!(
        n == 0,
        "{label}: an empty Some([]) dimension must narrow the search to nothing, got {n} result(s)"
    );
}

#[tokio::test]
async fn search_empty_set_dimensions_return_nothing_literal() {
    let addr = spawn().await;
    let keys = Keys::generate();
    seed(addr, &keys).await;

    // Sanity: the literal search DOES match when the dimension is absent, so an
    // empty result below is attributable to the empty-set narrowing, not a miss.
    let (st, body) = query(addr, json!([{ "search": "programming" }])).await;
    assert_eq!(st, 200);
    assert!(
        found_content(&body, "programming rust async"),
        "sanity: literal search must match without the empty constraint"
    );

    assert_search_empty(
        addr,
        json!([{ "search": "programming", "kinds": [] }]),
        "kinds:[]",
    )
    .await;
    assert_search_empty(
        addr,
        json!([{ "search": "programming", "ids": [] }]),
        "ids:[]",
    )
    .await;
    assert_search_empty(
        addr,
        json!([{ "search": "programming", "authors": [] }]),
        "authors:[]",
    )
    .await;
    assert_search_empty(
        addr,
        json!([{ "search": "programming", "#x": [] }]),
        "generic #x:[]",
    )
    .await;
}

#[tokio::test]
async fn search_empty_set_dimensions_return_nothing_prefix() {
    let addr = spawn().await;
    let keys = Keys::generate();
    seed(addr, &keys).await;

    // Sanity: the prefix search DOES match when the dimension is absent.
    let (st, body) = query(addr, json!([{ "search": "prog", "search_mode": "prefix" }])).await;
    assert_eq!(st, 200);
    assert!(
        found_content(&body, "programming rust async"),
        "sanity: prefix search must match without the empty constraint"
    );

    assert_search_empty(
        addr,
        json!([{ "search": "prog", "search_mode": "prefix", "kinds": [] }]),
        "prefix kinds:[]",
    )
    .await;
    assert_search_empty(
        addr,
        json!([{ "search": "prog", "search_mode": "prefix", "ids": [] }]),
        "prefix ids:[]",
    )
    .await;
    assert_search_empty(
        addr,
        json!([{ "search": "prog", "search_mode": "prefix", "authors": [] }]),
        "prefix authors:[]",
    )
    .await;
    assert_search_empty(
        addr,
        json!([{ "search": "prog", "search_mode": "prefix", "#x": [] }]),
        "prefix generic #x:[]",
    )
    .await;
}

// ---- BridgeFinalReview regressions: offset paging + conjunctive search ----

fn kind9_at(keys: &Keys, channel: &str, content: &str, created_at: u64) -> Event {
    EventBuilder::new(Kind::from(9u16), content)
        .tag(Tag::parse(["h", channel]).unwrap())
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(keys)
        .unwrap()
}

async fn post_event(addr: SocketAddr, pubkey: &str, ev: &Event) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/events"))
        .header("X-Pubkey", pubkey)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(ev.as_json())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "POST /events must be 200");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["accepted"], json!(true), "seed event must be accepted");
}

fn contents(body: &Value) -> Vec<String> {
    body.as_array()
        .expect("200 /query body is a result array")
        .iter()
        .filter_map(|e| e["content"].as_str().map(String::from))
        .collect()
}

/// page > 1 must return the LATER rows, not empty. Red on the pre-fix bridge:
/// run_query capped the store fetch at `filter.limit`, so the plain path's
/// offset-drain then emptied page 2. Fix: LIMIT/OFFSET at storage.
#[tokio::test]
async fn page_two_returns_later_rows_with_limit() {
    let addr = spawn().await;
    let keys = Keys::generate();
    let pk = keys.public_key().to_hex();
    // 4 rows, distinct created_at; storage order is created_at DESC, id ASC.
    for (i, ts) in [400u64, 300, 200, 100].iter().enumerate() {
        post_event(
            addr,
            &pk,
            &kind9_at(&keys, CH, &format!("row{i}-ts{ts}"), *ts),
        )
        .await;
    }

    let (_, p1) = query(
        addr,
        json!([{ "kinds": [9], "#h": [CH], "limit": 2, "page": 1 }]),
    )
    .await;
    let p1c = contents(&p1);
    assert_eq!(p1c.len(), 2, "page 1 returns `limit` rows");

    let (_, p2) = query(
        addr,
        json!([{ "kinds": [9], "#h": [CH], "limit": 2, "page": 2 }]),
    )
    .await;
    let p2c = contents(&p2);
    assert_eq!(
        p2c.len(),
        2,
        "page 2 must return the later rows (not empty)"
    );
    assert!(
        p1c.iter().all(|c| !p2c.contains(c)),
        "page 2 rows must be distinct from page 1: p1={p1c:?} p2={p2c:?}"
    );
    // Page 2 holds the OLDER (lower-ts) rows.
    assert!(
        p2c.iter()
            .all(|c| c.contains("ts100") || c.contains("ts200")),
        "page 2 must be the later/older rows: {p2c:?}"
    );
    let mut union = p1c.clone();
    union.extend(p2c);
    assert_eq!(union.len(), 4, "pages 1+2 together cover all rows");
}

/// A search carrying several nonempty dimensions must AND every one of them.
/// Red on the pre-fix bridge: the search branch dropped authors/#p/since/until
/// (only text+kinds+channel reached the store). Each decoy breaks exactly one
/// dimension, so if any dimension is dropped the matching decoy leaks in.
#[tokio::test]
async fn search_preserves_every_nonempty_dimension() {
    let addr = spawn().await;
    let a = Keys::generate();
    let b = Keys::generate();
    let pk_a = a.public_key().to_hex();
    let p_tag = Keys::generate().public_key().to_hex();
    let other_p = Keys::generate().public_key().to_hex();
    let t = 5_000u64;

    let tagged = |keys: &Keys, p: &str, ts: u64| {
        EventBuilder::new(Kind::from(9u16), "target token")
            .tag(Tag::parse(["h", CH]).unwrap())
            .tag(Tag::parse(["p", p]).unwrap())
            .custom_created_at(Timestamp::from(ts))
            .sign_with_keys(keys)
            .unwrap()
    };

    // X matches every dimension below.
    let x = tagged(&a, &p_tag, t);
    let d_author = tagged(&b, &p_tag, t); // breaks authors
    let d_ptag = tagged(&a, &other_p, t); // breaks #p
    let d_time = tagged(&a, &p_tag, t + 100_000); // breaks since/until window

    post_event(addr, &pk_a, &x).await;
    post_event(addr, &b.public_key().to_hex(), &d_author).await;
    post_event(addr, &pk_a, &d_ptag).await;
    post_event(addr, &pk_a, &d_time).await;

    // Control: the bare search matches all four (same text/kind/channel).
    let (_, ctrl) = query(addr, json!([{ "search": "target" }])).await;
    assert_eq!(
        contents(&ctrl).len(),
        4,
        "control: every decoy shares the search term"
    );

    // Conjunctive: every nonempty dimension is preserved → only X survives.
    let (st, hit) = query(
        addr,
        json!([{
            "search": "target",
            "authors": [pk_a],
            "kinds": [9],
            "#h": [CH],
            "#p": [p_tag],
            "since": t - 1,
            "until": t + 1,
        }]),
    )
    .await;
    assert_eq!(st, 200);
    let ids: Vec<String> = hit
        .as_array()
        .expect("result array")
        .iter()
        .filter_map(|e| e["id"].as_str().map(String::from))
        .collect();
    assert_eq!(
        ids,
        vec![x.id.to_hex()],
        "search must AND authors+#h+#p+since+until → exactly the one matching event"
    );
}

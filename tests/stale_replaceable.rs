//! Stale-replaceable regression (BridgeReview finding): an older replaceable
//! event (same pubkey+kind+d, lower `created_at` than the stored winner) must be
//! rejected at BOTH ingest doors without side effects.
//!
//! Contract (locked with BridgeConformance): a stale replaceable is NOT stored,
//! NOT gossip-published, NOT hub-live-fanned-out, and returns the existing
//! stale-rejection outcome — WS `OK false "duplicate: replaced"` and HTTP
//! `/events` `200 {accepted:false, message:"duplicate: replaced"}`. The newer
//! winner stays queryable.
//!
//! Red on the pre-fix bridge: `HistoryStoreEngine::ingest_local` mapped a stale
//! accepted event to `Stored`, so `/events` answered `accepted:true` and both
//! doors gossip-published + hub-dispatched a non-stored event.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use nostr::{
    ClientMessage, Event, EventBuilder, Filter, JsonUtil, Keys, Kind, SubscriptionId, Tag, TagKind,
    Timestamp,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use x0x_nostr_bridge::engine_api::HistoryEngine;
use x0x_nostr_bridge::history::HistoryStore;
use x0x_nostr_bridge::history_adapter::{HistoryStoreEngine, HistoryStoreEventStore};
use x0x_nostr_bridge::proto;
use x0x_nostr_bridge::relay::{router, AppState};
use x0x_nostr_bridge::relay_identity::RelayIdentity;
use x0x_nostr_bridge::settings::Settings;
use x0x_nostr_bridge::store::EventStore;
use x0x_nostr_bridge::transport::{GossipMessage, GossipTransport};

type WS =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const READER: &str = "e5ebc6cdb579be112e336cc319b5989b4bb6af11786ea90dbe52b5f08d741b34";

// ---- recording gossip transport -------------------------------------------

struct RecordingTransport {
    publishes: Mutex<Vec<(String, Vec<u8>)>>,
}

impl RecordingTransport {
    fn new() -> Self {
        Self {
            publishes: Mutex::new(Vec::new()),
        }
    }
    async fn published_ids(&self) -> HashSet<String> {
        let mut ids = HashSet::new();
        for (_, p) in self.publishes.lock().await.iter() {
            if let Ok(v) = serde_json::from_slice::<Value>(p) {
                if let Some(id) = v["id"].as_str() {
                    ids.insert(id.to_string());
                }
            }
        }
        ids
    }
}

#[async_trait]
impl GossipTransport for RecordingTransport {
    async fn ensure_topic(&self, _topic: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn publish(&self, topic: &str, payload: &[u8]) -> anyhow::Result<()> {
        self.publishes
            .lock()
            .await
            .push((topic.to_string(), payload.to_vec()));
        Ok(())
    }
    fn inbox(&self) -> tokio::sync::mpsc::Receiver<GossipMessage> {
        tokio::sync::mpsc::channel(1).1
    }
}

// ---- harness (real thread engine so replaceable dedup + /query are live) ---

async fn spawn(
    history: Arc<HistoryStore>,
    transport: Arc<RecordingTransport>,
    identity: Arc<RelayIdentity>,
) -> SocketAddr {
    let store: Arc<dyn EventStore> = Arc::new(HistoryStoreEventStore::new(
        Arc::clone(&history),
        Vec::new(),
    ));
    let engine: Arc<dyn HistoryEngine> = Arc::new(HistoryStoreEngine::new(history, Vec::new()));
    let state = Arc::new(AppState::new(
        store,
        transport,
        engine,
        identity,
        Arc::new(Settings::default()),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    addr
}

async fn connect(addr: SocketAddr) -> WS {
    let (ws, _resp) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
        .await
        .unwrap();
    ws
}

async fn recv_value(ws: &mut WS) -> Value {
    loop {
        match ws.next().await {
            Some(Ok(WsMessage::Text(t))) => {
                return serde_json::from_str(&t).expect("valid json frame");
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => panic!("ws error: {e}"),
            None => panic!("ws closed"),
        }
    }
}

async fn send_msg(ws: &mut WS, msg: ClientMessage<'_>) {
    ws.send(WsMessage::Text(msg.as_json())).await.expect("send");
}

async fn connect_with_challenge(addr: SocketAddr) -> (WS, String) {
    let mut ws = connect(addr).await;
    let auth_msg = recv_value(&mut ws).await;
    assert_eq!(auth_msg[0], "AUTH");
    let challenge = auth_msg[1].as_str().expect("challenge").to_string();
    (ws, challenge)
}

async fn authenticate(ws: &mut WS, keys: &Keys, challenge: &str) {
    send_msg(
        ws,
        ClientMessage::auth(auth_event_at(keys, challenge, Timestamp::now())),
    )
    .await;
    let ok = recv_value(ws).await;
    assert_eq!(ok[0], "OK");
    assert!(ok[2].as_bool().expect("status"), "AUTH should succeed");
}

fn auth_event_at(keys: &Keys, challenge: &str, ts: Timestamp) -> Event {
    EventBuilder::new(Kind::from(proto::AUTH_KIND), "")
        .custom_created_at(ts)
        .tag(Tag::custom(TagKind::custom("challenge"), [challenge]))
        .tag(Tag::custom(TagKind::custom("relay"), ["ws://127.0.0.1/"]))
        .sign_with_keys(keys)
        .unwrap()
}

/// Plain replaceable kind-0 metadata, signed by `keys`, at `created_at`.
fn kind0(keys: &Keys, content: &str, created_at: u64) -> Event {
    EventBuilder::new(Kind::from(0u16), content)
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(keys)
        .unwrap()
}

/// POST /events; returns the `{event_id, accepted, message}` envelope.
async fn post_event(addr: SocketAddr, pubkey: &str, ev: &Event) -> Value {
    reqwest::Client::new()
        .post(format!("http://{addr}/events"))
        .header("X-Pubkey", pubkey)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(ev.as_json())
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()
}

async fn query(addr: SocketAddr, filters: Value) -> Value {
    reqwest::Client::new()
        .post(format!("http://{addr}/query"))
        .header("X-Pubkey", READER)
        .json(&filters)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()
}

/// Collect every EVENT frame arriving within `window` (drains live dispatch).
async fn drain_events(ws: &mut WS, window: Duration) -> Vec<Event> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, recv_value(ws)).await {
            Ok(v) if v[0] == "EVENT" => {
                if let Ok(ev) = serde_json::from_value::<Event>(v[2].clone()) {
                    out.push(ev);
                }
            }
            Ok(_) => {}      // EOSE / others
            Err(_) => break, // timeout — no more frames
        }
    }
    out
}

// ---- WS door --------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_stale_replaceable_not_stored_published_or_dispatched() {
    let history = Arc::new(HistoryStore::open_in_memory("stale-ws-fp").unwrap());
    let transport = Arc::new(RecordingTransport::new());
    let identity = Arc::new(RelayIdentity::ephemeral());
    let addr = spawn(
        Arc::clone(&history),
        Arc::clone(&transport),
        Arc::clone(&identity),
    )
    .await;

    let author = Keys::generate();
    let author_pk = author.public_key().to_hex();
    let newer = kind0(&author, "newer-metadata", 2_000_000_000);
    let stale = kind0(&author, "stale-metadata", 1_000_000_000); // older → stale
    let newer_id = newer.id.to_hex();
    let stale_id = stale.id.to_hex();

    // Subscriber on the author's kind-0: would catch any (wrongful) live dispatch
    // of the stale event.
    let (mut sub, chal) = connect_with_challenge(addr).await;
    let sub_keys = Keys::generate();
    authenticate(&mut sub, &sub_keys, &chal).await;
    let filter =
        Filter::from_json(format!(r##"{{"kinds":[0],"authors":["{author_pk}"]}}"##)).unwrap();
    send_msg(
        &mut sub,
        ClientMessage::req(SubscriptionId::new("sub"), vec![filter]),
    )
    .await;
    let eose = recv_value(&mut sub).await;
    assert_eq!(eose[0], "EOSE");

    // Publisher: store the newer winner, then submit the stale loser.
    let (mut pubc, chal2) = connect_with_challenge(addr).await;
    authenticate(&mut pubc, &author, &chal2).await;

    send_msg(&mut pubc, ClientMessage::event(newer.clone())).await;
    let ok_newer = recv_value(&mut pubc).await;
    assert_eq!(ok_newer[0], "OK");
    assert!(
        ok_newer[2].as_bool().expect("newer accepted"),
        "newer must be accepted"
    );

    send_msg(&mut pubc, ClientMessage::event(stale.clone())).await;
    let ok_stale = recv_value(&mut pubc).await;
    assert_eq!(ok_stale[0], "OK");
    assert_eq!(
        ok_stale[2].as_bool(),
        Some(false),
        "stale must be rejected (OK false)"
    );
    assert_eq!(
        ok_stale[3].as_str(),
        Some("duplicate: replaced"),
        "stale must return the existing stale-rejection message"
    );

    // Live dispatch: only the newer winner reaches the subscriber.
    let seen = drain_events(&mut sub, Duration::from_millis(600)).await;
    let seen_ids: HashSet<String> = seen.iter().map(|e| e.id.to_hex()).collect();
    assert!(
        seen_ids.contains(&newer_id),
        "the newer winner must be hub-live-fanned-out to subscribers"
    );
    assert!(
        !seen_ids.contains(&stale_id),
        "the stale event must NOT be hub-live-fanned-out (dispatched): {seen_ids:?}"
    );

    // Gossip publish: newer published, stale never.
    let published = transport.published_ids().await;
    assert!(
        published.contains(&newer_id),
        "the newer winner must be gossip-published"
    );
    assert!(
        !published.contains(&stale_id),
        "the stale event must NOT be gossip-published: {published:?}"
    );

    // Newer winner stays queryable; the stale was never stored.
    let body = query(addr, json!([{ "authors": [author_pk], "kinds": [0] }])).await;
    let arr = body.as_array().expect("result array");
    let contents: Vec<&str> = arr.iter().filter_map(|e| e["content"].as_str()).collect();
    assert!(
        contents.contains(&"newer-metadata"),
        "newer winner must remain queryable"
    );
    assert!(
        !contents.contains(&"stale-metadata"),
        "stale event must not be stored/queryable: {contents:?}"
    );
}

// ---- HTTP door ------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_stale_replaceable_not_stored_published_or_dispatched() {
    let history = Arc::new(HistoryStore::open_in_memory("stale-http-fp").unwrap());
    let transport = Arc::new(RecordingTransport::new());
    let identity = Arc::new(RelayIdentity::ephemeral());
    let addr = spawn(
        Arc::clone(&history),
        Arc::clone(&transport),
        Arc::clone(&identity),
    )
    .await;

    let author = Keys::generate();
    let author_pk = author.public_key().to_hex();
    let newer = kind0(&author, "newer-metadata", 2_000_000_000);
    let stale = kind0(&author, "stale-metadata", 1_000_000_000);
    let newer_id = newer.id.to_hex();
    let stale_id = stale.id.to_hex();

    // Subscriber to observe live dispatch.
    let (mut sub, chal) = connect_with_challenge(addr).await;
    let sub_keys = Keys::generate();
    authenticate(&mut sub, &sub_keys, &chal).await;
    let filter =
        Filter::from_json(format!(r##"{{"kinds":[0],"authors":["{author_pk}"]}}"##)).unwrap();
    send_msg(
        &mut sub,
        ClientMessage::req(SubscriptionId::new("sub"), vec![filter]),
    )
    .await;
    let eose = recv_value(&mut sub).await;
    assert_eq!(eose[0], "EOSE");

    // POST the newer winner → accepted.
    let ack_newer = post_event(addr, &author_pk, &newer).await;
    assert_eq!(ack_newer["accepted"], json!(true), "newer must be accepted");

    // POST the stale loser → existing stale-rejection outcome.
    let ack_stale = post_event(addr, &author_pk, &stale).await;
    assert_eq!(
        ack_stale["accepted"],
        json!(false),
        "stale must be rejected with accepted:false"
    );
    assert_eq!(
        ack_stale["message"].as_str(),
        Some("duplicate: replaced"),
        "stale must return the existing stale-rejection message"
    );

    // Live dispatch: only the newer winner.
    let seen = drain_events(&mut sub, Duration::from_millis(600)).await;
    let seen_ids: HashSet<String> = seen.iter().map(|e| e.id.to_hex()).collect();
    assert!(seen_ids.contains(&newer_id), "newer must be dispatched");
    assert!(
        !seen_ids.contains(&stale_id),
        "stale must NOT be dispatched: {seen_ids:?}"
    );

    // Gossip publish: newer only.
    let published = transport.published_ids().await;
    assert!(published.contains(&newer_id), "newer must be published");
    assert!(
        !published.contains(&stale_id),
        "stale must NOT be published: {published:?}"
    );

    // Newer queryable; stale never stored.
    let body = query(addr, json!([{ "authors": [author_pk], "kinds": [0] }])).await;
    let contents: Vec<&str> = body
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|e| e["content"].as_str())
        .collect();
    assert!(contents.contains(&"newer-metadata"));
    assert!(
        !contents.contains(&"stale-metadata"),
        "stale must not be queryable: {contents:?}"
    );
}

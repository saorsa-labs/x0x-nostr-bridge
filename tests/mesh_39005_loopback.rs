//! Mesh-door (gossip-delivered) live 39005 fan-out: a reply arriving over the
//! x0x gossip fabric must produce a relay-signed kind-39005 dispatched to local
//! WS subscribers ONLY — never re-published to gossip (no fabric loopback).
//!
//! BridgeFinalReview finding: `ingest::ingest_one` (the mesh door) still called
//! `publish_to_topics(&transport, &overlay)` for the 39005 even after the local
//! door (`fan_out_emits`) was de-published. Red on the pre-fix bridge; green
//! once that publish line is dropped so the mesh door mirrors the local door.
//!
//! Wire-level: a reply is driven through the real gossip→ingest path (feedable
//! transport inbox → `ingest::ingest_one`), and the assertion observes a live WS
//! subscriber + the recorded gossip publishes — no internal-state coupling.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use nostr::{
    ClientMessage, Event, EventBuilder, Filter, JsonUtil, Keys, Kind, SubscriptionId, Tag, TagKind,
    Timestamp,
};
use serde_json::Value;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use x0x_nostr_bridge::engine_api::HistoryEngine;
use x0x_nostr_bridge::history::HistoryStore;
use x0x_nostr_bridge::history_adapter::{HistoryStoreEngine, HistoryStoreEventStore};
use x0x_nostr_bridge::ingest;
use x0x_nostr_bridge::kinds;
use x0x_nostr_bridge::proto;
use x0x_nostr_bridge::relay::{router, AppState};
use x0x_nostr_bridge::relay_identity::RelayIdentity;
use x0x_nostr_bridge::settings::Settings;
use x0x_nostr_bridge::store::EventStore;
use x0x_nostr_bridge::transport::{GossipMessage, GossipTransport};

type WS =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const CH: &str = "550e8400-e29b-41d4-a716-446655440000";

// ---- gossip transport that records publishes; the test owns the inbox -------//

struct FeedTransport {
    publishes: Mutex<Vec<(String, Vec<u8>)>>,
}

impl FeedTransport {
    fn new() -> Self {
        Self {
            publishes: Mutex::new(Vec::new()),
        }
    }
    async fn published(&self) -> Vec<(String, Vec<u8>)> {
        self.publishes.lock().await.clone()
    }
}

#[async_trait]
impl GossipTransport for FeedTransport {
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
    // The test drives its own (tx, rx) pair into `ingest::ingest_one`; the
    // trait inbox is never consumed here, so a fresh closed receiver suffices.
    fn inbox(&self) -> tokio::sync::mpsc::Receiver<GossipMessage> {
        tokio::sync::mpsc::channel(1).1
    }
}

fn payload_kind(payload: &[u8]) -> Option<u64> {
    serde_json::from_slice::<Value>(payload)
        .ok()
        .and_then(|v| v["kind"].as_u64())
}

async fn spawn(
    transport: Arc<FeedTransport>,
    identity: Arc<RelayIdentity>,
) -> (SocketAddr, Arc<AppState>) {
    let history = Arc::new(HistoryStore::open_in_memory("mesh-39005-fp").unwrap());
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
    let for_serve = Arc::clone(&state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(for_serve)).await;
    });
    (addr, state)
}

// ---- WS helpers (verbatim from the spike-pattern test suite) ---------------

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

fn build(keys: &Keys, kind: u16, content: &str, created_at: u64, tags: Vec<Tag>) -> Event {
    let mut b =
        EventBuilder::new(Kind::from(kind), content).custom_created_at(Timestamp::from(created_at));
    for t in tags {
        b = b.tag(t);
    }
    b.sign_with_keys(keys).unwrap()
}

fn auth_event_at(keys: &Keys, challenge: &str, ts: Timestamp) -> Event {
    EventBuilder::new(Kind::from(proto::AUTH_KIND), "")
        .custom_created_at(ts)
        .tag(Tag::custom(TagKind::custom("challenge"), [challenge]))
        .tag(Tag::custom(TagKind::custom("relay"), ["ws://127.0.0.1/"]))
        .sign_with_keys(keys)
        .unwrap()
}

// ---- the test --------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mesh_reply_39005_is_hub_dispatch_only_no_gossip_loopback() {
    let transport = Arc::new(FeedTransport::new());
    let identity = Arc::new(RelayIdentity::ephemeral());
    let relay_pk = identity.public_key_hex();
    let (addr, state) = spawn(Arc::clone(&transport), Arc::clone(&identity)).await;

    // Spawn the gossip→ingest loop on a feedable inbox the test controls.
    let (tx, rx) = tokio::sync::mpsc::channel::<GossipMessage>(16);
    let loop_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut rx = rx;
        while let Some(msg) = rx.recv().await {
            ingest::ingest_one(&loop_state, &msg).await;
        }
    });

    // Subscriber on the channel's kind-9 rows + kind-39005 summaries.
    let (mut sub, chal) = connect_with_challenge(addr).await;
    let sub_keys = Keys::generate();
    authenticate(&mut sub, &sub_keys, &chal).await;
    let filter = Filter::from_json(format!(r##"{{"kinds":[9,39005],"#h":["{CH}"]}}"##)).unwrap();
    send_msg(
        &mut sub,
        ClientMessage::req(SubscriptionId::new("sub"), vec![filter]),
    )
    .await;
    let eose = recv_value(&mut sub).await;
    assert_eq!(eose[0], "EOSE");

    let author = Keys::generate();
    let ts = 1_700_000_000u64;
    let root = build(
        &author,
        kinds::KIND_STREAM_MESSAGE,
        "mesh root",
        ts,
        vec![Tag::parse(["h", CH]).unwrap()],
    );
    let root_id = root.id.to_hex();
    let reply = build(
        &author,
        kinds::KIND_STREAM_MESSAGE,
        "mesh reply",
        ts + 10,
        vec![
            Tag::parse(["h", CH]).unwrap(),
            Tag::parse(["e", root_id.as_str(), "", "reply"]).unwrap(),
        ],
    );

    // Deliver root, then reply, over the gossip fabric (sequential ingest).
    let topic = proto::channel_topic(CH);
    tx.send(GossipMessage {
        topic: topic.clone(),
        payload: root.as_json().into_bytes(),
    })
    .await
    .unwrap();
    tx.send(GossipMessage {
        topic,
        payload: reply.as_json().into_bytes(),
    })
    .await
    .unwrap();

    // The mesh door must still fan the relay-signed 39005 to local subscribers.
    let summary = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let frame = recv_value(&mut sub).await;
            if frame[0] == "EVENT" {
                if let Ok(ev) = serde_json::from_value::<Event>(frame[2].clone()) {
                    if ev.kind.as_u16() == kinds::KIND_THREAD_SUMMARY {
                        return ev;
                    }
                }
            }
        }
    })
    .await
    .expect("timed out: subscriber never received the mesh-door kind-39005");

    // Hub-dispatched, relay-signed.
    assert!(summary.verify().is_ok(), "39005 signature must verify");
    assert_eq!(
        summary.pubkey.to_hex(),
        relay_pk,
        "39005 must be signed by the relay identity"
    );

    // NO fabric loopback: the overlay must not be re-published to gossip.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let published = transport.published().await;
    let looped = published
        .iter()
        .any(|(_, p)| payload_kind(p) == Some(u64::from(kinds::KIND_THREAD_SUMMARY)));
    assert!(
        !looped,
        "a mesh-delivered reply's 39005 must NOT be gossip-published (loopback): {published:?}"
    );
}

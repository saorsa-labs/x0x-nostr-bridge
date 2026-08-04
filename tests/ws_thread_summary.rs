//! Live thread-summary (kind 39005) fan-out over the NIP-42 WS door.
//!
//! Contract (locked with BridgeConformance): after a NIP-42-authenticated WS
//! `EVENT` reply (kind-9 with a marked `#e` root whose root already exists) is
//! stored, `handle_event` runs the existing `fan_out_emits`, which recomputes
//! `thread_summary(root)` and dispatches a relay-signed kind-39005 to every REQ
//! subscription that matches it — WITHOUT publishing the overlay to the gossip
//! fabric (zero self-loopback by construction: only `hub.dispatch`, never
//! `transport.publish` for the 39005). The original reply is still
//! gossip-published for cross-relay propagation.
//!
//! On the pre-change bridge these fail: the WS `EVENT` door routes through
//! `state.store.insert` (an `EventStore`) which discards the ingest emits, so
//! no 39005 is ever synthesized and the subscriber times out.

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
use serde_json::Value;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use x0x_nostr_bridge::engine_api::HistoryEngine;
use x0x_nostr_bridge::history::HistoryStore;
use x0x_nostr_bridge::history_adapter::{HistoryStoreEngine, HistoryStoreEventStore};
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

// ---- gossip transport that records every `publish` payload ---------------

struct RecordingTransport {
    publishes: Mutex<Vec<(String, Vec<u8>)>>,
}

impl RecordingTransport {
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
        // Disconnected inbox: nothing is fed back, so any loopback would have
        // to come from this transport's own `publish` — which is exactly what
        // the loopback assertion inspects.
        tokio::sync::mpsc::channel(1).1
    }
}

/// `kind` field of a gossip-published payload (`None` if the bytes are not a
/// parseable event object).
fn payload_kind(payload: &[u8]) -> Option<u64> {
    serde_json::from_slice::<Value>(payload)
        .ok()
        .and_then(|v| v["kind"].as_u64())
}

// ---- harness --------------------------------------------------------------

/// Spawn a relay backed by a real (in-memory) thread engine so 39005 synthesis
/// is exercised end-to-end. Returns the bound address; `transport` and
/// `identity` stay owned by the caller for post-hoc assertions.
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
    let url = format!("ws://{addr}");
    let (ws, _resp) = tokio_tungstenite::connect_async(url).await.unwrap();
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

/// Connect, read the AUTH challenge, return the socket + challenge string.
async fn connect_with_challenge(addr: SocketAddr) -> (WS, String) {
    let mut ws = connect(addr).await;
    let auth_msg = recv_value(&mut ws).await;
    assert_eq!(auth_msg[0], "AUTH", "expected AUTH challenge on connect");
    let challenge = auth_msg[1].as_str().expect("challenge str").to_string();
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
    assert!(ok[2].as_bool().expect("status bool"), "AUTH should succeed");
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

// ---- the test -------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_reply_fans_out_relay_signed_39005_without_gossip_loopback() {
    let history = Arc::new(HistoryStore::open_in_memory("ws-39005-fp").unwrap());
    let transport = Arc::new(RecordingTransport::new());
    let identity = Arc::new(RelayIdentity::ephemeral());
    let relay_pk = identity.public_key_hex();
    let addr = spawn(
        Arc::clone(&history),
        Arc::clone(&transport),
        Arc::clone(&identity),
    )
    .await;

    // --- subscriber: REQ the channel for kind-9 rows + kind-39005 summaries ---
    let (mut sub, chal) = connect_with_challenge(addr).await;
    let sub_keys = Keys::generate();
    authenticate(&mut sub, &sub_keys, &chal).await;
    let filter =
        Filter::from_json(format!(r##"{{"kinds":[9,39005],"#h":["{ch}"]}}"##, ch = CH)).unwrap();
    send_msg(
        &mut sub,
        ClientMessage::req(SubscriptionId::new("sub"), vec![filter]),
    )
    .await;
    let eose = recv_value(&mut sub).await;
    assert_eq!(eose[0], "EOSE", "REQ backfill must close with EOSE");

    // --- publisher: AUTH, then a top-level root message ---
    let (mut pubc, chal2) = connect_with_challenge(addr).await;
    let pub_keys = Keys::generate();
    authenticate(&mut pubc, &pub_keys, &chal2).await;

    let ts = 1_700_000_000u64;
    let root = build(
        &pub_keys,
        kinds::KIND_STREAM_MESSAGE,
        "thread root",
        ts,
        vec![Tag::parse(["h", CH]).unwrap()],
    );
    let root_id = root.id.to_hex();
    send_msg(&mut pubc, ClientMessage::event(root)).await;
    let ok = recv_value(&mut pubc).await;
    assert_eq!(ok[0], "OK");
    assert!(
        ok[2].as_bool().expect("root accepted"),
        "root must be accepted"
    );

    // A marked reply → the thread engine emits a 39005 for the root.
    let reply = build(
        &pub_keys,
        kinds::KIND_STREAM_MESSAGE,
        "first reply",
        ts + 10,
        vec![
            Tag::parse(["h", CH]).unwrap(),
            Tag::parse(["e", root_id.as_str(), "", "reply"]).unwrap(),
        ],
    );
    send_msg(&mut pubc, ClientMessage::event(reply)).await;
    let ok2 = recv_value(&mut pubc).await;
    assert_eq!(ok2[0], "OK");
    assert!(
        ok2[2].as_bool().expect("reply accepted"),
        "reply must be accepted (root exists)"
    );

    // --- await the relay-signed 39005 on the subscriber (3s, else red) ---
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
    .expect(
        "timed out: subscriber never received a relay-signed kind-39005 (WS live fan-out missing)",
    );

    // Signature + authorship: signed by the relay identity, never the publisher.
    assert!(summary.verify().is_ok(), "39005 signature must verify");
    assert_eq!(
        summary.pubkey.to_hex(),
        relay_pk,
        "39005 must be signed by the relay identity (NIP-11 self), not the publisher"
    );

    // Tags: exactly ["e",root], ["d",root], ["h",channel].
    let sv: Value = serde_json::from_str(&summary.as_json()).unwrap();
    let tagset: HashSet<(String, String)> = sv["tags"]
        .as_array()
        .expect("tags array")
        .iter()
        .map(|t| {
            (
                t[0].as_str().expect("tag name").to_string(),
                t.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string(),
            )
        })
        .collect();
    assert_eq!(tagset.len(), 3, "39005 must carry exactly e/d/h tags");
    assert!(
        tagset.contains(&("e".to_string(), root_id.clone())),
        "missing #e root tag"
    );
    assert!(
        tagset.contains(&("d".to_string(), root_id.clone())),
        "missing #d root tag (replaceable address)"
    );
    assert!(
        tagset.contains(&("h".to_string(), CH.to_string())),
        "missing #h channel tag"
    );

    // Content: the recomputed thread counters.
    let content: Value = serde_json::from_str(&summary.content).expect("content json");
    assert_eq!(
        content["reply_count"].as_u64(),
        Some(1),
        "reply_count must reflect the single direct reply"
    );
    assert_eq!(
        content["descendant_count"].as_u64(),
        Some(1),
        "descendant_count must reflect the single descendant"
    );
    assert!(
        content["last_reply_at"].as_u64().is_some(),
        "last_reply_at must be present for a replied root (null only when there are none)"
    );
    let participants = content["participants"]
        .as_array()
        .expect("participants array");
    assert!(
        participants
            .iter()
            .any(|p| p.as_str() == Some(&pub_keys.public_key().to_hex())),
        "participants must include the reply author"
    );

    // --- no gossip self-loopback: the 39005 overlay is dispatched to local
    //     subscribers ONLY, never published to the gossip fabric. The original
    //     reply IS still gossip-published (cross-relay propagation), which also
    //     proves the recording transport captured real publishes — so the
    //     absent-39005 assertion is non-vacuous. ---
    tokio::time::sleep(Duration::from_millis(150)).await;
    let published = transport.published().await;
    assert!(
        published
            .iter()
            .any(|(_, p)| payload_kind(p) == Some(u64::from(kinds::KIND_STREAM_MESSAGE))),
        "the original kind-9 reply must be gossip-published (proves the recording is non-vacuous)"
    );
    let looped: Vec<&(String, Vec<u8>)> = published
        .iter()
        .filter(|(_, p)| payload_kind(p) == Some(u64::from(kinds::KIND_THREAD_SUMMARY)))
        .collect();
    assert!(
        looped.is_empty(),
        "the kind-39005 overlay must NOT be gossip-published (self-loopback); found {} publish call(s)",
        looped.len()
    );
}

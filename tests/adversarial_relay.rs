//! Adversarial (red-team) tests for the x0x-nostr-bridge relay layer.
//!
//! Each test probes a specific review finding with a crafted request that MUST
//! be rejected/capped by a conformant relay. Written test-first: these fail
//! against the unfixed spike, then pass after the fixes.
//!
//! Findings covered:
//! - I1   REQ replace-at-cap (NIP-01: re-REQ existing sub id replaces, not CLOSED)
//! - M1   replaceable tie-break (equal created_at → lowest id wins, NIP-01)
//! - I3   topic-subscribe amplification (cap #h per REQ at 32, validate ids)
//! - I4   filter CPU-DoS (cap tag values/filter at 256, filters/REQ at 16)
//! - I5a  auth future-skew rejected (created_at > now + 60s)
//! - I5b  auth single-use (second AUTH on authed conn → NOTICE, key unchanged)
//! - I6   store error leak (generic "error: store failed", no internals)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use nostr::{
    Alphabet, ClientMessage, Event, EventBuilder, Filter, JsonUtil, Keys, Kind, RelayMessage,
    SingleLetterTag, SubscriptionId, Tag, TagKind, Timestamp,
};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use x0x_nostr_bridge::proto;
use x0x_nostr_bridge::relay::{router, AppState, Hub};
use x0x_nostr_bridge::store::{EventStore, InsertOutcome, SqliteStore};
use x0x_nostr_bridge::transport::{GossipMessage, GossipTransport};

type WS =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

// ===========================================================================
// In-memory fakes (counting / error) implementing the frozen traits.
// ===========================================================================

/// Records `ensure_topic` invocations + the topics seen.
struct CountingTransport {
    ensure_calls: AtomicUsize,
    topics: Mutex<Vec<String>>,
}

impl CountingTransport {
    fn new() -> Self {
        Self {
            ensure_calls: AtomicUsize::new(0),
            topics: Mutex::new(Vec::new()),
        }
    }
    fn ensure_count(&self) -> usize {
        self.ensure_calls.load(Ordering::SeqCst)
    }
    async fn topics_snapshot(&self) -> Vec<String> {
        self.topics.lock().await.clone()
    }
}

#[async_trait]
impl GossipTransport for CountingTransport {
    async fn ensure_topic(&self, topic: &str) -> anyhow::Result<()> {
        self.ensure_calls.fetch_add(1, Ordering::SeqCst);
        self.topics.lock().await.push(topic.to_string());
        Ok(())
    }
    async fn publish(&self, _topic: &str, _payload: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
    fn inbox(&self) -> mpsc::Receiver<GossipMessage> {
        mpsc::channel(1).1
    }
}

/// No-op transport for tests that don't inspect gossip.
struct FakeTransport;

#[async_trait]
impl GossipTransport for FakeTransport {
    async fn ensure_topic(&self, _topic: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn publish(&self, _topic: &str, _payload: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
    fn inbox(&self) -> mpsc::Receiver<GossipMessage> {
        mpsc::channel(1).1
    }
}

/// Store whose `insert` always fails with an internal-looking error, so we can
/// assert the relay does NOT echo it back to the client.
struct ErrorStore;

#[async_trait]
impl EventStore for ErrorStore {
    async fn insert(&self, _ev: &Event) -> anyhow::Result<InsertOutcome> {
        Err(anyhow::anyhow!(
            "internal sqlite disk I/O error: no such table: events_xyz"
        ))
    }
    async fn query(&self, _filter: &Filter) -> anyhow::Result<Vec<Event>> {
        Ok(Vec::new())
    }
    async fn known_channels(&self) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }
}

/// Store that counts `query` calls and the total generic-tag value count per
/// call — a seam for observing how many tag values the store actually receives.
struct CountingStore {
    query_calls: AtomicUsize,
    tag_sizes: Mutex<Vec<usize>>,
}

impl CountingStore {
    fn new() -> Self {
        Self {
            query_calls: AtomicUsize::new(0),
            tag_sizes: Mutex::new(Vec::new()),
        }
    }
    /// (query call count, max total tag values across all calls)
    async fn snapshot(&self) -> (usize, usize) {
        let sizes = self.tag_sizes.lock().await;
        let max = sizes.iter().copied().max().unwrap_or(0);
        (self.query_calls.load(Ordering::SeqCst), max)
    }
}

#[async_trait]
impl EventStore for CountingStore {
    async fn insert(&self, _ev: &Event) -> anyhow::Result<InsertOutcome> {
        Ok(InsertOutcome::Inserted)
    }
    async fn query(&self, filter: &Filter) -> anyhow::Result<Vec<Event>> {
        self.query_calls.fetch_add(1, Ordering::SeqCst);
        let total: usize = filter.generic_tags.values().map(|v| v.len()).sum();
        self.tag_sizes.lock().await.push(total);
        Ok(Vec::new())
    }
    async fn known_channels(&self) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }
}

// ===========================================================================
// Harness
// ===========================================================================

fn make_state(store: Arc<dyn EventStore>, transport: Arc<dyn GossipTransport>) -> Arc<AppState> {
    Arc::new(AppState::with_defaults(store, transport))
}

async fn spawn(state: Arc<AppState>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    addr
}

async fn spawn_with(store: Arc<dyn EventStore>, transport: Arc<dyn GossipTransport>) -> SocketAddr {
    spawn(make_state(store, transport)).await
}

async fn connect(addr: SocketAddr) -> WS {
    let url = format!("ws://{addr}");
    let (ws, _resp) = tokio_tungstenite::connect_async(url).await.unwrap();
    ws
}

async fn recv_value(ws: &mut WS) -> serde_json::Value {
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

/// Connect, read the AUTH challenge, return the socket + the challenge string.
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

/// Mirror of the relay's channel-id validation, for asserting no invalid id was
/// ever subscribed.
fn is_valid_channel_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
}

// ===========================================================================
// I1 — REQ replace-at-cap (NIP-01 conformance)
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i1_req_replace_at_cap_replaces_existing_not_closed() {
    let hub = Hub::new();
    let conn = hub.next_conn_id();
    let (tx, _rx) = mpsc::channel::<RelayMessage<'static>>(16);

    // Register the maximum number of subscriptions.
    for i in 0..proto::MAX_SUBS_PER_CONN {
        let id = format!("sub{i}");
        assert!(
            hub.register(conn, &id, vec![Filter::new()], tx.clone()),
            "register #{i} must succeed under cap"
        );
    }
    assert_eq!(hub.sub_count(conn), proto::MAX_SUBS_PER_CONN);

    // Re-REQ an EXISTING sub id while at cap → REPLACE (true), count unchanged.
    assert!(
        hub.register(
            conn,
            "sub0",
            vec![Filter::new().kind(Kind::from(9u16))],
            tx.clone()
        ),
        "re-REQ of an existing sub id at cap must replace, not CLOSED"
    );
    assert_eq!(
        hub.sub_count(conn),
        proto::MAX_SUBS_PER_CONN,
        "replace must not grow the sub count"
    );

    // REQ a NEW sub id while at cap → rejected (false → CLOSED by the relay).
    assert!(
        !hub.register(conn, "brand-new-sub", vec![Filter::new()], tx.clone()),
        "a NEW sub id at cap must be rejected"
    );
    assert_eq!(hub.sub_count(conn), proto::MAX_SUBS_PER_CONN);
}

// ===========================================================================
// M1 — replaceable tie-break: equal created_at → lowest id wins (NIP-01)
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m1_replaceable_equal_timestamp_keeps_lowest_id() {
    let k = Keys::generate();
    let ts = 1_700_000_000u64;
    // Same pubkey, kind 0, same timestamp, distinct content → distinct ids.
    let a = build(&k, 0, "content-a", ts, vec![]);
    let b = build(&k, 0, "content-b", ts, vec![]);
    assert_ne!(a.id, b.id);
    let (lower, higher) = if a.id < b.id { (a, b) } else { (b, a) };

    // Order 1: higher-id first, then lower-id → lower-id wins (Replaced).
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(&dir.path().join("m1a.db")).unwrap();
    assert_eq!(
        store.insert(&higher).await.unwrap(),
        InsertOutcome::Inserted
    );
    assert_eq!(
        store.insert(&lower).await.unwrap(),
        InsertOutcome::Replaced,
        "equal-timestamp lower-id must replace the higher-id stored event"
    );
    let got = store
        .query(&Filter::new().author(k.public_key()))
        .await
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0].id, lower.id,
        "tie must keep lowest id (insertion: higher-then-lower)"
    );

    // Order 2: lower-id first, then higher-id → lower stays (StaleRejected).
    let dir2 = tempfile::tempdir().unwrap();
    let store2 = SqliteStore::open(&dir2.path().join("m1b.db")).unwrap();
    assert_eq!(
        store2.insert(&lower).await.unwrap(),
        InsertOutcome::Inserted
    );
    assert_eq!(
        store2.insert(&higher).await.unwrap(),
        InsertOutcome::StaleRejected,
        "equal-timestamp higher-id must be rejected when lower-id is stored"
    );
    let got2 = store2
        .query(&Filter::new().author(k.public_key()))
        .await
        .unwrap();
    assert_eq!(got2.len(), 1);
    assert_eq!(
        got2[0].id, lower.id,
        "tie must keep lowest id (insertion: lower-then-higher)"
    );
}

// ===========================================================================
// I3 — topic-subscribe amplification: cap #h per REQ at 32, validate ids
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i3_topic_subscribe_amplification_capped_and_validated() {
    let transport = Arc::new(CountingTransport::new());
    let store: Arc<dyn EventStore> = Arc::new(CountingStore::new());
    let addr = spawn_with(store, Arc::clone(&transport) as Arc<dyn GossipTransport>).await;

    let keys = Keys::generate();
    let (mut ws, challenge) = connect_with_challenge(addr).await;
    authenticate(&mut ws, &keys, &challenge).await;

    // 500 #h values: many valid + several invalid ids.
    let mut h_vals: Vec<String> = (0..400).map(|i| format!("channel-{i:03x}")).collect();
    h_vals.push("../x".to_string()); // invalid: contains '/'
    h_vals.push("A".repeat(200)); // invalid: uppercase + too long
    h_vals.push(String::new()); // invalid: empty
    h_vals.push("bad space".to_string()); // invalid: space
    while h_vals.len() < 500 {
        h_vals.push(format!("extra-{}", h_vals.len()));
    }
    let filter = Filter::new().custom_tags(SingleLetterTag::lowercase(Alphabet::H), h_vals);

    send_msg(
        &mut ws,
        ClientMessage::req(SubscriptionId::new("amp"), vec![filter]),
    )
    .await;
    let eose = recv_value(&mut ws).await;
    assert_eq!(eose[0], "EOSE", "REQ must still complete with EOSE");

    // Let the fire-and-forget ensure_topic tasks flush.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let count = transport.ensure_count();
    assert!(
        count <= 32,
        "ensure_topic called {count} times; a REQ must subscribe at most 32 channels"
    );
    let topics = transport.topics_snapshot().await;
    for t in &topics {
        let id = t.strip_prefix("buzz.v1.ch.").unwrap_or(t);
        assert!(
            is_valid_channel_id(id),
            "an invalid channel id was subscribed: {t}"
        );
    }
}

// ===========================================================================
// I4 — filter CPU-DoS: cap tag values/filter at 256, filters/REQ at 16
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i4_filter_cpu_dosc_capped() {
    // Phase A: one filter carrying 10_000 #e values → store sees ≤ 256.
    {
        let store = Arc::new(CountingStore::new());
        let transport: Arc<dyn GossipTransport> = Arc::new(FakeTransport);
        let addr = spawn_with(Arc::clone(&store) as Arc<dyn EventStore>, transport).await;
        let keys = Keys::generate();
        let (mut ws, challenge) = connect_with_challenge(addr).await;
        authenticate(&mut ws, &keys, &challenge).await;

        // 5_000 short values: far above the 256 cap yet well within the
        // 65_536-byte WebSocket frame limit (the relay truncates *after*
        // receipt, so the client must still be able to send the full set).
        let e_vals: Vec<String> = (0..5_000).map(|i| format!("e{i}")).collect();
        let filter = Filter::new().custom_tags(SingleLetterTag::lowercase(Alphabet::E), e_vals);
        send_msg(
            &mut ws,
            ClientMessage::req(SubscriptionId::new("dosc"), vec![filter]),
        )
        .await;
        let eose = recv_value(&mut ws).await;
        assert_eq!(
            eose[0], "EOSE",
            "query must still complete with a huge tag set"
        );

        let (_calls, max_tags) = store.snapshot().await;
        assert!(
            max_tags <= 256,
            "store received {max_tags} tag values for one filter; expected ≤ 256"
        );
    }

    // Phase B: 20 filters → at most 16 honored (≤ 16 query calls).
    {
        let store = Arc::new(CountingStore::new());
        let transport: Arc<dyn GossipTransport> = Arc::new(FakeTransport);
        let addr = spawn_with(Arc::clone(&store) as Arc<dyn EventStore>, transport).await;
        let keys = Keys::generate();
        let (mut ws, challenge) = connect_with_challenge(addr).await;
        authenticate(&mut ws, &keys, &challenge).await;

        let filters: Vec<Filter> = (0..20)
            .map(|i| Filter::new().kind(Kind::from((i % 4) as u16)))
            .collect();
        send_msg(
            &mut ws,
            ClientMessage::req(SubscriptionId::new("many"), filters),
        )
        .await;
        let eose = recv_value(&mut ws).await;
        assert_eq!(eose[0], "EOSE");

        let (calls, _max_tags) = store.snapshot().await;
        assert!(
            calls <= 16,
            "store.query invoked {calls} times for a 20-filter REQ; expected ≤ 16"
        );
    }
}

// ===========================================================================
// I5a — auth future-skew rejected (created_at > now + 60s)
// ===========================================================================

#[test]
fn i5a_auth_window_future_skew_rejected_past_window_kept() {
    let keys = Keys::generate();
    let now = Timestamp::now();
    let challenge = "challenge-token-abc";

    // +300s future → must be rejected (beyond the 60s future-skew allowance).
    let future = Timestamp::from(now.as_secs() + 300);
    let ev = auth_event_at(&keys, challenge, future);
    assert!(
        proto::verify_auth_event(&ev, challenge, now, None).is_err(),
        "auth event +300s in the future must be rejected"
    );

    // +30s future → accepted (within the 60s allowance).
    let near = Timestamp::from(now.as_secs() + 30);
    let ev_near = auth_event_at(&keys, challenge, near);
    assert!(
        proto::verify_auth_event(&ev_near, challenge, now, None).is_ok(),
        "auth event +30s future (within allowance) must be accepted"
    );

    // -500s past → accepted (within the 600s past window).
    let past = Timestamp::from(now.as_secs().saturating_sub(500));
    let ev_past = auth_event_at(&keys, challenge, past);
    assert!(
        proto::verify_auth_event(&ev_past, challenge, now, None).is_ok(),
        "auth event -500s past (within window) must be accepted"
    );

    // -700s past → rejected (beyond the 600s window).
    let stale = Timestamp::from(now.as_secs().saturating_sub(700));
    let ev_stale = auth_event_at(&keys, challenge, stale);
    assert!(
        proto::verify_auth_event(&ev_stale, challenge, now, None).is_err(),
        "auth event -700s past must be rejected"
    );
}

// ===========================================================================
// I5b — auth single-use: second AUTH on an authed conn is ignored
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i5b_auth_single_use_second_key_ignored() {
    let store: Arc<dyn EventStore> = Arc::new(CountingStore::new());
    let transport: Arc<dyn GossipTransport> = Arc::new(FakeTransport);
    let addr = spawn_with(store, transport).await;

    let keys1 = Keys::generate();
    let (mut ws, challenge) = connect_with_challenge(addr).await;
    // First AUTH (keys1) succeeds.
    authenticate(&mut ws, &keys1, &challenge).await;

    // Second AUTH with a DIFFERENT key → NOTICE "already authed" (not OK).
    let keys2 = Keys::generate();
    send_msg(
        &mut ws,
        ClientMessage::auth(auth_event_at(&keys2, &challenge, Timestamp::now())),
    )
    .await;
    let notice = recv_value(&mut ws).await;
    assert_eq!(
        notice[0], "NOTICE",
        "second AUTH on an authed conn must yield NOTICE, not OK"
    );
    assert_eq!(
        notice[1], "already authed",
        "second AUTH must be answered with NOTICE 'already authed'"
    );

    // The authed pubkey must be unchanged (still keys1): an EVENT from keys1 is
    // accepted, an EVENT from keys2 is rejected.
    let ev1 = build(
        &keys1,
        1,
        "from-first-key",
        Timestamp::now().as_secs(),
        vec![],
    );
    send_msg(&mut ws, ClientMessage::event(ev1)).await;
    let ok1 = recv_value(&mut ws).await;
    assert_eq!(
        ok1[2], true,
        "event from the original authed key must succeed"
    );

    let ev2 = build(
        &keys2,
        1,
        "from-second-key",
        Timestamp::now().as_secs(),
        vec![],
    );
    send_msg(&mut ws, ClientMessage::event(ev2)).await;
    let ok2 = recv_value(&mut ws).await;
    assert_eq!(ok2[2], false, "event from the second key must be rejected");
    let msg2 = ok2[3].as_str().expect("msg");
    assert!(
        msg2.contains("not signed by"),
        "rejection reason should indicate key mismatch, got: {msg2}"
    );
}

// ===========================================================================
// I6 — store error leak: generic message, no internals
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i6_store_error_does_not_leak_internals() {
    let store: Arc<dyn EventStore> = Arc::new(ErrorStore);
    let transport: Arc<dyn GossipTransport> = Arc::new(FakeTransport);
    let addr = spawn_with(store, transport).await;

    let keys = Keys::generate();
    let (mut ws, challenge) = connect_with_challenge(addr).await;
    authenticate(&mut ws, &keys, &challenge).await;

    let ev = build(
        &keys,
        1,
        "will-fail-store",
        Timestamp::now().as_secs(),
        vec![],
    );
    let id = ev.id;
    send_msg(&mut ws, ClientMessage::event(ev)).await;
    let ok = recv_value(&mut ws).await;
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[1], id.to_hex());
    assert_eq!(ok[2], false, "store failure must report OK false");
    let msg = ok[3].as_str().expect("message");
    assert_eq!(
        msg, "error: store failed",
        "client must receive a generic message, got: {msg}"
    );
    // And it must not leak the internal error text.
    assert!(
        !msg.contains("sqlite") && !msg.contains("disk") && !msg.contains("table"),
        "message leaked store internals: {msg}"
    );
}

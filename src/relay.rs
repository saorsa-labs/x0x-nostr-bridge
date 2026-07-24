//! Nostr relay WebSocket layer + fan-out hub. Owner: RelayAgent.
//!
//! Contract (FROZEN):
//! - `router(state)` builds the axum Router: GET "/" upgrades to WebSocket
//!   (max frame proto::MAX_FRAME_BYTES); when the request Accept header is
//!   `application/nostr+json` (and no upgrade), serve a minimal NIP-11 doc.
//! - Connection flow mirrors buzz-relay:
//!   1. On connect: allocate ConnId, send `["AUTH", <challenge>]` (uuid v4).
//!   2. Unauthenticated EVENT/REQ → rejected (OK false "auth-required: …" /
//!      CLOSED "auth-required: …").
//!   3. AUTH: proto::verify_auth_event; on success record pubkey, reply
//!      `["OK", <id>, true, ""]`. (OK for AUTH is a UX choice, not NIP-42.)
//!   4. EVENT: authed; event.pubkey == authed pubkey; kind != 22242;
//!      proto::verify_event. On success: unless ephemeral, store.insert;
//!      transport.publish to each proto::topics_for_event (after
//!      ensure_topic); Hub::dispatch when Inserted/Replaced (ephemeral:
//!      always dispatch, never store/publish… ephemeral IS published to
//!      gossip but never stored). Reply OK true/false with message.
//!   5. REQ: authed; sub count < proto::MAX_SUBS_PER_CONN; register sub in
//!      Hub FIRST (live events may duplicate with the initial dump — NIP-01
//!      clients tolerate this); then for each filter store.query → EVENT
//!      frames; then EOSE. For every proto::filter_channels value call
//!      transport.ensure_topic(proto::channel_topic(..)) (fire-and-forget).
//!   6. CLOSE: unregister sub.
//! - Outbound frames go through a bounded mpsc (proto::SEND_QUEUE) to a
//!   writer task; Hub::dispatch applies slow-consumer strikes internally.
//! - Non-text frames: ping/pong handled by axum; binary frames ignored.
//! - Malformed JSON → NOTICE "error: bad message". Unknown verbs → NOTICE.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use nostr::filter::MatchEventOptions;
use nostr::{
    ClientMessage, Event, Filter, JsonUtil, PublicKey, RelayMessage, SubscriptionId, Timestamp,
};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::proto;
use crate::store::{EventStore, InsertOutcome};
use crate::transport::GossipTransport;

pub type ConnId = u64;

struct SubEntry {
    filters: Vec<Filter>,
    tx: mpsc::Sender<RelayMessage<'static>>,
    strikes: u32,
}

/// Subscription registry + fan-out. Slow-consumer policy: a full send queue
/// increments the sub's strike counter; after proto::SLOW_CLIENT_GRACE
/// consecutive full queues the connection's subs are dropped (documented
/// spike simplification of buzz-relay's connection cancel).
pub struct Hub {
    subs: DashMap<ConnId, DashMap<String, SubEntry>>,
    next_conn: AtomicU64,
}

impl Hub {
    pub fn new() -> Self {
        Self {
            subs: DashMap::new(),
            next_conn: AtomicU64::new(1),
        }
    }

    pub fn next_conn_id(&self) -> ConnId {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    /// Register (or replace) a subscription. Returns `false` only when a NEW
    /// sub id would exceed `proto::MAX_SUBS_PER_CONN`. Re-REQ of an EXISTING
    /// sub id replaces its filter set in place (NIP-01) — it never counts
    /// against the cap, and resets the slow-consumer strike counter.
    pub fn register(
        &self,
        conn: ConnId,
        sub_id: &str,
        filters: Vec<Filter>,
        tx: mpsc::Sender<RelayMessage<'static>>,
    ) -> bool {
        let conns = self.subs.entry(conn).or_default();
        // A re-REQ of an existing sub id REPLACES its filter set (NIP-01); only
        // genuinely new ids are counted against the per-connection cap.
        let is_new = !conns.contains_key(sub_id);
        if is_new && conns.len() >= proto::MAX_SUBS_PER_CONN {
            return false;
        }
        conns.insert(
            sub_id.to_string(),
            SubEntry {
                filters,
                tx,
                strikes: 0,
            },
        );
        true
    }

    pub fn unregister_sub(&self, conn: ConnId, sub_id: &str) {
        if let Some(conns) = self.subs.get(&conn) {
            conns.remove(sub_id);
        }
    }

    pub fn unregister_conn(&self, conn: ConnId) {
        self.subs.remove(&conn);
    }

    /// Contract API — consumed by e2e tests, not by the binary itself.
    #[allow(dead_code)]
    pub fn sub_count(&self, conn: ConnId) -> usize {
        self.subs.get(&conn).map(|c| c.len()).unwrap_or(0)
    }

    /// Fan out to matching subs (nostr `Filter::match_event`). Returns the
    /// number of successful deliveries (used by tests + metrics). A full send
    /// queue increments the sub's strike count; a dead receiver, or
    /// `proto::SLOW_CLIENT_GRACE` consecutive full queues, drops ALL subs of
    /// that connection.
    pub fn dispatch(&self, ev: &Event) -> usize {
        let opts = MatchEventOptions::default();
        let mut delivered: usize = 0;
        let mut slow_conns: Vec<ConnId> = Vec::new();

        for map_ref in self.subs.iter() {
            let conn = *map_ref.key();
            let conns = map_ref.value();
            for mut sub_ref in conns.iter_mut() {
                let sub_id = sub_ref.key().clone();
                let sub = sub_ref.value_mut();
                let matches = sub.filters.iter().any(|f| f.match_event(ev, opts));
                if !matches {
                    continue;
                }
                let msg = RelayMessage::event(SubscriptionId::new(sub_id), ev.clone());
                match sub.tx.try_send(msg) {
                    Ok(()) => {
                        sub.strikes = 0;
                        delivered += 1;
                    }
                    Err(TrySendError::Full(_)) => {
                        sub.strikes = sub.strikes.saturating_add(1);
                        if sub.strikes >= proto::SLOW_CLIENT_GRACE {
                            slow_conns.push(conn);
                        }
                    }
                    Err(TrySendError::Closed(_)) => slow_conns.push(conn),
                }
            }
        }

        // Now that every DashMap guard has been released, drop the subs of
        // any connection that tripped the slow/dead policy.
        slow_conns.sort_unstable();
        slow_conns.dedup();
        for conn in slow_conns {
            self.subs.remove(&conn);
        }

        delivered
    }
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AppState {
    pub store: Arc<dyn EventStore>,
    pub transport: Arc<dyn GossipTransport>,
    pub hub: Hub,
}

/// Build the axum router: a single GET "/" that either upgrades to a
/// WebSocket (max frame `proto::MAX_FRAME_BYTES`), serves a NIP-11 info doc
/// (Accept: `application/nostr+json`), or returns 426 Upgrade Required.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(root_handler))
        .with_state(state)
}

async fn root_handler(
    State(state): State<Arc<AppState>>,
    upgrade: Option<WebSocketUpgrade>,
    headers: HeaderMap,
) -> Response {
    if let Some(ws) = upgrade {
        return ws
            .max_message_size(proto::MAX_FRAME_BYTES)
            .max_frame_size(proto::MAX_FRAME_BYTES)
            .on_upgrade(move |socket| handle_connection(state, socket));
    }
    if is_nip11(&headers) {
        return nip11_response();
    }
    // Not a WebSocket upgrade and not a NIP-11 doc request.
    StatusCode::UPGRADE_REQUIRED.into_response()
}

fn is_nip11(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .any(|m| m.trim().eq_ignore_ascii_case("application/nostr+json"))
        })
        .unwrap_or(false)
}

fn nip11_response() -> Response {
    let body = serde_json::json!({
        "name": "x0x-nostr-bridge",
        "description": "Nostr relay facade over x0x gossip",
        "supported_nips": [1, 11, 16, 42, 50],
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/nostr+json")],
        body.to_string(),
    )
        .into_response()
}

/// Per-connection task: issue the NIP-42 challenge, spawn a writer that drains
/// the bounded outbound channel into the socket, and run the read loop that
/// dispatches each client message through the gates.
async fn handle_connection(state: Arc<AppState>, socket: WebSocket) {
    let conn_id = state.hub.next_conn_id();
    let challenge = uuid::Uuid::new_v4().to_string();
    let (tx, mut rx) = mpsc::channel::<RelayMessage<'static>>(proto::SEND_QUEUE);

    let (mut sink, mut stream) = socket.split();

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let frame = Message::Text(msg.as_json());
            if sink.send(frame).await.is_err() {
                break;
            }
        }
    });

    // NIP-42: challenge immediately on connect.
    let _ = tx.send(RelayMessage::auth(challenge.clone())).await;

    let mut authed: Option<PublicKey> = None;
    while let Some(frame) = stream.next().await {
        match frame {
            Ok(Message::Text(text)) => {
                handle_text(&state, &tx, conn_id, &challenge, &mut authed, text).await;
            }
            Ok(Message::Binary(_)) => { /* ignored: non-text frames */ }
            Ok(Message::Ping(_) | Message::Pong(_)) => { /* handled by axum/tungstenite */ }
            Ok(Message::Close(_)) | Err(_) => break,
        }
    }

    // Disconnect: stop accepting new subs and let the writer flush + exit.
    drop(tx);
    state.hub.unregister_conn(conn_id);
    let _ = writer.await;
}

async fn handle_text(
    state: &Arc<AppState>,
    tx: &mpsc::Sender<RelayMessage<'static>>,
    conn_id: ConnId,
    challenge: &str,
    authed: &mut Option<PublicKey>,
    text: String,
) {
    let msg = match ClientMessage::from_json(&text) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(error = %e, "failed to parse client message");
            let _ = tx.send(RelayMessage::notice("error: bad message")).await;
            return;
        }
    };

    match msg {
        ClientMessage::Auth(ev) => {
            let ev = ev.into_owned();
            // Challenges are single-use: once a connection is authenticated
            // the authed pubkey is fixed, and further AUTH messages are
            // ignored (NOTICE) rather than re-binding the identity.
            if authed.is_some() {
                let _ = tx.send(RelayMessage::notice("already authed")).await;
            } else {
                match proto::verify_auth_event(&ev, challenge, Timestamp::now()) {
                    Ok(()) => {
                        *authed = Some(ev.pubkey);
                        let _ = tx.send(RelayMessage::ok(ev.id, true, "")).await;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "auth event rejected");
                        let _ = tx
                            .send(RelayMessage::ok(ev.id, false, "invalid: auth"))
                            .await;
                    }
                }
            }
        }
        ClientMessage::Event(ev) => {
            let ev = ev.into_owned();
            handle_event(state, tx, authed, ev).await;
        }
        ClientMessage::Req {
            subscription_id,
            filters,
        } => {
            let sub_id = subscription_id.into_owned();
            let filters: Vec<Filter> = filters.into_iter().map(|f| f.into_owned()).collect();
            handle_req(state, tx, conn_id, authed, sub_id, filters).await;
        }
        ClientMessage::Close(sub_id) => {
            state.hub.unregister_sub(conn_id, sub_id.as_str());
        }
        // NIP-45 (COUNT) and the negentropy family are out of scope for the
        // spike; signal unsupported rather than silently dropping the request.
        ClientMessage::Count { .. }
        | ClientMessage::NegOpen { .. }
        | ClientMessage::NegMsg { .. }
        | ClientMessage::NegClose { .. } => {
            let _ = tx.send(RelayMessage::notice("unsupported")).await;
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn handle_event(
    state: &Arc<AppState>,
    tx: &mpsc::Sender<RelayMessage<'static>>,
    authed: &Option<PublicKey>,
    ev: Event,
) {
    let Some(authed_pk) = authed.as_ref() else {
        let _ = tx
            .send(RelayMessage::ok(
                ev.id,
                false,
                "auth-required: please AUTH first",
            ))
            .await;
        return;
    };
    if ev.pubkey != *authed_pk {
        let _ = tx
            .send(RelayMessage::ok(
                ev.id,
                false,
                "invalid: event not signed by the authenticated key",
            ))
            .await;
        return;
    }
    if ev.kind.as_u16() == proto::AUTH_KIND {
        let _ = tx
            .send(RelayMessage::ok(
                ev.id,
                false,
                "invalid: auth kind is not publishable",
            ))
            .await;
        return;
    }
    if let Err(e) = proto::verify_event(&ev) {
        tracing::debug!(error = %e, "event verification failed");
        let _ = tx
            .send(RelayMessage::ok(
                ev.id,
                false,
                "invalid: bad id or signature",
            ))
            .await;
        return;
    }

    if proto::is_ephemeral(ev.kind) {
        // Ephemeral kinds: gossip + live fan-out, never stored.
        publish_to_topics(&state.transport, &ev).await;
        state.hub.dispatch(&ev);
        let _ = tx.send(RelayMessage::ok(ev.id, true, "")).await;
        return;
    }

    match state.store.insert(&ev).await {
        Ok(InsertOutcome::Inserted | InsertOutcome::Replaced) => {
            publish_to_topics(&state.transport, &ev).await;
            state.hub.dispatch(&ev);
            let _ = tx.send(RelayMessage::ok(ev.id, true, "")).await;
        }
        Ok(InsertOutcome::Duplicate) => {
            let _ = tx.send(RelayMessage::ok(ev.id, true, "duplicate:")).await;
        }
        Ok(InsertOutcome::StaleRejected) => {
            let _ = tx
                .send(RelayMessage::ok(ev.id, false, "duplicate: replaced"))
                .await;
        }
        Err(e) => {
            // Log the full internal detail server-side; echo only a generic
            // message so the client cannot probe store internals (SQL errors,
            // filesystem paths, etc.).
            tracing::warn!(error = %e, "store insert failed");
            let _ = tx
                .send(RelayMessage::ok(ev.id, false, "error: store failed"))
                .await;
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn handle_req(
    state: &Arc<AppState>,
    tx: &mpsc::Sender<RelayMessage<'static>>,
    conn_id: ConnId,
    authed: &Option<PublicKey>,
    sub_id: SubscriptionId,
    filters: Vec<Filter>,
) {
    if authed.is_none() {
        let _ = tx
            .send(RelayMessage::closed(
                sub_id,
                "auth-required: please AUTH first",
            ))
            .await;
        return;
    }

    // CPU-DoS hardening: cap filters per REQ and truncate each filter's
    // generic-tag value sets BEFORE registration or querying.
    let filters = sanitize_req_filters(filters);

    // Register FIRST so live events interleave with the initial dump; NIP-01
    // clients tolerate duplicates between the dump and the live stream.
    if !state
        .hub
        .register(conn_id, sub_id.as_str(), filters.clone(), tx.clone())
    {
        let _ = tx
            .send(RelayMessage::closed(
                sub_id,
                "error: too many subscriptions",
            ))
            .await;
        return;
    }

    // Fire-and-forget channel topic subscriptions: validate channel ids,
    // de-duplicate, and cap at MAX_REQ_CHANNELS (topic-subscribe amplification).
    // Invalid ids never reach ensure_topic.
    for topic in req_channel_topics(&filters) {
        let transport = Arc::clone(&state.transport);
        tokio::spawn(async move {
            if let Err(e) = transport.ensure_topic(&topic).await {
                tracing::debug!(error = %e, %topic, "ensure_topic (req) failed");
            }
        });
    }

    // Initial dump: stored events for each filter, then EOSE.
    for f in &filters {
        match state.store.query(f).await {
            Ok(events) => {
                for ev in events {
                    let _ = tx.send(RelayMessage::event(sub_id.clone(), ev)).await;
                }
            }
            Err(e) => tracing::warn!(error = %e, "store query failed"),
        }
    }

    let _ = tx.send(RelayMessage::eose(sub_id)).await;
}

/// Max #h channel subscriptions ensured per REQ (topic-subscribe amplification).
const MAX_REQ_CHANNELS: usize = 32;
/// Max generic-tag values kept per tag key per filter (CPU-DoS protection).
const MAX_FILTER_TAGS: usize = 256;
/// Max filters honored per REQ; excess silently ignored.
const MAX_REQ_FILTERS: usize = 16;

/// Cap filters per REQ at `MAX_REQ_FILTERS` and truncate each filter's
/// generic-tag value sets to `MAX_FILTER_TAGS` per tag key (CPU-DoS).
fn sanitize_req_filters(filters: Vec<Filter>) -> Vec<Filter> {
    filters
        .into_iter()
        .take(MAX_REQ_FILTERS)
        .map(|mut f| {
            for values in f.generic_tags.values_mut() {
                if values.len() > MAX_FILTER_TAGS {
                    let kept: std::collections::BTreeSet<String> =
                        values.iter().take(MAX_FILTER_TAGS).cloned().collect();
                    *values = kept;
                }
            }
            f
        })
        .collect()
}

/// Validate a Buzz channel id: lowercase alphanumeric plus '-', '_', '.';
/// length 1..=64 (Buzz uuids fit). Invalid ids are dropped before topic
/// subscription (they must not reach `ensure_topic`).
fn is_valid_channel_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
}

/// Channel topics to subscribe for a REQ: validated, de-duplicated, and capped
/// at `MAX_REQ_CHANNELS`. Returns the gossip topics (one per unique valid
/// channel) so the caller spawns exactly one `ensure_topic` per topic.
fn req_channel_topics(filters: &[Filter]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for f in filters {
        for ch in proto::filter_channels(f) {
            if out.len() >= MAX_REQ_CHANNELS {
                break;
            }
            if !is_valid_channel_id(&ch) {
                continue;
            }
            let topic = proto::channel_topic(&ch);
            if seen.insert(topic.clone()) {
                out.push(topic);
            }
        }
    }
    out
}

/// Publish an event's JSON to every gossip topic it belongs to, ensuring each
/// topic is subscribed first. Best-effort: failures are logged, not fatal.
async fn publish_to_topics(transport: &Arc<dyn GossipTransport>, ev: &Event) {
    for topic in proto::topics_for_event(ev) {
        if let Err(e) = transport.ensure_topic(&topic).await {
            tracing::debug!(error = %e, %topic, "ensure_topic failed");
            continue;
        }
        if let Err(e) = transport.publish(&topic, ev.as_json().as_bytes()).await {
            tracing::debug!(error = %e, %topic, "publish failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{router, AppState, Hub};
    use crate::proto;
    use crate::store::{EventStore, InsertOutcome};
    use crate::transport::{GossipMessage, GossipTransport};
    use async_trait::async_trait;
    use futures_util::{SinkExt, StreamExt};
    use nostr::filter::MatchEventOptions;
    use nostr::{
        ClientMessage, Event, EventBuilder, Filter, JsonUtil, Keys, Kind, SubscriptionId, Tag,
        TagKind,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    type WS = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    // ---- in-memory fakes implementing the frozen traits ----

    struct FakeStore {
        events: tokio::sync::Mutex<Vec<Event>>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                events: tokio::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl EventStore for FakeStore {
        async fn insert(&self, ev: &Event) -> anyhow::Result<InsertOutcome> {
            let mut events = self.events.lock().await;
            if events.iter().any(|e| e.id == ev.id) {
                return Ok(InsertOutcome::Duplicate);
            }
            events.push(ev.clone());
            Ok(InsertOutcome::Inserted)
        }

        async fn query(&self, filter: &Filter) -> anyhow::Result<Vec<Event>> {
            let events = self.events.lock().await;
            let opts = MatchEventOptions::default();
            let mut out: Vec<Event> = events
                .iter()
                .filter(|e| filter.match_event(e, opts))
                .cloned()
                .collect();
            // Mirror the real store's ordering: created_at DESC.
            out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
            Ok(out)
        }

        async fn known_channels(&self) -> anyhow::Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

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

    // ---- harness ----

    async fn spawn_server() -> SocketAddr {
        let store: Arc<dyn EventStore> = Arc::new(FakeStore::new());
        let transport: Arc<dyn GossipTransport> = Arc::new(FakeTransport);
        let state = Arc::new(AppState {
            store,
            transport,
            hub: Hub::new(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    async fn connect(addr: SocketAddr) -> WS {
        let url = format!("ws://{addr}");
        let (ws, _resp) = tokio_tungstenite::connect_async(url).await.unwrap();
        ws
    }

    /// Read the next meaningful (text) frame and parse it as JSON.
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

    /// Full NIP-42 handshake: read AUTH, sign an auth event, expect OK true.
    async fn authenticate(ws: &mut WS, keys: &Keys) {
        let auth_msg = recv_value(ws).await;
        assert_eq!(auth_msg[0], "AUTH", "expected AUTH challenge");
        let challenge = auth_msg[1].as_str().expect("challenge str").to_string();
        send_msg(ws, ClientMessage::auth(auth_event(keys, &challenge))).await;
        let ok = recv_value(ws).await;
        assert_eq!(ok[0], "OK");
        assert!(ok[2].as_bool().expect("status bool"), "AUTH should succeed");
    }

    fn auth_event(keys: &Keys, challenge: &str) -> Event {
        EventBuilder::new(Kind::from(proto::AUTH_KIND), "")
            .tag(Tag::custom(TagKind::custom("challenge"), [challenge]))
            .tag(Tag::custom(TagKind::custom("relay"), ["ws://127.0.0.1/"]))
            .sign_with_keys(keys)
            .expect("sign auth")
    }

    // ---- acceptance tests ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handshake_then_event_and_req() {
        let addr = spawn_server().await;
        let keys = Keys::generate();
        let mut ws = connect(addr).await;

        authenticate(&mut ws, &keys).await;

        // Authenticated kind-9 EVENT → OK true.
        let ev = EventBuilder::new(Kind::from(9u16), "hello bridge")
            .sign_with_keys(&keys)
            .unwrap();
        let ev_id = ev.id;
        send_msg(&mut ws, ClientMessage::event(ev)).await;
        let ok = recv_value(&mut ws).await;
        assert_eq!(ok[0], "OK");
        assert_eq!(ok[1], ev_id.to_hex());
        assert_eq!(ok[2], true);

        // REQ returns the stored event + EOSE.
        let sub = SubscriptionId::new("sub1");
        let filter = Filter::new().author(keys.public_key());
        send_msg(&mut ws, ClientMessage::req(sub, vec![filter])).await;
        let evt = recv_value(&mut ws).await;
        assert_eq!(evt[0], "EVENT");
        assert_eq!(evt[1], "sub1");
        assert_eq!(evt[2]["id"], ev_id.to_hex());
        let eose = recv_value(&mut ws).await;
        assert_eq!(eose[0], "EOSE");
        assert_eq!(eose[1], "sub1");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unauthenticated_event_rejected() {
        let addr = spawn_server().await;
        let mut ws = connect(addr).await;
        // Drain the AUTH challenge without authenticating.
        let _ = recv_value(&mut ws).await;

        let keys = Keys::generate();
        let ev = EventBuilder::new(Kind::from(9u16), "no auth")
            .sign_with_keys(&keys)
            .unwrap();
        let id = ev.id;
        send_msg(&mut ws, ClientMessage::event(ev)).await;
        let ok = recv_value(&mut ws).await;
        assert_eq!(ok[0], "OK");
        assert_eq!(ok[1], id.to_hex());
        assert_eq!(ok[2], false);
        let msg = ok[3].as_str().expect("message");
        assert!(msg.starts_with("auth-required"), "got: {msg}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forged_event_rejected() {
        let addr = spawn_server().await;
        let keys = Keys::generate();
        let mut ws = connect(addr).await;
        authenticate(&mut ws, &keys).await;

        let mut ev = EventBuilder::new(Kind::from(9u16), "original")
            .sign_with_keys(&keys)
            .unwrap();
        ev.content.push_str(" tampered"); // invalidates the signed id/sig
        let id = ev.id;
        send_msg(&mut ws, ClientMessage::event(ev)).await;
        let ok = recv_value(&mut ws).await;
        assert_eq!(ok[1], id.to_hex());
        assert_eq!(ok[2], false);
        let msg = ok[3].as_str().expect("message");
        assert!(msg.starts_with("invalid"), "got: {msg}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_challenge_keeps_auth_pending() {
        let addr = spawn_server().await;
        let keys = Keys::generate();
        let mut ws = connect(addr).await;

        let _challenge = recv_value(&mut ws).await;
        // Send AUTH with the wrong challenge → verification fails.
        let bad = auth_event(&keys, "deadbeef-not-the-challenge");
        send_msg(&mut ws, ClientMessage::auth(bad)).await;
        let ok = recv_value(&mut ws).await;
        assert_eq!(ok[2], false, "wrong-challenge AUTH should fail");

        // Auth stays pending: a follow-up EVENT must still be auth-required.
        let ev = EventBuilder::new(Kind::from(9u16), "still pending")
            .sign_with_keys(&keys)
            .unwrap();
        send_msg(&mut ws, ClientMessage::event(ev)).await;
        let ok = recv_value(&mut ws).await;
        assert_eq!(ok[2], false);
        assert!(ok[3].as_str().unwrap().starts_with("auth-required"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn second_client_receives_live_event() {
        let addr = spawn_server().await;

        // Client 2: authenticate + open a REQ for kind 9.
        let keys2 = Keys::generate();
        let mut ws2 = connect(addr).await;
        authenticate(&mut ws2, &keys2).await;
        let sub2 = SubscriptionId::new("live");
        send_msg(
            &mut ws2,
            ClientMessage::req(sub2, vec![Filter::new().kind(Kind::from(9u16))]),
        )
        .await;
        let eose = recv_value(&mut ws2).await;
        assert_eq!(eose[0], "EOSE");

        // Client 1: authenticate + publish a kind-9 event.
        let keys1 = Keys::generate();
        let mut ws1 = connect(addr).await;
        authenticate(&mut ws1, &keys1).await;
        let ev = EventBuilder::new(Kind::from(9u16), "live from client 1")
            .sign_with_keys(&keys1)
            .unwrap();
        let ev_id = ev.id;
        send_msg(&mut ws1, ClientMessage::event(ev)).await;
        let ok = recv_value(&mut ws1).await;
        assert!(ok[2].as_bool().unwrap());

        // Client 2 must receive the live EVENT published after its EOSE.
        let evt = recv_value(&mut ws2).await;
        assert_eq!(evt[0], "EVENT");
        assert_eq!(evt[1], "live");
        assert_eq!(evt[2]["id"], ev_id.to_hex());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_stops_delivery() {
        let addr = spawn_server().await;

        // Subscriber.
        let keys2 = Keys::generate();
        let mut ws2 = connect(addr).await;
        authenticate(&mut ws2, &keys2).await;
        let sub = SubscriptionId::new("s");
        send_msg(
            &mut ws2,
            ClientMessage::req(sub.clone(), vec![Filter::new().kind(Kind::from(9u16))]),
        )
        .await;
        let _ = recv_value(&mut ws2).await; // EOSE

        // Publisher.
        let keys1 = Keys::generate();
        let mut ws1 = connect(addr).await;
        authenticate(&mut ws1, &keys1).await;

        // Publish ev1 → subscriber receives it.
        let ev1 = EventBuilder::new(Kind::from(9u16), "one")
            .sign_with_keys(&keys1)
            .unwrap();
        send_msg(&mut ws1, ClientMessage::event(ev1)).await;
        let ok = recv_value(&mut ws1).await;
        assert!(ok[2].as_bool().unwrap());
        let evt = recv_value(&mut ws2).await;
        assert_eq!(evt[2]["content"], "one");

        // CLOSE the subscription.
        send_msg(&mut ws2, ClientMessage::close(sub)).await;

        // Publish ev2 → subscriber must NOT receive it.
        let ev2 = EventBuilder::new(Kind::from(9u16), "two")
            .sign_with_keys(&keys1)
            .unwrap();
        send_msg(&mut ws1, ClientMessage::event(ev2)).await;
        let ok = recv_value(&mut ws1).await;
        assert!(ok[2].as_bool().unwrap());

        tokio::select! {
            biased;
            msg = recv_value(&mut ws2) => panic!("received after CLOSE: {msg}"),
            _ = tokio::time::sleep(Duration::from_millis(500)) => { /* ok: nothing delivered */ }
        }
    }
}

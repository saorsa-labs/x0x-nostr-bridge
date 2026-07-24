//! Nostr relay WebSocket layer + fan-out hub + HTTP dialect wiring.
//! Owner: wp2-http (WS core grafted from the spike's RelayAgent contract).
//!
//! Contract:
//! - `router(state)` builds the axum Router: GET "/" upgrades to a WebSocket
//!   (or serves NIP-11 on `Accept: application/nostr+json`), plus the Buzz HTTP
//!   dialect routes (`POST /events|/query|/count`, `GET /info`) behind a 1 MiB
//!   body cap. WS and HTTP share the one port (dialect.md §0).
//! - Connection flow mirrors buzz-relay: connection-first `["AUTH",challenge]`,
//!   5s auth timeout, NIP-42 verify incl. the relay-tag (WP3, issue #3),
//!   REQ-before-auth → CLOSED, per-connection sub cap, global connection cap
//!   (WP3, issue #2), and per-topic forwarder pruning on last unsubscribe
//!   (WP3, issue #4). Relay-authored kinds are rejected at WS + HTTP ingest.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use nostr::{
    ClientMessage, Event, Filter, JsonUtil, PublicKey, RelayMessage, SubscriptionId, Timestamp,
};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use crate::auth::ReplayCache;
use crate::engine_api::{HistoryEngine, StubEngine};
use crate::filter_match;
use crate::kinds;
use crate::proto;
use crate::rate_limit::RateLimiter;
use crate::relay_identity::RelayIdentity;
use crate::settings::Settings;
use crate::store::{EventStore, InsertOutcome};
use crate::transport::GossipTransport;

/// Body cap for HTTP dialect routes: 1 MiB → 413 (dialect.md §0).
const HTTP_BODY_LIMIT: usize = 1024 * 1024;
/// Server-side NIP-42 auth deadline from connect (dialect.md §4).
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);

pub type ConnId = u64;

struct SubEntry {
    filters: Vec<Filter>,
    tx: mpsc::Sender<RelayMessage<'static>>,
    strikes: u32,
}

/// Subscription registry + fan-out. Slow-consumer policy unchanged from spike.
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

    /// Register (or replace) a subscription. Returns `false` only when a NEW sub
    /// id would exceed `proto::MAX_SUBS_PER_CONN`.
    pub fn register(
        &self,
        conn: ConnId,
        sub_id: &str,
        filters: Vec<Filter>,
        tx: mpsc::Sender<RelayMessage<'static>>,
    ) -> bool {
        let conns = self.subs.entry(conn).or_default();
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

    /// Fan out to matching subs via the SHARED matcher (finding 3: live and
    /// historical matching cannot diverge). Slow/dead consumers are dropped.
    pub fn dispatch(&self, ev: &Event) -> usize {
        let mut delivered: usize = 0;
        let mut slow_conns: Vec<ConnId> = Vec::new();

        for map_ref in self.subs.iter() {
            let conn = *map_ref.key();
            let conns = map_ref.value();
            for mut sub_ref in conns.iter_mut() {
                let sub_id = sub_ref.key().clone();
                let sub = sub_ref.value_mut();
                let matches = sub.filters.iter().any(|f| filter_match::matches(f, ev));
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

/// Shared server state. New fields (engine/identity/settings/auth/limiter/
/// connection cap/topic refcounts/shutdown) back the HTTP dialect + WP3
/// hardening; the spike's store/transport/hub are unchanged.
pub struct AppState {
    pub store: Arc<dyn EventStore>,
    pub transport: Arc<dyn GossipTransport>,
    pub hub: Hub,
    pub engine: Arc<dyn HistoryEngine>,
    pub identity: Arc<RelayIdentity>,
    pub settings: Arc<Settings>,
    pub replay: ReplayCache,
    pub limiter: RateLimiter,
    /// Global WS connection cap permits (issue #2).
    pub conn_sem: Arc<Semaphore>,
    /// Per-topic subscriber refcount for forwarder pruning (issue #4).
    topic_refs: DashMap<String, usize>,
    /// Topics ensured per (conn, sub), so a CLOSE/disconnect can decrement.
    sub_topics: DashMap<(ConnId, String), Vec<String>>,
    /// Graceful-shutdown flag + waker (WP3 1012 stretch).
    pub shutting_down: AtomicBool,
    pub shutdown: Arc<Notify>,
}

impl AppState {
    /// Production constructor: caller supplies every dependency.
    pub fn new(
        store: Arc<dyn EventStore>,
        transport: Arc<dyn GossipTransport>,
        engine: Arc<dyn HistoryEngine>,
        identity: Arc<RelayIdentity>,
        settings: Arc<Settings>,
    ) -> Self {
        let conn_sem = Arc::new(Semaphore::new(settings.max_connections));
        Self {
            store,
            transport,
            hub: Hub::new(),
            engine,
            identity,
            settings,
            replay: ReplayCache::new(),
            limiter: RateLimiter::new(),
            conn_sem,
            topic_refs: DashMap::new(),
            sub_topics: DashMap::new(),
            shutting_down: AtomicBool::new(false),
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Test/wiring constructor with explicit settings and default HTTP deps
    /// (stub engine, ephemeral relay identity).
    pub fn for_test(
        store: Arc<dyn EventStore>,
        transport: Arc<dyn GossipTransport>,
        settings: Settings,
    ) -> Self {
        Self::new(
            store,
            transport,
            Arc::new(StubEngine::new()),
            Arc::new(RelayIdentity::ephemeral()),
            Arc::new(settings),
        )
    }

    /// Spike-parity constructor: default settings (dev-auth, relay-tag NOT
    /// enforced, membership off) so the WS-only spike tests behave as before.
    pub fn with_defaults(store: Arc<dyn EventStore>, transport: Arc<dyn GossipTransport>) -> Self {
        Self::for_test(store, transport, Settings::default())
    }

    fn acquire_topics(&self, conn: ConnId, sub_id: &str, topics: Vec<String>) {
        for t in &topics {
            *self.topic_refs.entry(t.clone()).or_insert(0) += 1;
        }
        self.sub_topics.insert((conn, sub_id.to_string()), topics);
    }

    /// Release a single subscription's topics, pruning the transport forwarder
    /// on the last unsubscribe (issue #4).
    fn release_sub_topics(self: &Arc<Self>, conn: ConnId, sub_id: &str) {
        if let Some((_, topics)) = self.sub_topics.remove(&(conn, sub_id.to_string())) {
            self.decrement_topics(topics);
        }
    }

    /// Release every subscription's topics for a connection (on disconnect).
    fn release_conn_topics(self: &Arc<Self>, conn: ConnId) {
        let keys: Vec<(ConnId, String)> = self
            .sub_topics
            .iter()
            .filter(|e| e.key().0 == conn)
            .map(|e| e.key().clone())
            .collect();
        for key in keys {
            if let Some((_, topics)) = self.sub_topics.remove(&key) {
                self.decrement_topics(topics);
            }
        }
    }

    fn decrement_topics(self: &Arc<Self>, topics: Vec<String>) {
        for t in topics {
            let now_zero = {
                let mut e = self.topic_refs.entry(t.clone()).or_insert(0);
                if *e > 0 {
                    *e -= 1;
                }
                *e == 0
            };
            if now_zero {
                self.topic_refs.remove(&t);
                let transport = Arc::clone(&self.transport);
                tokio::spawn(async move {
                    if let Err(e) = transport.remove_topic(&t).await {
                        tracing::debug!(error = %e, topic = %t, "remove_topic failed");
                    }
                });
            }
        }
    }
}

/// Build the axum router: WS + NIP-11 on `/`, plus the Buzz HTTP dialect routes
/// behind a shared 1 MiB body cap.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(root_handler))
        .route("/events", post(crate::http::post_events))
        .route("/query", post(crate::http::post_query))
        .route("/count", post(crate::http::post_count))
        .route("/info", get(crate::http::get_info))
        .layer(DefaultBodyLimit::max(HTTP_BODY_LIMIT))
        .with_state(state)
}

async fn root_handler(
    State(state): State<Arc<AppState>>,
    upgrade: Option<WebSocketUpgrade>,
    headers: HeaderMap,
) -> Response {
    // Pre-drain grace: new hits on `/` get 503 during graceful shutdown.
    if state.shutting_down.load(Ordering::Relaxed) {
        return (StatusCode::SERVICE_UNAVAILABLE, "relay restarting").into_response();
    }
    if let Some(ws) = upgrade {
        // Global connection cap (issue #2): acquire a permit at accept.
        let permit = match Arc::clone(&state.conn_sem).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                return (StatusCode::SERVICE_UNAVAILABLE, "connection limit reached")
                    .into_response()
            }
        };
        return ws
            .max_message_size(proto::MAX_FRAME_BYTES)
            .max_frame_size(proto::MAX_FRAME_BYTES)
            .on_upgrade(move |socket| handle_connection(state, socket, permit));
    }
    if is_nip11(&headers) {
        let doc = crate::nip11::document(&state.settings, &state.identity);
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/nostr+json")],
            doc.to_string(),
        )
            .into_response();
    }
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

/// Per-connection task: hold the connection-cap permit for the socket's life,
/// issue the NIP-42 challenge, run the writer (which emits a 1012 close on
/// graceful shutdown), and dispatch client messages through the gates with a 5s
/// auth deadline.
async fn handle_connection(state: Arc<AppState>, socket: WebSocket, permit: OwnedSemaphorePermit) {
    let _permit = permit; // released on connection drop
    let conn_id = state.hub.next_conn_id();
    let challenge = uuid::Uuid::new_v4().to_string();
    let (tx, mut rx) = mpsc::channel::<RelayMessage<'static>>(proto::SEND_QUEUE);

    let (mut sink, mut stream) = socket.split();

    let shutdown = Arc::clone(&state.shutdown);
    let writer = tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Some(m) => {
                        if sink.send(Message::Text(m.as_json())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = shutdown.notified() => {
                    // WP3 stretch: 1012 Service Restart so clients fast-reconnect.
                    let frame = CloseFrame {
                        code: 1012,
                        reason: "relay restarting".into(),
                    };
                    let _ = sink.send(Message::Close(Some(frame))).await;
                    break;
                }
            }
        }
    });

    // NIP-42: challenge immediately on connect.
    let _ = tx.send(RelayMessage::auth(challenge.clone())).await;

    let auth_deadline = tokio::time::Instant::now() + AUTH_TIMEOUT;
    let mut authed: Option<PublicKey> = None;
    loop {
        tokio::select! {
            biased;
            // Auth timeout: drop the connection if unauthenticated within 5s.
            _ = tokio::time::sleep_until(auth_deadline), if authed.is_none() => break,
            frame = stream.next() => {
                match frame {
                    Some(Ok(Message::Text(text))) => {
                        handle_text(&state, &tx, conn_id, &challenge, &mut authed, text).await;
                    }
                    Some(Ok(Message::Binary(_))) => {}
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                }
            }
        }
    }

    drop(tx);
    state.hub.unregister_conn(conn_id);
    state.release_conn_topics(conn_id);
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
            if authed.is_some() {
                let _ = tx.send(RelayMessage::notice("already authed")).await;
            } else {
                // WP3 (issue #3): validate the NIP-42 relay tag when configured.
                let expected = if state.settings.enforce_relay_tag {
                    Some(state.settings.relay_ws_url())
                } else {
                    None
                };
                match proto::verify_auth_event(&ev, challenge, Timestamp::now(), expected.as_deref())
                {
                    Ok(()) => {
                        *authed = Some(ev.pubkey);
                        let _ = tx.send(RelayMessage::ok(ev.id, true, "")).await;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "auth event rejected");
                        let _ = tx
                            .send(RelayMessage::ok(
                                ev.id,
                                false,
                                "auth-required: verification failed",
                            ))
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
            state.release_sub_topics(conn_id, sub_id.as_str());
        }
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
    // WP3: relay-authored kinds may not be client-submitted (dialect.md §7).
    if kinds::is_relay_authored(ev.kind.as_u16()) {
        let _ = tx
            .send(RelayMessage::ok(
                ev.id,
                false,
                "invalid: relay-authored kind may not be submitted",
            ))
            .await;
        return;
    }
    if let Err(e) = proto::verify_event(&ev) {
        tracing::debug!(error = %e, "event verification failed");
        let _ = tx
            .send(RelayMessage::ok(ev.id, false, "invalid: bad id or signature"))
            .await;
        return;
    }

    if proto::is_ephemeral(ev.kind) {
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
                "auth-required: authenticate before subscribing",
            ))
            .await;
        return;
    }

    let filters = sanitize_req_filters(filters);

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

    // Track this sub's channel topics for refcounted forwarder pruning, then
    // ensure each is subscribed (fire-and-forget).
    let topics = req_channel_topics(&filters);
    state.acquire_topics(conn_id, sub_id.as_str(), topics.clone());
    for topic in topics {
        let transport = Arc::clone(&state.transport);
        tokio::spawn(async move {
            if let Err(e) = transport.ensure_topic(&topic).await {
                tracing::debug!(error = %e, %topic, "ensure_topic (req) failed");
            }
        });
    }

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

fn is_valid_channel_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
}

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

/// Publish an event's JSON to every gossip topic it belongs to. Best-effort.
pub(crate) async fn publish_to_topics(transport: &Arc<dyn GossipTransport>, ev: &Event) {
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
    use crate::settings::Settings;
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

    async fn spawn_server() -> SocketAddr {
        spawn_server_with(Settings::default()).await
    }

    async fn spawn_server_with(settings: Settings) -> SocketAddr {
        let store: Arc<dyn EventStore> = Arc::new(FakeStore::new());
        let transport: Arc<dyn GossipTransport> = Arc::new(FakeTransport);
        let state = Arc::new(AppState::for_test(store, transport, settings));
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
        auth_event_relay(keys, challenge, "ws://127.0.0.1/")
    }

    fn auth_event_relay(keys: &Keys, challenge: &str, relay: &str) -> Event {
        EventBuilder::new(Kind::from(proto::AUTH_KIND), "")
            .tag(Tag::custom(TagKind::custom("challenge"), [challenge]))
            .tag(Tag::custom(TagKind::custom("relay"), [relay]))
            .sign_with_keys(keys)
            .expect("sign auth")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handshake_then_event_and_req() {
        let addr = spawn_server().await;
        let keys = Keys::generate();
        let mut ws = connect(addr).await;

        authenticate(&mut ws, &keys).await;

        let ev = EventBuilder::new(Kind::from(9u16), "hello bridge")
            .sign_with_keys(&keys)
            .unwrap();
        let ev_id = ev.id;
        send_msg(&mut ws, ClientMessage::event(ev)).await;
        let ok = recv_value(&mut ws).await;
        assert_eq!(ok[0], "OK");
        assert_eq!(ok[1], ev_id.to_hex());
        assert_eq!(ok[2], true);

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
        ev.content.push_str(" tampered");
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
        let bad = auth_event(&keys, "deadbeef-not-the-challenge");
        send_msg(&mut ws, ClientMessage::auth(bad)).await;
        let ok = recv_value(&mut ws).await;
        assert_eq!(ok[2], false, "wrong-challenge AUTH should fail");

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

        let evt = recv_value(&mut ws2).await;
        assert_eq!(evt[0], "EVENT");
        assert_eq!(evt[1], "live");
        assert_eq!(evt[2]["id"], ev_id.to_hex());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_stops_delivery() {
        let addr = spawn_server().await;

        let keys2 = Keys::generate();
        let mut ws2 = connect(addr).await;
        authenticate(&mut ws2, &keys2).await;
        let sub = SubscriptionId::new("s");
        send_msg(
            &mut ws2,
            ClientMessage::req(sub.clone(), vec![Filter::new().kind(Kind::from(9u16))]),
        )
        .await;
        let _ = recv_value(&mut ws2).await;

        let keys1 = Keys::generate();
        let mut ws1 = connect(addr).await;
        authenticate(&mut ws1, &keys1).await;

        let ev1 = EventBuilder::new(Kind::from(9u16), "one")
            .sign_with_keys(&keys1)
            .unwrap();
        send_msg(&mut ws1, ClientMessage::event(ev1)).await;
        let ok = recv_value(&mut ws1).await;
        assert!(ok[2].as_bool().unwrap());
        let evt = recv_value(&mut ws2).await;
        assert_eq!(evt[2]["content"], "one");

        send_msg(&mut ws2, ClientMessage::close(sub)).await;

        let ev2 = EventBuilder::new(Kind::from(9u16), "two")
            .sign_with_keys(&keys1)
            .unwrap();
        send_msg(&mut ws1, ClientMessage::event(ev2)).await;
        let ok = recv_value(&mut ws1).await;
        assert!(ok[2].as_bool().unwrap());

        tokio::select! {
            biased;
            msg = recv_value(&mut ws2) => panic!("received after CLOSE: {msg}"),
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }

    // ---- WP3 hardening tests ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_tag_accepted_when_matching() {
        let mut settings = Settings::default();
        settings.enforce_relay_tag = true;
        settings.public_base_url = "http://127.0.0.1:3000".into();
        let addr = spawn_server_with(settings).await;
        let keys = Keys::generate();
        let mut ws = connect(addr).await;
        let auth_msg = recv_value(&mut ws).await;
        let challenge = auth_msg[1].as_str().unwrap().to_string();
        let ev = auth_event_relay(&keys, &challenge, "ws://127.0.0.1:3000");
        send_msg(&mut ws, ClientMessage::auth(ev)).await;
        let ok = recv_value(&mut ws).await;
        assert_eq!(ok[2], true, "matching relay tag should authenticate");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_tag_rejected_when_mismatched() {
        let mut settings = Settings::default();
        settings.enforce_relay_tag = true;
        settings.public_base_url = "http://127.0.0.1:3000".into();
        let addr = spawn_server_with(settings).await;
        let keys = Keys::generate();
        let mut ws = connect(addr).await;
        let auth_msg = recv_value(&mut ws).await;
        let challenge = auth_msg[1].as_str().unwrap().to_string();
        let ev = auth_event_relay(&keys, &challenge, "ws://evil.example/");
        send_msg(&mut ws, ClientMessage::auth(ev)).await;
        let ok = recv_value(&mut ws).await;
        assert_eq!(ok[2], false, "mismatched relay tag must be rejected");
        assert!(ok[3].as_str().unwrap().starts_with("auth-required"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn req_before_auth_is_closed() {
        let addr = spawn_server().await;
        let mut ws = connect(addr).await;
        let _ = recv_value(&mut ws).await; // drain challenge, do not auth
        send_msg(
            &mut ws,
            ClientMessage::req(
                SubscriptionId::new("x"),
                vec![Filter::new().kind(Kind::from(9u16))],
            ),
        )
        .await;
        let closed = recv_value(&mut ws).await;
        assert_eq!(closed[0], "CLOSED");
        assert!(closed[2].as_str().unwrap().starts_with("auth-required"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn global_connection_cap_enforced() {
        let mut settings = Settings::default();
        settings.max_connections = 1;
        let addr = spawn_server_with(settings).await;
        let mut ws1 = connect(addr).await;
        let _ = recv_value(&mut ws1).await;
        let url = format!("ws://{addr}");
        let second = tokio_tungstenite::connect_async(url).await;
        assert!(second.is_err(), "second connection should be capped");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_authored_kind_rejected_over_ws() {
        let addr = spawn_server().await;
        let keys = Keys::generate();
        let mut ws = connect(addr).await;
        authenticate(&mut ws, &keys).await;
        let ev = EventBuilder::new(Kind::from(crate::kinds::KIND_THREAD_SUMMARY), "{}")
            .sign_with_keys(&keys)
            .unwrap();
        send_msg(&mut ws, ClientMessage::event(ev)).await;
        let ok = recv_value(&mut ws).await;
        assert_eq!(ok[2], false);
        assert!(ok[3].as_str().unwrap().contains("relay-authored"));
    }
}

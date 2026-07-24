//! x0xd gossip transport adapter. Owner: TransportAgent.
//!
//! Contract (FROZEN): implement `X0xTransport` + `GossipTransport` exactly as
//! declared here.
//! - `ensure_topic` is idempotent: first call for a topic subscribes on the
//!   daemon (POST /subscribe), later calls are no-ops. Subscribed topics feed
//!   the inbox stream.
//! - `publish` base64-encodes and POSTs /publish to the daemon.
//! - `inbox` yields daemon SSE (/events) messages for every subscribed topic
//!   as `GossipMessage { topic, payload (decoded bytes) }`. The stream must
//!   survive daemon hiccups: reconnect with backoff (1s → 30s cap), and on
//!   reconnect re-issue all active subscriptions. Take-once semantics: only
//!   the first call returns a live receiver; later calls return an empty
//!   closed receiver.
//! - Auth: bearer token from the daemon data dir (see `discover`).
//! - Reference docs: docs/api-reference.md ("Gossip messaging" section),
//!   docs/local-apps.md, SKILL.md.

use std::sync::Arc;
use std::time::Duration;

use crate::proto;
use anyhow::Context as _;
use async_trait::async_trait;
use base64::Engine as _;
use futures_util::StreamExt as _;
use parking_lot::Mutex;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct GossipMessage {
    pub topic: String,
    pub payload: Vec<u8>,
}

#[async_trait]
pub trait GossipTransport: Send + Sync {
    async fn ensure_topic(&self, topic: &str) -> anyhow::Result<()>;
    async fn publish(&self, topic: &str, payload: &[u8]) -> anyhow::Result<()>;
    fn inbox(&self) -> mpsc::Receiver<GossipMessage>;
    /// Tear down a topic's daemon forwarder and prune the local tracking maps
    /// (issue #4: the per-topic mutex map must not grow unbounded). Called by
    /// the relay when the last subscriber for a topic unsubscribes. Default is a
    /// no-op so test fakes need no change.
    async fn remove_topic(&self, _topic: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Locate the running daemon's REST address + bearer token.
///
/// Order: `(X0X_API, X0X_TOKEN)` env → platform data dir.
/// Returns `(base_url, token)`, e.g. `("http://127.0.0.1:12700", "abc…")`.
///
/// Data dir files (per `docs/local-apps.md`):
/// - `<data_dir>/api.port`  — bare `host:port` (e.g. `127.0.0.1:12700`)
/// - `<data_dir>/api-token` — bearer token (64-char hex)
///
/// macOS: `~/Library/Application Support/x0x/`
/// Linux: `$XDG_DATA_HOME/x0x/` (default `~/.local/share/x0x/`)
pub fn discover() -> anyhow::Result<(String, String)> {
    // Env override takes precedence when both are present.
    if let (Ok(api), Ok(token)) = (std::env::var("X0X_API"), std::env::var("X0X_TOKEN")) {
        let api = api.trim();
        let token = token.trim();
        if !api.is_empty() && !token.is_empty() {
            return Ok((normalize_base_url(api), token.to_string()));
        }
    }

    let data_dir = x0x_data_dir().ok_or_else(|| {
        anyhow::anyhow!(
            "cannot locate x0x data directory (HOME unset); set X0X_API/X0X_TOKEN or start x0xd"
        )
    })?;

    let port_path = data_dir.join("api.port");
    let token_path = data_dir.join("api-token");

    let addr = std::fs::read_to_string(&port_path)
        .with_context(|| format!("reading {}", port_path.display()))?
        .trim()
        .to_string();
    let token = std::fs::read_to_string(&token_path)
        .with_context(|| format!("reading {}", token_path.display()))?
        .trim()
        .to_string();

    if addr.is_empty() || token.is_empty() {
        anyhow::bail!(
            "x0x discovery files are empty ({}); is the daemon running?",
            data_dir.display()
        );
    }

    Ok((normalize_base_url(&addr), token))
}

/// Resolve the platform x0x data directory (macOS / Linux / other Unix).
fn x0x_data_dir() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    if cfg!(target_os = "macos") {
        let home = std::env::var_os("HOME")?;
        Some(PathBuf::from(home).join("Library/Application Support/x0x"))
    } else {
        // Linux / other Unix: honour XDG_DATA_HOME, fall back to ~/.local/share.
        let base = std::env::var_os("XDG_DATA_HOME")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|s| !s.is_empty())
                    .map(PathBuf::from)
                    .map(|h| h.join(".local/share"))
            })?;
        Some(base.join("x0x"))
    }
}

/// Normalise a raw API address into an `http://` base URL with no trailing slash.
/// Accepts `host:port`, `http://host:port`, or `https://…`.
pub fn normalize_base_url(raw: &str) -> String {
    let s = raw.trim().trim_end_matches('/');
    if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("http://{s}")
    }
}

// ---------------------------------------------------------------------------
// Internals shared between the transport handle and the SSE supervisor task.
// ---------------------------------------------------------------------------

struct Shared {
    client: reqwest::Client,
    base_url: String,
    #[allow(dead_code)]
    token: String,
    /// Topics we have POST /subscribe'd, mapped to the daemon-assigned
    /// `subscription_id`. Tracking the id lets `resubscribe_all` DELETE the
    /// stale forwarder before re-POSTing on reconnect, so the daemon never
    /// keeps duplicate live forwarders per topic (C2).
    topics: dashmap::DashMap<String, String>,
    /// Per-topic async flight locks so concurrent `ensure_topic(same)` callers
    /// serialize on a single POST (C3). One entry per topic ever ensured;
    /// bounded by the (small) distinct-topic count.
    inflight: dashmap::DashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

impl Shared {
    /// POST /subscribe for a single topic. Does NOT consult the local set —
    /// callers gate that themselves. Returns the daemon-assigned
    /// `subscription_id` parsed from the response body.
    async fn subscribe_once(&self, topic: &str) -> anyhow::Result<String> {
        let url = format!("{}/subscribe", self.base_url);
        let body = serde_json::json!({ "topic": topic });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST /subscribe for '{topic}'"))?;
        let status = resp.status();
        if !status.is_success() {
            let _ = resp.text().await;
            anyhow::bail!("subscribe to '{topic}' failed: HTTP {status}");
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .context("POST /subscribe response was not valid JSON")?;
        let id = v
            .get("subscription_id")
            .and_then(|i| i.as_str())
            .ok_or_else(|| anyhow::anyhow!("POST /subscribe response missing 'subscription_id'"))?
            .to_string();
        Ok(id)
    }

    /// DELETE /subscribe/:id — best-effort teardown of a forwarder. A 404 is
    /// tolerated (the daemon may have already dropped it on SSE disconnect).
    async fn unsubscribe_once(&self, id: &str) -> anyhow::Result<()> {
        let url = format!("{}/subscribe/{id}", self.base_url);
        let resp = self
            .client
            .delete(&url)
            .send()
            .await
            .with_context(|| format!("DELETE /subscribe/{id}"))?;
        let status = resp.status();
        if !status.is_success() && status != reqwest::StatusCode::NOT_FOUND {
            let _ = resp.text().await;
            anyhow::bail!("DELETE /subscribe/{id} failed: HTTP {status}");
        }
        Ok(())
    }
}

pub struct X0xTransport {
    shared: Arc<Shared>,
    /// Take-once: `inbox()` extracts the live receiver on the first call.
    inbox_rx: Mutex<Option<mpsc::Receiver<GossipMessage>>>,
}

impl X0xTransport {
    /// Connect to the daemon: build an authenticated HTTP client, verify
    /// liveness via `GET /health`, and spawn the SSE supervisor that feeds the
    /// inbox. Returns `Err` if the daemon is unreachable at startup.
    pub async fn connect(base_url: &str, token: &str) -> anyhow::Result<Self> {
        let bearer = format!("Bearer {token}");
        let auth_value = reqwest::header::HeaderValue::from_str(&bearer)
            .with_context(|| "daemon token contains invalid header characters")?;

        let mut default_headers = reqwest::header::HeaderMap::new();
        default_headers.insert(reqwest::header::AUTHORIZATION, auth_value);

        let client = reqwest::Client::builder()
            .default_headers(default_headers)
            .build()
            .context("building HTTP client")?;

        // Verify liveness (GET /health is public but harmless with the bearer).
        let health_url = format!("{base_url}/health");
        let health = client.get(&health_url).send().await.map_err(|e| {
            anyhow::anyhow!(
                "cannot reach x0xd at {base_url} (GET /health failed: {e}). \
                     Is the daemon running? Set X0X_API/X0X_TOKEN or start x0xd."
            )
        })?;
        if !health.status().is_success() {
            anyhow::bail!(
                "x0xd at {base_url} is not healthy (GET /health → HTTP {})",
                health.status()
            );
        }
        // Drain the health body.
        let _ = health.bytes().await;

        let shared = Arc::new(Shared {
            client,
            base_url: base_url.to_string(),
            token: token.to_string(),
            topics: dashmap::DashMap::new(),
            inflight: dashmap::DashMap::new(),
        });

        // Inbox channel — capacity per the contract.
        let (inbox_tx, inbox_rx) = mpsc::channel::<GossipMessage>(INBOX_CAPACITY);
        spawn_supervisor(Arc::clone(&shared), inbox_tx);

        Ok(Self {
            shared,
            inbox_rx: Mutex::new(Some(inbox_rx)),
        })
    }
}

#[async_trait]
impl GossipTransport for X0xTransport {
    async fn ensure_topic(&self, topic: &str) -> anyhow::Result<()> {
        // Fast path: already subscribed locally.
        if self.shared.topics.contains_key(topic) {
            return Ok(());
        }
        // C3: per-topic flight lock. Acquire (or create) the lock for this
        // topic, then RELEASE the DashMap guard before awaiting so we never
        // hold a shard lock across an await. The guard serializes concurrent
        // ensure_topic(same topic) callers; the double-check under the lock
        // guarantees exactly one POST wins.
        let flight = self
            .shared
            .inflight
            .entry(topic.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = flight.lock().await;
        if self.shared.topics.contains_key(topic) {
            return Ok(());
        }
        let id = self.shared.subscribe_once(topic).await?;
        self.shared.topics.insert(topic.to_string(), id);
        Ok(())
    }

    async fn publish(&self, topic: &str, payload: &[u8]) -> anyhow::Result<()> {
        let url = format!("{}/publish", self.shared.base_url);
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        let body = serde_json::json!({ "topic": topic, "payload": encoded });
        let resp = self
            .shared
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST /publish for '{topic}'"))?;
        let status = resp.status();
        if !status.is_success() {
            let _ = resp.text().await;
            anyhow::bail!("publish to '{topic}' failed: HTTP {status}");
        }
        Ok(())
    }

    async fn remove_topic(&self, topic: &str) -> anyhow::Result<()> {
        // Prune the tracking maps so they cannot grow unbounded (issue #4),
        // then best-effort DELETE the daemon forwarder.
        let id = self.shared.topics.remove(topic).map(|(_, id)| id);
        self.shared.inflight.remove(topic);
        if let Some(id) = id {
            self.shared.unsubscribe_once(&id).await?;
        }
        Ok(())
    }

    fn inbox(&self) -> mpsc::Receiver<GossipMessage> {
        // parking_lot::Mutex has no poisoning — `lock()` yields the guard
        // directly. Take-once: the first caller gets the live receiver; later
        // callers get a closed, empty receiver.
        let mut guard = self.inbox_rx.lock();
        guard.take().unwrap_or_else(|| {
            let (_tx, rx) = mpsc::channel(1);
            rx
        })
    }
}

// ---------------------------------------------------------------------------
// SSE supervisor: consume GET /events, survive drops with backoff.
// ---------------------------------------------------------------------------

const SSE_INIT_BACKOFF: Duration = Duration::from_secs(1);
const SSE_MAX_BACKOFF: Duration = Duration::from_secs(30);
const INBOX_CAPACITY: usize = 1024;

/// Spawn the background supervisor that consumes the daemon's `/events` SSE
/// stream, decodes gossip messages, and forwards them to the inbox channel.
/// On stream error/EOF it backs off (1s → 30s cap), re-subscribes all active
/// topics, and resumes. Exits when the inbox receiver is dropped.
fn spawn_supervisor(shared: Arc<Shared>, inbox_tx: mpsc::Sender<GossipMessage>) {
    tokio::spawn(async move {
        let mut backoff = SSE_INIT_BACKOFF;
        loop {
            if inbox_tx.is_closed() {
                tracing::info!("inbox receiver dropped; SSE supervisor exiting");
                return;
            }
            match run_sse_loop(&shared, &inbox_tx).await {
                SseOutcome::StreamEnded => {
                    // Connected fine and the stream closed (EOF). Reset backoff.
                    backoff = SSE_INIT_BACKOFF;
                    tracing::info!("x0xd /events stream ended; reconnecting");
                }
                SseOutcome::ConnectFailed(e) => {
                    tracing::warn!("x0xd /events connect failed ({e}); retrying in {backoff:?}");
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, SSE_MAX_BACKOFF);
                }
            }
            // Re-subscribe all active topics before resuming, so we do not miss
            // messages the daemon dropped while we were disconnected.
            if let Err(e) = resubscribe_all(&shared).await {
                tracing::warn!("re-subscribe after reconnect failed: {e}");
            }
        }
    });
}

enum SseOutcome {
    /// The stream connected successfully and later ended (EOF or channel close).
    StreamEnded,
    /// Could not establish the connection at all.
    ConnectFailed(anyhow::Error),
}

/// Run one `/events` SSE session until the stream ends or an error occurs.
async fn run_sse_loop(shared: &Shared, inbox_tx: &mpsc::Sender<GossipMessage>) -> SseOutcome {
    let url = format!("{}/events", shared.base_url);
    let resp = match shared
        .client
        .get(&url)
        .header("accept", "text/event-stream")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return SseOutcome::ConnectFailed(e.into()),
    };
    if !resp.status().is_success() {
        return SseOutcome::ConnectFailed(anyhow::anyhow!(
            "GET /events returned HTTP {}",
            resp.status()
        ));
    }

    let mut stream = resp.bytes_stream();
    let mut acc = SseAccumulator::new();
    let mut buf: Vec<u8> = Vec::new();

    while let Some(chunk) = stream.next().await {
        let bytes = match chunk {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("x0xd /events read error: {e}");
                break;
            }
        };
        buf.extend_from_slice(&bytes);
        // Process every complete line now available. Oversize lines (and any
        // partial line that alone exceeds MAX_FRAME_BYTES) are skipped so a
        // multi-MB blob can never force unbounded buffer growth or reach the
        // JSON/Schnorr path (GOSSIP-OVERSIZE-PREVERIFY).
        loop {
            match drain_line_capped(&mut buf, proto::MAX_FRAME_BYTES) {
                Drained::Line(line) => {
                    if let Some(data) = acc.process_line(&line) {
                        if let Some(msg) = parse_event_data(&data) {
                            if inbox_tx.send(msg).await.is_err() {
                                // Inbox receiver gone — bridge shutting down.
                                return SseOutcome::StreamEnded;
                            }
                        }
                    }
                }
                Drained::Oversize => {
                    tracing::warn!(
                        "x0xd /events: skipped SSE line > {} bytes",
                        proto::MAX_FRAME_BYTES
                    );
                }
                Drained::Pending => break,
            }
        }
    }
    SseOutcome::StreamEnded
}

/// Re-subscribe every topic in the active set on reconnect. For each topic we
/// first DELETE the stale forwarder (the daemon keeps forwarders alive after an
/// SSE disconnect — only DELETE removes them), tolerating 404, then POST a fresh
/// subscription and record the new id. This keeps exactly one live forwarder per
/// topic, preventing duplicate deliveries after repeated reconnects (C2).
/// Failures are logged per-topic but do not abort the supervisor.
async fn resubscribe_all(shared: &Shared) -> anyhow::Result<()> {
    // Snapshot topic + id pairs so we never hold a DashMap guard across an await.
    let topics: Vec<(String, String)> = shared
        .topics
        .iter()
        .map(|r| (r.key().clone(), r.value().clone()))
        .collect();
    for (topic, old_id) in &topics {
        if let Err(e) = shared.unsubscribe_once(old_id).await {
            tracing::warn!("DELETE /subscribe/{old_id} for '{topic}' failed: {e}");
        }
        match shared.subscribe_once(topic).await {
            Ok(new_id) => {
                shared.topics.insert(topic.clone(), new_id);
            }
            Err(e) => tracing::warn!("re-subscribe to '{topic}' failed: {e}"),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SSE parsing helpers (pure, unit-tested).
// ---------------------------------------------------------------------------

/// Outcome of a capped line drain.
enum Drained {
    /// A complete line within the byte cap.
    Line(String),
    /// A line (complete or partial) that exceeded the cap and was discarded.
    Oversize,
    /// No complete line is available yet.
    Pending,
}

/// Extract one complete SSE line from `buf`, enforcing a per-line byte cap. A
/// complete line longer than `max`, or a partial line (no newline yet) whose
/// accumulated length already exceeds `max`, is discarded and reported as
/// [`Drained::Oversize`] — bounding buffer memory and keeping oversized blobs
/// out of the JSON path.
fn drain_line_capped(buf: &mut Vec<u8>, max: usize) -> Drained {
    let Some(nl) = buf.iter().position(|&b| b == b'\n') else {
        // No newline yet. If the partial line alone is already oversize,
        // drop everything buffered so memory cannot grow without bound.
        if buf.len() > max {
            buf.clear();
            return Drained::Oversize;
        }
        return Drained::Pending;
    };
    if nl > max {
        // Complete line exceeds the cap: discard it (including the newline).
        buf.drain(..=nl);
        return Drained::Oversize;
    }
    let line: Vec<u8> = buf.drain(..nl).collect();
    buf.remove(0); // consume the newline
    let mut s = String::from_utf8_lossy(&line).into_owned();
    if s.ends_with('\r') {
        s.pop();
    }
    Drained::Line(s)
}

/// Incremental SSE line processor. Accumulates `data:` field lines and
/// dispatches the joined payload when a blank line terminates the event.
struct SseAccumulator {
    data_lines: Vec<String>,
}

impl SseAccumulator {
    fn new() -> Self {
        Self {
            data_lines: Vec::new(),
        }
    }

    /// Process one SSE line (newline already stripped). Returns the joined
    /// `data:` payload when a complete event is dispatched (on a blank line),
    /// otherwise `None`. Comment lines (`:` prefix) and unknown fields are
    /// silently ignored.
    fn process_line(&mut self, line: &str) -> Option<String> {
        if line.is_empty() {
            if self.data_lines.is_empty() {
                return None;
            }
            return Some(std::mem::take(&mut self.data_lines).join("\n"));
        }
        if line.starts_with(':') {
            // SSE comment — ignored, does not reset the data buffer.
            return None;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            // Per spec: strip exactly one optional leading space after the colon.
            let value = rest.strip_prefix(' ').unwrap_or(rest);
            self.data_lines.push(value.to_string());
        }
        // Other named fields (event:, id:, retry:) are ignored.
        None
    }
}

/// Parse a dispatched SSE event payload (the joined `data:` text) into a
/// `GossipMessage`. Only envelopes shaped
/// `{"type":"message","data":{"topic","payload",…}}` are recognised; the
/// base64 `payload` is decoded to raw bytes. Returns `None` for non-message
/// events, malformed JSON, missing fields, or bad base64.
fn parse_event_data(data: &str) -> Option<GossipMessage> {
    let v: serde_json::Value = serde_json::from_str(data).ok()?;
    if v.get("type").and_then(|t| t.as_str()) != Some("message") {
        return None;
    }
    let inner = v.get("data")?;
    let topic = inner.get("topic")?.as_str()?.to_string();
    let payload_b64 = inner.get("payload")?.as_str()?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .ok()?;
    // Defense-in-depth: a decoded payload over the frame cap is rejected before
    // it can reach the inbox / JSON re-parse path (GOSSIP-OVERSIZE-PREVERIFY).
    if payload.len() > proto::MAX_FRAME_BYTES {
        return None;
    }
    Some(GossipMessage { topic, payload })
}

// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ---- drain_line_capped ------------------------------------------------

    #[test]
    fn drain_line_capped_handles_lf_and_crlf() {
        let mut buf = b"a\r\nb\nc".to_vec();
        // max generously above content so the cap never trips here.
        assert!(matches!(
            drain_line_capped(&mut buf, 1024),
            Drained::Line(s) if s == "a"
        ));
        assert!(matches!(
            drain_line_capped(&mut buf, 1024),
            Drained::Line(s) if s == "b"
        ));
        assert!(matches!(
            drain_line_capped(&mut buf, 1024),
            Drained::Pending
        ));
        assert_eq!(buf, b"c");
    }

    #[test]
    fn drain_line_capped_empty_line() {
        let mut buf = b"\n".to_vec();
        assert!(matches!(
            drain_line_capped(&mut buf, 1024),
            Drained::Line(s) if s.is_empty()
        ));
        assert!(buf.is_empty());
    }

    #[test]
    fn drain_line_capped_drops_oversize_complete_line() {
        // A complete line longer than the cap is discarded, buffer cleared of it.
        let mut buf = b"abcdefghij\nx\n".to_vec();
        assert!(matches!(drain_line_capped(&mut buf, 4), Drained::Oversize));
        assert!(matches!(
            drain_line_capped(&mut buf, 4),
            Drained::Line(s) if s == "x"
        ));
    }

    #[test]
    fn drain_line_capped_drops_oversize_partial_line() {
        // No newline yet but the partial line already exceeds the cap.
        let mut buf = b"abcdefghij".to_vec();
        assert!(matches!(drain_line_capped(&mut buf, 4), Drained::Oversize));
        assert!(buf.is_empty());
    }

    // ---- SseAccumulator ---------------------------------------------------

    #[test]
    fn sse_good_data_line_dispatches_on_blank() {
        let mut acc = SseAccumulator::new();
        assert!(acc
            .process_line(r#"data: {"type":"message","data":{"topic":"t","payload":"aGk="}}"#)
            .is_none());
        let dispatched = acc.process_line("").unwrap();
        assert!(dispatched.contains(r#""type":"message""#));
    }

    #[test]
    fn sse_comment_line_is_ignored() {
        let mut acc = SseAccumulator::new();
        assert!(acc.process_line(": this is a heartbeat comment").is_none());
        // Blank line with no preceding data → nothing dispatched.
        assert!(acc.process_line("").is_none());
    }

    #[test]
    fn sse_multi_line_data_is_joined_with_newline() {
        let mut acc = SseAccumulator::new();
        assert!(acc.process_line("data: first").is_none());
        assert!(acc.process_line("data: second").is_none());
        let dispatched = acc.process_line("").unwrap();
        assert_eq!(dispatched, "first\nsecond");
    }

    #[test]
    fn sse_garbage_and_unknown_fields_are_ignored() {
        let mut acc = SseAccumulator::new();
        // Unknown field lines are ignored.
        assert!(acc.process_line("event: ping").is_none());
        assert!(acc.process_line("id: 42").is_none());
        assert!(acc.process_line("retry: 5000").is_none());
        // Pure garbage that isn't even a field: ignored.
        assert!(acc
            .process_line("total nonsense without a colon prefix that matters")
            .is_none());
        // Blank line → no data accumulated → nothing dispatched.
        assert!(acc.process_line("").is_none());
    }

    // ---- parse_event_data -------------------------------------------------

    #[test]
    fn parse_event_decodes_base64_payload() {
        // base64("hi") = "aGk="
        let data = r#"{"type":"message","data":{"topic":"updates","payload":"aGk="}}"#;
        let msg = parse_event_data(data).unwrap();
        assert_eq!(msg.topic, "updates");
        assert_eq!(msg.payload, b"hi");
    }

    #[test]
    fn parse_event_decodes_binary_payload() {
        let bytes = [0u8, 1, 2, 255, 128];
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        let data = format!(r#"{{"type":"message","data":{{"topic":"bin","payload":"{b64}"}}}}"#);
        let msg = parse_event_data(&data).unwrap();
        assert_eq!(msg.payload, bytes);
    }

    #[test]
    fn parse_event_rejects_non_message_type() {
        let data = r#"{"type":"presence","data":{"topic":"x","payload":"aGk="}}"#;
        assert!(parse_event_data(data).is_none());
    }

    #[test]
    fn parse_event_rejects_garbage_json() {
        assert!(parse_event_data("this is not json at all").is_none());
        assert!(parse_event_data("").is_none());
    }

    #[test]
    fn parse_event_rejects_bad_base64() {
        let data = r#"{"type":"message","data":{"topic":"t","payload":"@@@not-valid@@@"}}"#;
        assert!(parse_event_data(data).is_none());
    }

    #[test]
    fn parse_event_rejects_missing_fields() {
        assert!(parse_event_data(r#"{"type":"message"}"#).is_none());
        assert!(parse_event_data(r#"{"type":"message","data":{}}"#).is_none());
        assert!(parse_event_data(r#"{"type":"message","data":{"topic":"t"}}"#).is_none());
    }

    // ---- normalize_base_url ----------------------------------------------

    #[test]
    fn normalize_adds_scheme_and_strips_trailing_slash() {
        assert_eq!(
            normalize_base_url("127.0.0.1:12700"),
            "http://127.0.0.1:12700"
        );
        assert_eq!(
            normalize_base_url("http://127.0.0.1:12700"),
            "http://127.0.0.1:12700"
        );
        assert_eq!(
            normalize_base_url("http://127.0.0.1:12700/"),
            "http://127.0.0.1:12700"
        );
        assert_eq!(
            normalize_base_url("  https://host:443/path/  "),
            "https://host:443/path"
        );
    }

    // ---- Integration tests against a local axum mock daemon ---------------

    use axum::extract::State;
    use axum::response::IntoResponse;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Minimal axum router mocking the three daemon endpoints we exercise.
    /// Returns the bound address and a handle to the shared counters.
    struct MockDaemon {
        addr: std::net::SocketAddr,
    }

    async fn spawn_mock(subscribe_calls: Arc<AtomicUsize>) -> MockDaemon {
        let app = axum::Router::new()
            .route(
                "/health",
                axum::routing::get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
            )
            .route("/subscribe", axum::routing::post(subscribe_handler))
            .with_state(Arc::clone(&subscribe_calls));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        MockDaemon { addr }
    }

    async fn subscribe_handler(
        State(calls): State<Arc<AtomicUsize>>,
        _body: axum::extract::Json<serde_json::Value>,
    ) -> axum::Json<serde_json::Value> {
        calls.fetch_add(1, Ordering::SeqCst);
        axum::Json(serde_json::json!({"ok": true, "subscription_id": "mock"}))
    }

    #[tokio::test]
    async fn ensure_topic_is_idempotent_no_duplicate_posts() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mock = spawn_mock(Arc::clone(&calls)).await;
        let base = format!("http://{}", mock.addr);

        let transport = X0xTransport::connect(&base, "test-token").await.unwrap();

        // First call subscribes.
        transport.ensure_topic("buzz.v1.global").await.unwrap();
        // Second call for the same topic must NOT POST again.
        transport.ensure_topic("buzz.v1.global").await.unwrap();
        // A different topic does subscribe.
        transport.ensure_topic("buzz.v1.ch.general").await.unwrap();
        // And repeating it is a no-op.
        transport.ensure_topic("buzz.v1.ch.general").await.unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 2, "expected exactly 2 POSTs");
    }

    #[tokio::test]
    async fn publish_sends_base64_payload() {
        use std::sync::Mutex;
        let received: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(vec![]));

        async fn pub_handler(
            State(store): State<Arc<Mutex<Vec<serde_json::Value>>>>,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> axum::Json<serde_json::Value> {
            store.lock().unwrap().push(body);
            axum::Json(serde_json::json!({"ok": true}))
        }

        let app = axum::Router::new()
            .route(
                "/health",
                axum::routing::get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
            )
            .route("/publish", axum::routing::post(pub_handler))
            .with_state(Arc::clone(&received));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://{addr}");
        let transport = X0xTransport::connect(&base, "tok").await.unwrap();
        transport.publish("updates", b"hello world").await.unwrap();

        let got = received.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["topic"], "updates");
        // base64("hello world")
        assert_eq!(got[0]["payload"].as_str().unwrap(), "aGVsbG8gd29ybGQ=");
    }

    #[tokio::test]
    async fn inbox_delivers_decoded_sse_message() {
        // Mock /events that emits one gossip message as SSE then closes.
        async fn events_handler() -> impl IntoResponse {
            let body = "data: {\"type\":\"message\",\"data\":{\"topic\":\"updates\",\"payload\":\"aGk=\"}}\n\n";
            (
                [
                    ("content-type", "text/event-stream"),
                    ("cache-control", "no-cache"),
                ],
                body,
            )
        }

        let app = axum::Router::new()
            .route(
                "/health",
                axum::routing::get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
            )
            .route("/events", axum::routing::get(events_handler))
            .with_state(());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://{addr}");
        let transport = X0xTransport::connect(&base, "tok").await.unwrap();
        let mut rx = transport.inbox();

        let msg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for SSE message")
            .expect("inbox closed without a message");

        assert_eq!(msg.topic, "updates");
        assert_eq!(msg.payload, b"hi");
    }

    #[tokio::test]
    async fn inbox_take_once_second_call_returns_closed() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mock = spawn_mock(Arc::clone(&calls)).await;
        let base = format!("http://{}", mock.addr);

        let transport = X0xTransport::connect(&base, "tok").await.unwrap();
        let _first = transport.inbox();
        let mut second = transport.inbox();
        // The second receiver must be already closed (no sender).
        assert!(second.recv().await.is_none());
    }

    #[tokio::test]
    async fn connect_fails_when_daemon_unreachable() {
        // Bind and immediately drop to get an unused port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let base = format!("http://{addr}");
        let result = X0xTransport::connect(&base, "tok").await;
        assert!(result.is_err(), "connect should fail when daemon is down");
        let msg = format!("{}", result.err().unwrap());
        assert!(
            msg.contains("cannot reach x0xd") || msg.contains("/health"),
            "error should mention the daemon: {msg}"
        );
    }

    #[test]
    fn inbox_capacity_constant_matches_contract() {
        assert_eq!(INBOX_CAPACITY, 1024);
    }
}

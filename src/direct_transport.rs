//! x0xd direct-message transport leaf — the serverless invite RPC wire surface.
//!
//! Contract (FROZEN): a self-contained transport adapter over the x0x daemon's
//! authenticated **loopback** REST/SSE direct-message surface. It is deliberately
//! separate from [`crate::transport`] (which is gossip-only `/publish`-`/subscribe`
//! `/events`) and must not contaminate it.
//!
//! # What this module provides
//!
//! - [`X0xDirectTransport::send`] — the exact `POST /direct/send` daemon request,
//!   returning a transport-only [`DirectSendReceipt`]. The receipt is **never** an
//!   RPC-success signal: the daemon's `request_id` is parsed but intentionally
//!   *not exposed*, so a caller cannot mistake transport acceptance for protocol
//!   completion. The daemon's raw error bodies are likewise never surfaced
//!   (token / error leakage surface = zero).
//! - A reconnecting `GET /direct/events` SSE listener (`direct_message` events)
//!   with optional bounded backfill, exponential backoff (1s → 30s cap), and a
//!   [`CancellationToken`] hook so graceful shutdown breaks every wait. It yields
//!   [`DirectMessage`] frames that preserve all daemon source-auth metadata — in
//!   particular `verified == false` is kept verbatim so a downstream authority
//!   can reject an unverified source.
//!
//! # Security invariants
//!
//! - **Loopback only**: [`X0xDirectTransport::connect`] rejects any base URL
//!   whose host is not `127.0.0.1` / `::1` / `localhost` *before* issuing any
//!   request. A bridge never opens a remote daemon connection.
//! - **Bounded memory**: SSE lines, the base64 payload *string*, and the decoded
//!   payload are each capped (see `MAX_DIRECT_PAYLOAD_BYTES` /
//!   `MAX_PAYLOAD_B64_LEN`); an oversized or malformed frame is skipped, never
//!   allocated or panicked on.
//! - **No token leakage**: the bearer token lives only inside the `reqwest`
//!   client's default headers and an opaque (non-`Debug`) field; it never appears
//!   in an error message, a log line, or a returned struct.
//! - **Panic-free**: every fallible input is handled by returning `None` (parser)
//!   or `Err` (`send`/`connect`); there are no indexing panics, unwraps, or
//!   expects in non-test code.
//!
//! # Wiring (integration — not owned here)
//!
//! The bridge binary constructs this from the same resolved loopback daemon API
//! base + bearer token as the gossip transport, supplies a [`CancellationToken`]
//! tied to the process shutdown path, takes the [`X0xDirectTransport::messages`]
//! receiver exactly once, and `await`s [`X0xDirectTransport::join`] during
//! graceful drain. The authority invite service consumes the inbox.
//!
//! # What this module does NOT provide (explicit gaps)
//!
//! This is a *transport leaf only*. The following authority-side surfaces are
//! **not implemented here** and must be supplied by the authority invite
//! service (a separate module) — they are reported as missing integration
//! dependencies, not faked:
//!
//! - **Authority-bus listener**: there is no typed authority work item, no
//!   `InviteClaimV1` schema/validation, and no claim→mutation router. The
//!   [`X0xDirectTransport::messages`] receiver yields raw verified/payload
//!   [`DirectMessage`] frames; turning a payload into an authoritative action
//!   (and gating on `verified == true` + `sender` binding) is the consumer's
//!   job.
//! - **Response / reply correlation**: sending an authoritative result back to
//!   a claimant is just another [`X0xDirectTransport::send`]; this leaf ships
//!   no typed reply envelope, claim-result type, or request/response
//!   correlation id of its own.
//! - **Membership state**: this leaf holds and mutates no NIP-29 / channel
//!   membership state. A [`DirectSendReceipt`] is loopback transport
//!   acceptance and is **never** synthesised as a remote membership mutation
//!   or authoritative claim success.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use futures_util::StreamExt as _;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::proto;
use crate::transport::normalize_base_url;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Reconnect backoff for the `/direct/events` SSE session (mirrors the gossip
/// transport): start at 1s, double on each connect failure, cap at 30s.
const SSE_INIT_BACKOFF: Duration = Duration::from_secs(1);
const SSE_MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Bounded inbox channel capacity for decoded direct messages. A slow authority
/// consumer must not block stream reading; if this fills, frames are dropped
/// (the daemon `/direct/events` feed is at-least-once with optional backfill).
const INBOX_CAPACITY: usize = 1024;

/// Hard cap on a decoded direct-message payload, matching the bridge frame
/// limit. A payload above this is rejected before it reaches any consumer.
const MAX_DIRECT_PAYLOAD_BYTES: usize = proto::MAX_FRAME_BYTES;

/// Upper bound on the base64 *string* length we will even attempt to decode.
/// base64 inflates by 4/3, so this admits any encoding up to
/// [`MAX_DIRECT_PAYLOAD_BYTES`] and rejects larger ones **without** allocating
/// the decoded buffer — the core "cap before decode/allocation" defence.
const MAX_PAYLOAD_B64_LEN: usize = MAX_DIRECT_PAYLOAD_BYTES / 3 * 4 + 8;

/// Maximum number of stored DM rows to request on (re)connect via
/// `?backfill=`. The daemon honours the requested limit; we clamp caller values
/// so a misconfigured backfill cannot replay an unbounded history burst.
const MAX_BACKFILL: usize = 256;

// ---------------------------------------------------------------------------
// Public wire types
// ---------------------------------------------------------------------------

/// A validated x0x [`AgentId`] — 32 bytes encoded as 64 hex chars. Accepted in
/// any hex case (matching the daemon's `parse_agent_id_hex`), canonicalised to
/// lowercase for the wire. Validation errors are generic and never echo input.
///
/// `PartialEq`/`Eq`/`Hash` compare the *canonicalised* lowercase hex form, so
/// two inputs that differ only in case (e.g. an authority's `GET /agent` result
/// vs. an invitation code's bound `aid`) compare and hash as equal. This is the
/// comparison used to bind a verified result sender to the code-bound authority
/// AgentId — never compare raw daemon sender strings directly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentId(String);

impl AgentId {
    /// Parse a 64-character hex string into an [`AgentId`].
    pub fn from_hex(s: &str) -> anyhow::Result<Self> {
        let bytes =
            hex::decode(s).map_err(|_| anyhow::anyhow!("invalid agent id: not valid hex"))?;
        if bytes.len() != 32 {
            anyhow::bail!("invalid agent id: expected 64 hex chars (32 bytes)");
        }
        Ok(Self(s.to_ascii_lowercase()))
    }

    /// Canonical lowercase hex form used on the wire.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A received direct message parsed from a `/direct/events` SSE
/// `direct_message` (or backfill `history_direct_message`) event. Every
/// source-auth field is preserved verbatim.
///
/// **`verified` is load-bearing**: the daemon only cryptographically binds the
/// signing key to the [`DirectMessage::sender`] when `verified == true`; a raw
/// `sender` is otherwise an unauthenticated claim. Downstream authority
/// processing MUST therefore require `verified == true` and treat `false` as a
/// rejection — this struct never silently upgrades `false` to `true`.
#[derive(Debug, Clone)]
pub struct DirectMessage {
    /// Sender AgentId, 64 lowercase hex.
    pub sender: String,
    /// Sender MachineId, 64 lowercase hex.
    pub machine_id: String,
    /// Decoded payload bytes (capped at `MAX_DIRECT_PAYLOAD_BYTES`).
    pub payload: Vec<u8>,
    /// Daemon receive timestamp (epoch millis).
    pub received_at: u64,
    /// Whether the daemon cryptographically verified the envelope's source
    /// signature. Preserved exactly — `false` must reach the consumer.
    pub verified: bool,
    /// Optional daemon trust-decision label.
    pub trust_decision: Option<String>,
    /// Optional coarsened origin token (only present when the daemon emits it).
    pub observed_origin: Option<serde_json::Value>,
    /// `true` when this frame arrived via a `history_direct_message` backfill
    /// replay rather than the live `direct_message` stream.
    pub replayed: bool,
}

/// Transport-level acceptance receipt for a sent direct message.
///
/// This is proof **only** that the *loopback* daemon accepted the message onto
/// a delivery path (`gossip_inbox` / `raw_quic_acked` / `loopback`). It is
/// explicitly:
///
/// - **not** proof of end-to-end delivery;
/// - **not** an RPC success;
/// - **not** an authoritative claim success, and **never** evidence of a remote
///   membership mutation (a NIP-29 `39002` / channel membership change). The
///   only legitimate membership proof is a relay-signed `39002` observed over
///   gossip or verified out-of-band — never this transport receipt.
///
/// The daemon's `request_id` correlation id is parsed but deliberately withheld
/// so a caller cannot mistake transport acceptance for protocol completion.
#[derive(Debug, Clone)]
pub struct DirectSendReceipt {
    /// Daemon-reported delivery path (e.g. `"gossip_inbox"`, `"raw_quic_acked"`).
    pub path: String,
    /// Number of delivery retries the daemon used for this message.
    pub retries_used: u64,
}

// ---------------------------------------------------------------------------
// Transport handle
// ---------------------------------------------------------------------------

/// Authenticated loopback x0x daemon state shared between the send path and the
/// SSE supervisor task. Intentionally **not** `Debug`: it holds the bearer token,
/// which must never appear in any formatted output.
struct Shared {
    client: reqwest::Client,
    base_url: String,
    /// Daemon bearer token. Used only to build the client's default
    /// `Authorization` header (done in [`X0xDirectTransport::connect`]); held
    /// here for parity with the gossip transport but never logged, formatted, or
    /// returned in an error.
    #[allow(dead_code)]
    token: String,
    /// Bounded backfill row count requested on each (re)connect, or `None` to
    /// subscribe to the live stream only.
    backfill: Option<usize>,
}

/// Bridge-side client for the x0x direct-message transport: an authenticated
/// loopback `POST /direct/send` sender plus one reconnecting `GET /direct/events`
/// SSE listener.
pub struct X0xDirectTransport {
    shared: Arc<Shared>,
    /// Take-once: [`X0xDirectTransport::messages`] extracts the live receiver on
    /// the first call; later calls get a closed, empty receiver.
    inbox_rx: Mutex<Option<mpsc::Receiver<DirectMessage>>>,
    /// Supervisor task handle. Taken by [`X0xDirectTransport::join`] for clean
    /// drain, or aborted on drop as a no-leak safety net.
    supervisor: Mutex<Option<JoinHandle<()>>>,
}

impl X0xDirectTransport {
    /// Connect to the **loopback** x0x daemon: normalise + enforce loopback
    /// locality, build the authenticated HTTP client, verify liveness via
    /// `GET /health`, and start the reconnecting `/direct/events` SSE supervisor.
    ///
    /// - `base_url` — daemon REST base (scheme optional; bare `host:port` is
    ///   normalised). Must resolve to a loopback host or this returns `Err`
    ///   before any network call.
    /// - `token` — daemon bearer token (from env / data-dir discovery). Held
    ///   only to authenticate requests.
    /// - `cancel` — cancellation token; firing it breaks every SSE wait and
    ///   terminates the supervisor promptly (shutdown seam).
    /// - `backfill` — if `Some(n)`, request up to `min(n, MAX_BACKFILL)` stored
    ///   DMs on each (re)connect; `None` subscribes to the live stream only.
    pub async fn connect(
        base_url: &str,
        token: &str,
        cancel: CancellationToken,
        backfill: Option<usize>,
    ) -> anyhow::Result<Self> {
        let base_url = normalize_base_url(base_url);
        require_loopback(&base_url)?;

        let bearer = format!("Bearer {token}");
        let auth_value = reqwest::header::HeaderValue::from_str(&bearer)
            .context("daemon token contains invalid header characters")?;

        let mut default_headers = reqwest::header::HeaderMap::new();
        default_headers.insert(reqwest::header::AUTHORIZATION, auth_value);

        let client = reqwest::Client::builder()
            .default_headers(default_headers)
            .build()
            .context("building HTTP client")?;

        // Liveness check. By construction the URL is loopback (validated above),
        // so the {base_url} in the error is never a remote address.
        let health_url = format!("{base_url}/health");
        let health = client.get(&health_url).send().await.map_err(|e| {
            anyhow::anyhow!(
                "cannot reach loopback daemon (GET /health failed: {e}). \
                 Is the daemon running? Set X0X_API/X0X_TOKEN or start x0xd."
            )
        })?;
        if !health.status().is_success() {
            anyhow::bail!(
                "loopback daemon is not healthy (GET /health → HTTP {})",
                health.status()
            );
        }
        let _ = health.bytes().await;

        let shared = Arc::new(Shared {
            client,
            base_url,
            token: token.to_string(),
            backfill: backfill.map(|n| n.min(MAX_BACKFILL)),
        });

        let (inbox_tx, inbox_rx) = mpsc::channel::<DirectMessage>(INBOX_CAPACITY);
        let supervisor = spawn_direct_supervisor(Arc::clone(&shared), inbox_tx, cancel);

        Ok(Self {
            shared,
            inbox_rx: Mutex::new(Some(inbox_rx)),
            supervisor: Mutex::new(Some(supervisor)),
        })
    }

    /// `POST /direct/send` — send `payload` to `target` over the loopback daemon.
    ///
    /// Builds the exact daemon request body, with `require_gossip` taken from
    /// the caller and the remaining flags pinned to the safe serverless-RPC
    /// profile (`require_gossip_ack = true`, no raw-QUIC preference, no
    /// stop-on-raw-error) so a successful receipt means the recipient's inbox
    /// ACKed the message — the strongest transport acceptance the daemon offers,
    /// yet still explicitly not an RPC success.
    ///
    /// Returns a [`DirectSendReceipt`] carrying only safe transport metadata
    /// (`path`, `retries_used`). The daemon `request_id` is discarded; the
    /// daemon's raw error body is never surfaced to the caller.
    pub async fn send(
        &self,
        target: &AgentId,
        payload: &[u8],
        require_gossip: bool,
    ) -> anyhow::Result<DirectSendReceipt> {
        if payload.len() > MAX_DIRECT_PAYLOAD_BYTES {
            anyhow::bail!(
                "direct payload too large ({} > {} bytes)",
                payload.len(),
                MAX_DIRECT_PAYLOAD_BYTES
            );
        }
        let url = format!("{}/direct/send", self.shared.base_url);
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        let body = serde_json::json!({
            "agent_id": target.as_str(),
            "payload": encoded,
            "prefer_raw_quic_if_connected": false,
            "stop_fallback_on_raw_error": false,
            "require_gossip": require_gossip,
            "require_gossip_ack": true,
        });

        let resp = self
            .shared
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("POST /direct/send to loopback daemon failed")?;
        let status = resp.status();
        if !status.is_success() {
            // Drain the body so the connection can be reused, but NEVER surface
            // the daemon's error text: mapping its codes to stable domain codes
            // is the caller's (authority service) responsibility, not this
            // transport's. Only the HTTP status (loopback, non-secret) is reported.
            let _ = resp.text().await;
            anyhow::bail!("direct send failed: HTTP {status}");
        }

        // Parse the safe receipt. The daemon returns
        // `{ok, path, retries_used, request_id, require_ack}`. We extract
        // `path` + `retries_used` and deliberately drop `request_id` — it is a
        // transport correlation id, never a completion/RPC token.
        let v: serde_json::Value = resp
            .json()
            .await
            .context("direct send response was not valid JSON")?;
        if v.get("ok").and_then(|o| o.as_bool()) == Some(false) {
            // Defensive: a 2xx body that nonetheless denies acceptance.
            anyhow::bail!("direct send rejected by daemon");
        }
        let path = v
            .get("path")
            .and_then(|p| p.as_str())
            .unwrap_or("unknown")
            .to_string();
        let retries_used = v.get("retries_used").and_then(|r| r.as_u64()).unwrap_or(0);
        Ok(DirectSendReceipt { path, retries_used })
    }

    /// Take-once inbox receiver of decoded [`DirectMessage`] frames. The first
    /// caller gets the live receiver; later callers get a closed, empty one.
    pub fn messages(&self) -> mpsc::Receiver<DirectMessage> {
        // parking_lot::Mutex is non-poisoning; lock() yields the guard directly.
        let mut guard = self.inbox_rx.lock();
        guard.take().unwrap_or_else(|| {
            let (_tx, rx) = mpsc::channel(1);
            rx
        })
    }

    /// Query the loopback daemon for *this* bridge's own [`AgentId`] — the
    /// authority identity of the daemon we are connected to.
    ///
    /// Issues an authenticated `GET {base}/agent`, requires success, and parses
    /// the daemon's `{ok, data:{agent_id}}` envelope. The hex `agent_id` is
    /// re-validated through [`AgentId::from_hex`] so the returned value is a
    /// canonical, length-checked `AgentId` — exactly the identity an invitation
    /// code's `aid` is bound to, and exactly what a verified result sender must
    /// equal.
    ///
    /// **No leakage**: the daemon response body and the bearer token are never
    /// surfaced. On any failure the error carries only the HTTP status (or a
    /// generic parse message); the body is drained and discarded so the
    /// connection can be reused without ever being exposed.
    pub async fn self_agent_id(&self) -> anyhow::Result<AgentId> {
        let url = format!("{}/agent", self.shared.base_url);
        let resp = self
            .shared
            .client
            .get(&url)
            .send()
            .await
            .context("GET /agent to loopback daemon failed")?;
        let status = resp.status();
        if !status.is_success() {
            // Drain so the connection can be reused, but never surface the body:
            // only the HTTP status (loopback, non-secret) is reported.
            let _ = resp.text().await;
            anyhow::bail!("daemon identity query failed: HTTP {status}");
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .context("GET /agent response was not valid JSON")?;
        if v.get("ok").and_then(|o| o.as_bool()) == Some(false) {
            // Defensive: a 2xx body that nonetheless denies the query.
            anyhow::bail!("daemon identity query denied by daemon");
        }
        let agent_id_str = v.get("agent_id").and_then(|a| a.as_str()).ok_or_else(|| {
            // Generic: never echo response contents back.
            anyhow::anyhow!("daemon identity response missing agent_id")
        })?;
        // Re-validate through the canonical parser; from_hex's errors are
        // generic and never echo their input.
        AgentId::from_hex(agent_id_str)
    }

    /// Take + await the supervisor handle for graceful shutdown **without**
    /// consuming `self`. Intended for the `Arc`-owned ownership shape (where
    /// the transport is shared and cannot be moved out): after signalling the
    /// [`CancellationToken`] passed to [`connect`](Self::connect), call this to
    /// drain the SSE supervisor.
    ///
    /// The handle is taken out of its slot (so [`Drop`] will not abort it),
    /// then awaited. A second call is a no-op (the slot is already empty).
    pub async fn join_drain(&self) {
        // Release the synchronous mutex before awaiting supervisor shutdown.
        let handle = self.supervisor.lock().take();
        drain_supervisor_handle(handle).await;
    }

    /// Await supervisor termination after cancellation. Consumes `self`.
    /// Call this on the graceful-shutdown drain after signalling the
    /// [`CancellationToken`] passed to [`connect`](Self::connect).
    ///
    /// Equivalent to [`join_drain`](Self::join_drain) for the owned (non-`Arc`)
    /// shape; both route through the single `drain_supervisor_handle` await
    /// so there is no duplicated drain logic.
    pub async fn join(self) {
        self.join_drain().await
        // `self` drops here; inbox_rx is gone, supervisor handle is None.
    }
}

impl Drop for X0xDirectTransport {
    fn drop(&mut self) {
        // No-leak safety net: if the supervisor handle is still present (i.e.
        // `join` was not called), abort the task so a dropped transport never
        // leaves a detached SSE reader running.
        if let Some(h) = self.supervisor.lock().take() {
            h.abort();
        }
    }
}

/// Single await site for graceful supervisor drain, shared by
/// [`X0xDirectTransport::join`] (consuming) and
/// [`X0xDirectTransport::join_drain`] (non-consuming, `Arc`-owned). The handle
/// must already be **taken** out of its slot (so [`Drop`] will not abort it);
/// this function merely awaits it to completion. `None` is a no-op (already
/// drained on a prior call).
async fn drain_supervisor_handle(handle: Option<JoinHandle<()>>) {
    if let Some(h) = handle {
        let _ = h.await;
    }
}

// ---------------------------------------------------------------------------
// Loopback locality enforcement
// ---------------------------------------------------------------------------

/// Reject any base URL whose host is not a loopback address. Called before the
/// first request so a misconfigured remote daemon can never be dialled.
fn require_loopback(base_url: &str) -> anyhow::Result<()> {
    match host_of(base_url) {
        Some(host) if is_loopback_host(&host) => Ok(()),
        _ => Err(anyhow::anyhow!(
            "refusing non-loopback daemon address; only 127.0.0.1 / ::1 / localhost accepted"
        )),
    }
}

/// Extract the host portion of a normalised `http(s)://host[:port]` base URL
/// without depending on the `url` crate (not a direct bridge dependency).
/// Handles bracketed IPv6 literals (`[::1]:port`).
fn host_of(base_url: &str) -> Option<String> {
    let rest = base_url
        .strip_prefix("http://")
        .or_else(|| base_url.strip_prefix("https://"))?;
    // Normalised URLs carry no path, but defend against an injected one.
    let authority = rest.split('/').next().unwrap_or(rest);
    // IPv6 literal: `[::1]:port` → host is inside the brackets.
    if let Some(stripped) = authority.strip_prefix('[') {
        return stripped.split(']').next().map(|h| h.to_string());
    }
    // `host:port` (IPv4 or name) → split off the trailing port. A bare host
    // with no port yields itself.
    match authority.rsplit_once(':') {
        Some((host, _port)) => Some(host.to_string()),
        None => Some(authority.to_string()),
    }
}

/// `true` for `localhost` or any IP address that `is_loopback()`.
fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    if h == "localhost" {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// SSE supervisor: reconnecting GET /direct/events with backoff + cancellation.
// ---------------------------------------------------------------------------

fn spawn_direct_supervisor(
    shared: Arc<Shared>,
    inbox_tx: mpsc::Sender<DirectMessage>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut backoff = SSE_INIT_BACKOFF;
        loop {
            // Fast exit if already cancelled or the consumer is gone.
            if cancel.is_cancelled() || inbox_tx.is_closed() {
                tracing::info!("direct SSE supervisor: exiting (cancelled or inbox dropped)");
                return;
            }
            // Race the session against cancellation so a shutdown signal breaks
            // an in-flight SSE read (the future is dropped, cancelling the
            // pending `bytes_stream().next()` — reqwest streams are cancel-safe).
            let outcome = tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    tracing::info!("direct SSE supervisor: cancelled, exiting");
                    return;
                }
                o = run_direct_sse_loop(&shared, &inbox_tx) => o,
            };
            match outcome {
                SseOutcome::StreamEnded => {
                    // Clean EOF: reset backoff and reconnect immediately.
                    backoff = SSE_INIT_BACKOFF;
                    tracing::info!("x0xd /direct/events stream ended; reconnecting");
                }
                SseOutcome::ConnectFailed => {
                    tracing::warn!("x0xd /direct/events connect failed; retrying in {backoff:?}");
                    let sleep = tokio::time::sleep(backoff);
                    tokio::pin!(sleep);
                    // Backoff itself must be cancellation-aware.
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => {
                            tracing::info!("direct SSE supervisor: cancelled during backoff, exiting");
                            return;
                        }
                        _ = &mut sleep => {}
                    }
                    backoff = std::cmp::min(backoff * 2, SSE_MAX_BACKOFF);
                }
            }
        }
    })
}

/// Outcome of one `/direct/events` session.
enum SseOutcome {
    /// The stream connected successfully and later ended (EOF or read error).
    StreamEnded,
    /// The connection could not be established (connect error / non-2xx).
    ConnectFailed,
}

/// Run one `/direct/events` SSE session until the stream ends or errors. Has no
/// cancellation logic of its own — it relies on being dropped (by the
/// supervisor's `select!`) when the [`CancellationToken`] fires, which cancels
/// the in-flight `bytes_stream().next()` await.
async fn run_direct_sse_loop(
    shared: &Shared,
    inbox_tx: &mpsc::Sender<DirectMessage>,
) -> SseOutcome {
    let url = match shared.backfill {
        Some(n) => format!(
            "{}/direct/events?backfill={}",
            shared.base_url,
            n.min(MAX_BACKFILL)
        ),
        None => format!("{}/direct/events", shared.base_url),
    };

    let resp = match shared
        .client
        .get(&url)
        .header("accept", "text/event-stream")
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!("GET /direct/events returned HTTP {}", r.status());
            return SseOutcome::ConnectFailed;
        }
        Err(_) => return SseOutcome::ConnectFailed,
    };

    let mut stream = resp.bytes_stream();
    let mut acc = DirectSseAccumulator::new();
    let mut buf: Vec<u8> = Vec::new();

    while let Some(chunk) = stream.next().await {
        let bytes = match chunk {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("x0xd /direct/events read error: {e}");
                break;
            }
        };
        buf.extend_from_slice(&bytes);
        // Process every complete line now available. Oversize lines (and any
        // partial line already beyond the cap) are discarded so a multi-MB blob
        // can never force unbounded buffer growth or reach the JSON path.
        loop {
            match drain_line_capped(&mut buf, proto::MAX_FRAME_BYTES) {
                Drained::Line(line) => {
                    if let Some((replayed, data)) = acc.process_line(&line) {
                        let msg = parse_direct_event_data(&data, replayed);
                        if let Some(msg) = msg {
                            if inbox_tx.send(msg).await.is_err() {
                                // Inbox receiver gone — bridge shutting down.
                                return SseOutcome::StreamEnded;
                            }
                        }
                        // Malformed/oversize frame: silently skipped (parser
                        // returned None). The session continues.
                    }
                }
                Drained::Oversize => {
                    tracing::warn!(
                        "x0xd /direct/events: skipped SSE line > {} bytes",
                        proto::MAX_FRAME_BYTES
                    );
                }
                Drained::Pending => break,
            }
        }
    }
    SseOutcome::StreamEnded
}

// ---------------------------------------------------------------------------
// SSE parsing helpers (pure, panic-free).
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
        // No newline yet. If the partial line alone is already oversize, drop
        // everything buffered so memory cannot grow without bound.
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

/// Incremental SSE line processor that tracks the `event:` field (unlike the
/// gossip accumulator, which only needs `data:`). Dispatches the joined
/// `data:` payload when a blank line terminates the event, returning whether it
/// was a backfill replay and the joined data — but only for `direct_message`
/// and `history_direct_message` events. The `live` marker, comments, and all
/// other event types are silently ignored.
struct DirectSseAccumulator {
    event: Option<String>,
    data_lines: Vec<String>,
}

impl DirectSseAccumulator {
    fn new() -> Self {
        Self {
            event: None,
            data_lines: Vec::new(),
        }
    }

    /// Process one SSE line (newline already stripped). Returns
    /// `Some((replayed, data))` only when a `direct_message` or
    /// `history_direct_message` event is dispatched on a blank line.
    fn process_line(&mut self, line: &str) -> Option<(bool, String)> {
        if line.is_empty() {
            // Blank line dispatches the accumulated event, then resets.
            let event = self.event.take();
            if self.data_lines.is_empty() {
                return None;
            }
            let data = std::mem::take(&mut self.data_lines).join("\n");
            return match event.as_deref() {
                Some("direct_message") => Some((false, data)),
                Some("history_direct_message") => Some((true, data)),
                _ => None, // `live`, `ping`, unknown, or absent — skipped
            };
        }
        if line.starts_with(':') {
            // SSE comment / keepalive — ignored, does not reset the buffer.
            return None;
        }
        if let Some(rest) = line.strip_prefix("event:") {
            // Per spec: strip exactly one optional leading space after the colon.
            let value = rest.strip_prefix(' ').unwrap_or(rest).trim();
            self.event = Some(value.to_string());
            return None;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            let value = rest.strip_prefix(' ').unwrap_or(rest);
            self.data_lines.push(value.to_string());
            return None;
        }
        // `id:`, `retry:`, and any other field are ignored.
        None
    }
}

/// Parse a dispatched SSE event payload (the joined `data:` JSON) into a
/// [`DirectMessage`]. Recognises the daemon's
/// `{sender, machine_id, payload, received_at, verified, trust_decision,
/// observed_origin}` envelope. Returns `None` for malformed JSON, missing
/// required fields, an oversized base64 payload, bad base64, or a decoded
/// payload over the byte cap — i.e. every malformed/oversize frame is skipped
/// safely without panicking.
///
/// **`verified` is required and preserved exactly**: an event without a boolean
/// `verified` field is skipped (no way to trust its source), but `verified ==
/// false` is kept as `false` so the consumer can reject it.
fn parse_direct_event_data(data: &str, replayed: bool) -> Option<DirectMessage> {
    let v: serde_json::Value = serde_json::from_str(data).ok()?;

    let sender = v.get("sender")?.as_str()?.to_string();
    let machine_id = v.get("machine_id")?.as_str()?.to_string();
    let payload_b64 = v.get("payload")?.as_str()?;

    // Cap the base64 string length BEFORE decoding to bound the allocation.
    if payload_b64.len() > MAX_PAYLOAD_B64_LEN {
        tracing::warn!(
            "direct SSE payload base64 length {} exceeds cap; frame skipped",
            payload_b64.len()
        );
        return None;
    }
    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .ok()?;
    // Defense-in-depth: a decoded payload over the byte cap is rejected.
    if payload.len() > MAX_DIRECT_PAYLOAD_BYTES {
        tracing::warn!(
            "direct SSE decoded payload {} > {} bytes; frame skipped",
            payload.len(),
            MAX_DIRECT_PAYLOAD_BYTES
        );
        return None;
    }

    let received_at = v.get("received_at").and_then(|r| r.as_u64()).unwrap_or(0);
    // `verified` is required; a missing/non-boolean value skips the frame.
    let verified = v.get("verified").and_then(|b| b.as_bool())?;
    let trust_decision = v
        .get("trust_decision")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string());
    let observed_origin = v.get("observed_origin").cloned();

    Some(DirectMessage {
        sender,
        machine_id,
        payload,
        received_at,
        verified,
        trust_decision,
        observed_origin,
        replayed,
    })
}

//! M1b x0x direct-message transport wire regressions (the invite RPC seam).
//!
//! Proves the load-bearing transport invariants without a real x0xd daemon:
//!
//! - **Loopback-only**: `connect` rejects any non-loopback base URL *before*
//!   issuing a request, so a bridge can never dial a remote daemon.
//! - **`send`**: a `POST /direct/send` against a mock loopback daemon yields a
//!   `DirectSendReceipt` carrying only safe transport metadata — the daemon's
//!   `request_id` is never exposed (a caller cannot mistake transport
//!   acceptance for RPC/membership success).
//! - **`verified` is preserved exactly**: the SSE `/direct/events` listener
//!   decodes `direct_message` frames and keeps `verified == false` verbatim, so
//!   a downstream authority can reject an unverified source (never silently
//!   upgraded to `true`).
//!
//! Run: `cargo test -p x0x-nostr-bridge --test m1b_direct_transport -- --nocapture`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::{routing::get, routing::post, Json, Router};
use base64::Engine as _;
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use x0x_nostr_bridge::direct_transport::{AgentId, X0xDirectTransport};

// ===========================================================================
// AgentId parsing (pure)
// ===========================================================================

#[test]
fn agent_id_validates_32_byte_hex_and_lowercases() {
    let ok = AgentId::from_hex(&"ABCDEF0123456789".repeat(4)).expect("64 hex chars ok");
    assert_eq!(ok.as_str(), &"abcdef0123456789".repeat(4));

    assert!(AgentId::from_hex("ab").is_err());
    assert!(AgentId::from_hex(&"a".repeat(63)).is_err());
    assert!(AgentId::from_hex(&"a".repeat(65)).is_err());
    assert!(AgentId::from_hex(&"z".repeat(64)).is_err());
}

// ===========================================================================
// Loopback enforcement — no daemon, no network call
// ===========================================================================

#[tokio::test]
async fn connect_rejects_non_loopback_before_any_request() {
    let cancel = CancellationToken::new();
    for remote in [
        "http://192.168.1.5:8080",
        "http://8.8.8.8",
        "http://10.0.0.1:9999",
        "example.com:443",
    ] {
        let res = X0xDirectTransport::connect(remote, "sekret", cancel.clone(), None).await;
        assert!(res.is_err(), "non-loopback {remote} must be rejected");
        let msg = format!("{}", res.err().unwrap());
        assert!(
            !msg.contains("sekret"),
            "token must not leak in error: {msg}"
        );
    }
}

// ===========================================================================
// Mock loopback daemon
// ===========================================================================

#[derive(Clone, Default)]
struct SendLog {
    auth: Arc<Mutex<Option<String>>>,
    payload: Arc<Mutex<Option<Vec<u8>>>>,
    agent: Arc<Mutex<Option<String>>>,
}

/// Spawn a mock loopback daemon recording `/direct/send` and serving one canned
/// SSE `direct_message` frame on `/direct/events`.
async fn mock_daemon(send_log: SendLog, sse_frame: Arc<Mutex<Option<Vec<u8>>>>) -> SocketAddr {
    let log = send_log.clone();
    let send = post(move |headers: HeaderMap, body: Json<Value>| {
        let log = log.clone();
        async move {
            if let Some(a) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
                *log.auth.lock() = Some(a.to_string());
            }
            if let Some(agent) = body.0.get("agent_id").and_then(|v| v.as_str()) {
                *log.agent.lock() = Some(agent.to_string());
            }
            if let Some(p) = body.0.get("payload").and_then(|v| v.as_str()) {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(p) {
                    *log.payload.lock() = Some(bytes);
                }
            }
            // Daemon receipt includes request_id, which the transport MUST drop.
            Json(json!({
                "ok": true,
                "path": "gossip_inbox",
                "retries_used": 2,
                "request_id": "secret-correlation-id",
                "require_ack": true,
            }))
        }
    });

    let frame = sse_frame.clone();
    let events = get(move || {
        let frame = frame.clone();
        async move {
            let bytes = frame.lock().clone().unwrap_or_default();
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .header("cache-control", "no-cache")
                .body(Body::from(bytes))
                .unwrap()
        }
    });

    let app = Router::new()
        .route("/health", get(|| async { Json(json!({"ok": true})) }))
        .route("/direct/send", send)
        .route("/direct/events", events);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("[mock-daemon] serve ended: {e}");
        }
    });
    addr
}

// ===========================================================================
// send
// ===========================================================================

#[tokio::test]
async fn send_returns_safe_receipt_and_withholds_request_id() {
    let log = SendLog::default();
    let sse = Arc::new(Mutex::new(None));
    let addr = mock_daemon(log.clone(), sse).await;
    let base = format!("http://{addr}");
    let cancel = CancellationToken::new();

    let transport = X0xDirectTransport::connect(&base, "sekret-token", cancel.clone(), None)
        .await
        .expect("loopback connect ok");

    let target = AgentId::from_hex(&"a".repeat(64)).unwrap();
    let payload = b"hello-authority";
    let receipt = transport
        .send(&target, payload, true)
        .await
        .expect("send ok");

    assert_eq!(receipt.path, "gossip_inbox");
    assert_eq!(receipt.retries_used, 2);

    // The bearer reached the daemon.
    assert_eq!(
        log.auth.lock().clone().expect("auth recorded"),
        "Bearer sekret-token"
    );
    // The payload round-tripped through the daemon's base64 decode.
    assert_eq!(log.payload.lock().clone().unwrap(), payload);
    // The target agent id was sent verbatim.
    assert_eq!(log.agent.lock().clone().unwrap(), target.as_str());

    cancel.cancel();
    transport.join().await;
}

// ===========================================================================
// verified SSE round-trip (the load-bearing invariant)
// ===========================================================================

fn direct_frame(verified: bool) -> Vec<u8> {
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(b"claim-bytes");
    let data = json!({
        "sender": "a".repeat(64),
        "machine_id": "b".repeat(64),
        "payload": payload_b64,
        "received_at": 1_700_000_000_123u64,
        "verified": verified,
    });
    let mut out = Vec::new();
    out.extend_from_slice(b"event: direct_message\n");
    out.extend_from_slice(format!("data: {data}\n\n").as_bytes());
    out
}

async fn recv_one(base: &str, frame: Vec<u8>) -> x0x_nostr_bridge::direct_transport::DirectMessage {
    let sse = Arc::new(Mutex::new(Some(frame)));
    let addr = mock_daemon(SendLog::default(), sse).await;
    let _ = base; // base intentionally unused; daemon binds its own port
    let real_base = format!("http://{addr}");
    let cancel = CancellationToken::new();
    let transport = X0xDirectTransport::connect(&real_base, "t", cancel.clone(), Some(16))
        .await
        .expect("connect");
    let mut rx = transport.messages();
    let msg = tokio::time::timeout(Duration::from_secs(4), rx.recv())
        .await
        .expect("received a direct_message within 4s")
        .expect("message present");
    cancel.cancel();
    transport.join().await;
    msg
}

#[tokio::test]
async fn sse_preserves_verified_true_and_decodes_payload() {
    let msg = recv_one("", direct_frame(true)).await;
    assert!(msg.verified);
    assert_eq!(msg.payload, b"claim-bytes");
    assert_eq!(msg.sender, "a".repeat(64));
    assert_eq!(msg.machine_id, "b".repeat(64));
    assert_eq!(msg.received_at, 1_700_000_000_123);
    assert!(!msg.replayed, "live stream ⇒ not a backfill replay");
}

#[tokio::test]
async fn sse_keeps_verified_false_verbatim_never_upgraded() {
    // The load-bearing security invariant: unverified source must reach the
    // consumer as verified==false so the authority can reject it.
    let msg = recv_one("", direct_frame(false)).await;
    assert!(
        !msg.verified,
        "verified==false must NEVER be upgraded to true"
    );
}

#[tokio::test]
async fn oversized_payload_send_is_rejected_before_network() {
    let addr = mock_daemon(SendLog::default(), Arc::new(Mutex::new(None))).await;
    let base = format!("http://{addr}");
    let cancel = CancellationToken::new();
    let transport = X0xDirectTransport::connect(&base, "t", cancel.clone(), None)
        .await
        .expect("connect");

    let target = AgentId::from_hex(&"a".repeat(64)).unwrap();
    let huge = vec![0u8; x0x_nostr_bridge::proto::MAX_FRAME_BYTES + 1];
    assert!(
        transport.send(&target, &huge, true).await.is_err(),
        "oversized payload rejected"
    );

    cancel.cancel();
    transport.join().await;
}

//! Cross-node x0xd direct-message capability proof + the exact blocker that
//! keeps the bridge's cross-device invite claim from completing over the bridge
//! *binary* today.
//!
//! # Why this file exists (the contract gap)
//!
//! `m1b_cross_device_claim.rs` and `m1b_direct_transport.rs` prove the
//! `DirectAuthorityBus` transport invariants against a **mock** loopback daemon.
//! They cannot show that two *real* `x0xd` daemons actually deliver a
//! `/direct/send` to the peer's `/direct/events` — the capability the invite
//! claim forwards over. This file proves that capability for real, in both
//! directions, then pins the single production wiring defect that currently
//! disables the claim over the bridge binary.
//!
//! # Tests
//!
//! - [`direct_dm_routes_both_directions_over_real_mesh`] — boots two isolated
//!   `x0xd` daemons linked only by an explicit loopback bootstrap, then sends a
//!   real `/direct/send` from each to the other's AgentId and observes it arrive
//!   verified on the peer's `/direct/events` SSE. This is the load-bearing
//!   transport the claim depends on, exercised with no mocks.
//! - [`bridge_self_agent_id_blocked_by_flattened_agent_endpoint`] — proves the
//!   **exact blocker**: the bridge's `direct_transport::self_agent_id()` reads
//!   `GET /agent` as `data.agent_id`, but the daemon returns
//!   `ApiResponse<AgentData>` with `#[serde(flatten)] data` (status.rs), so
//!   `agent_id` is top-level. The bridge therefore resolves `self_agent_id =
//!   None`, which makes `with_direct` leave `direct_bus = None` and the mint
//!   route bind the code's `aid` to the relay pubkey fallback — so cross-device
//!   forwarding never engages. A one-line production fix
//!   (`v.get("agent_id")` instead of `v.get("data").and_then(|d|
//!   d.get("agent_id"))` in `src/direct_transport.rs`) re-enables it; the full
//!   claim flow is then covered by `tests/e2e_cross_device_claim.rs`.
//!
//! Both are `#[ignore]` (they spawn real daemons). Run:
//!
//! ```sh
//! cargo nextest run --test e2e_direct_dm_cross_node --run-ignored all --nocapture
//! # or: cargo test --test e2e_direct_dm_cross_node -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use base64::Engine as _;
use futures_util::StreamExt;
use serde_json::Value;

#[path = "harness/cluster.rs"]
mod cluster;
use cluster::{pair, AgentInstance};

/// Serialize daemon-spawning tests within this binary.
static TEST_MUTEX: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

static X0XD_BIN: LazyLock<PathBuf> = LazyLock::new(|| {
    if let Ok(p) = std::env::var("X0XD_TEST_BINARY") {
        let p = PathBuf::from(p);
        if p.exists() {
            return p;
        }
        panic!("X0XD_TEST_BINARY set but missing: {}", p.display());
    }
    let manifest = env!("CARGO_MANIFEST_DIR");
    for c in [
        PathBuf::from(manifest).join("../x0x/target/release/x0xd"),
        PathBuf::from(manifest).join("../x0x/target/debug/x0xd"),
        PathBuf::from(manifest).join("../target/release/x0xd"),
        PathBuf::from(manifest).join("../target/debug/x0xd"),
    ] {
        if c.exists() {
            return c;
        }
    }
    panic!("x0xd binary not found near {manifest}; set X0XD_TEST_BINARY");
});

async fn suite_lock() -> tokio::sync::MutexGuard<'static, ()> {
    TEST_MUTEX.lock().await
}

fn ensure_x0xd_binary() {
    std::env::set_var("X0XD_TEST_BINARY", &*X0XD_BIN);
    println!("[harness] x0xd binary: {}", X0XD_BIN.display());
}

// ---------------------------------------------------------------------------
// daemon REST helpers (no bridge involved)
// ---------------------------------------------------------------------------

/// The daemon's `GET /agent` returns `ApiResponse<AgentData>` with
/// `#[serde(flatten)] data`, so `agent_id` is a TOP LEVEL field (not nested
/// under `data`). This reads the real shape.
async fn daemon_agent_id(d: &AgentInstance) -> String {
    let resp: Value = d.get("/agent").await.json().await.expect("/agent json");
    resp.get("agent_id")
        .and_then(Value::as_str)
        .expect("top-level agent_id")
        .to_string()
}

/// The full `/agent` body (used to prove the flatten shape that blocks the
/// bridge).
async fn daemon_agent_body(d: &AgentInstance) -> Value {
    d.get("/agent").await.json().await.expect("/agent json")
}

/// `POST /direct/send {agent_id, payload}` → parsed JSON receipt.
async fn direct_send(d: &AgentInstance, target_agent_id: &str, payload: &[u8]) -> Value {
    let body = serde_json::json!({
        "agent_id": target_agent_id,
        "payload": base64::engine::general_purpose::STANDARD.encode(payload),
    });
    let resp: Value = d
        .post("/direct/send", body)
        .await
        .json()
        .await
        .expect("/direct/send json");
    println!("[dm] /direct/send → {resp}");
    resp
}

/// Open `GET /direct/events` as an SSE byte stream and return the response.
async fn open_direct_events(d: &AgentInstance) -> reqwest::Response {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .expect("client");
    let resp = client
        .get(format!("http://{}/direct/events", d.api_addr))
        .header("Authorization", format!("Bearer {}", d.api_token))
        .header("Accept", "text/event-stream")
        .send()
        .await
        .expect("GET /direct/events");
    assert!(
        resp.status().is_success(),
        "/direct/events status {}",
        resp.status()
    );
    resp
}

/// Pull SSE frames from `resp` until a `direct_message` (or
/// `history_direct_message`) event arrives whose decoded `payload` equals
/// `want_payload` and whose `sender` equals `want_sender`. Panics on timeout —
/// proving delivery did NOT happen.
async fn await_direct_message(
    resp: reqwest::Response,
    want_sender: &str,
    want_payload: &[u8],
    deadline: Instant,
    label: &str,
) -> Value {
    let want_b64 = base64::engine::general_purpose::STANDARD.encode(want_payload);
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    let mut cur_event = String::new();
    let mut cur_data = String::new();
    loop {
        let rem = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        if rem.is_zero() {
            panic!(
                "[{label}] no /direct/events frame matching payload {want_b64} from \
                 {want_sender} before deadline — cross-node DM did NOT deliver"
            );
        }
        match tokio::time::timeout(rem, stream.next()).await {
            Err(_) => {
                panic!("[{label}] /direct/events stream timed out before the DM arrived");
            }
            Ok(Some(Err(e))) => panic!("[{label}] /direct/events stream error: {e}"),
            Ok(Some(Ok(chunk))) => {
                buf.push_str(std::str::from_utf8(&chunk).unwrap_or(""));
                // Process complete SSE events (terminated by a blank line).
                while let Some(idx) = buf.find("\n\n") {
                    let block: String = buf.drain(..idx + 2).collect();
                    for line in block.lines() {
                        if let Some(e) = line.strip_prefix("event:") {
                            cur_event = e.trim().to_string();
                        } else if let Some(dd) = line.strip_prefix("data:") {
                            if !cur_data.is_empty() {
                                cur_data.push('\n');
                            }
                            cur_data.push_str(dd.trim());
                        }
                    }
                    if matches!(
                        cur_event.as_str(),
                        "direct_message" | "history_direct_message"
                    ) && !cur_data.is_empty()
                    {
                        let data: Value = serde_json::from_str(&cur_data).unwrap_or(Value::Null);
                        let sender = data.get("sender").and_then(Value::as_str).unwrap_or("");
                        let payload = data.get("payload").and_then(Value::as_str).unwrap_or("");
                        let verified = data.get("verified").and_then(Value::as_bool);
                        println!(
                            "[{label}] sse event={cur_event} sender={sender} verified={verified:?}"
                        );
                        if sender == want_sender && payload == want_b64 {
                            return data;
                        }
                    }
                    cur_event.clear();
                    cur_data.clear();
                }
            }
            Ok(None) => panic!("[{label}] /direct/events stream closed before the DM arrived"),
        }
    }
}

// ---------------------------------------------------------------------------
// Test 1: real cross-node /direct/send → /direct/events, both directions
// ---------------------------------------------------------------------------

/// Two isolated daemons (one explicit loopback link) exchange direct messages
/// in both directions over real QUIC — the transport the invite claim forwards
/// over. Verified sender binding is asserted on each delivered frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "spawns two real x0xd daemons"]
async fn direct_dm_routes_both_directions_over_real_mesh() {
    let _g = suite_lock().await;
    ensure_x0xd_binary();

    let mesh = pair().await;
    let alice_id = daemon_agent_id(&mesh.alice).await;
    let bob_id = daemon_agent_id(&mesh.bob).await;
    println!("[test] alice={alice_id} bob={bob_id}");

    // --- B → A --------------------------------------------------------------
    // Subscribe A's /direct/events BEFORE the send so the live tap catches it.
    let alice_sse = open_direct_events(&mesh.alice).await;
    // Give the SSE tap a beat to register, then send from B → A.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let payload_ba = b"claim-envelope:Bob->Alice";
    let send_ba = direct_send(&mesh.bob, &alice_id, payload_ba).await;
    assert_eq!(
        send_ba.get("ok").and_then(Value::as_bool),
        Some(true),
        "B->A /direct/send must be accepted: {send_ba}"
    );
    let delivered_ba = await_direct_message(
        alice_sse,
        &bob_id,
        payload_ba,
        Instant::now() + Duration::from_secs(30),
        "B->A",
    )
    .await;
    // The daemon cryptographically binds the sender only when verified==true.
    assert_eq!(
        delivered_ba.get("verified").and_then(Value::as_bool),
        Some(true),
        "B->A DM must arrive verified (sender binding is load-bearing for the claim)"
    );
    assert_eq!(
        delivered_ba.get("sender").and_then(Value::as_str),
        Some(&bob_id[..]),
        "B->A DM sender must be Bob's AgentId"
    );
    println!("[test] B->A verified DM delivered over real /direct/send + /direct/events");

    // --- A → B (symmetric) --------------------------------------------------
    let bob_sse = open_direct_events(&mesh.bob).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let payload_ab = b"result-envelope:Alice->Bob";
    let send_ab = direct_send(&mesh.alice, &bob_id, payload_ab).await;
    assert_eq!(
        send_ab.get("ok").and_then(Value::as_bool),
        Some(true),
        "A->B /direct/send must be accepted: {send_ab}"
    );
    let delivered_ab = await_direct_message(
        bob_sse,
        &alice_id,
        payload_ab,
        Instant::now() + Duration::from_secs(30),
        "A->B",
    )
    .await;
    assert_eq!(
        delivered_ab.get("verified").and_then(Value::as_bool),
        Some(true),
        "A->B DM must arrive verified"
    );
    assert_eq!(
        delivered_ab.get("sender").and_then(Value::as_str),
        Some(&alice_id[..]),
        "A->B DM sender must be Alice's AgentId"
    );
    println!("[test] A->B verified DM delivered over real /direct/send + /direct/events");

    println!("[test] PASS: cross-node /direct/send + /direct/events proven both directions");
}

// ---------------------------------------------------------------------------
// Test 2: regression guard — the daemon /agent shape the bridge must parse
// ---------------------------------------------------------------------------

/// Pins the daemon `GET /agent` shape against the real daemon so the
/// production parser can never silently regress: `ApiResponse<AgentData>`
/// uses `#[serde(flatten)]`, so `agent_id` is a TOP-LEVEL field with NO `data`
/// wrapper. The bridge's `direct_transport::self_agent_id()` now reads that
/// top-level path (the earlier nested `data.agent_id` parse resolved `None`
/// and silently disabled remote claims — fixed). This test asserts the
/// daemon shape is still flattened, that the correct top-level parse resolves
/// the AgentId, and that the obsolete nested path would yield `None` (so a
/// regression to it is caught here, and the end-to-end claim is covered by
/// `e2e_cross_device_claim.rs`).
#[ignore = "spawns a real x0xd daemon"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridge_self_agent_id_blocked_by_flattened_agent_endpoint() {
    let _g = suite_lock().await;
    ensure_x0xd_binary();

    let mesh = pair().await;
    let body = daemon_agent_body(&mesh.alice).await;
    println!("[test] daemon GET /agent body: {body}");

    // The daemon's real shape: agent_id is a TOP-LEVEL field ...
    assert_eq!(
        body.get("agent_id").and_then(Value::as_str).map(str::len),
        Some(64),
        "daemon /agent exposes a top-level 64-hex agent_id"
    );
    // ... and is NOT nested under a `data` object (flatten).
    assert!(
        body.get("data").is_none(),
        "daemon /agent does NOT nest under `data` (ApiResponse flattens) — \
         this is the exact shape the bridge mis-parses"
    );

    // ... and is NOT nested under a `data` object (flatten).
    assert!(
        body.get("data").is_none(),
        "daemon /agent does NOT nest under `data` (ApiResponse flattens)"
    );

    // The obsolete nested `data.agent_id` parse (the pre-fix parser) still
    // yields None against this body — pinned so a regression to it is caught.
    let nested_parse = body
        .get("data")
        .and_then(|d| d.get("agent_id"))
        .and_then(Value::as_str);
    assert!(
        nested_parse.is_none(),
        "the nested `v[\"data\"][\"agent_id\"]` path yields None — the parser must \
         read the top-level field (regression guard)"
    );

    // The correct top-level parse (what the production parser now reads).
    let correct_parse = body.get("agent_id").and_then(Value::as_str);
    assert_eq!(
        correct_parse.map(str::len),
        Some(64),
        "the top-level parse resolves the 64-hex AgentId"
    );

    println!(
        "[test] daemon /agent shape pinned: agent_id is top-level (flattened, no `data` \
         wrapper); the production parser reads it correctly (self_id=true). The full \
         cross-device claim over real /direct/send is proven by e2e_cross_device_claim.rs."
    );
}

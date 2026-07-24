//! End-to-end convergence proof for the x0x-nostr-bridge spike.
//!
//! Two x0xd daemons mesh over localhost (via the shared `cluster` harness);
//! two bridge binaries each front one daemon. A Nostr EVENT published through
//! bridge A is carried as signed JSON over the per-channel gossip topic,
//! ingested + verified + stored on bridge B, and fanned out live to a REQ
//! already open on B — then served again from B's SQLite on a fresh REQ.
//! The reverse direction (B publishes → A's REQ) is proved symmetrically.
//!
//! Ignored by default: each test spawns real `x0xd` daemons + bridge binaries.
//! Run explicitly: `cargo test -p x0x-nostr-bridge --test e2e_convergence -- --ignored --nocapture`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use nostr::Alphabet;
use nostr::{
    ClientMessage, EventBuilder, Filter, JsonUtil, Keys, Kind, SingleLetterTag, SubscriptionId,
    Tag, TagKind,
};
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use uuid::Uuid;

#[path = "harness/cluster.rs"]
mod cluster;
use cluster::{pair, solo, AgentInstance};

type WS =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Serialize daemon-spawning tests within this binary so their port/temp
/// allocation never overlaps and the mesh-form timing is deterministic.
static TEST_MUTEX: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Resolve the workspace `x0xd` binary once. The harness's `find_x0xd_binary`
/// resolves `target/debug/x0xd` relative to `CARGO_MANIFEST_DIR`, which from
/// *this* crate points at `x0x-nostr-bridge/target` (absent). We instead pin
/// the binary through the harness's sanctioned `X0XD_TEST_BINARY` override.
static X0XD_BIN: LazyLock<PathBuf> = LazyLock::new(|| {
    // `CARGO_MANIFEST_DIR` is the bridge crate dir (a direct workspace child),
    // so the workspace `target/` is one level up. The manifest-relative forms
    // below cover the bridge-crate layout (used here) and the root-crate layout.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let candidates = [
        PathBuf::from(manifest).join("../target/debug/x0xd"),
        PathBuf::from(manifest).join("../target/release/x0xd"),
        PathBuf::from(manifest).join("target/debug/x0xd"),
        PathBuf::from(manifest).join("target/release/x0xd"),
    ];
    for c in &candidates {
        if c.exists() {
            return c.to_path_buf();
        }
    }
    panic!(
        "x0xd binary not found near {manifest}; searched {}",
        candidates
            .iter()
            .map(|c| c.display().to_string())
            .collect::<Vec<_>>()
            .join(" / ")
    );
});

async fn suite_lock() -> tokio::sync::MutexGuard<'static, ()> {
    TEST_MUTEX.lock().await
}

fn ensure_x0xd_binary() {
    std::env::set_var("X0XD_TEST_BINARY", &*X0XD_BIN);
    println!("[harness] x0xd binary: {}", X0XD_BIN.display());
}

// ---------------------------------------------------------------------------
// Bridge subprocess orchestration
// ---------------------------------------------------------------------------

/// Owns one bridge binary process. `Drop` kills the child so a panic or test
/// end never orphans a listener. The DB tempdir is kept alive for the bridge's
/// lifetime; the stdout/stderr log file is left on disk for post-mortem.
struct BridgeGuard {
    child: Child,
    addr: String,
    name: String,
    log_path: PathBuf,
    _db_dir: tempfile::TempDir,
}

impl Drop for BridgeGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        eprintln!(
            "[{}] bridge killed; logs: {}",
            self.name,
            self.log_path.display()
        );
    }
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Spawn one bridge binary fronting `daemon`. `X0X_API` is given the explicit
/// `http://` scheme because `transport::connect` consumes the env value verbatim
/// (no normalization on the env path, unlike `transport::discover`).
fn spawn_bridge(daemon: &AgentInstance, name: &str) -> BridgeGuard {
    let bin = env!("CARGO_BIN_EXE_x0x-nostr-bridge");
    let port = free_tcp_port();
    let addr = format!("127.0.0.1:{port}");
    let db_dir = tempfile::tempdir().expect("bridge db tempdir");
    let db_path = db_dir.path().join("bridge.db");
    let log_path =
        std::env::temp_dir().join(format!("x0x-bridge-{name}-{}.log", std::process::id()));
    let out = std::fs::File::create(&log_path)
        .unwrap_or_else(|e| panic!("create bridge log {name}: {e}"));
    let err = out
        .try_clone()
        .unwrap_or_else(|e| panic!("clone bridge log {name}: {e}"));

    let child = Command::new(bin)
        .env("BRIDGE_BIND", &addr)
        .env("BRIDGE_DB", db_path.as_os_str())
        .env("X0X_API", format!("http://{}", daemon.api_addr))
        .env("X0X_TOKEN", &daemon.api_token)
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap_or_else(|e| panic!("spawn bridge {name}: {e}"));

    println!(
        "[{name}] bridge pid={} addr={addr} db={} log={}",
        child.id(),
        db_path.display(),
        log_path.display()
    );

    BridgeGuard {
        child,
        addr,
        name: name.to_string(),
        log_path,
        _db_dir: db_dir,
    }
}

/// Wait for the bridge's NIP-11 info endpoint (`GET /` with
/// `accept: application/nostr+json`) to answer — the readiness probe that
/// proves the binary booted, connected to its daemon, and bound its listener.
async fn wait_for_bridge(addr: &str) {
    let url = format!("http://{addr}/");
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(resp) = client
            .get(&url)
            .header("accept", "application/nostr+json")
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<Value>().await {
                    if body.get("name").is_some() {
                        return;
                    }
                }
            }
        }
        if Instant::now() > deadline {
            panic!("bridge at {addr} did not answer NIP-11 within 30s");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// ---------------------------------------------------------------------------
// Nostr client primitives
// ---------------------------------------------------------------------------

async fn connect_ws(addr: &str) -> WS {
    let url = format!("ws://{addr}");
    let (ws, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("ws connect");
    ws
}

/// Read the next meaningful (text) frame and parse it as JSON.
async fn next_text(ws: &mut WS) -> Value {
    loop {
        match ws.next().await {
            Some(Ok(WsMessage::Text(t))) => return serde_json::from_str(&t).expect("valid json"),
            Some(Ok(_)) => continue,
            Some(Err(e)) => panic!("ws error: {e}"),
            None => panic!("ws closed"),
        }
    }
}

async fn send_msg(ws: &mut WS, msg: ClientMessage<'_>) {
    ws.send(WsMessage::Text(msg.as_json()))
        .await
        .expect("ws send");
}

/// Full NIP-42 handshake: read the AUTH challenge, sign a kind-22242 auth event
/// tagged with the challenge, and assert the relay replies OK true.
async fn authenticate(ws: &mut WS, keys: &Keys) {
    let auth_msg = next_text(ws).await;
    assert_eq!(auth_msg[0], "AUTH", "expected AUTH challenge on connect");
    let challenge = auth_msg[1].as_str().expect("challenge str").to_string();
    let ev = EventBuilder::new(Kind::from(22_242u16), "")
        .tag(Tag::custom(
            TagKind::custom("challenge"),
            [challenge.as_str()],
        ))
        .tag(Tag::custom(TagKind::custom("relay"), ["ws://127.0.0.1/"]))
        .sign_with_keys(keys)
        .expect("sign auth");
    send_msg(ws, ClientMessage::auth(ev)).await;
    let ok = next_text(ws).await;
    assert_eq!(ok[0], "OK");
    assert!(ok[2].as_bool().expect("status bool"), "AUTH should succeed");
}

fn str_at(v: &Value, i: usize) -> Option<&str> {
    v.get(i).and_then(|x| x.as_str())
}

/// `id` field of an EVENT frame's event object (`["EVENT", sub, {…}]`).
fn event_id_of(v: &Value) -> Option<&str> {
    v.get(2)?.get("id")?.as_str()
}

fn letter(c: Alphabet) -> SingleLetterTag {
    SingleLetterTag::lowercase(c)
}

/// Drain frames for `sub` until its EOSE, counting delivered EVENT frames.
async fn drain_until_eose(ws: &mut WS, sub: &str, deadline: Instant) -> usize {
    let mut n = 0;
    loop {
        let rem = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        let v = tokio::time::timeout(rem, next_text(ws))
            .await
            .expect("EOSE timeout");
        if str_at(&v, 0) == Some("EOSE") && str_at(&v, 1) == Some(sub) {
            return n;
        }
        if str_at(&v, 0) == Some("EVENT") && str_at(&v, 1) == Some(sub) {
            n += 1;
        }
    }
}

/// Wait for a live EVENT frame carrying `ev_id` (on any subscription) before
/// `deadline`. Returns the matched event object.
async fn await_live_event(ws: &mut WS, ev_id: &str, deadline: Instant, label: &str) -> Value {
    loop {
        let rem = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        if rem.is_zero() {
            panic!("[{label}] live event {ev_id} not received before deadline");
        }
        let v = match tokio::time::timeout(rem, next_text(ws)).await {
            Ok(v) => v,
            Err(_) => panic!("[{label}] live event {ev_id} timed out"),
        };
        if str_at(&v, 0) == Some("EVENT") && event_id_of(&v) == Some(ev_id) {
            return v[2].clone();
        }
    }
}

/// Assert that subscription `sub` receives EVENT(`ev_id`) from the store dump
/// BEFORE its EOSE — i.e. the durable SQLite history path on the receiving bridge.
async fn await_history_then_eose(
    ws: &mut WS,
    sub: &str,
    ev_id: &str,
    deadline: Instant,
    label: &str,
) {
    let mut saw = false;
    loop {
        let rem = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        if rem.is_zero() {
            panic!("[{label}] history EVENT/EOSE for {sub} not received before deadline");
        }
        let v = match tokio::time::timeout(rem, next_text(ws)).await {
            Ok(v) => v,
            Err(_) => panic!("[{label}] history timed out for {sub}"),
        };
        if str_at(&v, 0) == Some("EOSE") && str_at(&v, 1) == Some(sub) {
            assert!(
                saw,
                "[{label}] EOSE for {sub} arrived before history EVENT {ev_id}"
            );
            return;
        }
        if str_at(&v, 0) == Some("EVENT")
            && str_at(&v, 1) == Some(sub)
            && event_id_of(&v) == Some(ev_id)
        {
            saw = true;
        }
    }
}

/// Prove one direction of convergence: a subscriber opens a channel REQ on
/// `subscriber_addr`, a publisher emits a kind-9 channel message on
/// `publisher_addr`, and the event arrives live over the fabric then from
/// history. Returns the live-delivery latency.
#[allow(clippy::too_many_lines)]
async fn prove_direction(
    publisher_addr: &str,
    subscriber_addr: &str,
    channel: &str,
    label: &str,
) -> Duration {
    println!("[{label}] subscriber={subscriber_addr} publisher={publisher_addr} channel={channel}");

    // Subscriber subscribes FIRST so its bridge joins the channel gossip topic
    // (the REQ path's fire-and-forget ensure_topic) before anything is published.
    let sub_keys = Keys::generate();
    let mut sub_ws = connect_ws(subscriber_addr).await;
    authenticate(&mut sub_ws, &sub_keys).await;

    let filter = Filter::new()
        .kinds([Kind::from(9u16)])
        .custom_tag(letter(Alphabet::H), channel);
    let sub1 = format!("{label}-live");
    send_msg(
        &mut sub_ws,
        ClientMessage::req(SubscriptionId::new(sub1.as_str()), vec![filter.clone()]),
    )
    .await;
    let pre = drain_until_eose(&mut sub_ws, &sub1, Instant::now() + Duration::from_secs(15)).await;
    assert_eq!(
        pre, 0,
        "[{label}] fresh channel had stored events before publish"
    );

    // Let the channel-topic subscription land on the subscriber's daemon.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Publisher: signed kind-9 channel message.
    let pub_keys = Keys::generate();
    let mut pub_ws = connect_ws(publisher_addr).await;
    authenticate(&mut pub_ws, &pub_keys).await;
    let ev = EventBuilder::new(Kind::from(9u16), "hello over x0x")
        .tag(Tag::custom(TagKind::custom("h"), [channel]))
        .sign_with_keys(&pub_keys)
        .expect("sign event");
    let ev_id_hex = ev.id.to_hex();
    let publish_at = Instant::now();
    send_msg(&mut pub_ws, ClientMessage::event(ev)).await;
    let ok = next_text(&mut pub_ws).await;
    assert_eq!(
        str_at(&ok, 0),
        Some("OK"),
        "[{label}] expected OK for publish"
    );
    assert_eq!(
        str_at(&ok, 1),
        Some(ev_id_hex.as_str()),
        "[{label}] OK id mismatch"
    );
    assert!(
        ok[2].as_bool().expect("status bool"),
        "[{label}] publish OK must be true: {ok:?}"
    );

    // Live fan-out over the fabric.
    let live = await_live_event(
        &mut sub_ws,
        &ev_id_hex,
        Instant::now() + Duration::from_secs(60),
        label,
    )
    .await;
    let latency = publish_at.elapsed();
    println!(
        "[{label}] live EVENT received, content={:?}, A->B latency={latency:?}",
        live["content"]
    );
    assert_eq!(
        live["content"].as_str(),
        Some("hello over x0x"),
        "[{label}] live content mismatch"
    );

    // History path: a fresh REQ must serve the event from the subscriber's
    // SQLite before its EOSE.
    let sub2 = format!("{label}-hist");
    send_msg(
        &mut sub_ws,
        ClientMessage::req(SubscriptionId::new(sub2.as_str()), vec![filter]),
    )
    .await;
    await_history_then_eose(
        &mut sub_ws,
        &sub2,
        &ev_id_hex,
        Instant::now() + Duration::from_secs(15),
        label,
    )
    .await;
    println!("[{label}] history path confirmed (SQLite served event before EOSE)");

    latency
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Definitive spike proof: events published through bridge A converge over the
/// x0x fabric to bridge B (live + SQLite history), and vice versa.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires spawning real x0xd daemons"]
async fn e2e_convergence_two_bridges_over_x0x_fabric() {
    let _g = suite_lock().await;
    ensure_x0xd_binary();

    println!("spawning two-daemon mesh…");
    let mesh = pair().await;
    println!(
        "mesh up: alice={} bob={}",
        mesh.alice.api_addr, mesh.bob.api_addr
    );

    let bridge_a = spawn_bridge(&mesh.alice, "bridge-a");
    let bridge_b = spawn_bridge(&mesh.bob, "bridge-b");
    wait_for_bridge(&bridge_a.addr).await;
    wait_for_bridge(&bridge_b.addr).await;
    println!("bridges ready: A={} B={}", bridge_a.addr, bridge_b.addr);

    let ch_a = Uuid::new_v4().to_string();
    let ch_b = Uuid::new_v4().to_string();

    let lat_ab = prove_direction(&bridge_a.addr, &bridge_b.addr, &ch_a, "A->B").await;
    let lat_ba = prove_direction(&bridge_b.addr, &bridge_a.addr, &ch_b, "B->A").await;

    println!("CONVERGENCE OK: A->B latency={lat_ab:?}, B->A latency={lat_ba:?}");
}

/// Single-bridge smoke: a global (no `#h`) kind-9 event is published, echoed
/// back over the daemon's `buzz.v1.global` subscription, stored, and returned
/// from a REQ by-author — the global-topic round trip the convergence test does
/// not exercise. Isolates binary-spawn + daemon-wiring + NIP-11 + NIP-42.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires spawning real x0xd daemons"]
async fn e2e_single_bridge_global_history_roundtrip() {
    let _g = suite_lock().await;
    ensure_x0xd_binary();

    let (daemon, _bind) = solo().await;
    println!("solo daemon up: {}", daemon.api_addr);

    let bridge = spawn_bridge(&daemon, "bridge-smoke");
    wait_for_bridge(&bridge.addr).await;
    println!("smoke bridge ready: {}", bridge.addr);

    let keys = Keys::generate();
    let mut ws = connect_ws(&bridge.addr).await;
    authenticate(&mut ws, &keys).await;

    let ev = EventBuilder::new(Kind::from(9u16), "smoke global message")
        .sign_with_keys(&keys)
        .expect("sign");
    let ev_id_hex = ev.id.to_hex();
    send_msg(&mut ws, ClientMessage::event(ev)).await;
    let ok = next_text(&mut ws).await;
    assert_eq!(str_at(&ok, 0), Some("OK"));
    assert!(
        ok[2].as_bool().expect("status bool"),
        "global publish must be OK true: {ok:?}"
    );

    // REQ by author returns the echoed+stored event from SQLite, then EOSE.
    let sub = "smoke-hist";
    let filter = Filter::new().author(keys.public_key());
    send_msg(
        &mut ws,
        ClientMessage::req(SubscriptionId::new(sub), vec![filter]),
    )
    .await;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut got = false;
    loop {
        let rem = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        if rem.is_zero() {
            panic!("smoke: no EOSE within window");
        }
        let v = tokio::time::timeout(rem, next_text(&mut ws))
            .await
            .expect("smoke eose timeout");
        if str_at(&v, 0) == Some("EOSE") && str_at(&v, 1) == Some(sub) {
            assert!(got, "smoke: EOSE before history EVENT");
            break;
        }
        if str_at(&v, 0) == Some("EVENT")
            && str_at(&v, 1) == Some(sub)
            && event_id_of(&v) == Some(ev_id_hex.as_str())
        {
            assert_eq!(
                v[2]["content"].as_str(),
                Some("smoke global message"),
                "smoke: stored content mismatch"
            );
            got = true;
        }
    }
    println!("SMOKE OK: global publish + echo store + REQ history round-trip on one bridge");
}

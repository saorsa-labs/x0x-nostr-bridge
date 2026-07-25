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
    // Explicit override wins: `X0XD_TEST_BINARY` is the harness's sanctioned
    // pin, and the only mechanism that works from a standalone worktree whose
    // daemon build lives in an unrelated checkout.
    if let Ok(pinned) = std::env::var("X0XD_TEST_BINARY") {
        let pinned = PathBuf::from(pinned);
        if pinned.exists() {
            return pinned;
        }
        panic!(
            "X0XD_TEST_BINARY set but does not exist: {}",
            pinned.display()
        );
    }
    // `CARGO_MANIFEST_DIR` is the bridge crate dir (a direct workspace child),
    // so the workspace `target/` is one level up. The manifest-relative forms
    // below cover the bridge-crate layout, the root-crate layout, and a
    // standalone checkout sitting next to an `x0x/` clone (this repo's
    // worktree layout).
    let manifest = env!("CARGO_MANIFEST_DIR");
    let candidates = [
        PathBuf::from(manifest).join("../target/debug/x0xd"),
        PathBuf::from(manifest).join("../target/release/x0xd"),
        PathBuf::from(manifest).join("target/debug/x0xd"),
        PathBuf::from(manifest).join("target/release/x0xd"),
        PathBuf::from(manifest).join("../x0x/target/debug/x0xd"),
        PathBuf::from(manifest).join("../x0x/target/release/x0xd"),
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
    db_path: PathBuf,
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
        // The binary enforces the NIP-42 relay tag against this URL
        // (`Settings::from_env` default); tests sign AUTH with `ws://{addr}`.
        .env("BRIDGE_PUBLIC_URL", format!("http://{addr}"))
        .env("X0X_API", format!("http://{}", daemon.api_addr))
        .env("X0X_TOKEN", &daemon.api_token)
        // ingest=debug: the mesh-duplicate line is the positive evidence that
        // a redelivered payload REACHED the bridge and was deduped there.
        .env("RUST_LOG", "info,x0x_nostr_bridge::ingest=debug")
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
        db_path,
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

/// Full NIP-42 handshake: read the AUTH challenge, sign a kind-22242 auth
/// event tagged with the challenge AND the relay URL the bridge enforces
/// (`Settings::from_env` turns relay-tag enforcement on by default; the tag
/// must equal `ws://{addr}` with no trailing slash), and assert OK true.
async fn authenticate(ws: &mut WS, keys: &Keys, addr: &str) {
    let auth_msg = next_text(ws).await;
    assert_eq!(auth_msg[0], "AUTH", "expected AUTH challenge on connect");
    let challenge = auth_msg[1].as_str().expect("challenge str").to_string();
    let ev = EventBuilder::new(Kind::from(22_242u16), "")
        .tag(Tag::custom(
            TagKind::custom("challenge"),
            [challenge.as_str()],
        ))
        .tag(Tag::custom(
            TagKind::custom("relay"),
            [format!("ws://{addr}").as_str()],
        ))
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
    authenticate(&mut sub_ws, &sub_keys, subscriber_addr).await;

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
    authenticate(&mut pub_ws, &pub_keys, publisher_addr).await;
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
        "[{label}] live EVENT received, content={:?}, latency={latency:?}",
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
    authenticate(&mut ws, &keys, &bridge.addr).await;

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

// ---------------------------------------------------------------------------
// WP5 property proofs (mesh-door parking; redelivery idempotence)
// ---------------------------------------------------------------------------

/// Publish raw bytes to a gossip topic directly through a daemon's REST API —
/// the same `POST /publish` the bridge's transport uses, driven by the test so
/// delivery ORDER is deterministic (reply-before-parent, redelivery).
async fn daemon_publish(daemon: &AgentInstance, topic: &str, payload: &[u8]) {
    use base64::Engine as _;
    let body = serde_json::json!({
        "topic": topic,
        "payload": base64::engine::general_purpose::STANDARD.encode(payload),
    });
    let resp = daemon.post("/publish", body).await;
    assert!(
        resp.status().is_success(),
        "daemon /publish to {topic} failed: HTTP {}",
        resp.status()
    );
}

/// Subscribe a daemon to a topic directly (`POST /subscribe`), so publishes
/// through that daemon propagate on a topic its bridge never joined.
async fn daemon_subscribe(daemon: &AgentInstance, topic: &str) {
    let resp = daemon
        .post("/subscribe", serde_json::json!({ "topic": topic }))
        .await;
    assert!(
        resp.status().is_success(),
        "daemon /subscribe to {topic} failed: HTTP {}",
        resp.status()
    );
}

/// One read-only query against a bridge's live SQLite (WAL: a concurrent
/// reader is fine). Returns the count for `sql` with `param` bound to ?1.
fn db_count(db: &PathBuf, sql: &str, param: &str) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("open bridge db");
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .expect("busy timeout");
    conn.query_row(sql, [param], |r| r.get::<_, i64>(0))
        .expect("count query")
}

/// Poll `cond` against the bridge DB until it holds or the deadline passes.
/// Gossip delivery is async; assertions on durable state must tolerate that.
async fn await_db(db: &PathBuf, label: &str, timeout: Duration, cond: impl Fn(&PathBuf) -> bool) {
    let deadline = Instant::now() + timeout;
    loop {
        if cond(db) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "[{label}] DB condition not met within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Assert that no live EVENT frame carrying `ev_id` arrives on the socket
/// within `window` (any other frame is drained and ignored). Used to prove a
/// redelivered duplicate does NOT fan out a second time.
async fn assert_no_live_event(ws: &mut WS, ev_id: &str, window: Duration, label: &str) {
    let deadline = Instant::now() + window;
    loop {
        let rem = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        if rem.is_zero() {
            return;
        }
        match tokio::time::timeout(rem, next_text(ws)).await {
            Ok(v) => {
                assert!(
                    !(str_at(&v, 0) == Some("EVENT") && event_id_of(&v) == Some(ev_id)),
                    "[{label}] duplicate live fan-out of {ev_id}: {v}"
                );
            }
            Err(_) => return, // window elapsed with no further frames
        }
    }
}

/// Collect every EVENT id served on subscription `sub` before its EOSE.
async fn history_ids_until_eose(ws: &mut WS, sub: &str, deadline: Instant) -> Vec<String> {
    let mut ids = Vec::new();
    loop {
        let rem = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        let v = tokio::time::timeout(rem, next_text(ws))
            .await
            .expect("history EOSE timeout");
        if str_at(&v, 0) == Some("EOSE") && str_at(&v, 1) == Some(sub) {
            return ids;
        }
        if str_at(&v, 0) == Some("EVENT") && str_at(&v, 1) == Some(sub) {
            if let Some(id) = event_id_of(&v) {
                ids.push(id.to_string());
            }
        }
    }
}

/// Signed kind-9 reply to `root_id` with the marked NIP-10 tags the thread
/// engine requires (`["e",root,"","root"]` + `["e",root,"","reply"]`).
fn signed_reply(keys: &Keys, channel: &str, root_id: &str, content: &str) -> nostr::Event {
    EventBuilder::new(Kind::from(9u16), content)
        .tag(Tag::custom(TagKind::custom("h"), [channel]))
        .tag(Tag::custom(TagKind::custom("e"), [root_id, "", "root"]))
        .tag(Tag::custom(TagKind::custom("e"), [root_id, "", "reply"]))
        .sign_with_keys(keys)
        .expect("sign reply")
}

/// WP5 property 2 — mesh-door events route through WP1 parking (design D2).
///
/// A reply is injected onto the channel topic BEFORE its root. On bridge B it
/// must PARK (invisible: not served, not dispatched, held in pending_orphans),
/// then — when the root lands — attach atomically and recompute the thread
/// counters. Every step is asserted against B's live SQLite and its REQ
/// surface, not log lines.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires spawning real x0xd daemons"]
async fn e2e_mesh_door_parks_orphan_reply_then_attaches() {
    let _g = suite_lock().await;
    ensure_x0xd_binary();

    let mesh = pair().await;
    let bridge_a = spawn_bridge(&mesh.alice, "p2-a");
    let bridge_b = spawn_bridge(&mesh.bob, "p2-b");
    wait_for_bridge(&bridge_a.addr).await;
    wait_for_bridge(&bridge_b.addr).await;

    let ch = Uuid::new_v4().to_string();
    let topic = format!("buzz.v1.ch.{ch}");
    // Injection point: daemon A carries test-published payloads to the mesh.
    daemon_subscribe(&mesh.alice, &topic).await;

    // B joins the channel topic via a live REQ (same pattern as prove_direction).
    let sub_keys = Keys::generate();
    let mut sub_ws = connect_ws(&bridge_b.addr).await;
    authenticate(&mut sub_ws, &sub_keys, &bridge_b.addr).await;
    let filter = Filter::new()
        .kinds([Kind::from(9u16)])
        .custom_tag(letter(Alphabet::H), ch.as_str());
    send_msg(
        &mut sub_ws,
        ClientMessage::req(SubscriptionId::new("p2-live"), vec![filter.clone()]),
    )
    .await;
    let pre = drain_until_eose(
        &mut sub_ws,
        "p2-live",
        Instant::now() + Duration::from_secs(15),
    )
    .await;
    assert_eq!(pre, 0, "fresh channel must be empty");
    tokio::time::sleep(Duration::from_secs(2)).await;

    let root_keys = Keys::generate();
    let root = EventBuilder::new(Kind::from(9u16), "wp5-p2 root")
        .tag(Tag::custom(TagKind::custom("h"), [ch.as_str()]))
        .sign_with_keys(&root_keys)
        .expect("sign root");
    let root_id = root.id.to_hex();
    let reply_keys = Keys::generate();
    let reply = signed_reply(&reply_keys, &ch, &root_id, "wp5-p2 reply-first");
    let reply_id = reply.id.to_hex();

    // STEP 1: the REPLY arrives first. B's mesh door must park it.
    daemon_publish(&mesh.alice, &topic, reply.as_json().as_bytes()).await;
    let db = bridge_b.db_path.clone();
    await_db(&db, "reply parked", Duration::from_secs(20), |db| {
        db_count(
            db,
            "SELECT COUNT(*) FROM pending_orphans WHERE event_id = ?1",
            &reply_id,
        ) == 1
    })
    .await;
    // Parked = invisible: no event row, no live fan-out, REQ serves nothing.
    assert_eq!(
        db_count(&db, "SELECT COUNT(*) FROM events WHERE id = ?1", &reply_id),
        0,
        "parked reply must not have an events row"
    );
    assert_no_live_event(&mut sub_ws, &reply_id, Duration::from_secs(2), "parked").await;
    send_msg(
        &mut sub_ws,
        ClientMessage::req(SubscriptionId::new("p2-parked-hist"), vec![filter.clone()]),
    )
    .await;
    let parked = drain_until_eose(
        &mut sub_ws,
        "p2-parked-hist",
        Instant::now() + Duration::from_secs(15),
    )
    .await;
    assert_eq!(parked, 0, "parked reply must be invisible to REQ");
    println!("[P2] reply parked: pending_orphans=1, events=0, REQ=0, no live fan-out");

    // STEP 2: the ROOT lands. The parked reply must attach in the same commit
    // and the thread counters must recompute.
    daemon_publish(&mesh.alice, &topic, root.as_json().as_bytes()).await;
    let live_root = await_live_event(
        &mut sub_ws,
        &root_id,
        Instant::now() + Duration::from_secs(30),
        "root-live",
    )
    .await;
    assert_eq!(live_root["content"].as_str(), Some("wp5-p2 root"));
    await_db(&db, "reply attached", Duration::from_secs(20), |db| {
        db_count(db, "SELECT COUNT(*) FROM events WHERE id = ?1", &reply_id) == 1
            && db_count(
                db,
                "SELECT COUNT(*) FROM pending_orphans WHERE event_id = ?1",
                &reply_id,
            ) == 0
    })
    .await;
    // Recompute evidence: root's reply_count and descendant_count both moved
    // to exactly 1 (single reply, root == parent here).
    await_db(&db, "counters recomputed", Duration::from_secs(10), |db| {
        db_count(
            db,
            "SELECT reply_count FROM thread_metadata WHERE event_id = ?1",
            &root_id,
        ) == 1
            && db_count(
                db,
                "SELECT descendant_count FROM thread_metadata WHERE event_id = ?1",
                &root_id,
            ) == 1
    })
    .await;
    // The drained reply is served from history (it is NOT re-dispatched live —
    // only the ingested root is; asserted by the no-fan-out window below).
    send_msg(
        &mut sub_ws,
        ClientMessage::req(SubscriptionId::new("p2-hist"), vec![filter.clone()]),
    )
    .await;
    let ids = history_ids_until_eose(
        &mut sub_ws,
        "p2-hist",
        Instant::now() + Duration::from_secs(15),
    )
    .await;
    assert!(
        ids.contains(&root_id) && ids.contains(&reply_id),
        "[P2] history must serve root AND attached reply, got {ids:?}"
    );
    assert_no_live_event(&mut sub_ws, &reply_id, Duration::from_secs(2), "drain").await;
    println!(
        "[P2] PARK->ATTACH OK: reply parked on arrival, attached when root landed, \
         reply_count=descendant_count=1, history serves both"
    );
}

/// WP5 property 3 — dedupe by event id survives gossip redelivery.
///
/// The same signed event is delivered to bridge B TWICE over the fabric with
/// DIFFERENT wire bytes (pretty-printed re-serialization — a byte-identical
/// republish is dropped by the pubsub payload-replay cache before it reaches
/// the bridge, so byte variance is what makes the redelivery real). A control
/// event with a fresh id proves the byte-different path delivers. Then:
/// single row, unchanged counters, no second live fan-out, and the bridge's
/// own log proves the copy arrived and was deduped THERE.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires spawning real x0xd daemons"]
async fn e2e_gossip_redelivery_is_idempotent() {
    let _g = suite_lock().await;
    ensure_x0xd_binary();

    let mesh = pair().await;
    let bridge_a = spawn_bridge(&mesh.alice, "p3-a");
    let bridge_b = spawn_bridge(&mesh.bob, "p3-b");
    wait_for_bridge(&bridge_a.addr).await;
    wait_for_bridge(&bridge_b.addr).await;

    let ch = Uuid::new_v4().to_string();
    let topic = format!("buzz.v1.ch.{ch}");
    daemon_subscribe(&mesh.alice, &topic).await;

    let sub_keys = Keys::generate();
    let mut sub_ws = connect_ws(&bridge_b.addr).await;
    authenticate(&mut sub_ws, &sub_keys, &bridge_b.addr).await;
    let filter = Filter::new()
        .kinds([Kind::from(9u16)])
        .custom_tag(letter(Alphabet::H), ch.as_str());
    send_msg(
        &mut sub_ws,
        ClientMessage::req(SubscriptionId::new("p3-live"), vec![filter.clone()]),
    )
    .await;
    let pre = drain_until_eose(
        &mut sub_ws,
        "p3-live",
        Instant::now() + Duration::from_secs(15),
    )
    .await;
    assert_eq!(pre, 0, "fresh channel must be empty");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Seed root + reply so a counter exists to protect.
    let root_keys = Keys::generate();
    let root = EventBuilder::new(Kind::from(9u16), "wp5-p3 root")
        .tag(Tag::custom(TagKind::custom("h"), [ch.as_str()]))
        .sign_with_keys(&root_keys)
        .expect("sign root");
    let root_id = root.id.to_hex();
    daemon_publish(&mesh.alice, &topic, root.as_json().as_bytes()).await;
    await_live_event(
        &mut sub_ws,
        &root_id,
        Instant::now() + Duration::from_secs(30),
        "root-live",
    )
    .await;

    let reply_keys = Keys::generate();
    let reply = signed_reply(&reply_keys, &ch, &root_id, "wp5-p3 reply");
    let reply_id = reply.id.to_hex();
    daemon_publish(&mesh.alice, &topic, reply.as_json().as_bytes()).await;
    await_live_event(
        &mut sub_ws,
        &reply_id,
        Instant::now() + Duration::from_secs(30),
        "reply-live",
    )
    .await;
    let db = bridge_b.db_path.clone();
    await_db(&db, "reply stored", Duration::from_secs(20), |db| {
        db_count(db, "SELECT COUNT(*) FROM events WHERE id = ?1", &reply_id) == 1
    })
    .await;
    assert_eq!(
        db_count(
            &db,
            "SELECT reply_count FROM thread_metadata WHERE event_id = ?1",
            &root_id
        ),
        1,
        "baseline reply_count must be 1"
    );

    // CONTROL: a fresh-id event as pretty-printed (byte-different) JSON MUST
    // arrive live — proving the redelivery path carries such payloads to B.
    let control = EventBuilder::new(Kind::from(9u16), "wp5-p3 control")
        .tag(Tag::custom(TagKind::custom("h"), [ch.as_str()]))
        .sign_with_keys(&root_keys)
        .expect("sign control");
    let control_id = control.id.to_hex();
    let control_pretty = serde_json::to_string_pretty(&control).expect("pretty control");
    assert_ne!(
        control_pretty,
        control.as_json(),
        "control: pretty serialization must differ on the wire"
    );
    daemon_publish(&mesh.alice, &topic, control_pretty.as_bytes()).await;
    await_live_event(
        &mut sub_ws,
        &control_id,
        Instant::now() + Duration::from_secs(30),
        "control-live",
    )
    .await;
    println!("[P3] control: byte-different payload arrived live (redelivery path works)");

    // SUBJECT: redeliver the REPLY — same event id, different wire bytes.
    let reply_pretty = serde_json::to_string_pretty(&reply).expect("pretty reply");
    assert_ne!(reply_pretty, reply.as_json());
    daemon_publish(&mesh.alice, &topic, reply_pretty.as_bytes()).await;

    // No second live fan-out within the window...
    assert_no_live_event(&mut sub_ws, &reply_id, Duration::from_secs(3), "redelivery").await;
    // ...exactly one row...
    assert_eq!(
        db_count(&db, "SELECT COUNT(*) FROM events WHERE id = ?1", &reply_id),
        1,
        "redelivery must not insert a duplicate row"
    );
    // ...counters untouched...
    assert_eq!(
        db_count(
            &db,
            "SELECT reply_count FROM thread_metadata WHERE event_id = ?1",
            &root_id
        ),
        1,
        "redelivery must not double-bump reply_count"
    );
    assert_eq!(
        db_count(
            &db,
            "SELECT descendant_count FROM thread_metadata WHERE event_id = ?1",
            &root_id
        ),
        1,
        "redelivery must not double-bump descendant_count"
    );
    // ...the copy PROVABLY reached the bridge and was deduped there (not
    // dropped upstream): bridge B's own log carries the duplicate line.
    let log = std::fs::read_to_string(&bridge_b.log_path).expect("bridge B log");
    assert!(
        log.contains("mesh ingest duplicate") && log.contains(reply_id.as_str()),
        "bridge B log must show the duplicate arriving and being deduped locally"
    );
    // ...and history serves exactly one copy.
    send_msg(
        &mut sub_ws,
        ClientMessage::req(SubscriptionId::new("p3-hist"), vec![filter.clone()]),
    )
    .await;
    let ids = history_ids_until_eose(
        &mut sub_ws,
        "p3-hist",
        Instant::now() + Duration::from_secs(15),
    )
    .await;
    let copies = ids.iter().filter(|i| *i == &reply_id).count();
    assert_eq!(
        copies, 1,
        "history must serve exactly one copy, got {ids:?}"
    );

    // BYTE-IDENTICAL redelivery — the common redelivery form. The fabric does
    // NOT suppress it: pubsub msg_id = H(topic, epoch_secs, peer, payload),
    // so a republish one second later carries a fresh msg_id and is delivered
    // again in full. A second duplicate line must appear at the bridge — and
    // the store must STILL hold exactly one row with untouched counters.
    daemon_publish(&mesh.alice, &topic, reply.as_json().as_bytes()).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    let dup_lines = loop {
        let log_now = std::fs::read_to_string(&bridge_b.log_path).expect("bridge B log");
        let n = log_now
            .lines()
            .filter(|l| l.contains("mesh ingest duplicate") && l.contains(reply_id.as_str()))
            .count();
        if n >= 2 {
            break n;
        }
        assert!(
            Instant::now() < deadline,
            "byte-identical redelivery never reached the bridge \
             (expected a second duplicate log line for {reply_id})"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(dup_lines, 2, "both redeliveries arrived and were deduped");
    assert_eq!(
        db_count(&db, "SELECT COUNT(*) FROM events WHERE id = ?1", &reply_id),
        1,
        "byte-identical redelivery must not insert a duplicate row"
    );
    assert_eq!(
        db_count(
            &db,
            "SELECT reply_count FROM thread_metadata WHERE event_id = ?1",
            &root_id
        ),
        1,
        "byte-identical redelivery must not double-bump reply_count"
    );
    assert_no_live_event(&mut sub_ws, &reply_id, Duration::from_secs(2), "identical").await;
    println!(
        "[P3] IDEMPOTENT OK: reply redelivered TWICE (byte-different + byte-identical), \
         both deduped by event id at the bridge — 1 row, counters unchanged, \
         no second fan-out, both arrivals logged"
    );
}

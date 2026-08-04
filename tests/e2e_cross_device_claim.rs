//! End-to-end cross-device invite-claim over two REAL x0xd daemons + two
//! bridge binaries — the production authority/claimant transport flow that the
//! mock-daemon tests (`m1b_cross_device_claim`, `m1b_direct_transport`) cannot
//! prove: that a claim minted on authority bridge **A** is honored only after a
//! real NIP-98-authenticated claimant request on bridge **B** forwards the claim
//! to A over the daemon `/direct/send` surface, A adjudicates + durably mutates
//! its NIP-29 membership, and returns the typed result over `/direct/send`,
//! which is the *only* thing that completes B's HTTP claim.
//!
//! # Topology (fully isolated except one explicit loopback link)
//!
//! ```text
//!   daemon A (alice) ──bootstrap loopback── daemon B (bob)
//!        │                                     │
//!     bridge A (authority)                  bridge B (claimant)
//!     POST /api/invites  (admin NIP-98)     POST /api/invites/claim (joiner NIP-98)
//!     GET  /query       (NIP-98)            ── /direct/send claim ──► A
//!     ◄── /direct/events result ──         ◄── /direct/events claim ──
//! ```
//!
//! Both daemons run with `--no-hard-coded-bootstrap` and are linked *only* by an
//! explicit loopback `bootstrap_peers` entry (the harness `pair()` contract — no
//! internet bootstrap, deterministic peering on 127.0.0.1). No mock transport is
//! used: every `/direct/send` + `/direct/events` frame crosses a real QUIC hop.
//!
//! # What this defends (the acceptance contract)
//!
//! - **code cid + authority aid**: the claim response's `community_id` equals the
//!   code's signed `cid` (A's relay pubkey), and the code's `aid` equals A's
//!   daemon AgentId (`GET /agent`) — the routing key the claim was DM'd to.
//! - **exactly one durable member record**: A's kind-39002 for the joiner holds
//!   the joiner exactly once — the authority mutated state exactly once.
//! - **no false completion on the send receipt**: B returns `joined` AND A holds
//!   the member record. The production bus only completes a claim on the verified
//!   *result* DM (never the `/direct/send` receipt); the durable record on A is
//!   observable proof the result round-trip fired, not a transport-acceptance
//!   shortcut. (The negative invariant — receipt-alone times out — is pinned by
//!   `m1b_cross_device_claim::send_receipt_does_not_complete_claim_it_times_out`.)
//! - **process cleanup + no external listeners**: every daemon/bridge is killed
//!   on drop and the test asserts each address refuses new connections.
//!
//! Ignored by default (spawns real daemons + bridges). Run:
//!
//! ```sh
//! cargo nextest run --test e2e_cross_device_claim --run-ignored all \
//!   --nocapture
//! #   # or, without nextest:
//! cargo test --test e2e_cross_device_claim -- --ignored --nocapture
//! ```
//! The x0xd binary is auto-resolved from `../x0x/target/{release,debug}/x0xd`,
//! or pinned via `X0XD_TEST_BINARY`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use base64::Engine as _;
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[path = "harness/cluster.rs"]
mod cluster;
use cluster::{pair, AgentInstance};

/// Serialize daemon-spawning tests within this binary so port/temp allocation
/// never overlaps and mesh-form timing stays deterministic.
static TEST_MUTEX: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Resolve the x0xd binary once. The bridge crate's own `target/` has no x0xd;
/// the sibling `x0x` checkout does. `X0XD_TEST_BINARY` always wins.
static X0XD_BIN: LazyLock<PathBuf> = LazyLock::new(|| {
    if let Ok(p) = std::env::var("X0XD_TEST_BINARY") {
        let p = PathBuf::from(p);
        if p.exists() {
            return p;
        }
        panic!("X0XD_TEST_BINARY set but missing: {}", p.display());
    }
    let manifest = env!("CARGO_MANIFEST_DIR");
    let candidates = [
        // sibling x0x checkout (the layout in this workspace).
        PathBuf::from(manifest).join("../x0x/target/release/x0xd"),
        PathBuf::from(manifest).join("../x0x/target/debug/x0xd"),
        // workspace-root / bridge-local fallbacks.
        PathBuf::from(manifest).join("../target/release/x0xd"),
        PathBuf::from(manifest).join("../target/debug/x0xd"),
        PathBuf::from(manifest).join("target/release/x0xd"),
        PathBuf::from(manifest).join("target/debug/x0xd"),
    ];
    for c in &candidates {
        if c.exists() {
            return c.to_path_buf();
        }
    }
    panic!(
        "x0xd binary not found near {manifest}; build it first \
         (cargo build --release --bin x0xd in the x0x checkout) or set X0XD_TEST_BINARY. Searched: {}",
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
    // The harness honors this override; pin it so `pair()` resolves the same
    // binary this test selected.
    std::env::set_var("X0XD_TEST_BINARY", &*X0XD_BIN);
    println!("[harness] x0xd binary: {}", X0XD_BIN.display());
}

// ---------------------------------------------------------------------------
// Bridge subprocess orchestration
// ---------------------------------------------------------------------------

/// Owns one bridge binary process. `Drop` kills the child so a panic or test end
/// never orphans a listener. The DB tempdir is kept alive for the bridge's life.
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

/// Spawn one bridge binary fronting `daemon`. Real NIP-98 is enforced
/// (`BUZZ_REQUIRE_AUTH_TOKEN=true`) and `BRIDGE_PUBLIC_URL` is pinned to the
/// loopback bind so the NIP-98 `u` tag and NIP-42 `relay` tag match exactly.
/// `extra_env` carries authority-only config (seed + admin list).
fn spawn_bridge(daemon: &AgentInstance, name: &str, extra_env: &[(&str, &str)]) -> BridgeGuard {
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

    let mut cmd = Command::new(bin);
    cmd.env("BRIDGE_BIND", &addr)
        .env("BRIDGE_DB", db_path.as_os_str())
        .env("X0X_API", format!("http://{}", daemon.api_addr))
        .env("X0X_TOKEN", &daemon.api_token)
        // Real NIP-98 on every HTTP write endpoint (the task requirement).
        .env("BUZZ_REQUIRE_AUTH_TOKEN", "true")
        // Pin the public base to the loopback bind so NIP-98 `u` / NIP-42
        // `relay` tags verify exactly against this bridge.
        .env("BRIDGE_PUBLIC_URL", format!("http://{addr}"))
        .env(
            "RUST_LOG",
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        )
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let child = cmd
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

/// Wait for the bridge's NIP-11 info endpoint (`GET /`, `accept:
/// application/nostr+json`) — proves the binary booted, connected to its daemon
/// (gossip + direct transport + self AgentId resolved), and bound its listener.
async fn wait_for_bridge(addr: &str, name: &str) {
    let url = format!("http://{addr}/");
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(45);
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
            panic!("[{name}] bridge at {addr} did not answer NIP-11 within 45s");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// ---------------------------------------------------------------------------
// NIP-98 HTTP auth (kind 27235) + invite-code codec helpers
// ---------------------------------------------------------------------------

const NIP98_KIND: u16 = 27235;
/// kind-39002 NIP-29 group members list — the durable membership record.
const KIND_GROUP_MEMBERS: u16 = 39002;

/// Build an `Authorization: Nostr <b64 event>` header signing `method`+`url`
/// over the SHA-256 of the exact `body` bytes (NIP-98 §payload).
fn nip98_header(keys: &Keys, method: &str, url: &str, body: &[u8]) -> String {
    let payload = hex::encode(Sha256::digest(body));
    let ev = EventBuilder::new(Kind::from(NIP98_KIND), "")
        .tag(Tag::parse(["u", url]).unwrap())
        .tag(Tag::parse(["method", method]).unwrap())
        .tag(Tag::parse(["payload", &payload]).unwrap())
        .custom_created_at(Timestamp::now())
        .sign_with_keys(keys)
        .expect("sign nip98");
    format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(ev.as_json())
    )
}

/// The `cid` (authority/community pubkey) + `aid` (authority AgentId) bound into
/// a minted code, decoded without any secret (base64url payload split on `.`).
struct CodeView {
    cid: String,
    aid: String,
}

fn decode_code(code: &str) -> CodeView {
    let (payload_b64, _sig_b64) = code.split_once('.').expect("code has '.' delimiter");
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .expect("payload b64");
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("payload json");
    CodeView {
        cid: payload
            .get("cid")
            .and_then(Value::as_str)
            .expect("cid")
            .to_string(),
        aid: payload
            .get("aid")
            .and_then(Value::as_str)
            .expect("aid")
            .to_string(),
    }
}

/// Assert no process is listening on `host:port` (connection refused / reset).
async fn assert_no_listener(host: &str, port: u16, label: &str) {
    let addr = format!("{host}:{port}");
    match tokio::net::TcpStream::connect(&addr).await {
        Ok(_) => panic!("[{label}] listener still alive on {addr} after cleanup"),
        Err(_) => println!("[{label}] no listener on {addr} (clean)"),
    }
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// Definitive cross-device claim proof: mint on A, claim on B over real x0xd
/// direct messages, observe A's durable membership, prove no false completion,
/// and verify full process cleanup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "spawns two real x0xd daemons + two bridge binaries"]
async fn e2e_cross_device_invite_claim_over_real_x0xd_direct_messages() {
    let _g = suite_lock().await;
    ensure_x0xd_binary();

    // --- identities ---------------------------------------------------------
    // Admin mints at A (must be in A's BRIDGE_COMMUNITY_ADMINS). The joiner is
    // the fresh key that claims through B and lands as a member on A.
    let admin = Keys::generate();
    let joiner = Keys::generate();
    let admin_pk = admin.public_key().to_hex();
    let joiner_pk = joiner.public_key().to_hex();
    println!("[test] admin={admin_pk} joiner={joiner_pk}");

    // --- two isolated daemons, one explicit loopback link ------------------
    // pair(): alice (no bootstrap) + bob (bootstraps to alice on 127.0.0.1),
    // both with --no-hard-coded-bootstrap. Asserts the mesh peered.
    let mesh = pair().await;
    let alice_aid = mesh.alice.agent_id().await;
    let bob_aid = mesh.bob.agent_id().await;
    println!("[test] alice agent={alice_aid} (authority)  bob agent={bob_aid} (claimant)");

    // --- two bridges --------------------------------------------------------
    // A = authority: seed the `general` community + admit the admin pubkey.
    let bridge_a = spawn_bridge(
        &mesh.alice,
        "A-authority",
        &[
            ("BRIDGE_SEED_DEMO", "true"),
            ("BRIDGE_COMMUNITY_ADMINS", &admin_pk),
        ],
    );
    wait_for_bridge(&bridge_a.addr, "A").await;
    // B = claimant: no seed, no admin — it only forwards claims over DMs.
    let bridge_b = spawn_bridge(&mesh.bob, "B-claimant", &[]);
    wait_for_bridge(&bridge_b.addr, "B").await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(75))
        .build()
        .expect("client");

    // === 0. Precondition: bridge A resolved its self AgentId ==================
    // The production parser now reads the daemon's top-level `agent_id`
    // (ApiResponse<AgentData> flattens — no `data` wrapper). Confirm the
    // daemon exposes it and it matches the harness-resolved AgentId, so the
    // code-bound `aid` the claim forwards to is the real daemon routing key.
    let agent_body: Value = mesh
        .alice
        .get("/agent")
        .await
        .json()
        .await
        .expect("/agent json");
    let top_level_aid = agent_body
        .get("agent_id")
        .and_then(Value::as_str)
        .expect("top-level agent_id");
    assert_eq!(
        top_level_aid, alice_aid,
        "daemon /agent top-level agent_id must equal the harness-resolved AgentId"
    );
    assert!(
        agent_body.get("data").is_none(),
        "daemon /agent must not nest under `data` (flatten) — the path the bridge now reads"
    );
    println!("[test] bridge A self_agent_id resolvable (top-level agent_id={alice_aid}) — full claim flow armed");

    // === 1. Mint a stateless invite code on authority A (admin NIP-98) ======
    let mint_body = serde_json::to_vec(&json!({})).expect("mint body");
    let mint_url = format!("http://{}/api/invites", bridge_a.addr);
    let mint_resp = client
        .post(&mint_url)
        .header(
            "Authorization",
            nip98_header(&admin, "POST", &mint_url, &mint_body),
        )
        .header("Content-Type", "application/json")
        .body(mint_body)
        .send()
        .await
        .expect("mint request");
    assert_eq!(
        mint_resp.status(),
        200,
        "mint should succeed for a community admin: {}",
        mint_resp.text().await.unwrap_or_default()
    );
    let mint_json: Value = mint_resp.json().await.expect("mint json");
    let code = mint_json
        .get("code")
        .and_then(Value::as_str)
        .expect("code field")
        .to_string();
    let view = decode_code(&code);
    // The bridge forwards the claim DM with require_gossip=true, which the
    // daemon rejects in milliseconds if the authority's gossip-inbox
    // capability advert has not yet propagated to B's daemon (a convergence
    // race on a freshly-meshed pair). That surfaces as a FAST 502
    // AuthorityUnavailable. We wait on the observable success condition —
    // retry the claim until it completes (or a non-transient failure / the
    // deadline) — rather than a fixed sleep. Each attempt mints a fresh NIP-98
    // event (replay-safe); a fast-502 send never reached A, so A mutates at
    // most once (the successful attempt), preserving the exactly-one-member
    // invariant asserted in step 3.
    let claim_url = format!("http://{}/api/invites/claim", bridge_b.addr);
    let claim_deadline = Instant::now() + Duration::from_secs(75);
    let mut attempts = 0u32;
    let (claim_json, claim_elapsed) = loop {
        attempts += 1;
        let claim_body = serde_json::to_vec(&json!({ "code": code })).expect("claim body");
        let attempt_start = Instant::now();
        // Per-attempt timeout exceeds the bus's internal 30s result-DM timeout.
        let send = tokio::time::timeout(
            Duration::from_secs(35),
            client
                .post(&claim_url)
                .header(
                    "Authorization",
                    nip98_header(&joiner, "POST", &claim_url, &claim_body),
                )
                .header("Content-Type", "application/json")
                .body(claim_body)
                .send(),
        )
        .await;
        let elapsed = attempt_start.elapsed();
        let resp = match send {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => panic!("claim HTTP send failed: {e}"),
            Err(_) => panic!(
                "claim attempt did not resolve within 35s (authority aid={})",
                view.aid
            ),
        };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        println!(
            "[test] claim attempt {attempts}: status={status} elapsed={elapsed:?} body={text}"
        );
        if status == 200 {
            let json: Value = serde_json::from_str(&text).expect("claim json");
            break (json, elapsed);
        }
        // A FAST 502 is the gossip-inbox capability convergence race — retry
        // until converged. A slow 502 (>= the bus result-DM timeout) or any
        // other status is a genuine, non-transient failure.
        let transient =
            status == 502 && elapsed < Duration::from_secs(10) && Instant::now() < claim_deadline;
        if transient {
            println!("[test]   fast 502 (gossip-inbox capability convergence race) — retry in 1s");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        panic!(
            "claim failed (status={status}, elapsed={elapsed:?}) — not a transient convergence \
             502, so the cross-device result-DM round-trip did not complete. Body: {text}"
        );
    };
    println!("[test] claim succeeded after {attempts} attempt(s), final elapsed={claim_elapsed:?}");
    // 200 + joined/already_member is only reachable via the authority's verified
    // RESULT DM (the production bus never completes on the /direct/send receipt).
    let claim_status = claim_json
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        claim_status == "joined" || claim_status == "already_member",
        "claim status must be joined/already_member (a result-DM completion): {claim_json}"
    );
    // code cid == response community_id (the authority echoed its own pubkey).
    let resp_cid = claim_json
        .get("community_id")
        .and_then(Value::as_str)
        .expect("community_id field");
    assert_eq!(
        resp_cid, view.cid,
        "claim response community_id must equal the code's signed cid (A's relay pubkey)"
    );
    // "No false completion on the send receipt" is deliberately NOT a timing
    // claim — a loopback result-DM round-trip is legitimately sub-50ms (this
    // run was {claim_elapsed:?}). It is proven two ways below: (1) the claim
    // returned `joined` — the production DirectAuthorityBus only completes a
    // pending claim on the verified RESULT DM, never the /direct/send receipt
    // (a receipt-only path times out → 502 AuthorityUnavailable, pinned by
    // m1b_cross_device_claim::send_receipt_does_not_complete_claim_it_times_out);
    // and (2) A holds exactly one durable member record for the joiner (step 3),
    // which only the claim DM reaching A + being adjudicated can produce.
    // === 3. Exactly one durable member record on A (kind-39002 for joiner) ==
    // Query A's durable store via NIP-98 /query for the joiner's membership.
    // This is observable proof A adjudicated + mutated state (which only the
    // verified claim DM can trigger).
    let query_req = json!([{ "kinds": [KIND_GROUP_MEMBERS], "#p": [joiner_pk] }]);
    let query_body = serde_json::to_vec(&query_req).expect("query body");
    let query_url = format!("http://{}/query", bridge_a.addr);

    // The membership write is durable before B's result DM is sent, but poll
    // briefly to absorb store-read scheduling jitter on a loaded host.
    let poll_deadline = Instant::now() + Duration::from_secs(15);
    let (joiner_p_occurrences, members_event_seen) = loop {
        let qresp = client
            .post(&query_url)
            .header(
                "Authorization",
                nip98_header(&admin, "POST", &query_url, &query_body),
            )
            .header("Content-Type", "application/json")
            .body(query_body.clone())
            .send()
            .await
            .expect("query request");
        assert_eq!(
            qresp.status(),
            200,
            "query must succeed: {}",
            qresp.text().await.unwrap_or_default()
        );
        let events: Vec<Value> = qresp.json().await.expect("query events array");
        // Count how many times the joiner appears as a `["p", joiner_pk, …]`
        // entry across all returned 39002 membership events.
        let mut count = 0usize;
        let mut saw_members_event = false;
        for ev in &events {
            let kind = ev.get("kind").and_then(Value::as_u64);
            if kind == Some(KIND_GROUP_MEMBERS as u64) {
                saw_members_event = true;
                if let Some(tags) = ev.get("tags").and_then(Value::as_array) {
                    for t in tags {
                        if let Some(arr) = t.as_array() {
                            if arr.first().and_then(Value::as_str) == Some("p")
                                && arr.get(1).and_then(Value::as_str) == Some(&joiner_pk)
                            {
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
        if count >= 1 || Instant::now() > poll_deadline {
            break (count, saw_members_event);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    };
    assert!(
        members_event_seen,
        "no kind-39002 membership event for the joiner on A — the claim DM never reached \
         the authority, or adjudication failed"
    );
    assert_eq!(
        joiner_p_occurrences, 1,
        "joiner must appear EXACTLY once in A's durable 39002 membership (found \
         {joiner_p_occurrences}) — idempotent single admission, no duplicate"
    );
    println!("[test] A membership verified: joiner appears exactly once in kind-39002");

    // === 4. Process cleanup + no external listeners =========================
    // Drop order: bridges first (close WS/HTTP + drain DM supervisor), then
    // daemons (AgentInstance::drop kills each). Then assert every address is
    // gone so no orphaned listener survives the test.
    let a_bridge_addr = bridge_a.addr.clone();
    let b_bridge_addr = bridge_b.addr.clone();
    let a_api = mesh.alice.api_addr.clone();
    let b_api = mesh.bob.api_addr.clone();
    drop(bridge_a);
    drop(bridge_b);
    drop(mesh); // kills alice + bob daemons

    // Give the kernel a beat to release the sockets.
    tokio::time::sleep(Duration::from_millis(400)).await;
    for (addr_str, label) in [
        (&a_bridge_addr[..], "bridge A"),
        (&b_bridge_addr[..], "bridge B"),
        (&a_api[..], "daemon A API"),
        (&b_api[..], "daemon B API"),
    ] {
        let (host, port) = addr_str.rsplit_once(':').expect("host:port");
        assert_no_listener(host, port.parse::<u16>().unwrap(), label).await;
    }
    println!(
        "[test] PASS: cross-device claim over real x0xd /direct/send both directions, \
              exactly one durable member, clean shutdown"
    );
}

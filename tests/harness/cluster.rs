#![allow(dead_code)]
//! Three-agent daemon orchestration for integration tests.
//!
//! Provides `AgentCluster` which manages 3 x0xd daemon processes
//! (alice, bob, charlie) with mutual discovery for multi-agent testing.

use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::sync::OnceCell;

/// A single x0xd daemon instance.
pub struct AgentInstance {
    process: Child,
    binary: PathBuf,
    config_path: PathBuf,
    /// Instance name (e.g., "alice-12345").
    pub name: String,
    /// API address (e.g., "127.0.0.1:19101").
    pub api_addr: String,
    /// Bearer token for authentication.
    pub api_token: String,
    /// Data directory (cleaned up on drop if temp).
    data_dir: PathBuf,
    /// Gossip-plane id this instance declared at spawn (issue #206). A late
    /// joiner must declare the SAME plane or the mesh refuses the connection.
    pub network_id: String,
    /// This daemon's own MachineId hex — the identity its peers see in their
    /// `/peers` list (ant-quic `PeerId` == `MachineId` bytes). Filled by
    /// [`Self::refresh_runtime_state`] from `GET /agent`; used by
    /// [`assert_nodes_connected`] to prove a mesh contains ONLY the daemons
    /// this cluster spawned.
    pub machine_id: String,
}

#[allow(dead_code)]
impl AgentInstance {
    /// Shared HTTP client with a hard per-request timeout: a stalled child
    /// must fail the test, never hang a nightly job forever.
    fn http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build reqwest client")
    }

    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    pub fn directory_subscriptions_path(&self) -> PathBuf {
        self.data_dir.join("directory-subscriptions.json")
    }

    pub async fn restart(&mut self) {
        self.stop();
        self.start().await;
    }

    /// Kill the daemon process without restarting it. Pair with
    /// [`Self::start`] to create a downtime window during which other
    /// instances can mutate shared state (offline-mutation tests).
    pub fn stop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }

    /// Start the daemon again after [`Self::stop`] and wait until healthy.
    ///
    /// Test-only: when `X0X_TEST_LOG_DIR` is set, the restarted daemon's
    /// stdout/stderr are appended to `{dir}/{name}.restart.{out,err}.log`
    /// (outside the per-node temp data_dir, so logs survive cleanup and are
    /// preserved on test failure). When unset, I/O is discarded as before.
    /// The daemon inherits `RUST_LOG` from this process — set it in the test
    /// environment to raise verbosity for post-restart diagnostics.
    pub async fn start(&mut self) {
        let (stdout, stderr) = match test_log_stdio(&self.name, "restart") {
            Some(pair) => pair,
            None => (Stdio::null(), Stdio::null()),
        };
        self.process = Command::new(&self.binary)
            .arg("--config")
            .arg(&self.config_path)
            .arg("--name")
            .arg(&self.name)
            .arg("--no-hard-coded-bootstrap")
            .arg("--disable-peer-cache")
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to restart x0xd {}: {e}", self.name));
        self.refresh_runtime_state()
            .await
            .unwrap_or_else(|e| panic!("x0xd {} failed post-restart readiness: {e}", self.name));
    }
    /// Restart the daemon on a FORCED NEW QUIC (bind) port, keeping the same
    /// data_dir (hence the same `machine.key`/`agent.key` → same MachineId and
    /// QUIC peer_id), and with NO bootstrap peers configured.
    ///
    /// This is the named-node-restart primitive for the reconnect-policy
    /// regression: the restarted peer cannot startup-dial anyone (no
    /// bootstrap, `--no-hard-coded-bootstrap`), so the mesh can only reform
    /// via the SURVIVOR's proactive reconnect refreshing the new mDNS-announced
    /// endpoint. Returns the new QUIC bind port so the test can assert it
    /// differs from the pre-kill port (no fixed-port shortcut).
    pub async fn restart_on_new_quic_port_no_bootstrap(&mut self) -> u16 {
        self.stop();
        let new_bind = allocate_unused_udp_port();

        // Rewrite the config in place: drop every `bootstrap_peers` line (so
        // the restarted peer cannot initiate) and repoint `bind_address` at the
        // new port. `data_dir` is preserved verbatim → identity is preserved.
        let old_cfg = std::fs::read_to_string(&self.config_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", self.config_path.display()));
        let mut rebuilt = String::new();
        for line in old_cfg.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("bootstrap_peers") {
                continue;
            }
            if trimmed.starts_with("bind_address") {
                rebuilt.push_str(&format!("bind_address = \"127.0.0.1:{new_bind}\"\n"));
                continue;
            }
            rebuilt.push_str(line);
            rebuilt.push('\n');
        }
        std::fs::write(&self.config_path, &rebuilt)
            .unwrap_or_else(|e| panic!("rewrite {}: {e}", self.config_path.display()));

        let (stdout, stderr) = match test_log_stdio(&self.name, "restart-newport") {
            Some(pair) => pair,
            None => (Stdio::null(), Stdio::null()),
        };
        self.process = Command::new(&self.binary)
            .arg("--config")
            .arg(&self.config_path)
            .arg("--name")
            .arg(&self.name)
            // No hard-coded internet bootstrap either: this peer must be
            // unreachable by its own dialing so reconnection is attributable
            // solely to the survivor's proactive path.
            .arg("--no-hard-coded-bootstrap")
            .arg("--disable-peer-cache")
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to restart x0xd {}: {e}", self.name));
        self.refresh_runtime_state()
            .await
            .unwrap_or_else(|e| panic!("x0xd {} failed post-restart readiness: {e}", self.name));
        new_bind
    }

    async fn refresh_runtime_state(&mut self) -> Result<(), String> {
        let api_addr = self.api_addr.clone();
        // 90s, not 30s: debug-build daemons doing ML-DSA keygen plus
        // hard-coded internet bootstrap rounds come healthy anywhere from
        // ~15s to >30s depending on machine load — the old deadline was a
        // flakiness knife-edge for the first daemon of a run.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        let client = Self::http_client();
        loop {
            if let Ok(resp) = client.get(format!("http://{api_addr}/health")).send().await {
                if resp.status().is_success() {
                    break;
                }
            }
            if tokio::time::Instant::now() > deadline {
                return Err(format!(
                    "x0xd {} did not become healthy within 90s",
                    self.name
                ));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let token_file = self.data_dir.join("api-token");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(token) = std::fs::read_to_string(&token_file) {
                let token = token.trim().to_string();
                if !token.is_empty() {
                    self.api_token = token;
                    break;
                }
            }
            if tokio::time::Instant::now() > deadline {
                return Err(format!("Cannot find api-token for {}", self.name));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Own MachineId — the identity this daemon's peers will report. Read
        // once per (re)start; `machine.key` is preserved across restarts, so
        // the value is stable for a given data dir.
        let agent: serde_json::Value = self
            .get("/agent")
            .await
            .json()
            .await
            .map_err(|e| format!("parse /agent for {}: {e}", self.name))?;
        self.machine_id = agent["machine_id"]
            .as_str()
            .ok_or_else(|| format!("/agent for {} missing machine_id", self.name))?
            .to_string();
        Ok(())
    }

    /// Full URL for a given API path.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.api_addr, path)
    }

    /// Exchange the durable API token for a short-lived browser session token
    /// (#127 / WS1.6). Session tokens are the only kind accepted via `?token=`
    /// query strings on WS/SSE endpoints.
    pub async fn session_token(&self) -> String {
        let resp = Self::http_client()
            .post(format!("http://{}/auth/session", self.api_addr))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .expect("POST /auth/session failed");
        let json: serde_json::Value = resp.json().await.expect("/auth/session response json");
        json["session_token"]
            .as_str()
            .expect("session_token field")
            .to_string()
    }

    /// WebSocket URL with a short-lived session token in the query parameter
    /// (#127 / WS1.6). The durable token is no longer accepted in query strings.
    pub async fn ws_url(&self, path: &str) -> String {
        let session = self.session_token().await;
        format!("ws://{}{}?token={session}", self.api_addr, path)
    }

    /// Authenticated GET request.
    pub async fn get(&self, path: &str) -> reqwest::Response {
        Self::http_client()
            .get(self.url(path))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .expect("GET request failed")
    }

    /// Authenticated POST request with JSON body.
    pub async fn post(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        Self::http_client()
            .post(self.url(path))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(&body)
            .send()
            .await
            .expect("POST request failed")
    }

    /// Authenticated PUT request with JSON body.
    pub async fn put(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        Self::http_client()
            .put(self.url(path))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(&body)
            .send()
            .await
            .expect("PUT request failed")
    }

    /// Authenticated PATCH request with JSON body.
    pub async fn patch(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        Self::http_client()
            .patch(self.url(path))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(&body)
            .send()
            .await
            .expect("PATCH request failed")
    }

    /// Authenticated DELETE request.
    pub async fn delete(&self, path: &str) -> reqwest::Response {
        Self::http_client()
            .delete(self.url(path))
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .expect("DELETE request failed")
    }

    /// Unauthenticated GET request.
    pub async fn raw_get(&self, path: &str) -> reqwest::Response {
        Self::http_client()
            .get(self.url(path))
            .send()
            .await
            .expect("raw GET request failed")
    }

    /// Get this agent's ID by calling GET /agent.
    pub async fn agent_id(&self) -> String {
        let resp: serde_json::Value = self.get("/agent").await.json().await.expect("parse agent");
        resp["agent_id"]
            .as_str()
            .expect("agent_id field")
            .to_string()
    }
}

/// Three x0xd daemon instances for multi-agent testing.
pub struct AgentCluster {
    pub alice: AgentInstance,
    pub bob: AgentInstance,
    #[allow(dead_code)]
    pub charlie: AgentInstance,
}

/// Two-daemon local pair for deterministic cross-peer tests.
pub struct AgentPair {
    pub alice: AgentInstance,
    pub bob: AgentInstance,
}

impl Drop for AgentInstance {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Drop for AgentCluster {
    fn drop(&mut self) {
        // AgentInstance::drop handles killing each process.
        // Explicit drop order: charlie, bob, alice (reverse of start).
        // (Rust drops fields in declaration order, which is alice, bob, charlie —
        //  but the order doesn't matter for cleanup, just that it happens.)
    }
}

impl Drop for AgentPair {
    fn drop(&mut self) {
        // AgentInstance::drop handles child cleanup.
    }
}

static CLUSTER: OnceCell<AgentCluster> = OnceCell::const_new();

/// Returns a shared `AgentCluster` singleton.
///
/// The cluster is created once per test binary (via `OnceCell`) and reused
/// across all tests in the same binary. This matches nextest's model where
/// each test file is a separate process.
///
/// # Panics
///
/// Panics if x0xd binary is not found or agents fail to start.
pub async fn cluster() -> &'static AgentCluster {
    CLUSTER.get_or_init(create_cluster).await
}

/// Start a fresh two-daemon pair with Bob bootstrapping to Alice.
pub async fn pair() -> AgentPair {
    pair_with_extra_config("").await
}

/// Start a single daemon with no bootstrap peers. Returns the instance
/// and its UDP bind port so a later daemon can bootstrap to it — the
/// staggered-start primitive for cold-late-join tests (issue #96), where
/// state must exist before the second daemon's process does.
pub async fn solo() -> (AgentInstance, u16) {
    let binary = find_x0xd_binary();
    let suffix = rand::random::<u16>();
    start_instance(
        &binary,
        &format!("solo-{suffix}"),
        "",
        "",
        &format!("x0x.test.solo-{suffix}"),
    )
    .await
}

/// Start a daemon that bootstraps to an already-running instance's UDP
/// bind port (as returned by [`solo`]). Waits for the mesh to settle and
/// asserts the two nodes actually peered, mirroring [`pair`]'s guarantees.
pub async fn join_peer(anchor: &AgentInstance, anchor_bind: u16) -> AgentInstance {
    let binary = find_x0xd_binary();
    let suffix = rand::random::<u16>();
    let (instance, _bind) = start_instance(
        &binary,
        &format!("late-{suffix}"),
        &format!("bootstrap_peers = [\"127.0.0.1:{anchor_bind}\"]"),
        "",
        // Same plane as the anchor: a different `network_id` would be refused
        // at the gossip layer (issue #206) and the join would never peer.
        &anchor.network_id.clone(),
    )
    .await;
    tokio::time::sleep(MESH_SETTLE_TIME).await;
    assert_nodes_connected(&[anchor, &instance]).await;
    instance
}

pub async fn trio_with_extra_config(extra_config: &str) -> AgentCluster {
    create_cluster_with_extra_config(extra_config).await
}

/// Start a fresh pair with the same extra TOML appended to each daemon's
/// generated config. Useful for test-only timing overrides.
pub async fn pair_with_extra_config(extra_config: &str) -> AgentPair {
    let binary = find_x0xd_binary();
    let suffix = rand::random::<u16>();
    let (alice, alice_bind) = start_instance(
        &binary,
        &format!("pair-alice-{suffix}"),
        "",
        extra_config,
        &format!("x0x.test.pair-{suffix}"),
    )
    .await;
    // Rolling start: use the same empirically-required delay as the trio so
    // bob has a stable alice to bootstrap against. The previous 5s was too
    // short and let propagation-dependent tests race mesh formation.
    tokio::time::sleep(ROLLING_START_DELAY).await;
    let (bob, _bob_bind) = start_instance(
        &binary,
        &format!("pair-bob-{suffix}"),
        &format!("bootstrap_peers = [\"127.0.0.1:{alice_bind}\"]"),
        extra_config,
        &format!("x0x.test.pair-{suffix}"),
    )
    .await;
    tokio::time::sleep(MESH_SETTLE_TIME).await;

    // Enforce peering before returning. Without this, propagation-dependent
    // assertions (member convergence, delete propagation) flake when alice and
    // bob have not yet connected — exactly the failure mode the trio path
    // already guards against via assert_mesh_connected.
    assert_nodes_connected(&[&alice, &bob]).await;

    AgentPair { alice, bob }
}

/// Delay between starting each node to allow connections and the gossip
/// mesh to form. Discovered empirically — without this rolling start,
/// nodes that come up simultaneously fail to establish stable connections.
const ROLLING_START_DELAY: Duration = Duration::from_secs(15);

/// Extra settling time after all nodes are up, before we start checking
/// for peers. Gives the mesh time to fully stabilise.
const MESH_SETTLE_TIME: Duration = Duration::from_secs(5);

async fn create_cluster() -> AgentCluster {
    create_cluster_with_extra_config("").await
}

async fn create_cluster_with_extra_config(extra_config: &str) -> AgentCluster {
    let binary = find_x0xd_binary();
    let suffix = rand::random::<u16>();

    // Rolling start: each node needs time for its QUIC listener to bind and
    // mDNS/bootstrap to propagate before the next node comes up. Starting
    // all three simultaneously causes connection races and mesh instability.

    eprintln!("[cluster] starting alice...");
    let (alice, alice_bind) = start_instance(
        &binary,
        &format!("test-alice-{suffix}"),
        "",
        extra_config,
        &format!("x0x.test.trio-{suffix}"),
    )
    .await;

    eprintln!(
        "[cluster] waiting {}s for alice to stabilise before starting bob...",
        ROLLING_START_DELAY.as_secs()
    );
    tokio::time::sleep(ROLLING_START_DELAY).await;

    eprintln!("[cluster] starting bob (bootstraps to alice)...");
    let (bob, _bob_bind) = start_instance(
        &binary,
        &format!("test-bob-{suffix}"),
        &format!("bootstrap_peers = [\"127.0.0.1:{alice_bind}\"]"),
        extra_config,
        &format!("x0x.test.trio-{suffix}"),
    )
    .await;

    eprintln!(
        "[cluster] waiting {}s for bob to join mesh before starting charlie...",
        ROLLING_START_DELAY.as_secs()
    );
    tokio::time::sleep(ROLLING_START_DELAY).await;

    eprintln!("[cluster] starting charlie (bootstraps to alice)...");
    let (charlie, _charlie_bind) = start_instance(
        &binary,
        &format!("test-charlie-{suffix}"),
        &format!("bootstrap_peers = [\"127.0.0.1:{alice_bind}\"]"),
        extra_config,
        &format!("x0x.test.trio-{suffix}"),
    )
    .await;

    // Give the full mesh a moment to settle after all three are up
    eprintln!(
        "[cluster] all nodes up — waiting {}s for mesh to settle...",
        MESH_SETTLE_TIME.as_secs()
    );
    tokio::time::sleep(MESH_SETTLE_TIME).await;

    // Enforce mesh connectivity — alice must see at least one peer.
    // A disconnected cluster is useless for integration tests, so we
    // panic rather than silently producing flaky results.
    assert_mesh_connected(&alice, &bob, &charlie).await;

    AgentCluster {
        alice,
        bob,
        charlie,
    }
}

/// Verify that the three-node mesh is connected. Panics if any node
/// cannot see at least one peer within 30 seconds.
async fn assert_mesh_connected(
    alice: &AgentInstance,
    bob: &AgentInstance,
    charlie: &AgentInstance,
) {
    assert_nodes_connected(&[alice, bob, charlie]).await;
    eprintln!("[cluster] mesh verified — all 3 nodes connected");
}

/// Poll `/peers` on each node until it reports at least one peer. Panics if any
/// node still has zero peers after 30s. A disconnected mesh produces flaky
/// propagation results, so we fail loudly here rather than let the test proceed
/// and time out on a downstream convergence assertion.
///
/// CONTAMINATION GUARD (safety-critical): a nonzero peer count is NOT
/// sufficient — every reported peer identity must be one of the daemons THIS
/// cluster spawned. Peer identities are MachineId hex (ant-quic `PeerId` ==
/// `MachineId` bytes), read from each spawned daemon's own `GET /agent`. If
/// isolation ever breaks, a foreign (e.g. production) daemon satisfies the
/// readiness check and silently carries test traffic; here that fails the
/// test immediately instead of masking the breach.
async fn assert_nodes_connected(nodes: &[&AgentInstance]) {
    let known: std::collections::HashSet<&str> =
        nodes.iter().map(|n| n.machine_id.as_str()).collect();
    assert!(
        !known.contains(""),
        "machine_id not populated for a spawned daemon — readiness cannot be verified"
    );
    for node in nodes {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let resp: serde_json::Value = node.get("/peers").await.json().await.unwrap_or_default();
            let peer_ids: Vec<String> = resp["peers"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|p| p["id"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            // A foreign peer is fatal IMMEDIATELY — waiting cannot make a
            // contaminated mesh safe.
            for id in &peer_ids {
                assert!(
                    known.contains(id.as_str()),
                    "[cluster] FATAL: {} sees foreign peer {id} — the test mesh is \
                     contaminated by a daemon this cluster did not spawn (isolation \
                     breach). Refusing to run: test traffic must never reach foreign \
                     daemons. Known spawned identities: {known:?}",
                    node.name
                );
            }
            if !peer_ids.is_empty() {
                eprintln!(
                    "[cluster] {} sees {} peer(s), all cluster-spawned",
                    node.name,
                    peer_ids.len()
                );
                break;
            }
            if tokio::time::Instant::now() > deadline {
                panic!(
                    "[cluster] FATAL: {} has zero peers after 30s — mesh is disconnected. \
                     Integration tests require a connected cluster. \
                     Check that x0xd bootstrap and mDNS are working.",
                    node.name
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

fn find_x0xd_binary() -> PathBuf {
    // Runtime override — lets a test run pin the daemon build (e.g. to
    // prove a regression test fails against a pre-fix binary while the
    // test code itself compiles from the current tree).
    if let Ok(path) = std::env::var("X0XD_TEST_BINARY") {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
        panic!(
            "X0XD_TEST_BINARY set but does not exist: {}",
            path.display()
        );
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_x0xd") {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }
    // From tests/harness/, the project root is ../../
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let debug = PathBuf::from(manifest_dir).join("target/debug/x0xd");
    if debug.exists() {
        return debug;
    }
    let release = PathBuf::from(manifest_dir).join("target/release/x0xd");
    if release.exists() {
        return release;
    }
    let legacy = PathBuf::from(manifest_dir).join("../../target/release/x0xd");
    if legacy.exists() {
        return legacy;
    }
    panic!(
        "x0xd binary not found. Build first: cargo build --bin x0xd\n\
         Searched: {}, {}, {}",
        debug.display(),
        release.display(),
        legacy.display()
    );
}

fn allocate_unused_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral TCP port")
        .local_addr()
        .expect("tcp local addr")
        .port()
}

fn allocate_unused_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral UDP port")
        .local_addr()
        .expect("udp local addr")
        .port()
}

/// Test-only daemon log capture.
///
/// When `X0X_TEST_LOG_DIR` is set, returns stdout/stderr `Stdio` handles that
/// append to `{dir}/{name}.{suffix}.{out,err}.log`. That path lives outside the
/// per-node temp data_dir, so the logs survive data-dir cleanup and are
/// preserved on test failure. Returns `None` when the env var is unset so the
/// caller's default sink (per-node data-dir files, or `Stdio::null()`) is used
/// and other tests are unaffected.
///
/// The daemon inherits `RUST_LOG` from this process, so set `RUST_LOG` (e.g.
/// `x0x::crdt=debug,x0x::server=debug`) in the test environment to raise
/// verbosity; the directive is honoured by the daemon's `init_logging`.
fn test_log_stdio(name: &str, suffix: &str) -> Option<(Stdio, Stdio)> {
    let dir = std::env::var("X0X_TEST_LOG_DIR").ok()?;
    let dir = dir.trim();
    if dir.is_empty() {
        return None;
    }
    let _ = std::fs::create_dir_all(dir);
    let base = std::path::Path::new(dir).join(format!("{name}.{suffix}"));
    let open = || {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{}.log", base.display()))
            .unwrap_or_else(|e| panic!("open test log {base:?}: {e}"))
    };
    // Two independent append handles to the same path; both file descriptions
    // share O_APPEND, so interleaved stdout/stderr writes stay ordered.
    Some((Stdio::from(open()), Stdio::from(open())))
}

/// Kill stale x0xd TEST daemons from prior failed runs that may still own
/// these ports. Two guards against killing an innocent bystander (the
/// pre-hardening version piped `lsof -ti tcp:PORT | xargs kill -9` blind —
/// including querying tcp: for a UDP port):
/// 1. protocol-correct lookup: TCP for the API port, UDP for the QUIC bind.
/// 2. process-identity match: the command line must contain BOTH an `x0xd`
///    binary AND this harness's `x0x-test-` config-dir marker. The
///    production daemon (`./target/release/x0xd --skip-update-check`, no test
///    config) never matches, and neither does any unrelated service that
///    merely holds the same port number.
fn kill_stale_test_daemons(api_port: u16, bind_port: u16) {
    for (proto, port) in [("tcp", api_port), ("udp", bind_port)] {
        let Ok(out) = Command::new("lsof")
            .args(["-ti", &format!("{proto}:{port}")])
            .output()
        else {
            continue;
        };
        for pid in String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.trim().parse::<u32>().ok())
        {
            let Ok(cmd) = Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "command="])
                .output()
            else {
                continue;
            };
            let cmdline = String::from_utf8_lossy(&cmd.stdout);
            if cmdline.contains("x0xd") && cmdline.contains("x0x-test-") {
                eprintln!("[cluster] killing stale test daemon pid={pid}: {cmdline}");
                let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
            }
        }
    }
}

/// Allocate ports and start one daemon, retrying once with FRESH ports if the
/// first attempt fails readiness. The port allocation is bind-to-zero-then-
/// release (a TOCTOU window: a racer can steal the port before the daemon
/// binds it, surfacing as a readiness timeout); one retry collapses the
/// failure probability without masking a genuinely broken daemon, which still
/// panics after attempt two.
async fn start_instance(
    binary: &PathBuf,
    name: &str,
    bootstrap: &str,
    extra_config: &str,
    network_id: &str,
) -> (AgentInstance, u16) {
    let mut last_err = String::new();
    for attempt in 1..=2u32 {
        let api_port = allocate_unused_tcp_port();
        let bind_port = allocate_unused_udp_port();
        match try_start_instance(
            binary,
            name,
            api_port,
            bind_port,
            bootstrap,
            extra_config,
            network_id,
        )
        .await
        {
            Ok(instance) => return (instance, bind_port),
            Err(e) => {
                eprintln!("[cluster] {name} start attempt {attempt} failed: {e}");
                last_err = e;
            }
        }
    }
    panic!("x0xd {name} failed to start after 2 attempts: {last_err}");
}

async fn try_start_instance(
    binary: &PathBuf,
    name: &str,
    api_port: u16,
    bind_port: u16,
    bootstrap: &str,
    extra_config: &str,
    network_id: &str,
) -> Result<AgentInstance, String> {
    let config_dir = std::env::temp_dir().join(format!("x0x-test-{name}"));
    let _ = std::fs::remove_dir_all(&config_dir);
    let _ = std::fs::create_dir_all(&config_dir);

    kill_stale_test_daemons(api_port, bind_port);

    let config_path = config_dir.join("config.toml");
    // Isolation contract (non-negotiable for test daemons):
    // - `127.0.0.1` QUIC bind: ant-quic skips mDNS on loopback-only endpoints,
    //    so the daemon neither advertises to nor browses the LAN — the
    //    production daemon on this machine stays undiscoverable.
    // - `bootstrap_peers = []` when no loopback peer is given: combined with
    //    `--no-hard-coded-bootstrap` no seed peer is ever dialled.
    // - `network_id`: a per-cluster gossip plane (issue #206), so even an
    //    accidentally-established connection to an off-test daemon is refused
    //    at the gossip layer.
    // - `--disable-peer-cache` (CLI below): no cached peers are loaded/saved.
    //
    // NOTE: `[update] enabled = false` is MANDATORY in every test config —
    // test binaries otherwise SELF-REPLACE via gossip-delivered auto-update
    // (x0x#226 standing rule). It goes LAST so table sections opened by
    // `extra_config` cannot swallow the flat keys above it.
    let bootstrap_line = if bootstrap.trim().is_empty() {
        "bootstrap_peers = []".to_string()
    } else {
        bootstrap.to_string()
    };
    let config_content = format!(
        "api_address = \"127.0.0.1:{api_port}\"\n\
         bind_address = \"127.0.0.1:{bind_port}\"\n\
         data_dir = \"{}\"\n\
         log_level = \"warn\"\n\
         network_id = \"{network_id}\"\n\
         {bootstrap_line}\n\
         {extra_config}\n\
         [update]\n\
         enabled = false\n",
        config_dir.display()
    );
    std::fs::write(&config_path, &config_content).expect("write config");

    // Test-only capture (see `test_log_stdio`); fall back to per-node data-dir
    // logs so the default behaviour is unchanged.
    let (stdout, stderr) = match test_log_stdio(name, "start") {
        Some(pair) => pair,
        None => {
            let stdout_path = config_dir.join("daemon.stdout.log");
            let stderr_path = config_dir.join("daemon.stderr.log");
            let out = std::fs::File::create(&stdout_path)
                .unwrap_or_else(|e| panic!("Failed to create stdout log for {name}: {e}"));
            let err = std::fs::File::create(&stderr_path)
                .unwrap_or_else(|e| panic!("Failed to create stderr log for {name}: {e}"));
            (Stdio::from(out), Stdio::from(err))
        }
    };

    let process = Command::new(binary)
        .arg("--config")
        .arg(&config_path)
        .arg("--name")
        .arg(name)
        .arg("--no-hard-coded-bootstrap")
        .arg("--disable-peer-cache")
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .map_err(|e| format!("Failed to start x0xd {name}: {e}"))?;

    // Wrap the Child in an AgentInstance immediately so that Drop kills
    // the process if anything below fails (health timeout, token read, etc.).
    // We'll fill in api_token once we have it.
    let api_addr = format!("127.0.0.1:{api_port}");
    let mut instance = AgentInstance {
        process,
        binary: binary.clone(),
        config_path: config_path.clone(),
        name: name.to_string(),
        api_addr: api_addr.clone(),
        api_token: String::new(), // placeholder — filled below
        data_dir: config_dir.clone(),
        network_id: network_id.to_string(),
        machine_id: String::new(), // placeholder — filled below
    };

    // Wait for health / token — on failure `instance` is dropped, killing the
    // process, and the retry wrapper starts over on fresh ports.
    instance.refresh_runtime_state().await?;
    Ok(instance)
}

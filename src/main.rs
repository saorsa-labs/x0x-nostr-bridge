//! x0x-nostr-bridge — Nostr relay facade backed by the x0x gossip fabric.
//!
//! Spike scope: NIP-01 (EVENT/REQ/CLOSE/EOSE/OK/NOTICE), NIP-42 auth,
//! NIP-16 replaceable semantics, NIP-50 search, NIP-11 info. Events are
//! distributed as signed JSON over per-channel gossip topics; history lives
//! in a local SQLite fed by the fabric. See docs/plans/ or the contract doc
//! for the module ownership map.
//!
//! The binary is a thin wiring wrapper over the `x0x_nostr_bridge` library;
//! all logic lives in the library modules so it is integration-testable.
//!
//! Config (env):
//! - BRIDGE_BIND  — ws listen addr (default 127.0.0.1:3300)
//! - BRIDGE_DB    — sqlite path (default ./nostr-bridge.db)
//! - X0X_API / X0X_TOKEN — daemon REST addr + bearer (else auto-discovered from the
//!   x0x data dir by transport::discover)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tracing::{info, warn};

use tokio_util::sync::CancellationToken;
use x0x_nostr_bridge::config;
use x0x_nostr_bridge::direct_transport::X0xDirectTransport;
use x0x_nostr_bridge::engine_api::HistoryEngine;
use x0x_nostr_bridge::history::HistoryStore;
use x0x_nostr_bridge::history_adapter::{HistoryStoreEngine, HistoryStoreEventStore};
use x0x_nostr_bridge::ingest;
use x0x_nostr_bridge::join_policy::JoinPolicyConfig;
use x0x_nostr_bridge::m1b;
use x0x_nostr_bridge::media::MediaStore;
use x0x_nostr_bridge::proto;
use x0x_nostr_bridge::relay::{self, AppState};
use x0x_nostr_bridge::relay_identity::RelayIdentity;
use x0x_nostr_bridge::seed;
use x0x_nostr_bridge::settings::Settings;
use x0x_nostr_bridge::store::EventStore;
use x0x_nostr_bridge::transport::{GossipTransport, X0xTransport};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind: SocketAddr = std::env::var("BRIDGE_BIND")
        .unwrap_or_else(|_| "127.0.0.1:3300".to_string())
        .parse()?;
    if !config::is_loopback(bind) {
        warn!(
            %bind,
            "BRIDGE_BIND is not loopback: the relay exposes a plaintext WebSocket with NO TLS \
             and NO connection allowlist. NIP-42 AUTH proves ownership of a key only — it is \
             NOT access control. Any client that can reach this address can read all events \
             and attempt AUTH. Bind to 127.0.0.1 unless you understand the exposure."
        );
    }
    let db_path =
        PathBuf::from(std::env::var("BRIDGE_DB").unwrap_or_else(|_| "nostr-bridge.db".to_string()));
    let (api, token) = config::resolve_api()?;
    let transport: Arc<dyn GossipTransport> = Arc::new(X0xTransport::connect(&api, &token).await?);
    // Shutdown signal — shared by the authority worker, the direct dispatcher,
    // and the direct transport's SSE supervisor.
    let shutdown_cancel = CancellationToken::new();

    // Bridge settings + relay identity (D4). The daemon-binding fingerprint is
    // derived from the resolved API base (privacy: only the SHA-256 is exposed).
    let mut settings = Settings::from_env();
    settings.x0x_api_fingerprint = config::api_fingerprint(&api);
    // M1b media: default the sidecar db + blob dir to siblings of BRIDGE_DB
    // (contract §3) when no explicit path was set. This is honest *local*
    // content-addressed storage — it never claims cross-device byte transport.
    if settings.media_db_path.as_os_str().is_empty() {
        settings.media_db_path = db_path.with_file_name("media.db");
    }
    if settings.media_dir.as_os_str().is_empty() {
        settings.media_dir = db_path.with_file_name("media");
    }
    let settings = Arc::new(settings);
    // M1b direct transport: authenticated loopback DM surface for cross-device
    // invite-claim forwarding. Same resolved daemon API + token as the gossip
    // transport; bounded backfill (BRIDGE_DIRECT_BACKFILL, default 64). This is
    // best-effort — if the daemon doesn't expose the direct-message surface,
    // remote claim forwarding is disabled and local claims still work in-process.
    let (direct_transport, self_agent_id) = match X0xDirectTransport::connect(
        &api,
        &token,
        shutdown_cancel.clone(),
        Some(settings.direct_backfill),
    )
    .await
    {
        Ok(dt) => {
            let arc = Arc::new(dt);
            // Discover our own AgentId (GET /agent) — this is the `aid` that
            // invite codes bind to and that verified result senders must equal.
            let id = match arc.self_agent_id().await {
                Ok(id) => Some(id),
                Err(e) => {
                    warn!(error = %e, "cannot resolve self agent id; remote claims disabled");
                    None
                }
            };
            (Some(arc), id)
        }
        Err(e) => {
            warn!(
                error = %e,
                "direct transport unavailable; remote invite claims disabled"
            );
            (None, None)
        }
    };
    info!(
        direct = direct_transport.is_some(),
        self_id = self_agent_id.is_some(),
        "direct transport"
    );

    let relay_key_path = PathBuf::from(std::env::var("BRIDGE_RELAY_KEY").unwrap_or_else(|_| {
        db_path
            .with_file_name("relay.key")
            .to_string_lossy()
            .into_owned()
    }));
    let identity = Arc::new(RelayIdentity::load_or_create(&relay_key_path)?);

    // ONE durable history store behind both lanes: the HTTP `HistoryEngine`
    // (read model + two-door ingest) and the WS `EventStore` (REQ backfill +
    // EVENT ingest) wrap the same `HistoryStore`, so every read/write path hits
    // one store (integration step 3). The community fingerprint guards against
    // accidental scope reuse (design §3).
    let community_fingerprint = std::env::var("BRIDGE_COMMUNITY_FINGERPRINT")
        .unwrap_or_else(|_| settings.public_base_url.clone());
    let history = Arc::new(HistoryStore::open(&db_path, &community_fingerprint)?);
    // p-gated kinds are excluded from NIP-50 search at the store layer.
    let p_gated: Vec<u32> = settings
        .access
        .p_gated_kinds
        .iter()
        .map(|&k| u32::from(k))
        .collect();
    let engine: Arc<dyn HistoryEngine> = Arc::new(HistoryStoreEngine::new(
        Arc::clone(&history),
        p_gated.clone(),
    ));
    let store: Arc<dyn EventStore> =
        Arc::new(HistoryStoreEventStore::new(Arc::clone(&history), p_gated));

    // Subscribe the global topic plus every channel we've ever stored.
    transport.ensure_topic(proto::GLOBAL_TOPIC).await?;
    for ch in store.known_channels().await? {
        transport.ensure_topic(&proto::channel_topic(&ch)).await?;
    }

    // M1b: local media CAS (own sidecar + blob dir), join-policy (env), and
    // the authority worker state (claim adjudication). Media is local CAS
    // only — it does not transport bytes across devices.
    let media = Arc::new(MediaStore::open(
        &settings.media_db_path,
        &settings.media_dir,
        &community_fingerprint,
    )?);
    let join_policy = Arc::new(JoinPolicyConfig::from_env()?);

    let state = Arc::new(
        AppState::new(
            Arc::clone(&store),
            Arc::clone(&transport),
            engine,
            identity,
            Arc::clone(&settings),
        )
        .with_media(media)
        .with_join_policy(join_policy)
        .with_authority()
        .with_direct(direct_transport, self_agent_id),
    );

    if settings.seed_demo {
        seed::seed_demo(&state).await?;
        info!("demo seed applied (--seed-demo / BRIDGE_SEED_DEMO)");
    }

    // Ingest: gossip → verify → store → fan out.
    let mut inbox = transport.inbox();
    let ingest_state = Arc::clone(&state);
    tokio::spawn(async move {
        while let Some(msg) = inbox.recv().await {
            ingest::ingest_one(&ingest_state, &msg).await;
        }
    });

    let app = relay::router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(bind).await?;

    // M1b authority worker: adjudicates invite claims via the in-process typed
    // RPC channel (verified sender → apply_claim → nip29::add_member_from_invite).
    // `Some` here because `with_authority()` was called; a claim only succeeds
    // after the authority's typed reply — never the transport receipt.
    let authority_worker = m1b::spawn_authority_worker(Arc::clone(&state), shutdown_cancel.clone());
    // M1b direct dispatcher: consumes verified DMs, routes incoming remote
    // claims to the authority worker and completes pending remote claims on
    // verified result DMs. `Some` when a direct transport + self id are wired.
    let direct_dispatcher =
        m1b::spawn_direct_dispatcher(Arc::clone(&state), shutdown_cancel.clone());
    info!(
        %bind,
        db = %db_path.display(),
        authority = authority_worker.is_some(),
        direct = direct_dispatcher.is_some(),
        "x0x-nostr-bridge listening"
    );

    // Graceful shutdown (WP3 stretch): on SIGTERM, refuse new `/` hits with 503,
    // broadcast a 1012 Service-Restart close to every live WS, cancel the
    // authority worker + direct dispatcher, and drain briefly.
    let shutdown_state = Arc::clone(&state);
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            wait_for_terminate().await;
            shutdown_state
                .shutting_down
                .store(true, std::sync::atomic::Ordering::Relaxed);
            shutdown_state.shutdown.notify_waiters();
            shutdown_cancel.cancel();
            info!("SIGTERM: draining WS connections with 1012 (relay restarting)");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        })
        .await?;

    // Drain the authority worker + direct dispatcher after the HTTP server has
    // stopped accepting, then drain the direct transport SSE supervisor.
    if let Some(handle) = authority_worker {
        let _ = handle.await;
    }
    if let Some(handle) = direct_dispatcher {
        let _ = handle.await;
    }
    if let Some(dt) = &state.direct {
        dt.join_drain().await;
    }
    Ok(())
}

/// Resolve when SIGTERM (or Ctrl-C) is received.
async fn wait_for_terminate() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

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

use x0x_nostr_bridge::config;
use x0x_nostr_bridge::engine_api::HistoryEngine;
use x0x_nostr_bridge::history::HistoryStore;
use x0x_nostr_bridge::history_adapter::{HistoryStoreEngine, HistoryStoreEventStore};
use x0x_nostr_bridge::ingest;
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

    // Bridge settings + relay identity (D4).
    let settings = Arc::new(Settings::from_env());
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

    let state = Arc::new(AppState::new(
        Arc::clone(&store),
        Arc::clone(&transport),
        engine,
        identity,
        Arc::clone(&settings),
    ));

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
    info!(%bind, db = %db_path.display(), "x0x-nostr-bridge listening");

    // Graceful shutdown (WP3 stretch): on SIGTERM, refuse new `/` hits with 503,
    // broadcast a 1012 Service-Restart close to every live WS, drain briefly.
    let shutdown_state = Arc::clone(&state);
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            wait_for_terminate().await;
            shutdown_state
                .shutting_down
                .store(true, std::sync::atomic::Ordering::Relaxed);
            shutdown_state.shutdown.notify_waiters();
            info!("SIGTERM: draining WS connections with 1012 (relay restarting)");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        })
        .await?;
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

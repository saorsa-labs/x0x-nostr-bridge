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
use x0x_nostr_bridge::ingest;
use x0x_nostr_bridge::proto;
use x0x_nostr_bridge::relay::{self, AppState};
use x0x_nostr_bridge::store::{EventStore, SqliteStore};
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

    let store: Arc<dyn EventStore> = Arc::new(SqliteStore::open(&db_path)?);
    let transport: Arc<dyn GossipTransport> = Arc::new(X0xTransport::connect(&api, &token).await?);

    // Subscribe the global topic plus every channel we've ever stored.
    transport.ensure_topic(proto::GLOBAL_TOPIC).await?;
    for ch in store.known_channels().await? {
        transport.ensure_topic(&proto::channel_topic(&ch)).await?;
    }

    let state = Arc::new(AppState {
        store: Arc::clone(&store),
        transport: Arc::clone(&transport),
        hub: relay::Hub::new(),
    });

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
    axum::serve(listener, app).await?;
    Ok(())
}

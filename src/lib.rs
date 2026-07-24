//! Library facade exposing the bridge modules. The binary (`src/main.rs`) and
//! the integration tests (`tests/*`) both link this library; `main.rs` wires
//! the modules together via `use x0x_nostr_bridge::…` rather than redeclaring
//! them, so the unit-test harness lives here exactly once.
//!
//! Ownership: this file is shared wiring; module behavior is owned per-file
//! (see each module's doc comment).
pub mod auth;
pub mod config;
pub mod engine_api;
pub mod filter_match;
pub mod history;
pub mod history_adapter;
pub mod http;
pub mod ingest;
pub mod kinds;
pub mod nip11;
pub mod proto;
pub mod rate_limit;
pub mod relay;
pub mod relay_identity;
pub mod seed;
pub mod settings;
pub mod store;
pub mod transport;

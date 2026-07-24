//! Library facade exposing the bridge modules. The binary (`src/main.rs`) and
//! the integration tests (`tests/*`) both link this library; `main.rs` wires
//! the modules together via `use x0x_nostr_bridge::…` rather than redeclaring
//! them, so the unit-test harness lives here exactly once.
//!
//! Ownership: this file is shared wiring; module behavior is owned per-file
//! (see each module's doc comment).

pub mod config;
pub mod ingest;
pub mod proto;
pub mod relay;
pub mod store;
pub mod transport;

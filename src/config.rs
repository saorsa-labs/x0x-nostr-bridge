//! Startup configuration resolution, factored out of `main.rs` so it is
//! unit-testable without touching process-global env vars.

use std::net::SocketAddr;

use crate::transport;

/// Resolve the daemon REST base URL + bearer token.
///
/// Order: `(X0X_API, X0X_TOKEN)` env → `transport::discover()`.
pub fn resolve_api() -> anyhow::Result<(String, String)> {
    resolve_api_from(
        std::env::var("X0X_API").ok(),
        std::env::var("X0X_TOKEN").ok(),
    )
}

/// Pure, env-free form of [`resolve_api`] for unit testing. A bare `host:port`
/// in `x0x_api` is normalised to an `http://` base URL, exactly as
/// [`transport::discover`] does for its data-dir file.
pub fn resolve_api_from(
    x0x_api: Option<String>,
    x0x_token: Option<String>,
) -> anyhow::Result<(String, String)> {
    match (x0x_api, x0x_token) {
        (Some(a), Some(t)) => {
            let api = a.trim();
            let token = t.trim();
            if api.is_empty() || token.is_empty() {
                return transport::discover();
            }
            // Normalise a bare `host:port` into an `http://` base URL, mirroring
            // `transport::discover()` (D1: X0X_API env was previously passed
            // through raw, so `127.0.0.1:9999` reached reqwest without a scheme).
            Ok((transport::normalize_base_url(api), token.to_string()))
        }
        _ => transport::discover(),
    }
}

/// Whether `addr` is bound to a loopback interface.
pub fn is_loopback(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
}

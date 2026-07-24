//! Bridge runtime settings (WP2/WP3). Owner: wp2-http.
//!
//! Env-driven, with defaults chosen so the M1a relay-mode gate passes
//! out of the box (dev-auth `X-Pubkey`, membership gate off, rate limiter off,
//! 256-connection cap). Nothing here is x0xd config — that stays in
//! `transport`/`config`.

use crate::filter_match::AccessPolicy;

/// Default global WS connection cap (issue #2).
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;
/// Default NIP-98 replay-cache TTL, seconds.
pub const DEFAULT_NIP98_TTL_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct Settings {
    /// D5: when false (default), the dev-auth `X-Pubkey` header is accepted on
    /// HTTP endpoints. When true, full NIP-98 is required.
    pub require_auth_token: bool,
    /// Membership gate (thread.md §3). Off by default so the gate — which
    /// creates channels dynamically — is not blocked; when on, non-member
    /// authors of closed channels are 403'd.
    pub require_membership: bool,
    /// Expected NIP-42 `relay` tag / NIP-98 `u` base — the client-facing base
    /// URL (e.g. `http://localhost:3000`). The WS variant is derived by
    /// swapping the scheme to `ws`.
    pub public_base_url: String,
    /// Global WS connection cap (issue #2).
    pub max_connections: usize,
    /// HTTP rate limit (per principal, per minute). `None` = limiter off
    /// (default); the 429 grammar is implemented regardless.
    pub rate_limit_per_min: Option<u32>,
    /// NIP-98 replay-cache TTL.
    pub nip98_ttl_secs: u64,
    /// Read access classes (finding 3 / dialect.md §1).
    pub access: AccessPolicy,
    /// Emit + store the demo seed at startup (WP4 slice).
    pub seed_demo: bool,
    /// WP3 (issue #3): validate the NIP-42 `relay` tag against [`Settings::relay_ws_url`].
    /// Default `false` so the WS-only spike tests (which sign a loopback relay
    /// tag) are unaffected; `from_env` turns it on for production.
    pub enforce_relay_tag: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            require_auth_token: false,
            require_membership: false,
            public_base_url: "http://localhost:3000".to_string(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            rate_limit_per_min: None,
            nip98_ttl_secs: DEFAULT_NIP98_TTL_SECS,
            access: AccessPolicy::default(),
            seed_demo: false,
            enforce_relay_tag: false,
        }
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

impl Settings {
    /// Resolve settings from the environment (see field docs for the keys).
    pub fn from_env() -> Self {
        let mut s = Settings::default();
        s.require_auth_token = env_bool("BUZZ_REQUIRE_AUTH_TOKEN", s.require_auth_token);
        s.require_membership = env_bool("BRIDGE_REQUIRE_MEMBERSHIP", s.require_membership);
        s.seed_demo = env_bool("BRIDGE_SEED_DEMO", s.seed_demo);
        // Enforce the NIP-42 relay tag by default in production.
        s.enforce_relay_tag = env_bool("BRIDGE_ENFORCE_RELAY_TAG", true);
        if let Ok(v) = std::env::var("BRIDGE_PUBLIC_URL") {
            if !v.trim().is_empty() {
                s.public_base_url = v.trim().trim_end_matches('/').to_string();
            }
        }
        if let Ok(v) = std::env::var("BRIDGE_MAX_CONNECTIONS") {
            if let Ok(n) = v.trim().parse::<usize>() {
                if n > 0 {
                    s.max_connections = n;
                }
            }
        }
        if let Ok(v) = std::env::var("BRIDGE_RATE_LIMIT_PER_MIN") {
            if let Ok(n) = v.trim().parse::<u32>() {
                s.rate_limit_per_min = if n == 0 { None } else { Some(n) };
            }
        }
        s
    }

    /// The WS URL the NIP-42 `relay` tag must match (public base with `ws`
    /// scheme), normalized without a trailing slash (dialect.md §4).
    pub fn relay_ws_url(&self) -> String {
        let base = self.public_base_url.trim_end_matches('/');
        if let Some(rest) = base.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = base.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            base.to_string()
        }
    }

    /// The NIP-98 `u` tag expected for `path` (dialect.md §0).
    pub fn nip98_expected_url(&self, path: &str) -> String {
        format!("{}{}", self.public_base_url.trim_end_matches('/'), path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_ws_url_swaps_scheme() {
        let mut s = Settings::default();
        s.public_base_url = "http://localhost:3000".into();
        assert_eq!(s.relay_ws_url(), "ws://localhost:3000");
        s.public_base_url = "https://relay.example".into();
        assert_eq!(s.relay_ws_url(), "wss://relay.example");
    }

    #[test]
    fn nip98_expected_url_joins_path() {
        let s = Settings::default();
        assert_eq!(s.nip98_expected_url("/events"), "http://localhost:3000/events");
        assert_eq!(s.nip98_expected_url("/query"), "http://localhost:3000/query");
    }
}

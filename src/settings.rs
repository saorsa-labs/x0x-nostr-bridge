//! Bridge runtime settings (WP2/WP3). Owner: wp2-http.
//!
//! Env-driven, with defaults chosen so the M1a relay-mode gate passes
//! out of the box (dev-auth `X-Pubkey`, membership gate off, rate limiter off,
//! 256-connection cap). Nothing here is x0xd config — that stays in
//! `transport`/`config`.

use crate::filter_match::AccessPolicy;
use std::path::PathBuf;

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
    /// Lowercase-hex SHA-256 of the normalized x0x daemon API base the bridge
    /// resolved at startup (empty when unset, e.g. tests). Published in the
    /// NIP-11 `/info` doc as `x0x_api_fingerprint` so a caller can verify the
    /// daemon binding without the bridge exposing the daemon's address.
    pub x0x_api_fingerprint: String,
    // ---- M1b media / invite / join-policy settings (contract §3) ----
    /// Media blob directory (BRIDGE_MEDIA_DIR). Default: sibling of BRIDGE_DB
    /// (computed in main.rs).
    pub media_dir: PathBuf,
    /// Media sidecar SQLite path (BRIDGE_MEDIA_DB). Default: sibling of BRIDGE_DB.
    pub media_db_path: PathBuf,
    /// Public base URL for media descriptor `url`/`thumb` (empty ⇒ public_base_url).
    pub media_public_base_url: String,
    /// Per-type upload byte caps (§3).
    pub media_max_image_bytes: u64,
    pub media_max_gif_bytes: u64,
    /// Absolute route body cap (the largest per-type cap).
    pub media_max_video_bytes: u64,
    pub media_max_file_bytes: u64,
    /// Blossom 24242 auth-event freshness windows (seconds).
    pub media_upload_auth_max_age_secs: u64,
    pub media_video_auth_max_age_secs: u64,
    pub media_get_auth_max_age_secs: u64,
    /// Require Blossom kind-24242 `get` auth (default false; fail-open).
    pub require_media_get_auth: bool,
    /// Bootstrap community admins (BRIDGE_COMMUNITY_ADMINS, comma-sep hex).
    pub community_admins: Vec<String>,
    /// Primary channel for invite-claim membership
    /// (BRIDGE_COMMUNITY_PRIMARY_CHANNEL; empty ⇒ seed::channel_id("general")).
    pub community_primary_channel: String,
    /// Default invite TTL when the client omits `ttl_secs`.
    pub invite_default_ttl_secs: u64,
    /// Bounded direct-message backfill on (re)connect
    /// (BRIDGE_DIRECT_BACKFILL). Default 64; clamped to 256 by the transport.
    pub direct_backfill: usize,
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
            x0x_api_fingerprint: String::new(),
            media_dir: PathBuf::new(),
            media_db_path: PathBuf::new(),
            media_public_base_url: String::new(),
            media_max_image_bytes: 50 * 1024 * 1024,
            media_max_gif_bytes: 10 * 1024 * 1024,
            media_max_video_bytes: 524_288_000,
            media_max_file_bytes: 104_857_600,
            media_upload_auth_max_age_secs: 600,
            media_video_auth_max_age_secs: 3600,
            media_get_auth_max_age_secs: 3600,
            require_media_get_auth: false,
            community_admins: Vec::new(),
            community_primary_channel: String::new(),
            invite_default_ttl_secs: 86_400,
            direct_backfill: 64,
        }
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
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
        // ---- M1b media / invite env overrides (contract §3) ----
        if let Ok(v) = std::env::var("BRIDGE_MEDIA_DIR") {
            if !v.trim().is_empty() {
                s.media_dir = PathBuf::from(v.trim());
            }
        }
        if let Ok(v) = std::env::var("BRIDGE_MEDIA_DB") {
            if !v.trim().is_empty() {
                s.media_db_path = PathBuf::from(v.trim());
            }
        }
        s.require_media_get_auth =
            env_bool("BUZZ_REQUIRE_MEDIA_GET_AUTH", s.require_media_get_auth);
        if let Ok(v) = std::env::var("BRIDGE_COMMUNITY_ADMINS") {
            s.community_admins = v
                .split(',')
                .map(|p| p.trim().to_ascii_lowercase())
                .filter(|p| !p.is_empty())
                .collect();
        }
        if let Ok(v) = std::env::var("BRIDGE_COMMUNITY_PRIMARY_CHANNEL") {
            if !v.trim().is_empty() {
                s.community_primary_channel = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("BRIDGE_DIRECT_BACKFILL") {
            if let Ok(n) = v.trim().parse::<usize>() {
                s.direct_backfill = n;
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
        let s = Settings {
            public_base_url: "http://localhost:3000".into(),
            ..Default::default()
        };
        assert_eq!(s.relay_ws_url(), "ws://localhost:3000");
        let s = Settings {
            public_base_url: "https://relay.example".into(),
            ..Default::default()
        };
        assert_eq!(s.relay_ws_url(), "wss://relay.example");
    }

    #[test]
    fn nip98_expected_url_joins_path() {
        let s = Settings::default();
        assert_eq!(
            s.nip98_expected_url("/events"),
            "http://localhost:3000/events"
        );
        assert_eq!(
            s.nip98_expected_url("/query"),
            "http://localhost:3000/query"
        );
    }
}

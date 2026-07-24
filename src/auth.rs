//! HTTP auth (D5) — the two doors of Buzz's bridge auth. Owner: wp2-http.
//!
//! - `require_auth_token=false` (default for the gate): accept the dev-auth
//!   `X-Pubkey: <hex>` header as the caller identity (dialect.md §0).
//! - `require_auth_token=true`: full NIP-98 — `Authorization: Nostr
//!   <base64(kind-27235 event JSON)>` with `u`/`method`/`payload` tags, a TTL
//!   replay cache, fail-closed.
//!
//! The membership gate (dialect.md §0 "runs after auth") lives in the HTTP
//! handlers, which have the engine + channel context; this module only proves
//! *who* the caller is.

use std::collections::HashMap;

use axum::http::HeaderMap;
use base64::Engine as _;
use nostr::{Event, JsonUtil};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::settings::Settings;

/// A caller whose identity has been established.
#[derive(Debug, Clone)]
pub struct Principal {
    pub pubkey_hex: String,
}

/// Auth failure — always HTTP 401, with an exact body message (dialect.md §0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    Missing,
    ReplayDetected,
    ReplayUnavailable,
}

impl AuthError {
    pub fn status(self) -> u16 {
        401
    }
    pub fn message(self) -> &'static str {
        match self {
            AuthError::Missing => "missing Nostr auth",
            AuthError::ReplayDetected => "NIP-98: replay detected",
            AuthError::ReplayUnavailable => "NIP-98: replay check unavailable",
        }
    }
}

/// TTL replay cache for NIP-98 event ids (community-scoped in Buzz; single
/// community here).
#[derive(Default)]
pub struct ReplayCache {
    seen: Mutex<HashMap<String, u64>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `id`; `Err(ReplayDetected)` if it was already recorded and not yet
    /// expired. Expired entries are pruned opportunistically.
    fn check_and_record(&self, id: &str, now: u64, ttl: u64) -> Result<(), AuthError> {
        let mut seen = self.seen.lock();
        seen.retain(|_, &mut exp| exp > now);
        if seen.contains_key(id) {
            return Err(AuthError::ReplayDetected);
        }
        seen.insert(id.to_string(), now + ttl);
        Ok(())
    }
}

/// Canonicalize + validate a 64-hex pubkey (lowercased). Design §3: ids are
/// lowercase 64-hex on every input.
pub fn canonical_pubkey(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_lowercase();
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(s)
    } else {
        None
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn tag_value<'a>(ev: &'a Event, key: &str) -> Option<&'a str> {
    ev.tags.iter().find_map(|t| {
        let s = t.as_slice();
        if s.first().map(String::as_str) == Some(key) {
            s.get(1).map(String::as_str)
        } else {
            None
        }
    })
}

/// Establish the caller identity for an HTTP request. `require_payload` is set
/// for writes (`POST /events`) so the NIP-98 `payload` tag (sha256 of body) is
/// enforced.
pub fn authenticate(
    settings: &Settings,
    replay: &ReplayCache,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
    require_payload: bool,
    now: u64,
) -> Result<Principal, AuthError> {
    // NIP-98 path (always honored when the header is present and well-formed).
    if let Some(h) = header_str(headers, "authorization") {
        let b64 = h.strip_prefix("Nostr ").ok_or(AuthError::Missing)?.trim();
        return verify_nip98(settings, replay, b64, method, path, body, require_payload, now);
    }

    // Dev-auth fallback: X-Pubkey, only when NIP-98 is not required.
    if !settings.require_auth_token {
        if let Some(pk) = header_str(headers, "x-pubkey").and_then(canonical_pubkey) {
            return Ok(Principal { pubkey_hex: pk });
        }
    }

    Err(AuthError::Missing)
}

#[allow(clippy::too_many_arguments)]
fn verify_nip98(
    settings: &Settings,
    replay: &ReplayCache,
    b64: &str,
    method: &str,
    path: &str,
    body: &[u8],
    require_payload: bool,
    now: u64,
) -> Result<Principal, AuthError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| AuthError::Missing)?;
    let json = std::str::from_utf8(&raw).map_err(|_| AuthError::Missing)?;
    let ev = Event::from_json(json).map_err(|_| AuthError::Missing)?;

    if ev.kind.as_u16() != crate::kinds::KIND_NIP98_AUTH {
        return Err(AuthError::Missing);
    }
    ev.verify().map_err(|_| AuthError::Missing)?;

    // Freshness window (±ttl).
    let created = ev.created_at.as_secs();
    let within = if created > now { created - now } else { now - created };
    if within > settings.nip98_ttl_secs {
        return Err(AuthError::Missing);
    }

    // u tag must equal the tenant-expected URL.
    let expected_u = settings.nip98_expected_url(path);
    if tag_value(&ev, "u") != Some(expected_u.as_str()) {
        return Err(AuthError::Missing);
    }
    // method tag must match.
    if tag_value(&ev, "method")
        .map(|m| m.eq_ignore_ascii_case(method))
        != Some(true)
    {
        return Err(AuthError::Missing);
    }
    // payload tag (sha256 body) for writes.
    if require_payload {
        let mut hasher = Sha256::new();
        hasher.update(body);
        let want = hex::encode(hasher.finalize());
        if tag_value(&ev, "payload") != Some(want.as_str()) {
            return Err(AuthError::Missing);
        }
    }

    // Replay protection (fail-closed).
    replay.check_and_record(&ev.id.to_hex(), now, settings.nip98_ttl_secs)?;

    Ok(Principal {
        pubkey_hex: ev.pubkey.to_hex(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind, Tag};

    fn hdrs(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn x_pubkey_accepted_in_dev_mode() {
        let s = Settings::default(); // require_auth_token=false
        let replay = ReplayCache::new();
        let me = "e5ebc6cdb579be112e336cc319b5989b4bb6af11786ea90dbe52b5f08d741b34";
        let h = hdrs(&[("x-pubkey", me)]);
        let p = authenticate(&s, &replay, &h, "POST", "/events", b"{}", false, 100).unwrap();
        assert_eq!(p.pubkey_hex, me);
    }

    #[test]
    fn missing_auth_is_401_message() {
        let s = Settings::default();
        let replay = ReplayCache::new();
        let h = hdrs(&[]);
        let e = authenticate(&s, &replay, &h, "POST", "/events", b"{}", false, 100).unwrap_err();
        assert_eq!(e, AuthError::Missing);
        assert_eq!(e.message(), "missing Nostr auth");
    }

    #[test]
    fn x_pubkey_rejected_when_token_required() {
        let mut s = Settings::default();
        s.require_auth_token = true;
        let replay = ReplayCache::new();
        let me = "e5ebc6cdb579be112e336cc319b5989b4bb6af11786ea90dbe52b5f08d741b34";
        let h = hdrs(&[("x-pubkey", me)]);
        let e = authenticate(&s, &replay, &h, "POST", "/query", b"[]", false, 100).unwrap_err();
        assert_eq!(e, AuthError::Missing);
    }

    fn nip98_header(keys: &Keys, url: &str, method: &str, created: u64) -> String {
        let ev = EventBuilder::new(Kind::from(27235u16), "")
            .tag(Tag::parse(["u", url]).unwrap())
            .tag(Tag::parse(["method", method]).unwrap())
            .custom_created_at(nostr::Timestamp::from(created))
            .sign_with_keys(keys)
            .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(ev.as_json());
        format!("Nostr {b64}")
    }

    #[test]
    fn nip98_accept_then_replay_reject() {
        let mut s = Settings::default();
        s.require_auth_token = true;
        let replay = ReplayCache::new();
        let keys = Keys::generate();
        let hdr = nip98_header(&keys, "http://localhost:3000/query", "POST", 100);
        let h = hdrs(&[("authorization", &hdr)]);
        // first use accepted
        let p = authenticate(&s, &replay, &h, "POST", "/query", b"[]", false, 100).unwrap();
        assert_eq!(p.pubkey_hex, keys.public_key().to_hex());
        // replay of the same event id rejected
        let e = authenticate(&s, &replay, &h, "POST", "/query", b"[]", false, 100).unwrap_err();
        assert_eq!(e, AuthError::ReplayDetected);
        assert_eq!(e.message(), "NIP-98: replay detected");
    }

    #[test]
    fn nip98_wrong_url_rejected() {
        let mut s = Settings::default();
        s.require_auth_token = true;
        let replay = ReplayCache::new();
        let keys = Keys::generate();
        // u tag points at /events but request is /query
        let hdr = nip98_header(&keys, "http://localhost:3000/events", "POST", 100);
        let h = hdrs(&[("authorization", &hdr)]);
        let e = authenticate(&s, &replay, &h, "POST", "/query", b"[]", false, 100).unwrap_err();
        assert_eq!(e, AuthError::Missing);
    }
}

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
use std::net::IpAddr;

use axum::http::HeaderMap;
use base64::Engine as _;
use nostr::{Event, JsonUtil};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::proto;
use crate::settings::Settings;

/// A portable, re-verifiable NIP-98 HTTP-auth proof a claimant forwards to the
/// authority over the x0xd direct-message bus: the verified kind-27235 event
/// JSON plus the exact request body it authenticates (base64, standard).
///
/// `Clone` + `serde` so it rides inside `invites::ClaimBusRequest` and the DM
/// envelope, and is re-verified byte-for-byte at the authority via
/// [`verify_portable_nip98_claim`]. It holds no secret — a NIP-98 event is
/// public by construction (it travels in the `Authorization` header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableNip98Proof {
    /// The exact kind-27235 event JSON the claimant verified locally. Stored
    /// verbatim (not re-serialized) so the authority re-parses the identical
    /// bytes that passed the claimant's `verify()`.
    pub event_json: String,
    /// Base64 (standard alphabet) of the exact claim request body the event's
    /// `payload` tag commits to. Bounded by [`proto::MAX_FRAME_BYTES`] before
    /// decode at the authority.
    pub body_b64: String,
}

/// A caller whose identity has been established.
#[derive(Debug, Clone)]
pub struct Principal {
    pub pubkey_hex: String,
    /// Portable NIP-98 proof established at the claimant bridge and re-verified
    /// at the authority. `None` on the dev `X-Pubkey` path (no event to carry);
    /// `Some` on the verified NIP-98 path.
    pub portable_nip98: Option<PortableNip98Proof>,
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
    pub fn check_and_record(&self, id: &str, now: u64, ttl: u64) -> Result<(), AuthError> {
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
#[allow(clippy::too_many_arguments)]
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
        return verify_nip98(
            settings,
            replay,
            b64,
            method,
            path,
            body,
            require_payload,
            now,
        );
    }

    // Dev-auth fallback: X-Pubkey, only when NIP-98 is not required.
    if !settings.require_auth_token {
        if let Some(pk) = header_str(headers, "x-pubkey").and_then(canonical_pubkey) {
            return Ok(Principal {
                pubkey_hex: pk,
                portable_nip98: None,
            });
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
    let within = created.abs_diff(now);
    if within > settings.nip98_ttl_secs {
        return Err(AuthError::Missing);
    }

    // u tag must equal the tenant-expected URL.
    let expected_u = settings.nip98_expected_url(path);
    if tag_value(&ev, "u") != Some(expected_u.as_str()) {
        return Err(AuthError::Missing);
    }
    // method tag must match.
    if tag_value(&ev, "method").map(|m| m.eq_ignore_ascii_case(method)) != Some(true) {
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
        portable_nip98: Some(PortableNip98Proof {
            event_json: json.to_string(),
            body_b64: base64::engine::general_purpose::STANDARD.encode(body),
        }),
    })
}

// ---------------------------------------------------------------------------
// Portable NIP-98 proof — authority-side re-verification
// ---------------------------------------------------------------------------

/// Total, panic-free re-verification of a [`PortableNip98Proof`] at the
/// authority (the remote claim path). On success returns the decoded request
/// body the proof commits to; on **any** failure returns `None`. Never echoes
/// proof contents — no logging, no error payload (the proof may carry a code
/// or receipt, so it must never appear in a diagnostic).
///
/// Checks, in order:
/// 1. `event_json` parses to a kind-27235 event whose id + Schnorr signature
///    verify.
/// 2. The event pubkey **exactly** equals `expected_pubkey` (canonicalized to
///    lowercase 64-hex) — the code-bound authority `aid`'s pubkey.
/// 3. Freshness: `created_at` within `±ttl_secs` of `now`.
/// 4. `method` tag is `POST` (case-insensitive, matching the claimant check).
/// 5. `u` tag URL parses, uses a loopback host (`127.0.0.1` / `::1` /
///    `localhost`), and has the exact path `/api/invites/claim`.
/// 6. `body_b64` length is bounded by [`proto::MAX_FRAME_BYTES`] before decode.
/// 7. The decoded body's SHA-256 equals the `payload` tag.
/// 8. Remote replay: `replay.check_and_record(ev.id, now, ttl_secs)` (the id is
///    recorded only for a fully-valid proof).
pub fn verify_portable_nip98_claim(
    proof: &PortableNip98Proof,
    expected_pubkey: &str,
    replay: &ReplayCache,
    now: u64,
    ttl_secs: u64,
) -> Option<Vec<u8>> {
    // 1. Parse + verify. `Event::from_json` rejects malformed structure; verify
    //    checks the id hash + Schnorr signature. Both are panic-free on the
    //    validated object `from_json` returns.
    let ev = Event::from_json(&proof.event_json).ok()?;
    if ev.kind.as_u16() != crate::kinds::KIND_NIP98_AUTH {
        return None;
    }
    ev.verify().ok()?;

    // 2. Exact pubkey match (canonical lowercase 64-hex).
    let expected = canonical_pubkey(expected_pubkey)?;
    if ev.pubkey.to_hex() != expected {
        return None;
    }

    // 3. Freshness window (±ttl).
    let created = ev.created_at.as_secs();
    if created.abs_diff(now) > ttl_secs {
        return None;
    }

    // 4. POST method (case-insensitive — matches the claimant-side check so a
    //    proof the claimant accepted is never spuriously rejected here).
    if tag_value(&ev, "method").map(|m| m.eq_ignore_ascii_case("POST")) != Some(true) {
        return None;
    }

    // 5. Loopback host + exact claim path.
    let u = tag_value(&ev, "u")?;
    if !claim_url_is_loopback(u) {
        return None;
    }

    // 6. Bound the base64 *string* before allocating the decode buffer.
    if proof.body_b64.len() > proto::MAX_FRAME_BYTES {
        return None;
    }
    let body = base64::engine::general_purpose::STANDARD
        .decode(&proof.body_b64)
        .ok()?;

    // 7. payload tag == sha256(body).
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let want = hex::encode(hasher.finalize());
    if tag_value(&ev, "payload") != Some(want.as_str()) {
        return None;
    }

    // 8. Remote replay (check-and-record; recorded only on full validity).
    replay
        .check_and_record(&ev.id.to_hex(), now, ttl_secs)
        .ok()?;

    Some(body)
}

/// `true` iff `u` is an `http(s)://<loopback-host>[:port]/api/invites/claim`
/// URL. Rejects anything without a scheme, a non-loopback host, a missing or
/// non-exact path, or trailing path segments. No `url` crate dependency (not a
/// direct bridge dep); mirrors `direct_transport::host_of` /
/// `direct_transport::is_loopback_host` so the claimant and authority agree on
/// "loopback" by construction.
fn claim_url_is_loopback(u: &str) -> bool {
    let rest = u
        .strip_prefix("http://")
        .or_else(|| u.strip_prefix("https://"));
    let rest = match rest {
        Some(r) => r,
        None => return false,
    };
    // Split the authority from the path on the first '/'.
    let (authority, path_tail) = match rest.split_once('/') {
        Some((auth, tail)) => (auth, tail),
        None => return false, // no path ⇒ not the claim route
    };
    // Path component only (drop ?query / #fragment), then require exact match.
    let path = format!("/{}", path_tail.split(['?', '#']).next().unwrap_or(""));
    if path != "/api/invites/claim" {
        return false;
    }
    is_loopback_host(&host_of_authority(authority))
}

/// Host portion of a URL authority (`host[:port]`, no scheme). Handles bracketed
/// IPv6 literals (`[::1]:port`). Mirrors `direct_transport::host_of`.
fn host_of_authority(authority: &str) -> String {
    if let Some(stripped) = authority.strip_prefix('[') {
        return stripped.split(']').next().unwrap_or("").to_string();
    }
    match authority.rsplit_once(':') {
        Some((host, _port)) => host.to_string(),
        None => authority.to_string(),
    }
}

/// `true` for `localhost` or any loopback IP. Mirrors
/// `direct_transport::is_loopback_host`.
fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    if h == "localhost" {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
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
        let s = Settings {
            require_auth_token: true,
            ..Default::default()
        };
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
        let s = Settings {
            require_auth_token: true,
            ..Default::default()
        };
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
        let s = Settings {
            require_auth_token: true,
            ..Default::default()
        };
        let replay = ReplayCache::new();
        let keys = Keys::generate();
        // u tag points at /events but request is /query
        let hdr = nip98_header(&keys, "http://localhost:3000/events", "POST", 100);
        let h = hdrs(&[("authorization", &hdr)]);
        let e = authenticate(&s, &replay, &h, "POST", "/query", b"[]", false, 100).unwrap_err();
        assert_eq!(e, AuthError::Missing);
    }
}

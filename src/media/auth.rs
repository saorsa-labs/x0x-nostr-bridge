//! Blossom (BUD-01) kind:24242 media-authorization verifier — the upload/get
//! auth door for the bridge's media routes. Owner: wp-media-auth (WP-MA, leaf).
//!
//! Desktop callers send `Authorization: Nostr <URL_SAFE_NO_PAD(JSON event)>` —
//! note the URL-safe no-pad alphabet, distinct from the STANDARD base64 of
//! NIP-98 kind:27235 (the existing `crate::auth` path, which this module does
//! NOT reuse). The event is a BUD-11 kind:24242 auth event carrying `t=<verb>`,
//! `x=<sha256>` (upload), an `expiration`, and an optional `server=<host[:port]>`.
//!
//! This module is a **pure verifier**: it decodes and validates the event and
//! returns the authenticated principal (pubkey + event id). It never reads the
//! request body and never buffers bytes — the body sha256 is **passed in by the
//! caller** (`x_sha256`), so a streaming/temp-file upload pipeline computes it
//! without a 500 MiB in-memory copy. Replay enforcement is the caller's job,
//! performed against the shared `crate::auth::ReplayCache` using the returned
//! `event_id` (24242 carries `expiration`; replay window = `max_age_secs`).
//!
//! Failure is fail-closed: every malformed input (bad base64/JSON/signature,
//! wrong kind/verb, missing/empty content, expired/skewed/stale timestamps,
//! server-tag mismatch, hash mismatch) is rejected. The 401-facing body is a
//! **constant** sanitized string so no auth detail leaks; the detailed enum is
//! unit-variant only and never carries the token or event JSON.
//!
//! Derived from `crates/buzz-media/src/auth.rs` (BUD-01/BUD-11); dual-licensed
//! MIT OR Apache-2.0 per the crate manifest.

use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use nostr::{Event, JsonUtil};

/// Kind:24242 Blossom media-auth event.
const KIND_BLOSSOM_AUTH: u16 = 24242;

/// Clock-skew tolerance (seconds) for `created_at`: a token minted up to this
/// far in the future is accepted (the 5s Blossom convention).
const CREATED_AT_SKEW_SECS: u64 = 5;

/// The Blossom verbs the bridge media routes accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlossomVerb {
    Upload,
    Get,
}

impl BlossomVerb {
    fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Get => "get",
        }
    }
}

/// An authenticated Blossom caller.
#[derive(Debug, Clone)]
pub struct BlossomPrincipal {
    /// Verified event author (64 lowercase hex).
    pub pubkey_hex: String,
    /// Verified event id (64 lowercase hex) — the caller's replay-cache key.
    pub event_id: String,
}

/// Blossom auth failure. Unit-variant only: it never carries the token or event
/// JSON (both are attacker-controlled and must not be logged or echoed).
///
/// Every variant except [`Self::HashMismatch`] and [`Self::Sha256HeaderMismatch`]
/// is HTTP **401**; those two are **400** (the declared blob hash does not match
/// the body — a tamper/length-extension guard, not an identity failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlossomAuthError {
    /// No `Authorization: Nostr …` header or wrong auth scheme.
    Missing,
    /// base64-URL-safe-no-pad, UTF-8, or Nostr-JSON decode failed.
    MalformedToken,
    /// Schnorr signature (or event id) verification failed.
    BadSignature,
    /// Event kind is not 24242.
    WrongKind,
    /// `content` is empty/whitespace (BUD-11 requires a human-readable string).
    EmptyContent,
    /// No `t` tag present.
    MissingVerb,
    /// A `t` tag is present but none matches the expected verb.
    WrongVerb,
    /// No `expiration` tag present.
    MissingExpiration,
    /// `expiration` tag present but not a valid unix timestamp.
    MalformedExpiration,
    /// `expiration` is in the past (or exactly now).
    Expired,
    /// `created_at` is too far in the future (beyond skew tolerance).
    CreatedInFuture,
    /// `created_at` is older than the verb's max-age window.
    TooOld,
    /// A `server` tag is present but none matches this relay's authority.
    ServerMismatch,
    /// (GET) Neither an `x` tag nor a `server` tag authorizes this blob.
    InsufficientScope,
    /// (UPLOAD) No `x` tag equals the computed body sha256. → 400.
    HashMismatch,
    /// (UPLOAD) `X-SHA-256` header present but disagrees with the body sha256. → 400.
    Sha256HeaderMismatch,
}

impl BlossomAuthError {
    /// HTTP status: 401 for identity/scope failures, 400 for the hash guards.
    pub fn status(self) -> u16 {
        match self {
            Self::HashMismatch | Self::Sha256HeaderMismatch => 400,
            _ => 401,
        }
    }

    /// Sanitized, constant client-facing message. 401s are always the same
    /// opaque string (no auth-detail leak); the 400 hash guards report a short
    /// constant reason. Never echoes the token or event.
    pub fn message(self) -> &'static str {
        match self {
            Self::HashMismatch => "hash mismatch",
            Self::Sha256HeaderMismatch => "x-sha-256 mismatch",
            _ => "unauthorized",
        }
    }
}

/// Verify a kind:24242 Blossom auth event for `verb` and return the principal.
///
/// Performs the common (non-scope) checks:
/// 1. `Authorization: Nostr <URL_SAFE_NO_PAD json>` present and decodable.
/// 2. Schnorr signature (and event id) valid.
/// 3. `kind == 24242`.
/// 4. `content` non-empty.
/// 5. at least one `t` tag equals `verb`.
/// 6. an `expiration` tag exists, parses, and is strictly in the future.
/// 7. `created_at` within `[now - max_age_secs, now + 5s]`.
/// 8. if any `server` tag is present, at least one matches `relay_authority`.
///
/// `relay_authority` is the `host[:port]` of the bridge public base URL. `now` is
/// injected for deterministic testing. Verb-specific scope (`x`/`server`) is
/// added by [`verify_upload`] / [`verify_get`].
pub fn verify_blossom(
    headers: &HeaderMap,
    verb: BlossomVerb,
    max_age_secs: u64,
    relay_authority: &str,
    now: u64,
) -> Result<BlossomPrincipal, BlossomAuthError> {
    verify_common(headers, verb, max_age_secs, relay_authority, now).map(|ev| principal_of(&ev))
}

/// Verify a kind:24242 **upload** auth event for the blob whose sha256 is
/// `x_sha256` (computed by the caller over the request body — streaming /
/// temp-file safe; this verifier never reads the body).
///
/// After the common checks, the body hash is bound: at least one `x` tag must
/// equal `x_sha256` (else **400** `HashMismatch` — a tamper/length-extension
/// guard). If an `X-SHA-256` header is present it is cross-checked against
/// `x_sha256` (else **400** `Sha256HeaderMismatch`); the `x` tag remains
/// authoritative.
pub fn verify_upload(
    headers: &HeaderMap,
    x_sha256: &str,
    max_age_secs: u64,
    relay_authority: &str,
    now: u64,
) -> Result<BlossomPrincipal, BlossomAuthError> {
    let ev = verify_common(
        headers,
        BlossomVerb::Upload,
        max_age_secs,
        relay_authority,
        now,
    )?;

    // BUD-11 §6: at least one `x` tag matches the body sha256.
    let x_matches = ev.tags.iter().any(|tag| {
        let s = tag.as_slice();
        s.first().map(String::as_str) == Some("x")
            && s.get(1)
                .map(|v| v.eq_ignore_ascii_case(x_sha256))
                .unwrap_or(false)
    });
    if !x_matches {
        return Err(BlossomAuthError::HashMismatch);
    }

    // Optional X-SHA-256 header cross-check (the `x` tag drives).
    if let Some(hdr) = header_str(headers, "x-sha-256") {
        if !hdr.trim().eq_ignore_ascii_case(x_sha256) {
            return Err(BlossomAuthError::Sha256HeaderMismatch);
        }
    }

    Ok(principal_of(&ev))
}

/// Verify a kind:24242 **get** auth event for the blob whose sha256 is `sha256`
/// (the `{sha256}` segment of the requested `/media/{sha256}.{ext}` path).
///
/// BUD-01 accepts either blob-scoped authorization (an `x` tag equals `sha256`)
/// or server-scoped authorization (a `server` tag equals `relay_authority`).
/// Lacking both ⇒ **401** `InsufficientScope`. Callers must still apply relay
/// membership after this verifier returns.
pub fn verify_get(
    headers: &HeaderMap,
    sha256: &str,
    max_age_secs: u64,
    relay_authority: &str,
    now: u64,
) -> Result<BlossomPrincipal, BlossomAuthError> {
    let ev = verify_common(
        headers,
        BlossomVerb::Get,
        max_age_secs,
        relay_authority,
        now,
    )?;

    let want_server = normalize_authority(relay_authority);
    let mut x_matches = false;
    let mut server_matches = false;
    for tag in ev.tags.iter() {
        let s = tag.as_slice();
        match s.first().map(String::as_str).unwrap_or("") {
            "x" => {
                if s.get(1)
                    .map(|v| v.eq_ignore_ascii_case(sha256))
                    .unwrap_or(false)
                {
                    x_matches = true;
                }
            }
            "server" => {
                if let Some(v) = s.get(1).map(String::as_str) {
                    if normalize_authority(v) == want_server {
                        server_matches = true;
                    }
                }
            }
            _ => {}
        }
    }

    if !x_matches && !server_matches {
        return Err(BlossomAuthError::InsufficientScope);
    }

    Ok(principal_of(&ev))
}

/// Decode + authenticate a kind:24242 event and run the common (non-scope)
/// authorization checks. Returns the verified event for the caller's scope pass.
fn verify_common(
    headers: &HeaderMap,
    verb: BlossomVerb,
    max_age_secs: u64,
    relay_authority: &str,
    now: u64,
) -> Result<Event, BlossomAuthError> {
    let token = extract_nostr_token(headers).ok_or(BlossomAuthError::Missing)?;

    // URL_SAFE_NO_PAD decode → UTF-8 → Nostr event (NOT standard base64).
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| BlossomAuthError::MalformedToken)?;
    let json = std::str::from_utf8(&raw).map_err(|_| BlossomAuthError::MalformedToken)?;
    let ev = Event::from_json(json).map_err(|_| BlossomAuthError::MalformedToken)?;

    // Signature + event-id integrity (verify() recomputes the id).
    ev.verify().map_err(|_| BlossomAuthError::BadSignature)?;

    if ev.kind.as_u16() != KIND_BLOSSOM_AUTH {
        return Err(BlossomAuthError::WrongKind);
    }
    if ev.content.trim().is_empty() {
        return Err(BlossomAuthError::EmptyContent);
    }

    // Single pass over tags: t / expiration / server-authority.
    let our_authority = normalize_authority(relay_authority);
    let mut has_verb = false;
    let mut any_other_verb = false;
    let mut expiration_raw: Option<&str> = None;
    let mut has_server = false;
    let mut server_match = false;

    for tag in ev.tags.iter() {
        let s = tag.as_slice();
        match s.first().map(String::as_str).unwrap_or("") {
            "t" => {
                if let Some(v) = s.get(1).map(String::as_str) {
                    if v == verb.as_str() {
                        has_verb = true;
                    } else {
                        any_other_verb = true;
                    }
                }
            }
            "expiration" => {
                if expiration_raw.is_none() {
                    expiration_raw = s.get(1).map(String::as_str);
                }
            }
            "server" => {
                if let Some(v) = s.get(1).map(String::as_str) {
                    has_server = true;
                    if normalize_authority(v) == our_authority {
                        server_match = true;
                    }
                }
            }
            _ => {}
        }
    }

    if !has_verb {
        return Err(if any_other_verb {
            BlossomAuthError::WrongVerb
        } else {
            BlossomAuthError::MissingVerb
        });
    }

    let exp = match expiration_raw {
        Some(v) => v
            .parse::<u64>()
            .map_err(|_| BlossomAuthError::MalformedExpiration)?,
        None => return Err(BlossomAuthError::MissingExpiration),
    };
    if exp <= now {
        return Err(BlossomAuthError::Expired);
    }

    let created = ev.created_at.as_secs();
    if created > now.saturating_add(CREATED_AT_SKEW_SECS) {
        return Err(BlossomAuthError::CreatedInFuture);
    }
    // saturating_add keeps this panic-free even for pathological timestamps.
    if now > created.saturating_add(max_age_secs) {
        return Err(BlossomAuthError::TooOld);
    }

    if has_server && !server_match {
        return Err(BlossomAuthError::ServerMismatch);
    }

    Ok(ev)
}

fn principal_of(ev: &Event) -> BlossomPrincipal {
    BlossomPrincipal {
        pubkey_hex: ev.pubkey.to_hex(),
        event_id: ev.id.to_hex(),
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Extract the `<token>` from an `Authorization: Nostr <token>` header (scheme
/// matched case-insensitively per RFC 7235; surrounding whitespace trimmed).
fn extract_nostr_token(headers: &HeaderMap) -> Option<&str> {
    let h = header_str(headers, "authorization")?;
    let trimmed = h.trim();
    let (scheme, token) = trimmed.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("nostr") {
        Some(token.trim())
    } else {
        None
    }
}

/// Normalize a `server` tag value / relay authority for comparison: strip an
/// optional `scheme://`, drop any path/query/fragment, ASCII-lowercase, and
/// trim trailing dots. The port is kept verbatim (host[:port] as configured).
fn normalize_authority(value: &str) -> String {
    let rest = match value.split_once("://") {
        Some((_scheme, rest)) => rest,
        None => value,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let mut s = authority.to_ascii_lowercase();
    while s.ends_with('.') {
        s.pop();
    }
    s
}

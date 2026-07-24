//! Buzz HTTP dialect (WP2) — `POST /events`, `POST /query`, `POST /count`,
//! `GET /info`. Owner: wp2-http. Wire contract: `docs/recon/dialect.md`.
//!
//! All four endpoints share the `{"error": msg}` envelope on 4xx/5xx and the
//! auth model in [`crate::auth`]. `/query` is the critical read path: it does
//! the two-pass parse (typed `Filter` for matching + raw `Value` for Buzz
//! extension fields), routes search vs window vs thread vs plain, and — for a
//! `top_level` request — assembles rows → aux closure → relay-signed 39005
//! overlays → exactly one relay-signed 39006 bounds event.

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use nostr::{Event, Filter, JsonUtil};
use serde_json::{json, Value};

use crate::auth;
use crate::engine_api::{event_to_value, Cursor, IngestOutcome, ThreadQuery, WindowQuery};
use crate::filter_match;
use crate::kinds;
use crate::proto;
use crate::relay::{publish_to_topics, AppState};
use crate::relay_identity::now_secs;

// ---- response helpers ------------------------------------------------------

/// `{"error": msg}` with `status` (dialect.md §0 `api_error`).
pub fn api_error(status: u16, msg: &str) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (code, Json(json!({ "error": msg }))).into_response()
}

/// The `/events` 200 envelope `{event_id, accepted, message}` (dialect.md §2).
fn events_ok(event_id: &str, accepted: bool, message: &str) -> Response {
    (
        StatusCode::OK,
        Json(json!({ "event_id": event_id, "accepted": accepted, "message": message })),
    )
        .into_response()
}

/// Bare heterogeneous JSON array response (dialect.md §1 — no envelope object).
fn json_array(values: Vec<Value>) -> Response {
    (StatusCode::OK, Json(Value::Array(values))).into_response()
}

/// 429 grammar helper (dialect.md §5): `rate-limited: ... retry in <N>s`.
pub fn rate_limited_body(retry_secs: u64) -> String {
    format!("rate-limited: quota exceeded; retry in {retry_secs}s")
}

// ---- extension-field extractors (raw Value) --------------------------------

fn ext_flag(raw: &Value, key: &str) -> bool {
    raw.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn filter_kinds(raw: &Value) -> Vec<u16> {
    raw.get("kinds")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|k| k.as_u64().map(|n| n as u16))
                .collect()
        })
        .unwrap_or_default()
}

fn h_channels(raw: &Value) -> Vec<String> {
    raw.get("#h")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_lowercase))
                .collect()
        })
        .unwrap_or_default()
}

fn single_e_tag(raw: &Value) -> Option<String> {
    raw.get("#e")
        .and_then(Value::as_array)
        .and_then(|a| if a.len() == 1 { a[0].as_str() } else { None })
        .map(|s| s.to_lowercase())
}

/// `thread_cursor`/`threadCursor` (+ `_id`) composite keyset (dialect.md §1).
fn thread_cursor(raw: &Value) -> Option<Cursor> {
    let ts = raw
        .get("thread_cursor")
        .or_else(|| raw.get("threadCursor"))
        .and_then(Value::as_i64)?;
    let id = raw
        .get("thread_cursor_id")
        .or_else(|| raw.get("threadCursorId"))
        .and_then(Value::as_str)?;
    Some(Cursor {
        created_at: ts.max(0) as u64,
        id: id.to_lowercase(),
    })
}

// ---- POST /events ----------------------------------------------------------

pub async fn post_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = now_secs();

    // Auth (NIP-98 replay included). Writes enforce the payload tag in NIP-98
    // mode; the dev-auth X-Pubkey path ignores it.
    let principal = match auth::authenticate(
        &state.settings,
        &state.replay,
        &headers,
        "POST",
        "/events",
        &body,
        true,
        now,
    ) {
        Ok(p) => p,
        Err(e) => return api_error(e.status(), e.message()),
    };

    // Admission (per-principal rate limit; default-off).
    if let Some(quota) = state.settings.rate_limit_per_min {
        if let Err(retry) = state.limiter.check(&principal.pubkey_hex, quota, now) {
            return api_error(429, &rate_limited_body(retry));
        }
    }

    // Parse a single signed event.
    let ev = match Event::from_json(&body) {
        Ok(ev) => ev,
        Err(e) => return api_error(400, &format!("invalid event JSON: {e}")),
    };

    // Signature/id integrity.
    if proto::verify_event(&ev).is_err() {
        return api_error(400, "invalid: bad id or signature");
    }

    // Membership gate (after auth; open channels skip — thread.md §3).
    if state.settings.require_membership {
        for ch in proto::event_channels(&ev) {
            let closed = matches!(
                state.engine.visibility(&ch).await,
                Ok(crate::engine_api::Visibility::Closed)
            );
            if closed {
                let member = state
                    .engine
                    .is_member(&ch, &ev.pubkey.to_hex())
                    .await
                    .unwrap_or(false);
                if !member {
                    return api_error(403, "restricted: not a channel member");
                }
            }
        }
    }

    // Relay-authored kind guard (before the engine call — dialect.md §7).
    if ev.kind.as_u16() == proto::AUTH_KIND {
        return api_error(400, "invalid: auth kind is not publishable");
    }
    if kinds::is_relay_authored(ev.kind.as_u16()) {
        return api_error(400, "invalid: relay-authored kind may not be submitted");
    }

    // Ingest through the local door.
    match state.engine.ingest_local(&ev).await {
        Ok(IngestOutcome::Stored { event_id, emits }) => {
            // Post-commit: publish to gossip + fan out live to WS subscribers,
            // then fire-and-forget the recomputed 39005 per emitted root.
            publish_to_topics(&state.transport, &ev).await;
            state.hub.dispatch(&ev);
            fan_out_emits(&state, emits);
            events_ok(&event_id, true, "")
        }
        Ok(IngestOutcome::Duplicate { event_id }) => events_ok(&event_id, true, "duplicate:"),
        Ok(IngestOutcome::SoftReject { event_id, message }) => {
            events_ok(&event_id, false, &message)
        }
        Ok(IngestOutcome::Rejected { reason }) => api_error(400, &reason),
        Ok(IngestOutcome::Parked { event_id }) => events_ok(&event_id, false, "parked:"),
        Ok(IngestOutcome::Quarantined { reason }) => {
            // Local door never quarantines; surface defensively as a soft reject.
            tracing::warn!(%reason, "unexpected quarantine on local door");
            api_error(400, &reason)
        }
        Err(e) => {
            tracing::warn!(error = %e, "ingest_local failed");
            api_error(500, "internal error")
        }
    }
}

/// Post-commit live 39005 fan-out (WP3 / design §4): for each root the ingest
/// reported as mutated, recompute its summary and dispatch the relay-signed
/// 39005 (covers both the reply and delete paths). Fire-and-forget; a dropped
/// emit is corrected by the next reply or by a window's `include_summaries`.
pub(crate) fn fan_out_emits(state: &Arc<AppState>, emits: Vec<crate::engine_api::Emit>) {
    for emit in emits {
        let Some(channel) = emit.channel_id else {
            continue;
        };
        let root = emit.root_id;
        let state = Arc::clone(state);
        tokio::spawn(async move {
            if let Ok(Some(summary)) = state.engine.thread_summary(&channel, &root).await {
                if let Ok(overlay) = state.identity.thread_summary_event(&summary, now_secs()) {
                    publish_to_topics(&state.transport, &overlay).await;
                    state.hub.dispatch(&overlay);
                }
            }
        });
    }
}

// ---- POST /query -----------------------------------------------------------

pub async fn post_query(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = now_secs();
    let principal = match auth::authenticate(
        &state.settings,
        &state.replay,
        &headers,
        "POST",
        "/query",
        &body,
        false,
        now,
    ) {
        Ok(p) => p,
        Err(e) => return api_error(e.status(), e.message()),
    };
    if let Some(quota) = state.settings.rate_limit_per_min {
        if let Err(retry) = state.limiter.check(&principal.pubkey_hex, quota, now) {
            return api_error(429, &rate_limited_body(retry));
        }
    }

    // Body = JSON array of filters (two-pass: raw Values kept for extensions).
    let raws: Vec<Value> = match serde_json::from_slice::<Vec<Value>>(&body) {
        Ok(v) => v,
        Err(e) => return api_error(400, &format!("invalid query JSON: {e}")),
    };

    // Search-filter routing: mixing search + non-search is unsupported.
    let searches: Vec<bool> = raws.iter().map(|r| r.get("search").is_some()).collect();
    if searches.iter().any(|&b| b) && !searches.iter().all(|&b| b) {
        return api_error(400, "mixed search and non-search filters not supported");
    }

    // Read access classes (p-gated / engram / author-only → 403).
    for raw in &raws {
        if let Err(d) = filter_match::authorize(&state.settings.access, raw, &principal.pubkey_hex)
        {
            return api_error(403, d.message());
        }
    }

    // Window read-model (dialect.md §1 — the critical path).
    if let Some(raw) = raws.iter().find(|r| ext_flag(r, "top_level")) {
        return window_response(&state, raw, &principal.pubkey_hex).await;
    }

    // Thread-reply keyset page.
    if let Some(raw) = raws.iter().find(|r| thread_cursor(r).is_some()) {
        return thread_response(&state, raw).await;
    }

    // Plain / search / ids / directory path — bare event array, no overlays.
    let mut out: Vec<Value> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for raw in &raws {
        // Presence-only filters are answered empty, never hitting storage.
        if filter_match::is_presence_only(&state.settings.access, raw) {
            continue;
        }
        let filter = match Filter::from_json(raw.to_string()) {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!(error = %e, "skipping unparseable filter");
                continue;
            }
        };
        let mut events = match state.engine.query(&filter).await {
            Ok(ev) => ev,
            Err(e) => {
                tracing::warn!(error = %e, "engine query failed");
                return api_error(500, "internal error");
            }
        };
        // Result-gated defense: even an id/kind probe must not surface a
        // result-gated event unless its #p matches the reader.
        events.retain(|ev| {
            !filter_match::result_gated_hidden(&state.settings.access, ev, &principal.pubkey_hex)
        });
        // NIP-50 FTS never returns p-gated kinds (Buzz nulls their search vector).
        if raw.get("search").is_some() {
            events.retain(|ev| {
                !filter_match::p_gated_excluded_from_search(
                    &state.settings.access,
                    ev.kind.as_u16(),
                )
            });
        }
        // Offset paging (`page` > 1) + limit truncation for the plain path.
        if let Some(page) = raw.get("page").and_then(Value::as_u64) {
            let limit = raw.get("limit").and_then(Value::as_u64).unwrap_or(0) as usize;
            let offset = page.saturating_sub(1) as usize * limit;
            if offset < events.len() {
                events.drain(0..offset);
            } else {
                events.clear();
            }
        }
        if let Some(limit) = raw.get("limit").and_then(Value::as_u64) {
            events.truncate(limit as usize);
        }
        for ev in events {
            if seen.insert(ev.id.to_hex()) {
                out.push(event_to_value(&ev));
            }
        }
    }
    json_array(out)
}

/// Assemble the `top_level` window response: rows → aux → 39005 → one 39006.
async fn window_response(state: &Arc<AppState>, raw: &Value, caller: &str) -> Response {
    // Exactly one #h channel.
    let channels = h_channels(raw);
    if channels.len() != 1 {
        return api_error(400, "top_level requires exactly one #h channel");
    }
    let channel = channels[0].clone();

    // Keyset cursor: until + before_id both-or-neither.
    let until = raw.get("until").and_then(Value::as_u64);
    let before_id = raw.get("before_id").and_then(Value::as_str);
    if let Some(b) = before_id {
        if !is_hex64(b) {
            return api_error(400, "top_level: before_id must be a 64-hex event id");
        }
    }
    let cursor = match (until, before_id) {
        (Some(ts), Some(id)) => Some(Cursor {
            created_at: ts,
            id: id.to_lowercase(),
        }),
        (None, None) => None,
        _ => {
            return api_error(
                400,
                "top_level cursor requires both until and before_id, or neither",
            )
        }
    };

    let limit = raw
        .get("limit")
        .and_then(Value::as_u64)
        .map(|n| n.clamp(1, 200) as usize)
        .unwrap_or(50);

    // Inaccessible channel → empty result, 200 (access-scope skip, not error).
    if state.settings.require_membership {
        let closed = matches!(
            state.engine.visibility(&channel).await,
            Ok(crate::engine_api::Visibility::Closed)
        );
        if closed
            && !state
                .engine
                .is_member(&channel, caller)
                .await
                .unwrap_or(false)
        {
            return json_array(Vec::new());
        }
    }

    let q = WindowQuery {
        channel_id: channel.clone(),
        kinds: filter_kinds(raw),
        limit,
        cursor,
        include_aux: ext_flag(raw, "include_aux"),
        include_summaries: ext_flag(raw, "include_summaries"),
        caller_pubkey: Some(caller.to_string()),
    };

    let window = match state.engine.channel_window(&q).await {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(error = %e, "channel_window failed");
            return api_error(500, "internal error");
        }
    };

    let now = now_secs();
    let mut out: Vec<Value> = Vec::new();
    // 1. rows (keyset order).
    for ev in &window.rows {
        out.push(event_to_value(ev));
    }
    // 2. aux closure (real stored events; never charged to the row budget).
    if q.include_aux {
        for ev in &window.aux {
            out.push(event_to_value(ev));
        }
    }
    // 3. relay-signed 39005 thread-summary overlays.
    if q.include_summaries {
        for s in &window.summaries {
            match state.identity.thread_summary_event(s, now) {
                Ok(overlay) => out.push(event_to_value(&overlay)),
                Err(e) => tracing::warn!(error = %e, "39005 synthesis failed"),
            }
        }
    }
    // 4. exactly one relay-signed 39006 window-bounds overlay.
    match state
        .identity
        .window_bounds_event(&channel, &window.bounds, now)
    {
        Ok(bounds) => out.push(event_to_value(&bounds)),
        Err(e) => {
            tracing::warn!(error = %e, "39006 synthesis failed");
            return api_error(500, "internal error");
        }
    }
    json_array(out)
}

/// Thread-reply keyset page — bare event array, no overlays (dialect.md §1).
async fn thread_response(state: &Arc<AppState>, raw: &Value) -> Response {
    let Some(root) = single_e_tag(raw) else {
        return api_error(400, "thread query requires exactly one #e root");
    };
    let channel = h_channels(raw).into_iter().next().unwrap_or_default();
    let limit = raw
        .get("limit")
        .and_then(Value::as_u64)
        .map(|n| n.clamp(1, 500) as usize)
        .unwrap_or(200);
    let q = ThreadQuery {
        channel_id: channel,
        root_id: root,
        limit,
        cursor: thread_cursor(raw),
        depth_limit: raw
            .get("depth_limit")
            .and_then(Value::as_u64)
            .map(|n| n as u32),
        caller_pubkey: None,
    };
    match state.engine.thread_replies(&q).await {
        Ok(events) => json_array(events.iter().map(event_to_value).collect()),
        Err(e) => {
            tracing::warn!(error = %e, "thread_replies failed");
            api_error(500, "internal error")
        }
    }
}

// ---- POST /count -----------------------------------------------------------

pub async fn post_count(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = now_secs();
    let principal = match auth::authenticate(
        &state.settings,
        &state.replay,
        &headers,
        "POST",
        "/count",
        &body,
        false,
        now,
    ) {
        Ok(p) => p,
        Err(e) => return api_error(e.status(), e.message()),
    };
    let raws: Vec<Value> = match serde_json::from_slice::<Vec<Value>>(&body) {
        Ok(v) => v,
        Err(e) => return api_error(400, &format!("invalid count JSON: {e}")),
    };
    for raw in &raws {
        if let Err(d) = filter_match::authorize(&state.settings.access, raw, &principal.pubkey_hex)
        {
            return api_error(403, d.message());
        }
    }
    let mut total = 0usize;
    for raw in &raws {
        let filter = match Filter::from_json(raw.to_string()) {
            Ok(f) => f,
            Err(_) => continue,
        };
        total += state.engine.count(&filter).await.unwrap_or(0);
    }
    (StatusCode::OK, Json(json!({ "count": total }))).into_response()
}

// ---- GET /info -------------------------------------------------------------

pub async fn get_info(State(state): State<Arc<AppState>>) -> Response {
    let doc = crate::nip11::document(&state.settings, &state.identity);
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/nostr+json")],
        doc.to_string(),
    )
        .into_response()
}

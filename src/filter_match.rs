//! Shared Nostr filter matching + read access classes. Owner: wp2-http.
//!
//! Finding 3 (design §4): tag matching (`#h`/`#p`/`#e`, authors, kinds, ids)
//! and the read access classes (p-gated / engram / author-only) live in ONE
//! module used by BOTH the HTTP `/query` historical path and the WS
//! live-dispatch path, so historical and live matching cannot diverge
//! (`integration.spec`'s mention refetch depends on stored-query and live-match
//! agreeing exactly).
//!
//! - [`matches`] is the typed hot-path matcher used by WS `Hub::dispatch` and by
//!   the in-memory engine backfill.
//! - [`authorize`] enforces the p-gated / engram / author-only 403 classes over
//!   the RAW filter value (the same value the two-pass `/query` parse keeps),
//!   so access checks see the exact JSON the client sent.
//! - [`is_presence_only`] detects presence-only filters so `/query` can answer
//!   `[]` without touching storage (finding 11).

use std::collections::BTreeSet;

use nostr::filter::MatchEventOptions;
use nostr::{Event, Filter};
use serde_json::Value;

/// Typed match used by both live dispatch and historical backfill. Wraps
/// `nostr::Filter::match_event` so there is exactly one matching implementation.
pub fn matches(filter: &Filter, ev: &Event) -> bool {
    filter.match_event(ev, MatchEventOptions::default())
}

/// Kind sets that gate read access. Populated from config; defaults are the
/// values the recon pack surfaced with certainty (gift-wrap `1059`). Classes
/// whose exact Buzz kind numbers were not in the recon pack default to empty —
/// the enforcement mechanism is present, the numbers are pluggable.
#[derive(Debug, Clone)]
pub struct AccessPolicy {
    /// Gift wraps, member notifications, observer frames — a query MUST carry
    /// `#p`=self.
    pub p_gated_kinds: BTreeSet<u16>,
    /// Agent-engram kinds — require `authors=[self]` or `#p=[self]`.
    pub engram_kinds: BTreeSet<u16>,
    /// Author-only kinds — require `authors=[self]`.
    pub author_only_kinds: BTreeSet<u16>,
    /// Result-gated kinds — even a kindless `ids:[…]` lookup must NOT return
    /// these unless the returned event's `#p` matches the reader (closes the
    /// id-probe leak). Enforced as a post-query result filter, not a pre-check.
    pub result_gated_kinds: BTreeSet<u16>,
    /// Presence kinds — presence-only filters short-circuit to `[]`.
    pub presence_kinds: BTreeSet<u16>,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        // Real buzz_core::kind values @ anchor 710ed9ff (team-lead, verified
        // from source). Presence kinds remain empty (Buzz synthesizes presence
        // from Redis; the M1a gate never queries it). Config-pluggable.
        Self {
            p_gated_kinds: [24200, 44100, 44101, 1059, 30622, 44200].into_iter().collect(),
            engram_kinds: [30174].into_iter().collect(),
            author_only_kinds: [30300, 30350].into_iter().collect(),
            result_gated_kinds: [30622, 44200].into_iter().collect(),
            presence_kinds: BTreeSet::new(),
        }
    }
}

/// A read denied by an access class → HTTP 403 with [`ReadDenied::message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadDenied {
    PGated,
    Engram,
    AuthorOnly,
}

impl ReadDenied {
    /// Exact 403 body message (dialect.md §1 read-path authorization).
    pub fn message(self) -> &'static str {
        match self {
            ReadDenied::PGated => {
                "restricted: p-gated kinds require #p tag matching your pubkey"
            }
            ReadDenied::Engram => {
                "restricted: agent-engram kinds require authors or #p matching your pubkey"
            }
            ReadDenied::AuthorOnly => {
                "restricted: author-only kinds require authors matching your pubkey"
            }
        }
    }
}

/// Kinds listed by a raw filter value (`"kinds":[...]`).
fn filter_kinds(raw: &Value) -> Vec<u16> {
    raw.get("kinds")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|k| k.as_u64().map(|n| n as u16)).collect())
        .unwrap_or_default()
}

/// Whether a raw filter's `authors` set is exactly (and only) the caller.
fn authors_is_self(raw: &Value, caller_hex: &str) -> bool {
    match raw.get("authors").and_then(Value::as_array) {
        Some(arr) if !arr.is_empty() => {
            arr.iter().all(|a| a.as_str() == Some(caller_hex))
        }
        _ => false,
    }
}

/// Whether a raw filter's `#p` tag set contains the caller.
fn p_tag_has_self(raw: &Value, caller_hex: &str) -> bool {
    raw.get("#p")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().any(|p| p.as_str() == Some(caller_hex)))
        .unwrap_or(false)
}

/// Enforce the read access classes over a raw filter (dialect.md §1). Returns
/// `Err(ReadDenied)` → the caller should answer 403 with the message.
pub fn authorize(policy: &AccessPolicy, raw: &Value, caller_hex: &str) -> Result<(), ReadDenied> {
    let kinds = filter_kinds(raw);
    let hits = |set: &BTreeSet<u16>| kinds.iter().any(|k| set.contains(k));

    if hits(&policy.p_gated_kinds) && !p_tag_has_self(raw, caller_hex) {
        return Err(ReadDenied::PGated);
    }
    if hits(&policy.engram_kinds)
        && !(authors_is_self(raw, caller_hex) || p_tag_has_self(raw, caller_hex))
    {
        return Err(ReadDenied::Engram);
    }
    if hits(&policy.author_only_kinds) && !authors_is_self(raw, caller_hex) {
        return Err(ReadDenied::AuthorOnly);
    }
    Ok(())
}

/// A presence-only filter: it carries kinds and every one of them is a presence
/// kind (dialect.md §1 / finding 11). With an empty presence set this is always
/// false — the safe default (never spuriously empties a real query).
pub fn is_presence_only(policy: &AccessPolicy, raw: &Value) -> bool {
    if policy.presence_kinds.is_empty() {
        return false;
    }
    let kinds = filter_kinds(raw);
    !kinds.is_empty() && kinds.iter().all(|k| policy.presence_kinds.contains(k))
}

/// A stored event's `#p` tag set contains `caller_hex`.
fn event_p_tags_contain(ev: &Event, caller_hex: &str) -> bool {
    ev.tags.iter().any(|t| {
        let s = t.as_slice();
        s.first().map(String::as_str) == Some("p") && s.get(1).map(String::as_str) == Some(caller_hex)
    })
}

/// Whether a returned event must be HIDDEN from `caller` on a plain-query
/// result: result-gated kind whose `#p` does not match the reader (id-probe
/// leak defense — even `ids:[…]` must not surface these).
pub fn result_gated_hidden(policy: &AccessPolicy, ev: &Event, caller_hex: &str) -> bool {
    policy.result_gated_kinds.contains(&ev.kind.as_u16())
        && !event_p_tags_contain(ev, caller_hex)
}

/// Whether a p-gated kind should be excluded from NIP-50 FTS results (Buzz nulls
/// their search vector so they never match a search).
pub fn p_gated_excluded_from_search(policy: &AccessPolicy, kind: u16) -> bool {
    policy.p_gated_kinds.contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn p_gated_requires_self_p_tag() {
        let policy = AccessPolicy::default();
        let me = "e5ebc6cdb579be112e336cc319b5989b4bb6af11786ea90dbe52b5f08d741b34";
        // gift wrap without #p → denied
        let f = json!({ "kinds": [1059] });
        assert_eq!(authorize(&policy, &f, me), Err(ReadDenied::PGated));
        // gift wrap with #p=self → allowed
        let f = json!({ "kinds": [1059], "#p": [me] });
        assert!(authorize(&policy, &f, me).is_ok());
        // gift wrap with #p=other → denied
        let f = json!({ "kinds": [1059], "#p": ["deadbeef"] });
        assert_eq!(authorize(&policy, &f, me), Err(ReadDenied::PGated));
    }

    #[test]
    fn ordinary_filter_is_unrestricted() {
        let policy = AccessPolicy::default();
        let f = json!({ "kinds": [9], "#h": ["general"] });
        assert!(authorize(&policy, &f, "abc").is_ok());
    }

    #[test]
    fn presence_only_default_is_false() {
        // Empty presence set: never short-circuits (safe default).
        let policy = AccessPolicy::default();
        let f = json!({ "kinds": [30078] });
        assert!(!is_presence_only(&policy, &f));
    }

    #[test]
    fn presence_only_detected_when_configured() {
        let mut policy = AccessPolicy::default();
        policy.presence_kinds.insert(30078);
        policy.presence_kinds.insert(30079);
        assert!(is_presence_only(&policy, &json!({ "kinds": [30078] })));
        assert!(is_presence_only(&policy, &json!({ "kinds": [30078, 30079] })));
        // mixed with a non-presence kind → not presence-only
        assert!(!is_presence_only(&policy, &json!({ "kinds": [30078, 9] })));
        // no kinds → not presence-only
        assert!(!is_presence_only(&policy, &json!({ "#h": ["general"] })));
    }

    #[test]
    fn p_gated_message_is_exact() {
        assert_eq!(
            ReadDenied::PGated.message(),
            "restricted: p-gated kinds require #p tag matching your pubkey"
        );
    }
}

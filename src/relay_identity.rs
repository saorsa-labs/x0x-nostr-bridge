//! Relay identity: a persisted secp256k1 keypair (Nostr wire requirement, D4).
//! Owner: wp2-http.
//!
//! It supplies the NIP-11 `self` value and signs every relay-authored event —
//! the 39005 thread-summary and 39006 window-bounds overlays and the kind-13534
//! membership list. Per the Stage-2 identity rules this is a loopback-dialect
//! artifact; it authenticates nothing in x0x terms.

use std::path::Path;

use nostr::{Event, EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};

use crate::engine_api::{ThreadSummary, WindowBounds};
use crate::kinds;

/// The relay's signing identity.
pub struct RelayIdentity {
    keys: Keys,
}

impl RelayIdentity {
    /// Load the keypair from `path` (hex secret key), generating and persisting a
    /// fresh one if the file is absent. The file is written `0600` on Unix.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let hex = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("reading relay key {}: {e}", path.display()))?;
            let keys = Keys::parse(hex.trim())
                .map_err(|e| anyhow::anyhow!("parsing relay key {}: {e}", path.display()))?;
            return Ok(Self { keys });
        }
        let keys = Keys::generate();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| anyhow::anyhow!("creating {}: {e}", parent.display()))?;
            }
        }
        let secret_hex = keys.secret_key().to_secret_hex();
        std::fs::write(path, &secret_hex)
            .map_err(|e| anyhow::anyhow!("writing relay key {}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
        Ok(Self { keys })
    }

    /// Construct from an in-memory keypair (tests / ephemeral wiring).
    pub fn from_keys(keys: Keys) -> Self {
        Self { keys }
    }

    /// A fresh ephemeral identity (tests / defaults that never persist).
    pub fn ephemeral() -> Self {
        Self {
            keys: Keys::generate(),
        }
    }

    /// The relay's stable signing pubkey, hex — the NIP-11 `self` value.
    pub fn public_key_hex(&self) -> String {
        self.keys.public_key().to_hex()
    }

    fn sign(&self, kind: u16, content: String, tags: Vec<Tag>, now: u64) -> anyhow::Result<Event> {
        let ev = EventBuilder::new(Kind::from(kind), content)
            .tags(tags)
            .custom_created_at(Timestamp::from(now))
            .sign_with_keys(&self.keys)
            .map_err(|e| anyhow::anyhow!("relay-signing kind {kind}: {e}"))?;
        Ok(ev)
    }

    /// Synthesize a relay-signed kind-39005 thread-summary overlay
    /// (thread.md §2). `content` = `{reply_count, descendant_count,
    /// last_reply_at, participants}`; tags `["e",root],["d",root],["h",channel]`.
    pub fn thread_summary_event(&self, s: &ThreadSummary, now: u64) -> anyhow::Result<Event> {
        let content = serde_json::json!({
            "reply_count": s.reply_count,
            "descendant_count": s.descendant_count,
            "last_reply_at": s.last_reply_at,
            "participants": s.participants,
        })
        .to_string();
        let tags = vec![
            Tag::parse(["e", s.root_id.as_str()])?,
            Tag::parse(["d", s.root_id.as_str()])?,
            Tag::parse(["h", s.channel_id.as_str()])?,
        ];
        self.sign(kinds::KIND_THREAD_SUMMARY, content, tags, now)
    }

    /// Synthesize the single relay-signed kind-39006 window-bounds overlay
    /// (dialect.md §1). `content` = `{has_more, next_cursor:{created_at,id}|null}`;
    /// `d` tag = `"{channel}:{ts}:{id}"` or `"{channel}:head"`.
    pub fn window_bounds_event(
        &self,
        channel_id: &str,
        bounds: &WindowBounds,
        now: u64,
    ) -> anyhow::Result<Event> {
        let next_cursor = match &bounds.next_cursor {
            Some(c) => serde_json::json!({ "created_at": c.created_at, "id": c.id }),
            None => serde_json::Value::Null,
        };
        let content = serde_json::json!({
            "has_more": bounds.has_more,
            "next_cursor": next_cursor,
        })
        .to_string();
        let d_tag = match &bounds.next_cursor {
            Some(c) => format!("{channel_id}:{}:{}", c.created_at, c.id),
            None => format!("{channel_id}:head"),
        };
        let tags = vec![Tag::parse(["d", d_tag.as_str()])?, Tag::parse(["h", channel_id])?];
        self.sign(kinds::KIND_WINDOW_BOUNDS, content, tags, now)
    }

    /// Synthesize a relay-signed kind-39000 channel-metadata event (seed / WP4).
    /// Tags include `["name", <name>]` so `assertRelaySeeded` matches.
    pub fn channel_metadata_event(
        &self,
        channel_id: &str,
        name: &str,
        now: u64,
    ) -> anyhow::Result<Event> {
        let content = serde_json::json!({ "name": name }).to_string();
        let tags = vec![
            Tag::parse(["d", channel_id])?,
            Tag::parse(["name", name])?,
            Tag::parse(["h", channel_id])?,
        ];
        self.sign(kinds::KIND_CHANNEL_METADATA, content, tags, now)
    }

    /// Synthesize the relay-signed kind-13534 membership list (dialect.md §3).
    /// A single replaceable event; members carried as `["p", <hex>]` tags.
    pub fn membership_list_event(
        &self,
        channel_id: &str,
        members: &[String],
        now: u64,
    ) -> anyhow::Result<Event> {
        let mut tags = vec![Tag::parse(["h", channel_id])?, Tag::parse(["d", channel_id])?];
        for m in members {
            tags.push(Tag::parse(["p", m.as_str()])?);
        }
        self.sign(kinds::KIND_MEMBERSHIP_LIST, String::new(), tags, now)
    }
}

/// Current wall-clock in unix seconds (overlay `created_at`).
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_api::Cursor;

    #[test]
    fn thread_summary_shape_and_signature() {
        let id = RelayIdentity::ephemeral();
        let s = ThreadSummary {
            root_id: "a".repeat(64),
            channel_id: "general".into(),
            reply_count: 2,
            descendant_count: 3,
            last_reply_at: Some(1_700_000_000),
            participants: vec!["b".repeat(64), "c".repeat(64)],
        };
        let ev = id.thread_summary_event(&s, 1_700_000_100).unwrap();
        assert_eq!(ev.kind.as_u16(), kinds::KIND_THREAD_SUMMARY);
        assert!(ev.verify().is_ok(), "39005 must be relay-signed");
        assert_eq!(ev.pubkey.to_hex(), id.public_key_hex());
        let content: serde_json::Value = serde_json::from_str(&ev.content).unwrap();
        assert_eq!(content["reply_count"], 2);
        assert_eq!(content["descendant_count"], 3);
        assert_eq!(content["last_reply_at"], 1_700_000_000u64);
        assert_eq!(content["participants"].as_array().unwrap().len(), 2);
        // tags e/d/h present.
        let has = |k: &str, v: &str| {
            ev.tags.iter().any(|t| {
                let s = t.as_slice();
                s.first().map(String::as_str) == Some(k) && s.get(1).map(String::as_str) == Some(v)
            })
        };
        assert!(has("e", &s.root_id));
        assert!(has("d", &s.root_id));
        assert!(has("h", "general"));
    }

    #[test]
    fn window_bounds_head_and_cursor_d_tag() {
        let id = RelayIdentity::ephemeral();
        // head (no next cursor)
        let head = id
            .window_bounds_event("general", &WindowBounds { has_more: false, next_cursor: None }, 1)
            .unwrap();
        assert_eq!(head.kind.as_u16(), kinds::KIND_WINDOW_BOUNDS);
        let content: serde_json::Value = serde_json::from_str(&head.content).unwrap();
        assert_eq!(content["has_more"], false);
        assert!(content["next_cursor"].is_null());
        let d = head
            .tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some("d"))
            .and_then(|t| t.as_slice().get(1).cloned())
            .unwrap();
        assert_eq!(d, "general:head");

        // with cursor
        let c = Cursor { created_at: 1234, id: "f".repeat(64) };
        let more = id
            .window_bounds_event(
                "general",
                &WindowBounds { has_more: true, next_cursor: Some(c.clone()) },
                1,
            )
            .unwrap();
        let content: serde_json::Value = serde_json::from_str(&more.content).unwrap();
        assert_eq!(content["has_more"], true);
        assert_eq!(content["next_cursor"]["created_at"], 1234u64);
        assert_eq!(content["next_cursor"]["id"], c.id);
        let d = more
            .tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some("d"))
            .and_then(|t| t.as_slice().get(1).cloned())
            .unwrap();
        assert_eq!(d, format!("general:1234:{}", c.id));
    }
}

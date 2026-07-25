//! Relay identity: a persisted secp256k1 keypair (Nostr wire requirement, D4).
//! Owner: wp2-http.
//!
//! It supplies the NIP-11 `self` value and signs every relay-authored event —
//! the 39005 thread-summary and 39006 window-bounds overlays and the kind-13534
//! membership list. Per the Stage-2 identity rules this is a loopback-dialect
//! artifact; it authenticates nothing in x0x terms.

use std::path::Path;

use nostr::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};

use crate::engine_api::{Cursor, ThreadSummary, WindowBounds};
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
    /// (dialect.md §1).
    ///
    /// The two halves answer different questions and must not be confused:
    ///
    /// - `d` is the response's **correlation key**. It echoes `request_cursor`
    ///   — the cursor the client *sent* — so the client can prove the response
    ///   answers the request it made. `expectedBoundsKey`
    ///   (`channelWindowResponse.ts:74-82`) rebuilds it from its own request and
    ///   **hard-fails** the whole page on a mismatch (`:116-120`).
    /// - `content` (`{has_more, next_cursor}`) is the **next page's address**,
    ///   and is the client's pagination source.
    ///
    /// Keying `d` off `next_cursor` instead makes the two agree only for a head
    /// request that has no second page — i.e. every channel small enough to fit
    /// in one window — so a channel over the row limit renders empty and never
    /// paginates, silently. Buzz's own reference relay for mock mode keys on the
    /// request cursor (`e2eBridge.ts:4440-4451`).
    ///
    /// The channel id and event id are lower-cased because the client lower-cases
    /// both before comparing.
    pub fn window_bounds_event(
        &self,
        channel_id: &str,
        request_cursor: Option<&Cursor>,
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
        let channel_key = channel_id.to_lowercase();
        let d_tag = match request_cursor {
            Some(c) => format!("{channel_key}:{}:{}", c.created_at, c.id.to_lowercase()),
            None => format!("{channel_key}:head"),
        };
        let tags = vec![
            Tag::parse(["d", d_tag.as_str()])?,
            Tag::parse(["h", channel_id])?,
        ];
        self.sign(kinds::KIND_WINDOW_BOUNDS, content, tags, now)
    }

    /// Sign a relay-authored NIP-29 group-state replaceable (39000/39001/39002)
    /// on behalf of the command executor ([`crate::nip29`]), which owns the tag
    /// contract for each kind and therefore supplies the tags itself.
    pub fn group_state_event(
        &self,
        kind: u16,
        content: String,
        tags: Vec<Tag>,
        now: u64,
    ) -> anyhow::Result<Event> {
        self.sign(kind, content, tags, now)
    }

    /// Synthesize the relay-signed kind-13534 membership list (dialect.md §3).
    /// A single replaceable event; members carried as `["p", <hex>]` tags.
    pub fn membership_list_event(
        &self,
        channel_id: &str,
        members: &[String],
        now: u64,
    ) -> anyhow::Result<Event> {
        let mut tags = vec![
            Tag::parse(["h", channel_id])?,
            Tag::parse(["d", channel_id])?,
        ];
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

    fn d_tag(ev: &Event) -> String {
        ev.tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some("d"))
            .and_then(|t| t.as_slice().get(1).cloned())
            .expect("39006 carries a d tag")
    }

    /// `d` echoes the **request** cursor. This test previously asserted the
    /// opposite — that `d` was built from `next_cursor` — which is how the
    /// defect survived: the client rebuilds the key from its own request
    /// (`expectedBoundsKey`, `channelWindowResponse.ts:74-82`) and throws the
    /// whole page away on a mismatch.
    #[test]
    fn window_bounds_d_tag_echoes_the_request_cursor() {
        let id = RelayIdentity::ephemeral();
        let next = Cursor {
            created_at: 1234,
            id: "f".repeat(64),
        };

        // Head request. `d` is `:head` regardless of whether a next page exists.
        for bounds in [
            WindowBounds {
                has_more: false,
                next_cursor: None,
            },
            WindowBounds {
                has_more: true,
                next_cursor: Some(next.clone()),
            },
        ] {
            let ev = id.window_bounds_event("general", None, &bounds, 1).unwrap();
            assert_eq!(ev.kind.as_u16(), kinds::KIND_WINDOW_BOUNDS);
            assert_eq!(d_tag(&ev), "general:head");
        }

        // Cursor request. `d` echoes the cursor sent, never the one returned.
        let sent = Cursor {
            created_at: 999,
            id: "a".repeat(64),
        };
        let ev = id
            .window_bounds_event(
                "general",
                Some(&sent),
                &WindowBounds {
                    has_more: true,
                    next_cursor: Some(next.clone()),
                },
                1,
            )
            .unwrap();
        assert_eq!(d_tag(&ev), format!("general:999:{}", sent.id));
        assert!(
            !d_tag(&ev).contains(&next.id),
            "the next page's address belongs in content, never in the key"
        );
    }

    /// The exact combination the old keying got wrong and no test covered: a
    /// head request on a channel that has a second page. `d` must still be
    /// `:head` while `content.next_cursor` is non-null — the client needs both
    /// at once to accept the page *and* know to paginate.
    #[test]
    fn first_page_of_a_multi_page_channel_keys_head_and_still_advertises_more() {
        let id = RelayIdentity::ephemeral();
        let next = Cursor {
            created_at: 1784971226,
            id: "e".repeat(64),
        };
        let ev = id
            .window_bounds_event(
                "general",
                None,
                &WindowBounds {
                    has_more: true,
                    next_cursor: Some(next.clone()),
                },
                1,
            )
            .unwrap();

        assert_eq!(d_tag(&ev), "general:head");
        let content: serde_json::Value = serde_json::from_str(&ev.content).unwrap();
        assert_eq!(content["has_more"], true);
        assert_eq!(content["next_cursor"]["created_at"], 1784971226u64);
        assert_eq!(content["next_cursor"]["id"], next.id);
    }

    /// The client lower-cases both halves before comparing
    /// (`${channelId.toLowerCase()}:${cursor.eventId.toLowerCase()}`), so a
    /// mixed-case channel id or event id must not produce a key that misses.
    #[test]
    fn window_bounds_key_is_lower_cased_like_the_client_does() {
        let id = RelayIdentity::ephemeral();
        let sent = Cursor {
            created_at: 7,
            id: "AB".repeat(32),
        };
        let ev = id
            .window_bounds_event(
                "General-UUID",
                Some(&sent),
                &WindowBounds {
                    has_more: false,
                    next_cursor: None,
                },
                1,
            )
            .unwrap();
        assert_eq!(d_tag(&ev), format!("general-uuid:7:{}", "ab".repeat(32)));
    }
}

//! NIP-29 group-command execution — the write half of the Buzz dialect.
//! Owner: wp-nip29.
//!
//! Buzz's relay-mode client publishes NIP-29 moderation kinds and then reads
//! back the *replaceable* group state the relay is expected to emit as a side
//! effect. A kind-9007 "create channel" is only ever observable through the
//! kind-39000 that follows it: `e2eBridge.ts::handleCreateChannel` publishes
//! 9007 and immediately queries `{kinds:[39000], "#d":[channelId], limit:1}`,
//! throwing `Channel "<name>" not found after creation` when that comes back
//! empty. Storing the command and materializing nothing means the channel never
//! exists, which is the second defect in the M1a gate report.
//!
//! ## Derived tag contract
//!
//! The shapes below are read off the client's *readers*, not off the NIP-29
//! text — where the two disagree the client wins, because the client is the
//! thing we have to satisfy.
//!
//! kind-39000 (channel metadata), keyed by `["d", channelId]`:
//!
//! | tag                       | client reader                                    |
//! |---------------------------|--------------------------------------------------|
//! | `["d", id]`               | list mapper `getTag("d")` → `RawChannel.id`       |
//! | `["name", s]`             | `getTag("name")`                                  |
//! | `["about", s]`            | `getTag("about")` → `description`                 |
//! | `["t", s]`                | `getTag("t")` → `channel_type` (default `stream`) |
//! | `["visibility", s]`       | `handleUpdateChannel` `getTag("visibility")`      |
//! | `["private", "true"]`     | list mapper / details `tags.some(t[0]=="private")` |
//! | `["topic", s]`            | `getTag("topic")`                                 |
//! | `["purpose", s]`          | `getTag("purpose")`                               |
//! | `["ttl", secs]`           | `getTag("ttl")` → `Number(...)`                   |
//! | `["archived", "true"]`    | `tags.some(t[0]=="archived" && t[1]=="true")`     |
//!
//! Visibility is carried **twice** on purpose: `handleUpdateChannel` reads the
//! `visibility` tag's value while the list mapper and `handleGetChannelDetails`
//! test for the presence of a `private` tag. Emitting only one of the two makes
//! one of those three call sites wrong.
//!
//! kind-39002 (members), keyed by `["d", channelId]`, entries `["p", pk, role]`
//! — `handleGetChannelMembers` reads the role as `t[3] ?? t[2] ?? "member"`, and
//! `handleListChannels` resolves *its own* membership with `{kinds:[39002],
//! "#p":[mypubkey]}`, so the `p` tags are also the client's `is_member` source.
//!
//! kind-39001 (admins) is not read by the client; it is the durable home for
//! the "who may moderate this channel" answer that `is_authorized` needs.
//!
//! ## Why the executor re-reads state instead of accumulating it
//!
//! The materialized events *are* the state — there is no separate channel
//! table. Each command reads the current 39000/39001/39002 back out of the
//! engine, applies its mutation, and re-signs the whole replaceable. That keeps
//! the store the single source of truth across restarts and across both ingest
//! doors.

use nostr::{Event, Filter, Kind, Tag};

use crate::engine_api::Visibility;
use crate::kinds;
use crate::relay::AppState;
use crate::relay_identity::now_secs;

/// Execute a NIP-29 group command and materialize the relay-authored group
/// state it implies.
///
/// Returns the events that were signed and stored, for the caller to publish to
/// gossip and fan out to live WS subscribers. `Err(reason)` is a client-visible
/// rejection in the relay's `"<class>: <detail>"` convention — the command must
/// NOT be stored when this returns `Err`, otherwise a rejected moderation
/// attempt would still replicate to peers.
pub async fn execute(state: &AppState, ev: &Event) -> Result<Vec<Event>, String> {
    let author = ev.pubkey.to_hex();
    let channel_id =
        first_tag(ev, "h").ok_or_else(|| "invalid: group command requires an h tag".to_string())?;
    if channel_id.is_empty() {
        return Err("invalid: group command h tag is empty".to_string());
    }

    let meta_ev = latest_addressable(state, kinds::KIND_CHANNEL_METADATA, &channel_id).await?;
    let admins_ev = latest_addressable(state, kinds::KIND_GROUP_ADMINS, &channel_id).await?;
    let members_ev = latest_addressable(state, kinds::KIND_GROUP_MEMBERS, &channel_id).await?;
    let mut members = MemberSet::from_event(members_ev.as_ref());

    match ev.kind.as_u16() {
        kinds::KIND_GROUP_CREATE => {
            // Re-creating an existing channel is a replace, not a duplicate, so
            // it is gated exactly like any other mutation of that channel.
            if meta_ev.is_some()
                && !is_authorized(state, &channel_id, &author, admins_ev.as_ref()).await
            {
                return Err("restricted: not a group admin".to_string());
            }
            let name = first_tag(ev, "name").unwrap_or_default();
            if name.is_empty() {
                // The client always sends one; a nameless channel renders as an
                // empty row in the sidebar and is indistinguishable from a bug.
                return Err("invalid: create requires a non-empty name tag".to_string());
            }
            let meta = ChannelMeta {
                id: channel_id.clone(),
                name,
                about: non_empty(first_tag(ev, "about")),
                // The command spells it `channel_type`; the client reads it
                // back off the `t` tag.
                channel_type: non_empty(first_tag(ev, "channel_type"))
                    .unwrap_or_else(|| "stream".to_string()),
                private: first_tag(ev, "visibility").as_deref() == Some("private"),
                topic: None,
                purpose: None,
                ttl: non_empty(first_tag(ev, "ttl")),
                archived: false,
                deleted: false,
            };
            members.upsert(&author, "owner");

            let mut out = Vec::with_capacity(3);
            out.push(emit_meta(state, &meta, meta_ev.as_ref()).await?);
            out.push(
                emit_p_list(
                    state,
                    kinds::KIND_GROUP_ADMINS,
                    &channel_id,
                    &[(author.clone(), "admin".to_string())],
                    admins_ev.as_ref(),
                )
                .await?,
            );
            out.push(emit_members(state, &channel_id, &members, members_ev.as_ref()).await?);
            seed_member(state, &channel_id, &author).await;
            Ok(out)
        }

        kinds::KIND_GROUP_EDIT_METADATA => {
            let prev = meta_ev
                .as_ref()
                .ok_or_else(|| "invalid: unknown group".to_string())?;
            if !is_authorized(state, &channel_id, &author, admins_ev.as_ref()).await {
                return Err("restricted: not a group admin".to_string());
            }
            let mut meta = ChannelMeta::from_event(prev);
            // Only tags actually present mutate; the client sends one 9002 per
            // field it is changing (name/about/visibility/ttl from
            // `handleUpdateChannel`, `topic`, `purpose`, `archived` each alone).
            if let Some(v) = first_tag(ev, "name") {
                if v.is_empty() {
                    return Err("invalid: name may not be cleared".to_string());
                }
                meta.name = v;
            }
            if let Some(v) = first_tag(ev, "about") {
                meta.about = non_empty(Some(v));
            }
            if let Some(v) = first_tag(ev, "visibility") {
                meta.private = v == "private";
            }
            if let Some(v) = first_tag(ev, "ttl") {
                // `handleUpdateChannel` clears a TTL with `["ttl", ""]`.
                meta.ttl = non_empty(Some(v));
            }
            if let Some(v) = first_tag(ev, "topic") {
                meta.topic = non_empty(Some(v));
            }
            if let Some(v) = first_tag(ev, "purpose") {
                meta.purpose = non_empty(Some(v));
            }
            if let Some(v) = first_tag(ev, "archived") {
                // `handleUnarchiveChannel` sends `["archived","false"]`, so the
                // flag has to be clearable, not just settable.
                meta.archived = v == "true";
            }
            Ok(vec![emit_meta(state, &meta, meta_ev.as_ref()).await?])
        }

        kinds::KIND_GROUP_ADD_USER => {
            if meta_ev.is_none() {
                return Err("invalid: unknown group".to_string());
            }
            if !is_authorized(state, &channel_id, &author, admins_ev.as_ref()).await {
                return Err("restricted: not a group admin".to_string());
            }
            let target = first_tag(ev, "p")
                .ok_or_else(|| "invalid: add-user requires a p tag".to_string())?;
            let role = non_empty(first_tag(ev, "role")).unwrap_or_else(|| "member".to_string());
            members.upsert(&target, &role);
            let out = emit_members(state, &channel_id, &members, members_ev.as_ref()).await?;
            seed_member(state, &channel_id, &target).await;
            Ok(vec![out])
        }

        kinds::KIND_GROUP_REMOVE_USER => {
            if meta_ev.is_none() {
                return Err("invalid: unknown group".to_string());
            }
            if !is_authorized(state, &channel_id, &author, admins_ev.as_ref()).await {
                return Err("restricted: not a group admin".to_string());
            }
            let target = first_tag(ev, "p")
                .ok_or_else(|| "invalid: remove-user requires a p tag".to_string())?;
            members.remove(&target);
            Ok(vec![
                emit_members(state, &channel_id, &members, members_ev.as_ref()).await?,
            ])
        }

        kinds::KIND_GROUP_JOIN_REQUEST => {
            let meta = meta_ev
                .as_ref()
                .map(ChannelMeta::from_event)
                .ok_or_else(|| "invalid: unknown group".to_string())?;
            // Self-service join is the whole point of an open channel; a private
            // one requires an admin's 9000 instead.
            if meta.private {
                return Err("restricted: group is not open".to_string());
            }
            members.upsert(&author, "member");
            let out = emit_members(state, &channel_id, &members, members_ev.as_ref()).await?;
            seed_member(state, &channel_id, &author).await;
            Ok(vec![out])
        }

        kinds::KIND_GROUP_LEAVE_REQUEST => {
            if meta_ev.is_none() {
                return Err("invalid: unknown group".to_string());
            }
            // Leaving is always permitted, and leaving twice is not an error.
            members.remove(&author);
            Ok(vec![
                emit_members(state, &channel_id, &members, members_ev.as_ref()).await?,
            ])
        }

        kinds::KIND_GROUP_DELETE => {
            let prev = meta_ev
                .as_ref()
                .ok_or_else(|| "invalid: unknown group".to_string())?;
            if !is_authorized(state, &channel_id, &author, admins_ev.as_ref()).await {
                return Err("restricted: not a group admin".to_string());
            }
            // PARTIAL (reported): a replaceable can only be superseded, never
            // withdrawn, through `seed_event`. Removing the row outright needs a
            // tombstone/delete primitive in `src/history/*`. Until then a delete
            // is materialized as archived + emptied membership + a `deleted`
            // marker, which removes the channel from every member's sidebar but
            // leaves it visible in the all-channels browser query.
            let mut meta = ChannelMeta::from_event(prev);
            meta.archived = true;
            meta.deleted = true;
            let empty = MemberSet::default();
            Ok(vec![
                emit_meta(state, &meta, meta_ev.as_ref()).await?,
                emit_members(state, &channel_id, &empty, members_ev.as_ref()).await?,
            ])
        }

        other => Err(format!("invalid: unsupported group command kind {other}")),
    }
}

/// May `author` moderate this channel?
///
/// A channel created through 9007 carries a kind-39001 admin list and only
/// those pubkeys may moderate it. Channels that predate the executor — the demo
/// seed's `general`, and any channel materialized before this module landed —
/// have no 39001 at all; freezing them permanently would be worse than the
/// looser rule, so those fall back to the engine's membership table.
async fn is_authorized(
    state: &AppState,
    channel_id: &str,
    author: &str,
    admins: Option<&Event>,
) -> bool {
    match admins {
        Some(a) => p_entries(a).iter().any(|(pk, _)| pk == author),
        None => state
            .engine
            .is_member(channel_id, author)
            .await
            .unwrap_or(false),
    }
}

/// Mirror an addition into the engine's membership table so the (default-off)
/// membership gate agrees with the 39002 the client reads. Best-effort: the
/// 39002 event is the client-visible authority, and the trait exposes no
/// removal counterpart, so a failure here must not fail the command.
async fn seed_member(state: &AppState, channel_id: &str, pubkey_hex: &str) {
    if let Err(e) = state.engine.seed_member(channel_id, pubkey_hex).await {
        tracing::debug!(error = %e, %channel_id, "seed_member mirror failed");
    }
}

/// The current state of one channel, as carried by its kind-39000 tags.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChannelMeta {
    id: String,
    name: String,
    about: Option<String>,
    channel_type: String,
    private: bool,
    topic: Option<String>,
    purpose: Option<String>,
    ttl: Option<String>,
    archived: bool,
    deleted: bool,
}

impl ChannelMeta {
    fn from_event(ev: &Event) -> Self {
        Self {
            id: first_tag(ev, "d").unwrap_or_default(),
            name: first_tag(ev, "name").unwrap_or_default(),
            about: non_empty(first_tag(ev, "about")),
            channel_type: non_empty(first_tag(ev, "t")).unwrap_or_else(|| "stream".to_string()),
            private: has_tag(ev, "private"),
            topic: non_empty(first_tag(ev, "topic")),
            purpose: non_empty(first_tag(ev, "purpose")),
            ttl: non_empty(first_tag(ev, "ttl")),
            archived: first_tag(ev, "archived").as_deref() == Some("true"),
            deleted: first_tag(ev, "deleted").as_deref() == Some("true"),
        }
    }

    fn to_tags(&self) -> Result<Vec<Tag>, String> {
        // `h` duplicates `d` so the event binds to the channel topic on gossip
        // (`proto::topics_for_event`) the same way the seed's 39000 does.
        let mut raw: Vec<Vec<String>> = vec![
            vec!["d".into(), self.id.clone()],
            vec!["h".into(), self.id.clone()],
            vec!["name".into(), self.name.clone()],
            vec!["t".into(), self.channel_type.clone()],
            vec![
                "visibility".into(),
                if self.private { "private" } else { "open" }.into(),
            ],
        ];
        if self.private {
            raw.push(vec!["private".into(), "true".into()]);
        }
        for (name, value) in [
            ("about", &self.about),
            ("topic", &self.topic),
            ("purpose", &self.purpose),
            ("ttl", &self.ttl),
        ] {
            if let Some(v) = value {
                raw.push(vec![name.into(), v.clone()]);
            }
        }
        if self.archived {
            raw.push(vec!["archived".into(), "true".into()]);
        }
        if self.deleted {
            raw.push(vec!["deleted".into(), "true".into()]);
        }
        parse_tags(raw)
    }
}

/// The `["p", pubkey, role]` entries of a kind-39001/39002 list, insertion
/// ordered so a re-emitted list stays stable under repeated edits.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct MemberSet {
    entries: Vec<(String, String)>,
}

impl MemberSet {
    fn from_event(ev: Option<&Event>) -> Self {
        Self {
            entries: ev.map(p_entries).unwrap_or_default(),
        }
    }

    fn upsert(&mut self, pubkey: &str, role: &str) {
        if let Some(slot) = self.entries.iter_mut().find(|(pk, _)| pk == pubkey) {
            slot.1 = role.to_string();
        } else {
            self.entries.push((pubkey.to_string(), role.to_string()));
        }
    }

    fn remove(&mut self, pubkey: &str) {
        self.entries.retain(|(pk, _)| pk != pubkey);
    }
}

async fn emit_meta(
    state: &AppState,
    meta: &ChannelMeta,
    prev: Option<&Event>,
) -> Result<Event, String> {
    // Mirror visibility into the engine for the same reason `seed_member`
    // exists: the (default-off) membership gate reads `visibility`, and a
    // channel the client shows as private must not be gated as open. Every
    // meta-mutating path funnels through here, so an edit that flips
    // `visibility` moves the gate with it. Best-effort — the 39000 is the
    // client-visible authority.
    let vis = if meta.private {
        Visibility::Closed
    } else {
        Visibility::Open
    };
    if let Err(e) = state.engine.seed_visibility(&meta.id, vis).await {
        tracing::debug!(error = %e, channel_id = %meta.id, "seed_visibility mirror failed");
    }
    // Content mirrors the seed's 39000 so seeded and command-created channels
    // are byte-shaped alike.
    let content = serde_json::json!({ "name": meta.name }).to_string();
    emit(
        state,
        kinds::KIND_CHANNEL_METADATA,
        content,
        meta.to_tags()?,
        prev,
    )
    .await
}

async fn emit_members(
    state: &AppState,
    channel_id: &str,
    members: &MemberSet,
    prev: Option<&Event>,
) -> Result<Event, String> {
    emit_p_list(
        state,
        kinds::KIND_GROUP_MEMBERS,
        channel_id,
        &members.entries,
        prev,
    )
    .await
}

async fn emit_p_list(
    state: &AppState,
    kind: u16,
    channel_id: &str,
    entries: &[(String, String)],
    prev: Option<&Event>,
) -> Result<Event, String> {
    let mut raw: Vec<Vec<String>> = vec![
        vec!["d".into(), channel_id.to_string()],
        vec!["h".into(), channel_id.to_string()],
    ];
    for (pk, role) in entries {
        raw.push(vec!["p".into(), pk.clone(), role.clone()]);
    }
    emit(state, kind, String::new(), parse_tags(raw)?, prev).await
}

/// Sign and store one relay-authored replaceable.
///
/// `created_at` is forced strictly past the event it supersedes. Two commands
/// landing in the same wall-clock second are routine (Buzz creates a channel
/// and sets its topic back to back), and NIP-01's tie-break keeps the *lower
/// event id* on equal timestamps — so without this the second command's state
/// is silently `StaleRejected` about half the time.
async fn emit(
    state: &AppState,
    kind: u16,
    content: String,
    tags: Vec<Tag>,
    prev: Option<&Event>,
) -> Result<Event, String> {
    let floor = prev.map_or(0, |e| e.created_at.as_secs().saturating_add(1));
    let now = now_secs().max(floor);
    let out = state
        .identity
        .group_state_event(kind, content, tags, now)
        .map_err(|e| format!("error: signing group state failed: {e}"))?;
    state
        .engine
        .seed_event(&out)
        .await
        .map_err(|e| format!("error: storing group state failed: {e}"))?;
    Ok(out)
}

/// Latest relay-authored `kind` whose `d` tag is `channel_id`.
///
/// The `d` match is applied here rather than as a `#d` filter dimension: the
/// engine's filter surface does not yet model generic tags (gate-report defect
/// 1, owned by WP-A), and an unmodelled dimension currently *widens* the query
/// instead of narrowing it. Matching locally is correct either way.
async fn latest_addressable(
    state: &AppState,
    kind: u16,
    channel_id: &str,
) -> Result<Option<Event>, String> {
    let filter = Filter::new().kind(Kind::from(kind));
    let events = state
        .engine
        .query(&filter)
        .await
        .map_err(|e| format!("error: reading group state failed: {e}"))?;
    Ok(events
        .into_iter()
        .filter(|e| first_tag(e, "d").as_deref() == Some(channel_id))
        .max_by_key(|e| e.created_at.as_secs()))
}

fn parse_tags(raw: Vec<Vec<String>>) -> Result<Vec<Tag>, String> {
    raw.into_iter()
        .map(|t| Tag::parse(t).map_err(|e| format!("error: building group state tag failed: {e}")))
        .collect()
}

/// Value of the first `name` tag, or `Some("")` for a valueless marker tag.
fn first_tag(ev: &Event, name: &str) -> Option<String> {
    ev.tags.iter().find_map(|t| {
        let s = t.as_slice();
        (s.first().map(String::as_str) == Some(name)).then(|| s.get(1).cloned().unwrap_or_default())
    })
}

fn has_tag(ev: &Event, name: &str) -> bool {
    ev.tags
        .iter()
        .any(|t| t.as_slice().first().map(String::as_str) == Some(name))
}

fn p_entries(ev: &Event) -> Vec<(String, String)> {
    ev.tags
        .iter()
        .filter_map(|t| {
            let s = t.as_slice();
            if s.first().map(String::as_str) != Some("p") {
                return None;
            }
            let pk = s.get(1)?.clone();
            let role = s
                .get(2)
                .cloned()
                .filter(|r| !r.is_empty())
                .unwrap_or_else(|| "member".to_string());
            Some((pk, role))
        })
        .collect()
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys};

    fn command(keys: &Keys, kind: u16, tags: &[&[&str]]) -> Event {
        let tags: Vec<Tag> = tags
            .iter()
            .map(|t| Tag::parse(t.iter().copied()).expect("test tag parses"))
            .collect();
        EventBuilder::new(Kind::from(kind), "")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("test event signs")
    }

    #[test]
    fn meta_round_trips_through_its_own_tags() {
        // The executor re-reads a 39000 to apply the next 9002 to it, so a
        // to_tags/from_event round trip losing a field silently reverts state.
        let keys = Keys::generate();
        let meta = ChannelMeta {
            id: "chan-1".into(),
            name: "design".into(),
            about: Some("where design happens".into()),
            channel_type: "forum".into(),
            private: true,
            topic: Some("q3 planning".into()),
            purpose: Some("decisions".into()),
            ttl: Some("3600".into()),
            archived: true,
            deleted: false,
        };
        let ev = EventBuilder::new(Kind::from(kinds::KIND_CHANNEL_METADATA), "")
            .tags(meta.to_tags().expect("tags build"))
            .sign_with_keys(&keys)
            .expect("signs");
        assert_eq!(ChannelMeta::from_event(&ev), meta);
    }

    #[test]
    fn visibility_is_carried_for_both_client_readers() {
        // handleUpdateChannel reads getTag("visibility"); the list mapper and
        // handleGetChannelDetails test for a `private` tag's presence. Dropping
        // either one breaks a different call site.
        let open = ChannelMeta {
            id: "c".into(),
            name: "n".into(),
            about: None,
            channel_type: "stream".into(),
            private: false,
            topic: None,
            purpose: None,
            ttl: None,
            archived: false,
            deleted: false,
        };
        let tags = open.to_tags().expect("tags build");
        let slices: Vec<Vec<String>> = tags.iter().map(|t| t.as_slice().to_vec()).collect();
        assert!(slices
            .iter()
            .any(|t| t.first().map(String::as_str) == Some("visibility")
                && t.get(1).map(String::as_str) == Some("open")));
        assert!(
            !slices
                .iter()
                .any(|t| t.first().map(String::as_str) == Some("private")),
            "an open channel must carry no `private` tag or it renders as private"
        );

        let private = ChannelMeta {
            private: true,
            ..open
        };
        let tags = private.to_tags().expect("tags build");
        let slices: Vec<Vec<String>> = tags.iter().map(|t| t.as_slice().to_vec()).collect();
        assert!(slices
            .iter()
            .any(|t| t.first().map(String::as_str) == Some("visibility")
                && t.get(1).map(String::as_str) == Some("private")));
        assert!(slices
            .iter()
            .any(|t| t.first().map(String::as_str) == Some("private")));
    }

    #[test]
    fn member_upsert_is_idempotent_and_role_updating() {
        // A re-add must change the role in place; duplicating the pubkey would
        // double the client's member_count (it counts `p` tags, not distinct
        // pubkeys).
        let mut set = MemberSet::default();
        set.upsert("aa", "member");
        set.upsert("bb", "member");
        set.upsert("aa", "admin");
        assert_eq!(
            set.entries,
            vec![
                ("aa".to_string(), "admin".to_string()),
                ("bb".to_string(), "member".to_string())
            ]
        );
        set.remove("aa");
        assert_eq!(set.entries, vec![("bb".to_string(), "member".to_string())]);
        set.remove("aa");
        assert_eq!(
            set.entries.len(),
            1,
            "removing a non-member is not an error"
        );
    }

    #[test]
    fn p_entries_defaults_missing_role_to_member() {
        let keys = Keys::generate();
        let ev = command(&keys, 39002, &[&["p", "aa"], &["p", "bb", "owner"]]);
        assert_eq!(
            p_entries(&ev),
            vec![
                ("aa".to_string(), "member".to_string()),
                ("bb".to_string(), "owner".to_string())
            ]
        );
    }

    #[test]
    fn command_kinds_are_recognized() {
        for kind in [9000u16, 9001, 9002, 9007, 9008, 9021, 9022] {
            assert!(kinds::is_group_command(kind), "kind {kind} must execute");
        }
        // A stream message must not be mistaken for a command.
        assert!(!kinds::is_group_command(kinds::KIND_STREAM_MESSAGE));
        // Relay-authored group state stays client-unsubmittable.
        assert!(kinds::is_relay_authored(kinds::KIND_CHANNEL_METADATA));
        assert!(!kinds::is_group_command(kinds::KIND_CHANNEL_METADATA));
    }
}

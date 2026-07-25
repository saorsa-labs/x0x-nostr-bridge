//! NIP-29 group-command execution over the REAL `history::HistoryStore`.
//!
//! Buzz never observes a group command directly — it observes the replaceable
//! group state the relay emits as a side effect. `handleCreateChannel`
//! (`e2eBridge.ts`) publishes kind-9007 and then queries
//! `{kinds:[39000],"#d":[channelId],limit:1}`, throwing
//! `Channel "<name>" not found after creation` on an empty result. So the thing
//! worth testing is not "the command was accepted" but "the state the client
//! reads back afterwards is the state the client's own mappers expect".
//!
//! Each assertion below is therefore written against a *client reader*: the
//! kind-39000 → `RawChannel` mapper in `handleListChannels`, the
//! `handleGetChannelDetails` / `handleUpdateChannel` read-backs, and the
//! kind-39002 `p`-tag walk in `handleGetChannelMembers`.
//!
//! Assertions read the store through `engine.query` + a local `d` match rather
//! than a `#d` filter: the engine's filter surface does not yet model generic
//! single-letter tags (gate-report defect 1, owned by `wp-tagfilter`), and an
//! unmodelled dimension currently *widens* the query. Once that lands these can
//! use `#d` directly, which is also what the client sends.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use nostr::{Event, EventBuilder, Filter, JsonUtil, Keys, Kind, Tag};
use serde_json::Value;

use x0x_nostr_bridge::history::HistoryStore;
use x0x_nostr_bridge::history_adapter::{HistoryStoreEngine, HistoryStoreEventStore};
use x0x_nostr_bridge::relay::{router, AppState};
use x0x_nostr_bridge::relay_identity::RelayIdentity;
use x0x_nostr_bridge::settings::Settings;
use x0x_nostr_bridge::store::EventStore;
use x0x_nostr_bridge::transport::{GossipMessage, GossipTransport};

struct FakeTransport;
#[async_trait]
impl GossipTransport for FakeTransport {
    async fn ensure_topic(&self, _t: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn publish(&self, _t: &str, _p: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
    fn inbox(&self) -> tokio::sync::mpsc::Receiver<GossipMessage> {
        tokio::sync::mpsc::channel(1).1
    }
}

async fn spawn_real() -> (SocketAddr, Arc<AppState>) {
    let settings = Settings::default();
    let p_gated: Vec<u32> = settings
        .access
        .p_gated_kinds
        .iter()
        .map(|&k| u32::from(k))
        .collect();
    let history = Arc::new(HistoryStore::open_in_memory("test-community").unwrap());
    let engine = Arc::new(HistoryStoreEngine::new(
        Arc::clone(&history),
        p_gated.clone(),
    ));
    let store: Arc<dyn EventStore> =
        Arc::new(HistoryStoreEventStore::new(Arc::clone(&history), p_gated));
    let state = Arc::new(AppState::new(
        store,
        Arc::new(FakeTransport),
        engine,
        Arc::new(RelayIdentity::ephemeral()),
        Arc::new(settings),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(Arc::clone(&state));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, state)
}

/// Publish a signed group command through the client's door (`POST /events`).
async fn command(addr: SocketAddr, keys: &Keys, kind: u16, tags: &[&[&str]]) -> reqwest::Response {
    let tags: Vec<Tag> = tags
        .iter()
        .map(|t| Tag::parse(t.iter().copied()).unwrap())
        .collect();
    let ev = EventBuilder::new(Kind::from(kind), "")
        .tags(tags)
        .sign_with_keys(keys)
        .unwrap();
    reqwest::Client::new()
        .post(format!("http://{addr}/events"))
        .header("X-Pubkey", keys.public_key().to_hex())
        .body(ev.as_json())
        .send()
        .await
        .unwrap()
}

/// The relay-authored replaceable of `kind` addressed by `["d", channel_id]`.
async fn addressable(state: &Arc<AppState>, kind: u16, channel_id: &str) -> Option<Event> {
    state
        .engine
        .query(&Filter::new().kind(Kind::from(kind)))
        .await
        .unwrap()
        .into_iter()
        .filter(|e| tag(e, "d").as_deref() == Some(channel_id))
        .max_by_key(|e| e.created_at.as_secs())
}

/// Every relay-authored replaceable of `kind` carrying this `d` — a replaceable
/// that leaves more than one row behind has not replaced, it has duplicated.
async fn all_addressable(state: &Arc<AppState>, kind: u16, channel_id: &str) -> Vec<Event> {
    state
        .engine
        .query(&Filter::new().kind(Kind::from(kind)))
        .await
        .unwrap()
        .into_iter()
        .filter(|e| tag(e, "d").as_deref() == Some(channel_id))
        .collect()
}

/// `getTag(name)` as the client's mappers spell it.
fn tag(ev: &Event, name: &str) -> Option<String> {
    ev.tags.iter().find_map(|t| {
        let s = t.as_slice();
        (s.first().map(String::as_str) == Some(name)).then(|| s.get(1).cloned().unwrap_or_default())
    })
}

/// `tags.some(t => t[0] === name)` — the presence test the mapper uses for
/// `private`.
fn has_tag(ev: &Event, name: &str) -> bool {
    ev.tags
        .iter()
        .any(|t| t.as_slice().first().map(String::as_str) == Some(name))
}

/// The `p` pubkeys of a 39001/39002, in order — `member_count` counts these.
fn p_pubkeys(ev: &Event) -> Vec<String> {
    ev.tags
        .iter()
        .filter_map(|t| {
            let s = t.as_slice();
            (s.first().map(String::as_str) == Some("p")).then(|| s.get(1).cloned())?
        })
        .collect()
}

/// The role slot the client reads as `t[3] ?? t[2] ?? "member"`.
fn role_of(ev: &Event, pubkey: &str) -> Option<String> {
    ev.tags.iter().find_map(|t| {
        let s = t.as_slice();
        if s.first().map(String::as_str) != Some("p")
            || s.get(1).map(String::as_str) != Some(pubkey)
        {
            return None;
        }
        Some(
            s.get(3)
                .or_else(|| s.get(2))
                .cloned()
                .unwrap_or_else(|| "member".to_string()),
        )
    })
}

const KIND_META: u16 = 39000;
const KIND_ADMINS: u16 = 39001;
const KIND_MEMBERS: u16 = 39002;

/// The exact tag shape `handleCreateChannel` builds for a full-featured
/// channel: `h`, `name`, `channel_type`, `visibility`, plus optional `about`
/// and `ttl`.
#[tokio::test]
async fn create_channel_materializes_the_39000_the_client_reads_back() {
    let (addr, state) = spawn_real().await;
    let owner = Keys::generate();
    let owner_hex = owner.public_key().to_hex();
    let id = "11111111-1111-4111-8111-111111111111";

    let resp = command(
        addr,
        &owner,
        9007,
        &[
            &["h", id],
            &["name", "design"],
            &["channel_type", "forum"],
            &["visibility", "open"],
            &["about", "where design happens"],
            &["ttl", "3600"],
        ],
    )
    .await;
    assert_eq!(resp.status(), 200, "the client's create door must accept");

    let meta = addressable(&state, KIND_META, id)
        .await
        .expect("handleCreateChannel throws `not found after creation` without this 39000");

    // Read the 39000 back exactly as the RawChannel mapper does.
    assert_eq!(
        tag(&meta, "d").as_deref(),
        Some(id),
        "mapper: RawChannel.id"
    );
    assert_eq!(tag(&meta, "name").as_deref(), Some("design"));
    assert_eq!(
        tag(&meta, "about").as_deref(),
        Some("where design happens"),
        "mapper: RawChannel.description"
    );
    assert_eq!(
        tag(&meta, "t").as_deref(),
        Some("forum"),
        "the command spells it `channel_type`; the mapper reads `t`"
    );
    assert_eq!(
        tag(&meta, "ttl").as_deref(),
        Some("3600"),
        "mapper: Number(getTag(\"ttl\")) → ttl_seconds"
    );
    assert!(
        !has_tag(&meta, "private"),
        "an open channel carrying a `private` tag renders as private"
    );
    assert!(
        !has_tag(&meta, "archived"),
        "a fresh channel must not come back archived"
    );
    assert_eq!(
        tag(&meta, "visibility").as_deref(),
        Some("open"),
        "handleUpdateChannel reads the visibility *value*, not the private marker"
    );

    // The creator has to land in the 39002, or `handleListChannels` resolves
    // `is_member` false for the person who just made the channel and the
    // sidebar drops it.
    let members = addressable(&state, KIND_MEMBERS, id)
        .await
        .expect("creator membership must be materialized");
    assert_eq!(p_pubkeys(&members), vec![owner_hex.clone()]);
    assert_eq!(
        role_of(&members, &owner_hex).as_deref(),
        Some("owner"),
        "handleGetChannelMembers reads the role from t[3] ?? t[2]"
    );

    // 39001 is the durable answer to "who may moderate", used by every later
    // command's authorization check.
    let admins = addressable(&state, KIND_ADMINS, id)
        .await
        .expect("creator must be recorded as an admin");
    assert_eq!(p_pubkeys(&admins), vec![owner_hex]);
}

/// A private channel has to satisfy two different client readers at once:
/// `handleUpdateChannel` reads `getTag("visibility")`, while the list mapper and
/// `handleGetChannelDetails` test for the *presence* of a `private` tag.
#[tokio::test]
async fn private_channel_satisfies_both_visibility_readers() {
    let (addr, state) = spawn_real().await;
    let owner = Keys::generate();
    let id = "22222222-2222-4222-8222-222222222222";

    command(
        addr,
        &owner,
        9007,
        &[
            &["h", id],
            &["name", "secret"],
            &["channel_type", "stream"],
            &["visibility", "private"],
        ],
    )
    .await;

    let meta = addressable(&state, KIND_META, id).await.unwrap();
    assert_eq!(tag(&meta, "visibility").as_deref(), Some("private"));
    assert!(
        has_tag(&meta, "private"),
        "the list mapper decides visibility on the private tag's presence alone"
    );
}

/// 39000 is a NIP-01 addressable replaceable. Two rows for one `d` would make
/// `{kinds:[39000],"#d":[id],limit:1}` return whichever the store happened to
/// order first, so a rename could appear to silently revert.
#[tokio::test]
async fn recreating_a_channel_replaces_rather_than_duplicates() {
    let (addr, state) = spawn_real().await;
    let owner = Keys::generate();
    let id = "33333333-3333-4333-8333-333333333333";

    for name in ["first", "second"] {
        let resp = command(
            addr,
            &owner,
            9007,
            &[
                &["h", id],
                &["name", name],
                &["channel_type", "stream"],
                &["visibility", "open"],
            ],
        )
        .await;
        assert_eq!(resp.status(), 200);
    }

    let rows = all_addressable(&state, KIND_META, id).await;
    assert_eq!(
        rows.len(),
        1,
        "39000 must replace, not accumulate: {rows:?}"
    );
    assert_eq!(
        tag(&rows[0], "name").as_deref(),
        Some("second"),
        "the surviving row must be the later command's state"
    );
}

/// Anyone may create a *new* channel, but re-issuing 9007 against an existing
/// one is a rewrite of that channel's metadata. Letting a stranger do it means
/// any pubkey can rename or re-scope a channel it has no part in.
#[tokio::test]
async fn recreating_someone_elses_channel_is_refused_and_changes_nothing() {
    let (addr, state) = spawn_real().await;
    let owner = Keys::generate();
    let stranger = Keys::generate();
    let id = "44444444-4444-4444-8444-444444444444";

    command(
        addr,
        &owner,
        9007,
        &[
            &["h", id],
            &["name", "ours"],
            &["channel_type", "stream"],
            &["visibility", "open"],
        ],
    )
    .await;

    let resp = command(
        addr,
        &stranger,
        9007,
        &[
            &["h", id],
            &["name", "hijacked"],
            &["channel_type", "stream"],
            &["visibility", "private"],
        ],
    )
    .await;
    assert_eq!(
        resp.status(),
        403,
        "a moderation refusal is an authorization outcome"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .starts_with("restricted:"),
        "the client must be told why, not just that it failed: {body}"
    );

    let meta = addressable(&state, KIND_META, id).await.unwrap();
    assert_eq!(
        tag(&meta, "name").as_deref(),
        Some("ours"),
        "a refused command must not have partially applied"
    );
    assert!(!has_tag(&meta, "private"));
}

/// `handleArchiveChannel` sends `["archived","true"]` and
/// `handleUnarchiveChannel` sends `["archived","false"]`, so the flag has to be
/// clearable — a set-only implementation strands a channel in the archive.
#[tokio::test]
async fn archive_then_unarchive_round_trips_the_archived_flag() {
    let (addr, state) = spawn_real().await;
    let owner = Keys::generate();
    let id = "55555555-5555-4555-8555-555555555555";

    command(
        addr,
        &owner,
        9007,
        &[
            &["h", id],
            &["name", "attic"],
            &["channel_type", "stream"],
            &["visibility", "open"],
        ],
    )
    .await;

    let resp = command(addr, &owner, 9002, &[&["h", id], &["archived", "true"]]).await;
    assert_eq!(resp.status(), 200);
    let meta = addressable(&state, KIND_META, id).await.unwrap();
    assert_eq!(
        tag(&meta, "archived").as_deref(),
        Some("true"),
        "the mapper sets archived_at from tags.some(t[0]=='archived' && t[1]=='true')"
    );
    assert_eq!(
        tag(&meta, "name").as_deref(),
        Some("attic"),
        "a single-field 9002 must not blank the fields it did not mention"
    );

    let resp = command(addr, &owner, 9002, &[&["h", id], &["archived", "false"]]).await;
    assert_eq!(resp.status(), 200);
    let meta = addressable(&state, KIND_META, id).await.unwrap();
    assert!(
        !has_tag(&meta, "archived"),
        "unarchive must clear the flag; the mapper only tests for value 'true', \
         but leaving the tag behind misreports the channel to any stricter reader"
    );
}

/// `handleSetChannelTopic` / `handleSetChannelPurpose` each send a 9002 with a
/// single field. Applying only-present-tags is what keeps them from wiping the
/// rest of the channel's metadata.
#[tokio::test]
async fn single_field_edits_compose_instead_of_clobbering() {
    let (addr, state) = spawn_real().await;
    let owner = Keys::generate();
    let id = "66666666-6666-4666-8666-666666666666";

    command(
        addr,
        &owner,
        9007,
        &[
            &["h", id],
            &["name", "planning"],
            &["channel_type", "forum"],
            &["visibility", "open"],
            &["about", "the description"],
        ],
    )
    .await;
    command(addr, &owner, 9002, &[&["h", id], &["topic", "q3 roadmap"]]).await;
    command(addr, &owner, 9002, &[&["h", id], &["purpose", "decisions"]]).await;

    let meta = addressable(&state, KIND_META, id).await.unwrap();
    assert_eq!(tag(&meta, "topic").as_deref(), Some("q3 roadmap"));
    assert_eq!(tag(&meta, "purpose").as_deref(), Some("decisions"));
    assert_eq!(
        tag(&meta, "about").as_deref(),
        Some("the description"),
        "setting a topic must not drop the description"
    );
    assert_eq!(tag(&meta, "t").as_deref(), Some("forum"));
    assert_eq!(tag(&meta, "name").as_deref(), Some("planning"));
}

/// `handleUpdateChannel` clears a TTL by sending `["ttl",""]`, so an empty
/// value has to mean "remove" rather than "store the empty string" — the mapper
/// would otherwise read `Number("")` as `0`.
#[tokio::test]
async fn empty_ttl_clears_rather_than_storing_blank() {
    let (addr, state) = spawn_real().await;
    let owner = Keys::generate();
    let id = "77777777-7777-4777-8777-777777777777";

    command(
        addr,
        &owner,
        9007,
        &[
            &["h", id],
            &["name", "ephemeral"],
            &["channel_type", "stream"],
            &["visibility", "open"],
            &["ttl", "600"],
        ],
    )
    .await;
    assert_eq!(
        tag(&addressable(&state, KIND_META, id).await.unwrap(), "ttl").as_deref(),
        Some("600")
    );

    command(addr, &owner, 9002, &[&["h", id], &["ttl", ""]]).await;
    let meta = addressable(&state, KIND_META, id).await.unwrap();
    assert!(
        !has_tag(&meta, "ttl"),
        "a cleared TTL must leave no ttl tag, or the channel reads as ttl_seconds 0"
    );
}

/// `handleAddChannelMembers` publishes one 9000 per pubkey and
/// `handleRemoveChannelMember` publishes 9001; both are only observable through
/// the 39002 `p` set, which is simultaneously the client's `member_count`,
/// `participants`, and (via `#p`) its own `is_member` answer.
#[tokio::test]
async fn member_add_and_remove_update_the_39002_p_set() {
    let (addr, state) = spawn_real().await;
    let owner = Keys::generate();
    let alice = Keys::generate();
    let bob = Keys::generate();
    let (owner_hex, alice_hex, bob_hex) = (
        owner.public_key().to_hex(),
        alice.public_key().to_hex(),
        bob.public_key().to_hex(),
    );
    let id = "88888888-8888-4888-8888-888888888888";

    command(
        addr,
        &owner,
        9007,
        &[
            &["h", id],
            &["name", "team"],
            &["channel_type", "stream"],
            &["visibility", "open"],
        ],
    )
    .await;

    let resp = command(
        addr,
        &owner,
        9000,
        &[&["h", id], &["p", &alice_hex], &["role", "admin"]],
    )
    .await;
    assert_eq!(resp.status(), 200);
    command(addr, &owner, 9000, &[&["h", id], &["p", &bob_hex]]).await;

    let members = addressable(&state, KIND_MEMBERS, id).await.unwrap();
    assert_eq!(
        p_pubkeys(&members),
        vec![owner_hex.clone(), alice_hex.clone(), bob_hex.clone()],
        "member_count counts p tags, so a duplicate or a drop is directly visible"
    );
    assert_eq!(role_of(&members, &alice_hex).as_deref(), Some("admin"));
    assert_eq!(
        role_of(&members, &bob_hex).as_deref(),
        Some("member"),
        "9000 without a role tag defaults to member"
    );
    assert_eq!(
        all_addressable(&state, KIND_MEMBERS, id).await.len(),
        1,
        "39002 must replace on every membership change"
    );

    let resp = command(addr, &owner, 9001, &[&["h", id], &["p", &alice_hex]]).await;
    assert_eq!(resp.status(), 200);
    let members = addressable(&state, KIND_MEMBERS, id).await.unwrap();
    assert_eq!(p_pubkeys(&members), vec![owner_hex, bob_hex]);
}

/// Moderation has to be gated on the 39001 admin list, not on "whoever asks":
/// an unprivileged member adding themselves as an admin would be a complete
/// bypass of the channel's access control.
#[tokio::test]
async fn a_non_admin_cannot_add_or_remove_members() {
    let (addr, state) = spawn_real().await;
    let owner = Keys::generate();
    let intruder = Keys::generate();
    let victim = Keys::generate();
    let id = "99999999-9999-4999-8999-999999999999";
    let owner_hex = owner.public_key().to_hex();
    let intruder_hex = intruder.public_key().to_hex();

    command(
        addr,
        &owner,
        9007,
        &[
            &["h", id],
            &["name", "closed-shop"],
            &["channel_type", "stream"],
            &["visibility", "open"],
        ],
    )
    .await;

    let resp = command(
        addr,
        &intruder,
        9000,
        &[&["h", id], &["p", &victim.public_key().to_hex()]],
    )
    .await;
    assert_eq!(resp.status(), 403);

    let resp = command(addr, &intruder, 9001, &[&["h", id], &["p", &owner_hex]]).await;
    assert_eq!(
        resp.status(),
        403,
        "a non-admin must not be able to evict the owner"
    );

    let members = addressable(&state, KIND_MEMBERS, id).await.unwrap();
    assert_eq!(
        p_pubkeys(&members),
        vec![owner_hex],
        "neither refused command may have applied"
    );
    assert!(!p_pubkeys(&members).contains(&intruder_hex));
}

/// `handleJoinChannel` (9021) is self-service on an open channel and
/// `handleLeaveChannel` (9022) is always permitted — leaving is not a privilege
/// an admin can withhold, and leaving twice is not an error the UI can show.
#[tokio::test]
async fn join_is_self_service_on_open_channels_and_leave_always_works() {
    let (addr, state) = spawn_real().await;
    let owner = Keys::generate();
    let joiner = Keys::generate();
    let owner_hex = owner.public_key().to_hex();
    let joiner_hex = joiner.public_key().to_hex();
    let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    command(
        addr,
        &owner,
        9007,
        &[
            &["h", id],
            &["name", "lobby"],
            &["channel_type", "stream"],
            &["visibility", "open"],
        ],
    )
    .await;

    let resp = command(addr, &joiner, 9021, &[&["h", id]]).await;
    assert_eq!(resp.status(), 200);
    let members = addressable(&state, KIND_MEMBERS, id).await.unwrap();
    assert_eq!(p_pubkeys(&members), vec![owner_hex.clone(), joiner_hex]);

    let resp = command(addr, &joiner, 9022, &[&["h", id]]).await;
    assert_eq!(resp.status(), 200);
    let resp = command(addr, &joiner, 9022, &[&["h", id]]).await;
    assert_eq!(resp.status(), 200, "leaving twice must not be an error");
    let members = addressable(&state, KIND_MEMBERS, id).await.unwrap();
    assert_eq!(p_pubkeys(&members), vec![owner_hex]);
}

/// A private channel is joined by invitation (an admin's 9000), never by the
/// joiner's own 9021 — otherwise `visibility: "private"` means nothing.
#[tokio::test]
async fn join_is_refused_on_a_private_channel() {
    let (addr, state) = spawn_real().await;
    let owner = Keys::generate();
    let outsider = Keys::generate();
    let id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    command(
        addr,
        &owner,
        9007,
        &[
            &["h", id],
            &["name", "private-room"],
            &["channel_type", "stream"],
            &["visibility", "private"],
        ],
    )
    .await;

    let resp = command(addr, &outsider, 9021, &[&["h", id]]).await;
    assert_eq!(resp.status(), 403);

    let members = addressable(&state, KIND_MEMBERS, id).await.unwrap();
    assert_eq!(p_pubkeys(&members), vec![owner.public_key().to_hex()]);
}

/// A command naming a channel that does not exist must be refused rather than
/// conjuring one: materializing a 39000 from a stray 9002 would let any pubkey
/// create channels it is automatically the admin of.
#[tokio::test]
async fn commands_against_an_unknown_channel_are_refused() {
    let (addr, state) = spawn_real().await;
    let anyone = Keys::generate();
    let id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

    for kind in [9002u16, 9000, 9001, 9008, 9021, 9022] {
        let resp = command(
            addr,
            &anyone,
            kind,
            &[
                &["h", id],
                &["p", &anyone.public_key().to_hex()],
                &["name", "ghost"],
            ],
        )
        .await;
        assert_eq!(resp.status(), 400, "kind {kind} must not create a channel");
    }
    assert!(
        addressable(&state, KIND_META, id).await.is_none(),
        "no channel may exist for an id only ever named by a non-create command"
    );
}

/// Rejections have to carry the reason the client can surface. `submitSignedEvent`
/// turns the body into the error the UI shows, so an empty or generic message
/// leaves the user with a failed action and no explanation.
#[tokio::test]
async fn a_malformed_command_is_rejected_with_a_reason_and_stored_nowhere() {
    let (addr, state) = spawn_real().await;
    let anyone = Keys::generate();

    // No `h` tag: there is no channel to address.
    let resp = command(addr, &anyone, 9007, &[&["name", "nowhere"]]).await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or_default().contains("h tag"),
        "the reason must name the missing tag: {body}"
    );

    // A create with no name renders as a blank sidebar row, indistinguishable
    // from a bug, so it is refused at the door.
    let id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    let resp = command(addr, &anyone, 9007, &[&["h", id], &["visibility", "open"]]).await;
    assert_eq!(resp.status(), 400);
    assert!(addressable(&state, KIND_META, id).await.is_none());

    // A refused command must not be stored either, or it replicates to peers
    // and re-executes on the far side.
    let stored = state
        .engine
        .query(&Filter::new().kind(Kind::from(9007u16)))
        .await
        .unwrap();
    assert!(
        stored.is_empty(),
        "a rejected command must not reach the store: {stored:?}"
    );
}

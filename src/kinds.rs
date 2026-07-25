//! Buzz Nostr kind constants + kind-class predicates shared across the HTTP
//! dialect, the WS layer, and the read-model synthesis. Owner: wp2-http.
//!
//! Numbers are mined from `buzz_core::kind` via the recon pack
//! (`docs/recon/dialect.md` §7, `docs/recon/thread.md`, `thread-fixtures.json`).
//! Where the recon pack did not surface an exact number (presence, some access
//! classes) the value is `None`/empty and documented as such — the mechanism is
//! wired so plugging the confirmed number in is a one-line change.

/// KIND_STREAM_MESSAGE — the channel timeline message (thread-fixtures.json).
pub const KIND_STREAM_MESSAGE: u16 = 9;
/// NIP-09 deletion.
pub const KIND_DELETION: u16 = 5;
/// NIP-25 reaction (aux closure; never threaded).
pub const KIND_REACTION: u16 = 7;
/// NIP-42 WS auth event.
pub const KIND_NIP42_AUTH: u16 = 22242;
/// NIP-98 HTTP auth event.
pub const KIND_NIP98_AUTH: u16 = 27235;
/// Channel metadata (kind-39000 — the seed target for `assertRelaySeeded`).
pub const KIND_CHANNEL_METADATA: u16 = 39000;
/// NIP-29 group admins list.
pub const KIND_GROUP_ADMINS: u16 = 39001;
/// NIP-29 group members list.
pub const KIND_GROUP_MEMBERS: u16 = 39002;
/// NIP-29 group roles list.
pub const KIND_GROUP_ROLES: u16 = 39003;
/// Relay-signed thread-summary overlay (dialect.md §1, thread.md §2).
pub const KIND_THREAD_SUMMARY: u16 = 39005;
/// Relay-signed window-bounds overlay (dialect.md §1).
pub const KIND_WINDOW_BOUNDS: u16 = 39006;
/// NIP-43 replaceable membership list (single, relay-authored).
pub const KIND_MEMBERSHIP_LIST: u16 = 13534;
/// Forum-post kind used by the NIP-50 search path alongside kind 9 (tests.md §4c).
pub const KIND_FORUM_POST: u16 = 40002;

/// NIP-29 add-user command (`e2eBridge.ts::handleAddChannelMembers`).
pub const KIND_GROUP_ADD_USER: u16 = 9000;
/// NIP-29 remove-user command (`handleRemoveChannelMember`).
pub const KIND_GROUP_REMOVE_USER: u16 = 9001;
/// NIP-29 edit-metadata command — also carries topic / purpose / archived
/// (`handleUpdateChannel`, `handleSetChannelTopic`, `handleSetChannelPurpose`,
/// `handleArchiveChannel`, `handleUnarchiveChannel`).
pub const KIND_GROUP_EDIT_METADATA: u16 = 9002;
/// NIP-29 create-group command (`handleCreateChannel`).
pub const KIND_GROUP_CREATE: u16 = 9007;
/// NIP-29 delete-group command (`handleDeleteChannel`).
pub const KIND_GROUP_DELETE: u16 = 9008;
/// NIP-29 join-request command (`handleJoinChannel`).
pub const KIND_GROUP_JOIN_REQUEST: u16 = 9021;
/// NIP-29 leave-request command (`handleLeaveChannel`).
pub const KIND_GROUP_LEAVE_REQUEST: u16 = 9022;

/// Client-submitted NIP-29 kinds the relay must **execute**, not merely store
/// (dialect.md §7). Each materializes relay-authored 39000/39001/39002 that the
/// client reads straight back — see [`crate::nip29`]. Kinds in the 9000..=9022
/// band that Buzz never publishes are deliberately absent: an unrecognized
/// command would otherwise be answered with a materialization we invented.
pub fn is_group_command(kind: u16) -> bool {
    matches!(
        kind,
        KIND_GROUP_ADD_USER
            | KIND_GROUP_REMOVE_USER
            | KIND_GROUP_EDIT_METADATA
            | KIND_GROUP_CREATE
            | KIND_GROUP_DELETE
            | KIND_GROUP_JOIN_REQUEST
            | KIND_GROUP_LEAVE_REQUEST
    )
}

/// Depth cap for the `Some(meta)` thread branch (thread.md §1.4).
pub const DEPTH_CAP: i64 = 100;
/// Participant list cap in a 39005 summary (thread.md §1.5).
pub const PARTICIPANT_CAP: usize = 10;

/// Kinds only the relay may author. Client submissions of these are rejected at
/// ingest (dialect.md §7, thread.md §2: "Client-submitted 39005/39006 are
/// rejected at ingest"; 39000-39003 + 13534 are relay-authored group state).
pub fn is_relay_authored(kind: u16) -> bool {
    matches!(
        kind,
        KIND_CHANNEL_METADATA
            | KIND_GROUP_ADMINS
            | KIND_GROUP_MEMBERS
            | KIND_GROUP_ROLES
            | KIND_THREAD_SUMMARY
            | KIND_WINDOW_BOUNDS
            | KIND_MEMBERSHIP_LIST
    )
}

/// Kinds that make up the aux closure of a channel-window row (dialect.md §1
/// step 2): reactions, deletions, and stream-message edits. The second hop
/// (deletions targeting these aux events) is closure logic in the HTTP layer,
/// not a kind class.
pub fn is_aux_kind(kind: u16) -> bool {
    matches!(kind, KIND_DELETION | KIND_REACTION)
}

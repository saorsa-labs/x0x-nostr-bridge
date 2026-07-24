//! Thread-engine conformance suite (WP1 gate).
//!
//! Every vector V1–V15 from `docs/recon/thread-fixtures.json` is implemented
//! here against the public `HistoryStore` API, plus the mesh-door
//! park/attach/recursive-drain, quarantine-on-mismatch, dup-delivery
//! idempotence, fingerprint-mismatch refusal, id-canonicalization, and
//! same-second keyset-tie scenarios the design calls out.
//!
//! Ids are content-addressed, so (as the fixture driver intends) each test
//! builds the root/parent first, reads its real 32-byte id, and references that
//! id in the child's NIP-10 marker tags.

use std::time::Duration;

use nostr::{Event, EventBuilder, Keys, Kind, TagKind, Timestamp};
use x0x_nostr_bridge::history::types::{LocalIngest, MeshIngest};
use x0x_nostr_bridge::history::{
    canonical_event_id, is_relay_authored_kind, HistoryStore, ThreadCursor, WindowCursor,
};

const CH: &str = "550e8400-e29b-41d4-a716-446655440000";
const CH_B: &str = "660e8400-e29b-41d4-a716-446655440001";
const FP: &str = "test-community-fingerprint";

fn store() -> HistoryStore {
    HistoryStore::open_in_memory(FP).expect("open in-memory history store")
}

/// A tag builder that produces exactly `[name, values...]`.
fn tag(name: &str, values: &[&str]) -> nostr::Tag {
    nostr::Tag::custom(
        TagKind::custom(name.to_string()),
        values.iter().map(|s| s.to_string()),
    )
}

fn h(channel: &str) -> nostr::Tag {
    tag("h", &[channel])
}

/// A marked NIP-10 e-tag: `["e", <id>, "", <marker>]`.
fn e_marked(id: &str, marker: &str) -> nostr::Tag {
    tag("e", &[id, "", marker])
}

fn build(keys: &Keys, kind: u16, content: &str, created_at: u64, tags: Vec<nostr::Tag>) -> Event {
    let mut b =
        EventBuilder::new(Kind::from(kind), content).custom_created_at(Timestamp::from(created_at));
    for t in tags {
        b = b.tag(t);
    }
    b.sign_with_keys(keys).expect("sign event")
}

/// Kind-9 stream message in channel `CH` with the given marker tags.
fn msg(keys: &Keys, content: &str, created_at: u64, mut tags: Vec<nostr::Tag>) -> Event {
    tags.insert(0, h(CH));
    build(keys, 9, content, created_at, tags)
}

async fn accept_local(s: &HistoryStore, ev: &Event) -> Vec<String> {
    match s.ingest_local(ev).await.expect("ingest_local") {
        LocalIngest::Accepted(e) => e.emits.into_iter().map(|x| x.root_event_id).collect(),
        LocalIngest::Rejected(r) => panic!("expected accept, got reject: {r}"),
    }
}

async fn reject_local(s: &HistoryStore, ev: &Event) -> String {
    match s.ingest_local(ev).await.expect("ingest_local") {
        LocalIngest::Rejected(r) => r,
        LocalIngest::Accepted(_) => panic!("expected reject, got accept"),
    }
}

async fn reply_ids(s: &HistoryStore, root: &str) -> Vec<String> {
    s.thread_replies(root, None, 500, None)
        .await
        .expect("thread_replies")
        .rows
        .iter()
        .map(|e| e.id.to_hex())
        .collect()
}

// ---- V1 --------------------------------------------------------------------

#[tokio::test]
async fn v1_simple_reply_to_root() {
    let s = store();
    let a = Keys::generate();
    let root = msg(&a, "root message", 1000, vec![]);
    let root_id = root.id.to_hex();

    let emits = accept_local(&s, &root).await;
    assert!(emits.is_empty(), "top-level root produces no 39005 emit");

    let r1 = msg(&a, "reply to root", 1001, vec![e_marked(&root_id, "reply")]);
    let emits = accept_local(&s, &r1).await;
    assert_eq!(
        emits,
        vec![root_id.clone()],
        "reply emits a 39005 for the root"
    );

    let summary = s
        .thread_summary(&root_id)
        .await
        .expect("thread_summary")
        .expect("root has a summary after a reply");
    assert_eq!(summary.reply_count, 1);
    assert_eq!(summary.descendant_count, 1);
    assert!(
        summary.last_reply_at.is_some(),
        "local door stamps last_reply_at"
    );
    assert!(summary.participants.contains(&a.public_key().to_hex()));

    let replies = reply_ids(&s, &root_id).await;
    assert_eq!(replies, vec![r1.id.to_hex()]);
    assert!(
        !replies.contains(&root_id),
        "root itself is never in thread_replies"
    );
}

// ---- V2 --------------------------------------------------------------------

#[tokio::test]
async fn v2_reply_with_both_markers_depth2() {
    let s = store();
    let (a, b, c) = (Keys::generate(), Keys::generate(), Keys::generate());
    let root = msg(&a, "root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;

    let r1 = msg(&b, "child", 1001, vec![e_marked(&root_id, "reply")]);
    accept_local(&s, &r1).await;
    let r1_id = r1.id.to_hex();

    let r2 = msg(
        &c,
        "grandchild",
        1002,
        vec![e_marked(&root_id, "root"), e_marked(&r1_id, "reply")],
    );
    accept_local(&s, &r2).await;

    let root_sum = s.thread_summary(&root_id).await.unwrap().unwrap();
    assert_eq!(root_sum.reply_count, 1, "ROOT has one DIRECT child (R1)");
    assert_eq!(root_sum.descendant_count, 2, "ROOT subtree = R1 + R2");
    assert!(root_sum.participants.contains(&b.public_key().to_hex()));
    assert!(root_sum.participants.contains(&c.public_key().to_hex()));

    let r1_sum = s.thread_summary(&r1_id).await.unwrap().unwrap();
    assert_eq!(r1_sum.reply_count, 1, "R1 has one direct child (R2)");
}

// ---- V3 --------------------------------------------------------------------

#[tokio::test]
async fn v3_orphan_reply_unknown_parent_rejected_local() {
    let s = store();
    let a = Keys::generate();
    let fake = "f".repeat(64);
    let r1 = msg(&a, "orphan reply", 1001, vec![e_marked(&fake, "reply")]);

    let reason = reject_local(&s, &r1).await;
    assert!(reason.contains("reply parent not found"), "got: {reason}");
    // Not stored flat.
    assert!(reply_ids(&s, &fake).await.is_empty());
}

// ---- V4 --------------------------------------------------------------------

#[tokio::test]
async fn v4_root_mismatch_rejected() {
    let s = store();
    let a = Keys::generate();
    let root = msg(&a, "real root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;

    let wrong_root = "a".repeat(64);
    let bad = msg(
        &a,
        "reply with wrong root",
        1001,
        vec![e_marked(&wrong_root, "root"), e_marked(&root_id, "reply")],
    );
    let reason = reject_local(&s, &bad).await;
    assert!(reason.contains("root tag does not match"), "got: {reason}");
}

// ---- V5 --------------------------------------------------------------------

#[tokio::test]
async fn v5_only_root_marker_is_top_level() {
    let s = store();
    let (a, b) = (Keys::generate(), Keys::generate());
    let root = msg(&a, "root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;

    let e1 = msg(
        &b,
        "tags only root marker",
        1001,
        vec![e_marked(&root_id, "root")],
    );
    let emits = accept_local(&s, &e1).await;
    assert!(
        emits.is_empty(),
        "only-root is top-level, no thread mutation"
    );

    assert!(
        s.thread_summary(&root_id).await.unwrap().is_none(),
        "ROOT got no replies (only-root is NOT a reply)"
    );
    assert!(reply_ids(&s, &root_id).await.is_empty());
}

// ---- V6 --------------------------------------------------------------------

#[tokio::test]
async fn v6_positional_etag_ignored() {
    let s = store();
    let (a, b) = (Keys::generate(), Keys::generate());
    let root = msg(&a, "root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;

    // Bare positional e-tag (len 2, no marker).
    let e1 = msg(&b, "positional reply", 1001, vec![tag("e", &[&root_id])]);
    let emits = accept_local(&s, &e1).await;
    assert!(emits.is_empty());
    assert!(s.thread_summary(&root_id).await.unwrap().is_none());
}

// ---- V7 --------------------------------------------------------------------

#[tokio::test]
async fn v7_mention_marker_ignored() {
    let s = store();
    let (a, b) = (Keys::generate(), Keys::generate());
    let root = msg(&a, "root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;

    let e1 = msg(
        &b,
        "mentions root",
        1001,
        vec![e_marked(&root_id, "mention")],
    );
    let emits = accept_local(&s, &e1).await;
    assert!(emits.is_empty());
    assert!(s.thread_summary(&root_id).await.unwrap().is_none());
}

// ---- V8 --------------------------------------------------------------------

#[tokio::test]
async fn v8_broadcast_depth1_surfaced_vs_hidden() {
    let s = store();
    let a = Keys::generate();
    let root = msg(&a, "root-toplevel", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;

    let hidden = msg(
        &a,
        "reply-excluded",
        1001,
        vec![e_marked(&root_id, "reply")],
    );
    accept_local(&s, &hidden).await;
    let shown = msg(
        &a,
        "reply-broadcast",
        1002,
        vec![e_marked(&root_id, "reply"), tag("broadcast", &["1"])],
    );
    accept_local(&s, &shown).await;

    // Both are recorded under the root.
    let replies = reply_ids(&s, &root_id).await;
    assert!(replies.contains(&hidden.id.to_hex()));
    assert!(replies.contains(&shown.id.to_hex()));

    // Only ROOT and the broadcast reply are top-level window rows.
    let window = s.channel_window(CH, 50, None).await.unwrap();
    let ids: Vec<String> = window.rows.iter().map(|e| e.id.to_hex()).collect();
    assert!(ids.contains(&root_id), "root is a window row");
    assert!(
        ids.contains(&shown.id.to_hex()),
        "broadcast depth-1 surfaces"
    );
    assert!(
        !ids.contains(&hidden.id.to_hex()),
        "ordinary depth-1 reply is hidden from the window"
    );
}

// ---- V9 --------------------------------------------------------------------

#[tokio::test]
async fn v9_channel_window_summary_overlay() {
    let s = store();
    let (a, b) = (Keys::generate(), Keys::generate());
    let root = msg(&a, "windowed root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;
    let r1 = msg(&b, "window reply", 1001, vec![e_marked(&root_id, "reply")]);
    accept_local(&s, &r1).await;

    let window = s.channel_window(CH, 50, None).await.unwrap();
    let ids: Vec<String> = window.rows.iter().map(|e| e.id.to_hex()).collect();
    assert_eq!(ids, vec![root_id.clone()], "root is a row, reply is not");

    assert_eq!(window.summaries.len(), 1, "one 39005 overlay for the root");
    assert_eq!(window.summaries[0].root_event_id, root_id);
    assert_eq!(window.summaries[0].reply_count, 1);

    // The 39006 window-bounds overlay is always available.
    assert!(!window.bounds.has_more);
    assert!(window.bounds.next_cursor.is_none());
}

// ---- V10 -------------------------------------------------------------------

#[tokio::test]
async fn v10_client_overlay_kinds_rejected() {
    let s = store();
    let a = Keys::generate();
    let spoof_summary = build(&a, 39005, "{\"reply_count\":999}", 1000, vec![h(CH)]);
    let spoof_bounds = build(&a, 39006, "{}", 1000, vec![h(CH)]);

    assert!(reject_local(&s, &spoof_summary)
        .await
        .contains("relay-authored"));
    assert!(reject_local(&s, &spoof_bounds)
        .await
        .contains("relay-authored"));

    // The kind-guard helper the HTTP lane reuses.
    for k in [39000u16, 39001, 39002, 39003, 39005, 39006, 13534] {
        assert!(is_relay_authored_kind(k), "kind {k} is relay-authored");
    }
    for k in [9u16, 7, 5, 9005, 1, 0] {
        assert!(!is_relay_authored_kind(k), "kind {k} is client-authored");
    }
}

// ---- V11 -------------------------------------------------------------------

#[tokio::test]
async fn v11_deep_nesting_at_cap() {
    let s = store();
    let a = Keys::generate();
    let root = msg(&a, "root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;

    // R1..R100: each replies to the previous; depth k == k.
    let mut prev = root_id.clone();
    for k in 1..=100u64 {
        let rk = msg(
            &a,
            &format!("r{k}"),
            1000 + k,
            vec![e_marked(&root_id, "root"), e_marked(&prev, "reply")],
        );
        accept_local(&s, &rk).await;
        prev = rk.id.to_hex();
    }

    // R101 (depth 101) is rejected at the cap.
    let r101 = msg(
        &a,
        "r101",
        1101,
        vec![e_marked(&root_id, "root"), e_marked(&prev, "reply")],
    );
    let reason = reject_local(&s, &r101).await;
    assert!(
        reason.contains("thread depth limit exceeded"),
        "got: {reason}"
    );

    let sum = s.thread_summary(&root_id).await.unwrap().unwrap();
    assert_eq!(sum.descendant_count, 100, "each level bumps the root once");
    assert_eq!(sum.reply_count, 1, "only R1 is a direct child of ROOT");
}

// ---- V12 -------------------------------------------------------------------

#[tokio::test]
async fn v12_cross_channel_parent_rejected() {
    let s = store();
    let a = Keys::generate();
    let root = build(&a, 9, "root in channel A", 1000, vec![h(CH)]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;

    let r1 = build(
        &a,
        9,
        "reply from channel B",
        1001,
        vec![h(CH_B), e_marked(&root_id, "reply")],
    );
    let reason = reject_local(&s, &r1).await;
    assert!(
        reason.contains("belongs to a different channel"),
        "got: {reason}"
    );
}

// ---- V13 -------------------------------------------------------------------

#[tokio::test]
async fn v13_nested_reply_creates_root_stub_and_subtree_read() {
    let s = store();
    let a = Keys::generate();
    let root = msg(&a, "root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;

    let child = msg(&a, "child", 1001, vec![e_marked(&root_id, "reply")]);
    accept_local(&s, &child).await;
    let child_id = child.id.to_hex();

    let grandchild = msg(
        &a,
        "grandchild",
        1002,
        vec![e_marked(&root_id, "root"), e_marked(&child_id, "reply")],
    );
    accept_local(&s, &grandchild).await;

    // Subtree read reaches depth 2 (must not stop at depth 1).
    let replies = s
        .thread_replies(&root_id, Some(64), 500, None)
        .await
        .unwrap()
        .rows
        .iter()
        .map(|e| e.id.to_hex())
        .collect::<Vec<_>>();
    assert!(replies.contains(&child_id));
    assert!(replies.contains(&grandchild.id.to_hex()));

    assert_eq!(
        s.thread_summary(&root_id)
            .await
            .unwrap()
            .unwrap()
            .descendant_count,
        2
    );
}

// ---- V14 -------------------------------------------------------------------

#[tokio::test]
async fn v14_same_second_thread_tie_pagination() {
    let s = store();
    let a = Keys::generate();
    let root = msg(&a, "root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;

    // Five replies, all created_at == 1001 (identical second), distinct content
    // so their ids differ.
    for i in 1..=5 {
        let r = msg(
            &a,
            &format!("r{i}"),
            1001,
            vec![e_marked(&root_id, "reply")],
        );
        accept_local(&s, &r).await;
    }

    // Walk pages of 2; the composite (created_at, id) cursor must not drop ties.
    let mut collected: Vec<String> = Vec::new();
    let mut cursor: Option<ThreadCursor> = None;
    loop {
        let page = s
            .thread_replies(&root_id, None, 2, cursor.take())
            .await
            .unwrap();
        for e in &page.rows {
            collected.push(e.id.to_hex());
        }
        if page.has_more {
            cursor = page.next_cursor;
        } else {
            break;
        }
    }
    collected.sort();
    collected.dedup();
    assert_eq!(
        collected.len(),
        5,
        "all 5 same-second ties collected, no loss/dup"
    );
}

// ---- V15 -------------------------------------------------------------------

#[tokio::test]
async fn v15_delete_reply_decrements_counters() {
    let s = store();
    let (a, b) = (Keys::generate(), Keys::generate());
    let root = msg(&a, "root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;
    let r1 = msg(&b, "reply", 1001, vec![e_marked(&root_id, "reply")]);
    accept_local(&s, &r1).await;
    let r1_id = r1.id.to_hex();

    let after_reply = s.thread_summary(&root_id).await.unwrap().unwrap();
    assert_eq!(
        (after_reply.reply_count, after_reply.descendant_count),
        (1, 1)
    );

    // NIP-09 deletion of R1 (kind 5, e-tag target).
    let del = build(&b, 5, "delete", 1002, vec![h(CH), tag("e", &[&r1_id])]);
    let emits = accept_local(&s, &del).await;
    assert!(
        emits.contains(&root_id),
        "delete emits a recomputed 39005 for root"
    );

    let after_del = s.thread_summary(&root_id).await.unwrap().unwrap();
    assert_eq!((after_del.reply_count, after_del.descendant_count), (0, 0));
    assert!(
        reply_ids(&s, &root_id).await.is_empty(),
        "deleted reply is invisible to thread_replies"
    );

    // A second, distinct delete targeting the same (already-deleted) reply must
    // NOT double-decrement below zero.
    let del2 = build(
        &b,
        5,
        "delete again",
        1003,
        vec![h(CH), tag("e", &[&r1_id])],
    );
    accept_local(&s, &del2).await;
    let after_del2 = s.thread_summary(&root_id).await.unwrap().unwrap();
    assert_eq!(
        (after_del2.reply_count, after_del2.descendant_count),
        (0, 0)
    );
}

#[tokio::test]
async fn v15b_deleting_root_makes_summary_none() {
    let s = store();
    let (a, b) = (Keys::generate(), Keys::generate());
    let root = msg(&a, "root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;
    accept_local(
        &s,
        &msg(&b, "reply", 1001, vec![e_marked(&root_id, "reply")]),
    )
    .await;

    let del = build(
        &a,
        5,
        "delete root",
        1002,
        vec![h(CH), tag("e", &[&root_id])],
    );
    accept_local(&s, &del).await;
    assert!(
        s.thread_summary(&root_id).await.unwrap().is_none(),
        "a deleted root has no summary (emit no-ops)"
    );
}

// ---- mesh door: park -> attach -> recursive drain --------------------------

#[tokio::test]
async fn mesh_park_attach_recursive_drain() {
    let s = store();
    let a = Keys::generate();

    // Root arrives (local); build the reply chain's ids up front.
    let root = msg(&a, "root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;

    let child = msg(&a, "child", 1001, vec![e_marked(&root_id, "reply")]);
    let child_id = child.id.to_hex();
    let gchild = msg(
        &a,
        "gchild",
        1002,
        vec![e_marked(&root_id, "root"), e_marked(&child_id, "reply")],
    );
    let gchild_id = gchild.id.to_hex();
    let ggchild = msg(
        &a,
        "ggchild",
        1003,
        vec![e_marked(&root_id, "root"), e_marked(&gchild_id, "reply")],
    );

    // Descendants arrive BEFORE their parents (out of order) via the mesh door.
    assert_eq!(s.ingest_mesh(&ggchild).await.unwrap(), MeshIngest::Parked);
    assert_eq!(s.ingest_mesh(&gchild).await.unwrap(), MeshIngest::Parked);

    // While parked, everything is invisible.
    assert!(reply_ids(&s, &root_id).await.is_empty());
    assert!(s.thread_summary(&root_id).await.unwrap().is_none());

    // The child lands: it attaches AND recursively drains gchild then ggchild.
    match s.ingest_mesh(&child).await.unwrap() {
        MeshIngest::Accepted(_) => {}
        other => panic!("expected Accepted, got {other:?}"),
    }

    let replies = reply_ids(&s, &root_id).await;
    assert!(replies.contains(&child_id));
    assert!(replies.contains(&gchild_id));
    assert!(replies.contains(&ggchild.id.to_hex()));
    assert_eq!(
        s.thread_summary(&root_id)
            .await
            .unwrap()
            .unwrap()
            .descendant_count,
        3,
        "root subtree = child + gchild + ggchild after recursive drain"
    );
}

// ---- mesh door: quarantine on ancestry mismatch ----------------------------

#[tokio::test]
async fn mesh_quarantine_on_root_mismatch_is_invisible() {
    let s = store();
    let a = Keys::generate();
    let root = msg(&a, "root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;
    let child = msg(&a, "child", 1001, vec![e_marked(&root_id, "reply")]);
    accept_local(&s, &child).await;
    let child_id = child.id.to_hex();

    // Mesh event claims the wrong root; parent (child) exists -> quarantine.
    let wrong_root = "b".repeat(64);
    let bad = msg(
        &a,
        "bad ancestry",
        1002,
        vec![e_marked(&wrong_root, "root"), e_marked(&child_id, "reply")],
    );
    match s.ingest_mesh(&bad).await.unwrap() {
        MeshIngest::Quarantined(r) => assert!(r.contains("root tag does not match")),
        other => panic!("expected Quarantined, got {other:?}"),
    }

    // Quarantined event is invisible and did not move counters.
    let replies = reply_ids(&s, &root_id).await;
    assert!(!replies.contains(&bad.id.to_hex()));
    assert_eq!(
        s.thread_summary(&root_id)
            .await
            .unwrap()
            .unwrap()
            .descendant_count,
        1,
        "only the legitimate child counts"
    );
}

// ---- mesh door: duplicate delivery idempotence -----------------------------

#[tokio::test]
async fn mesh_dup_delivery_is_idempotent() {
    let s = store();
    let a = Keys::generate();
    let root = msg(&a, "root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;
    let child = msg(&a, "child", 1001, vec![e_marked(&root_id, "reply")]);

    match s.ingest_mesh(&child).await.unwrap() {
        MeshIngest::Accepted(e) => assert!(!e.duplicate),
        other => panic!("first delivery should be accepted, got {other:?}"),
    }
    match s.ingest_mesh(&child).await.unwrap() {
        MeshIngest::Accepted(e) => assert!(e.duplicate, "redelivery flagged duplicate"),
        other => panic!("redelivery should be accepted-duplicate, got {other:?}"),
    }

    // Counter bumped exactly once.
    assert_eq!(
        s.thread_summary(&root_id)
            .await
            .unwrap()
            .unwrap()
            .descendant_count,
        1
    );
}

// ---- fingerprint mismatch refusal ------------------------------------------

#[tokio::test]
async fn fingerprint_mismatch_refuses_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.db");

    let s = HistoryStore::open(&path, "community-A").expect("first open writes fingerprint");
    drop(s);

    let err = match HistoryStore::open(&path, "community-B") {
        Ok(_) => panic!("mismatched fingerprint must refuse"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("fingerprint mismatch"),
        "got: {err}"
    );

    // Re-opening with the original fingerprint still works.
    HistoryStore::open(&path, "community-A").expect("matching fingerprint reopens");
}

// ---- id canonicalization ---------------------------------------------------

#[tokio::test]
async fn id_canonicalization_rules() {
    let upper = "A".repeat(64);
    assert_eq!(canonical_event_id(&upper).unwrap(), "a".repeat(64));
    assert!(canonical_event_id("not-hex").is_err());
    assert!(canonical_event_id(&"a".repeat(63)).is_err(), "too short");
    assert!(
        canonical_event_id(&"g".repeat(64)).is_err(),
        "non-hex chars"
    );

    // A mixed-case marker id still resolves to the stored (lowercase) parent.
    let s = store();
    let a = Keys::generate();
    let root = msg(&a, "root", 1000, vec![]);
    let root_id = root.id.to_hex();
    accept_local(&s, &root).await;
    let upper_ref = root_id.to_uppercase();
    let r1 = msg(&a, "reply", 1001, vec![e_marked(&upper_ref, "reply")]);
    accept_local(&s, &r1).await;
    assert_eq!(
        s.thread_summary(&root_id)
            .await
            .unwrap()
            .unwrap()
            .reply_count,
        1,
        "uppercase-hex marker canonicalizes to the lowercase parent id"
    );
}

// ---- window keyset: same-second ties + exact-multiple exhaustion -----------

#[tokio::test]
async fn window_exact_multiple_page_reports_has_more_false() {
    let s = store();
    let a = Keys::generate();
    // Four distinct top-level roots, all in the same second (id-tie-break path).
    let mut ids = Vec::new();
    for i in 0..4 {
        let ev = msg(&a, &format!("root-{i}"), 2000, vec![]);
        ids.push(ev.id.to_hex());
        accept_local(&s, &ev).await;
    }

    // Page 1 of 2: has_more true.
    let p1 = s.channel_window(CH, 2, None).await.unwrap();
    assert_eq!(p1.rows.len(), 2);
    assert!(p1.bounds.has_more);
    let cursor: Option<WindowCursor> = p1.bounds.next_cursor.clone();
    assert!(cursor.is_some());

    // Page 2 (exact-multiple final page): exactly 2 rows, has_more MUST be false.
    let p2 = s.channel_window(CH, 2, cursor).await.unwrap();
    assert_eq!(p2.rows.len(), 2);
    assert!(
        !p2.bounds.has_more,
        "exact-multiple final page reports has_more=false (rows<limit proves nothing)"
    );
    assert!(p2.bounds.next_cursor.is_none());

    // No loss / no dup across the two same-second pages.
    let mut seen: Vec<String> = p1
        .rows
        .iter()
        .chain(p2.rows.iter())
        .map(|e| e.id.to_hex())
        .collect();
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen.len(),
        4,
        "all four same-second roots paged exactly once"
    );
}

// ---- orphan TTL reap -------------------------------------------------------

#[tokio::test]
async fn orphan_ttl_reap() {
    let s = store();
    let a = Keys::generate();
    // Park an orphan (parent never arrives).
    let fake_parent = "c".repeat(64);
    let orphan = msg(&a, "orphan", 1001, vec![e_marked(&fake_parent, "reply")]);
    assert_eq!(s.ingest_mesh(&orphan).await.unwrap(), MeshIngest::Parked);

    // received_at was wall-clock now; reap with a future `now` beyond the TTL.
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let reaped = s
        .reap_orphans(Duration::from_secs(3600), now + 7200)
        .await
        .unwrap();
    assert_eq!(reaped, 1, "the stale orphan is reaped");
}

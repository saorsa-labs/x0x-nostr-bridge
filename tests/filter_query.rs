//! WP1b — general filter-query surface conformance.
//!
//! Exercises `HistoryStore::{query, count, search, events_by_ids,
//! store_relay_authored}`: filter combinations (ids/kinds/authors/generic tags),
//! the served-state invariant (parked/quarantined/deleted rows are never
//! returned), FTS search with p-gated exclusion, count/query parity, offset
//! paging, and relay-authored + client replaceable dedup.

use nostr::{Event, EventBuilder, Keys, Kind, TagKind, Timestamp};
use x0x_nostr_bridge::history::types::{LocalIngest, MeshIngest, RelayStoreOutcome};
use x0x_nostr_bridge::history::{FilterSpec, HistoryStore};

const CH: &str = "550e8400-e29b-41d4-a716-446655440000";
const FP: &str = "wp1b-filter-query";

fn store() -> HistoryStore {
    HistoryStore::open_in_memory(FP).expect("open in-memory history store")
}

fn tag(name: &str, values: &[&str]) -> nostr::Tag {
    nostr::Tag::custom(
        TagKind::custom(name.to_string()),
        values.iter().map(|s| s.to_string()),
    )
}

fn h(channel: &str) -> nostr::Tag {
    tag("h", &[channel])
}

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

/// Kind-9 stream message in channel `CH`.
fn msg(keys: &Keys, content: &str, created_at: u64, mut tags: Vec<nostr::Tag>) -> Event {
    tags.insert(0, h(CH));
    build(keys, 9, content, created_at, tags)
}

async fn accept(s: &HistoryStore, ev: &Event) {
    match s.ingest_local(ev).await.expect("ingest_local") {
        LocalIngest::Accepted(_) => {}
        LocalIngest::Rejected(r) => panic!("expected accept, got reject: {r}"),
    }
}

fn ids_of(evs: &[Event]) -> Vec<String> {
    evs.iter().map(|e| e.id.to_hex()).collect()
}

fn spec() -> FilterSpec {
    FilterSpec::default()
}

// ---- filter combinations ---------------------------------------------------

#[tokio::test]
async fn query_by_ids_kinds_authors() {
    let s = store();
    let (a, b) = (Keys::generate(), Keys::generate());
    let m1 = msg(&a, "from a", 1000, vec![]);
    let m2 = msg(&b, "from b", 1001, vec![]);
    let r = build(
        &a,
        7,
        "reaction",
        1002,
        vec![h(CH), tag("e", &[&m1.id.to_hex()])],
    );
    accept(&s, &m1).await;
    accept(&s, &m2).await;
    accept(&s, &r).await;

    // by ids
    let by_id = s
        .query(
            &FilterSpec {
                ids: vec![m1.id.to_hex()],
                ..spec()
            },
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(ids_of(&by_id), vec![m1.id.to_hex()]);

    // by kinds
    let kind9 = s
        .query(
            &FilterSpec {
                kinds: vec![9],
                ..spec()
            },
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(kind9.len(), 2, "two kind-9 messages");

    // author + kind narrowing
    let a_kind9 = s
        .query(
            &FilterSpec {
                kinds: vec![9],
                authors: vec![a.public_key().to_hex()],
                ..spec()
            },
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(ids_of(&a_kind9), vec![m1.id.to_hex()]);
}

#[tokio::test]
async fn query_by_h_e_p_tags() {
    let s = store();
    let (a, target) = (Keys::generate(), Keys::generate());
    let referenced = msg(&a, "referenced", 1000, vec![]);
    accept(&s, &referenced).await;
    // A message that #e-references `referenced` and #p-references `target`.
    let reply = msg(
        &a,
        "mentions",
        1001,
        vec![
            e_marked(&referenced.id.to_hex(), "reply"),
            tag("p", &[&target.public_key().to_hex()]),
        ],
    );
    accept(&s, &reply).await;

    // #h scoping returns both.
    let by_h = s
        .query(
            // #h matches case-insensitively
            &spec().with_tag("h", [CH.to_uppercase()]),
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(by_h.len(), 2);

    // #e finds the reply.
    let by_e = s
        .query(&spec().with_tag("e", [referenced.id.to_hex()]), 10, 0)
        .await
        .unwrap();
    assert_eq!(ids_of(&by_e), vec![reply.id.to_hex()]);

    // #p finds the reply.
    let by_p = s
        .query(&spec().with_tag("p", [target.public_key().to_hex()]), 10, 0)
        .await
        .unwrap();
    assert_eq!(ids_of(&by_p), vec![reply.id.to_hex()]);
}

// ---- served-state invariant ------------------------------------------------

#[tokio::test]
async fn parked_quarantined_deleted_are_never_returned() {
    let s = store();
    let a = Keys::generate();
    let root = msg(&a, "root", 1000, vec![]);
    accept(&s, &root).await;
    let root_id = root.id.to_hex();
    let child = msg(&a, "child", 1001, vec![e_marked(&root_id, "reply")]);
    accept(&s, &child).await;

    // Parked: a mesh reply whose parent has not arrived.
    let ghost_parent = "d".repeat(64);
    let parked = msg(&a, "parked", 1002, vec![e_marked(&ghost_parent, "reply")]);
    assert_eq!(s.ingest_mesh(&parked).await.unwrap(), MeshIngest::Parked);

    // Quarantined: a mesh reply with a wrong root (parent = child exists).
    let wrong_root = "e".repeat(64);
    let quarantined = msg(
        &a,
        "quarantined",
        1003,
        vec![
            e_marked(&wrong_root, "root"),
            e_marked(&child.id.to_hex(), "reply"),
        ],
    );
    assert!(matches!(
        s.ingest_mesh(&quarantined).await.unwrap(),
        MeshIngest::Quarantined(_)
    ));

    // Deleted: soft-delete the child.
    let del = build(
        &a,
        5,
        "del",
        1004,
        vec![h(CH), tag("e", &[&child.id.to_hex()])],
    );
    accept(&s, &del).await;

    let kind9 = s
        .query(
            &FilterSpec {
                kinds: vec![9],
                ..spec()
            },
            50,
            0,
        )
        .await
        .unwrap();
    let got = ids_of(&kind9);
    assert!(got.contains(&root_id), "root still served");
    assert!(!got.contains(&parked.id.to_hex()), "parked invisible");
    assert!(
        !got.contains(&quarantined.id.to_hex()),
        "quarantined invisible"
    );
    assert!(!got.contains(&child.id.to_hex()), "deleted reply invisible");

    // But the deletion event itself is a normal, servable event.
    let kind5 = s
        .query(
            &FilterSpec {
                kinds: vec![5],
                ..spec()
            },
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(ids_of(&kind5), vec![del.id.to_hex()]);
}

// ---- search ----------------------------------------------------------------

#[tokio::test]
async fn search_hit_and_pgated_exclusion() {
    let s = store();
    let a = Keys::generate();
    accept(&s, &msg(&a, "rust async programming", 1000, vec![])).await;
    accept(&s, &msg(&a, "garden tomatoes recipe", 1001, vec![])).await;
    // A p-gated-shaped kind (say 1059 gift wrap) whose content also matches.
    accept(&s, &build(&a, 1059, "rust secret", 1002, vec![h(CH)])).await;

    // Plain search hits both "rust" docs (kind 9 + kind 1059).
    let all = s.search("rust", &[], Some(CH), &[], 10).await.unwrap();
    assert_eq!(all.len(), 2);

    // Narrow to kind 9.
    let k9 = s.search("rust", &[9], Some(CH), &[], 10).await.unwrap();
    assert_eq!(k9.len(), 1);
    assert!(k9[0].content.contains("async"));

    // p-gated exclusion: 1059 must be unsearchable.
    let excluded = s.search("rust", &[], Some(CH), &[1059], 10).await.unwrap();
    assert_eq!(excluded.len(), 1, "gift-wrap kind excluded from search");
    assert!(excluded[0].content.contains("async"));

    // Miss.
    assert!(s
        .search("blockchain", &[], None, &[], 10)
        .await
        .unwrap()
        .is_empty());
    // Deleted content is unsearchable.
    let target = &s.search("tomatoes", &[], None, &[], 10).await.unwrap()[0]
        .id
        .to_hex();
    accept(
        &s,
        &build(&a, 5, "d", 1005, vec![h(CH), tag("e", &[target])]),
    )
    .await;
    assert!(s
        .search("tomatoes", &[], None, &[], 10)
        .await
        .unwrap()
        .is_empty());
}

// ---- count parity ----------------------------------------------------------

#[tokio::test]
async fn count_matches_query() {
    let s = store();
    let a = Keys::generate();
    for i in 0..5 {
        accept(&s, &msg(&a, &format!("m{i}"), 1000 + i, vec![])).await;
    }
    let f = FilterSpec {
        kinds: vec![9],
        ..spec()
    };
    let q = s.query(&f, 500, 0).await.unwrap();
    let c = s.count(&f).await.unwrap();
    assert_eq!(c, 5);
    assert_eq!(c, q.len() as u64);
}

// ---- offset paging ---------------------------------------------------------

#[tokio::test]
async fn query_offset_paging_directory() {
    // kind:0 directory across four distinct authors, offset-paged.
    let s = store();
    for i in 0..4 {
        let k = Keys::generate();
        accept(&s, &build(&k, 0, &format!("profile-{i}"), 1000 + i, vec![])).await;
    }
    let f = FilterSpec {
        kinds: vec![0],
        ..spec()
    };
    let p1 = s.query(&f, 2, 0).await.unwrap();
    let p2 = s.query(&f, 2, 2).await.unwrap();
    assert_eq!(p1.len(), 2);
    assert_eq!(p2.len(), 2);
    let mut seen: Vec<String> = ids_of(&p1).into_iter().chain(ids_of(&p2)).collect();
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen.len(),
        4,
        "offset paging covers all four with no overlap"
    );
}

// ---- events_by_ids ---------------------------------------------------------

#[tokio::test]
async fn events_by_ids_fetch() {
    let s = store();
    let a = Keys::generate();
    let m1 = msg(&a, "one", 1000, vec![]);
    let m2 = msg(&a, "two", 1001, vec![]);
    accept(&s, &m1).await;
    accept(&s, &m2).await;
    assert!(s.events_by_ids(&[]).await.unwrap().is_empty());
    let got = s
        .events_by_ids(&[m1.id.to_hex(), m2.id.to_hex(), "f".repeat(64)])
        .await
        .unwrap();
    let mut ids = ids_of(&got);
    ids.sort();
    let mut want = vec![m1.id.to_hex(), m2.id.to_hex()];
    want.sort();
    assert_eq!(ids, want, "known ids returned, unknown id ignored");
}

// ---- known_channels --------------------------------------------------------

#[tokio::test]
async fn known_channels_distinct() {
    let s = store();
    let a = Keys::generate();
    accept(&s, &msg(&a, "in CH", 1000, vec![])).await;
    accept(&s, &msg(&a, "also CH", 1001, vec![])).await;
    // A message in a different channel.
    accept(&s, &build(&a, 9, "other", 1002, vec![h("other-channel")])).await;
    // A channel-less event (kind 0) contributes no channel.
    accept(&s, &build(&a, 0, "profile", 1003, vec![])).await;

    let mut chans = s.known_channels().await.unwrap();
    chans.sort();
    assert_eq!(chans, vec![CH.to_string(), "other-channel".to_string()]);
}

// ---- relay-authored + client replaceable dedup -----------------------------

fn seed_39000(relay: &Keys, channel: &str, name: &str, created_at: u64) -> Event {
    build(
        relay,
        39000,
        name,
        created_at,
        vec![h(channel), tag("d", &[channel]), tag("name", &[name])],
    )
}

#[tokio::test]
async fn relay_authored_seed_is_servable_and_dedups() {
    let s = store();
    let relay = Keys::generate();
    let seed = seed_39000(&relay, CH, "general", 1000);
    assert_eq!(
        s.store_relay_authored(&seed).await.unwrap(),
        RelayStoreOutcome::Inserted
    );

    // assertRelaySeeded()-shaped poll.
    let got = s
        .query(
            &FilterSpec {
                kinds: vec![39000],
                ..spec()
            }
            .with_tag("h", [CH.to_string()]),
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(ids_of(&got), vec![seed.id.to_hex()], "seed 39000 servable");

    // A client cannot author it.
    match s
        .ingest_local(&seed_39000(&relay, CH, "spoof", 1001))
        .await
        .unwrap()
    {
        LocalIngest::Rejected(r) => assert!(r.contains("relay-authored")),
        LocalIngest::Accepted(_) => panic!("client 39000 must be rejected"),
    }

    // Newer relay metadata replaces; older is stale.
    let v2 = seed_39000(&relay, CH, "v2", 2000);
    assert_eq!(
        s.store_relay_authored(&v2).await.unwrap(),
        RelayStoreOutcome::Replaced
    );
    assert_eq!(
        s.store_relay_authored(&seed_39000(&relay, CH, "v0", 500))
            .await
            .unwrap(),
        RelayStoreOutcome::StaleRejected
    );
    let latest = s
        .query(
            &FilterSpec {
                kinds: vec![39000],
                ..spec()
            },
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(
        ids_of(&latest),
        vec![v2.id.to_hex()],
        "only latest survives"
    );
}

#[tokio::test]
async fn client_replaceable_kind0_dedup_via_ingest() {
    // Kind 0 (profile) is replaceable; the opaque ingest branch must dedup it.
    let s = store();
    let a = Keys::generate();
    accept(&s, &build(&a, 0, "old profile", 1000, vec![])).await;
    accept(&s, &build(&a, 0, "new profile", 2000, vec![])).await;

    let got = s
        .query(
            &FilterSpec {
                kinds: vec![0],
                authors: vec![a.public_key().to_hex()],
                ..spec()
            },
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "only latest profile kept");
    assert_eq!(got[0].content, "new profile");
}

// ---- generic tag dimensions ------------------------------------------------
//
// WHY: an unmodelled filter dimension does not fail closed — it WIDENS the
// result set. Buzz resolves an addressable (NIP-33/NIP-29) channel with
// `{kinds:[39000], "#d":[channelId], limit:1}`; a bridge that drops `#d`
// returns every 39000, the client takes `[0]`, and reads the wrong channel's
// metadata. These tests pin that every tag name the caller supplies is
// evaluated, not just the `#h`/`#e`/`#p` the store once had columns for.

const CH_B: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
const CH_C: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

#[tokio::test]
async fn addressable_d_lookup_returns_only_that_channel() {
    let s = store();
    let relay = Keys::generate();
    for (ch, name) in [(CH, "general"), (CH_B, "random"), (CH_C, "dev")] {
        assert_eq!(
            s.store_relay_authored(&seed_39000(&relay, ch, name, 1000))
                .await
                .unwrap(),
            RelayStoreOutcome::Inserted
        );
    }

    let got = s
        .query(
            &FilterSpec {
                kinds: vec![39000],
                ..spec()
            }
            .with_tag("d", [CH_B.to_string()]),
            1,
            0,
        )
        .await
        .unwrap();

    // The `limit:1` is what makes a dropped `#d` fatal rather than merely
    // wasteful: the client takes row [0] and never sees the mismatch.
    assert_eq!(got.len(), 1, "#d must narrow to one addressable row");
    assert_eq!(got[0].content, "random");
    assert_eq!(
        s.count(
            &FilterSpec {
                kinds: vec![39000],
                ..spec()
            }
            .with_tag("d", [CH_B.to_string()])
        )
        .await
        .unwrap(),
        1,
        "count must apply #d exactly as query does"
    );
}

#[tokio::test]
async fn tag_names_and_while_values_or() {
    let s = store();
    let relay = Keys::generate();
    // Two channels, each carrying a distinct `d`; `h` scopes them separately.
    let general = build(&relay, 39000, "general", 1000, vec![h(CH), tag("d", &[CH])]);
    let random = build(
        &relay,
        39000,
        "random",
        1001,
        vec![h(CH_B), tag("d", &[CH_B])],
    );
    s.store_relay_authored(&general).await.unwrap();
    s.store_relay_authored(&random).await.unwrap();

    // OR within one name: both `d` values match.
    let both = s
        .query(
            &spec().with_tag("d", [CH.to_string(), CH_B.to_string()]),
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(both.len(), 2, "values within one tag name are OR'd");

    // AND across names: `#d`=CH_B with `#h`=CH is unsatisfiable.
    let crossed = s
        .query(
            &spec()
                .with_tag("d", [CH_B.to_string()])
                .with_tag("h", [CH.to_string()]),
            10,
            0,
        )
        .await
        .unwrap();
    assert!(
        crossed.is_empty(),
        "distinct tag names must AND, not OR: got {:?}",
        ids_of(&crossed)
    );

    // ...and the satisfiable pairing still resolves.
    let matched = s
        .query(
            &spec()
                .with_tag("d", [CH_B.to_string()])
                .with_tag("h", [CH_B.to_string()]),
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(ids_of(&matched), vec![random.id.to_hex()]);
}

#[tokio::test]
async fn multi_char_tag_name_does_not_over_match() {
    let s = store();
    let relay = Keys::generate();
    // `seed_39000` emits a multi-character `name` tag — a dimension the store
    // never had a column for. It must be evaluated, not dropped.
    s.store_relay_authored(&seed_39000(&relay, CH, "general", 1000))
        .await
        .unwrap();
    s.store_relay_authored(&seed_39000(&relay, CH_B, "random", 1001))
        .await
        .unwrap();

    let got = s
        .query(&spec().with_tag("name", ["random".to_string()]), 10, 0)
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "unmodelled tag name must still constrain");
    assert_eq!(got[0].content, "random");

    // A tag name no stored event carries matches nothing — it must never fall
    // through to "unconstrained".
    let none = s
        .query(&spec().with_tag("zzz", ["anything".to_string()]), 10, 0)
        .await
        .unwrap();
    assert!(
        none.is_empty(),
        "unknown tag name must not match everything"
    );
}

#[tokio::test]
async fn empty_tag_value_list_is_unconstrained_not_empty() {
    let s = store();
    let a = Keys::generate();
    accept(&s, &msg(&a, "hello", 1000, vec![])).await;

    // The empty vec is the UNCONSTRAINED sentinel at this layer; a nostr
    // empty-`Some`-set (which matches nothing) is the ADAPTER's job to turn
    // into an early empty return — see `history_adapter::to_filter_spec`.
    let got = s
        .query(&spec().with_tag("d", Vec::<String>::new()), 10, 0)
        .await
        .unwrap();
    assert_eq!(got.len(), 1, "empty value list means unconstrained here");
}

//! Demo seed (WP4 slice). Owner: wp2-http.
//!
//! Reproduces the effect of Buzz's absent `setup-desktop-test-data.sh` so
//! `assertRelaySeeded()` passes from startup. That script is not in our tree,
//! which is how the seed drifted from what the suite assumes in the first
//! place, so the channel set below is pinned by [`seeded_channels`] and covered
//! by a test rather than left implicit.
//!
//! The four channels the e2e suite treats as ambient — it opens them without
//! creating or joining them first:
//!
//! | name | type | asserted by |
//! |------|--------|-------------|
//! | `general` | stream | `stream.spec.ts` "loads channels from the relay" |
//! | `random` | stream | same |
//! | `watercooler` | forum | `smoke.spec.ts:95`, `integration.spec.ts:409`, `channels.spec.ts` |
//! | `alice-tyler` | dm | `stream.spec.ts`, `tests.md §2c` |
//!
//! All four carry every test identity in their 39002: the specs assume the
//! active identity is already a member, and the sidebar only renders channels
//! whose `isMember` is true.

use std::sync::Arc;

use uuid::Uuid;

use crate::nip29;
use crate::relay::AppState;
use crate::relay_identity::now_secs;

/// The four test identities seeded as members of `general` (tests.md §3).
pub const TEST_MEMBERS: [(&str, &str); 4] = [
    (
        "tyler",
        "e5ebc6cdb579be112e336cc319b5989b4bb6af11786ea90dbe52b5f08d741b34",
    ),
    (
        "alice",
        "953d3363262e86b770419834c53d2446409db6d918a57f8f339d495d54ab001f",
    ),
    (
        "bob",
        "bb22a5299220cad76ffd46190ccbeede8ab5dc260faa28b6e5a2cb31b9aff260",
    ),
    (
        "charlie",
        "554cef57437abac34522ac2c9f0490d685b72c80478cf9f7ed6f9570ee8624ea",
    ),
];

/// Deterministic DM channel id: `uuid5(NAMESPACE_DNS, "buzz.channel.dm.<name>")`
/// (tests.md §2c).
pub fn dm_channel_id(name: &str) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        format!("buzz.channel.dm.{name}").as_bytes(),
    )
    .to_string()
}

/// Deterministic non-DM channel id: `uuid5(NAMESPACE_DNS, "buzz.channel.<name>")`.
///
/// Buzz itself mints a `crypto.randomUUID()` per channel, so a uuid shape is
/// what the client expects to round-trip; deriving it from the name keeps the
/// seed stable across restarts, which the specs rely on when they reopen a
/// seeded channel in a later test.
pub fn channel_id(name: &str) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_DNS,
        format!("buzz.channel.{name}").as_bytes(),
    )
    .to_string()
}

/// The channels the seed materializes, as `(id, name, channel_type, private)`.
///
/// **Every** id is uuid5-derived, including `general`. It was briefly seeded as
/// the literal `"general"` on the grounds that the bridge's own tests use that
/// string as a channel literal — but those tests post their own rows and never
/// read the seed, so the concern was local while the breakage was not:
/// `parity-ancestor-island.spec.ts:33-34` addresses the seeded channel as
/// `9f28288a-d724-587a-9709-92dc7f967110`, exactly `channel_id("general")`, so
/// every row it seeded landed in a channel the client never opens.
pub fn seeded_channels() -> Vec<(String, &'static str, &'static str, bool)> {
    vec![
        (channel_id("general"), "general", "stream", false),
        (channel_id("random"), "random", "stream", false),
        (channel_id("watercooler"), "watercooler", "forum", false),
        (
            dm_channel_id("alice-tyler"),
            "alice-tyler",
            "dm",
            // A DM is not browsable; the client reads that off the `private` tag.
            true,
        ),
    ]
}

/// Seed the demo community. Idempotent-ish: re-running stores duplicates as
/// `Duplicate` (no error).
pub async fn seed_demo(state: &Arc<AppState>) -> anyhow::Result<()> {
    let now = now_secs();
    let member_pubkeys: Vec<String> = TEST_MEMBERS.iter().map(|(_, pk)| pk.to_string()).collect();
    // The DM is between tyler and alice specifically — its id is derived from
    // those two names, so seeding bob and charlie into it would contradict it.
    let dm_members: Vec<String> = member_pubkeys[..2].to_vec();

    // Every channel goes through `nip29::seed_channel`, the same builder a
    // kind-9007 create uses. Hand-rolling the tags here is what let the seed
    // drift out of the client's contract: it used to emit only `d`/`name`/`h`,
    // leaving `general` with no description and typing the DM as a `stream`.
    for (id, name, channel_type, private) in seeded_channels() {
        let members = if channel_type == "dm" {
            &dm_members
        } else {
            &member_pubkeys
        };
        nip29::seed_channel(state, &id, name, channel_type, private, members)
            .await
            .map_err(|e| anyhow::anyhow!("seeding {name} failed: {e}"))?;
    }

    // relay-signed 13534 membership list for `general` (dialect.md §3). This is
    // a separate NIP-43 surface from the 39002 above, not a duplicate of it. It
    // has to name the same channel id, or it describes a channel nobody opens.
    let list =
        state
            .identity
            .membership_list_event(&channel_id("general"), &member_pubkeys, now)?;
    state.engine.seed_event(&list).await?;

    tracing::info!(
        channels = seeded_channels().len(),
        dm_channel = %dm_channel_id("alice-tyler"),
        "demo seed complete"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dm_channel_id_is_deterministic_uuid5() {
        // Stable across runs and equal to uuid5(DNS, "buzz.channel.dm.alice-tyler").
        let expected =
            Uuid::new_v5(&Uuid::NAMESPACE_DNS, b"buzz.channel.dm.alice-tyler").to_string();
        assert_eq!(dm_channel_id("alice-tyler"), expected);
        // sanity: a valid lowercased channel id
        assert!(dm_channel_id("alice-tyler")
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }
}

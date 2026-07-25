//! Demo seed (WP4 slice). Owner: wp2-http.
//!
//! Reproduces the effect of Buzz's absent `setup-desktop-test-data.sh` so
//! `assertRelaySeeded()` passes from startup: a `general` channel (kind-39000,
//! tags incl. `["name","general"]`), members tyler/alice/bob/charlie, and the
//! `alice-tyler` DM channel with the deterministic uuid5 id (tests.md §2/§3).

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

/// Seed the demo community. Idempotent-ish: re-running stores duplicates as
/// `Duplicate` (no error).
pub async fn seed_demo(state: &Arc<AppState>) -> anyhow::Result<()> {
    let now = now_secs();
    let member_pubkeys: Vec<String> = TEST_MEMBERS.iter().map(|(_, pk)| pk.to_string()).collect();

    // `general` — 39000 + 39002, built by the same code path a kind-9007
    // create goes through (`nip29::seed_channel`). Hand-rolling the tags here
    // is what let the seed drift out of the client's contract: it used to emit
    // only `d`/`name`/`h`, leaving `general` with no description and typing
    // the DM below as a `stream`.
    nip29::seed_channel(
        state,
        "general",
        "general",
        "stream",
        false,
        &member_pubkeys,
    )
    .await
    .map_err(|e| anyhow::anyhow!("seeding general failed: {e}"))?;

    // relay-signed 13534 membership list for `general` (dialect.md §3). This is
    // a separate NIP-43 surface from the 39002 above, not a duplicate of it.
    let list = state
        .identity
        .membership_list_event("general", &member_pubkeys, now)?;
    state.engine.seed_event(&list).await?;

    // alice-tyler DM channel. `["t","dm"]` is load-bearing: the client types a
    // channel from `getTag("t") ?? "stream"`, and a DM mistyped as a stream
    // misses the dm-specific render paths entirely.
    let dm_id = dm_channel_id("alice-tyler");
    let dm_members: Vec<String> = [TEST_MEMBERS[0], TEST_MEMBERS[1]]
        .iter()
        .map(|(_, pk)| pk.to_string())
        .collect();
    nip29::seed_channel(state, &dm_id, "alice-tyler", "dm", true, &dm_members)
        .await
        .map_err(|e| anyhow::anyhow!("seeding dm failed: {e}"))?;

    tracing::info!(dm_channel = %dm_id, "demo seed complete (general + members + DM)");
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

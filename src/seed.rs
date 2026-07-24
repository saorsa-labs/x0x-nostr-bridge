//! Demo seed (WP4 slice). Owner: wp2-http.
//!
//! Reproduces the effect of Buzz's absent `setup-desktop-test-data.sh` so
//! `assertRelaySeeded()` passes from startup: a `general` channel (kind-39000,
//! tags incl. `["name","general"]`), members tyler/alice/bob/charlie, and the
//! `alice-tyler` DM channel with the deterministic uuid5 id (tests.md §2/§3).

use std::sync::Arc;

use uuid::Uuid;

use crate::engine_api::Visibility;
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

    // general channel metadata (relay-signed 39000).
    let general = state
        .identity
        .channel_metadata_event("general", "general", now)?;
    state.engine.ingest_local(&general).await?;
    state
        .engine
        .seed_visibility("general", Visibility::Open)
        .await?;

    // members.
    let member_pubkeys: Vec<String> = TEST_MEMBERS.iter().map(|(_, pk)| pk.to_string()).collect();
    for pk in &member_pubkeys {
        state.engine.seed_member("general", pk).await?;
    }

    // relay-signed 13534 membership list for `general`.
    let list = state
        .identity
        .membership_list_event("general", &member_pubkeys, now)?;
    state.engine.ingest_local(&list).await?;

    // alice-tyler DM channel.
    let dm_id = dm_channel_id("alice-tyler");
    let dm = state
        .identity
        .channel_metadata_event(&dm_id, "alice-tyler", now)?;
    state.engine.ingest_local(&dm).await?;
    state
        .engine
        .seed_visibility(&dm_id, Visibility::Closed)
        .await?;
    for (_, pk) in &[TEST_MEMBERS[0], TEST_MEMBERS[1]] {
        state.engine.seed_member(&dm_id, pk).await?;
    }

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

//! Gossip → store/hub ingest, factored out of the `main.rs` ingest loop so the
//! adversarial tests can drive a single message through the path.

use tracing::warn;

use crate::engine_api::IngestOutcome;
use crate::proto;
use crate::relay::{publish_to_topics, AppState};
use crate::relay_identity::now_secs;
use crate::transport::GossipMessage;

/// Process one gossip message: decode → verify → topic-bind → store/fan-out.
///
/// - Verify the Schnorr signature (rejected events are dropped with a warn).
/// - Enforce topic binding: the event must arrive on a topic matching its own
///   `h` tags (or the global topic if it has none), else it is dropped.
/// - AUTH_KIND (22242) is dropped entirely (relay-internal; never stored or
///   dispatched from gossip).
/// - Ephemeral kinds (20000-29999) are live fan-out only — dispatched, never
///   stored.
/// - Everything else is stored; Inserted/Replaced are also dispatched live.
pub async fn ingest_one(state: &AppState, msg: &GossipMessage) {
    let ev: nostr::Event = match serde_json::from_slice(&msg.payload) {
        Ok(ev) => ev,
        Err(e) => {
            warn!(topic = %msg.topic, error = %e, "gossip payload is not a nostr event");
            return;
        }
    };
    if let Err(e) = proto::verify_event(&ev) {
        warn!(topic = %msg.topic, error = %e, "gossip event failed verification");
        return;
    }
    // GOSSIP-TOPIC-BINDING: a signed event must arrive on a topic that matches
    // its own `h` tags (or the global topic when it has none). A mismatch means
    // the event was misrouted (or deliberately injected onto the wrong channel)
    // and is dropped before store/dispatch.
    let allowed = proto::topics_for_event(&ev);
    if !allowed.iter().any(|t| t == &msg.topic) {
        warn!(
            topic = %msg.topic,
            event_id = %ev.id,
            "gossip event dropped: topic does not match its h tags"
        );
        return;
    }
    // C1/GOSSIP-EPHEMERAL-STORED: ephemeral kinds (20000-29999) are live
    // fan-out only — never stored. AUTH_KIND (22242) is relay-internal auth and
    // must never be stored OR dispatched from gossip (it carries challenge/
    // response material and has no business on the fabric).
    if ev.kind.as_u16() == proto::AUTH_KIND {
        warn!(event_id = %ev.id, "gossip AUTH-kind event dropped (never stored/dispatched)");
        return;
    }
    if proto::is_ephemeral(ev.kind) {
        state.hub.dispatch(&ev);
        return;
    }
    // Mesh door: park orphans / quarantine ancestry mismatches (invisible); a
    // stored event fans out live + re-emits any thread summaries post-commit.
    match state.engine.ingest_mesh(&ev).await {
        Ok(IngestOutcome::Stored { emits, .. }) => {
            state.hub.dispatch(&ev);
            for emit in emits {
                let Some(channel) = emit.channel_id else { continue };
                if let Ok(Some(summary)) =
                    state.engine.thread_summary(&channel, &emit.root_id).await
                {
                    if let Ok(overlay) = state.identity.thread_summary_event(&summary, now_secs()) {
                        publish_to_topics(&state.transport, &overlay).await;
                        state.hub.dispatch(&overlay);
                    }
                }
            }
        }
        // Duplicate / Parked / Quarantined / rejected: invisible, no dispatch.
        Ok(_) => {}
        Err(e) => warn!(error = %e, "mesh ingest failed"),
    }
}

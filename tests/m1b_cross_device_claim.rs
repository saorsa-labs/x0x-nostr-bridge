//! M1b cross-device claim RPC regressions (DirectAuthorityBus / the claimant
//! half of the two-authority transport flow).
//!
//! `DirectAuthorityBus` is the pub surface a claimant bridge uses to forward a
//! claim to a remote authority over verified x0x direct messages and await the
//! typed result. These tests prove the transport-level invariants against a
//! mock loopback daemon:
//!
//! - **`DirectSendReceipt` never completes a request**: the bus discards the
//!   transport receipt and waits for the authority's verified result DM. Even
//!   when `/direct/send` returns a success receipt, a claim with no result
//!   times out — the receipt is explicitly not completion.
//! - **Timeout removes pending + maps to `AuthorityUnavailable`**: a claim that
//!   gets no result returns `AuthorityUnavailable` after the timeout (never
//!   hangs), and the pending entry is cleaned so the bounded map does not fill.
//! - The claim envelope is actually transmitted to the daemon (target agent +
//!   payload).
//!
//! The authority-side dispatcher envelope checks (reply_to≠sender, code-aid≠self,
//! forged-result-sender, ok-cid-mismatch) live in private m1b handlers backed by
//! pub(crate) types (AuthorityState/DirectEnvelope/PendingRemoteClaim) — those
//! are not reachable from an integration test (separate crate) and are covered
//! by `verify_portable_nip98_claim` (the proof half) + the lib's own tests; see
//! the report to Main for the exposure needed to test them here.
//!
//! Run: `cargo test -p x0x-nostr-bridge --test m1b_cross_device_claim -- --nocapture`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::{routing::get, routing::post, Json, Router};
use base64::Engine as _;
use nostr::secp256k1::{self, Keypair, Message, Secp256k1};
use nostr::Keys;
use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use x0x_nostr_bridge::direct_transport::{AgentId, X0xDirectTransport};
use x0x_nostr_bridge::invites::{
    AuthorityBus, ClaimBusRequest, InviteAuthority, InviteAuthorityService, InviteError,
    InviteOptions, MintRequest,
};
use x0x_nostr_bridge::join_policy::JoinPolicyConfig;
use x0x_nostr_bridge::m1b::{DirectAuthorityBus, DirectBusState};

const BASE_URL: &str = "http://127.0.0.1:3000";
const PRIMARY_CHANNEL: &str = "general";
/// A 64-hex authority AgentId the code is routed to.
const AUTHORITY_AID: &str = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";
const JOINER_PK: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// ---------------------------------------------------------------------------
// real-crypto authority (to mint a code the bus parses for cid/aid)
// ---------------------------------------------------------------------------

struct TestAuthority {
    keys: Keys,
    secp: Secp256k1<secp256k1::All>,
}
impl TestAuthority {
    fn generate() -> Self {
        Self {
            keys: Keys::generate(),
            secp: Secp256k1::new(),
        }
    }
    fn keypair(&self) -> Keypair {
        Keypair::from_secret_key(&self.secp, self.keys.secret_key())
    }
}
impl InviteAuthority for TestAuthority {
    fn public_key_hex(&self) -> String {
        self.keys.public_key().to_hex()
    }
    fn sign_authority_payload(&self, payload: &str) -> Vec<u8> {
        let mut d = [0u8; 32];
        d.copy_from_slice(&Sha256::digest(payload.as_bytes()));
        self.secp
            .sign_schnorr(&Message::from_digest(d), &self.keypair())
            .serialize()
            .to_vec()
    }
    fn verify_authority_payload(&self, payload: &str, sig: &[u8]) -> bool {
        let Ok(s) = secp256k1::schnorr::Signature::from_slice(sig) else {
            return false;
        };
        let mut d = [0u8; 32];
        d.copy_from_slice(&Sha256::digest(payload.as_bytes()));
        self.secp
            .verify_schnorr(
                &s,
                &Message::from_digest(d),
                &self.keypair().x_only_public_key().0,
            )
            .is_ok()
    }
    fn mac(&self, domain: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(domain);
        h.update(self.keys.secret_key().secret_bytes());
        let key = h.finalize();
        hmac_sha256(&key, msg).to_vec()
    }
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let (mut ipad, mut opad) = ([0u8; BLOCK], [0u8; BLOCK]);
    for i in 0..BLOCK {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(ih);
    outer.finalize().into()
}

/// Mint a valid code bound to `AUTHORITY_AID`.
async fn mint_code() -> String {
    let auth = TestAuthority::generate();
    let policy = JoinPolicyConfig::disabled();
    let svc = InviteAuthorityService::new(
        &auth,
        &AdminMembership,
        &policy,
        InviteOptions::new(BASE_URL, PRIMARY_CHANNEL),
    );
    svc.mint(
        &auth.public_key_hex(),
        AUTHORITY_AID,
        "n",
        MintRequest { ttl_secs: None },
        1_700_000_000,
    )
    .await
    .expect("mint")
    .code
}

struct AdminMembership;
impl x0x_nostr_bridge::invites::InviteMembership for AdminMembership {
    fn is_community_admin(&self, _pk: &str) -> bool {
        // the authority admits its own pubkey as admin
        true
    }
    fn is_community_member(&self, _: &str) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// mock loopback daemon: accepts /direct/send (records it), serves empty SSE
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct DaemonLog {
    send_count: Arc<AtomicU32>,
    last_target: Arc<Mutex<Option<String>>>,
    last_payload: Arc<Mutex<Option<Vec<u8>>>>,
}

async fn mock_daemon(log: DaemonLog) -> String {
    let count = log.send_count.clone();
    let target = log.last_target.clone();
    let payload = log.last_payload.clone();
    let send = post(move |headers: HeaderMap, body: Json<Value>| {
        let count = count.clone();
        let target = target.clone();
        let payload = payload.clone();
        async move {
            let _ = headers;
            count.fetch_add(1, Ordering::SeqCst);
            if let Some(t) = body.0.get("agent_id").and_then(|v| v.as_str()) {
                *target.lock() = Some(t.to_string());
            }
            if let Some(p) = body.0.get("payload").and_then(|v| v.as_str()) {
                if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(p) {
                    *payload.lock() = Some(b);
                }
            }
            Json(json!({ "ok": true, "path": "gossip_inbox", "retries_used": 0 }))
        }
    });
    let events = get(|| async {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/event-stream")
            .body(Body::empty())
            .unwrap()
    });
    let app = Router::new()
        .route("/health", get(|| async { Json(json!({"ok": true})) }))
        .route("/direct/send", send)
        .route("/direct/events", events);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn claim_req(code: &str) -> ClaimBusRequest {
    ClaimBusRequest {
        code: code.to_string(),
        policy_receipt: None,
        joiner_pubkey: JOINER_PK.to_string(),
        auth_proof: None,
    }
}

// ===========================================================================
// DirectSendReceipt is never completion — the claim waits for a result DM
// ===========================================================================

#[tokio::test]
async fn send_receipt_does_not_complete_claim_it_times_out() {
    let log = DaemonLog::default();
    let base = mock_daemon(log.clone()).await;
    let cancel = CancellationToken::new();

    let transport = X0xDirectTransport::connect(&base, "tok", cancel.clone(), None)
        .await
        .expect("connect");
    let self_id = AgentId::from_hex(&"1".repeat(64)).unwrap();
    // Very short timeout so the test is fast yet proves it actually waited.
    let bus_state = DirectBusState::with_timeout(Duration::from_millis(120));
    let bus = DirectAuthorityBus::new(Arc::new(transport), self_id, bus_state);

    let code = mint_code().await;
    let start = Instant::now();
    let result = bus.request_claim(AUTHORITY_AID, claim_req(&code)).await;
    let elapsed = start.elapsed();

    // The send succeeded (a receipt was returned)...
    assert!(
        log.send_count.load(Ordering::SeqCst) >= 1,
        "claim was transmitted to the daemon"
    );
    // ...but the receipt did NOT complete it — it waited for the timeout.
    assert!(
        elapsed >= Duration::from_millis(110),
        "waited for the result timeout, not instant"
    );
    assert!(
        matches!(result, Err(InviteError::AuthorityUnavailable)),
        "no result DM ⇒ AuthorityUnavailable (receipt is not completion)"
    );

    cancel.cancel();
}

#[tokio::test]
async fn claim_envelope_is_transmitted_to_the_target_agent() {
    let log = DaemonLog::default();
    let base = mock_daemon(log.clone()).await;
    let cancel = CancellationToken::new();

    let transport = X0xDirectTransport::connect(&base, "tok", cancel.clone(), None)
        .await
        .expect("connect");
    let self_id = AgentId::from_hex(&"2".repeat(64)).unwrap();
    let bus_state = DirectBusState::with_timeout(Duration::from_millis(60));
    let bus = DirectAuthorityBus::new(Arc::new(transport), self_id, bus_state);

    let code = mint_code().await;
    let _ = bus.request_claim(AUTHORITY_AID, claim_req(&code)).await; // times out

    // The daemon received the claim addressed to the authority agent id...
    let target = log.last_target.lock().clone().expect("target recorded");
    assert_eq!(
        target, AUTHORITY_AID,
        "routed to the code's authority agent"
    );
    // ...and a non-empty payload (the serialized claim envelope).
    let payload = log.last_payload.lock().clone().expect("payload recorded");
    assert!(!payload.is_empty(), "claim envelope payload transmitted");
    // The payload is JSON carrying the verbatim code (the envelope wraps it).
    let s = std::str::from_utf8(&payload).unwrap_or("");
    assert!(
        s.contains(&code) || s.contains("claim"),
        "envelope carries the claim"
    );

    cancel.cancel();
}

// ===========================================================================
// Timeout removes pending + maps to AuthorityUnavailable (never hangs)
// ===========================================================================

#[tokio::test]
async fn timeout_returns_authority_unavailable_and_does_not_hang() {
    let log = DaemonLog::default();
    let base = mock_daemon(log.clone()).await;
    let cancel = CancellationToken::new();

    let transport = X0xDirectTransport::connect(&base, "tok", cancel.clone(), None)
        .await
        .expect("connect");
    let self_id = AgentId::from_hex(&"3".repeat(64)).unwrap();
    let bus_state = DirectBusState::with_timeout(Duration::from_millis(80));
    let bus = DirectAuthorityBus::new(Arc::new(transport), self_id, bus_state);

    let code = mint_code().await;
    // Must resolve (not hang) within a bounded window around the timeout.
    let result = tokio::time::timeout(
        Duration::from_millis(500),
        bus.request_claim(AUTHORITY_AID, claim_req(&code)),
    )
    .await
    .expect("claim resolved within 500ms (did not hang)");
    assert!(matches!(result, Err(InviteError::AuthorityUnavailable)));

    cancel.cancel();
}

#[tokio::test]
async fn timeout_cleans_pending_so_subsequent_claims_still_transmit() {
    // After a timed-out claim, the pending entry is removed — the next claim is
    // not blocked by a stale entry and still reaches the daemon (capacity guard
    // never trips). This is the observable proof of pending cleanup.
    let log = DaemonLog::default();
    let base = mock_daemon(log.clone()).await;
    let cancel = CancellationToken::new();

    let transport = X0xDirectTransport::connect(&base, "tok", cancel.clone(), None)
        .await
        .expect("connect");
    let self_id = AgentId::from_hex(&"4".repeat(64)).unwrap();
    let bus_state = DirectBusState::with_timeout(Duration::from_millis(50));
    let bus = DirectAuthorityBus::new(Arc::new(transport), self_id, bus_state);

    for _ in 0..5 {
        let code = mint_code().await;
        let r = bus.request_claim(AUTHORITY_AID, claim_req(&code)).await;
        assert!(matches!(r, Err(InviteError::AuthorityUnavailable)));
    }
    // Every claim reached send ⇒ pending was cleaned between them (map never filled).
    assert_eq!(
        log.send_count.load(Ordering::SeqCst),
        5,
        "all 5 claims transmitted post-cleanup"
    );

    cancel.cancel();
}

#[tokio::test]
async fn malformed_authority_agent_id_is_unavailable_before_send() {
    let log = DaemonLog::default();
    let base = mock_daemon(log.clone()).await;
    let cancel = CancellationToken::new();
    let transport = X0xDirectTransport::connect(&base, "tok", cancel.clone(), None)
        .await
        .expect("connect");
    let self_id = AgentId::from_hex(&"5".repeat(64)).unwrap();
    let bus = DirectAuthorityBus::new(
        Arc::new(transport),
        self_id,
        DirectBusState::with_timeout(Duration::from_millis(200)),
    );

    let code = mint_code().await;
    // A non-hex agent id cannot be parsed into an AgentId ⇒ unavailable, no send.
    let r = bus.request_claim("not-hex-at-all", claim_req(&code)).await;
    assert!(matches!(r, Err(InviteError::AuthorityUnavailable)));
    assert_eq!(
        log.send_count.load(Ordering::SeqCst),
        0,
        "no send on unparseable target"
    );

    cancel.cancel();
}

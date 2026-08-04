//! M1b invite + policy-receipt two-authority wire regressions (WP-IP).
//!
//! Exercises the full authority/claimant split with **real cryptography**: the
//! `TestAuthority` fake signs/verifies invite codes with real BIP-340 Schnorr
//! (via `nostr::secp256k1`) and computes the policy-receipt MAC with real
//! HMAC-SHA256. This makes every assertion load-bearing — a production
//! mutation to the signing convention, code codec, receipt binding, expiry
//! check, or the "exactly-one-membership-mutation" contract fails a test.
//!
//! The two-authority round trip is proved through a `LinkedAuthorityBus` that a
//! *claimant* uses to reach a real `InviteAuthorityService` on the *authority*
//! side — mirroring the x0x direct-message hop, with the verified request/result
//! observed at the bus boundary (the seam the production wiring adapts over
//! `X0xDirectTransport`).
//!
//! Run: `cargo test -p x0x-nostr-bridge --test m1b_invites -- --nocapture`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use nostr::secp256k1::{self, Keypair, Message, Secp256k1, XOnlyPublicKey};
use nostr::Keys;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use x0x_nostr_bridge::invites::{
    claimant_claim, parse_invite_code, AuthorityBus, ClaimBusRequest, ClaimRequest, ClaimResponse,
    InviteAuthority, InviteAuthorityService, InviteError, InviteMembership, InviteMembershipWriter,
    InviteOptions, MintRequest,
};
use x0x_nostr_bridge::join_policy::{
    constant_time_eq, encode_receipt, parse_receipt, receipt_message, JoinPolicyConfig,
    RECEIPT_DOMAIN,
};

const BASE_URL: &str = "http://auth.example";
const PRIMARY_CHANNEL: &str = "general";

// ===========================================================================
// Real-crypto test collaborators
// ===========================================================================

/// A test authority backed by a real secp256k1 keypair. Sign/verify are a
/// matched pair over `SHA256(payload)`; the MAC is real HMAC-SHA256 keyed with
/// `SHA256(domain || secret)`. No production `RelayIdentity` is needed.
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

    fn xonly(&self) -> XOnlyPublicKey {
        self.keypair().x_only_public_key().0
    }
}

impl InviteAuthority for TestAuthority {
    fn public_key_hex(&self) -> String {
        self.keys.public_key().to_hex()
    }

    fn sign_authority_payload(&self, payload: &str) -> Vec<u8> {
        let digest = sha256_array(payload.as_bytes());
        let msg = Message::from_digest(digest);
        let sig = self.secp.sign_schnorr(&msg, &self.keypair());
        sig.serialize().to_vec()
    }

    fn verify_authority_payload(&self, payload: &str, sig: &[u8]) -> bool {
        let Ok(s) = secp256k1::schnorr::Signature::from_slice(sig) else {
            return false;
        };
        let msg = Message::from_digest(sha256_array(payload.as_bytes()));
        self.secp.verify_schnorr(&s, &msg, &self.xonly()).is_ok()
    }

    fn mac(&self, domain: &[u8], msg: &[u8]) -> Vec<u8> {
        let secret = self.keys.secret_key().secret_bytes();
        let mut h = Sha256::new();
        h.update(domain);
        h.update(secret);
        let key = h.finalize();
        hmac_sha256(&key, msg).to_vec()
    }
}

/// Mutable community membership: a fixed admin set + a growable member set
/// behind a sync lock (the `InviteMembership` checks are synchronous). The
/// writer mutates the same set so a second claim observes the first's member.
#[derive(Default)]
struct MembershipState {
    admins: Vec<String>,
    members: Arc<Mutex<Vec<String>>>,
}

impl MembershipState {
    fn with_admins(admins: Vec<String>) -> Self {
        Self {
            admins,
            members: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl InviteMembership for MembershipState {
    fn is_community_admin(&self, pk: &str) -> bool {
        self.admins.iter().any(|a| a == pk)
    }
    fn is_community_member(&self, pk: &str) -> bool {
        self.members.lock().iter().any(|m| m == pk)
    }
}

/// Membership writer that counts `add_community_member` calls and appends to
/// the shared member set. The call count *is* the "exactly one 39002 mutation"
/// proof at the service seam (the production writer emits the kind-39002 once).
struct CountingWriter {
    members: Arc<Mutex<Vec<String>>>,
    calls: Arc<AtomicU32>,
}

impl CountingWriter {
    fn new(members: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            members,
            calls: Arc::new(AtomicU32::new(0)),
        }
    }
    fn call_count(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl InviteMembershipWriter for CountingWriter {
    async fn add_community_member(
        &self,
        _channel: &str,
        pubkey: &str,
        _role: &str,
    ) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.members.lock().push(pubkey.to_string());
        Ok(())
    }
}

/// One observed bus request: the routing key + the forwarded claim.
type ObservedRequest = (String, String, String);

/// A claimant-side `AuthorityBus` that links straight to a real authority
/// service, recording each forwarded request. This is the verified x0x
/// direct-message round-trip seam: the request crosses the bus boundary with
/// the embedded `authority_agent_id` routing key, the authority adjudicates
/// with real crypto, and the sanitized result returns.
struct LinkedAuthorityBus {
    auth: Arc<TestAuthority>,
    members: Arc<MembershipState>,
    policy: Arc<JoinPolicyConfig>,
    writer: Arc<CountingWriter>,
    now: u64,
    requests: Arc<Mutex<Vec<ObservedRequest>>>,
}

impl LinkedAuthorityBus {
    fn requests(&self) -> Vec<ObservedRequest> {
        self.requests.lock().clone()
    }
}

#[async_trait]
impl AuthorityBus for LinkedAuthorityBus {
    async fn request_claim(
        &self,
        authority_agent_id: &str,
        req: ClaimBusRequest,
    ) -> Result<ClaimResponse, InviteError> {
        self.requests.lock().push((
            authority_agent_id.to_string(),
            req.code.clone(),
            req.joiner_pubkey.clone(),
        ));
        let svc = InviteAuthorityService::new(
            self.auth.as_ref(),
            self.members.as_ref(),
            self.policy.as_ref(),
            InviteOptions::new(BASE_URL, PRIMARY_CHANNEL),
        );
        svc.apply_claim(&req, self.writer.as_ref(), self.now).await
    }
}

/// A bus that always reports the authority unreachable (timeout / unroutable).
struct UnroutableBus;

#[async_trait]
impl AuthorityBus for UnroutableBus {
    async fn request_claim(
        &self,
        _agent: &str,
        _req: ClaimBusRequest,
    ) -> Result<ClaimResponse, InviteError> {
        Err(InviteError::AuthorityUnavailable)
    }
}

// ---------------------------------------------------------------------------
// crypto helpers
// ---------------------------------------------------------------------------

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    let d: [u8; 32] = Sha256::digest(bytes).into();
    d
}

/// RFC 2104 HMAC-SHA256 (faithful to the contract's receipt MAC), over `sha2`.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = Sha256::digest(key);
        k[..32].copy_from_slice(&h);
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
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

// ---------------------------------------------------------------------------
// shared fixtures
// ---------------------------------------------------------------------------

struct Harness {
    auth: Arc<TestAuthority>,
    members: Arc<MembershipState>,
    policy: Arc<JoinPolicyConfig>,
    writer: Arc<CountingWriter>,
    agent_id: String,
}

impl Harness {
    /// Disabled policy, one admin (`ADMIN_PK`), no members yet.
    fn new() -> Self {
        Self::with_policy(Arc::new(JoinPolicyConfig::disabled()))
    }

    fn with_policy(policy: Arc<JoinPolicyConfig>) -> Self {
        let auth = Arc::new(TestAuthority::generate());
        let members = Arc::new(MembershipState::with_admins(vec![ADMIN_PK.to_string()]));
        let writer = Arc::new(CountingWriter::new(Arc::clone(&members.members)));
        Self {
            auth,
            members,
            policy,
            writer,
            agent_id: AGENT_ID.to_string(),
        }
    }

    fn now(&self) -> u64 {
        1_700_000_000
    }

    fn svc(&self) -> InviteAuthorityService<'_, TestAuthority, MembershipState> {
        InviteAuthorityService::new(
            self.auth.as_ref(),
            self.members.as_ref(),
            self.policy.as_ref(),
            InviteOptions::new(BASE_URL, PRIMARY_CHANNEL),
        )
    }

    /// Mint a valid code as the admin.
    async fn mint(&self) -> String {
        let resp = self
            .svc()
            .mint(
                ADMIN_PK,
                &self.agent_id,
                "nonce-1",
                MintRequest { ttl_secs: None },
                self.now(),
            )
            .await
            .expect("mint must succeed as admin");
        resp.code
    }

    fn bus(&self) -> LinkedAuthorityBus {
        LinkedAuthorityBus {
            auth: Arc::clone(&self.auth),
            members: Arc::clone(&self.members),
            policy: Arc::clone(&self.policy),
            writer: Arc::clone(&self.writer),
            now: self.now(),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

/// A well-known admin pubkey (32-byte hex). The harness admits only this key.
const ADMIN_PK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// The joiner's pubkey (the claiming identity).
const JOINER_PK: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// A distinct authority agent id embedded in minted codes (the bus routing key).
const AGENT_ID: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

// ===========================================================================
// Mint (POST /api/invites)
// ===========================================================================

#[tokio::test]
async fn mint_as_admin_yields_url_safe_signed_code() {
    let h = Harness::new();
    let now = h.now();
    let ttl = 3600u64;
    let resp = h
        .svc()
        .mint(
            ADMIN_PK,
            &h.agent_id,
            "n1",
            MintRequest {
                ttl_secs: Some(ttl),
            },
            now,
        )
        .await
        .expect("admin may mint");

    // URL shape: {base}/invite/{code}.
    assert_eq!(resp.url, format!("{BASE_URL}/invite/{}", resp.code));
    assert_eq!(resp.expires_at, now + ttl);

    // Code is URL-safe: no slash (valid in /invite/<code> and bare-code form).
    assert!(!resp.code.contains('/'), "code must not contain '/'");
    assert!(resp.code.contains('.'), "code is payload.sig");

    // Structurally valid: parses without a secret and carries our authority.
    let view = parse_invite_code(&resp.code).expect("code must parse");
    assert_eq!(view.community_id, h.auth.public_key_hex());
    assert_eq!(view.authority_agent_id, h.agent_id);
    assert_eq!(view.expires_at, now + ttl);

    // Real signature verifies under the authority key.
    assert!(
        h.auth
            .verify_authority_payload(&view.payload_json, &view.sig),
        "minted code signature must verify under the authority key"
    );
}

#[tokio::test]
async fn mint_as_non_admin_is_forbidden() {
    let h = Harness::new();
    let err = h
        .svc()
        .mint(
            JOINER_PK,
            &h.agent_id,
            "n",
            MintRequest { ttl_secs: None },
            h.now(),
        )
        .await
        .err()
        .expect("non-admin must be rejected");
    assert_eq!(err, InviteError::NotAdmin);
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mint_rejects_out_of_range_ttl_and_default_applies() {
    let h = Harness::new();
    // ttl == 0 ⇒ out of range.
    let err = h
        .svc()
        .mint(
            ADMIN_PK,
            &h.agent_id,
            "n",
            MintRequest { ttl_secs: Some(0) },
            h.now(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(err, InviteError::TtlOutOfRange);

    // ttl beyond the cap ⇒ out of range.
    let err = h
        .svc()
        .mint(
            ADMIN_PK,
            &h.agent_id,
            "n",
            MintRequest {
                ttl_secs: Some(30 * 86400 + 1),
            },
            h.now(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(err, InviteError::TtlOutOfRange);

    // Omitted ttl ⇒ default applies (expires_at = now + default).
    let resp = h
        .svc()
        .mint(
            ADMIN_PK,
            &h.agent_id,
            "n",
            MintRequest { ttl_secs: None },
            h.now(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.expires_at,
        h.now() + InviteOptions::new(BASE_URL, PRIMARY_CHANNEL).default_ttl_secs
    );
}

// ===========================================================================
// Authority claim adjudication (apply_claim)
// ===========================================================================

#[tokio::test]
async fn apply_claim_valid_code_no_policy_joins_with_exactly_one_mutation() {
    let h = Harness::new();
    let code = h.mint().await;
    let req = ClaimBusRequest {
        code: code.clone(),
        policy_receipt: None,
        joiner_pubkey: JOINER_PK.to_string(),
        auth_proof: None,
    };

    let resp = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now())
        .await
        .expect("claim ok");
    assert_eq!(resp.status, "joined");
    assert_eq!(resp.community_id, h.auth.public_key_hex());
    assert_eq!(resp.host, BASE_URL);
    assert_eq!(resp.role, "member");

    // Exactly one membership mutation.
    assert_eq!(h.writer.call_count(), 1, "writer invoked exactly once");
    assert!(h.members.is_community_member(JOINER_PK));
}

#[tokio::test]
async fn apply_claim_repeat_is_idempotent_no_second_mutation() {
    let h = Harness::new();
    let code = h.mint().await;
    let req = ClaimBusRequest {
        code,
        policy_receipt: None,
        joiner_pubkey: JOINER_PK.to_string(),
        auth_proof: None,
    };

    let first = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now())
        .await
        .unwrap();
    assert_eq!(first.status, "joined");

    // A second claim for the now-member short-circuits: no write, stable 200.
    let second = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now())
        .await
        .unwrap();
    assert_eq!(second.status, "already_member");
    assert_eq!(second.community_id, h.auth.public_key_hex());

    // Still exactly one mutation across both claims.
    assert_eq!(
        h.writer.call_count(),
        1,
        "repeat claim must not mutate again"
    );
}

#[tokio::test]
async fn apply_claim_expired_code_is_rejected_before_any_mutation() {
    let h = Harness::new();
    let code = h.mint().await;
    let req = ClaimBusRequest {
        code,
        policy_receipt: None,
        joiner_pubkey: JOINER_PK.to_string(),
        auth_proof: None,
    };
    // now is well past the code's expiry (mint used h.now(); expiry = now+ttl).
    let err = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now() + 10 * 86400)
        .await
        .err()
        .unwrap();
    assert_eq!(err, InviteError::ExpiredCode);
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(h.writer.call_count(), 0, "no mutation on rejection");
}

#[tokio::test]
async fn apply_claim_wrong_authority_key_is_invalid() {
    let h = Harness::new();
    // Mint with a DIFFERENT authority (different signing key).
    let other = TestAuthority::generate();
    let disabled = JoinPolicyConfig::disabled();
    let other_members = MembershipState::with_admins(vec![other.public_key_hex()]);
    let other_svc = InviteAuthorityService::new(
        &other,
        &other_members,
        &disabled,
        InviteOptions::new(BASE_URL, PRIMARY_CHANNEL),
    );
    let foreign = other_svc
        .mint(
            &other.public_key_hex(),
            &h.agent_id,
            "n",
            MintRequest { ttl_secs: None },
            h.now(),
        )
        .await
        .unwrap();

    // The foreign code carries `other`'s community_id; h's authority must reject.
    let req = ClaimBusRequest {
        code: foreign.code,
        policy_receipt: None,
        joiner_pubkey: JOINER_PK.to_string(),
        auth_proof: None,
    };
    let err = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now())
        .await
        .err()
        .unwrap();
    assert_eq!(err, InviteError::InvalidCode);
    assert_eq!(h.writer.call_count(), 0);
}

#[tokio::test]
async fn apply_claim_tampered_signature_is_invalid() {
    let h = Harness::new();
    let code = h.mint().await;
    // Flip one byte of the signature half (after the '.').
    let mut tampered = code.clone();
    let dot = tampered.find('.').unwrap();
    let sig_byte = tampered.as_bytes()[dot + 1];
    tampered.replace_range(dot + 1..dot + 2, flip_char(sig_byte));

    let req = ClaimBusRequest {
        code: tampered,
        policy_receipt: None,
        joiner_pubkey: JOINER_PK.to_string(),
        auth_proof: None,
    };
    let err = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now())
        .await
        .err()
        .unwrap();
    // A tampered sig either fails base64 (MalformedCode) or signature verify
    // (InvalidCode); both are non-2xx rejections with no mutation.
    assert!(
        matches!(err, InviteError::InvalidCode | InviteError::MalformedCode),
        "tampered signature must be rejected, got {err:?}"
    );
    assert_eq!(h.writer.call_count(), 0);
}

#[tokio::test]
async fn apply_claim_malformed_code_is_rejected() {
    let h = Harness::new();
    for bad in ["", "nodelimit", "a.b.c", "!!!.!!!", "validb64half"] {
        let req = ClaimBusRequest {
            code: bad.to_string(),
            policy_receipt: None,
            joiner_pubkey: JOINER_PK.to_string(),
            auth_proof: None,
        };
        let err = h
            .svc()
            .apply_claim(&req, h.writer.as_ref(), h.now())
            .await
            .err()
            .unwrap();
        assert_eq!(
            err,
            InviteError::MalformedCode,
            "input {bad:?} should be MalformedCode"
        );
    }
}

#[tokio::test]
async fn apply_claim_empty_joiner_is_malformed() {
    let h = Harness::new();
    let code = h.mint().await;
    let req = ClaimBusRequest {
        code,
        policy_receipt: None,
        joiner_pubkey: String::new(),
        auth_proof: None,
    };
    let err = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now())
        .await
        .err()
        .unwrap();
    assert_eq!(err, InviteError::MalformedRequest);
}

// ===========================================================================
// Policy gate (accept-policy + claim receipt enforcement)
// ===========================================================================

fn enabled_policy(version: &str, age_required: bool) -> Arc<JoinPolicyConfig> {
    Arc::new(JoinPolicyConfig::from_explicit(
        version,
        Some("# Terms".into()),
        Some("# Privacy".into()),
        age_required,
    ))
}

#[tokio::test]
async fn accept_policy_disabled_returns_not_found() {
    let h = Harness::new(); // disabled
    let resp = h.svc().accept_policy(accept_req("any", "1.0.0", true));
    assert!(resp.is_err());
    assert_eq!(resp.err().unwrap(), InviteError::PolicyDisabled);
}

#[tokio::test]
async fn accept_policy_wrong_version_is_rejected() {
    let h = Harness::with_policy(enabled_policy("1.0.0", false));
    let err = h
        .svc()
        .accept_policy(accept_req("CODE", "2.0.0", true))
        .err()
        .unwrap();
    assert_eq!(err, InviteError::PolicyVersionMismatch);
}

#[tokio::test]
async fn claim_with_policy_requires_and_verifies_receipt() {
    let h = Harness::with_policy(enabled_policy("1.0.0", false));
    let code = h.mint().await;

    // (a) No receipt ⇒ rejected.
    let req = ClaimBusRequest {
        code: code.clone(),
        policy_receipt: None,
        joiner_pubkey: JOINER_PK.to_string(),
        auth_proof: None,
    };
    let err = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now())
        .await
        .err()
        .unwrap();
    assert_eq!(err, InviteError::PolicyReceiptInvalid);

    // (b) Mint a genuine receipt via accept-policy, then claim succeeds.
    let receipt = h
        .svc()
        .accept_policy(accept_req(&code, "1.0.0", true))
        .expect("accept ok")
        .receipt;
    let req = ClaimBusRequest {
        code: code.clone(),
        policy_receipt: Some(receipt),
        joiner_pubkey: JOINER_PK.to_string(),
        auth_proof: None,
    };
    let resp = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now())
        .await
        .expect("claim ok");
    assert_eq!(resp.status, "joined");
    assert_eq!(h.writer.call_count(), 1);
}

#[tokio::test]
async fn claim_rejects_receipt_for_a_different_code() {
    let h = Harness::with_policy(enabled_policy("1.0.0", false));
    let code_a = h.mint().await;
    let code_b = h
        .svc()
        .mint(
            ADMIN_PK,
            &h.agent_id,
            "n2",
            MintRequest { ttl_secs: None },
            h.now(),
        )
        .await
        .unwrap()
        .code;

    // Receipt bound to code_b, presented for code_a.
    let receipt = h
        .svc()
        .accept_policy(accept_req(&code_b, "1.0.0", true))
        .unwrap()
        .receipt;
    let req = ClaimBusRequest {
        code: code_a,
        policy_receipt: Some(receipt),
        joiner_pubkey: JOINER_PK.to_string(),
        auth_proof: None,
    };
    let err = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now())
        .await
        .err()
        .unwrap();
    assert_eq!(err, InviteError::PolicyReceiptInvalid);
    assert_eq!(h.writer.call_count(), 0);
}

#[tokio::test]
async fn claim_rejects_receipt_with_stale_version() {
    let h = Harness::with_policy(enabled_policy("2.0.0", false));
    let code = h.mint().await;
    // Forge a structurally-valid receipt whose version is stale (1.0.0) but
    // whose MAC is computed by the authority — currency check must still fail.
    let stale_msg = receipt_message(&code, "1.0.0", true);
    let stale_mac = h.auth.mac(RECEIPT_DOMAIN, stale_msg.as_bytes());
    let receipt = encode_receipt(&stale_msg, &stale_mac);

    let req = ClaimBusRequest {
        code,
        policy_receipt: Some(receipt),
        joiner_pubkey: JOINER_PK.to_string(),
        auth_proof: None,
    };
    let err = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now())
        .await
        .err()
        .unwrap();
    assert_eq!(err, InviteError::PolicyVersionMismatch);
}

#[tokio::test]
async fn claim_rejects_forged_receipt_single_byte_flip() {
    let h = Harness::with_policy(enabled_policy("1.0.0", false));
    let code = h.mint().await;
    let receipt = h
        .svc()
        .accept_policy(accept_req(&code, "1.0.0", true))
        .unwrap()
        .receipt;

    // Flip one bit of the MAC half and confirm constant-time compare rejects.
    let mut parts = parse_receipt(&receipt).unwrap();
    parts.mac[0] ^= 0x01;
    let forged = encode_receipt(&parts.message, &parts.mac);
    assert!(!constant_time_eq(
        &h.auth.mac(RECEIPT_DOMAIN, parts.message.as_bytes()),
        &parts.mac
    ));

    let req = ClaimBusRequest {
        code,
        policy_receipt: Some(forged),
        joiner_pubkey: JOINER_PK.to_string(),
        auth_proof: None,
    };
    let err = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now())
        .await
        .err()
        .unwrap();
    assert_eq!(err, InviteError::PolicyReceiptInvalid);
    assert_eq!(h.writer.call_count(), 0);
}

#[tokio::test]
async fn claim_age_attestation_required_blocks_unconfirmed() {
    let h = Harness::with_policy(enabled_policy("1.0.0", true));
    let code = h.mint().await;
    // Receipt with age_confirmed == false.
    let receipt = h
        .svc()
        .accept_policy(accept_req(&code, "1.0.0", false))
        .unwrap()
        .receipt;
    let req = ClaimBusRequest {
        code,
        policy_receipt: Some(receipt),
        joiner_pubkey: JOINER_PK.to_string(),
        auth_proof: None,
    };
    let err = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now())
        .await
        .err()
        .unwrap();
    assert_eq!(err, InviteError::AgeAttestationRequired);
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);

    // ...and confirming age lets it through.
    let code2 = h.mint().await;
    let receipt = h
        .svc()
        .accept_policy(accept_req(&code2, "1.0.0", true))
        .unwrap()
        .receipt;
    let req = ClaimBusRequest {
        code: code2,
        policy_receipt: Some(receipt),
        joiner_pubkey: JOINER_PK.to_string(),
        auth_proof: None,
    };
    let resp = h
        .svc()
        .apply_claim(&req, h.writer.as_ref(), h.now())
        .await
        .unwrap();
    assert_eq!(resp.status, "joined");
}

// ===========================================================================
// Claimant side: parse → forward → relay (verified request/result)
// ===========================================================================

#[tokio::test]
async fn claimant_claim_two_authority_round_trip_is_verified() {
    let h = Harness::new();
    let code = h.mint().await;
    let bus = h.bus();

    // The claimant holds NO secret; it parses, fail-fast checks, then forwards.
    let resp = claimant_claim(
        &bus,
        JOINER_PK,
        ClaimRequest {
            code: code.clone(),
            policy_receipt: None,
        },
        None,
        h.now(),
    )
    .await
    .expect("claim succeeds");

    assert_eq!(resp.status, "joined");
    assert_eq!(resp.community_id, h.auth.public_key_hex());

    // The bus observed exactly one forwarded request, routed to the embedded
    // authority agent id, carrying the verbatim code + authed joiner.
    let observed = bus.requests();
    assert_eq!(observed.len(), 1, "exactly one bus round trip");
    let (routed_agent, code_fwd, joiner_fwd) = &observed[0];
    assert_eq!(
        routed_agent, &h.agent_id,
        "routed to the code's authority agent"
    );
    assert_eq!(code_fwd, &code, "code forwarded verbatim");
    assert_eq!(joiner_fwd, JOINER_PK, "joiner identity carried");
    assert_eq!(h.writer.call_count(), 1);
}

#[tokio::test]
async fn claimant_claim_expired_short_circuits_without_bus_round_trip() {
    let h = Harness::new();
    let code = h.mint().await; // expiry = now + default ttl
    let bus = h.bus();
    // now is past expiry ⇒ the claimant fails fast locally, no bus call.
    let err = claimant_claim(
        &bus,
        JOINER_PK,
        ClaimRequest {
            code,
            policy_receipt: None,
        },
        None,
        h.now() + 10 * 86400,
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err, InviteError::ExpiredCode);
    assert!(
        bus.requests().is_empty(),
        "no bus round trip on local expiry"
    );
}

#[tokio::test]
async fn claimant_claim_authority_unavailable_maps_to_bad_gateway() {
    let h = Harness::new();
    let code = h.mint().await;
    let err = claimant_claim(
        &UnroutableBus,
        JOINER_PK,
        ClaimRequest {
            code,
            policy_receipt: None,
        },
        None,
        h.now(),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err, InviteError::AuthorityUnavailable);
    assert_eq!(err.status_code(), axum::http::StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn claimant_claim_propagates_authority_rejection_sanitized() {
    // The authority rejects (e.g. bad signature) and the sanitized InviteError
    // travels back over the bus to the claimant unchanged.
    let h = Harness::new();
    let bus = h.bus();
    let err = claimant_claim(
        &bus,
        JOINER_PK,
        ClaimRequest {
            code: "garbage".into(),
            policy_receipt: None,
        },
        None,
        h.now(),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err, InviteError::MalformedCode);
    assert_eq!(err.message(), "malformed invite code");
}

// ===========================================================================
// small helpers
// ===========================================================================

fn accept_req(
    code: &str,
    version: &str,
    age: bool,
) -> x0x_nostr_bridge::invites::AcceptPolicyRequest {
    x0x_nostr_bridge::invites::AcceptPolicyRequest {
        code: code.to_string(),
        policy_version: version.to_string(),
        age_confirmed: age,
    }
}

/// Map a base64url char to a different valid base64url char (sig tamper).
fn flip_char(b: u8) -> &'static str {
    // Any change to the signature bytes invalidates the BIP-340 signature.
    if b == b'A' {
        "B"
    } else {
        "A"
    }
}

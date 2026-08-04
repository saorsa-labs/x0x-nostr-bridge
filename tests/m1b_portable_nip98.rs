//! M1b portable NIP-98 proof regressions (the authority-side re-verification).
//!
//! `auth::verify_portable_nip98_claim` is the total, panic-free re-check the
//! authority runs on a forwarded claim before honoring it — it is the entire
//! "portable proof" trust boundary. These tests drive it directly with real
//! kind-27235 events (signed with `nostr` keys) and assert every fail-closed
//! branch: valid proof ⇒ body; body/payload mismatch ⇒ None; replay ⇒ None;
//! wrong pubkey / expiry / wrong method / non-loopback URL / bad path / bad
//! signature / malformed ⇒ None.
//!
//! Run: `cargo test -p x0x-nostr-bridge --test m1b_portable_nip98 -- --nocapture`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine as _;
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use sha2::{Digest, Sha256};
use x0x_nostr_bridge::auth::{
    canonical_pubkey, verify_portable_nip98_claim, PortableNip98Proof, ReplayCache,
};

const NOW: u64 = 1_700_000_000;
const TTL: u64 = 600;
const CLAIM_URL: &str = "http://127.0.0.1:3000/api/invites/claim";
const KIND_NIP98: u16 = 27235;

/// A proof whose `payload` tag commits to `body`, signed by `keys` at `now`.
fn proof_for(keys: &Keys, body: &[u8], now: u64, url: &str, method: &str) -> PortableNip98Proof {
    let payload = hex::encode(Sha256::digest(body));
    let ev = EventBuilder::new(Kind::from(KIND_NIP98), "")
        .tag(Tag::parse(["u", url]).unwrap())
        .tag(Tag::parse(["method", method]).unwrap())
        .tag(Tag::parse(["payload", &payload]).unwrap())
        .custom_created_at(Timestamp::from(now))
        .sign_with_keys(keys)
        .expect("sign nip98");
    PortableNip98Proof {
        event_json: ev.as_json(),
        body_b64: base64::engine::general_purpose::STANDARD.encode(body),
    }
}

fn body_bytes() -> Vec<u8> {
    br#"{"code":"abc.def","policy_receipt":null}"#.to_vec()
}

// ===========================================================================
// Valid proof round-trips the exact committed body
// ===========================================================================

#[test]
fn valid_proof_returns_the_exact_committed_body() {
    let keys = Keys::generate();
    let body = body_bytes();
    let proof = proof_for(&keys, &body, NOW, CLAIM_URL, "POST");
    let replay = ReplayCache::new();

    let decoded =
        verify_portable_nip98_claim(&proof, &keys.public_key().to_hex(), &replay, NOW, TTL);
    assert_eq!(decoded.as_deref(), Some(body.as_slice()));
}

#[test]
fn pubkey_is_case_insensitive_canonical_match() {
    let keys = Keys::generate();
    let body = body_bytes();
    let proof = proof_for(&keys, &body, NOW, CLAIM_URL, "POST");
    let upper = keys.public_key().to_hex().to_uppercase(); // non-canonical input
    assert!(
        canonical_pubkey(&upper).is_some(),
        "canonical accepts upper hex"
    );
    // The verifier canonicalizes the expected pubkey internally.
    let decoded = verify_portable_nip98_claim(&proof, &upper, &ReplayCache::new(), NOW, TTL);
    assert_eq!(decoded.as_deref(), Some(body.as_slice()));
}

// ===========================================================================
// Body / payload mismatch (tamper guard)
// ===========================================================================

#[test]
fn body_not_matching_payload_tag_is_rejected() {
    let keys = Keys::generate();
    let body = body_bytes();
    let proof = proof_for(&keys, &body, NOW, CLAIM_URL, "POST");
    // Swap the body half for a DIFFERENT body the proof did not commit to.
    let tampered = PortableNip98Proof {
        event_json: proof.event_json.clone(),
        body_b64: base64::engine::general_purpose::STANDARD.encode(br#"{"code":"evil"}"#),
    };
    assert_eq!(
        verify_portable_nip98_claim(
            &tampered,
            &keys.public_key().to_hex(),
            &ReplayCache::new(),
            NOW,
            TTL
        ),
        None,
        "payload tag ≠ sha256(body) ⇒ reject"
    );
}

#[test]
fn payload_tag_tamper_is_rejected() {
    // Rebuild the event with a payload tag that does not match the body.
    let keys = Keys::generate();
    let body = body_bytes();
    let bogus_payload = "f".repeat(64);
    let ev = EventBuilder::new(Kind::from(KIND_NIP98), "")
        .tag(Tag::parse(["u", CLAIM_URL]).unwrap())
        .tag(Tag::parse(["method", "POST"]).unwrap())
        .tag(Tag::parse(["payload", &bogus_payload]).unwrap())
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(&keys)
        .unwrap();
    let proof = PortableNip98Proof {
        event_json: ev.as_json(),
        body_b64: base64::engine::general_purpose::STANDARD.encode(&body),
    };
    assert_eq!(
        verify_portable_nip98_claim(
            &proof,
            &keys.public_key().to_hex(),
            &ReplayCache::new(),
            NOW,
            TTL
        ),
        None
    );
}

// ===========================================================================
// Replay (fail-closed, recorded only on full validity)
// ===========================================================================

#[test]
fn replayed_proof_is_rejected_second_time() {
    let keys = Keys::generate();
    let body = body_bytes();
    let proof = proof_for(&keys, &body, NOW, CLAIM_URL, "POST");
    let replay = ReplayCache::new();

    let first = verify_portable_nip98_claim(&proof, &keys.public_key().to_hex(), &replay, NOW, TTL);
    assert!(first.is_some(), "first sight accepted");

    let second =
        verify_portable_nip98_claim(&proof, &keys.public_key().to_hex(), &replay, NOW, TTL);
    assert_eq!(second, None, "replayed event id ⇒ reject");
}

#[test]
fn an_invalid_proof_does_not_burn_the_replay_slot() {
    // A proof that fails (wrong pubkey) must NOT record its event id, so a later
    // valid use of the same event still succeeds.
    let keys = Keys::generate();
    let other = Keys::generate();
    let body = body_bytes();
    let proof = proof_for(&keys, &body, NOW, CLAIM_URL, "POST");
    let replay = ReplayCache::new();

    // Fails on pubkey (not recorded).
    assert_eq!(
        verify_portable_nip98_claim(&proof, &other.public_key().to_hex(), &replay, NOW, TTL),
        None
    );
    // Same proof, correct pubkey ⇒ still accepted (slot not burned).
    assert!(
        verify_portable_nip98_claim(&proof, &keys.public_key().to_hex(), &replay, NOW, TTL)
            .is_some()
    );
}

// ===========================================================================
// Identity / freshness / method / URL binding
// ===========================================================================

#[test]
fn wrong_expected_pubkey_is_rejected() {
    let keys = Keys::generate();
    let body = body_bytes();
    let proof = proof_for(&keys, &body, NOW, CLAIM_URL, "POST");
    let intruder = Keys::generate();
    assert_eq!(
        verify_portable_nip98_claim(
            &proof,
            &intruder.public_key().to_hex(),
            &ReplayCache::new(),
            NOW,
            TTL
        ),
        None,
        "proof pubkey ≠ expected ⇒ reject (cross-authority binding)"
    );
}

#[test]
fn stale_created_at_outside_ttl_is_rejected() {
    let keys = Keys::generate();
    let body = body_bytes();
    // Minted far outside the ±ttl window.
    let proof = proof_for(&keys, &body, NOW - 10_000, CLAIM_URL, "POST");
    assert_eq!(
        verify_portable_nip98_claim(
            &proof,
            &keys.public_key().to_hex(),
            &ReplayCache::new(),
            NOW,
            TTL
        ),
        None
    );
}

#[test]
fn wrong_method_is_rejected() {
    let keys = Keys::generate();
    let body = body_bytes();
    let proof = proof_for(&keys, &body, NOW, CLAIM_URL, "GET");
    assert_eq!(
        verify_portable_nip98_claim(
            &proof,
            &keys.public_key().to_hex(),
            &ReplayCache::new(),
            NOW,
            TTL
        ),
        None,
        "method must be POST"
    );
}

#[test]
fn method_match_is_case_insensitive() {
    let keys = Keys::generate();
    let body = body_bytes();
    // "post" (lowercase) is accepted — matches the claimant-side check.
    let proof = proof_for(&keys, &body, NOW, CLAIM_URL, "post");
    assert!(verify_portable_nip98_claim(
        &proof,
        &keys.public_key().to_hex(),
        &ReplayCache::new(),
        NOW,
        TTL
    )
    .is_some());
}

#[test]
fn non_loopback_url_is_rejected() {
    let keys = Keys::generate();
    let body = body_bytes();
    let proof = proof_for(
        &keys,
        &body,
        NOW,
        "http://evil.example:443/api/invites/claim",
        "POST",
    );
    assert_eq!(
        verify_portable_nip98_claim(
            &proof,
            &keys.public_key().to_hex(),
            &ReplayCache::new(),
            NOW,
            TTL
        ),
        None,
        "non-loopback host ⇒ reject"
    );
}

#[test]
fn wrong_path_is_rejected() {
    let keys = Keys::generate();
    let body = body_bytes();
    for bad in [
        "http://127.0.0.1:3000/api/invites",
        "http://127.0.0.1:3000/api/invites/claim/extra",
        "http://127.0.0.1:3000/",
        "http://127.0.0.1:3000/api/invites/accept-policy",
    ] {
        let proof = proof_for(&keys, &body, NOW, bad, "POST");
        assert_eq!(
            verify_portable_nip98_claim(
                &proof,
                &keys.public_key().to_hex(),
                &ReplayCache::new(),
                NOW,
                TTL
            ),
            None,
            "path {bad:?} must be rejected"
        );
    }
}

#[test]
fn localhost_and_ipv6_loopback_hosts_accepted() {
    let keys = Keys::generate();
    let body = body_bytes();
    for ok in [
        "http://localhost:3000/api/invites/claim",
        "http://[::1]:3000/api/invites/claim",
        "http://127.0.0.1/api/invites/claim",
    ] {
        let proof = proof_for(&keys, &body, NOW, ok, "POST");
        assert!(
            verify_portable_nip98_claim(
                &proof,
                &keys.public_key().to_hex(),
                &ReplayCache::new(),
                NOW,
                TTL
            )
            .is_some(),
            "loopback host {ok:?} should be accepted"
        );
    }
}

// ===========================================================================
// Structural / signature integrity (panic-free on attacker input)
// ===========================================================================

#[test]
fn malformed_event_json_is_rejected_without_panic() {
    let keys = Keys::generate();
    let body = body_bytes();
    let bogus = PortableNip98Proof {
        event_json: "!!!not json!!!".to_string(),
        body_b64: base64::engine::general_purpose::STANDARD.encode(&body),
    };
    assert_eq!(
        verify_portable_nip98_claim(
            &bogus,
            &keys.public_key().to_hex(),
            &ReplayCache::new(),
            NOW,
            TTL
        ),
        None
    );
}

#[test]
fn bad_signature_is_rejected() {
    // Two events with identical tags/created_at signed by DIFFERENT keys: the
    // second's id+sig do not verify, so it is rejected.
    let signer = Keys::generate();
    let other = Keys::generate();
    let body = body_bytes();
    let payload = hex::encode(Sha256::digest(&body));
    let ev = EventBuilder::new(Kind::from(KIND_NIP98), "")
        .tag(Tag::parse(["u", CLAIM_URL]).unwrap())
        .tag(Tag::parse(["method", "POST"]).unwrap())
        .tag(Tag::parse(["payload", &payload]).unwrap())
        .custom_created_at(Timestamp::from(NOW))
        // Signed by `other` but presented as if from `signer`:
        .sign_with_keys(&other)
        .unwrap();
    let proof = PortableNip98Proof {
        event_json: ev.as_json(),
        body_b64: base64::engine::general_purpose::STANDARD.encode(&body),
    };
    assert_eq!(
        verify_portable_nip98_claim(
            &proof,
            &signer.public_key().to_hex(),
            &ReplayCache::new(),
            NOW,
            TTL
        ),
        None,
        "signature must verify under the claimed pubkey"
    );
}

#[test]
fn wrong_kind_is_rejected() {
    let keys = Keys::generate();
    let body = body_bytes();
    let payload = hex::encode(Sha256::digest(&body));
    // kind 1 (text note), not 27235.
    let ev = EventBuilder::new(Kind::from(1u16), "")
        .tag(Tag::parse(["u", CLAIM_URL]).unwrap())
        .tag(Tag::parse(["method", "POST"]).unwrap())
        .tag(Tag::parse(["payload", &payload]).unwrap())
        .custom_created_at(Timestamp::from(NOW))
        .sign_with_keys(&keys)
        .unwrap();
    let proof = PortableNip98Proof {
        event_json: ev.as_json(),
        body_b64: base64::engine::general_purpose::STANDARD.encode(&body),
    };
    assert_eq!(
        verify_portable_nip98_claim(
            &proof,
            &keys.public_key().to_hex(),
            &ReplayCache::new(),
            NOW,
            TTL
        ),
        None
    );
}

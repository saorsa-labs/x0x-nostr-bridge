//! M1b join-policy wire-level regressions (WP-JP).
//!
//! Exercises the pure `JoinPolicyConfig` surface that the HTTP wire layer
//! mounts: the enable rule (§9), the client envelope shape, doc serving, and
//! the policy-receipt message/encode/parse/MAC-input pipeline consumed by the
//! invite claim path (§8). No AppState, no network, no secret — the module is a
//! pure leaf, so these tests pin its exact deterministic shapes and fail on any
//! production mutation to the enable rule, envelope field order, receipt codec,
//! or constant-time compare.
//!
//! Run: `cargo test -p x0x-nostr-bridge --test m1b_join_policy -- --nocapture`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use x0x_nostr_bridge::join_policy::{
    constant_time_eq, encode_receipt, parse_receipt, receipt_message, JoinPolicyConfig, PolicyDoc,
    RECEIPT_DOMAIN,
};

// ---------------------------------------------------------------------------
// Enable rule (§9): a policy is enabled iff its version is non-empty.
// ---------------------------------------------------------------------------

#[test]
fn disabled_is_the_default_and_reports_disabled() {
    let p = JoinPolicyConfig::disabled();
    assert!(!p.enabled(), "disabled() must not be enabled");
    assert!(p.version.is_empty(), "disabled version must be empty");
    assert!(!p.age_attestation_required);
    assert!(p.terms_markdown.is_none());
    assert!(p.privacy_markdown.is_none());
    // default() is the same explicit off-state.
    assert!(!JoinPolicyConfig::default().enabled());
}

#[test]
fn empty_or_whitespace_version_is_disabled_even_with_docs() {
    // A whitespace-only version trims to empty ⇒ disabled (the invariant that
    // "no version" and "configured" can never disagree).
    let p = JoinPolicyConfig::from_explicit("   ", Some("t".into()), None, false);
    assert!(!p.enabled());
    // docs configured without a version stay inert (envelope is not served).
}

#[test]
fn nonempty_version_is_enabled() {
    let p = JoinPolicyConfig::from_explicit("1.2.0", None, None, false);
    assert!(p.enabled());
    assert_eq!(p.version, "1.2.0");
}

#[test]
fn from_explicit_trims_surrounding_whitespace_from_version() {
    let p = JoinPolicyConfig::from_explicit("  2.0.0\n", None, None, false);
    assert_eq!(p.version, "2.0.0");
    assert!(p.enabled());
}

// ---------------------------------------------------------------------------
// Client envelope (§9): GET /api/join-policy shape + deterministic bytes.
// ---------------------------------------------------------------------------

#[test]
fn envelope_carries_all_configured_fields_in_wire_order() {
    let p = JoinPolicyConfig::from_explicit(
        "3.0.0",
        Some("# Terms".into()),
        Some("# Privacy".into()),
        true,
    );
    let env = p.envelope();
    assert_eq!(env.policy.version, "3.0.0");
    assert!(env.policy.age_attestation_required);
    assert_eq!(env.policy.terms_markdown.as_deref(), Some("# Terms"));
    assert_eq!(env.policy.privacy_markdown.as_deref(), Some("# Privacy"));
}

#[test]
fn envelope_json_omits_absent_optional_docs_and_is_stable() {
    let p = JoinPolicyConfig::from_explicit("1.0.0", None, None, false);
    let j = p.envelope_json().unwrap();
    // Minimal upload yields exactly these keys; absent docs are skipped.
    assert_eq!(
        j,
        r#"{"policy":{"age_attestation_required":false,"version":"1.0.0"}}"#
    );
    // Deterministic: re-serialize yields identical bytes.
    assert_eq!(p.envelope_json().unwrap(), j);
}

#[test]
fn envelope_json_includes_docs_when_present() {
    let p = JoinPolicyConfig::from_explicit("1.0.0", Some("T".into()), Some("P".into()), true);
    let j = p.envelope_json().unwrap();
    assert!(j.contains(r#""terms_markdown":"T""#));
    assert!(j.contains(r#""privacy_markdown":"P""#));
    assert!(j.contains(r#""age_attestation_required":true"#));
}

// ---------------------------------------------------------------------------
// Doc serving: GET /api/join-policy/{terms,privacy} (404 when absent).
// ---------------------------------------------------------------------------

#[test]
fn doc_markdown_returns_configured_doc_and_none_otherwise() {
    let p = JoinPolicyConfig::from_explicit("1.0.0", Some("# T".into()), None, false);
    assert_eq!(p.doc_markdown(PolicyDoc::Terms), Some("# T"));
    assert_eq!(p.doc_markdown(PolicyDoc::Privacy), None);
}

#[test]
fn policy_doc_segment_round_trip_rejects_unknown() {
    assert_eq!(PolicyDoc::Terms.segment(), "terms");
    assert_eq!(PolicyDoc::Privacy.segment(), "privacy");
    assert_eq!(PolicyDoc::from_segment("terms"), Some(PolicyDoc::Terms));
    assert_eq!(PolicyDoc::from_segment("privacy"), Some(PolicyDoc::Privacy));
    // Unknown segments ⇒ None (wire layer answers 404; never a path).
    assert_eq!(PolicyDoc::from_segment("../etc/passwd"), None);
    assert_eq!(PolicyDoc::from_segment(""), None);
    assert_eq!(PolicyDoc::from_segment("Terms"), None); // case-sensitive
}

#[test]
fn from_explicit_trims_trailing_newline_from_docs_only() {
    // A trailing newline (the common artifact of a file read) is trimmed, but
    // interior/leading content is preserved verbatim.
    let p = JoinPolicyConfig::from_explicit(
        "1.0.0",
        Some("line one\nline two\n".into()),
        Some("  keep indent\n".into()),
        false,
    );
    assert_eq!(p.doc_markdown(PolicyDoc::Terms), Some("line one\nline two"));
    assert_eq!(p.doc_markdown(PolicyDoc::Privacy), Some("  keep indent"));
}

// ---------------------------------------------------------------------------
// Receipt pipeline (§8): message → encode → parse → MAC inputs.
// ---------------------------------------------------------------------------

#[test]
fn receipt_message_is_deterministic_with_age_as_zero_or_one() {
    assert_eq!(receipt_message("CODE", "1.0.0", true), "CODE|1.0.0|1");
    assert_eq!(receipt_message("CODE", "1.0.0", false), "CODE|1.0.0|0");
    // Identical inputs ⇒ identical bytes.
    assert_eq!(
        receipt_message("CODE", "1.0.0", true),
        receipt_message("CODE", "1.0.0", true)
    );
}

#[test]
fn receipt_encode_parse_round_trip_preserves_all_fields() {
    let msg = receipt_message("INVITECODE", "2.0.0", true);
    let mac = [0xabu8; 32]; // representative 32-byte MAC
    let token = encode_receipt(&msg, &mac);
    let parts = parse_receipt(&token).expect("valid receipt must parse");

    assert_eq!(parts.code, "INVITECODE");
    assert_eq!(parts.version, "2.0.0");
    assert!(parts.age_confirmed);
    assert_eq!(parts.message, msg);
    assert_eq!(parts.mac, mac.to_vec());
}

#[test]
fn receipt_parse_rejects_every_malformed_shape() {
    // No delimiter.
    assert!(parse_receipt("nodelimitherexxx").is_none());
    // Two delimiters.
    assert!(parse_receipt("a.b.c").is_none());
    // Bad base64url in the message half.
    assert!(parse_receipt("!!!notb64!!.AAAA").is_none());
    // Message decodes but is not the expected 3-field "code|version|age".
    assert!(parse_receipt(&encode_two(&b64("onlyonefield"), &[0u8; 32])).is_none());
    // age field is not an integer.
    assert!(parse_receipt(&encode_two(&b64("code|1.0.0|notanint"), &[0u8; 32])).is_none());
    // Empty code in the message.
    assert!(parse_receipt(&encode_two(&b64("|1.0.0|1"), &[0u8; 32])).is_none());
    // Empty version in the message.
    assert!(parse_receipt(&encode_two(&b64("code||1"), &[0u8; 32])).is_none());
}

#[test]
fn receipt_mac_inputs_are_none_when_disabled_and_bound_when_enabled() {
    // Disabled ⇒ no receipt gate (claim proceeds without one).
    let off = JoinPolicyConfig::disabled();
    assert!(off.receipt_mac_inputs("CODE", true).is_none());

    // Enabled ⇒ the message binds code + current version + age, over the
    // public domain separator. No secret lives here.
    let on = JoinPolicyConfig::from_explicit("7.7.7", None, None, false);
    let inputs = on.receipt_mac_inputs("CODE", true).expect("enabled ⇒ Some");
    assert_eq!(inputs.domain, RECEIPT_DOMAIN);
    assert_eq!(inputs.message, "CODE|7.7.7|1");

    let inputs_false = on
        .receipt_mac_inputs("CODE", false)
        .expect("enabled ⇒ Some");
    assert_eq!(inputs_false.message, "CODE|7.7.7|0");
}

// ---------------------------------------------------------------------------
// constant_time_eq (§8): MAC comparison must be length-aware and total.
// ---------------------------------------------------------------------------

#[test]
fn constant_time_eq_handles_equal_unequal_and_mismatched_lengths() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    assert!(constant_time_eq(&a, &b));

    let c = [1u8, 2, 3, 5];
    assert!(!constant_time_eq(&a, &c));

    // Mismatched lengths return false immediately (length is public for MACs).
    assert!(!constant_time_eq(&a, &[1u8, 2, 3]));
    assert!(!constant_time_eq(&[], &a));
    // Two empty slices are equal.
    assert!(constant_time_eq(&[], &[]));
}

#[test]
fn single_byte_mac_flip_changes_constant_time_compare() {
    let mac_a = [0xaau8; 32];
    let mut mac_b = mac_a;
    mac_b[7] ^= 0x01; // flip one bit
    assert!(!constant_time_eq(&mac_a, &mac_b));
    assert!(constant_time_eq(&mac_a, &mac_a));
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn b64(bytes: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_bytes())
}

/// Join two url-safe-no-pad halves with a single `.` (the receipt shape),
/// taking raw bytes for each half.
fn encode_two(msg_b64: &str, mac: &[u8]) -> String {
    use base64::Engine as _;
    format!(
        "{}.{}",
        msg_b64,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac)
    )
}

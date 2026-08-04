//! Join-policy configuration + serve/receipt helpers (M1b, WP-JP). Owner: wp-policy.
//!
//! Dual-licensed under MIT or Apache-2.0 (see `Cargo.toml`). Behavior mined
//! from `local://m1b-media-invites-contract.md` §9 (enable rule, GET envelope,
//! doc serving) and the receipt format of §8; no upstream caller mutates policy
//! at runtime, so this module is config-only — loaded once at startup, held
//! immutably in `AppState`.
//!
//! # Scope: a pure leaf
//!
//! This module owns the in-memory [`JoinPolicyConfig`] and exposes the
//! deterministic shapes the HTTP wire layer (WP-W) needs for:
//! - `GET /api/join-policy` — the client envelope (404 when disabled).
//! - `GET /api/join-policy/{terms,privacy}` — markdown doc (404 when absent).
//! - the policy-receipt inputs consumed by the invite claim path (WP-IP).
//!
//! It deliberately depends on **no** `AppState`, route/axum type, or relay
//! secret. The only MAC material produced here is the public domain string and
//! the canonical `(code|version|age)` message; the relay secret is applied by
//! the *caller* via `RelayIdentity::mac(domain, msg)`. No secret ever crosses
//! this module's API.
//!
//! # Enable rule (authoritative)
//!
//! A policy is **enabled iff its `version` is non-empty** (contract §9). An
//! empty version is the explicit *disabled* state: `GET /api/join-policy`
//! answers 404 and the claim path ignores any receipt. There is no separate
//! `enabled` flag to fall out of sync — `enabled()` is derived from `version`,
//! so "disabled when no version" is an invariant that cannot be violated.

use base64::Engine as _;

/// Canonical HMAC domain separator for policy receipts
/// (`b"bridge.policy_receipt.v1"`). **Public, not secret** — the secret is the
/// relay key, applied by the caller. Passed as the `domain` argument to
/// `RelayIdentity::mac`.
pub const RECEIPT_DOMAIN: &[u8] = b"bridge.policy_receipt.v1";

// --- env keys (inline vs file are distinct, unambiguous) -------------------

/// Policy version; non-empty ⇒ enabled. Unset/empty ⇒ disabled.
pub const ENV_VERSION: &str = "BRIDGE_JOIN_POLICY_VERSION";
/// Terms markdown, inline (the value *is* the document).
pub const ENV_TERMS: &str = "BRIDGE_JOIN_POLICY_TERMS";
/// Terms markdown, read from a file path at startup.
pub const ENV_TERMS_FILE: &str = "BRIDGE_JOIN_POLICY_TERMS_FILE";
/// Privacy markdown, inline (the value *is* the document).
pub const ENV_PRIVACY: &str = "BRIDGE_JOIN_POLICY_PRIVACY";
/// Privacy markdown, read from a file path at startup.
pub const ENV_PRIVACY_FILE: &str = "BRIDGE_JOIN_POLICY_PRIVACY_FILE";
/// Age-attestation gate (`1`/`true`/`yes`/`on`), default off.
pub const ENV_AGE_ATTESTATION: &str = "BRIDGE_JOIN_POLICY_AGE_ATTESTATION";

/// A loaded join-policy. Immutable after startup (no runtime writes in M1b).
///
/// Construct via [`JoinPolicyConfig::from_explicit`] (resolved inputs),
/// [`JoinPolicyConfig::from_env`] (env + files), or [`JoinPolicyConfig::disabled`]
/// (the explicit off-state / [`Default`]). `enabled()` is derived from
/// [`version`](Self::version); do not treat an empty version as "configured".
#[derive(Debug, Clone, Default)]
pub struct JoinPolicyConfig {
    /// Opaque policy version string (e.g. `"1.2.0"`). Empty ⇒ disabled.
    pub version: String,
    /// Optional terms-of-service markdown, loaded inline or from a file.
    pub terms_markdown: Option<String>,
    /// Optional privacy-policy markdown, loaded inline or from a file.
    pub privacy_markdown: Option<String>,
    /// When true, the claim path requires a receipt whose `age_confirmed` is
    /// `true`. Inert when disabled.
    pub age_attestation_required: bool,
}

/// Startup-loading failure for join-policy. A doc that was *configured* but
/// cannot be read is a hard startup error — the operator asked for a document
/// the bridge cannot serve, so the bridge refuses to boot rather than silently
/// advertising a policy it cannot back. A doc that was never configured is
/// `None` (not an error): the policy is simply leaner.
#[derive(Debug, thiserror::Error)]
pub enum JoinPolicyError {
    /// A configured `*_FILE` path is missing or unreadable.
    #[error("join-policy: cannot read {kind} markdown file `{path}`: {source}")]
    FileRead {
        kind: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// Both the inline key and the `*_FILE` key were set for the same document.
    /// The source is intentionally unambiguous: set exactly one.
    #[error(
        "join-policy: ambiguous {kind} source — set only one of `{inline}` (inline) or `{file}` (path)"
    )]
    Ambiguous {
        kind: &'static str,
        inline: &'static str,
        file: &'static str,
    },
}

impl JoinPolicyConfig {
    /// The explicit disabled policy (empty version). This is [`Self::default`]
    /// and the state used when no `BRIDGE_JOIN_POLICY_VERSION` is configured.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// `true` iff a non-empty `version` is configured — the contract §9 enable
    /// rule. Derived (not stored) so it can never disagree with `version`.
    #[inline]
    pub fn enabled(&self) -> bool {
        !self.version.trim().is_empty()
    }

    /// Build a policy from already-resolved inputs (no env, no filesystem).
    ///
    /// This is the deterministic, allocation-minimal core used by
    /// [`Self::from_env`], by explicit wiring, and by tests. `version` is
    /// trimmed (whitespace-only ⇒ disabled). Markdown is taken verbatim except
    /// for a trimmed trailing newline (the common artifact of a file read);
    /// document semantics are otherwise untouched.
    pub fn from_explicit(
        version: impl AsRef<str>,
        terms: Option<String>,
        privacy: Option<String>,
        age_attestation_required: bool,
    ) -> Self {
        Self {
            version: version.as_ref().trim().to_string(),
            terms_markdown: terms.map(trim_doc),
            privacy_markdown: privacy.map(trim_doc),
            age_attestation_required,
        }
    }

    /// Load the join-policy from the environment, reading any `*_FILE` paths
    /// from the filesystem at call time.
    ///
    /// - Unset/empty `BRIDGE_JOIN_POLICY_VERSION` ⇒ a **disabled** policy
    ///   (not an error).
    /// - For each doc, exactly one of the inline key / `*_FILE` key may be set;
    ///   both set ⇒ [`JoinPolicyError::Ambiguous`].
    /// - A set `*_FILE` whose path is missing/unreadable ⇒
    ///   [`JoinPolicyError::FileRead`] (startup error).
    pub fn from_env() -> Result<Self, JoinPolicyError> {
        let version = std::env::var(ENV_VERSION)
            .ok()
            .filter(|v| !v.trim().is_empty());

        let terms = resolve_doc(
            "terms",
            ENV_TERMS,
            ENV_TERMS_FILE,
            std::env::var(ENV_TERMS).ok(),
            std::env::var(ENV_TERMS_FILE).ok(),
        )?;
        let privacy = resolve_doc(
            "privacy",
            ENV_PRIVACY,
            ENV_PRIVACY_FILE,
            std::env::var(ENV_PRIVACY).ok(),
            std::env::var(ENV_PRIVACY_FILE).ok(),
        )?;
        let age_attestation_required = env_bool(ENV_AGE_ATTESTATION, false);

        let cfg = Self::from_explicit(
            version.unwrap_or_default(),
            terms,
            privacy,
            age_attestation_required,
        );

        if !cfg.enabled() && (cfg.terms_markdown.is_some() || cfg.privacy_markdown.is_some()) {
            tracing::debug!(
                "join-policy: terms/privacy configured without a VERSION — policy stays disabled"
            );
        }
        Ok(cfg)
    }

    /// The client-facing envelope for `GET /api/join-policy`. Call only when
    /// [`Self::enabled`] is true (the wire layer answers 404 otherwise).
    ///
    /// Shape (contract §9, fixed field order ⇒ deterministic serialization):
    /// `{"policy":{"terms_markdown"?,"privacy_markdown"?,"age_attestation_required","version"}}`.
    pub fn envelope(&self) -> PolicyEnvelope {
        PolicyEnvelope {
            policy: PolicyBody {
                terms_markdown: self.terms_markdown.clone(),
                privacy_markdown: self.privacy_markdown.clone(),
                age_attestation_required: self.age_attestation_required,
                version: self.version.clone(),
            },
        }
    }

    /// Deterministic JSON serialization of [`Self::envelope`] as a [`String`].
    /// `serde_json` emits struct fields in declaration order, so the bytes are
    /// stable for a given config. Errors propagate honestly (no fake fallback)
    /// — the wire layer may pass [`Self::envelope`] to axum's `Json` directly,
    /// or `?`-propagate this [`Result`] at a startup/serialize seam.
    pub fn envelope_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(&self.envelope())
    }

    /// The markdown for `doc`, or `None` when that document was not configured
    /// (the wire layer answers 404). Served from in-memory config — **no
    /// runtime filesystem access**, so there is no path-traversal surface.
    #[inline]
    pub fn doc_markdown(&self, doc: PolicyDoc) -> Option<&str> {
        match doc {
            PolicyDoc::Terms => self.terms_markdown.as_deref(),
            PolicyDoc::Privacy => self.privacy_markdown.as_deref(),
        }
    }

    /// Build the receipt-MAC inputs for `code` bound to *this* policy's
    /// version. Returns `None` when disabled (no version to bind) — the wire
    /// layer then skips the receipt gate and the claim proceeds without one.
    ///
    /// The caller computes the MAC itself (it holds the relay secret):
    /// `mac = RelayIdentity::mac(inputs.domain, inputs.message.as_bytes())`.
    pub fn receipt_mac_inputs(&self, code: &str, age_confirmed: bool) -> Option<ReceiptMacInputs> {
        if !self.enabled() {
            return None;
        }
        Some(ReceiptMacInputs {
            domain: RECEIPT_DOMAIN,
            message: receipt_message(code, &self.version, age_confirmed),
        })
    }
}

/// Which policy document a doc route serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDoc {
    /// Terms of service.
    Terms,
    /// Privacy policy.
    Privacy,
}

impl PolicyDoc {
    /// The URL path segment: `"terms"` / `"privacy"`.
    #[inline]
    pub fn segment(self) -> &'static str {
        match self {
            PolicyDoc::Terms => "terms",
            PolicyDoc::Privacy => "privacy",
        }
    }

    /// Parse a URL path segment into a doc kind. Any other value ⇒ `None`
    /// (the wire layer answers 404). A user-supplied segment is mapped to this
    /// enum and **never** used to derive a filesystem path, so there is no
    /// traversal risk regardless of input.
    pub fn from_segment(segment: &str) -> Option<Self> {
        match segment {
            "terms" => Some(PolicyDoc::Terms),
            "privacy" => Some(PolicyDoc::Privacy),
            _ => None,
        }
    }
}

/// Serializable client envelope for `GET /api/join-policy`.
///
/// Construct via [`JoinPolicyConfig::envelope`] so field order (and thus the
/// serialized bytes) stays deterministic.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyEnvelope {
    /// The policy body.
    pub policy: PolicyBody,
}

/// The `policy` object inside the envelope. Field order is the wire order.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyBody {
    /// Terms markdown, omitted from JSON when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_markdown: Option<String>,
    /// Privacy markdown, omitted from JSON when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_markdown: Option<String>,
    /// Whether the client must attest to age before claiming.
    pub age_attestation_required: bool,
    /// The policy version (the enable switch).
    pub version: String,
}

/// Inputs the wire layer needs to compute/verify a policy receipt's MAC.
///
/// No secret lives here. The caller applies the relay key:
/// `mac = RelayIdentity::mac(self.domain, self.message.as_bytes())`, then
/// compares the result (constant-time) against the parsed receipt's MAC.
#[derive(Debug, Clone)]
pub struct ReceiptMacInputs {
    /// [`RECEIPT_DOMAIN`] — the public domain separator.
    pub domain: &'static [u8],
    /// The canonical message `"{code}|{version}|{age}"` (UTF-8).
    pub message: String,
}

/// Build the canonical receipt message: `"{code}|{version}|{age}"` where `age`
/// is `1` (true) or `0` (false) — the `age_confirmed_int` of contract §8.
/// Deterministic for identical inputs.
pub fn receipt_message(code: &str, version: &str, age_confirmed: bool) -> String {
    // `format!` is the single allocation; no intermediate strings.
    format!("{code}|{version}|{}", u8::from(age_confirmed))
}

/// Encode a receipt token: `base64url_no_pad(message) + "." + base64url_no_pad(mac)`.
///
/// Used by the accept-policy path: the caller has the canonical `message`
/// (from [`receipt_message`]) and the computed `mac` bytes.
pub fn encode_receipt(message: &str, mac: &[u8]) -> String {
    let eng = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!("{}.{}", eng.encode(message.as_bytes()), eng.encode(mac))
}

/// A parsed receipt token — the message fields plus the raw MAC bytes carried
/// in the token, for the wire layer to recompute-and-compare.
#[derive(Debug, Clone)]
pub struct ReceiptParts {
    /// The invite code embedded in the receipt message.
    pub code: String,
    /// The policy version embedded in the receipt message.
    pub version: String,
    /// The age attestation carried by the receipt.
    pub age_confirmed: bool,
    /// The exact message bytes that were MACed. Recompute the MAC over
    /// `message.as_bytes()` and compare to [`mac`](Self::mac).
    pub message: String,
    /// Raw HMAC bytes from the token (32 bytes when well-formed).
    pub mac: Vec<u8>,
}

/// Parse and decode a receipt token produced by [`encode_receipt`].
///
/// Returns `None` on any malformation — wrong shape (no single `.`), invalid
/// base64url, non-UTF-8 message, a field count other than three, a non-integer
/// age, or empty code/version. The wire layer answers 400 `policy_receipt` then.
///
/// This only *parses*; it does not verify the MAC (the caller does, using the
/// relay secret) nor check version/age policy (the caller does, against the
/// live config).
pub fn parse_receipt(receipt: &str) -> Option<ReceiptParts> {
    let eng = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (msg_b64, mac_b64) = receipt.split_once('.')?;
    // Reject a second delimiter — the token has exactly two parts.
    if mac_b64.contains('.') {
        return None;
    }
    let msg_bytes = eng.decode(msg_b64.as_bytes()).ok()?;
    let mac = eng.decode(mac_b64.as_bytes()).ok()?;
    let message = std::str::from_utf8(&msg_bytes).ok()?.to_string();

    let mut fields = message.split('|');
    let code = fields.next()?;
    let version = fields.next()?;
    let age_raw = fields.next()?;
    if fields.next().is_some() {
        return None; // too many fields
    }
    if code.is_empty() || version.is_empty() {
        return None;
    }
    // Canonical mint emits "1"/"0"; "true"/"false" accepted for robustness
    // (the MAC still authenticates the exact message bytes either way).
    let age_confirmed = match age_raw {
        "1" | "true" => true,
        "0" | "false" => false,
        _ => return None,
    };

    Some(ReceiptParts {
        code: code.to_string(),
        version: version.to_string(),
        age_confirmed,
        message,
        mac,
    })
}

/// Constant-time comparison of two byte slices.
///
/// Intended for fixed-length MACs (the 32-byte HMAC-SHA256 here), whose length
/// is public; unequal lengths return `false` immediately. For variable-length
/// secret comparison, prefer a crate like `subtle`.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// --- private helpers -------------------------------------------------------

/// Trim a trailing newline / trailing whitespace from a loaded markdown doc.
/// Leading and interior content (including meaningful indentation) is kept.
fn trim_doc(raw: String) -> String {
    // `trim_end` returns a view into `raw`; normalize an all-whitespace doc to
    // `None` upstream (resolve_doc) — here just trim the tail.
    let end = raw.trim_end();
    end.to_string()
}

/// Resolve a markdown document from an optional inline value and an optional
/// file path.
///
/// - `Ok(None)` — neither source set (the doc is simply not configured).
/// - `Ok(Some(md))` — inline value, or the file's contents (trailing newline
///   trimmed).
/// - `Err(Ambiguous)` — both inline and file set (the source must be
///   unambiguous).
/// - `Err(FileRead)` — a file path was set but is missing/unreadable.
fn resolve_doc(
    kind: &'static str,
    inline_key: &'static str,
    file_key: &'static str,
    inline: Option<String>,
    file: Option<String>,
) -> Result<Option<String>, JoinPolicyError> {
    match (inline, file) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(JoinPolicyError::Ambiguous {
            kind,
            inline: inline_key,
            file: file_key,
        }),
        (Some(raw), None) => {
            let trimmed = raw.trim_end();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        (None, Some(path)) => {
            let p = path.trim();
            if p.is_empty() {
                return Ok(None);
            }
            read_doc_file(kind, p).map(Some)
        }
    }
}

/// Read a markdown document from `path`. Trims a trailing newline only.
fn read_doc_file(kind: &'static str, path: &str) -> Result<String, JoinPolicyError> {
    let raw = std::fs::read_to_string(path).map_err(|source| JoinPolicyError::FileRead {
        kind,
        path: path.to_string(),
        source,
    })?;
    Ok(trim_doc(raw))
}

/// Parse a boolean env var, matching the bridge's accepted truthy set
/// (`1`/`true`/`yes`/`on`, case-insensitive). Anything else ⇒ `default`.
fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

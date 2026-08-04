//! M1b invite + policy-receipt service (WP-IP). Owner: wp-invites.
//!
//! A **pure, stateless leaf**: no `AppState`, no route/axum concrete wiring, no
//! relay secret, no invite database. It owns only the deterministic shapes the
//! HTTP wire layer (WP-W) and the x0x direct-message bus need, plus the trait
//! seams the wire layer adapts over the real collaborators.
//!
//! # Authority / claimant split (loopback-bridge aware)
//!
//! A loopback bridge is a *facade* backed by the x0x fabric; it **cannot**
//! directly mutate a *remote* authority's NIP-29 group state. The invite
//! `code` is therefore minted by, and ultimately honored by, the **authority**
//! — the relay whose signing key owns the community (its pubkey *is*
//! `community_id`). This module exposes two independent pure surfaces:
//!
//! - **Authority-side** ([`InviteAuthorityService`]): mints the relay-signed
//!   multi-use code, mints policy receipts (HMAC), and — when a claim request
//!   arrives over the bus — verifies the code against the *current* authority
//!   identity, gates on policy/age, short-circuits `already_member`, then
//!   invokes the membership-mutation callback **exactly once**. The authority
//!   owns the group, so the durable kind-39002 write is correct *here*.
//! - **Claimant-side** ([`parse_invite_code`] + [`claimant_claim`]): parses a
//!   code **without** any secret (extracting `community_id` +
//!   `authority_agent_id`), optionally pre-verifies the signature against the
//!   embedded `community_id`, then forwards the claim to the authority over the
//!   [`AuthorityBus`] trait (x0xd direct-message, supplied by the wire layer).
//!
//! # The invite `code` (stateless, multi-use, relay-signed)
//!
//! ```text
//! payload = {"v":1,"cid":<authority_pubkey_hex>,"aid":<authority_agent_id>,
//!            "exp":<unix_secs>,"n":<nonce>}
//! sig     = Schnorr_sign(authority_secret, payload_json_bytes)
//! code    = b64url_no_pad(payload_json) + "." + b64url_no_pad(sig)
//! ```
//!
//! - **Multi-use**: one code admits many joiners until `exp`; it is not
//!   individually revocable — rotating the authority relay key revokes every
//!   outstanding code (verification binds the *current* identity).
//! - **No `/` in the alphabet** (base64url-no-pad + `.`) ⇒ URL-safe in
//!   `/invite/<code>` and the bare-code form.
//! - The signature is computed over the **exact stored payload bytes**, so mint
//!   and verify can never disagree on canonicalization: the verifier decodes
//!   the payload bytes from the token and checks the signature over *those*
//!   bytes — no re-serialization is involved.
//!
//! # Secret hygiene
//!
//! No type in this module holds secret key material. The authority secret lives
//! behind the [`InviteAuthority`] trait (sign / MAC / verify). [`InviteError`]
//! is a unit enum — its `Debug`/`Display` and every response body carry only
//! fixed, sanitized reason strings. Wire types that transport a `code`,
//! receipt, or pubkey deliberately omit `Debug` so a capability can never leak
//! into a log line.
//!
//! # What this module does NOT do (reported integration seams)
//!
//! - NIP-98 caller auth — the existing `auth::authenticate` (kind 27235)
//!   establishes the principal before any service method runs; the pubkey is
//!   passed in. The joining key's claim is authenticated on the claimant side
//!   by NIP-98 and on the authority side by the bus's agent-id↔pubkey binding.
//! - The x0xd direct-message hop — abstracted by [`AuthorityBus`].
//! - NIP-29 group-state emission — abstracted by [`InviteMembershipWriter`];
//!   the wire layer must expose `nip29::emit_members` (+ `MemberSet` /
//!   `latest_addressable`) as `pub(crate)` or add a thin
//!   `add_community_member` wrapper.
//! - The two new `RelayIdentity` helpers (`mac`, `sign_invite_payload`) plus a
//!   panic-free Schnorr `verify` — see [`InviteAuthority`].

use async_trait::async_trait;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::auth::PortableNip98Proof;
use crate::join_policy::{
    constant_time_eq, encode_receipt, parse_receipt, receipt_message, JoinPolicyConfig,
    RECEIPT_DOMAIN,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default invite TTL when the client omits `ttl_secs` (contract §3: 86400).
pub const DEFAULT_INVITE_TTL_SECS: u64 = 86_400;
/// Hard ceiling on a requested TTL (contract §7: "cap ≤ 30d").
pub const MAX_INVITE_TTL_SECS: u64 = 30 * 86_400;
/// Invite payload version — the `v` field in the signed JSON. Bump only on a
/// breaking change to the payload shape; the authority rejects any other `v`.
pub const INVITE_PAYLOAD_VERSION: u8 = 1;
/// Canonical HMAC domain separator for policy receipts. **Public, not secret**
/// — re-exported from `join_policy` so callers import it from one place.
pub use crate::join_policy::RECEIPT_DOMAIN as POLICY_RECEIPT_DOMAIN;

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
/// Expected raw BIP-340 signature length, in bytes.
const SCHNORR_SIG_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Authority-side capability traits
// ---------------------------------------------------------------------------

/// The authority relay's signing capability. The wire layer implements this over
/// `RelayIdentity` once the three new methods land (contract §11 / WP-IP):
///
/// - `pub fn mac(&self, domain: &[u8], msg: &[u8]) -> Vec<u8>` —
///   `HMAC-SHA256(key = SHA256(domain || secret_bytes), msg)`.
/// - `pub fn sign_invite_payload(&self, payload: &str) -> Vec<u8>` — Schnorr
///   sign over `payload.as_bytes()`, returning the raw 64-byte BIP-340 sig.
/// - a panic-free `verify` against the current key (see below).
///
/// `public_key_hex` already exists on `RelayIdentity`. **Critical:** the
/// `verify_*` impls MUST be total — return `false` on any malformed input
/// (wrong sig length, bad point, bad encoding); never panic. This module guards
/// the signature length first, but the impl must still be panic-free.
///
/// Sign and verify are a matched pair owned by the same key: keeping both here
/// (rather than verifying in the leaf) means the leaf never guesses the signing
/// convention and the two can never disagree.
pub trait InviteAuthority: Send + Sync {
    /// The authority's stable pubkey hex — the NIP-11 `self`, i.e. `community_id`.
    fn public_key_hex(&self) -> String;
    /// Schnorr-sign the canonical invite payload JSON; raw 64-byte sig.
    fn sign_authority_payload(&self, payload: &str) -> Vec<u8>;
    /// Verify a payload signature against the **current** authority identity.
    /// Rotation ⇒ `false` for every previously-minted code.
    fn verify_authority_payload(&self, payload: &str, sig: &[u8]) -> bool;
    /// HMAC-SHA256 keyed with `SHA256(domain || secret)` over `msg`. Used for
    /// the (public-domain) policy-receipt MAC; the secret never leaves the impl.
    fn mac(&self, domain: &[u8], msg: &[u8]) -> Vec<u8>;
}

/// Caller-supplied **read** authorization surface. The authority answers these
/// over its membership store / env admin list (contract §0):
/// - `is_community_admin` — env `BRIDGE_COMMUNITY_ADMINS` OR an `admin`/`owner`
///   role in any channel's kind-39001.
/// - `is_community_member` — the pubkey is a `member`/`owner`/`admin` in any
///   channel's kind-39002 (equivalently, a row in `members`).
pub trait InviteMembership: Send + Sync {
    /// `true` iff `pubkey` may mint invites for this community.
    fn is_community_admin(&self, pubkey: &str) -> bool;
    /// `true` iff `pubkey` is already a member of this community.
    fn is_community_member(&self, pubkey: &str) -> bool;
}

/// Caller-supplied **write** surface: the durable membership mutation the
/// authority performs once a claim is fully validated. The wire layer
/// implements this by emitting the updated signed kind-39002 (durable
/// authority) + mirroring into the engine's membership table (best-effort),
/// then fanning out to gossip / live WS. `Err` carries a sanitized reason.
///
/// Invoked **exactly once** per successful [`InviteAuthorityService::apply_claim`],
/// only after the code, policy, and already-member checks have all passed.
#[async_trait]
pub trait InviteMembershipWriter: Send + Sync {
    async fn add_community_member(
        &self,
        channel_id: &str,
        pubkey: &str,
        role: &str,
    ) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Claimant-side capability traits
// ---------------------------------------------------------------------------

/// Public-key signature verifier a *claimant* (loopback bridge) may supply to
/// reject forged codes before paying for a bus round-trip. Schnorr verify is
/// public-key only — no secret is needed, so this is safe to hand to the
/// claimant side. MUST be total (return `false`, never panic) on malformed
/// input. Optional: the authority verifies authoritatively regardless.
pub trait InviteCodeVerifier: Send + Sync {
    /// Verify `sig` over `payload` against the hex pubkey `pubkey_hex`.
    fn verify(&self, payload: &str, sig: &[u8], pubkey_hex: &str) -> bool;
}

/// The x0x direct-message bus a claimant uses to reach the authority that
/// minted a code. The wire layer implements this over x0xd once the
/// agent-routed DM capability exists: it forwards [`ClaimBusRequest`] to
/// `authority_agent_id`, authenticating the sender via the x0x AgentId ↔ NIP-98
/// pubkey mapping, then awaits the authority's decision (response or gossip).
///
/// - `Ok(ClaimResponse)` — the authority honored the claim (joined /
///   already_member).
/// - `Err(InviteError)` — the authority rejected it (the same sanitized
///   [`InviteError`] travels back and maps straight to an HTTP response), OR
///   the bus itself failed ([`InviteError::AuthorityUnavailable`] — timeout,
///   unroutable, no response).
#[async_trait]
pub trait AuthorityBus: Send + Sync {
    async fn request_claim(
        &self,
        authority_agent_id: &str,
        req: ClaimBusRequest,
    ) -> Result<ClaimResponse, InviteError>;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Borrowed authority/claimant wiring held for the duration of one request.
#[derive(Clone, Copy)]
pub struct InviteOptions<'s> {
    /// Authority's public base URL (the `host`/`url` prefix in responses).
    pub public_base_url: &'s str,
    /// Primary channel a joiner is materialized into (default
    /// `seed::channel_id("general")` at the wire layer).
    pub primary_channel: &'s str,
    /// TTL used when a mint request omits `ttl_secs`.
    pub default_ttl_secs: u64,
    /// Hard ceiling on a requested TTL; out-of-range ⇒ [`InviteError::TtlOutOfRange`].
    pub max_ttl_secs: u64,
}

impl<'s> InviteOptions<'s> {
    /// Construct with the documented TTL defaults
    /// ([`DEFAULT_INVITE_TTL_SECS`] / [`MAX_INVITE_TTL_SECS`]).
    pub fn new(public_base_url: &'s str, primary_channel: &'s str) -> Self {
        Self {
            public_base_url,
            primary_channel,
            default_ttl_secs: DEFAULT_INVITE_TTL_SECS,
            max_ttl_secs: MAX_INVITE_TTL_SECS,
        }
    }
}

// ---------------------------------------------------------------------------
// Authority service
// ---------------------------------------------------------------------------

/// The authority-side pure service. Borrows its collaborators for one request;
/// holds no state and no secret. Construct per-request in the handler.
pub struct InviteAuthorityService<'s, A: InviteAuthority, M: InviteMembership> {
    authority: &'s A,
    membership: &'s M,
    policy: &'s JoinPolicyConfig,
    options: InviteOptions<'s>,
}

impl<'s, A: InviteAuthority, M: InviteMembership> InviteAuthorityService<'s, A, M> {
    pub fn new(
        authority: &'s A,
        membership: &'s M,
        policy: &'s JoinPolicyConfig,
        options: InviteOptions<'s>,
    ) -> Self {
        Self {
            authority,
            membership,
            policy,
            options,
        }
    }

    /// `POST /api/invites` (authority) — mint a stateless, multi-use,
    /// relay-signed invite code. `admin_pubkey` is the already-NIP-98-authed
    /// caller; `authority_agent_id` + `nonce` are bound into the payload so a
    /// claimant can route the claim back over the bus.
    pub async fn mint(
        &self,
        admin_pubkey: &str,
        authority_agent_id: &str,
        nonce: &str,
        req: MintRequest,
        now: u64,
    ) -> Result<MintResponse, InviteError> {
        // 1. Admin gate — rejected before any signing or allocation beyond the
        //    principal lookup. No mutation, no secret op on the deny path.
        if !self.membership.is_community_admin(admin_pubkey) {
            tracing::debug!(target: "invites", "mint denied: not a community admin");
            return Err(InviteError::NotAdmin);
        }
        // 2. TTL bounds.
        let ttl = req.ttl_secs.unwrap_or(self.options.default_ttl_secs);
        if ttl == 0 || ttl > self.options.max_ttl_secs {
            return Err(InviteError::TtlOutOfRange);
        }
        // checked_add: even an absurd `now` cannot overflow into a panic.
        let exp = now.checked_add(ttl).ok_or(InviteError::TtlOutOfRange)?;
        if authority_agent_id.is_empty() {
            return Err(InviteError::MalformedRequest);
        }

        // 3. Build + sign the payload. serde_json owns field order + escaping,
        //    and the *exact* serialized bytes are what travel in the code (and
        //    what verify checks the signature over) — no canonicalization gap.
        let community_id = self.authority.public_key_hex();
        let payload = InvitePayload {
            v: INVITE_PAYLOAD_VERSION,
            cid: community_id.clone(),
            aid: authority_agent_id.to_string(),
            exp,
            n: nonce.to_string(),
        };
        let payload_json =
            serde_json::to_string(&payload).map_err(|_| InviteError::MalformedRequest)?;
        let sig = self.authority.sign_authority_payload(&payload_json);

        let code = encode_code(&payload_json, &sig);
        let url = format!(
            "{}/invite/{code}",
            self.options.public_base_url.trim_end_matches('/')
        );

        Ok(MintResponse {
            code,
            expires_at: exp,
            url,
        })
    }

    /// `POST /api/invites/accept-policy` (authority) — mint a policy receipt.
    /// Unauthed; the MAC requires the authority secret, so this is authority-side
    /// (a loopback bridge forwards it, or the client hits the authority directly).
    /// `code` is NOT signature-verified here — it is only bound into the receipt;
    /// the claim path authenticates the code before honoring any receipt.
    pub fn accept_policy(
        &self,
        req: AcceptPolicyRequest,
    ) -> Result<AcceptPolicyResponse, InviteError> {
        // Disabled ⇒ 404 (contract §9 enable rule: empty version is "off").
        if !self.policy.enabled() {
            return Err(InviteError::PolicyDisabled);
        }
        if req.code.is_empty() || req.policy_version.is_empty() {
            return Err(InviteError::MalformedRequest);
        }
        // The receipt must be for the *current* policy version.
        if req.policy_version != self.policy.version {
            return Err(InviteError::PolicyVersionMismatch);
        }

        let msg = receipt_message(&req.code, &self.policy.version, req.age_confirmed);
        let mac = self.authority.mac(RECEIPT_DOMAIN, msg.as_bytes());
        let receipt = encode_receipt(&msg, &mac);
        Ok(AcceptPolicyResponse { receipt })
    }

    /// Authority-side claim adjudication. Receives the bus request, verifies the
    /// code against the **current** authority identity, enforces the policy gate,
    /// short-circuits `already_member`, then performs the durable membership
    /// mutation **exactly once**. No mutation, no secret op precedes the checks.
    pub async fn apply_claim<W: InviteMembershipWriter>(
        &self,
        req: &ClaimBusRequest,
        writer: &W,
        now: u64,
    ) -> Result<ClaimResponse, InviteError> {
        let joiner = req.joiner_pubkey.as_str();
        if joiner.is_empty() {
            return Err(InviteError::MalformedRequest);
        }

        // 1. Verify code: parse → signature → current-identity binding → expiry.
        //    Parse is shared with the claimant side (no secret needed).
        let view = parse_invite_code(&req.code)?;
        // Signature against the *current* authority key (rotation ⇒ invalid).
        if view.sig.len() != SCHNORR_SIG_LEN
            || !self
                .authority
                .verify_authority_payload(&view.payload_json, &view.sig)
        {
            return Err(InviteError::InvalidCode);
        }
        // The code must be for *this* authority (community_id == our pubkey).
        if view.community_id != self.authority.public_key_hex() {
            return Err(InviteError::InvalidCode);
        }
        if view.expires_at <= now {
            return Err(InviteError::ExpiredCode);
        }

        // 2. Policy gate (only when a policy is enabled — contract §8 step 3).
        if self.policy.enabled() {
            let receipt = req
                .policy_receipt
                .as_deref()
                .ok_or(InviteError::PolicyReceiptInvalid)?;
            let parts = parse_receipt(receipt).ok_or(InviteError::PolicyReceiptInvalid)?;
            // Authenticity: recompute the MAC over the receipt's own message and
            // compare in constant time. This is the only secret-derived compare.
            let expected = self.authority.mac(RECEIPT_DOMAIN, parts.message.as_bytes());
            if !constant_time_eq(&expected, &parts.mac) {
                return Err(InviteError::PolicyReceiptInvalid);
            }
            // Binding: the receipt must be for the code being claimed.
            if parts.code != req.code {
                return Err(InviteError::PolicyReceiptInvalid);
            }
            // Currency: receipt version must match the live policy version.
            if parts.version != self.policy.version {
                return Err(InviteError::PolicyVersionMismatch);
            }
            // Age attestation, if the policy demands it.
            if self.policy.age_attestation_required && !parts.age_confirmed {
                return Err(InviteError::AgeAttestationRequired);
            }
        }

        // 3. Idempotent membership: already a member ⇒ stable 200, no write.
        if self.membership.is_community_member(joiner) {
            return Ok(ClaimResponse::already_member(
                self.authority.public_key_hex(),
                self.options.public_base_url,
            ));
        }

        // 4. Mutation — exactly once, after every check has passed.
        if let Err(reason) = writer
            .add_community_member(self.options.primary_channel, joiner, "member")
            .await
        {
            tracing::warn!(target: "invites", error = %reason, "community membership write failed");
            return Err(InviteError::MembershipWriteFailed);
        }

        Ok(ClaimResponse::joined(
            self.authority.public_key_hex(),
            self.options.public_base_url,
        ))
    }
}

// ---------------------------------------------------------------------------
// Claimant-side pure API
// ---------------------------------------------------------------------------

/// Parse an invite code **without** any secret. Returns the bound authority
/// routing fields (`community_id`, `authority_agent_id`) plus the raw payload
/// and signature bytes (for optional verification / bus forwarding). Reused by
/// the authority's [`InviteAuthorityService::apply_claim`].
///
/// Only structural validation happens here: a single `.` delimiter, valid
/// base64url, UTF-8 payload, the expected `v`, and non-empty `cid`/`aid`. The
/// signature is NOT checked (callers with a key do that via
/// [`InviteCodeView::verify`] or [`InviteAuthority::verify_authority_payload`]).
pub fn parse_invite_code(code: &str) -> Result<InviteCodeView<'_>, InviteError> {
    let (payload_b64, sig_b64) = code.split_once('.').ok_or(InviteError::MalformedCode)?;
    if sig_b64.contains('.') {
        return Err(InviteError::MalformedCode);
    }
    let payload_bytes = B64URL
        .decode(payload_b64.as_bytes())
        .map_err(|_| InviteError::MalformedCode)?;
    let sig = B64URL
        .decode(sig_b64.as_bytes())
        .map_err(|_| InviteError::MalformedCode)?;
    let payload_json =
        std::str::from_utf8(&payload_bytes).map_err(|_| InviteError::MalformedCode)?;
    let payload: InvitePayload =
        serde_json::from_str(payload_json).map_err(|_| InviteError::MalformedCode)?;
    if payload.v != INVITE_PAYLOAD_VERSION {
        return Err(InviteError::MalformedCode);
    }
    if payload.cid.is_empty() || payload.aid.is_empty() {
        return Err(InviteError::MalformedCode);
    }
    Ok(InviteCodeView {
        version: payload.v,
        community_id: payload.cid,
        authority_agent_id: payload.aid,
        expires_at: payload.exp,
        nonce: payload.n,
        payload_json: payload_json.to_string(),
        sig,
        raw_code: code,
    })
}

/// A parsed, structurally-valid invite code (no signature verdict). Borrows the
/// original code string for zero-copy forwarding.
pub struct InviteCodeView<'a> {
    /// Payload version (currently [`INVITE_PAYLOAD_VERSION`]).
    pub version: u8,
    /// Authority relay pubkey hex — the `community_id` a successful join lands in.
    pub community_id: String,
    /// x0x AgentId to direct-message with the claim (the bus routing key).
    pub authority_agent_id: String,
    /// Code expiry, unix seconds.
    pub expires_at: u64,
    /// Per-mint nonce (identifies this multi-use code; not per-claim).
    pub nonce: String,
    /// The exact payload bytes the authority signed.
    pub payload_json: String,
    /// Raw signature bytes from the token.
    pub sig: Vec<u8>,
    /// The original code string, for verbatim bus forwarding.
    pub raw_code: &'a str,
}

impl<'a> InviteCodeView<'a> {
    /// `true` if the code has expired relative to `now` (`exp <= now`).
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at <= now
    }

    /// Optional claimant-side pre-verification against the embedded
    /// `community_id`. Returns `false` for any malformed signature; never
    /// panics (the verifier impl contract is total).
    pub fn verify<V: InviteCodeVerifier>(&self, verifier: &V) -> bool {
        if self.sig.len() != SCHNORR_SIG_LEN {
            return false;
        }
        verifier.verify(&self.payload_json, &self.sig, &self.community_id)
    }
}

/// `POST /api/invites/claim` on a **loopback** bridge: parse the code, fail
/// fast on local expiry, then forward to the authority over the bus and relay
/// its decision. `joiner_pubkey` is the already-NIP-98-authed joining key.
/// `auth_proof` is the portable NIP-98 proof established at this claimant (from
/// `auth::Principal::portable_nip98`); the authority re-verifies it
/// byte-for-byte before honoring the claim. `None` on the dev `X-Pubkey` path.
///
/// The authority is the sole arbiter of code validity, policy, and membership —
/// this function never mutates anything locally and holds no authority secret.
pub async fn claimant_claim<B: AuthorityBus>(
    bus: &B,
    joiner_pubkey: &str,
    req: ClaimRequest,
    auth_proof: Option<PortableNip98Proof>,
    now: u64,
) -> Result<ClaimResponse, InviteError> {
    if joiner_pubkey.is_empty() {
        return Err(InviteError::MalformedRequest);
    }
    // Parse routes the claim; a malformed code is rejected without a round-trip.
    let view = parse_invite_code(&req.code)?;
    // Fail fast on expiry — `exp` is in the clear and readable locally.
    if view.is_expired(now) {
        return Err(InviteError::ExpiredCode);
    }
    let bus_req = ClaimBusRequest {
        code: req.code.clone(),
        policy_receipt: req.policy_receipt,
        joiner_pubkey: joiner_pubkey.to_string(),
        auth_proof,
    };
    // The authority's sanitized error (or a bus-level AuthorityUnavailable)
    // propagates straight to the HTTP layer via InviteError::IntoResponse.
    bus.request_claim(&view.authority_agent_id, bus_req).await
}

// ---------------------------------------------------------------------------
// Wire payload (private) + code codec helpers
// ---------------------------------------------------------------------------

/// The signed JSON payload. Field order is the wire order; serde owns escaping
/// so an arbitrary `aid` string cannot break the JSON.
#[derive(Serialize, Deserialize)]
struct InvitePayload {
    v: u8,
    cid: String,
    aid: String,
    exp: u64,
    n: String,
}

/// `b64url_no_pad(payload_json) + "." + b64url_no_pad(sig)`.
fn encode_code(payload_json: &str, sig: &[u8]) -> String {
    format!(
        "{}.{}",
        B64URL.encode(payload_json.as_bytes()),
        B64URL.encode(sig),
    )
}

// ---------------------------------------------------------------------------
// Request / response / error types (axum-composable)
// ---------------------------------------------------------------------------

/// `POST /api/invites` body: `{}` or `{"ttl_secs":N}`.
#[derive(Deserialize)]
pub struct MintRequest {
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

/// `POST /api/invites/accept-policy` body.
#[derive(Deserialize)]
pub struct AcceptPolicyRequest {
    pub code: String,
    pub policy_version: String,
    pub age_confirmed: bool,
}

/// `POST /api/invites/claim` body (desktop `claimInvite`).
#[derive(Deserialize, Serialize, PartialEq, Eq)]
pub struct ClaimRequest {
    pub code: String,
    #[serde(default)]
    pub policy_receipt: Option<String>,
}

/// The direct-message payload a claimant forwards to the authority. Serializes
/// for the x0xd hop; the authority deserializes it into [`apply_claim`].
///
/// [`apply_claim`]: InviteAuthorityService::apply_claim
#[derive(Serialize, Deserialize)]
pub struct ClaimBusRequest {
    /// Verbatim invite code (the authority re-parses + verifies).
    pub code: String,
    /// Policy receipt (required iff the authority's policy is enabled).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub policy_receipt: Option<String>,
    /// The joining key's pubkey (bus-authenticated as the sender).
    pub joiner_pubkey: String,
    /// Portable NIP-98 proof the claimant established and the authority
    /// re-verifies byte-for-byte (contract: portable joiner proof). `None` on
    /// the dev `X-Pubkey` path. Omitted from the wire when absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub auth_proof: Option<PortableNip98Proof>,
}

/// `POST /api/invites` 200 response.
#[derive(Serialize, Deserialize)]
pub struct MintResponse {
    pub code: String,
    pub expires_at: u64,
    pub url: String,
}

/// `POST /api/invites/accept-policy` 200 response.
#[derive(Serialize, Deserialize)]
pub struct AcceptPolicyResponse {
    pub receipt: String,
}

/// `POST /api/invites/claim` 200 response — `joined` or `already_member`.
/// Travels back over the bus verbatim from authority to claimant.
#[derive(Serialize, Deserialize)]
pub struct ClaimResponse {
    /// `"joined"` or `"already_member"`.
    pub status: String,
    /// Authority relay pubkey (= the community joined).
    pub community_id: String,
    /// Authority public base URL.
    pub host: String,
    /// Always `"member"` for a claim materialization.
    pub role: String,
}

impl ClaimResponse {
    pub fn joined(community_id: String, host: &str) -> Self {
        Self {
            status: "joined".to_string(),
            community_id,
            host: host.to_string(),
            role: "member".to_string(),
        }
    }

    pub fn already_member(community_id: String, host: &str) -> Self {
        Self {
            status: "already_member".to_string(),
            community_id,
            host: host.to_string(),
            role: "member".to_string(),
        }
    }
}

/// Sanitized invite-service error. A unit enum by design: no variant carries
/// data, so `Debug`/`Display` and every response body expose only fixed reason
/// strings — a code, receipt, pubkey, or secret can never leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InviteError {
    /// Request body could not be parsed / failed sanity checks (400).
    MalformedRequest,
    /// `ttl_secs` is zero or exceeds the max (400).
    TtlOutOfRange,
    /// Code is structurally malformed / undecodable (400).
    MalformedCode,
    /// Code signature fails or is for a different authority (403).
    InvalidCode,
    /// Code's `exp` is in the past (403).
    ExpiredCode,
    /// Caller is not a community admin (403).
    NotAdmin,
    /// Policy is disabled — `accept-policy` is not served (404).
    PolicyDisabled,
    /// Receipt/policy-version does not match the live policy (400).
    PolicyVersionMismatch,
    /// Receipt missing/malformed/forged, or not for this code (400).
    PolicyReceiptInvalid,
    /// Policy requires age attestation and the receipt did not confirm (403).
    AgeAttestationRequired,
    /// The durable membership write failed (500).
    MembershipWriteFailed,
    /// The authority could not be reached / did not answer (502).
    AuthorityUnavailable,
}

impl InviteError {
    /// HTTP status code for this error.
    pub fn status_code(self) -> StatusCode {
        match self {
            Self::MalformedRequest
            | Self::TtlOutOfRange
            | Self::MalformedCode
            | Self::PolicyVersionMismatch
            | Self::PolicyReceiptInvalid => StatusCode::BAD_REQUEST,
            Self::InvalidCode
            | Self::ExpiredCode
            | Self::NotAdmin
            | Self::AgeAttestationRequired => StatusCode::FORBIDDEN,
            Self::PolicyDisabled => StatusCode::NOT_FOUND,
            Self::MembershipWriteFailed => StatusCode::INTERNAL_SERVER_ERROR,
            Self::AuthorityUnavailable => StatusCode::BAD_GATEWAY,
        }
    }

    /// Fixed, sanitized reason string (the `{"error": …}` body).
    pub fn message(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed request body",
            Self::TtlOutOfRange => "ttl_secs out of range",
            Self::MalformedCode => "malformed invite code",
            Self::InvalidCode => "invalid invite code",
            Self::ExpiredCode => "invite_expired",
            Self::NotAdmin => "restricted: not a community admin",
            Self::PolicyDisabled => "join policy is disabled",
            Self::PolicyVersionMismatch => "policy_version mismatch",
            Self::PolicyReceiptInvalid => "policy_receipt",
            Self::AgeAttestationRequired => "age attestation required",
            Self::MembershipWriteFailed => "membership update failed",
            Self::AuthorityUnavailable => "authority unavailable",
        }
    }
}

// --- IntoResponse: success bodies (200 JSON) + the error envelope ----------

impl IntoResponse for MintResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

impl IntoResponse for AcceptPolicyResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

impl IntoResponse for ClaimResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

impl IntoResponse for InviteError {
    fn into_response(self) -> Response {
        // Mirrors http::api_error: `(status, Json({"error": msg}))`.
        (
            self.status_code(),
            Json(serde_json::json!({ "error": self.message() })),
        )
            .into_response()
    }
}

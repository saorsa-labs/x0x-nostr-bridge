//! M1b wiring layer: trait adapters, the typed authority request/response
//! worker, and the HTTP route handlers for media, join-policy, and invites.
//!
//! This module is pure glue — it implements the trait seams declared by the
//! leaf modules (`media/**`, `invites.rs`, `join_policy.rs`,
//! `direct_transport.rs`) over the concrete collaborators (`AppState`,
//! `RelayIdentity`, `HistoryEngine`, `nip29`). No behavior is invented here:
//! every decision flows through the leaf-module APIs.
//!
//! # Authority / claimant architecture
//!
//! The bridge IS the authority (its relay key owns the community). A claim
//! arriving at `POST /api/invites/claim` is forwarded to the authority worker
//! via an in-process typed RPC channel — NOT a direct local mutation. The
//! worker adjudicates (`apply_claim` → `nip29::add_member_from_invite`) and
//! replies; the claimant handler awaits that reply (never the transport
//! receipt). Cross-node claim forwarding over `X0xDirectTransport` is wired at
//! startup but depends on daemon self-DM routing that is not verified for the
//! single-node case (reported as a capability gap, not faked).

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use dashmap::DashMap;
use nostr::{Filter, Kind, PublicKey};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::auth::{self, AuthError};
use crate::direct_transport::{AgentId, DirectMessage, X0xDirectTransport};
use crate::engine_api::HistoryEngine;
use crate::http;
use crate::invites::{
    self, AcceptPolicyRequest, AuthorityBus, ClaimBusRequest, ClaimRequest, ClaimResponse,
    InviteAuthority, InviteError, InviteMembership, InviteMembershipWriter, InviteOptions,
    MintRequest,
};
use crate::join_policy::PolicyDoc;
use crate::media::serve::{MediaServe, MemberCheck, ReplayGuard, ReplayRejection};
use crate::media::upload::{MediaMembership, MediaReplay, MediaUploadConfig, MediaUploadState};
use crate::media::MediaStore;
use crate::relay::AppState;
use crate::relay_identity::{self, RelayIdentity};
use crate::seed;
use crate::settings::Settings;

// ===========================================================================
// Helpers
// ===========================================================================

/// Extract `host[:port]` from the public base URL — the BUD-11 `server`-tag
/// comparison target. Strips scheme + path/query/fragment, lowercases.
pub fn relay_authority(public_base_url: &str) -> String {
    let base = public_base_url.trim();
    let after_scheme = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base);
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme)
        .to_ascii_lowercase()
}

/// Resolve the primary channel: explicit setting, or the deterministic seed
/// `general` channel UUID.
pub fn primary_channel(settings: &Settings) -> String {
    if settings.community_primary_channel.is_empty() {
        seed::channel_id("general")
    } else {
        settings.community_primary_channel.clone()
    }
}

// ===========================================================================
// Invite trait adapters
// ===========================================================================

/// `InviteAuthority` over `RelayIdentity` — sign/verify/MAC via the relay key.
pub struct RelayInviteAuthority(pub Arc<RelayIdentity>);

impl InviteAuthority for RelayInviteAuthority {
    fn public_key_hex(&self) -> String {
        self.0.public_key_hex()
    }
    fn sign_authority_payload(&self, payload: &str) -> Vec<u8> {
        self.0.sign_invite_payload(payload)
    }
    fn verify_authority_payload(&self, payload: &str, sig: &[u8]) -> bool {
        self.0.verify_authority_payload(payload, sig)
    }
    fn mac(&self, domain: &[u8], msg: &[u8]) -> Vec<u8> {
        self.0.mac(domain, msg)
    }
}

/// `InviteMembership` over the history engine + env admin list.
///
/// The sync trait methods bridge to the async engine via `block_in_place`
/// (safe on the multi-threaded runtime the bridge uses). A query failure is
/// fail-closed: `is_community_admin` returns `false`, and
/// `is_community_member` returns `false` (the idempotent mutation in
/// `add_member_from_invite` is the safety net — it re-checks the 39002 set).
pub struct EngineInviteMembership {
    engine: Arc<dyn HistoryEngine>,
    admins: Vec<String>,
}

impl EngineInviteMembership {
    pub fn new(engine: Arc<dyn HistoryEngine>, settings: &Settings) -> Self {
        Self {
            engine,
            admins: settings.community_admins.clone(),
        }
    }
}

impl InviteMembership for EngineInviteMembership {
    fn is_community_admin(&self, pubkey: &str) -> bool {
        let pk_lower = pubkey.to_ascii_lowercase();
        if self.admins.contains(&pk_lower) {
            return true;
        }
        // Admin/owner role in any channel's kind-39001.
        let Ok(pk) = PublicKey::from_hex(pubkey) else {
            return false;
        };
        let engine = Arc::clone(&self.engine);
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let filter = Filter::new()
                    .kind(Kind::from(crate::kinds::KIND_GROUP_ADMINS))
                    .pubkey(pk);
                engine
                    .query(&filter)
                    .await
                    .map(|evs| !evs.is_empty())
                    .unwrap_or(false)
            })
        })
    }

    fn is_community_member(&self, pubkey: &str) -> bool {
        let Ok(pk) = PublicKey::from_hex(pubkey) else {
            return false;
        };
        let engine = Arc::clone(&self.engine);
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let filter = Filter::new()
                    .kind(Kind::from(crate::kinds::KIND_GROUP_MEMBERS))
                    .pubkey(pk);
                engine
                    .query(&filter)
                    .await
                    .map(|evs| !evs.is_empty())
                    .unwrap_or(false)
            })
        })
    }
}

/// `InviteMembershipWriter` over `nip29::add_member_from_invite` — the
/// authoritative durable mutation (signed kind-39002 + members mirror +
/// gossip/WS fan-out), invoked exactly once per validated claim.
pub struct Nip29MembershipWriter(pub Arc<AppState>);

#[async_trait]
impl InviteMembershipWriter for Nip29MembershipWriter {
    async fn add_community_member(
        &self,
        channel_id: &str,
        pubkey: &str,
        _role: &str,
    ) -> Result<(), String> {
        // `add_member_from_invite` is idempotent (checks the current 39002
        // MemberSet before emitting) and authoritative (signs with the relay
        // identity, stores durably, fans out). A sanitized reason string
        // travels back on failure — no secret detail.
        crate::nip29::add_member_from_invite(&self.0, channel_id, pubkey)
            .await
            .map(|_| ())
    }
}

// ===========================================================================
// Media trait adapters
// ===========================================================================

/// Shared replay guard — adapts the NIP-98 `ReplayCache` for both Blossom
/// serve (`ReplayGuard`) and upload (`MediaReplay`) paths. One cache instance
/// serves all auth-event replay checks (NIP-98 27235 + Blossom 24242);
/// event ids are globally unique so cross-keying is impossible.
pub struct SharedReplayGuard(pub Arc<auth::ReplayCache>);

impl ReplayGuard for SharedReplayGuard {
    fn check_and_record(
        &self,
        event_id: &str,
        now: u64,
        ttl_secs: u64,
    ) -> Result<(), ReplayRejection> {
        match self.0.check_and_record(event_id, now, ttl_secs) {
            Ok(()) => Ok(()),
            Err(AuthError::ReplayDetected) => Err(ReplayRejection::Replayed),
            Err(_) => Err(ReplayRejection::Unavailable),
        }
    }
}

impl MediaReplay for SharedReplayGuard {
    fn check_and_record(&self, event_id: &str, now: u64, ttl_secs: u64) -> bool {
        self.0.check_and_record(event_id, now, ttl_secs).is_ok()
    }
}

/// Fail-closed community membership check for the serve path.
pub struct EngineMemberCheck(pub Arc<dyn HistoryEngine>);

#[async_trait]
impl MemberCheck for EngineMemberCheck {
    async fn is_community_member(&self, pubkey_hex: &str) -> anyhow::Result<bool> {
        let Ok(pk) = PublicKey::from_hex(pubkey_hex) else {
            return Ok(false);
        };
        let engine = Arc::clone(&self.0);
        let filter = Filter::new()
            .kind(Kind::from(crate::kinds::KIND_GROUP_MEMBERS))
            .pubkey(pk);
        Ok(!engine.query(&filter).await?.is_empty())
    }
}

/// Fail-closed community membership check for the upload path.
pub struct EngineMediaMembership(pub Arc<dyn HistoryEngine>);

#[async_trait]
impl MediaMembership for EngineMediaMembership {
    async fn is_community_member(&self, pubkey_hex: &str) -> bool {
        let Ok(pk) = PublicKey::from_hex(pubkey_hex) else {
            return false;
        };
        let engine = Arc::clone(&self.0);
        let filter = Filter::new()
            .kind(Kind::from(crate::kinds::KIND_GROUP_MEMBERS))
            .pubkey(pk);
        engine
            .query(&filter)
            .await
            .map(|evs| !evs.is_empty())
            .unwrap_or(false)
    }
}

// ===========================================================================
// Typed authority request/response worker
// ===========================================================================

/// Claim outcome travelling from authority to claimant.
#[derive(Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ClaimResult {
    #[serde(rename = "ok")]
    Ok(ClaimResponse),
    #[serde(rename = "err")]
    Err(InviteError),
}

impl From<Result<ClaimResponse, InviteError>> for ClaimResult {
    fn from(r: Result<ClaimResponse, InviteError>) -> Self {
        match r {
            Ok(r) => ClaimResult::Ok(r),
            Err(e) => ClaimResult::Err(e),
        }
    }
}

// ===========================================================================
// Direct-message RPC envelope (cross-device claim/result)
// ===========================================================================

/// Direct-message RPC envelope version.
pub(crate) const DIRECT_ENVELOPE_VERSION: u8 = 1;

/// The authority's adjudication, carried explicitly split into ok/err arms.
/// `ClaimResult`'s `#[serde(tag = "status")]` collides with
/// [`ClaimResponse`]'s own `status` field and cannot round-trip over the wire;
/// this struct avoids that by using a boolean discriminator.
#[derive(Serialize, Deserialize)]
pub(crate) struct DirectResult {
    pub(crate) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) response: Option<ClaimResponse>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) error: Option<InviteError>,
}

impl DirectResult {
    fn from_claim_result(r: ClaimResult) -> Self {
        match r {
            ClaimResult::Ok(resp) => DirectResult {
                ok: true,
                response: Some(resp),
                error: None,
            },
            ClaimResult::Err(e) => DirectResult {
                ok: false,
                response: None,
                error: Some(e),
            },
        }
    }

    fn into_claim_result(self) -> Option<ClaimResult> {
        match (self.ok, self.response, self.error) {
            (true, Some(r), None) => Some(ClaimResult::Ok(r)),
            (false, None, Some(e)) => Some(ClaimResult::Err(e)),
            _ => None,
        }
    }
}

/// Tagged direct-message envelope carrying a claim request or its result
/// between a claimant bridge and the authority bridge over verified x0xd
/// direct messages.
///
/// **Unsigned by design.** Trust flows from the daemon's verified sender
/// binding (ML-DSA) matching the code-bound authority AgentId, which in turn
/// binds the community relay pubkey via the signed invite code — no redundant
/// secp256k1 signature is needed on the envelope.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind")]
pub(crate) enum DirectEnvelope {
    #[serde(rename = "claim")]
    Claim {
        version: u8,
        request_id: String,
        /// Claimant's AgentId — where the authority should send the result.
        reply_to: String,
        /// The portable claim (code + proof + joiner pubkey).
        claim: ClaimBusRequest,
    },
    #[serde(rename = "result")]
    Result {
        version: u8,
        request_id: String,
        /// The authority's adjudication.
        result: DirectResult,
    },
}

/// One pending claim awaiting an authority reply.
struct PendingClaim {
    reply: oneshot::Sender<ClaimResult>,
    #[allow(dead_code)]
    deadline: Instant,
}

/// RAII guard for one pending-claim map entry. Created after a bounded
/// `Semaphore` permit is acquired and the entry inserted; on drop — whether
/// `request_claim` returns normally or its future is dropped early (client
/// disconnect) — it removes the entry and releases the permit. This is the
/// sole cleanup owner on the bus side: the worker's `complete` / dispatcher's
/// result handler also remove (to extract the reply sender), idempotently
/// against this guard.
///
/// Fixes two defects: (1) a dropped HTTP future leaked the DashMap entry (the
/// trailing `pending.remove` never ran); (2) `len() >= MAX` then `insert` was a
/// TOCTOU capacity race. `try_acquire_owned` bounds live entries atomically.
struct PendingEntryGuard<T> {
    pending: Arc<DashMap<String, T>>,
    request_id: String,
    _permit: OwnedSemaphorePermit,
}

impl<T> PendingEntryGuard<T> {
    fn new(
        pending: Arc<DashMap<String, T>>,
        request_id: String,
        permit: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            pending,
            request_id,
            _permit: permit,
        }
    }
}

impl<T> Drop for PendingEntryGuard<T> {
    fn drop(&mut self) {
        self.pending.remove(&self.request_id);
        // `_permit` drops here, releasing the bounded pending slot.
    }
}

/// A work item the authority worker processes.
pub(crate) struct ClaimWork {
    pub(crate) request_id: String,
    pub(crate) req: ClaimBusRequest,
    /// Daemon-verified sender binding (always `true` for the local in-process
    /// path; required `true` for any future remote-DM path).
    pub(crate) verified: bool,
    /// When `Some`, the adjudication result is serialized and sent back to this
    /// agent over the direct transport (a remote claim received via the
    /// dispatcher). When `None`, the local pending oneshot is completed.
    pub(crate) remote_reply_to: Option<AgentId>,
}

/// Shared authority state: a bounded pending-claim map, the in-process work
/// channel's sender, and its single-take receiver (drained by the worker).
///
/// Cloned cheaply via `Arc` — the router clones this to build the
/// [`LocalAuthorityBus`], sharing the pending map + sender. The work-channel
/// receiver is held behind a shared `Arc<Mutex<Option<_>>>` so
/// [`spawn_authority_worker`] can take it exactly once from any clone.
#[derive(Clone)]
pub struct AuthorityState {
    pending: Arc<DashMap<String, PendingClaim>>,
    work_tx: mpsc::Sender<ClaimWork>,
    work_rx: Arc<Mutex<Option<mpsc::Receiver<ClaimWork>>>>,
    claim_timeout: Duration,
    /// Bounded pending-slot semaphore (MAX_PENDING_CLAIMS). Acquired per claim
    /// via `try_acquire_owned` before the insert — atomically bounds live
    /// pending claims and is released by the [`PendingEntryGuard`] on drop.
    semaphore: Arc<Semaphore>,
}

/// Bounded capacity for the pending-claim map (DoS guard).
const MAX_PENDING_CLAIMS: usize = 256;
/// Default claim round-trip timeout.
const DEFAULT_CLAIM_TIMEOUT: Duration = Duration::from_secs(30);

impl AuthorityState {
    /// Create the authority state, holding the work-channel receiver until
    /// [`spawn_authority_worker`] takes it. The router calls this for the
    /// test fallback (no worker ⇒ a claim times out → 502, honestly).
    pub(crate) fn new() -> Self {
        Self::with_timeout(DEFAULT_CLAIM_TIMEOUT)
    }

    /// Create with an explicit claim timeout (tests).
    pub(crate) fn with_timeout(timeout: Duration) -> Self {
        let (work_tx, work_rx) = mpsc::channel(64);
        Self {
            pending: Arc::new(DashMap::with_capacity(MAX_PENDING_CLAIMS)),
            work_tx,
            work_rx: Arc::new(Mutex::new(Some(work_rx))),
            claim_timeout: timeout,
            semaphore: Arc::new(Semaphore::new(MAX_PENDING_CLAIMS)),
        }
    }
    /// Take the work-channel receiver. Called exactly once, by
    /// [`spawn_authority_worker`], to hand the receiver to the worker task.
    /// `None` if already taken (double-spawn guard). Shared across clones via
    /// `Arc`, so it is taken from whichever clone the worker holds.
    pub(crate) fn take_work_receiver(&self) -> Option<mpsc::Receiver<ClaimWork>> {
        self.work_rx.lock().take()
    }
}

/// The in-process authority bus. Implements `AuthorityBus` by forwarding
/// claims to the authority worker over the work channel and awaiting the reply
/// on a oneshot — **never** treating the channel send as success.
pub struct LocalAuthorityBus {
    state: AuthorityState,
}

impl LocalAuthorityBus {
    pub fn new(state: AuthorityState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl AuthorityBus for LocalAuthorityBus {
    async fn request_claim(
        &self,
        _authority_agent_id: &str,
        req: ClaimBusRequest,
    ) -> Result<ClaimResponse, InviteError> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();

        // Bounded pending slots: acquire atomically (no len()+insert race).
        let permit = Arc::clone(&self.state.semaphore)
            .try_acquire_owned()
            .map_err(|_| InviteError::AuthorityUnavailable)?;

        self.state.pending.insert(
            request_id.clone(),
            PendingClaim {
                reply: tx,
                deadline: Instant::now() + self.state.claim_timeout,
            },
        );
        // RAII: if this future is dropped (client disconnect) the entry is
        // removed and the slot released — no leak. The worker's `complete`
        // also removes (to send the reply); idempotent against this guard.
        let _guard =
            PendingEntryGuard::new(Arc::clone(&self.state.pending), request_id.clone(), permit);

        // Forward to the authority worker. The send receipt is NOT success.
        let work = ClaimWork {
            request_id: request_id.clone(),
            req,
            verified: true,        // NIP-98-authenticated at the HTTP door
            remote_reply_to: None, // in-process: complete via pending oneshot
        };
        if self.state.work_tx.send(work).await.is_err() {
            return Err(InviteError::AuthorityUnavailable); // _guard cleans up
        }

        // Await the authority's adjudication (or timeout). Cleanup is owned by
        // `_guard` on every return path — no manual `pending.remove` here.
        match timeout(self.state.claim_timeout, rx).await {
            Ok(Ok(result)) => match result {
                ClaimResult::Ok(r) => Ok(r),
                ClaimResult::Err(e) => Err(e),
            },
            _ => Err(InviteError::AuthorityUnavailable),
        }
    }
}

/// Run the authority worker: consume claim work items, adjudicate each via
/// `apply_claim` → `nip29::add_member_from_invite`, and reply on the
/// pending oneshot. Breaks on cancellation.
pub(crate) async fn run_authority_worker(
    state: Arc<AppState>,
    auth_state: AuthorityState,
    mut work_rx: mpsc::Receiver<ClaimWork>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            Some(work) = work_rx.recv() => {
                process_claim(&state, &auth_state, work).await;
            }
            else => break,
        }
    }
}
/// Spawn the authority worker that adjudicates invite claims. Takes the
/// [`AuthorityState`] stored in `AppState` (set at startup) and drains its
/// work-channel receiver, replying to each claim via the in-process bus.
///
/// This is the single production entry point that connects the claim HTTP
/// route to the durable `nip29::add_member_from_invite` mutation: it is what
/// makes the claimant's await-on-the-authority-reply (never the transport
/// receipt) resolve. Returns `None` — and spawns nothing — when no authority
/// is configured; a claim then times out → 502 (honest: the authority is not
/// running). Safe to call at most once per `AppState` (the receiver is
/// single-take).
pub fn spawn_authority_worker(
    state: Arc<AppState>,
    cancel: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let auth_state = state.authority.clone()?;
    let work_rx = auth_state.take_work_receiver()?;
    Some(tokio::spawn(run_authority_worker(
        state, auth_state, work_rx, cancel,
    )))
}

/// Adjudicate one claim: verify sender binding, run `apply_claim`, reply.
async fn process_claim(state: &Arc<AppState>, auth_state: &AuthorityState, work: ClaimWork) {
    // Security: require verified sender binding (contract).
    if !work.verified {
        complete(
            auth_state,
            &work.request_id,
            ClaimResult::Err(InviteError::AuthorityUnavailable),
        );
        return;
    }

    let now = relay_identity::now_secs();
    let authority = RelayInviteAuthority(Arc::clone(&state.identity));
    let membership = EngineInviteMembership::new(Arc::clone(&state.engine), &state.settings);
    let primary_ch = primary_channel(&state.settings);
    let options = InviteOptions::new(&state.settings.public_base_url, &primary_ch);
    let writer = Nip29MembershipWriter(Arc::clone(state));

    let svc =
        invites::InviteAuthorityService::new(&authority, &membership, &state.join_policy, options);

    let result: ClaimResult = svc.apply_claim(&work.req, &writer, now).await.into();
    match work.remote_reply_to {
        Some(reply_to) => {
            // Remote claim (received via the direct dispatcher): serialize
            // the result and send it back over the direct transport. The
            // receipt is discarded — completion is the verified result DM.
            send_result_envelope(state, &work.request_id, &reply_to, result).await;
        }
        None => {
            complete(auth_state, &work.request_id, result);
        }
    }
}

/// Serialize the authority decision as a result envelope and send it back to
/// the remote claimant over the direct transport. The receipt is discarded —
/// this is transport acceptance, never completion (the claimant's pending
/// entry is resolved when the dispatcher receives the verified result DM).
async fn send_result_envelope(
    state: &Arc<AppState>,
    request_id: &str,
    reply_to: &AgentId,
    result: ClaimResult,
) {
    let Some(direct) = state.direct.as_ref() else {
        return;
    };
    let envelope = DirectEnvelope::Result {
        version: DIRECT_ENVELOPE_VERSION,
        request_id: request_id.to_string(),
        result: DirectResult::from_claim_result(result),
    };
    let payload = match serde_json::to_vec(&envelope) {
        Ok(p) => p,
        Err(_) => return,
    };
    // Discard the receipt: transport acceptance, never completion.
    let _ = direct.send(reply_to, &payload, true).await;
}

/// Deliver the adjudication result to the waiting claimant (if still pending).
fn complete(state: &AuthorityState, request_id: &str, result: ClaimResult) {
    if let Some((_, pending)) = state.pending.remove(request_id) {
        let _ = pending.reply.send(result);
    }
}

// ===========================================================================
// Direct authority bus (remote claim forwarding over x0xd DMs)
// ===========================================================================

/// One pending remote claim awaiting a result DM from the authority.
struct PendingRemoteClaim {
    /// Oneshot completed by the dispatcher when the verified result arrives.
    reply: oneshot::Sender<ClaimResult>,
    /// Expected authority AgentId — the verified DM sender must equal this.
    expected_aid: AgentId,
    /// Expected community relay pubkey — an Ok result's community_id must equal
    /// this (the signed code binds aid+cid).
    expected_cid: String,
}

/// Shared state between [`DirectAuthorityBus`] (claimant side) and the direct
/// dispatcher (authority inbox). Both hold a clone so a result DM arriving at
/// the dispatcher can complete the pending oneshot the bus inserted.
#[derive(Clone)]
pub struct DirectBusState {
    pending: Arc<DashMap<String, PendingRemoteClaim>>,
    claim_timeout: Duration,
    /// Bounded pending-slot semaphore (MAX_PENDING_CLAIMS); released by the
    /// [`PendingEntryGuard`] on drop. Same DoS guard as [`AuthorityState`].
    semaphore: Arc<Semaphore>,
}

impl DirectBusState {
    /// Create with the default claim round-trip timeout.
    pub fn new() -> Self {
        Self::with_timeout(DEFAULT_CLAIM_TIMEOUT)
    }

    /// Create with an explicit claim timeout (tests).
    pub fn with_timeout(claim_timeout: Duration) -> Self {
        Self {
            pending: Arc::new(DashMap::with_capacity(MAX_PENDING_CLAIMS)),
            claim_timeout,
            semaphore: Arc::new(Semaphore::new(MAX_PENDING_CLAIMS)),
        }
    }
}

impl Default for DirectBusState {
    fn default() -> Self {
        Self::new()
    }
}

/// The remote authority bus: forwards a claim to a remote authority over
/// verified x0xd direct messages and awaits the typed result. The transport
/// receipt is **never** treated as completion — the claimant waits for the
/// authority's verified result DM (or times out).
pub struct DirectAuthorityBus {
    transport: Arc<X0xDirectTransport>,
    self_id: AgentId,
    state: DirectBusState,
}

impl DirectAuthorityBus {
    pub fn new(
        transport: Arc<X0xDirectTransport>,
        self_id: AgentId,
        state: DirectBusState,
    ) -> Self {
        Self {
            transport,
            self_id,
            state,
        }
    }
}

#[async_trait]
impl AuthorityBus for DirectAuthorityBus {
    async fn request_claim(
        &self,
        authority_agent_id: &str,
        req: ClaimBusRequest,
    ) -> Result<ClaimResponse, InviteError> {
        // Parse the code to capture the community relay pubkey (cid) for the
        // pending entry — the dispatcher checks it against the result.
        let view = invites::parse_invite_code(&req.code)?;
        let cid = view.community_id.clone();
        let target =
            AgentId::from_hex(authority_agent_id).map_err(|_| InviteError::AuthorityUnavailable)?;

        let request_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();

        // Bounded pending slots: acquire atomically (no len()+insert race).
        let permit = Arc::clone(&self.state.semaphore)
            .try_acquire_owned()
            .map_err(|_| InviteError::AuthorityUnavailable)?;
        self.state.pending.insert(
            request_id.clone(),
            PendingRemoteClaim {
                reply: tx,
                expected_aid: target.clone(),
                expected_cid: cid,
            },
        );
        // RAII: a dropped future (client disconnect) removes the entry and
        // releases the slot — no leak. The dispatcher's result handler also
        // removes (to complete the oneshot); idempotent against this guard.
        let _guard =
            PendingEntryGuard::new(Arc::clone(&self.state.pending), request_id.clone(), permit);

        // Build + send the claim envelope. reply_to = our self AgentId so the
        // authority knows where to send the result. require_gossip = true.
        let envelope = DirectEnvelope::Claim {
            version: DIRECT_ENVELOPE_VERSION,
            request_id: request_id.clone(),
            reply_to: self.self_id.as_str().to_string(),
            claim: req,
        };
        let payload =
            serde_json::to_vec(&envelope).map_err(|_| InviteError::AuthorityUnavailable)?;
        // Discard the receipt — transport acceptance is never completion.
        if self.transport.send(&target, &payload, true).await.is_err() {
            return Err(InviteError::AuthorityUnavailable); // _guard cleans up
        }

        // Await the authority's verified result (or timeout). Cleanup is owned
        // by `_guard` on every return path — no manual `pending.remove` here.
        match timeout(self.state.claim_timeout, rx).await {
            Ok(Ok(result)) => match result {
                ClaimResult::Ok(r) => Ok(r),
                ClaimResult::Err(e) => Err(e),
            },
            _ => Err(InviteError::AuthorityUnavailable),
        }
    }
}

// ===========================================================================
// Direct-message dispatcher (authority inbox)
// ===========================================================================

/// Spawn the direct-message dispatcher that consumes verified DMs from the
/// transport inbox. Incoming claims are validated and enqueued for authority
/// adjudication; incoming results complete pending remote claims. Returns
/// `None` when no direct transport / self identity is configured.
pub fn spawn_direct_dispatcher(
    state: Arc<AppState>,
    cancel: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let direct = state.direct.clone()?;
    let self_id = state.self_agent_id.clone()?;
    let bus_state = state.direct_bus.clone()?;
    let auth_state = state.authority.clone()?;
    Some(tokio::spawn(run_direct_dispatcher(
        state, direct, self_id, bus_state, auth_state, cancel,
    )))
}

/// Run the direct-message dispatcher loop: consume verified [`DirectMessage`]
/// frames, route claim/result envelopes, and either enqueue authority work
/// (incoming remote claim) or complete a pending remote claim (incoming
/// result). Breaks on cancellation or inbox close.
async fn run_direct_dispatcher(
    state: Arc<AppState>,
    transport: Arc<X0xDirectTransport>,
    self_id: AgentId,
    bus_state: DirectBusState,
    auth_state: AuthorityState,
    cancel: CancellationToken,
) {
    let mut messages = transport.messages();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            Some(msg) = messages.recv() => {
                handle_direct_message(&state, &self_id, &bus_state, &auth_state, msg).await;
            }
            else => break,
        }
    }
}

/// Process one direct message: require verified, parse the envelope, and
/// dispatch to the claim or result handler. All failure paths silently drop
/// the frame (the feed is at-least-once; a malformed/spoofed frame is never
/// acted on).
async fn handle_direct_message(
    state: &Arc<AppState>,
    self_id: &AgentId,
    bus_state: &DirectBusState,
    auth_state: &AuthorityState,
    msg: DirectMessage,
) {
    // Security: require daemon-verified sender binding (contract).
    if !msg.verified {
        return;
    }
    let sender = match AgentId::from_hex(&msg.sender) {
        Ok(a) => a,
        Err(_) => return,
    };
    let envelope: DirectEnvelope = match serde_json::from_slice(&msg.payload) {
        Ok(e) => e,
        Err(_) => return,
    };
    match envelope {
        DirectEnvelope::Claim {
            version,
            request_id,
            reply_to,
            claim,
        } => {
            if version != DIRECT_ENVELOPE_VERSION {
                return;
            }
            handle_incoming_claim(
                state, self_id, auth_state, sender, &reply_to, request_id, claim,
            )
            .await;
        }
        DirectEnvelope::Result {
            version,
            request_id,
            result,
        } => {
            if version != DIRECT_ENVELOPE_VERSION {
                return;
            }
            handle_incoming_result(bus_state, &sender, &request_id, result);
        }
    }
}

/// Validate an incoming remote claim and enqueue it for authority
/// adjudication. Every check is fail-closed (silent drop); only a fully-valid
/// portable proof + binding-matched code reaches the authority worker.
async fn handle_incoming_claim(
    state: &Arc<AppState>,
    self_id: &AgentId,
    auth_state: &AuthorityState,
    sender: AgentId,
    reply_to: &str,
    request_id: String,
    claim: ClaimBusRequest,
) {
    // Anti-spoofing: reply_to must equal the DM sender (the claimant cannot
    // redirect the authority's reply to a third party).
    let reply_to_id = match AgentId::from_hex(reply_to) {
        Ok(a) => a,
        Err(_) => return,
    };
    if reply_to_id != sender {
        return;
    }
    // The code's authority AgentId must be us (this claim is for our community).
    let view = match invites::parse_invite_code(&claim.code) {
        Ok(v) => v,
        Err(_) => return,
    };
    let code_aid = match AgentId::from_hex(&view.authority_agent_id) {
        Ok(a) => a,
        Err(_) => return,
    };
    if &code_aid != self_id {
        return;
    }
    // Validate the portable NIP-98 proof: re-verify the joiner's signature
    // over the exact request body. Returns the decoded body on success.
    let now = relay_identity::now_secs();
    let Some(proof) = &claim.auth_proof else {
        return;
    };
    let body = match auth::verify_portable_nip98_claim(
        proof,
        &claim.joiner_pubkey,
        state.replay.as_ref(),
        now,
        state.settings.nip98_ttl_secs,
    ) {
        Some(b) => b,
        None => return,
    };
    // The parsed exact ClaimRequest must match the forwarded code / receipt.
    let parsed: ClaimRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return,
    };
    if parsed.code != claim.code || parsed.policy_receipt != claim.policy_receipt {
        return;
    }
    // Enqueue remote work with the sender as the reply target.
    let work = ClaimWork {
        request_id,
        req: claim,
        verified: true,
        remote_reply_to: Some(sender),
    };
    let _ = auth_state.work_tx.send(work).await;
}

/// Complete a pending remote claim when a verified result DM arrives.
/// Requires: pending entry exists, verified sender == expected authority
/// AgentId, and (for Ok results) community_id == expected cid. Only then
/// complete the oneshot.
fn handle_incoming_result(
    bus_state: &DirectBusState,
    sender: &AgentId,
    request_id: &str,
    result: DirectResult,
) {
    // Validate under a read guard, then remove + complete (exactly-once).
    let valid = {
        let Some(entry) = bus_state.pending.get(request_id) else {
            return;
        };
        if &entry.expected_aid != sender {
            return;
        }
        // For an Ok result, the community_id must equal the expected cid.
        if result.ok {
            result
                .response
                .as_ref()
                .map(|r| r.community_id == entry.expected_cid)
                .unwrap_or(false)
        } else {
            // Err results carry no community_id; sender binding suffices.
            true
        }
    };
    if !valid {
        return;
    }
    if let Some((_, pending)) = bus_state.pending.remove(request_id) {
        if let Some(cr) = result.into_claim_result() {
            let _ = pending.reply.send(cr);
        }
    }
}

// ===========================================================================
// State builders (called from relay::router)
// ===========================================================================

/// Build the `MediaUploadState` Extension for the upload routes.
pub fn build_upload_state(state: &Arc<AppState>, store: Arc<MediaStore>) -> Arc<MediaUploadState> {
    let config = Arc::new(MediaUploadConfig {
        media_public_base_url: if state.settings.media_public_base_url.is_empty() {
            state.settings.public_base_url.clone()
        } else {
            state.settings.media_public_base_url.clone()
        },
        relay_authority: relay_authority(&state.settings.public_base_url),
        max_image_bytes: state.settings.media_max_image_bytes,
        max_gif_bytes: state.settings.media_max_gif_bytes,
        max_video_bytes: state.settings.media_max_video_bytes,
        max_file_bytes: state.settings.media_max_file_bytes,
        upload_auth_max_age_secs: state.settings.media_upload_auth_max_age_secs,
        video_auth_max_age_secs: state.settings.media_video_auth_max_age_secs,
        require_membership: state.settings.require_membership,
    });
    let replay: Arc<dyn MediaReplay> = Arc::new(SharedReplayGuard(Arc::clone(&state.replay)));
    let membership: Arc<dyn MediaMembership> =
        Arc::new(EngineMediaMembership(Arc::clone(&state.engine)));
    Arc::new(MediaUploadState::new(store, config, replay, membership))
}

/// Build the `MediaServe` service Extension for GET/HEAD routes.
pub fn build_media_serve(state: &Arc<AppState>, store: Arc<MediaStore>) -> Arc<MediaServe> {
    let config = crate::media::serve::ServeConfig {
        require_get_auth: state.settings.require_media_get_auth,
        require_membership: state.settings.require_membership,
        get_auth_max_age_secs: state.settings.media_get_auth_max_age_secs,
        relay_authority: relay_authority(&state.settings.public_base_url),
        cache_max_age_secs: crate::media::serve::ServeConfig::default().cache_max_age_secs,
    };
    Arc::new(MediaServe::new(store, config))
}

// ===========================================================================
// Route handlers — media
// ===========================================================================

/// Catch-all path param for `/media/*path`.
#[derive(Deserialize)]
pub struct MediaPathTail {
    path: String,
}

/// `GET /media/{*path}` — streamed, range-aware, cacheable media serve.
pub async fn get_media(
    Extension(serve): Extension<Arc<MediaServe>>,
    Extension(replay): Extension<Arc<SharedReplayGuard>>,
    Extension(members): Extension<Arc<EngineMemberCheck>>,
    Path(tail): Path<MediaPathTail>,
    Query(q): Query<crate::media::serve::MediaQuery>,
    headers: HeaderMap,
) -> Response {
    let now = relay_identity::now_secs();
    serve
        .serve(
            Method::GET,
            &tail.path,
            q.download.unwrap_or(false),
            &headers,
            now,
            replay.as_ref(),
            members.as_ref(),
        )
        .await
}

/// `HEAD /media/{*path}` — same headers as GET, empty body.
pub async fn head_media(
    Extension(serve): Extension<Arc<MediaServe>>,
    Extension(replay): Extension<Arc<SharedReplayGuard>>,
    Extension(members): Extension<Arc<EngineMemberCheck>>,
    Path(tail): Path<MediaPathTail>,
    Query(q): Query<crate::media::serve::MediaQuery>,
    headers: HeaderMap,
) -> Response {
    let now = relay_identity::now_secs();
    serve
        .serve(
            Method::HEAD,
            &tail.path,
            q.download.unwrap_or(false),
            &headers,
            now,
            replay.as_ref(),
            members.as_ref(),
        )
        .await
}

// ===========================================================================
// Route handlers — join policy
// ===========================================================================

/// `GET /api/join-policy` — client envelope (404 when disabled).
pub async fn get_join_policy(State(state): State<Arc<AppState>>) -> Response {
    if !state.join_policy.enabled() {
        return http::api_error(404, "join policy is disabled");
    }
    Json(state.join_policy.envelope()).into_response()
}

/// `GET /api/join-policy/terms` — terms markdown (404 when absent).
pub async fn get_policy_terms(State(state): State<Arc<AppState>>) -> Response {
    serve_policy_doc(&state, PolicyDoc::Terms)
}

/// `GET /api/join-policy/privacy` — privacy markdown (404 when absent).
pub async fn get_policy_privacy(State(state): State<Arc<AppState>>) -> Response {
    serve_policy_doc(&state, PolicyDoc::Privacy)
}

fn serve_policy_doc(state: &Arc<AppState>, doc: PolicyDoc) -> Response {
    match state.join_policy.doc_markdown(doc) {
        Some(md) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("text/markdown"),
            )],
            md.to_string(),
        )
            .into_response(),
        None => http::api_error(404, "not found"),
    }
}

// ===========================================================================
// Route handlers — invites
// ===========================================================================

/// `POST /api/invites` — mint a stateless, multi-use invite code (admin only).
pub async fn post_invites(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = relay_identity::now_secs();
    let principal = match auth::authenticate(
        &state.settings,
        state.replay.as_ref(),
        &headers,
        "POST",
        "/api/invites",
        &body,
        true,
        now,
    ) {
        Ok(p) => p,
        Err(e) => return http::api_error(e.status(), e.message()),
    };

    let req: MintRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return InviteError::MalformedRequest.into_response(),
    };

    let authority = RelayInviteAuthority(Arc::clone(&state.identity));
    let membership = EngineInviteMembership::new(Arc::clone(&state.engine), &state.settings);
    let primary_ch = primary_channel(&state.settings);
    let options = InviteOptions::new(&state.settings.public_base_url, &primary_ch);
    let svc =
        invites::InviteAuthorityService::new(&authority, &membership, &state.join_policy, options);

    // The authority agent_id bound into the code is this daemon's AgentId
    // (from GET /agent) — that is what a claimant DMs to route the claim.
    // Tests with no direct transport fall back to the relay pubkey.
    let agent_id = match &state.self_agent_id {
        Some(id) => id.as_str().to_string(),
        None => state.identity.public_key_hex(),
    };
    let nonce = uuid::Uuid::new_v4().simple().to_string();

    match svc
        .mint(&principal.pubkey_hex, &agent_id, &nonce, req, now)
        .await
    {
        Ok(resp) => resp.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /api/invites/accept-policy` — mint a policy receipt (unauthed; the
/// MAC requires the authority secret).
pub async fn post_accept_policy(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let authority = RelayInviteAuthority(Arc::clone(&state.identity));
    let membership = EngineInviteMembership::new(Arc::clone(&state.engine), &state.settings);
    let primary_ch = primary_channel(&state.settings);
    let options = InviteOptions::new(&state.settings.public_base_url, &primary_ch);
    let svc =
        invites::InviteAuthorityService::new(&authority, &membership, &state.join_policy, options);

    let req: AcceptPolicyRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return InviteError::MalformedRequest.into_response(),
    };

    match svc.accept_policy(req) {
        Ok(resp) => resp.into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /api/invites/claim` — forward a claim to the authority worker and
/// await its adjudication. The joining key is NIP-98-authenticated; the
/// DirectSendReceipt is **never** treated as success (the claimant waits for
/// the authority's typed reply).
pub async fn post_claim(
    State(state): State<Arc<AppState>>,
    Extension(bus): Extension<Arc<LocalAuthorityBus>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = relay_identity::now_secs();
    let principal = match auth::authenticate(
        &state.settings,
        state.replay.as_ref(),
        &headers,
        "POST",
        "/api/invites/claim",
        &body,
        true,
        now,
    ) {
        Ok(p) => p,
        Err(e) => return http::api_error(e.status(), e.message()),
    };

    let req: ClaimRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return InviteError::MalformedRequest.into_response(),
    };

    // Route: parse the code to determine the bound authority. Local fast path
    // when the code's `aid` == our self AgentId; no direct transport ⇒
    // in-process (test fallback). Otherwise forward over the direct bus.
    let view = match invites::parse_invite_code(&req.code) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let auth_proof = principal.portable_nip98.clone();

    let is_local = match &state.self_agent_id {
        Some(self_id) => AgentId::from_hex(&view.authority_agent_id)
            .map(|code_aid| &code_aid == self_id)
            .unwrap_or(false),
        None => true, // no direct transport → in-process (tests)
    };

    let result = if is_local {
        invites::claimant_claim(bus.as_ref(), &principal.pubkey_hex, req, auth_proof, now).await
    } else {
        let Some(direct) = state.direct.as_ref() else {
            return InviteError::AuthorityUnavailable.into_response();
        };
        let Some(self_id) = state.self_agent_id.as_ref() else {
            return InviteError::AuthorityUnavailable.into_response();
        };
        let Some(bus_state) = state.direct_bus.as_ref() else {
            return InviteError::AuthorityUnavailable.into_response();
        };
        let remote_bus =
            DirectAuthorityBus::new(Arc::clone(direct), self_id.clone(), bus_state.clone());
        invites::claimant_claim(&remote_bus, &principal.pubkey_hex, req, auth_proof, now).await
    };

    match result {
        Ok(resp) => resp.into_response(),
        Err(e) => e.into_response(),
    }
}
// ===========================================================================
// Claim-RPC dispatcher unit tests (private-state, in-file)
// ===========================================================================
// Every envelope-validation check is fail-closed (silent return → no side
// effect). These tests drive the private handlers directly with private state
// and assert on the side effect (pending removed / work enqueued) — proving
// forged sender, ok-cid-mismatch, reply_to≠sender, and code-aid≠self are all
// rejected, while the happy paths complete. No production visibility changes.
#[cfg(test)]
mod claim_rpc_tests {
    use super::*;
    use crate::invites::InviteAuthorityService;
    use crate::join_policy::JoinPolicyConfig;
    use crate::store::{EventStore, InsertOutcome};
    use crate::transport::{GossipMessage, GossipTransport};
    use nostr::{Event, Filter};
    use tokio::sync::oneshot;

    // ---- minimal no-op collaborators (rejection paths never query them) ----
    struct NoopStore;
    #[async_trait]
    impl EventStore for NoopStore {
        async fn insert(&self, _ev: &Event) -> anyhow::Result<InsertOutcome> {
            Ok(InsertOutcome::Inserted)
        }
        async fn query(&self, _f: &Filter) -> anyhow::Result<Vec<Event>> {
            Ok(Vec::new())
        }
        async fn known_channels(&self) -> anyhow::Result<Vec<String>> {
            Ok(Vec::new())
        }
    }
    struct NoopTransport;
    #[async_trait]
    impl GossipTransport for NoopTransport {
        async fn ensure_topic(&self, _t: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn publish(&self, _t: &str, _p: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        fn inbox(&self) -> mpsc::Receiver<GossipMessage> {
            mpsc::channel(1).1
        }
    }

    fn make_state() -> Arc<AppState> {
        Arc::new(AppState::for_test(
            Arc::new(NoopStore) as Arc<dyn EventStore>,
            Arc::new(NoopTransport) as Arc<dyn GossipTransport>,
            Settings::default(),
        ))
    }

    fn aid(hex: char) -> AgentId {
        AgentId::from_hex(&hex.to_string().repeat(64)).unwrap()
    }
    fn cid(c: char) -> String {
        c.to_string().repeat(64)
    }

    /// Insert a pending remote claim and return its oneshot receiver.
    fn stage_pending(
        bus: &DirectBusState,
        request_id: &str,
        expected_aid: AgentId,
        expected_cid: &str,
    ) -> oneshot::Receiver<ClaimResult> {
        let (tx, rx) = oneshot::channel();
        bus.pending.insert(
            request_id.to_string(),
            PendingRemoteClaim {
                reply: tx,
                expected_aid,
                expected_cid: expected_cid.to_string(),
            },
        );
        rx
    }

    // ---- handle_incoming_result: forged sender / cid mismatch / happy ----

    #[test]
    fn result_from_forged_sender_is_silently_dropped() {
        let bus = DirectBusState::new();
        let real = aid('a');
        let _rx = stage_pending(&bus, "r1", real.clone(), &cid('c'));
        let forged = aid('b');
        let result = DirectResult {
            ok: true,
            response: Some(ClaimResponse::joined(cid('c'), "h")),
            error: None,
        };
        handle_incoming_result(&bus, &forged, "r1", result);
        // No side effect: the pending entry is NOT removed (claim stays unresolved).
        assert!(
            bus.pending.contains_key("r1"),
            "forged sender must not resolve the claim"
        );
    }

    #[test]
    fn result_ok_with_mismatched_cid_is_silently_dropped() {
        let bus = DirectBusState::new();
        let real = aid('a');
        let expected = cid('c');
        let _rx = stage_pending(&bus, "r2", real.clone(), &expected);
        // Sender matches, but the Ok result's community_id != expected cid.
        let result = DirectResult {
            ok: true,
            response: Some(ClaimResponse::joined(cid('z'), "h")),
            error: None,
        };
        handle_incoming_result(&bus, &real, "r2", result);
        assert!(
            bus.pending.contains_key("r2"),
            "cid mismatch must not resolve the claim"
        );
    }

    #[test]
    fn result_ok_with_matching_cid_resolves_the_claim() {
        let bus = DirectBusState::new();
        let real = aid('a');
        let expected = cid('c');
        let mut rx = stage_pending(&bus, "r3", real.clone(), &expected);
        let result = DirectResult {
            ok: true,
            response: Some(ClaimResponse::joined(expected, "h")),
            error: None,
        };
        handle_incoming_result(&bus, &real, "r3", result);
        assert!(
            !bus.pending.contains_key("r3"),
            "matching sender+cid resolves + removes"
        );
        assert!(matches!(rx.try_recv(), Ok(ClaimResult::Ok(r)) if r.status == "joined"));
    }

    #[test]
    fn result_err_resolves_regardless_of_community_id() {
        let bus = DirectBusState::new();
        let real = aid('a');
        let mut rx = stage_pending(&bus, "r4", real.clone(), "irrelevant");
        let result = DirectResult {
            ok: false,
            response: None,
            error: Some(InviteError::InvalidCode),
        };
        handle_incoming_result(&bus, &real, "r4", result);
        assert!(
            !bus.pending.contains_key("r4"),
            "Err result resolves via sender binding alone"
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(ClaimResult::Err(InviteError::InvalidCode))
        ));
    }

    #[test]
    fn result_for_unknown_request_id_is_a_noop() {
        let bus = DirectBusState::new();
        let real = aid('a');
        let result = DirectResult {
            ok: true,
            response: Some(ClaimResponse::joined(cid('c'), "h")),
            error: None,
        };
        handle_incoming_result(&bus, &real, "never-existed", result);
        // No panic; nothing inserted.
        assert!(bus.pending.is_empty());
    }

    // ---- handle_incoming_claim: reply_to≠sender / code-aid≠self ----

    /// Mint a real relay-signed code whose authority_agent_id == `authority_aid`.
    async fn mint_code(authority_aid: &str) -> String {
        let identity = Arc::new(RelayIdentity::ephemeral());
        let auth = RelayInviteAuthority(Arc::clone(&identity));
        struct AllAdmin;
        impl InviteMembership for AllAdmin {
            fn is_community_admin(&self, _pk: &str) -> bool {
                true
            }
            fn is_community_member(&self, _pk: &str) -> bool {
                false
            }
        }
        let policy = JoinPolicyConfig::disabled();
        let svc = InviteAuthorityService::new(
            &auth,
            &AllAdmin,
            &policy,
            InviteOptions::new("http://127.0.0.1:3000", "general"),
        );
        svc.mint(
            &identity.public_key_hex(),
            authority_aid,
            "n",
            MintRequest { ttl_secs: None },
            1_700_000_000,
        )
        .await
        .expect("mint")
        .code
    }

    #[tokio::test]
    async fn claim_with_reply_to_not_equal_sender_is_dropped() {
        let state = make_state();
        let self_id = aid('a');
        let auth_state = AuthorityState::new();
        let mut work_rx = auth_state.work_rx.lock().take().expect("work rx");
        let sender = aid('b');
        let reply_to = cid('c'); // != sender → anti-spoofing drop
        let claim = ClaimBusRequest {
            code: "ignored-until-after-reply-check".into(),
            policy_receipt: None,
            joiner_pubkey: cid('d'),
            auth_proof: None,
        };
        handle_incoming_claim(
            &state,
            &self_id,
            &auth_state,
            sender,
            &reply_to,
            "req".into(),
            claim,
        )
        .await;
        assert!(
            work_rx.try_recv().is_err(),
            "reply_to≠sender ⇒ no authority work enqueued"
        );
    }

    #[tokio::test]
    async fn claim_whose_code_aid_is_not_self_is_dropped() {
        let state = make_state();
        let self_id = aid('a');
        let auth_state = AuthorityState::new();
        let mut work_rx = auth_state.work_rx.lock().take().expect("work rx");
        // A valid code whose authority_agent_id is a DIFFERENT agent than self.
        let foreign_aid = cid('e');
        let code = mint_code(&foreign_aid).await;
        let claim = ClaimBusRequest {
            code,
            policy_receipt: None,
            joiner_pubkey: cid('d'),
            auth_proof: None,
        };
        // reply_to == sender (passes anti-spoof), but code.aid != self_id.
        handle_incoming_claim(
            &state,
            &self_id,
            &auth_state,
            self_id.clone(),
            self_id.as_str(),
            "req".into(),
            claim,
        )
        .await;
        assert!(
            work_rx.try_recv().is_err(),
            "code-aid≠self ⇒ no authority work enqueued"
        );
    }
    // ---- RAII PendingEntryGuard: cancellation-drop + capacity ----

    use axum::body::Body;
    use axum::{routing::get, routing::post, Router};
    use serde_json::{json, Value};

    /// A mock loopback daemon that signals readiness on each `/direct/send` —
    /// the test thereby knows the claim's pending entry was inserted (insert
    /// precedes send) before it aborts the in-flight future. Serves an empty SSE
    /// stream so the transport supervisor stays alive. No arbitrary sleeps.
    async fn signaling_daemon() -> (String, mpsc::Receiver<()>) {
        let (tx, rx) = mpsc::channel::<()>(512);
        let send = post(move |_h: HeaderMap, _b: Json<Value>| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(()).await;
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
        (format!("http://{addr}"), rx)
    }

    fn claim_body(code: String) -> ClaimBusRequest {
        ClaimBusRequest {
            code,
            policy_receipt: None,
            joiner_pubkey: cid('b'),
            auth_proof: None,
        }
    }

    #[tokio::test]
    async fn aborting_request_claim_reclaims_slot_and_permit() {
        let cancel = CancellationToken::new();
        let (base, mut sig) = signaling_daemon().await;
        let transport = X0xDirectTransport::connect(&base, "t", cancel.clone(), None)
            .await
            .unwrap();
        let bus_state = DirectBusState::with_timeout(Duration::from_secs(30));
        let bus = DirectAuthorityBus::new(Arc::new(transport), aid('1'), bus_state.clone());
        let code = mint_code(&cid('a')).await;
        let target = cid('a');

        let task = tokio::spawn(async move { bus.request_claim(&target, claim_body(code)).await });
        // Readiness: the daemon received /direct/send ⇒ entry inserted + permit
        // acquired (insert precedes send by construction).
        tokio::time::timeout(Duration::from_secs(2), sig.recv())
            .await
            .expect("send within 2s")
            .expect("signal present");
        assert_eq!(bus_state.pending.len(), 1, "exactly one pending entry live");
        assert_eq!(
            bus_state.semaphore.available_permits(),
            MAX_PENDING_CLAIMS - 1
        );

        // Abort the in-flight future ⇒ the guard's Drop reclaims entry + permit.
        task.abort();
        let _ = task.await;
        assert_eq!(
            bus_state.pending.len(),
            0,
            "guard reclaimed the map entry on abort"
        );
        assert_eq!(
            bus_state.semaphore.available_permits(),
            MAX_PENDING_CLAIMS,
            "guard released the permit on abort"
        );

        cancel.cancel();
    }

    #[tokio::test]
    async fn capacity_256_rejects_the_next_claim_with_no_permits() {
        let cancel = CancellationToken::new();
        let (base, _sig) = signaling_daemon().await;
        let transport = X0xDirectTransport::connect(&base, "t", cancel.clone(), None)
            .await
            .unwrap();
        let bus_state = DirectBusState::with_timeout(Duration::from_secs(30));
        let bus = DirectAuthorityBus::new(Arc::new(transport), aid('1'), bus_state.clone());
        let code = mint_code(&cid('a')).await;
        let target = cid('a');

        // Hold all 256 permits externally (simulate 256 in-flight claims).
        let mut held = Vec::new();
        for _ in 0..MAX_PENDING_CLAIMS {
            held.push(bus_state.semaphore.clone().acquire_owned().await.unwrap());
        }
        assert_eq!(bus_state.semaphore.available_permits(), 0);

        let r = bus.request_claim(&target, claim_body(code)).await;
        assert!(
            matches!(r, Err(InviteError::AuthorityUnavailable)),
            "257th ⇒ unavailable"
        );
        assert_eq!(
            bus_state.semaphore.available_permits(),
            0,
            "no permit leaked on rejection"
        );

        drop(held);
        assert_eq!(
            bus_state.semaphore.available_permits(),
            MAX_PENDING_CLAIMS,
            "permits restored"
        );
        cancel.cancel();
    }

    #[tokio::test]
    async fn repeated_cancellation_cannot_exhaust_capacity() {
        let cancel = CancellationToken::new();
        let (base, mut sig) = signaling_daemon().await;
        let transport = Arc::new(
            X0xDirectTransport::connect(&base, "t", cancel.clone(), None)
                .await
                .unwrap(),
        );
        let bus_state = DirectBusState::with_timeout(Duration::from_secs(30));
        let self_id = aid('1');
        let code = mint_code(&cid('a')).await; // multi-use code, minted once
        let target = cid('a');

        // >256 abort cycles. Each acquires a permit + inserts, then reclaims on
        // abort. If the guard leaked, the 257th could not acquire ⇒ no send ⇒
        // the readiness recv would stall (and the final permits would be < MAX).
        let n = MAX_PENDING_CLAIMS + 10;
        for _ in 0..n {
            let bus =
                DirectAuthorityBus::new(Arc::clone(&transport), self_id.clone(), bus_state.clone());
            let target = target.clone();
            let code = code.clone();
            let task =
                tokio::spawn(async move { bus.request_claim(&target, claim_body(code)).await });
            tokio::time::timeout(Duration::from_secs(2), sig.recv())
                .await
                .expect("send within 2s (no capacity stall)")
                .expect("signal");
            task.abort();
            let _ = task.await;
        }
        assert_eq!(
            bus_state.pending.len(),
            0,
            "no leaked entries after {n} aborts"
        );
        assert_eq!(
            bus_state.semaphore.available_permits(),
            MAX_PENDING_CLAIMS,
            "capacity fully restored after {n} cancellation cycles"
        );
        cancel.cancel();
    }
}

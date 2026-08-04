// SPDX-License-Identifier: MIT OR Apache-2.0
//! Blossom media subsystem (bridge M1b): content-addressed blob store, Blossom
//! kind-24242 auth, and the upload/serve HTTP leaves.
//!
//! Owner: WP-MS. This is pure glue — each leaf owns its own behavior (see the
//! per-file doc comments). `lib.rs` gains `pub mod media;` during wiring (WP-W);
//! until then this tree is not compiled by the crate.
//!
pub mod auth;
pub mod serve;
pub mod store;
pub mod upload;

pub use serve::{
    MediaQuery, MediaServe, MemberCheck, NoopMemberCheck, NoopReplayGuard, ReplayGuard,
    ReplayRejection, ServeConfig,
};
pub use store::{BlobDisposition, InstallOutcome, MediaRecord, MediaStore, NewMediaRecord};

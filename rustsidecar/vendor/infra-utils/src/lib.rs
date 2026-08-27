//! `utils` — axisless, closed generic helpers and bounded owner-neutral primitives.
//!
//! Only helpers that remain meaningful when copied into an unrelated Rust
//! repository belong here. Retained state must be bounded, owner-neutral, and
//! justified by a reusable invariant (for example an atomic admission gate). Import through a descriptive category path; the
//! crate root deliberately exposes modules only and never re-exports external
//! dependencies or owner-specific capability contracts.
//!
//! Kept categories:
//! - [`crypto`] — hashing, checksums, encodings, validation primitives.
//! - [`id`] — small validated identifier/value types.
//! - [`net`] — passive URL/TLS/origin/SSRF/request-target values and checks.
//! - [`sync`] — pure-atomic admission/drain primitives.
//! - [`text`] — deterministic string, formatting, and template helpers.
//! - [`time`] — passive time values plus strict timezone conversion helpers.
//! - [`value_error`] — validation errors shared by the small utility values.
//!
//! Deliberately absent are runtime supervision, stdin/stdout relays, caches,
//! environment/config ingress, SQL dialect policy, and stream-combinator
//! re-exports. Those require an operational or domain owner instead of a
//! catch-all utility route.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod crypto;
pub mod id;
pub mod net;
pub mod sync;
pub mod text;
pub mod time;
pub mod value_error;

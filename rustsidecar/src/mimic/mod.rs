//! Account Mimic and Realistic Workstation Simulation Engine.
//!
//! Enforces official OpenAI Codex CLI identity convergence, UUID derivation,
//! exact protocol-fidelity window_id/window_number preservation across compactions,
//! header normalization, tracking channel stripping, and realistic organic
//! client workstation simulation per account/group cluster on the egress boundary.

pub mod body;
pub mod headers;
pub mod identity;
pub mod metadata;
pub mod types;

#[cfg(test)]
mod tests;

pub use body::{transform_request_body, transform_ws_frame};
pub use headers::sanitize_and_inject_headers;
pub use identity::{extract_client_version_from_headers, extract_window_number};
pub use types::{MimicError, UnknownFieldPolicy};

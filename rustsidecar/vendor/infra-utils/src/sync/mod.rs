//! Pure-atomic admission and drain primitives.
//!
//! This module has no runtime dependency. Loom models build the crate with
//! `--no-default-features` and `--cfg loom`; there is no compatibility `sync`
//! feature label.

pub mod shutdown_gate;

pub use shutdown_gate::{Permit, ShutdownGate};

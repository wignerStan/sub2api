//! Owned shutdown / in-flight admission gate.
//!
//! A tiny atomic state machine: requests are admitted while the gate is open
//! ([`ShutdownGate::try_enter`] returns a [`Permit`]); once
//! [`ShutdownGate::shutdown`] is called, new requests are rejected and the gate
//! is at rest only when in-flight permits drop to zero. The RAII `Permit` is the
//! invariant: every accepted request is counted on enter and decremented on
//! drop, so `in_flight` can never underflow or leak.
//!
//! This module is **pure std atomics** — no tokio, no async, no loom. Callers
//! that need an async drain wait compose that themselves (poll `in_flight()` with
//! a runtime yield); the async concern stays out of utils.
//!
//! Loom model: `tests/loom_shutdown_gate.rs` expands the same logic via
//! [`shutdown_gate_impl!`] against `loom::sync::atomics`, so the model exercises
//! identical code with no hand-maintained copy.

#![allow(clippy::std_instead_of_core)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The gate logic, as a macro over the concrete atomic types. Expanded once here
/// with `std` atomics (production) and once in the Loom model with `loom` atomics
/// — single source of truth, no copy to drift. `Ordering`/`AtomicBool`/
/// `AtomicUsize` are referenced by name, so the macro works with both
/// `std::sync::atomic` and `loom::sync::atomic` in scope at the expansion site.
#[macro_export]
macro_rules! shutdown_gate_impl {
    () => {
        /// Admission/shutdown gate over two atomics: a shutdown flag and an
        /// in-flight counter.
        #[derive(Debug, Default)]
        pub struct ShutdownGate {
            shutdown: AtomicBool,
            in_flight: AtomicUsize,
        }

        /// RAII proof that one request is in flight. Decrementing on `Drop`
        /// balances the increment taken in `ShutdownGate::try_enter`.
        #[derive(Debug)]
        #[must_use = "a Permit holds the in-flight slot; dropping it releases the gate"]
        pub struct Permit<'a> {
            gate: &'a ShutdownGate,
        }

        impl ShutdownGate {
            /// Create a new, open gate (not shutting down, zero in-flight).
            #[must_use]
            pub fn new() -> Self {
                Self::default()
            }

            /// Try to admit one request. Returns `None` once shutdown has begun.
            ///
            /// Double-checked: load the shutdown flag, increment in-flight, then
            /// re-check the flag and back out (decrement + reject) if shutdown
            /// flipped in between. This closes the admit/shutdown race window.
            #[must_use]
            pub fn try_enter(&self) -> Option<Permit<'_>> {
                if self.shutdown.load(Ordering::Acquire) {
                    return None;
                }
                self.in_flight.fetch_add(1, Ordering::AcqRel);
                if self.shutdown.load(Ordering::Acquire) {
                    // Shutdown began between our two loads: undo the increment.
                    self.in_flight.fetch_sub(1, Ordering::AcqRel);
                    return None;
                }
                Some(Permit { gate: self })
            }

            /// Begin shutdown: reject all future admissions. Idempotent.
            pub fn shutdown(&self) {
                self.shutdown.store(true, Ordering::Release);
            }

            /// Whether shutdown has begun.
            #[must_use]
            pub fn is_shutdown(&self) -> bool {
                self.shutdown.load(Ordering::Acquire)
            }

            /// Current in-flight count (admitted permits not yet dropped).
            ///
            /// A snapshot for assertions and a drain wait; not a synchronization
            /// primitive by itself.
            #[must_use]
            pub fn in_flight(&self) -> usize {
                self.in_flight.load(Ordering::Acquire)
            }
        }

        impl Drop for Permit<'_> {
            fn drop(&mut self) {
                self.gate.in_flight.fetch_sub(1, Ordering::AcqRel);
            }
        }
    };
}

shutdown_gate_impl!();

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn admit_then_release_balances_in_flight() {
        let gate = ShutdownGate::new();
        let p = gate.try_enter().expect("open gate admits");
        assert_eq!(gate.in_flight(), 1);
        drop(p);
        assert_eq!(gate.in_flight(), 0);
    }

    #[test]
    fn shutdown_rejects_new_admissions() {
        let gate = ShutdownGate::new();
        assert!(gate.try_enter().is_some());
        gate.shutdown();
        assert!(gate.try_enter().is_none());
        assert!(gate.is_shutdown());
    }

    #[test]
    fn in_flight_admitted_before_shutdown_is_held_until_drop() {
        let gate = ShutdownGate::new();
        let p = gate.try_enter().expect("admitted");
        gate.shutdown();
        assert_eq!(gate.in_flight(), 1, "in-flight permit held across shutdown");
        drop(p);
        assert_eq!(gate.in_flight(), 0);
    }
}

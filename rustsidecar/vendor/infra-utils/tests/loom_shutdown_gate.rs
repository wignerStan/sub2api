//! Loom model for the `utils::sync::ShutdownGate` admission/drain primitive.
//!
//! Loom systematically explores all interleavings of a small sync state machine
//! under the memory model (docs/testing-philosophy.md "Concurrency & Memory
//! Safety Testing" → Rust race-detect = loom/shuttle). The gate is pure atomics
//! + a RAII `Permit`, so it is exactly the kind of primitive Loom is for.
//!
//! `loom` is a dev-dependency, and `utils` is a closed axisless leaf that may not
//! own raw third-party crates — so the gate logic lives in `utils` as a macro
//! (`utils::shutdown_gate_impl!`) expanded with `std` atomics in the lib. This
//! test re-expands the SAME macro against `loom::sync::atomics`, so the model
//! exercises identical code with no hand-maintained copy.
//!
//! Run with:
//!
//! ```bash
//! RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 \
//!   cargo test -p utils --no-default-features \
//!     --test loom_shutdown_gate --release
//! ```
//!
//! Oracle (must hold under every explored schedule): after the entry thread and
//! the shutdown thread both join, the gate is shut down AND `in_flight == 0` —
//! the RAII `Permit` always balances the enter increment.

#![cfg(loom)]
// Loom model tests: expect/unwrap produce clear failures.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// Re-expand the authoritative gate logic with loom atomics. The macro references
// AtomicBool / AtomicUsize / Ordering by name, resolved to loom's here.
utils::shutdown_gate_impl!();

use loom::sync::Arc;
use loom::thread;

#[test]
fn shutdown_races_with_request_entry() {
    loom::model(|| {
        let gate = Arc::new(ShutdownGate::new());

        // Entry thread: try to admit one request; if admitted, drop the permit
        // immediately (simulating a request that completes). The permit's Drop
        // must always balance the enter increment.
        let entry = {
            let gate = gate.clone();
            thread::spawn(move || {
                if let Some(permit) = gate.try_enter() {
                    drop(permit);
                }
            })
        };

        // Shutdown thread: begin shutdown. It may run before, during, or after
        // the entry thread's double-checked admit.
        let shutdown = {
            let gate = gate.clone();
            thread::spawn(move || {
                gate.shutdown();
            })
        };

        entry.join().expect("entry thread");
        shutdown.join().expect("shutdown thread");

        // Invariant under every interleaving:
        assert!(gate.is_shutdown(), "shutdown must have been called");
        assert_eq!(
            gate.in_flight(),
            0,
            "in-flight must be 0 after the permit dropped — no leaked admit"
        );
    });
}

#[test]
fn many_entries_race_shutdown_never_underflow_or_leak() {
    // Stress the balancing invariant with several concurrent entries racing one
    // shutdown. Loom explores their interleavings; in_flight must end at 0.
    loom::model(|| {
        let gate = Arc::new(ShutdownGate::new());

        let mut handles = Vec::new();
        for _ in 0..3 {
            let gate = gate.clone();
            handles.push(thread::spawn(move || {
                if let Some(permit) = gate.try_enter() {
                    // Hold the slot across a yield so shutdown can land mid-flight.
                    loom::thread::yield_now();
                    drop(permit);
                }
            }));
        }
        {
            let gate = gate.clone();
            handles.push(thread::spawn(move || {
                gate.shutdown();
            }));
        }

        for h in handles {
            h.join().expect("thread join");
        }

        assert_eq!(
            gate.in_flight(),
            0,
            "all admitted permits must have released under every schedule"
        );
    });
}

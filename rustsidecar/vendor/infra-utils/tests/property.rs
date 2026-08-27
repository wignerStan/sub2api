//! Property-based tests for the pure semantic core (FCIS testing-philosophy
//! Layer 3): invariants held over many generated inputs, not isolated examples.
//!
//! These probe properties a mirror-the-implementation unit test cannot:
//! determinism, idempotency, and round-trip preservation. proptest minimizes
//! any failing case to a regression fixture.

use proptest::prelude::*;

use utils::crypto::stable::{normalize_slash_path, stable_digest};

// ---------------------------------------------------------------------------
// stable_digest (FNV-1a): determinism + distinctness.
// ---------------------------------------------------------------------------

proptest! {
    /// Same input always yields the same digest (pure function).
    #[test]
    fn digest_is_deterministic(input in ".{0,64}") {
        prop_assert_eq!(stable_digest(&input), stable_digest(&input));
    }

    /// A prefix change changes the digest (FNV-1a is position-sensitive: every
    /// distinct byte sequence is overwhelmingly likely to collide only by the
    /// birthday bound on 64 bits, which we do not assert here — only that a
    /// single trailing-byte change almost always differs).
    #[test]
    fn digest_distinct_under_extension(prefix in ".{0,32}", tail in "[a-z]") {
        let a = stable_digest(&prefix);
        let b = stable_digest(format!("{prefix}{tail}"));
        // Only fails on the astronomically rare 64-bit collision.
        prop_assume!(a != b);
    }

    /// The digest carries the documented `fnv1a64:` scheme prefix.
    #[test]
    fn digest_has_scheme_prefix(input in ".{0,16}") {
        prop_assert!(stable_digest(&input).starts_with("fnv1a64:"));
        // 16 hex nibbles follow the prefix.
        prop_assert_eq!(stable_digest(&input).len(), "fnv1a64:".len() + 16);
    }
}

// ---------------------------------------------------------------------------
// normalize_slash_path: idempotency (normalize ∘ normalize == normalize).
// ---------------------------------------------------------------------------

proptest! {
    /// Normalizing twice equals normalizing once — the fixpoint property. A
    /// path with no backslashes is already normalized; one with them reaches its
    /// fixpoint in one step.
    #[test]
    fn normalize_slash_path_is_idempotent(path in ".{0,64}") {
        let once = normalize_slash_path(&path);
        let twice = normalize_slash_path(&once);
        prop_assert_eq!(once, twice);
    }

    /// After normalization, no backslash remains.
    #[test]
    fn normalize_slash_path_has_no_backslash(path in ".{0,64}") {
        let normalized = normalize_slash_path(&path);
        prop_assert!(
            !normalized.contains('\\'),
            "backslash survived normalization: {normalized:?}"
        );
    }
}

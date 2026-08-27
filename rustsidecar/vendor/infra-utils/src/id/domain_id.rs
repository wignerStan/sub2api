//! Domain-specific typed ID newtypes over `Uuid`.
//!
//! NOTE: `dead_code` is allowed at the module level because the shipped ID types
//! (`RequestId`, `RunId`, `ArtifactId`) and their `parse` methods are PUBLIC API
//! for external consumers, but the crate is `publish = false` — rustc can't see
//! external consumers, so it flags pub items with no internal call sites as dead.
//! The macro-generated `parse` is genuinely useful API; the allow is scoped here
//! only, not sprinkled on individual methods.
//!
//! The footgun these prevent: passing an `OrgId` where a `UserId` is expected.
//! Raw `Uuid`/`String` IDs are interchangeable at the type level, so a
//! mix-up compiles and silently corrupts. A per-domain newtype makes two
//! unrelated IDs incomparable: `load(RequestId)` rejects a `RunId` at compile
//! time.
//!
//! This module ships a small set of common IDs ([`RequestId`], [`RunId`],
//! [`ArtifactId`]) plus a [`domain_id!`] macro so a consuming crate can declare
//! its own (`UserId`, `OrgId`, …) with one line. Each newtype:
//! - generates with v7 (timestamp-ordered, the DB-key policy),
//! - parses strict (rejects nil),
//! - exposes `as_uuid()` and a hyphenated string.
//!
//! Never use these (or any UUID) as an auth capability token — RFC 9562.

// The shipped ID types + their methods are public API consumed externally,
// but the crate is `publish = false` so rustc flags them as dead (no internal
// call site). Allow at the module level — see the NOTE in the module doc above.
#![allow(dead_code)]

use uuid::Uuid;

use crate::id::uuid_ext::IdError;

/// A typed domain ID. Sealed pattern: construct via [`domain_id!`] or the
/// per-domain constructors below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainId(Uuid);

impl DomainId {
    /// Generate a new v7 (sortable) ID.
    #[must_use]
    fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

/// Declare a domain ID newtype.
///
/// Each declared type wraps a distinct `DomainId`, so two declared types are
/// incomparable (a `UserId` cannot be passed where an `OrgId` is expected).
/// The generated type has `new()`, `parse(s)`, `as_uuid()`, and `to_string()`.
#[macro_export]
macro_rules! domain_id {
    ($(#[$meta:meta])* $vis:vis $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        $vis struct $name($crate::id::domain_id::DomainId);

        impl $name {
            /// Generate a new v7 (timestamp-ordered) ID.
            #[must_use]
            pub fn new() -> Self {
                Self($crate::id::domain_id::DomainId::__new_for_macro())
            }

            /// Parse a non-nil UUID string.
            ///
            /// # Errors
            ///
            /// [`crate::IdError::Parse`] for malformed input;
            /// [`crate::IdError::Nil`] for the nil UUID.
            pub fn parse(s: &str) -> Result<Self, $crate::id::uuid_ext::IdError> {
                Ok(Self($crate::id::domain_id::DomainId::__parse_for_macro(s)?))
            }

            /// The underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> ::uuid::Uuid {
                $crate::id::domain_id::DomainId::__as_uuid(self.0)
            }
        }

        impl ::std::default::Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

// ---- shipped common IDs ----

domain_id! {
    /// A request ID (traces/spans, inbound request correlation).
    pub RequestId
}
domain_id! {
    /// A run ID (a single execution / CI run / agent run).
    pub RunId
}
domain_id! {
    /// An artifact ID (a published/produced artifact).
    pub ArtifactId
}

// ---- macro-facing constructors (pub(crate) but reachable via the macro path) ----
impl DomainId {
    #[doc(hidden)]
    #[must_use]
    pub fn __new_for_macro() -> Self {
        Self::new()
    }

    #[doc(hidden)]
    /// # Errors
    ///
    /// [`IdError::Parse`] / [`IdError::Nil`].
    pub fn __parse_for_macro(s: &str) -> Result<Self, IdError> {
        Ok(Self(crate::id::uuid_ext::parse_non_nil_uuid(s)?))
    }

    #[doc(hidden)]
    #[must_use]
    pub const fn __as_uuid(self) -> Uuid {
        self.0
    }

    #[doc(hidden)]
    #[must_use]
    pub fn __to_string(self) -> String {
        self.0.to_string()
    }
}

impl std::fmt::Display for DomainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_generates_and_parses() {
        let id = RequestId::new();
        let s = id.to_string(); // uses Display
        let again = RequestId::parse(&s).unwrap();
        assert_eq!(id.as_uuid(), again.as_uuid());
    }

    #[test]
    fn run_id_rejects_nil() {
        assert!(matches!(
            RunId::parse("00000000-0000-0000-0000-000000000000"),
            Err(IdError::Nil)
        ));
    }

    #[test]
    fn distinct_types_do_not_mix() {
        // Compile-time check: RequestId and RunId are distinct types.
        let req = RequestId::new();
        let run = RunId::new();
        assert_ne!(req.as_uuid(), run.as_uuid());
        // `req == run` would not compile (different types).
    }

    #[test]
    fn custom_domain_id_via_macro() {
        domain_id! {
            /// A user ID.
            pub UserId
        }
        domain_id! {
            /// An org ID.
            pub OrgId
        }
        let u = UserId::new();
        let o = OrgId::new();
        assert_ne!(u.as_uuid(), o.as_uuid());
        // Display works.
        assert_eq!(
            UserId::parse(&u.to_string()).unwrap().as_uuid(),
            u.as_uuid()
        );
    }
}

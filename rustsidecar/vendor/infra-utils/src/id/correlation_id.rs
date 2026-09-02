//! `CorrelationId` — a UUID-backed correlation identifier.
//!
//! Distinct from [`crate::id::RequestId`] (which marks a single request):
//! a correlation id groups a *chain* of requests/spans that belong to one
//! logical operation across services. UUID-v7-backed (sortable, the same key
//! policy as the other domain ids), strict-parsed (rejects nil), incomparable
//! with other id newtypes at the type level.

crate::domain_id! {
    /// A correlation ID — groups a chain of requests/spans in one logical
    /// operation across services. Incomparable with `RequestId`/`RunId`.
    pub CorrelationId
}

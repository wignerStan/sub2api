//! Networking category: TLS config, URL helpers, origin/host-port value types,
//! SSRF/blocklist safety, header-value validation, redirect-target validation,
//! distributed-trace context.
//!
//! Runtime supervision, stdin/stdout relays, and executor lifecycle do not
//! belong in this leaf module. Callers own those operational boundaries.

pub mod blocklist;
pub mod header_value;
pub mod host_authority;
pub mod host_port;
pub mod media;
pub mod origin;
pub mod redirect;
pub mod request_target;
pub mod ssrf;
pub mod tls;
pub mod trace;
pub mod url_ext;

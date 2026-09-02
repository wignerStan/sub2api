//! Identifier category: UUID helpers (uuid_ext), domain ID newtypes
//! (domain_id — `RequestId`/`RunId`/`ArtifactId`/`CorrelationId`), W3C
//! `TraceId`, non-empty string, positive int, validated path segments.

pub mod correlation_id;
pub mod domain_id;
pub mod non_empty_string;
pub mod positive_int;
pub mod trace_id;
pub mod uuid_ext;
pub mod validated_path_segment;

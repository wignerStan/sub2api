//! Text category: string helpers, fuzzy match, percent, byte size,
//! ASCII-safe JSON formatting, token-aware truncation, strict templating.
//!
//! The `regex` crate is not routed through `utils`; depend on `regex` directly
//! from the owner that needs it.

pub mod byte_size;
pub mod delimited;
pub mod fuzzy;
pub mod percent;
pub mod strings;
pub mod template;
pub mod token_truncate;

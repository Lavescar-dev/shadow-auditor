//! Alias module: expose the `SharedAstCache` as `AstCache` for consumers that
//! do not need to reason about sharing semantics.

pub use super::SharedAstCache as AstCache;

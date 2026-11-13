//! Portable service contracts: no LLVM, QEMU, OS processes or HTTP client.
pub mod annotations;
pub mod bundle;
pub mod diff;
pub mod job;
pub mod packages;
pub mod tokens;
pub use packages::*;
pub const SCHEMA_VERSION: u32 = 1;
pub const ANALYSIS_TRIPLE: &str = "x86_64-unknown-linux-gnu";
pub use job::{MIN_MEMORY_BYTES, MIN_WORKER_BYTES};

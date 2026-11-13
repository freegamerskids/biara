//! Version-one decompilation records. Statements link to surviving source
//! contributors, not exhaustive original instruction coverage. Type/name
//! evidence never authorizes changing guest arithmetic or pointer bounds.
//!
//! The record shape is the portable contract in `biara_proto::packages`;
//! lift re-exports it so renderer JSON and bundle readers share one type.

/// A proven function-entry architectural-register name binding.
#[derive(Clone, Debug)]
pub struct DebugName {
    pub function: u64,
    pub register: String,
    pub name: String,
}
/// A whole declared variable with precise PC validity and entry-SP offset.
#[derive(Clone, Debug)]
pub struct DebugObject {
    pub function: u64,
    pub start: u64,
    pub end: u64,
    pub offset: i64,
    pub size: u64,
    pub name: String,
    pub type_name: Option<String>,
}

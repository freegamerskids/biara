//! Version-one decompilation records. Statements link to surviving source
//! contributors, not exhaustive original instruction coverage. Type/name
//! evidence never authorizes changing guest arithmetic or pointer bounds.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionPackage {
    pub address: u64,
    pub name: String,
    pub signature: String,
    /// Full analysis definition, not a standalone translation unit.
    pub body: String,
    pub statements: Vec<PackageStatement>,
    pub dependencies: Vec<PackageDependency>,
    pub names: Vec<PackageName>,
    pub metrics: ReadabilityMetrics,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageStatement {
    pub id: String,
    /// One-based line within FunctionPackage::body.
    pub line: u64,
    pub text: String,
    pub addresses: Vec<u64>,
    /// exact: all observed contributors mapped; inferred: partial metadata;
    /// unknown: no source contributor. Never a whole-function completeness claim.
    pub provenance: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageDependency {
    pub id: String,
    pub kind: String,
    pub text: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageName {
    pub name: String,
    pub original: String,
    /// debug, symbol, inferred, or unknown.
    pub evidence: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadabilityMetrics {
    /// Deterministic lexical estimate, not a model-specific tokenizer.
    pub tokens: u64,
    pub temporaries: u64,
    pub register_names: u64,
    /// Lexical explicit-cast count in the body, including inferred callback
    /// typedefs; function parameter-list syntax is not an expression cast.
    pub casts: u64,
    pub gotos: u64,
    pub max_nesting: u64,
    pub statements: u64,
    pub mapped_statements: u64,
    pub unsupported: u64,
}
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

//! Version-one decompilation records. Statements link to surviving source
//! contributors, not exhaustive original instruction coverage. Type/name
//! evidence never authorizes changing guest arithmetic or pointer bounds.
//!
//! Serde-only contract: this is the canonical record shape shared by the
//! renderer and bundle readers. Field names and JSON shapes must stay
//! wire-compatible with the decompilation emitter.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionPackage {
    pub address: u64,
    pub name: String,
    pub signature: String,
    /// Full analysis definition, not a standalone translation unit.
    pub body: String,
    /// Lexical token stream over `body`: byte offsets plus optional
    /// semantic symbol references. Renames substitute tokens carrying a
    /// matching [`crate::tokens::SymbolRef`]; all other bytes stay fixed.
    /// Empty for records produced before token emission existed.
    #[serde(default)]
    pub tokens: Vec<crate::tokens::Token>,
    /// Authoritative native symbol table for this record (C3): emitted
    /// nonlocal spellings with true identity. `None` for records produced
    /// before native symbol emission existed (clients fall back to the
    /// legacy display-text tables, which cannot distinguish shadows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbols: Option<PackageSymbols>,
    pub statements: Vec<PackageStatement>,
    pub dependencies: Vec<PackageDependency>,
    pub names: Vec<PackageName>,
    pub metrics: ReadabilityMetrics,
}
/// Authoritative emitted-symbol table for one function record: sanitized
/// display spellings with stable identity, recorded by the native renderer
/// at emission. Functions/globals key by guest/image address; types by
/// layout-analysis shared id scoped to this record's module. Emitted
/// spellings are globally unique nonlocal names (locals were suffixed on
/// collision), so any identifier in the body matching a table spelling is
/// a genuine symbol unless positionally excluded (member-field side after
/// `->`/`.`, comment, or string literal).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageSymbols {
    #[serde(default)]
    pub functions: Vec<PackageFunctionSymbol>,
    #[serde(default)]
    pub globals: Vec<PackageGlobalSymbol>,
    #[serde(default)]
    pub types: Vec<PackageTypeSymbol>,
}
/// One emitted function spelling and its guest entry address.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageFunctionSymbol {
    pub text: String,
    pub address: u64,
}
/// One emitted copied-data global spelling and its image address.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageGlobalSymbol {
    pub text: String,
    pub address: u64,
}
/// One emitted layout spelling and its shared id (scoped to the
/// referencing function record: resolve against the same record's
/// `types/<addr>` facts).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageTypeSymbol {
    pub text: String,
    pub layout: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageStatement {
    /// Stable statement id (`function_<addr>/s<n>`), matching the renderer's
    /// chunk-addressable identity.
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

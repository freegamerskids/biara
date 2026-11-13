//! Portable binary-diff report: function matches with confidence and
//! per-function block maps. No LLVM, QEMU, CFG or loader types.
use serde::{Deserialize, Serialize};

use crate::SCHEMA_VERSION;

fn version() -> u32 {
    SCHEMA_VERSION
}

/// Which input side a [`DiffIssue`] was recovered from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Old,
    New,
}

/// How a function of one binary relates to the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionKind {
    Same,
    Changed,
    Uncertain,
    Added,
    Removed,
}

/// How one positional (topology-order) block pair relates.
///
/// Paired entries claim [`BlockStatus::Same`] only when the normalized code
/// is equal and [`BlockStatus::Changed`] only on a defensible opcode,
/// operand, literal or callee difference; otherwise [`BlockStatus::Uncertain`].
/// Single-sided entries are explicit [`BlockStatus::Added`] or
/// [`BlockStatus::Removed`] with correct guest addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockStatus {
    Same,
    Changed,
    Uncertain,
    Added,
    Removed,
}

/// One positional (topology-order) block pair within a matched function.
/// Guest addresses; exactly one side is `None` for added/removed blocks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockPair {
    pub old_block: Option<u64>,
    pub new_block: Option<u64>,
    pub old_index: Option<usize>,
    pub new_index: Option<usize>,
    pub status: BlockStatus,
}

/// One function match with confidence and its per-function block map.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionDiff {
    pub kind: FunctionKind,
    #[serde(default)]
    pub old_function: Option<u64>,
    #[serde(default)]
    pub new_function: Option<u64>,
    #[serde(default)]
    pub old_name: Option<String>,
    #[serde(default)]
    pub new_name: Option<String>,
    /// Classification confidence in normalized recovered code, not a
    /// calibrated probability of semantic equivalence or safe annotation porting.
    /// Lower when pairing or recovery is uncertain.
    pub confidence: f32,
    /// True for ambiguous pairings, unsupported code, or incomplete recovery.
    /// Never set for definite same/changed/added/removed.
    pub uncertain: bool,
    /// Evidence: differing block addresses, changed callees, ambiguity or
    /// recovery notes. Empty only for clean same-function matches.
    #[serde(default)]
    pub reasons: Vec<String>,
    /// Positional (topology-order) block pairs. Added/removed functions list
    /// their blocks single-sided.
    #[serde(default)]
    pub blocks: Vec<BlockPair>,
}

/// A recovery fact that limits what the comparison may claim, attributed to
/// the side it was recovered from, plus explicit records of caller-supplied
/// rows outside the pairing. Includes comparison limitations from both inputs;
/// uncertain facts and supplied rows must not be dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum DiffIssue {
    Unsupported {
        side: Side,
        function: u64,
        block: u64,
        operation: String,
    },
    Incomplete {
        side: Side,
        function: Option<u64>,
        address: Option<u64>,
        reason: String,
    },
    Ambiguous {
        side: Side,
        functions: Vec<u64>,
    },
    /// A caller-supplied match that is not part of this
    /// old/new pairing (unknown function, stub, or a pairing the evidence
    /// does not support). The entry is excluded from `functions` and
    /// recorded here so `report` never silently drops rows.
    Inconsistent {
        detail: String,
    },
}
/// All function matches of one old/new comparison, in stable address order,
/// plus every uncertainty fact from both sides.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffReport {
    #[serde(default = "version")]
    pub version: u32,
    pub functions: Vec<FunctionDiff>,
    #[serde(default)]
    pub issues: Vec<DiffIssue>,
}

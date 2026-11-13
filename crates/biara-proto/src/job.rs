//! Provider-independent worker job and staged analysis records.
use crate::{ANALYSIS_TRIPLE, SCHEMA_VERSION, annotations::Annotations};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    #[serde(default = "version")]
    pub version: u32,
    pub id: String,
    /// file:// or HTTPS URL; workers receive no ambient storage credentials.
    pub input: String,
    #[serde(default)]
    pub resume_database: Option<String>,
    pub outputs: JobOutputs,
    #[serde(default)]
    pub entries: Vec<u64>,
    /// Empty requests recovery and ABI only; listed functions render lazily.
    #[serde(default)]
    pub decompile: Vec<u64>,
    #[serde(default)]
    pub annotations: Annotations,
    #[serde(default)]
    pub limits: JobLimits,
    #[serde(default = "triple")]
    pub target_triple: String,
}
fn version() -> u32 {
    SCHEMA_VERSION
}
fn triple() -> String {
    ANALYSIS_TRIPLE.into()
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobOutputs {
    pub bundle: String,
    pub database: String,
}
/// Minimum worker address-space share, including statically linked LLVM,
/// libtcg's 128 MiB JIT reservation and analysis allocations. RLIMIT_AS counts
/// mapped pages, not just resident memory; a 256 MiB share can fail at startup.
pub const MIN_WORKER_BYTES: u64 = 1024 * 1024 * 1024;
/// Minimum total job budget: coordinator half plus one worker half.
pub const MIN_MEMORY_BYTES: u64 = 2 * MIN_WORKER_BYTES;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JobLimits {
    pub memory_bytes: u64,
    pub wall_seconds: u64,
    pub max_blocks: usize,
    pub workers: usize,
    pub max_input_bytes: u64,
}
impl Default for JobLimits {
    fn default() -> Self {
        Self {
            memory_bytes: 4 * 1024 * 1024 * 1024,
            wall_seconds: 3600,
            max_blocks: 1_000_000,
            workers: 1,
            max_input_bytes: 1024 * 1024 * 1024,
        }
    }
}
impl JobSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != SCHEMA_VERSION {
            return Err("unsupported job schema".into());
        }
        if self.target_triple != ANALYSIS_TRIPLE {
            return Err("unsupported analysis target triple".into());
        }
        if self.id.is_empty() {
            return Err("job id is empty".into());
        }
        if self.limits.memory_bytes < MIN_MEMORY_BYTES
            || self.limits.wall_seconds == 0
            || self.limits.workers == 0
            || self.limits.max_blocks == 0
            || self.limits.max_input_bytes == 0
        {
            return Err(
                "memory >=2 GiB and positive time/worker/block/input limits required".into(),
            );
        }
        self.annotations.validate().map_err(|e| e.to_string())?;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Scan,
    Cfg,
    Abi,
    Decomp,
    Upload,
    Complete,
    Failed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub version: u32,
    pub job: String,
    pub sequence: u64,
    pub stage: Stage,
    pub elapsed_ms: u64,
    pub functions: usize,
    pub blocks: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Initial candidates or incremental CFG facts, available before decompilation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionEntry {
    pub address: u64,
    pub name: Option<String>,
    pub blocks: Vec<u64>,
    pub calls: Vec<u64>,
    pub returns: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisIndex {
    pub version: u32,
    pub binary_hash: String,
    pub build_hash: String,
    pub annotation_hash: String,
    pub target_triple: String,
    pub arch: String,
    pub os: String,
    pub functions: Vec<FunctionEntry>,
    pub rendered: Vec<u64>,
    pub complete: bool,
    pub issues: Vec<serde_json::Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CfgBlock {
    pub address: u64,
    pub end: u64,
    pub instructions: Vec<u64>,
    pub exits: Vec<CfgExit>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CfgExit {
    pub kind: String,
    pub target: Option<u64>,
    pub continuation: Option<u64>,
    pub slot: Option<u64>,
    pub op: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossReferences {
    pub callers: BTreeMap<u64, Vec<u64>>,
    pub callees: BTreeMap<u64, Vec<u64>>,
}

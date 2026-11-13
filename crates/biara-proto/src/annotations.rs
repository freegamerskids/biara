//! Portable annotation inputs: user-supplied function names and signatures.
//!
//! Serde-only contract shared by the CLI, the worker service and analysis
//! backends. Parsing and validation live here; interpretation (ABI, lift,
//! render) lives with the consumers. No LLVM, QEMU, OS or HTTP types.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::SCHEMA_VERSION;

fn version() -> u32 {
    SCHEMA_VERSION
}

/// One function's user-supplied overrides.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionAnnotation {
    /// Replacement display name; `None` keeps the recovered name.
    #[serde(default)]
    pub name: Option<String>,
    /// C-spelled function signature (return type, name and parameter list,
    /// e.g. `"int add(int a, int b)"`); `None` keeps the recovered signature.
    /// Stored opaquely here; consumers parse it as C. Supported grammar
    /// (see lift `annotations`): one return type plus a parenthesized
    /// parameter list (`(void)` for no parameters); scalar types `void`
    /// (return only), 8-bit (`char`, `signed char`, `unsigned char`,
    /// `int8_t`, `uint8_t`), 16-bit (`short`, `signed short`,
    /// `unsigned short`, `int16_t`, `uint16_t`), 32-bit (`int`, `signed`,
    /// `unsigned`, `int32_t`, `uint32_t`, `long` on LLP64 Windows,
    /// `enum E`), 64-bit (`long` on LP64, `long long`, `int64_t`,
    /// `uint64_t`, `size_t`, `uintptr_t`, `intptr_t`), `bool`/`_Bool`
    /// (real boolean), `float`, `double`; pointers (`T *`,
    /// `const`-qualified, any depth, arrays decay); named struct pointers
    /// (`struct name *`, declared in [`Annotations::structs`]).
    /// Unsupported (loud error, never silent downgrade): variadics,
    /// function pointers, by-value aggregates, 128-bit by-value scalars,
    /// `void` parameters, empty `()` lists.
    #[serde(default)]
    pub signature: Option<String>,
}

/// One named struct's declared layout: typed fields by byte offset.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructField {
    /// Byte offset of the field within the struct.
    pub offset: i64,
    /// Field width in bytes (1, 2, 4, 8 or 16).
    pub bytes: u32,
    /// Field display name.
    pub name: String,
    /// Declared C spelling of the field type (`u64`, `u32`, `float`,
    /// `u8`, pointer `T *`, `struct name *`); defaults to the
    /// width-implied unsigned integer. Signed, float and pointer
    /// spellings bind the field's rendered type; anything else is a
    /// validation error, never a silent integer fallback.
    #[serde(default = "default_field_type")]
    pub type_name: String,
}

fn default_field_type() -> String {
    String::new()
}

/// One user-declared struct type, referenced by signature pointer types.
/// Each field binds by offset+width to a recovered layout field of a
/// pointer-lane-referenced layout only (never by shape matching across
/// unrelated structures); `type_name` becomes the rendered field type
/// with asserted provenance. Declared padding gaps are preserved; extra
/// declared fields beyond the recovered extent ride along as asserted
/// members.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructAnnotation {
    /// Ordered field declarations; offsets must be non-overlapping and
    /// sorted by offset at validation time.
    #[serde(default)]
    pub fields: Vec<StructField>,
}

/// User-supplied function names/signatures, global names and struct
/// layouts, keyed by guest address (functions/globals) or struct name.
/// Both JSON (`{"version":1,"functions":{"4195584":{"name":"main"}}}`) and
/// TOML (`[functions.4195584]`) spell addresses decimally. The custom
/// deserializer parses those string keys explicitly so both formats behave
/// identically.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Annotations {
    #[serde(default = "version")]
    pub version: u32,
    #[serde(default, deserialize_with = "de_functions")]
    pub functions: BTreeMap<u64, FunctionAnnotation>,
    /// Replacement display names for copied-data globals, by image
    /// address; empty keeps the recovered name.
    #[serde(default, deserialize_with = "de_names")]
    pub globals: BTreeMap<u64, String>,
    /// User-declared struct layouts, by struct name (without `struct`).
    #[serde(default)]
    pub structs: BTreeMap<String, StructAnnotation>,
}

fn de_functions<'de, D>(deserializer: D) -> Result<BTreeMap<u64, FunctionAnnotation>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let raw = BTreeMap::<String, FunctionAnnotation>::deserialize(deserializer)?;
    raw.into_iter()
        .map(|(key, value)| {
            key.parse::<u64>()
                .map(|address| (address, value))
                .map_err(|_| D::Error::custom(format!("invalid function address key {key:?}")))
        })
        .collect()
}

fn de_names<'de, D>(deserializer: D) -> Result<BTreeMap<u64, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let raw = BTreeMap::<String, String>::deserialize(deserializer)?;
    raw.into_iter()
        .map(|(key, value)| {
            key.parse::<u64>()
                .map(|address| (address, value))
                .map_err(|_| D::Error::custom(format!("invalid global address key {key:?}")))
        })
        .collect()
}
impl Default for Annotations {
    fn default() -> Self {
        Self {
            version: SCHEMA_VERSION,
            functions: BTreeMap::new(),
            globals: BTreeMap::new(),
            structs: BTreeMap::new(),
        }
    }
}

/// Annotation validation failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("unsupported annotations schema version {0}")]
    Version(u32),
    #[error("function {0:#x}: name is empty")]
    EmptyName(u64),
    #[error("function {0:#x}: signature is empty")]
    EmptySignature(u64),
    #[error("global {0:#x}: name is empty")]
    EmptyGlobalName(u64),
    #[error("struct or field name is empty")]
    EmptyStructName,
    #[error("struct {0:?}: field {1:?} has bad width {2}")]
    BadFieldWidth(String, String, u32),
    #[error("struct {0:?}: fields overlap at offset {1}")]
    OverlappingFields(String, i64),
    #[error("struct {0:?}: field {1:?} type {2:?} mismatches width {3}")]
    BadFieldType(String, String, String, u32),
}

/// Declared field types bind exactly to their widths: `u8/i8`→1,
/// `u16/i16`→2, `u32/i32/float`→4, `u64/i64/double`→8, pointers→8,
/// `u128/i128`→16. Empty keeps the width-implied unsigned integer.
/// `long` is 4 bytes on LLP64 (Windows) and 8 on LP64 (Linux/macOS);
/// both widths validate here so one schema covers both guests, and
/// consumers resolve the width by guest model. Negative offsets are
/// rejected; offset+bytes overflow is a validation error, never wrap.
fn validate_field_type(struct_name: &str, field: &StructField) -> Result<(), Error> {
    let spelling = field.type_name.trim();
    if spelling.is_empty() {
        return Ok(());
    }
    let mut core = spelling.to_owned();
    let mut depth = 0u32;
    while core.trim_end().ends_with('*') {
        depth += 1;
        core = core.trim_end()[..core.trim_end().len() - 1].trim_end().to_owned();
    }
    if depth > 0 {
        if field.bytes != 8 {
            return Err(Error::BadFieldType(struct_name.to_owned(), field.name.clone(), field.type_name.clone(), field.bytes));
        }
        return Ok(());
    }
    let normalized: String = core.split_whitespace().filter(|w| *w != "const" && *w != "volatile").collect::<Vec<_>>().join(" ");
    // Width sets: `long` spellings validate at 4 or 8 (guest model
    // resolves later); everything else has exactly one width.
    const LONG: &[&str] = &[
        "long", "signed long", "unsigned long", "long int",
        "signed long int", "unsigned long int",
    ];
    if LONG.contains(&normalized.as_str()) {
        if field.bytes != 4 && field.bytes != 8 {
            return Err(Error::BadFieldType(struct_name.to_owned(), field.name.clone(), field.type_name.clone(), field.bytes));
        }
        return Ok(());
    }
    let width = match normalized.as_str() {
        "bool" | "_Bool" | "char" | "signed char" | "unsigned char" | "int8_t" | "uint8_t" | "u8" | "i8" => 1,
        "short" | "signed short" | "unsigned short" | "short int" | "unsigned short int" | "signed short int" | "int16_t" | "uint16_t" | "u16" | "i16" => 2,
        "int" | "signed" | "signed int" | "unsigned" | "unsigned int" | "int32_t" | "uint32_t" | "u32" | "i32" | "float" => 4,
        "long long" | "signed long long" | "unsigned long long" | "int64_t" | "uint64_t" | "u64" | "i64" | "size_t" | "uintptr_t" | "intptr_t" | "double" => 8,
        "biara_u128" | "biara_i128" | "u128" | "i128" => 16,
        _ if normalized.starts_with("enum ") => 4,
        _ => return Err(Error::BadFieldType(struct_name.to_owned(), field.name.clone(), field.type_name.clone(), field.bytes)),
    };
    if width != field.bytes {
        return Err(Error::BadFieldType(struct_name.to_owned(), field.name.clone(), field.type_name.clone(), field.bytes));
    }
    Ok(())
}

impl Annotations {
    /// Reject version skew, empty overrides and overlapping struct
    /// fields; never normalization.
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != SCHEMA_VERSION {
            return Err(Error::Version(self.version));
        }
        for (&address, function) in &self.functions {
            if function.name.as_deref().is_some_and(str::is_empty) {
                return Err(Error::EmptyName(address));
            }
            if function.signature.as_deref().is_some_and(str::is_empty) {
                return Err(Error::EmptySignature(address));
            }
        }
        for (&address, name) in &self.globals {
            if name.is_empty() {
                return Err(Error::EmptyGlobalName(address));
            }
        }
        for (name, layout) in &self.structs {
            if name.is_empty() {
                return Err(Error::EmptyStructName);
            }
            let mut cursor = 0i64;
            let mut first = true;
            let mut fields = layout.fields.clone();
            fields.sort_by_key(|f| f.offset);
            for field in &fields {
                if field.name.is_empty() {
                    return Err(Error::EmptyStructName);
                }
                if !matches!(field.bytes, 1 | 2 | 4 | 8 | 16) {
                    return Err(Error::BadFieldWidth(name.clone(), field.name.clone(), field.bytes));
                }
                // Negative offsets are rejected; offset+bytes overflow is
                // a validation error, never wrapping arithmetic.
                if field.offset < 0 {
                    return Err(Error::OverlappingFields(name.clone(), field.offset));
                }
                let end = field.offset.checked_add(field.bytes as i64).ok_or_else(|| {
                    Error::OverlappingFields(name.clone(), field.offset)
                })?;
                if !first && field.offset < cursor {
                    return Err(Error::OverlappingFields(name.clone(), field.offset));
                }
                cursor = end;
                first = false;
                // Typed fields bind exactly: signed/float/pointer spellings
                // must width-match the declared bytes; an empty spelling
                // keeps the width-implied unsigned integer. Declared
                // padding (gaps between offsets) is preserved, never
                // back-filled; extra declared fields beyond the recovered
                // extent ride along as asserted layout members.
                validate_field_type(name, field)?;
            }
        }
        Ok(())
    }
}

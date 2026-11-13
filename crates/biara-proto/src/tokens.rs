//! Decompilation token-stream contract (C3): one [`Token`] per lexical
//! unit of a function body, with byte offsets into [`FunctionPackage::body`]
//! and optional semantic symbol references.
//!
//! Renames are client-side text substitutions over tokens carrying a
//! [`SymbolRef`]: replacing the bytes of every token whose symbol matches
//! yields the renamed body without re-rendering. Tokens without a symbol
//! are never renamed, even when their text equals a symbol name (locals,
//! parameters, comments and string literals stay untouched). Symbol
//! identity is the referenced address, keyed by [`SymbolRef`]
//! (functions/globals by address, types by layout id scoped to the
//! referencing function record), never the current display text. The
//! rename map is keyed by [`SymbolRef`] itself, so a function address
//! and a global image address that are numerically equal never collide.
use serde::{Deserialize, Serialize};

/// What a token references, by stable identity rather than display text.
/// Function/global identity is the guest/image address; type identity is
/// the layout-analysis `SharedLayout` id **scoped to the referencing
/// function record**: ids come from the `LayoutFacts` exported alongside
/// that function's module, so clients must resolve them against the
/// same record's `types/<addr>` facts, never a global table. Use
/// [`FunctionPackage::symbols`] (the renderer's authoritative emitted
/// table for that record) to build rename keys: type symbols carry the
/// referencing function scope explicitly when the record provides it.
/// Renaming a function/global substitutes every token carrying its
/// address/scope; struct display renames arrive through re-render (type
/// tokens never rename through [`substitute`]).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SymbolRef {
    /// A lifted function, by guest entry address.
    Function { address: u64 },
    /// A copied-data global, by image address.
    Global { address: u64 },
    /// A reusable inferred layout, by layout-analysis `SharedLayout` id
    /// scoped to the referencing function record (resolve against the
    /// same record's `types/<addr>` facts). `function` names the record
    /// whose facts own the id (0 when the record predates scoped export);
    /// the rename map keys the full triple, never the bare layout id.
    Type { layout: u32, #[serde(default)] function: u64 },
}

/// One lexical unit of a rendered function body: byte offsets plus an
/// optional semantic symbol reference. Span-only (no per-token text
/// copy): clients slice `body[start..end]`; `substitute` validates
/// offsets, ordering and UTF-8 boundaries and rejects hostile streams
/// instead of panicking.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    /// Byte offset of the token's first byte within the function body.
    pub start: u64,
    /// One-past-the-end byte offset within the function body.
    pub end: u64,
    /// `identifier`, `keyword`, `number`, `string`, `comment`, `punct`,
    /// `whitespace`, or `other`. Consumers mask non-code spans with it;
    /// identity always comes from `symbol`, never from position guessing.
    pub kind: String,
    /// Semantic reference, when the lexer attributed this token to a
    /// known symbol. `None` for locals, parameters, literals, comments,
    /// keywords and punctuation: never rename targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<SymbolRef>,
}
/// Substitute renamed symbols into `body` using `tokens`.
///
/// Every token carrying `SymbolRef::Function { address }` (or
/// `SymbolRef::Global { address }`) whose [`SymbolRef`] is in `renames`
/// is replaced by the mapped text; all other bytes (including unreferenced
/// tokens whose text happens to match) are kept verbatim. The map is
/// keyed by [`SymbolRef`] itself: a function address and a global image
/// address that are numerically equal are distinct keys and never collide.
///
/// Hostile token streams are rejected, never panicked on: out-of-range
/// offsets, overlapping or unordered tokens, non-UTF-8-boundary offsets,
/// and empty replacement names all return `Err`. Span-only tokens carry
/// no text copy: offsets index `body` directly. Type symbols are
/// identity-stable (layout ids scoped to the referencing function) and
/// never renamed by this function; struct display renames arrive through
/// re-render.
pub fn substitute(
    body: &str,
    tokens: &[Token],
    renames: &std::collections::BTreeMap<SymbolRef, String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(body.len());
    let mut cursor = 0usize;
    for token in tokens {
        let (start, end) = (token.start as usize, token.end as usize);
        if start > end || end > body.len() || start < cursor {
            return Err(format!(
                "token [{}, {}) out of range or overlapping",
                token.start, token.end
            ));
        }
        if !body.is_char_boundary(start) || !body.is_char_boundary(end) {
            return Err(format!(
                "token [{}, {}) splits a character",
                token.start, token.end
            ));
        }
        // Span-only tokens carry no text copy, so a shifted or forged span
        // that still parses as in-range must not silently substitute the
        // wrong identifier: renamed symbol spans must slice exactly one
        // identifier (no mid-identifier boundaries on either side).
        if let Some(symbol @ (SymbolRef::Function { .. } | SymbolRef::Global { .. })) = &token.symbol {
            if renames.contains_key(symbol) {
                let span = &body[start..end];
                if span.is_empty() || !span.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    return Err(format!("token [{}, {}) is not an identifier span", token.start, token.end));
                }
                if start > 0 && body[..start].chars().last().is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    return Err(format!("token [{}, {}) starts mid-identifier", token.start, token.end));
                }
                if end < body.len() && body[end..].chars().next().is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    return Err(format!("token [{}, {}) ends mid-identifier", token.start, token.end));
                }
            }
        }
        let replacement: Option<&String> = match &token.symbol {
            Some(symbol @ (SymbolRef::Function { .. } | SymbolRef::Global { .. })) => renames.get(symbol),
            _ => None,
        };
        match replacement {
            Some(name) if name.is_empty() => {
                return Err("empty replacement name".into());
            }
            Some(name) => out.push_str(name),
            None => out.push_str(&body[start..end]),
        }
        cursor = end;
    }
    out.push_str(&body[cursor..]);
    Ok(out)
}

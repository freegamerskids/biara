//! Authoritative token lexer for decompilation bodies (C3).
//!
//! [`lex`] splits a rendered function `body` into
//! [`biara_proto::tokens::Token`] records with byte offsets, then resolves
//! every identifier against the renderer's authoritative emitted-symbol
//! table for that record ([`biara_proto::PackageSymbols`], carried on the
//! record as `symbols`): emitted (sanitized) nonlocal spellings with true
//! identity (functions by guest address, globals by image address, types
//! by layout id scoped to the referencing function). Identity derives from
//! real LLVM/native entities at emission, never from lexical guesses over
//! the C text:
//! - the body's own definition name resolves through the table (its first
//!   `name(` occurrence references the record's function address);
//! - any other table hit (call callee, declaration, plain global load,
//!   address use `&g`, dereference `*g`, function value, cast/type use,
//!   field-base `g->f`/`g.f` base side) references the table identity;
//! - member field sides (after `->`/`.`), locals, parameters, keywords,
//!   numbers, punctuation, comments and string contents carry no symbol.
//! Locals/parameters were uniquified against the table at emission
//! (colliding spellings suffixed), so table spellings are globally unique
//! nonlocal names: a hit is a genuine symbol, and shadowing is impossible
//! by construction. No heuristic call/address/member-position guessing,
//! no dropped plain-value refs: every address-backed referent attributes.
/// Raw lexical token: byte offsets, coarse kind, and exact text.
struct Raw {
    start: usize,
    end: usize,
    kind: &'static str,
    text: String,
}
use std::collections::BTreeMap;

use biara_proto::tokens::{SymbolRef, Token};

/// C identifier sanitization shared with the renderer (`ident()` in
/// cpp/cgen.cpp): non-alphanumeric bytes become `_`, leading digits gain
/// `_`, keywords gain a trailing `_`.
pub fn c_ident(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() || out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    const KEYWORDS: &[&str] = &[
        "auto",
        "break",
        "case",
        "char",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "float",
        "for",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "register",
        "restrict",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "typedef",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while",
        "bool",
        "true",
        "false",
        "biara_cpu",
    ];
    if KEYWORDS.contains(&out.as_str()) {
        out.push('_');
    }
    out
}

/// Lex `body` and attribute symbols from the record's authoritative native
/// table (`symbols`: emitted spellings with true identity). `signature`
/// is accepted for backward compatibility and ignored: every table hit
/// attributes regardless of syntactic position (declarations, plain loads,
/// address uses, calls/function values, casts/type uses), because identity
/// comes from the renderer, not from position guessing. Returns span-only
/// tokens (no text duplication): clients slice `body[start..end]`.
pub fn lex(body: &str, signature: &str, symbols: &[LexSymbol]) -> Vec<Token> {
    let _ = signature;
    let bytes = body.as_bytes();
    let mut functions: BTreeMap<&str, u64> = BTreeMap::new();
    let mut globals: BTreeMap<&str, u64> = BTreeMap::new();
    let mut types: BTreeMap<&str, (u32, u64)> = BTreeMap::new();
    // Record scope for type symbols: the body's own function address
    // (first Function entry), so `SymbolRef::Type` encodes
    // `{function, layout}` explicitly.
    let scope = symbols.iter().find_map(|s| match &s.symbol {
        SymbolRef::Function { address } => Some(*address),
        _ => None,
    });
    for symbol in symbols {
        match &symbol.symbol {
            SymbolRef::Function { address } => {
                functions.entry(symbol.text.as_str()).or_insert(*address);
            }
            SymbolRef::Global { address } => {
                globals.entry(symbol.text.as_str()).or_insert(*address);
            }
            SymbolRef::Type { layout, function } => {
                let f = if *function == 0 {
                    scope.unwrap_or(0)
                } else {
                    *function
                };
                types.entry(symbol.text.as_str()).or_insert((*layout, f));
            }
        }
    }
    // Raw lexical pass: byte offsets, kinds, and comment/string masking.
    let mut raw: Vec<Raw> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let start = i;
        let c = bytes[i];
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            raw.push(Raw {
                start,
                end: i,
                kind: "comment",
                text: body[start..i].to_owned(),
            });
            continue;
        }
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            raw.push(Raw {
                start,
                end: i,
                kind: "comment",
                text: body[start..i].to_owned(),
            });
            continue;
        }
        if c == b'"' || c == b'\'' {
            let quote = c;
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                } else if bytes[i] == quote {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            raw.push(Raw {
                start,
                end: i,
                kind: "string",
                text: body[start..i].to_owned(),
            });
            continue;
        }
        if c.is_ascii_whitespace() {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            raw.push(Raw {
                start,
                end: i,
                kind: "whitespace",
                text: body[start..i].to_owned(),
            });
            continue;
        }
        if (c.is_ascii_alphabetic() || c == b'_') && c < 0x80 {
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                && bytes[i] < 0x80
            {
                i += 1;
            }
            let text = &body[start..i];
            let kind = match text {
                "if" | "else" | "for" | "while" | "do" | "switch" | "case" | "default" | "goto"
                | "return" | "break" | "continue" | "sizeof" | "struct" | "union" | "enum"
                | "typedef" | "static" | "extern" | "const" | "volatile" | "void" | "char"
                | "short" | "int" | "long" | "signed" | "unsigned" | "float" | "double"
                | "bool" | "_Bool" => "keyword",
                _ if text.chars().all(|c| c.is_ascii_digit()) => "number",
                _ => "identifier",
            };
            raw.push(Raw {
                start,
                end: i,
                kind,
                text: text.to_owned(),
            });
            continue;
        }
        if c.is_ascii_digit() {
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric()
                    || bytes[i] == b'_'
                    || bytes[i] == b'.'
                    || bytes[i] == b'\'')
            {
                // Stop before identifier continuation after hex prefix end.
                if bytes[i] == b'.' && i + 1 < bytes.len() && bytes[i + 1] == b'.' {
                    break;
                }
                i += 1;
            }
            raw.push(Raw {
                start,
                end: i,
                kind: "number",
                text: body[start..i].to_owned(),
            });
            continue;
        }
        // Punctuation: longest match for multi-byte operators.
        let mut len = 1usize;
        for width in [3usize, 2usize] {
            if i + width <= bytes.len() {
                let slice = &body[i..i + width];
                if matches!(
                    slice,
                    "->" | ">>="
                        | "<<="
                        | "..."
                        | "=="
                        | "!="
                        | "<="
                        | ">="
                        | "&&"
                        | "||"
                        | "<<"
                        | ">>"
                        | "+="
                        | "-="
                        | "*="
                        | "/="
                        | "%="
                        | "&="
                        | "|="
                        | "^="
                        | "++"
                        | "--"
                        | "##"
                ) {
                    len = width;
                    break;
                }
            }
        }
        i += len;
        raw.push(Raw {
            start,
            end: i,
            kind: "punct",
            text: body[start..i].to_owned(),
        });
    }
    // The body's own definition name: first table-spelled `identifier(` in
    // the body. Bodies start with `\n<signature>\n{`, so this is the
    // defined symbol; a non-table spelling never defines one.
    let mut own_name: Option<&str> = None;
    for (index, token) in raw.iter().enumerate() {
        if token.kind == "identifier" {
            let mut next = index + 1;
            while next < raw.len() && raw[next].kind == "whitespace" {
                next += 1;
            }
            if next < raw.len()
                && raw[next].text == "("
                && functions.contains_key(token.text.as_str())
            {
                own_name = Some(token.text.as_str());
                break;
            }
        }
    }
    let mut tokens = Vec::with_capacity(raw.len());
    for (index, token) in raw.iter().enumerate() {
        let mut symbol: Option<SymbolRef> = None;
        if token.kind == "identifier" {
            // Previous significant token: member-field sides (`p->field`,
            // `p.field`) are layout display names, never symbols. The
            // base `p` keeps its own symbol; only the field side drops.
            let mut prev = index;
            while prev > 0
                && (raw[prev - 1].kind == "whitespace" || raw[prev - 1].kind == "comment")
            {
                prev -= 1;
            }
            let prev_text = if prev > 0 {
                raw[prev - 1].text.as_str()
            } else {
                ""
            };
            let is_definition = own_name == Some(token.text.as_str())
                && raw[..index]
                    .iter()
                    .all(|t| t.kind != "identifier" || t.text != token.text);
            if prev_text == "->" || prev_text == "." {
                symbol = None;
            } else if is_definition {
                // The definition site references the record's function.
                if let Some(&address) = functions.get(token.text.as_str()) {
                    symbol = Some(SymbolRef::Function { address });
                }
            } else if let Some(&address) = functions.get(token.text.as_str()) {
                // Authoritative hit: calls, declarations, function
                // values, casts, plain uses all attribute. Locals were
                // suffixed against this table at emission, so a hit is
                // a genuine symbol, never a shadowed local.
                symbol = Some(SymbolRef::Function { address });
            } else if let Some(&address) = globals.get(token.text.as_str()) {
                // Authoritative hit: declarations, plain loads, address
                // uses, dereferences, member bases all attribute. No
                // plain-value shortcut: every address-backed referent
                // renames.
                symbol = Some(SymbolRef::Global { address });
            } else if let Some(&(layout, function)) = types.get(token.text.as_str()) {
                // Authoritative hit: declaration slots, casts, `struct`
                // uses all attribute, with the referencing function
                // scope encoded explicitly.
                symbol = Some(SymbolRef::Type { layout, function });
            }
        }
        tokens.push(Token {
            start: token.start as u64,
            end: token.end as u64,
            kind: token.kind.to_owned(),
            symbol,
        });
    }
    tokens
}

/// One known symbol spelling for [`lex`].
#[derive(Clone, Debug)]
pub struct LexSymbol {
    /// Sanitized display text as it appears in the body.
    pub text: String,
    /// Stable identity the text references.
    pub symbol: SymbolRef,
}

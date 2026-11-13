//! UI-independent analysis session: opening a binary, background recovery, indexes and
//! on-demand views of one function. Nothing here knows about Rune, so it runs under
//! `cargo test`.

pub mod decomp;
pub mod demangle;
pub mod disasm;
pub mod flow;
pub mod graph;
pub mod listing;
pub mod names;
pub mod program;
pub mod recovery;

pub use decomp::{Decompiled, Decompiler};
pub use demangle::Demangled;
pub use disasm::{Arch, Flow, Insn, Span, Tok};
pub use flow::{FlowError, FlowGraph, FlowNode};
pub use listing::{Head, HeadKind, Listing};
pub use names::{NameKind, Names};
pub use program::{
    FunctionInfo, FunctionKind, ImportEntry, Index, Program, StringEntry, Xref, XrefKind,
};
pub use recovery::{Event, Notify, OpenOptions, Stage};

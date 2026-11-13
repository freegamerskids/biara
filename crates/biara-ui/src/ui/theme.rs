//! Colours and type for the workbench.
//!
//! One dark theme, designed for long sessions: a cool charcoal ramp for surfaces, a single
//! indigo accent, and a code palette whose hues carry meaning (control flow warm, data cool,
//! names green) so structure reads before the text does.

use std::sync::LazyLock;

use rune::{Color, TextStyle, color::hex};
use rune_kit::{Kit, PaletteSeed};

use crate::backend::{Flow, Tok};

/// Every colour the views use.
pub struct Colors {
    // Surfaces, darkest to lightest.
    pub window: Color,
    pub panel: Color,
    pub raised: Color,
    pub hover: Color,
    pub selected: Color,
    pub line: Color,
    pub line_strong: Color,
    // Text.
    pub text: Color,
    pub muted: Color,
    pub faint: Color,
    pub accent: Color,
    pub accent_soft: Color,
    pub good: Color,
    pub warn: Color,
    pub bad: Color,
    // Disassembly.
    pub addr: Color,
    pub bytes: Color,
    pub mnemonic: Color,
    pub mnemonic_call: Color,
    pub mnemonic_jump: Color,
    pub mnemonic_ret: Color,
    pub register: Color,
    pub number: Color,
    pub target: Color,
    pub punct: Color,
    pub comment: Color,
    pub label: Color,
    // Pseudocode.
    pub keyword: Color,
    pub ty: Color,
    pub function: Color,
    pub string: Color,
    pub global: Color,
    // Graph edges.
    pub edge_taken: Color,
    pub edge_not_taken: Color,
    pub edge_flow: Color,
    pub edge_table: Color,
    pub node_bg: Color,
    pub node_border: Color,
}

fn c(s: &str) -> Color {
    hex(s).unwrap_or_else(|| panic!("bad colour {s}"))
}

static COLORS: LazyLock<Colors> = LazyLock::new(|| Colors {
    window: c("#0c0e13"),
    panel: c("#11141a"),
    raised: c("#171b23"),
    hover: c("#1e232d"),
    selected: c("#252c3d"),
    line: c("#1f242e"),
    line_strong: c("#2d3442"),
    text: c("#d9dde6"),
    muted: c("#8d95a6"),
    faint: c("#596175"),
    accent: c("#7c8cff"),
    accent_soft: c("#7c8cff").alpha(0.16),
    good: c("#5fd0a0"),
    warn: c("#e8b05c"),
    bad: c("#ef6b7b"),
    addr: c("#4f586b"),
    bytes: c("#3f475a"),
    mnemonic: c("#b9a4f5"),
    mnemonic_call: c("#62d0c0"),
    mnemonic_jump: c("#f0a768"),
    mnemonic_ret: c("#ef6b7b"),
    register: c("#7cc2ff"),
    number: c("#e6c27a"),
    target: c("#79dba0"),
    punct: c("#6a7388"),
    comment: c("#5d6678"),
    label: c("#e8b05c"),
    keyword: c("#c59bf5"),
    ty: c("#5ccfe6"),
    function: c("#86a8ff"),
    string: c("#a6e08a"),
    global: c("#f0c674"),
    edge_taken: c("#5fd0a0"),
    edge_not_taken: c("#ef6b7b"),
    edge_flow: c("#7c8cff"),
    edge_table: c("#e8b05c"),
    node_bg: c("#12151c"),
    node_border: c("#2a3140"),
});

/// The palette, built once.
pub fn colors() -> &'static Colors {
    &COLORS
}

static KIT: LazyLock<Kit> = LazyLock::new(|| {
    let p = colors();
    let mut k = Kit::from_palette(PaletteSeed {
        bg: p.panel,
        fg: p.text,
        accent: p.accent,
    });
    k.radius.sm = 4.0;
    k.radius.md = 6.0;
    k
});

/// The rune-kit theme the shared components (inputs, tabs, menus) draw with.
pub fn kit() -> &'static Kit {
    &KIT
}

/// UI text.
pub const UI: TextStyle = TextStyle::new(12.5, 400.0);
pub const UI_MEDIUM: TextStyle = TextStyle::new(12.5, 500.0);
pub const SMALL: TextStyle = TextStyle::new(11.0, 400.0);
pub const SMALL_MEDIUM: TextStyle = TextStyle::new(11.0, 500.0);
pub const TITLE: TextStyle = TextStyle::new(13.0, 600.0);
/// Code: the mono face at a size that fits dense listings.
pub const CODE: TextStyle = TextStyle::new(12.0, 400.0).mono();
pub const CODE_SIZE: f32 = 12.0;
/// One code row's height.
pub const ROW_H: f32 = 19.0;
/// Advance of one mono character at [`CODE_SIZE`] (IBM Plex Mono is 0.6 em wide).
pub const CHAR_W: f32 = CODE_SIZE * 0.6;

/// The colour of an instruction token.
pub fn tok_color(tok: Tok, flow: Flow) -> Color {
    let p = colors();
    match tok {
        Tok::Mnemonic => match flow {
            Flow::Call => p.mnemonic_call,
            Flow::Jump | Flow::Branch => p.mnemonic_jump,
            Flow::Return | Flow::Stop => p.mnemonic_ret,
            Flow::Next => p.mnemonic,
        },
        Tok::Register => p.register,
        Tok::Number => p.number,
        Tok::Target => p.target,
        Tok::Punct => p.punct,
        Tok::Text => p.text,
        Tok::Comment => p.comment,
    }
}

//! Instruction decoding for the listing and graph views.
//!
//! The analysis engine works on TCG, which has no instruction text, so the UI decodes the
//! guest bytes itself: `iced-x86` for x86-64 and `yaxpeax-arm` for AArch64. Both produce the
//! same shape: a mnemonic and operands as coloured [`Span`]s, the control-flow effect
//! ([`Flow`]) and the direct branch target, if any. Decoding is a few hundred nanoseconds per
//! instruction, so views decode the rows they draw and cache nothing.

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, FormatterOutput, FormatterTextKind,
    Instruction as X86, IntelFormatter,
};
use yaxpeax_arch::{Decoder as _, U8Reader};
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction as A64, Opcode, Operand};

/// Guest architectures the disassembler understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// The architecture named by `Image::arch`, if the UI can disassemble it.
    pub fn from_name(name: &str) -> Option<Arch> {
        match name {
            "x86_64" => Some(Arch::X86_64),
            "aarch64" => Some(Arch::Aarch64),
            _ => None,
        }
    }

    /// Fixed instruction width in bytes, or `None` when instructions vary in length.
    pub fn fixed_width(self) -> Option<u8> {
        match self {
            Arch::X86_64 => None,
            Arch::Aarch64 => Some(4),
        }
    }

    /// The register that holds a call's return address, if the architecture has one.
    pub fn link_register(self) -> Option<&'static str> {
        match self {
            Arch::X86_64 => None,
            Arch::Aarch64 => Some("lr"),
        }
    }
}

/// What a run of instruction text is, for colouring and clicking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tok {
    Mnemonic,
    Register,
    Number,
    /// A direct code or data address; [`Span::target`] holds it.
    Target,
    Punct,
    Text,
    Comment,
}

/// One coloured run of text in an instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub text: String,
    pub tok: Tok,
    /// The address this span names, for [`Tok::Target`].
    pub target: Option<u64>,
}

impl Span {
    fn new(text: impl Into<String>, tok: Tok) -> Span {
        Span {
            text: text.into(),
            tok,
            target: None,
        }
    }
}

/// How an instruction continues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Falls through to the next instruction.
    Next,
    /// Unconditional jump; does not fall through.
    Jump,
    /// Conditional branch; may fall through.
    Branch,
    Call,
    Return,
    /// Traps or halts: nothing follows.
    Stop,
}

impl Flow {
    /// Whether execution can continue at the next instruction.
    pub fn falls_through(self) -> bool {
        matches!(self, Flow::Next | Flow::Branch | Flow::Call)
    }
}

/// One decoded instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insn {
    pub addr: u64,
    pub len: u8,
    pub flow: Flow,
    /// Direct branch or call destination.
    pub target: Option<u64>,
    /// An address the instruction reads or computes (RIP-relative operand, `adr`/`adrp`
    /// result): where a data reference points, for annotations.
    pub data_ref: Option<u64>,
    pub spans: Vec<Span>,
}

impl Insn {
    /// The instruction as plain text.
    pub fn text(&self) -> String {
        self.spans.iter().map(|s| s.text.as_str()).collect()
    }

    /// The mnemonic, lowercased.
    pub fn mnemonic(&self) -> &str {
        self.spans
            .iter()
            .find(|s| s.tok == Tok::Mnemonic)
            .map_or("", |s| s.text.as_str())
    }
}

/// Decode the instruction at the start of `bytes`, which sits at guest address `addr`.
///
/// Undecodable bytes come back as a one-unit `db`/`.word` pseudo-instruction, so a linear
/// sweep always advances.
pub fn decode(arch: Arch, addr: u64, bytes: &[u8]) -> Insn {
    match arch {
        Arch::X86_64 => decode_x86(addr, bytes),
        Arch::Aarch64 => decode_a64(addr, bytes),
    }
}

/// Decode consecutive instructions in `bytes` (at `addr`).
pub fn sweep(arch: Arch, addr: u64, bytes: &[u8]) -> Vec<Insn> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() {
        let insn = decode(arch, addr + at as u64, &bytes[at..]);
        at += insn.len as usize;
        out.push(insn);
    }
    out
}

fn data_byte(addr: u64, byte: u8) -> Insn {
    Insn {
        addr,
        len: 1,
        flow: Flow::Next,
        target: None,
        data_ref: None,
        spans: vec![
            Span::new("db", Tok::Mnemonic),
            Span::new(" ", Tok::Text),
            Span::new(format!("0x{byte:02x}"), Tok::Number),
        ],
    }
}

// x86-64 ---------------------------------------------------------------------------------

/// Collects formatter output as spans.
struct X86Spans {
    spans: Vec<Span>,
}

impl FormatterOutput for X86Spans {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        let tok = match kind {
            FormatterTextKind::Mnemonic
            | FormatterTextKind::Directive
            | FormatterTextKind::Prefix => Tok::Mnemonic,
            FormatterTextKind::Register => Tok::Register,
            FormatterTextKind::Number => Tok::Number,
            FormatterTextKind::LabelAddress | FormatterTextKind::FunctionAddress => Tok::Target,
            FormatterTextKind::Punctuation | FormatterTextKind::Operator => Tok::Punct,
            _ => Tok::Text,
        };
        let target = (tok == Tok::Target).then(|| parse_hex(text)).flatten();
        // Merge neighbours of the same kind so a row has few text runs.
        if target.is_none()
            && let Some(last) = self.spans.last_mut()
            && last.tok == tok
            && last.target.is_none()
        {
            last.text.push_str(text);
            return;
        }
        self.spans.push(Span {
            text: text.to_owned(),
            tok,
            target,
        });
    }
}

fn parse_hex(text: &str) -> Option<u64> {
    let t = text.trim_start_matches("0x").trim_end_matches('h');
    u64::from_str_radix(t, 16).ok()
}

fn x86_formatter() -> IntelFormatter {
    let mut f = IntelFormatter::new();
    let o = f.options_mut();
    o.set_hex_prefix("0x");
    o.set_hex_suffix("");
    o.set_uppercase_hex(false);
    o.set_uppercase_mnemonics(false);
    o.set_uppercase_registers(false);
    o.set_uppercase_keywords(false);
    o.set_uppercase_prefixes(false);
    o.set_space_after_operand_separator(true);
    // `false` prints the absolute address (`[0x403000]`) instead of `[rip+0x2cea]`.
    o.set_rip_relative_addresses(false);
    o.set_small_hex_numbers_in_decimal(true);
    o.set_branch_leading_zeros(false);
    o.set_leading_zeros(false);
    o.set_first_operand_char_index(8);
    f
}

thread_local! {
    static X86_FORMATTER: std::cell::RefCell<IntelFormatter> = std::cell::RefCell::new(x86_formatter());
}

fn decode_x86(addr: u64, bytes: &[u8]) -> Insn {
    let take = bytes.len().min(15);
    let mut decoder = Decoder::with_ip(64, &bytes[..take], addr, DecoderOptions::NONE);
    let ins: X86 = decoder.decode();
    if ins.is_invalid() {
        return data_byte(addr, bytes.first().copied().unwrap_or(0));
    }
    let mut out = X86Spans {
        spans: Vec::with_capacity(6),
    };
    X86_FORMATTER.with(|f| f.borrow_mut().format(&ins, &mut out));
    // `first_operand_char_index` pads the mnemonic with spaces; keep the padding as plain text
    // so columns line up, and trim any trailing blanks.
    while out
        .spans
        .last()
        .is_some_and(|s| s.tok == Tok::Text && s.text.trim().is_empty())
    {
        out.spans.pop();
    }
    use iced_x86::{Mnemonic, OpKind};
    let flow = match ins.flow_control() {
        // A system call comes back to the next instruction; it is not a branch.
        FlowControl::Call
            if matches!(
                ins.mnemonic(),
                Mnemonic::Syscall | Mnemonic::Sysenter | Mnemonic::Vmcall
            ) =>
        {
            Flow::Next
        }
        FlowControl::Next | FlowControl::XbeginXabortXend => Flow::Next,
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => Flow::Jump,
        FlowControl::ConditionalBranch => Flow::Branch,
        FlowControl::Call | FlowControl::IndirectCall => Flow::Call,
        FlowControl::Return => Flow::Return,
        FlowControl::Interrupt | FlowControl::Exception => {
            // `int3` and friends continue; `ud2`/`hlt` do not.
            if matches!(
                ins.mnemonic(),
                Mnemonic::Ud0 | Mnemonic::Ud1 | Mnemonic::Ud2 | Mnemonic::Hlt
            ) {
                Flow::Stop
            } else {
                Flow::Next
            }
        }
    };
    // Only an instruction whose first operand is a near branch has a direct target.
    let target = matches!(flow, Flow::Jump | Flow::Branch | Flow::Call)
        .then(|| {
            matches!(
                ins.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
            .then(|| ins.near_branch_target())
        })
        .flatten();
    let data_ref = ins
        .is_ip_rel_memory_operand()
        .then(|| ins.ip_rel_memory_address());
    // The formatter prints the resolved address as a plain number; make it a target so the
    // listing can name it and jump to it.
    if let Some(a) = data_ref {
        for span in out.spans.iter_mut().filter(|s| s.tok == Tok::Number) {
            if parse_hex(&span.text) == Some(a) {
                span.tok = Tok::Target;
                span.target = Some(a);
            }
        }
    }
    Insn {
        addr,
        len: ins.len() as u8,
        flow,
        target,
        data_ref,
        spans: out.spans,
    }
}

// AArch64 --------------------------------------------------------------------------------

fn decode_a64(addr: u64, bytes: &[u8]) -> Insn {
    if bytes.len() < 4 {
        return data_byte(addr, bytes.first().copied().unwrap_or(0));
    }
    let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let decoder = InstDecoder::default();
    let mut reader = U8Reader::new(&bytes[..4]);
    let Ok(ins): Result<A64, _> = decoder.decode(&mut reader) else {
        return Insn {
            addr,
            len: 4,
            flow: Flow::Next,
            target: None,
            data_ref: None,
            spans: vec![
                Span::new(".word", Tok::Mnemonic),
                Span::new(" ", Tok::Text),
                Span::new(format!("0x{word:08x}"), Tok::Number),
            ],
        };
    };
    // The PC-relative operand, as an absolute address.
    let mut pc_target = None;
    for op in &ins.operands {
        if let Operand::PCOffset(off) = op {
            let base = if ins.opcode == Opcode::ADRP {
                addr & !0xfff
            } else {
                addr
            };
            pc_target = Some((base as i64).wrapping_add(*off) as u64);
        }
    }
    let flow = match ins.opcode {
        Opcode::B => Flow::Jump,
        Opcode::Bcc(_) | Opcode::CBZ | Opcode::CBNZ | Opcode::TBZ | Opcode::TBNZ => Flow::Branch,
        Opcode::BL | Opcode::BLR => Flow::Call,
        Opcode::BR => Flow::Jump,
        Opcode::RET | Opcode::ERET => Flow::Return,
        Opcode::BRK | Opcode::HLT | Opcode::UDF => Flow::Stop,
        _ => Flow::Next,
    };
    let mut text = ins.to_string();
    // Display prints a PC-relative operand as `$+0x..`; the listing wants the address.
    if let Some(t) = pc_target {
        for op in &ins.operands {
            if let Operand::PCOffset(_) = op {
                text = text.replace(&op.to_string(), &format!("0x{t:x}"));
            }
        }
    }
    let direct = matches!(
        ins.opcode,
        Opcode::B
            | Opcode::BL
            | Opcode::Bcc(_)
            | Opcode::CBZ
            | Opcode::CBNZ
            | Opcode::TBZ
            | Opcode::TBNZ
    );
    let spans = lex_a64(&text, pc_target);
    let (target, data_ref) = match (direct, pc_target) {
        (true, t) => (t, None),
        (false, t) => (None, t),
    };
    Insn {
        addr,
        len: 4,
        flow,
        target,
        data_ref,
        spans,
    }
}

/// Split AArch64 assembly into coloured spans.
fn lex_a64(text: &str, target: Option<u64>) -> Vec<Span> {
    let (mnemonic, rest) = match text.split_once(' ') {
        Some((m, r)) => (m, Some(r)),
        None => (text, None),
    };
    let mut spans = vec![Span::new(mnemonic, Tok::Mnemonic)];
    let Some(rest) = rest else { return spans };
    // Pad the mnemonic like the x86 formatter so operands line up.
    spans.push(Span::new(
        " ".repeat(8usize.saturating_sub(mnemonic.len()).max(1)),
        Tok::Text,
    ));
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_alphanumeric()
            || c == '_'
            || c == '.'
            || c == '#'
            || c == '-' && bytes.get(i + 1).is_some_and(|n| n.is_ascii_digit())
        {
            let start = i;
            i += 1;
            while i < bytes.len()
                && ((bytes[i] as char).is_ascii_alphanumeric()
                    || bytes[i] == b'_'
                    || bytes[i] == b'.')
            {
                i += 1;
            }
            let word = &rest[start..i];
            spans.push(classify_a64_word(word, target));
        } else {
            let start = i;
            i += 1;
            while i < bytes.len()
                && !((bytes[i] as char).is_ascii_alphanumeric()
                    || bytes[i] == b'#'
                    || bytes[i] == b'_')
            {
                i += 1;
            }
            let chunk = &rest[start..i];
            spans.push(Span::new(
                chunk,
                if chunk.trim().is_empty() {
                    Tok::Text
                } else {
                    Tok::Punct
                },
            ));
        }
    }
    spans
}

fn classify_a64_word(word: &str, target: Option<u64>) -> Span {
    let imm = word.trim_start_matches('#');
    if let Some(hex) = imm.strip_prefix("0x")
        && let Ok(v) = u64::from_str_radix(hex, 16)
    {
        if target == Some(v) {
            return Span {
                text: word.to_owned(),
                tok: Tok::Target,
                target: Some(v),
            };
        }
        return Span::new(word, Tok::Number);
    }
    if imm
        .strip_prefix("-0x")
        .is_some_and(|h| u64::from_str_radix(h, 16).is_ok())
        || imm.parse::<i64>().is_ok()
    {
        return Span::new(word, Tok::Number);
    }
    if is_a64_register(word) {
        return Span::new(word, Tok::Register);
    }
    Span::new(word, Tok::Text)
}

fn is_a64_register(word: &str) -> bool {
    let w = word.split('.').next().unwrap_or(word);
    if matches!(w, "sp" | "wsp" | "xzr" | "wzr" | "lr" | "fp" | "nzcv") {
        return true;
    }
    let mut chars = w.chars();
    matches!(
        chars.next(),
        Some('x' | 'w' | 'v' | 'q' | 'd' | 's' | 'b' | 'h' | 'z' | 'p')
    ) && {
        let digits = &w[1..];
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(i: &Insn) -> String {
        i.text()
    }

    #[test]
    fn x86_decodes_calls_with_direct_targets() {
        // call +0x10 at 0x1000 -> target 0x1015
        let i = decode(Arch::X86_64, 0x1000, &[0xe8, 0x10, 0x00, 0x00, 0x00, 0x90]);
        assert_eq!(i.len, 5);
        assert_eq!(i.flow, Flow::Call);
        assert_eq!(i.target, Some(0x1015));
        assert!(text(&i).starts_with("call"), "{}", text(&i));
        let t = i
            .spans
            .iter()
            .find(|s| s.tok == Tok::Target)
            .expect("target span");
        assert_eq!(t.target, Some(0x1015));
    }

    #[test]
    fn x86_conditional_branch_falls_through_and_ret_does_not() {
        let jne = decode(Arch::X86_64, 0x2000, &[0x75, 0x04]);
        assert_eq!((jne.flow, jne.target), (Flow::Branch, Some(0x2006)));
        assert!(jne.flow.falls_through());
        let ret = decode(Arch::X86_64, 0x2002, &[0xc3]);
        assert_eq!((ret.flow, ret.target), (Flow::Return, None));
        assert!(!ret.flow.falls_through());
        let indirect = decode(Arch::X86_64, 0x2003, &[0xff, 0xe0]); // jmp rax
        assert_eq!((indirect.flow, indirect.target), (Flow::Jump, None));
    }

    #[test]
    fn x86_syscall_continues_and_has_no_target() {
        let i = decode(Arch::X86_64, 0x1816, &[0x0f, 0x05]);
        assert_eq!(
            (i.len, i.flow, i.target),
            (2, Flow::Next, None),
            "{}",
            i.text()
        );
        // An indirect call has no direct target either.
        let call = decode(Arch::X86_64, 0x1000, &[0xff, 0xd0]); // call rax
        assert_eq!((call.flow, call.target), (Flow::Call, None));
    }

    #[test]
    fn x86_rip_relative_operand_reports_the_data_address() {
        // lea rdi, [rip+0x2000] at 0x1000 (7 bytes) -> 0x3007
        let i = decode(
            Arch::X86_64,
            0x1000,
            &[0x48, 0x8d, 0x3d, 0x00, 0x20, 0x00, 0x00],
        );
        assert_eq!(i.len, 7);
        assert_eq!(i.data_ref, Some(0x3007));
        assert_eq!(i.target, None);
        // The resolved address is a clickable target, not `rip+0x2000`.
        let t = i
            .spans
            .iter()
            .find(|s| s.tok == Tok::Target)
            .expect("address span");
        assert_eq!(t.target, Some(0x3007), "{}", i.text());
        assert!(!i.text().contains("rip"), "{}", i.text());
    }

    #[test]
    fn x86_invalid_bytes_become_data_and_advance() {
        let swept = sweep(Arch::X86_64, 0x10, &[0x06, 0x90]);
        assert!(
            swept.len() >= 2,
            "an undecodable byte must not stall the sweep: {swept:?}"
        );
        assert_eq!(swept[0].mnemonic(), "db");
        assert_eq!(swept.last().unwrap().mnemonic(), "nop");
    }

    #[test]
    fn a64_branches_resolve_to_absolute_targets() {
        // bl +0x20 at 0x4000 (imm26 = 8)
        let bl = decode(Arch::Aarch64, 0x4000, &0x9400_0008u32.to_le_bytes());
        assert_eq!((bl.len, bl.flow, bl.target), (4, Flow::Call, Some(0x4020)));
        assert!(text(&bl).contains("0x4020"), "{}", text(&bl));
        // b.ne -8 at 0x4008: imm19 = -2
        let bne = decode(Arch::Aarch64, 0x4008, &0x54ff_ffc1u32.to_le_bytes());
        assert_eq!(
            (bne.flow, bne.target),
            (Flow::Branch, Some(0x4000)),
            "{}",
            text(&bne)
        );
        // ret
        let ret = decode(Arch::Aarch64, 0x400c, &0xd65f_03c0u32.to_le_bytes());
        assert_eq!((ret.flow, ret.target), (Flow::Return, None));
    }

    #[test]
    fn a64_adrp_is_page_relative_and_is_a_data_reference() {
        // adrp x0, +0x1000 pages at 0x4ff0 -> page(0x4ff0)=0x4000 + 0x1000
        let adrp = decode(Arch::Aarch64, 0x4ff0, &0xb000_0000u32.to_le_bytes());
        assert_eq!(adrp.data_ref, Some(0x5000), "{}", text(&adrp));
        assert_eq!(adrp.target, None);
        assert_eq!(adrp.flow, Flow::Next);
    }

    #[test]
    fn a64_registers_and_numbers_are_coloured() {
        // mov x1, #5
        let mov = decode(Arch::Aarch64, 0, &0xd280_00a1u32.to_le_bytes());
        let kinds: Vec<_> = mov
            .spans
            .iter()
            .filter(|s| s.tok != Tok::Text && s.tok != Tok::Punct)
            .map(|s| (s.text.as_str(), s.tok))
            .collect();
        assert_eq!(
            kinds,
            [
                ("mov", Tok::Mnemonic),
                ("x1", Tok::Register),
                ("#0x5", Tok::Number)
            ],
            "{}",
            text(&mov)
        );
    }

    #[test]
    fn a64_garbage_is_a_word_and_advances_by_four() {
        let i = decode(Arch::Aarch64, 0, &[0, 0, 0, 0]);
        assert_eq!(i.len, 4);
        let short = decode(Arch::Aarch64, 0, &[1, 2]);
        assert_eq!(short.len, 1);
    }
}

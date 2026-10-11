//! Caller arithmetic and entry-safe shared frames; candidates are not proofs
//! of every runtime caller. Actual native execution supplies fixture ground truth.
#![cfg(target_os = "linux")]
mod common;
use biara_cfg::ExitKind;
use biara_loader::Image;
use biara_tcg::Libtcg;
use common::{linker, recover_program, tmp};
use std::{collections::BTreeSet, fs, process::Command};

#[test]
fn expressions_and_shared_frames() {
    for arch in ["x86_64", "aarch64"] {
        for opt in [0, 2] {
            let dir = tmp().join(format!("indirect-context-{arch}-O{opt}"));
            fs::create_dir_all(&dir).unwrap();
            let source = dir.join("calls.c");
            let start = dir.join("start.c");
            let assembly = dir.join("frame.S");
            let binary = dir.join("program");
            fs::write(
                &source,
                r#"
typedef unsigned long Word;
typedef long (*Callback)(long);
__attribute__((noinline,used)) long chosen(long x) { return x+7; }
__attribute__((noinline,used)) long other(long x) { return x+9; }
__attribute__((noinline,used)) Word encode(Word p,Word key,unsigned n) {
    return __builtin_rotateleft64(p^key,n);
}
__attribute__((noinline,used)) long expression(Word encoded,Word key,unsigned n) {
    Callback cb=(Callback)(__builtin_rotateright64(encoded,n)^key);
    return cb(5)+1;
}
extern long frame(Word *), hidden_entry(Word *), poisoned_frame(Word *);
__attribute__((noinline,used)) void change(Word *p) { p[0]=(Word)other^0x1234; }
__attribute__((noinline,used)) long run_frame(void) {
    Word slots[2]={(Word)chosen^0x1234,0xdeadbeef00001234UL}; return frame(slots);
}
__attribute__((noinline,used)) long run_hidden(void) {
    Word slots[2]={(Word)chosen^0x1234,0xdeadbeef00001234UL}; return hidden_entry(slots);
}
__attribute__((noinline,used)) long run_poisoned(void) {
    Word slots[2]={(Word)chosen^0x1234,0xdeadbeef00001234UL}; return poisoned_frame(slots);
}
"#,
            )
            .unwrap();
            fs::write(
                &start,
                r#"
typedef unsigned long Word;
extern long chosen(long),other(long),expression(Word,Word,unsigned);
extern Word encode(Word,Word,unsigned);
extern long run_frame(void),run_hidden(void),run_poisoned(void);
__attribute__((noreturn,used)) void _start(void) {
    long result=expression(encode((Word)chosen,0x9abcdef012345678UL,11),0x9abcdef012345678UL,11);
    result+=run_frame()+run_hidden()+run_poisoned();
#if defined(__x86_64__)
    __asm__ volatile("syscall"::"a"(60L),"D"(result==51 ? 0L : 1L):"rcx","r11","memory");
#else
    register long number __asm__("x8")=93;
    register long status __asm__("x0")=result==51 ? 0 : 1;
    __asm__ volatile("svc #0"::"r"(number),"r"(status):"memory");
#endif
    __builtin_unreachable();
}
"#,
            )
            .unwrap();
            let asm = if arch == "x86_64" {
                r#"
.text
.globl frame
.type frame,@function
frame:
 movq (%rdi),%rax
 movzwl 8(%rdi),%ecx
 xorq %rcx,%rax
 movl $5,%edi
 subq $8,%rsp
 call *%rax
 addq $8,%rsp
 ret
.size frame,.-frame
.globl hidden_entry
.type hidden_entry,@function
hidden_entry:
 movq %rbp,%r10
 movq %rdi,%rbp
 jmp hidden_frame
.size hidden_entry,.-hidden_entry
.globl hidden_frame
.type hidden_frame,@function
hidden_frame:
 movq (%rbp),%rax
 movzwl 8(%rbp),%ecx
 xorq %rcx,%rax
 movq %r10,%rbp
 movl $5,%edi
 subq $8,%rsp
 call *%rax
 addq $8,%rsp
 ret
.size hidden_frame,.-hidden_frame
.globl poisoned_frame
.type poisoned_frame,@function
poisoned_frame:
 pushq %rdi
 call change
 popq %rdi
 movq (%rdi),%rax
 movzwl 8(%rdi),%ecx
 xorq %rcx,%rax
 movl $5,%edi
 subq $8,%rsp
 call *%rax
 addq $8,%rsp
 ret
.size poisoned_frame,.-poisoned_frame
.section .note.GNU-stack,"",@progbits
"#
            } else {
                r#"
.text
.globl frame
.type frame,%function
frame:
 ldr x16,[x0]
 ldrh w17,[x0,#8]
 eor x16,x16,x17
 mov x0,#5
 str x30,[sp,#-16]!
 blr x16
 ldr x30,[sp],#16
 ret
.size frame,.-frame
.globl hidden_entry
.type hidden_entry,%function
hidden_entry:
 mov x9,x19
 mov x19,x0
 b hidden_frame
.size hidden_entry,.-hidden_entry
.globl hidden_frame
.type hidden_frame,%function
hidden_frame:
 ldr x16,[x19]
 ldrh w17,[x19,#8]
 eor x16,x16,x17
 mov x19,x9
 mov x0,#5
 str x30,[sp,#-16]!
 blr x16
 ldr x30,[sp],#16
 ret
.size hidden_frame,.-hidden_frame
.globl poisoned_frame
.type poisoned_frame,%function
poisoned_frame:
 stp x0,x30,[sp,#-16]!
 bl change
 ldp x0,x30,[sp],#16
 ldr x16,[x0]
 ldrh w17,[x0,#8]
 eor x16,x16,x17
 mov x0,#5
 str x30,[sp,#-16]!
 blr x16
 ldr x30,[sp],#16
 ret
.size poisoned_frame,.-poisoned_frame
.section .note.GNU-stack,"",%progbits
"#
            };
            fs::write(&assembly, asm).unwrap();
            let output = Command::new(env!("BIARA_CLANG"))
                .args([
                    format!("--target={arch}-linux-gnu"),
                    format!("-O{opt}"),
                    format!("--ld-path={}", linker().display()),
                ])
                .args([
                    "-ffreestanding",
                    "-nostdlib",
                    "-fno-pie",
                    "-static",
                    "-funwind-tables",
                ])
                .arg(&source)
                .arg(&start)
                .arg(&assembly)
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            if arch == "x86_64" {
                assert!(
                    Command::new(&binary).status().unwrap().success(),
                    "native frame/expression ground truth"
                );
            }
            let image = Image::load(&binary).unwrap();
            let address = |name: &str| image.symbol(name).unwrap().addr;
            let lib = Libtcg::load(&Libtcg::find(arch).unwrap(), None).unwrap();
            let cfg = recover_program(&mut lib.lock(), &image);
            for name in ["expression", "frame", "hidden_frame", "poisoned_frame"] {
                let site = *cfg.functions[&address(name)]
                    .blocks
                    .iter()
                    .find(|&&pc| {
                        cfg.blocks[&pc]
                            .exits
                            .iter()
                            .any(|e| matches!(e.kind, ExitKind::IndirectCall { .. }))
                    })
                    .unwrap_or_else(|| panic!("{arch} O{opt} {name}: indirect call missing"));
                let targets = cfg.indirect_calls.get(&site);
                let values = targets.map(|t| t.targets.clone()).unwrap_or_default();
                assert!(
                    !targets.is_some_and(|t| t.complete),
                    "{arch} O{opt} {name}: runtime callers remain unknown"
                );
                if name == "poisoned_frame" {
                    assert!(
                        values.is_empty(),
                        "{arch} O{opt}: intervening guest write/call must stop frame forwarding: {values:x?}"
                    );
                } else {
                    assert_eq!(
                        values,
                        BTreeSet::from([address("chosen")]),
                        "{arch} O{opt} {name}"
                    );
                    assert!(
                        cfg.functions[&address(name)]
                            .calls
                            .contains(&address("chosen")),
                        "recovered target must enter the call graph"
                    );
                }
            }
            assert!(
                !cfg.recovery.resolution_limit_reached,
                "fixed-point recovery must stabilize"
            );
        }
    }
}

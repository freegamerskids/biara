//! Isolated binary-consumer tests for allocation aliases and declared bounds.
#![cfg(target_os = "linux")]

#[path = "common/mod.rs"]
mod common;

use std::{collections::BTreeSet, process::Command};

use biara_lift::{
    Arg, CallSites, SizeRange, analysis_machine,
    audit::{
        Input, Issue, audit,
        object::{
            ObjectBound, ObjectEvidence, ObjectOrigin, ObjectQuery, UnknownExtent, pointer_facts,
        },
    },
};
use biara_loader::Image;
use biara_tcg::Libtcg;

fn declared(image: &Image, query: ObjectQuery) -> Option<ObjectBound> {
    match query {
        ObjectQuery::Global { address } => {
            // Reject ambiguous overlapping symbol extents rather than choose
            // whichever name happened to sort first.
            let mut symbols = image.symbols.iter().filter(|s| {
                !s.is_function && s.size != 0 && address >= s.addr && address - s.addr < s.size
            });
            let symbol = symbols.next()?;
            if symbols.any(|s| s.addr != symbol.addr || s.size != symbol.size) {
                return None;
            }
            Some(ObjectBound {
                origin: ObjectOrigin::Global {
                    name: symbol.name.clone(),
                    address: symbol.addr,
                },
                offset: i64::try_from(address - symbol.addr).ok()?,
                size: SizeRange {
                    lo: symbol.size,
                    hi: symbol.size,
                },
                evidence: ObjectEvidence::DataSymbol {
                    name: symbol.name.clone(),
                    address: symbol.addr,
                },
            })
        }
        ObjectQuery::Stack {
            function,
            pc,
            entry_offset,
        } => {
            let object = image.stack_object(function, pc, entry_offset)?;
            Some(ObjectBound {
                origin: ObjectOrigin::Stack {
                    function,
                    name: object.name.clone(),
                    entry_offset: object.offset,
                },
                offset: entry_offset.checked_sub(object.offset)?,
                size: SizeRange {
                    lo: object.size,
                    hi: object.size,
                },
                evidence: ObjectEvidence::Dwarf { function, pc },
            })
        }
    }
}

#[test]
fn binary_object_bounds_and_return_aliases() {
    let dir = common::tmp().join("object-audit-isolated");
    std::fs::create_dir_all(&dir).unwrap();
    let debug = dir.join("objects-debug");
    let out = Command::new(env!("BIARA_CLANG"))
        .args([
            "-O0",
            "-g",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-pie",
            "-no-pie",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/audit/objects.c"
        ))
        .arg("-o")
        .arg(&debug)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stripped = dir.join("objects-no-debug");
    std::fs::copy(&debug, &stripped).unwrap();
    let out = Command::new(common::llvm_tool("llvm-strip"))
        .arg("--strip-debug")
        .arg(&stripped)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let machine = analysis_machine().unwrap();
    let lib = Libtcg::load(&Libtcg::find("x86_64").expect("libtcg"), None).unwrap();
    let mut lib = lib.lock();
    for (path, has_debug) in [(&debug, true), (&stripped, false)] {
        let image = Image::load(path).unwrap();
        let cfg = common::recover_program(&mut lib, &image);
        let mut calls = CallSites::new(&machine, lib.info(), &cfg).unwrap();
        let provider = |query| declared(&image, query);
        let findings = audit(
            &mut calls,
            &image.indirect_entries(),
            image.main,
            &|address, bytes| image.read_const(address, bytes),
            &provider,
        )
        .unwrap();
        let name = |address| image.function_at(address).unwrap().name.clone();
        let overflow: BTreeSet<_> = findings
            .iter()
            .filter(|finding| matches!(finding.issue, Issue::ObjectOverflow { .. }))
            .map(|finding| name(finding.site.caller))
            .collect();
        let mut expected: BTreeSet<String> = [
            "bad_heap",
            "bad_interior",
            "bad_calloc",
            "bad_allocation_wrapper",
            "bad_argument_wrapper",
            "copy_wrapper",
            "bad_realloc",
            "bad_global",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        if has_debug {
            expected.insert("bad_adjacent_stack".into());
        }
        assert_eq!(overflow, expected, "debug={has_debug}");

        for (function, offset, size, len) in [
            ("bad_heap", 0, 16, 17),
            ("bad_interior", 4, 16, 13),
            ("bad_calloc", 0, 16, 17),
            ("bad_allocation_wrapper", 2, 16, 15),
            ("bad_argument_wrapper", 3, 16, 14),
            ("bad_realloc", 0, 16, 17),
        ] {
            let finding = findings
                .iter()
                .find(|f| {
                    name(f.site.caller) == function
                        && matches!(f.issue, Issue::ObjectOverflow { .. })
                })
                .unwrap();
            let Issue::ObjectOverflow {
                object,
                len: actual_len,
            } = &finding.issue
            else {
                unreachable!()
            };
            assert_eq!(object.offset, offset, "{function}");
            assert_eq!(
                object.size,
                Some(SizeRange { lo: size, hi: size }),
                "{function}"
            );
            assert_eq!(*actual_len, SizeRange { lo: len, hi: len }, "{function}");
            assert!(object.nullable, "{function}");
            assert!(matches!(object.origin, Some(ObjectOrigin::Heap { .. })));
            assert!(matches!(
                object.evidence.as_slice(),
                [ObjectEvidence::AllocatorArguments { .. }]
            ));
        }
        let via = findings
            .iter()
            .find(|f| {
                name(f.site.caller) == "copy_wrapper"
                    && matches!(f.issue, Issue::ObjectOverflow { .. })
            })
            .unwrap();
        assert!(
            via.path
                .iter()
                .any(|c| name(c.caller) == "bad_copy_wrapper")
        );
        assert!(
            findings
                .iter()
                .any(|f| name(f.site.caller) == "bad_unbounded"
                    && matches!(f.issue, Issue::ObjectUnbounded { .. }))
        );
        assert!(
            !findings
                .iter()
                .any(|f| name(f.site.caller) == "ok_format_wrapper")
        );
        for (function, environment) in [
            ("bad_environment_wrapper", true),
            ("bad_input_wrapper", false),
        ] {
            assert!(
                findings.iter().any(|f| name(f.site.caller) == function
                    && match &f.issue {
                        Issue::Format {
                            input: Some(Input::Environment),
                            ..
                        } => environment,
                        Issue::Format {
                            input: Some(Input::Read { .. }),
                            ..
                        } => !environment,
                        _ => false,
                    }),
                "{function}"
            );
        }
        let copy = calls
            .sites()
            .iter()
            .find(|c| {
                name(c.caller) == "unknown_calloc"
                    && c.import().is_some_and(|n| n.starts_with("memcpy"))
            })
            .unwrap();
        let arg = calls.resolve_arg(&copy.args[0], copy.caller);
        let facts = pointer_facts(&arg, copy.caller, copy.pc, &provider);
        assert!(matches!(facts.origin, Some(ObjectOrigin::Heap { .. })));
        assert_eq!(facts.size, None);
        assert_eq!(
            facts.unknown_extent,
            Some(UnknownExtent::AllocationSizeUnknown)
        );

        let stack_copy = calls
            .sites()
            .iter()
            .find(|c| {
                name(c.caller) == "bad_adjacent_stack"
                    && c.import().is_some_and(|n| n.starts_with("memcpy"))
            })
            .unwrap();
        assert!(matches!(stack_copy.args[0], Arg::Stack(off) if off < -9));
        assert!(
            !findings
                .iter()
                .any(|f| name(f.site.caller) == "bad_adjacent_stack"
                    && matches!(f.issue, Issue::Overflow { .. })),
            "object overflow must not rely on return-address reach"
        );
        let facts = pointer_facts(
            &calls.resolve_arg(&stack_copy.args[0], stack_copy.caller),
            stack_copy.caller,
            stack_copy.pc,
            &provider,
        );
        if has_debug {
            assert_eq!(facts.size, Some(SizeRange { lo: 8, hi: 8 }));
            assert!(matches!(
                facts.evidence.as_slice(),
                [ObjectEvidence::Dwarf { .. }]
            ));
        } else {
            assert_eq!(facts.size, None);
            assert_eq!(facts.unknown_extent, Some(UnknownExtent::NoDebugObject));
        }
    }
}

#[test]
fn nullable_sites_intervals_and_unknown_extents() {
    let allocation = Arg::Allocation {
        function: 0x100,
        pc: 0x120,
        allocator: "realloc".into(),
        size: Some(SizeRange { lo: 8, hi: 16 }),
    };
    let facts = pointer_facts(&allocation.offset(3), 0x100, 0x130, &|_| None);
    assert!(facts.nullable);
    assert_eq!(facts.offset, 3);
    assert!(facts.overflows(SizeRange { lo: 6, hi: 6 }));
    assert!(!facts.overflows(SizeRange { lo: 5, hi: 5 }));
    assert!(!facts.overflows(SizeRange { lo: 0, hi: 0 }));
    let stack = pointer_facts(&Arg::Stack(-32), 0x100, 0x130, &|_| None);
    assert_eq!(stack.size, None);
    assert_eq!(stack.unknown_extent, Some(UnknownExtent::NoDebugObject));
    let wrapped = Arg::Offset {
        base: Box::new(Arg::Offset {
            base: Box::new(Arg::Incoming("rdi".into())),
            off: i64::MAX,
        }),
        off: 1,
    };
    assert_eq!(
        pointer_facts(&wrapped, 0x100, 0x130, &|_| None).unknown_extent,
        Some(UnknownExtent::OffsetOverflow)
    );
}

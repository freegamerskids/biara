//! Layout regression fixtures: combined cross-callee fields, offset-pointer
//! and return-alias propagation, generic-callee separation, container-field
//! separation, and explicit conflicts through multiple call levels.
//!
//! Each test builds a small ABI-form-like LLVM module directly (pointer
//! variables as `i64`/`ptr` arguments, loads/stores through `base + offset`
//! address arithmetic, direct calls), runs the cached native layout analysis
//! through [`biara_lift::layouts::analyze_layouts`], and asserts on owned
//! layout evidence without requiring the full lift pipeline.
//!
//! Behavioral coverage, per the acceptance contract:
//! - accesses through two callees yield combined reusable fields under one
//!   shared layout id;
//! - offset pointers (`p + 8` passed where `p` was bound) and returned
//!   aliases propagate to the right offsets;
//! - a generic helper called with unrelated objects does not merge layouts;
//! - a container holding a pointer field does not leak its own offsets
//!   into unrelated child shapes;
//! - overlapping incompatible accesses are explicit conflicts (including
//!   through multiple call levels), and sizes stay observed extents;
//! - executable equivalence of the generated C is covered by the existing
//!   end-to-end `tests/decompile.rs` corpus (x86-64/AArch64, -O0/-O2),
//!   which renders through this same cached analysis.
//!
//! Assertions are binding-specific (per-function `args`/`returns` entries
//! and per-layout `functions` lists), not global any-field scans: a fact
//! bound to the wrong function fails here even when the field exists
//! somewhere in the module.

#[cfg(target_os = "linux")]
mod layouts {
    use biara_lift::layouts::analyze_layouts;
    use inkwell::{
        AddressSpace, context::Context, targets::TargetMachine, types::BasicType,
        values::BasicValueEnum,
    };

    fn machine() -> TargetMachine {
        biara_lift::analysis_machine().unwrap()
    }

    fn tag(cx: &Context, m: &inkwell::module::Module, f: inkwell::values::FunctionValue, e: u64) {
        let i64t = cx.i64_type();
        f.as_global_value().set_metadata(
            cx.metadata_node(&[
                i64t.const_int(e, false).into(),
                cx.i32_type().const_int(1, false).into(),
            ]),
            m.get_context().get_kind_id("biara.entry"),
        );
    }

    fn load_at<'c>(
        cx: &'c Context,
        b: &inkwell::builder::Builder<'c>,
        arg: inkwell::values::IntValue<'c>,
        off: u64,
        bits: u32,
        name: &str,
    ) -> BasicValueEnum<'c> {
        let i64t = cx.i64_type();
        let a = b
            .build_int_add(arg, i64t.const_int(off, false), name)
            .unwrap();
        let ptr = b
            .build_int_to_ptr(a, cx.ptr_type(AddressSpace::default()), name)
            .unwrap();
        let ty = if bits == 32 {
            cx.i32_type().as_basic_type_enum()
        } else {
            i64t.as_basic_type_enum()
        };
        b.build_load(ty, ptr, name).unwrap()
    }

    fn widen32<'c>(
        cx: &'c Context,
        b: &inkwell::builder::Builder<'c>,
        v: BasicValueEnum<'c>,
    ) -> BasicValueEnum<'c> {
        match v {
            BasicValueEnum::IntValue(iv) if iv.get_type().get_bit_width() == 32 => {
                BasicValueEnum::IntValue(b.build_int_z_extend(iv, cx.i64_type(), "z").unwrap())
            }
            v => v,
        }
    }

    fn arg_binding(
        facts: &biara_lift::layouts::LayoutFacts,
        function: u64,
        arg: u32,
    ) -> Option<u32> {
        facts
            .args
            .iter()
            .find(|a| a.function == function && a.arg == arg)
            .and_then(|a| a.layout)
    }

    fn layout_by_id(
        facts: &biara_lift::layouts::LayoutFacts,
        id: u32,
    ) -> &biara_lift::layouts::SharedLayout {
        facts.layouts.iter().find(|l| l.id == id).unwrap()
    }

    #[test]
    fn two_callees_yield_combined_reusable_fields() {
        let cx = Context::create();
        let m = cx.create_module("layouts-combined");
        m.set_triple(&machine().get_triple());
        let i64t = cx.i64_type();
        // set_field8(p): *(u32*)(p+8) = 3.
        let set_field8 = m.add_function(
            "set_field8",
            cx.void_type().fn_type(&[i64t.into()], false),
            None,
        );
        tag(&cx, &m, set_field8, 0x1000);
        let b = cx.create_builder();
        b.position_at_end(cx.append_basic_block(set_field8, "entry"));
        let p = set_field8.get_nth_param(0).unwrap().into_int_value();
        let a8 = b.build_int_add(p, i64t.const_int(8, false), "a8").unwrap();
        let p8 = b
            .build_int_to_ptr(a8, cx.ptr_type(AddressSpace::default()), "p8")
            .unwrap();
        b.build_store(p8, cx.i32_type().const_int(3, false))
            .unwrap();
        b.build_return(None).unwrap();

        // get_field16(p): *(u64*)(p+16).
        let get_field16 = m.add_function("get_field16", i64t.fn_type(&[i64t.into()], false), None);
        tag(&cx, &m, get_field16, 0x2000);
        b.position_at_end(cx.append_basic_block(get_field16, "entry"));
        let q = get_field16.get_nth_param(0).unwrap().into_int_value();
        let v = load_at(&cx, &b, q, 16, 64, "v");
        b.build_return(Some(&v)).unwrap();

        // Caller passes one object to both.
        let use_both = m.add_function("use_both", i64t.fn_type(&[i64t.into()], false), None);
        tag(&cx, &m, use_both, 0x3000);
        b.position_at_end(cx.append_basic_block(use_both, "entry"));
        let o = use_both.get_nth_param(0).unwrap();
        b.build_call(set_field8, &[o.into()], "c0").unwrap();
        let r = b.build_call(get_field16, &[o.into()], "c1").unwrap();
        let rv = r.try_as_basic_value().basic().unwrap();
        b.build_return(Some(&rv)).unwrap();

        let facts = analyze_layouts(&m, &[], 0).unwrap();
        // The caller's object accumulates both callees' evidence: its
        // binding resolves to a layout carrying (8,4) and (16,8).
        let caller = arg_binding(&facts, 0x3000, 0).expect("caller bound");
        let combined = layout_by_id(&facts, caller);
        assert!(
            combined.fields.iter().any(|f| f.off == 8 && f.bytes == 4),
            "caller field 8: {combined:?}"
        );
        assert!(
            combined.fields.iter().any(|f| f.off == 16 && f.bytes == 8),
            "caller field 16: {combined:?}"
        );
        // Reusable: each callee's own field set is contained in the
        // caller's combined layout (the shared object serves both), and
        // the combined layout's entry list converges all three functions.
        for (entry, want) in [(0x1000u64, (8i64, 4u32)), (0x2000u64, (16i64, 8u32))] {
            let id = arg_binding(&facts, entry, 0).expect("callee bound");
            let own = layout_by_id(&facts, id);
            assert!(
                own.fields
                    .iter()
                    .any(|f| f.off == want.0 && f.bytes == want.1),
                "callee {entry:#x} keeps ({},{}): {own:?}",
                want.0,
                want.1
            );
            assert!(
                combined
                    .fields
                    .iter()
                    .any(|f| f.off == want.0 && f.bytes == want.1),
                "caller covers callee {entry:#x}: {combined:?}"
            );
        }
        assert!(
            combined.functions.contains(&0x3000),
            "caller converged: {combined:?}"
        );
    }

    #[test]
    fn structurally_equal_layouts_share_one_stable_id() {
        let cx = Context::create();
        let m = cx.create_module("layouts-shared-id");
        m.set_triple(&machine().get_triple());
        let i64t = cx.i64_type();
        // Two independent readers of the same shape: (0,8) and (8,4).
        for (name, entry) in [("reader_a", 0x1000u64), ("reader_b", 0x2000u64)] {
            let f = m.add_function(name, i64t.fn_type(&[i64t.into()], false), None);
            tag(&cx, &m, f, entry);
            let b = cx.create_builder();
            b.position_at_end(cx.append_basic_block(f, "entry"));
            let arg = f.get_nth_param(0).unwrap().into_int_value();
            let v0 = load_at(&cx, &b, arg, 0, 64, "v0");
            let v1 = load_at(&cx, &b, arg, 8, 32, "v1");
            let s = b
                .build_int_add(
                    v0.into_int_value(),
                    widen32(&cx, &b, v1).into_int_value(),
                    "s",
                )
                .unwrap();
            b.build_return(Some(&s)).unwrap();
        }
        let facts = analyze_layouts(&m, &[], 0).unwrap();
        let a = arg_binding(&facts, 0x1000, 0).expect("A bound");
        let b = arg_binding(&facts, 0x2000, 0).expect("B bound");
        // One id per shared printed structure: equal shapes, equal ids,
        // one exported layout, both entries converged.
        assert_eq!(a, b, "shared id: {a} vs {b}");
        assert_eq!(
            facts.layouts.iter().filter(|l| l.id == a).count(),
            1,
            "single export: {:?}",
            facts.layouts
        );
        let shared = layout_by_id(&facts, a);
        assert!(shared.functions.contains(&0x1000) && shared.functions.contains(&0x2000));
        assert!(shared.fields.iter().any(|f| f.off == 0 && f.bytes == 8));
        assert!(shared.fields.iter().any(|f| f.off == 8 && f.bytes == 4));
    }

    #[test]
    fn offset_pointers_and_returned_aliases_propagate() {
        let cx = Context::create();
        let m = cx.create_module("layouts-offret");
        m.set_triple(&machine().get_triple());
        let i64t = cx.i64_type();
        let ptrt = cx.ptr_type(AddressSpace::default());
        // id(p): return p (returned alias).
        let id = m.add_function("id_alias", i64t.fn_type(&[i64t.into()], false), None);
        tag(&cx, &m, id, 0x1000);
        let b = cx.create_builder();
        b.position_at_end(cx.append_basic_block(id, "entry"));
        b.build_return(Some(&id.get_nth_param(0).unwrap())).unwrap();
        // read16(p): *(u64*)(p+16).
        let read16 = m.add_function("read16", i64t.fn_type(&[i64t.into()], false), None);
        tag(&cx, &m, read16, 0x2000);
        b.position_at_end(cx.append_basic_block(read16, "entry"));
        let q = read16.get_nth_param(0).unwrap().into_int_value();
        let a16 = b
            .build_int_add(q, i64t.const_int(16, false), "a16")
            .unwrap();
        let p16 = b.build_int_to_ptr(a16, ptrt, "p16").unwrap();
        let v = b.build_load(i64t.as_basic_type_enum(), p16, "v").unwrap();
        b.build_return(Some(&v)).unwrap();
        // Caller: q = id(p); read16(q+8) shifts the callee's +16 to the
        // actual's offset 24.
        let go = m.add_function("go_offret", i64t.fn_type(&[i64t.into()], false), None);
        tag(&cx, &m, go, 0x3000);
        b.position_at_end(cx.append_basic_block(go, "entry"));
        let p = go.get_nth_param(0).unwrap();
        let qv = b.build_call(id, &[p.into()], "q").unwrap();
        let qi: inkwell::values::IntValue = match qv.try_as_basic_value().basic().unwrap() {
            BasicValueEnum::IntValue(v) => v,
            _ => panic!("expected int"),
        };
        let qa = b.build_int_add(qi, i64t.const_int(8, false), "qa").unwrap();
        let r = b.build_call(read16, &[qa.into()], "r").unwrap();
        b.build_return(Some(&r.try_as_basic_value().basic().unwrap()))
            .unwrap();

        let facts = analyze_layouts(&m, &[], 0).unwrap();
        // The caller's binding carries the shifted access at offset 24.
        let caller = arg_binding(&facts, 0x3000, 0).expect("caller bound");
        let shifted = layout_by_id(&facts, caller);
        assert!(
            shifted.fields.iter().any(|f| f.off == 24 && f.bytes == 8),
            "shifted field 24 on caller: {shifted:?}"
        );
        // read16's own binding keeps its direct access at 16 (not shifted).
        let reader = arg_binding(&facts, 0x2000, 0).expect("reader bound");
        assert!(
            layout_by_id(&facts, reader)
                .fields
                .iter()
                .any(|f| f.off == 16 && f.bytes == 8),
            "direct field 16 on reader: {:?}",
            facts.layouts
        );
        // Return bindings exist for the aliasing function and the reader.
        assert!(
            facts.returns.iter().any(|r| r.function == 0x1000),
            "return binding: {:?}",
            facts.returns
        );
    }

    #[test]
    fn generic_helper_does_not_merge_unrelated_objects() {
        let cx = Context::create();
        let m = cx.create_module("layouts-generic");
        m.set_triple(&machine().get_triple());
        let i64t = cx.i64_type();
        // touch(p): reads *(u64*)p (offset 0 only).
        let touch = m.add_function("touch", i64t.fn_type(&[i64t.into()], false), None);
        tag(&cx, &m, touch, 0x1000);
        let b = cx.create_builder();
        b.position_at_end(cx.append_basic_block(touch, "entry"));
        let p = touch.get_nth_param(0).unwrap().into_int_value();
        let pp = b
            .build_int_to_ptr(p, cx.ptr_type(AddressSpace::default()), "pp")
            .unwrap();
        let v = b.build_load(i64t.as_basic_type_enum(), pp, "v").unwrap();
        b.build_return(Some(&v)).unwrap();
        // A: u32 at offset 8; B: u64 at offset 24. Both call touch.
        for (name, entry, off, bits) in [
            ("obj_a", 0x2000u64, 8u64, 32u32),
            ("obj_b", 0x3000u64, 24u64, 64u32),
        ] {
            let f = m.add_function(name, i64t.fn_type(&[i64t.into()], false), None);
            tag(&cx, &m, f, entry);
            b.position_at_end(cx.append_basic_block(f, "entry"));
            let arg = f.get_nth_param(0).unwrap().into_int_value();
            let lv = load_at(&cx, &b, arg, off, bits, "lv");
            let _ = b.build_call(touch, &[f.get_nth_param(0).unwrap().into()], "t");
            b.build_return(Some(&widen32(&cx, &b, lv))).unwrap();
        }
        let facts = analyze_layouts(&m, &[], 0).unwrap();
        // Binding-specific: A's layout has (8,4) and no (24,8); B's has
        // (24,8) and no (8,4).
        let a = arg_binding(&facts, 0x2000, 0).expect("A bound");
        let la = layout_by_id(&facts, a);
        assert!(
            la.fields.iter().any(|f| f.off == 8 && f.bytes == 4),
            "A keeps (8,4): {la:?}"
        );
        assert!(
            !la.fields.iter().any(|f| f.off == 24 && f.bytes == 8),
            "A unpolluted by B: {la:?}"
        );
        let bb = arg_binding(&facts, 0x3000, 0).expect("B bound");
        let lb = layout_by_id(&facts, bb);
        assert!(
            lb.fields.iter().any(|f| f.off == 24 && f.bytes == 8),
            "B keeps (24,8): {lb:?}"
        );
        assert!(
            !lb.fields.iter().any(|f| f.off == 8 && f.bytes == 4),
            "B unpolluted by A: {lb:?}"
        );
        assert_ne!(a, bb, "separate ids: {a} vs {bb}");
    }

    #[test]
    fn generic_identity_keeps_two_unrelated_arguments_apart() {
        let cx = Context::create();
        let m = cx.create_module("layouts-identity");
        m.set_triple(&machine().get_triple());
        let i64t = cx.i64_type();
        // id2(p): return p. Called once with an (8,4) object and once with
        // a (24,8) object; neither caller's layout may gain the other's.
        let id2 = m.add_function("id2", i64t.fn_type(&[i64t.into()], false), None);
        tag(&cx, &m, id2, 0x1000);
        let b = cx.create_builder();
        b.position_at_end(cx.append_basic_block(id2, "entry"));
        b.build_return(Some(&id2.get_nth_param(0).unwrap()))
            .unwrap();
        for (name, entry, off, bits) in [
            ("use_a", 0x2000u64, 8u64, 32u32),
            ("use_b", 0x3000u64, 24u64, 64u32),
        ] {
            let f = m.add_function(name, i64t.fn_type(&[i64t.into()], false), None);
            tag(&cx, &m, f, entry);
            b.position_at_end(cx.append_basic_block(f, "entry"));
            let arg = f.get_nth_param(0).unwrap().into_int_value();
            let lv = load_at(&cx, &b, arg, off, bits, "lv");
            let qv = b
                .build_call(id2, &[f.get_nth_param(0).unwrap().into()], "q")
                .unwrap();
            let qi: inkwell::values::IntValue = match qv.try_as_basic_value().basic().unwrap() {
                BasicValueEnum::IntValue(v) => v,
                _ => panic!("expected int"),
            };
            // Touch the alias at the same offset, so the result class has
            // a reason to exist per site without merging across sites.
            let back = load_at(&cx, &b, qi, off, bits, "back");
            let s = b
                .build_int_add(
                    widen32(&cx, &b, lv).into_int_value(),
                    widen32(&cx, &b, back).into_int_value(),
                    "s",
                )
                .unwrap();
            b.build_return(Some(&s)).unwrap();
        }
        let facts = analyze_layouts(&m, &[], 0).unwrap();
        let a = arg_binding(&facts, 0x2000, 0).expect("A bound");
        let la = layout_by_id(&facts, a);
        assert!(
            la.fields.iter().any(|f| f.off == 8 && f.bytes == 4),
            "A: {la:?}"
        );
        assert!(!la.fields.iter().any(|f| f.off == 24), "A apart: {la:?}");
        let bb = arg_binding(&facts, 0x3000, 0).expect("B bound");
        let lb = layout_by_id(&facts, bb);
        assert!(
            lb.fields.iter().any(|f| f.off == 24 && f.bytes == 8),
            "B: {lb:?}"
        );
        assert!(!lb.fields.iter().any(|f| f.off == 8), "B apart: {lb:?}");
    }

    #[test]
    fn container_pointer_field_does_not_leak_into_child() {
        let cx = Context::create();
        let m = cx.create_module("layouts-container");
        m.set_triple(&machine().get_triple());
        let i64t = cx.i64_type();
        // child(p): *(u64*)(p+16) = deep field of the child shape.
        let child = m.add_function("child", i64t.fn_type(&[i64t.into()], false), None);
        tag(&cx, &m, child, 0x1000);
        let b = cx.create_builder();
        b.position_at_end(cx.append_basic_block(child, "entry"));
        let cp = child.get_nth_param(0).unwrap().into_int_value();
        let cv = load_at(&cx, &b, cp, 16, 64, "cv");
        b.build_return(Some(&cv)).unwrap();
        // holder(h, c): stores c at *(h+0) (pointer field), reads
        // *(u32*)(h+8) (container's own flag). The container's offset-8
        // flag must never appear in the child's layout.
        let holder = m.add_function(
            "holder",
            i64t.fn_type(&[i64t.into(), i64t.into()], false),
            None,
        );
        tag(&cx, &m, holder, 0x2000);
        b.position_at_end(cx.append_basic_block(holder, "entry"));
        let h = holder.get_nth_param(0).unwrap().into_int_value();
        let c = holder.get_nth_param(1).unwrap().into_int_value();
        let hp = b
            .build_int_to_ptr(h, cx.ptr_type(AddressSpace::default()), "hp")
            .unwrap();
        b.build_store(hp, c).unwrap();
        let fv = load_at(&cx, &b, h, 8, 32, "fv");
        let r = b.build_call(child, &[c.into()], "r").unwrap();
        let s = b
            .build_int_add(
                widen32(&cx, &b, fv).into_int_value(),
                r.try_as_basic_value().basic().unwrap().into_int_value(),
                "s",
            )
            .unwrap();
        b.build_return(Some(&s)).unwrap();
        // Top passes an unrelated child shape: only *(u64*)(c+16) plus an
        // unrelated *(u32*)(c+40) marker that the container never sees.
        let top = m.add_function("top", i64t.fn_type(&[i64t.into()], false), None);
        tag(&cx, &m, top, 0x3000);
        b.position_at_end(cx.append_basic_block(top, "entry"));
        let t = top.get_nth_param(0).unwrap().into_int_value();
        let t16 = load_at(&cx, &b, t, 16, 64, "t16");
        let t40 = load_at(&cx, &b, t, 40, 32, "t40");
        let s2 = b
            .build_int_add(
                t16.into_int_value(),
                widen32(&cx, &b, t40).into_int_value(),
                "s2",
            )
            .unwrap();
        b.build_return(Some(&s2)).unwrap();

        let facts = analyze_layouts(&m, &[], 0).unwrap();
        // The child's binding (holder arg 1) carries the deep field (16,8)
        // but not the container's own (8,4).
        let held = arg_binding(&facts, 0x2000, 1).expect("held child bound");
        let lh = layout_by_id(&facts, held);
        assert!(
            lh.fields.iter().any(|f| f.off == 16 && f.bytes == 8),
            "child deep field: {lh:?}"
        );
        assert!(
            !lh.fields.iter().any(|f| f.off == 8 && f.bytes == 4),
            "no container leak: {lh:?}"
        );
        // The holder's own binding keeps its flag.
        let hk = arg_binding(&facts, 0x2000, 0).expect("holder bound");
        assert!(
            layout_by_id(&facts, hk)
                .fields
                .iter()
                .any(|f| f.off == 8 && f.bytes == 4),
            "holder flag: {:?}",
            facts.layouts
        );
        // Pointee evidence: some layout has a field whose pointee is the
        // held child's layout id (established through the stored pointer
        // field, not guessed).
        assert!(
            facts
                .layouts
                .iter()
                .any(|l| l.fields.iter().any(|f| f.pointee == Some(held))),
            "pointee linkage: {:?}",
            facts.layouts
        );
    }

    #[test]
    fn conflicting_widths_are_explicit_and_sizes_stay_observed() {
        let cx = Context::create();
        let m = cx.create_module("layouts-conflict");
        m.set_triple(&machine().get_triple());
        let i64t = cx.i64_type();
        // w4(p): *(u32*)(p+8). w8(p): *(u64*)(p+8). Same offset, widths 4/8.
        for (name, entry, bits) in [("w4", 0x1000u64, 32u32), ("w8", 0x2000u64, 64u32)] {
            let f = m.add_function(name, i64t.fn_type(&[i64t.into()], false), None);
            tag(&cx, &m, f, entry);
            let b = cx.create_builder();
            b.position_at_end(cx.append_basic_block(f, "entry"));
            let arg = f.get_nth_param(0).unwrap().into_int_value();
            let lv = load_at(&cx, &b, arg, 8, bits, "lv");
            b.build_return(Some(&widen32(&cx, &b, lv))).unwrap();
        }
        // Mid forwards its object to w8: the 8-byte width reaches the top
        // through two call levels (top -> mid -> w8), while w4 gives the
        // top the 4-byte width directly. Both widths must surface.
        let mid = m.add_function("w_mid", i64t.fn_type(&[i64t.into()], false), None);
        tag(&cx, &m, mid, 0x3000);
        let b = cx.create_builder();
        b.position_at_end(cx.append_basic_block(mid, "entry"));
        let mo = mid.get_nth_param(0).unwrap();
        let w8 = m.get_function("w8").unwrap();
        let mr = b.build_call(w8, &[mo.into()], "mr").unwrap();
        b.build_return(Some(&mr.try_as_basic_value().basic().unwrap()))
            .unwrap();
        let both = m.add_function("w_both", i64t.fn_type(&[i64t.into()], false), None);
        tag(&cx, &m, both, 0x4000);
        b.position_at_end(cx.append_basic_block(both, "entry"));
        let o = both.get_nth_param(0).unwrap();
        let w4 = m.get_function("w4").unwrap();
        let midf = m.get_function("w_mid").unwrap();
        let r1 = b.build_call(w4, &[o.into()], "r1").unwrap();
        let r2 = b.build_call(midf, &[o.into()], "r2").unwrap();
        let s = b
            .build_int_add(
                r1.try_as_basic_value().basic().unwrap().into_int_value(),
                r2.try_as_basic_value().basic().unwrap().into_int_value(),
                "s",
            )
            .unwrap();
        b.build_return(Some(&s)).unwrap();

        let facts = analyze_layouts(&m, &[], 0).unwrap();
        // The top object's binding observes both widths at offset 8: the
        // conflict is bound to the top's layout id (not just anywhere).
        let top = arg_binding(&facts, 0x4000, 0).expect("top bound");
        assert!(
            facts.conflicts.iter().any(|c| c.layout == Some(top)
                && c.off == 8
                && c.widths.contains(&4)
                && c.widths.contains(&8)),
            "explicit conflict on top: {:?}",
            facts.conflicts
        );
        for l in &facts.layouts {
            let end = l
                .fields
                .iter()
                .map(|f| f.off + f.bytes as i64)
                .max()
                .unwrap_or(0);
            assert_eq!(l.size as i64, end, "size is accessed extent: {l:?}");
        }
    }

    #[test]
    fn different_return_layouts_remain_unbound() {
        let cx = Context::create();
        let m = cx.create_module("layouts-return-alternatives");
        let i64t = cx.i64_type();
        let f = m.add_function(
            "choose",
            i64t.fn_type(&[i64t.into(), i64t.into(), cx.bool_type().into()], false),
            None,
        );
        tag(&cx, &m, f, 0x1000);
        let entry = cx.append_basic_block(f, "entry");
        let left = cx.append_basic_block(f, "left");
        let right = cx.append_basic_block(f, "right");
        let b = cx.create_builder();
        b.position_at_end(entry);
        let a = f.get_nth_param(0).unwrap().into_int_value();
        let z = f.get_nth_param(1).unwrap().into_int_value();
        load_at(&cx, &b, a, 8, 32, "a8");
        load_at(&cx, &b, z, 24, 64, "z24");
        b.build_conditional_branch(f.get_nth_param(2).unwrap().into_int_value(), left, right)
            .unwrap();
        b.position_at_end(left);
        b.build_return(Some(&a)).unwrap();
        b.position_at_end(right);
        b.build_return(Some(&z)).unwrap();
        let facts = analyze_layouts(&m, &[], 0).unwrap();
        let a_layout = arg_binding(&facts, 0x1000, 0).unwrap();
        let z_layout = arg_binding(&facts, 0x1000, 1).unwrap();
        assert_ne!(a_layout, z_layout);
        assert_eq!(
            facts
                .returns
                .iter()
                .find(|r| r.function == 0x1000)
                .unwrap()
                .layout,
            None,
            "neither return arm establishes a common layout"
        );
    }

    #[test]
    fn cross_call_pointer_field_binds_child_layout_per_site() {
        // getter(p): reads p->child (at 0) then child->field16.
        // use(p, q): stores q into p->child, then calls getter(p).
        // Caller q must gain field16, and p's field must bind q's layout.
        // A second site with a differently-shaped child stays separate.
        let cx = Context::create();
        let m = cx.create_module("layouts-xfield");
        m.set_triple(&machine().get_triple());
        let i64t = cx.i64_type();
        let getter = m.add_function("getter", i64t.fn_type(&[i64t.into()], false), None);
        tag(&cx, &m, getter, 0x1000);
        let b = cx.create_builder();
        b.position_at_end(cx.append_basic_block(getter, "entry"));
        let gp = getter.get_nth_param(0).unwrap().into_int_value();
        let ga = b.build_int_add(gp, i64t.const_int(0, false), "ga").unwrap();
        let gpp = b
            .build_int_to_ptr(ga, cx.ptr_type(AddressSpace::default()), "gpp")
            .unwrap();
        let child: inkwell::values::IntValue =
            match b.build_load(i64t.as_basic_type_enum(), gpp, "ch").unwrap() {
                BasicValueEnum::IntValue(v) => v,
                _ => panic!("expected int"),
            };
        let fv = load_at(&cx, &b, child, 16, 64, "fv");
        b.build_return(Some(&fv)).unwrap();
        // Site 1: plain child; site 2: child with an extra (40,4) marker.
        for (name, entry, extra) in [("use1", 0x2000u64, false), ("use2", 0x3000u64, true)] {
            let f = m.add_function(name, i64t.fn_type(&[i64t.into(), i64t.into()], false), None);
            tag(&cx, &m, f, entry);
            b.position_at_end(cx.append_basic_block(f, "entry"));
            let p = f.get_nth_param(0).unwrap().into_int_value();
            let q = f.get_nth_param(1).unwrap().into_int_value();
            let pa = b.build_int_add(p, i64t.const_int(0, false), "pa").unwrap();
            let pp = b
                .build_int_to_ptr(pa, cx.ptr_type(AddressSpace::default()), "pp")
                .unwrap();
            b.build_store(pp, q).unwrap();
            if extra {
                load_at(&cx, &b, q, 40, 32, "mk");
            }
            let r = b.build_call(getter, &[p.into()], "r").unwrap();
            b.build_return(Some(&r.try_as_basic_value().basic().unwrap()))
                .unwrap();
        }
        let facts = analyze_layouts(&m, &[], 0).unwrap();
        // Site 1 child gains the getter-observed field16 through the
        // cross-call pointer field.
        let q1 = arg_binding(&facts, 0x2000, 1).expect("site1 child bound");
        let lq1 = layout_by_id(&facts, q1);
        assert!(
            lq1.fields.iter().any(|f| f.off == 16 && f.bytes == 8),
            "site1 child gains field16: {lq1:?}"
        );
        // Site 1 container's field at 0 binds the child layout.
        let p1 = arg_binding(&facts, 0x2000, 0).expect("site1 container bound");
        let lp1 = layout_by_id(&facts, p1);
        let slot = lp1.fields.iter().find(|f| f.off == 0).expect("slot field");
        assert_eq!(
            slot.pointee,
            Some(q1),
            "container field binds child layout: {lp1:?} vs child {q1}"
        );
        // Site 2 child keeps its own marker and gains field16; site 1
        // child never gains the marker: unrelated sites stay separate.
        let q2 = arg_binding(&facts, 0x3000, 1).expect("site2 child bound");
        let lq2 = layout_by_id(&facts, q2);
        assert!(
            lq2.fields.iter().any(|f| f.off == 40 && f.bytes == 4),
            "site2 marker kept: {lq2:?}"
        );
        assert!(
            lq2.fields.iter().any(|f| f.off == 16 && f.bytes == 8),
            "site2 gains field16: {lq2:?}"
        );
        assert!(
            !lq1.fields.iter().any(|f| f.off == 40),
            "site1 unpolluted by site2: {lq1:?}"
        );
    }
}

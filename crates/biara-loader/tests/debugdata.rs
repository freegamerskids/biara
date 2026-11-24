//! A stripped binary with Fedora-style `.gnu_debugdata` keeps its names:
//! `foo` and `_start` come back from the XZ-compressed symtab-only ELF.
//!
//! The section is synthesized the way `find-debuginfo` makes it: the debug
//! file is split off and the binary stripped (`eu-strip -f`; here the pinned
//! LLVM's objcopy and strip), `xz` compresses it, `objcopy --add-section`
//! attaches it. Requires `xz` on `PATH`.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use biara_loader::Image;

fn tmp() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

/// `llvm-objcopy`, `llvm-strip`: next to the pinned clang.
fn llvm_tool(name: &str) -> PathBuf {
    Path::new(env!("BIARA_CLANG")).with_file_name(name)
}

fn run(prog: &Path, args: &[&str]) {
    let status = Command::new(prog).args(args).status().unwrap_or_else(|e| {
        panic!("{} missing: {e}", prog.display());
    });
    assert!(status.success(), "{} {args:?} failed", prog.display());
}

#[test]
fn gnu_debugdata() {
    let dir = tmp().join("debugdata");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("prog.c"),
        "__attribute__((noinline)) long foo(long x) { return x * 2 + 1; }\n\
         void _start(void) { volatile long s = foo(21); (void)s; for (;;) {} }\n",
    )
    .unwrap();
    let cc = |args: &[&str]| {
        let status = Command::new(env!("BIARA_CLANG"))
            .args(["--target=x86_64-linux-gnu", "-fuse-ld=lld"])
            .args(args)
            .arg("-o")
            .arg(dir.join("prog"))
            .arg(dir.join("prog.c"))
            .status()
            .unwrap();
        assert!(status.success(), "building the corpus");
    };
    cc(&["-O2", "-nostdlib", "-fno-pie", "-static"]);
    // The stripped binary alone has no names.
    let (prog, debug) = (dir.join("prog"), dir.join("prog.debug"));
    let (prog, debug) = (prog.to_str().unwrap(), debug.to_str().unwrap());
    run(
        &llvm_tool("llvm-objcopy"),
        &["--only-keep-debug", prog, debug],
    );
    run(&llvm_tool("llvm-strip"), &[prog]);
    let stripped = Image::load(&dir.join("prog")).unwrap();
    assert!(stripped.symbol("foo").is_none(), "stripped binary kept foo");
    // Compress the debug file and attach it as `.gnu_debugdata`.
    let xz = Command::new("xz")
        .args(["-c", dir.join("prog.debug").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(xz.status.success(), "compressing the debug file");
    std::fs::write(dir.join("prog.debug.xz"), &xz.stdout).unwrap();
    run(
        &llvm_tool("llvm-objcopy"),
        &[
            "--add-section",
            &format!(".gnu_debugdata={}", dir.join("prog.debug.xz").display()),
            dir.join("prog").to_str().unwrap(),
            dir.join("prog.dd").to_str().unwrap(),
        ],
    );
    let image = Image::load(&dir.join("prog.dd")).unwrap();
    let foo = image.symbol("foo").expect("foo from .gnu_debugdata");
    assert!(
        image.function_at(foo.addr).is_some_and(|s| s.name == "foo"),
        "foo is a function"
    );
    assert!(
        image.symbol("_start").is_some(),
        "_start from .gnu_debugdata"
    );
    // A corrupt payload never fails the load; it just yields no names.
    let mut raw = std::fs::read(dir.join("prog.debug.xz")).unwrap();
    raw.truncate(raw.len() / 2);
    std::fs::write(dir.join("prog.debug.xz"), &raw).unwrap();
    run(
        &llvm_tool("llvm-objcopy"),
        &[
            "--add-section",
            &format!(".gnu_debugdata={}", dir.join("prog.debug.xz").display()),
            dir.join("prog").to_str().unwrap(),
            dir.join("prog.bad").to_str().unwrap(),
        ],
    );
    let bad = Image::load(&dir.join("prog.bad")).unwrap();
    assert!(
        bad.symbol("foo").is_none(),
        "corrupt .gnu_debugdata kept foo"
    );
}

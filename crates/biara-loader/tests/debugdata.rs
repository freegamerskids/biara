//! A stripped binary with Fedora-style `.gnu_debugdata` keeps its names:
//! `foo` and `_start` come back from the XZ-compressed symtab-only ELF.
//!
//! The section is synthesized the way `find-debuginfo` makes it: `eu-strip
//! -f` extracts the debug file, `xz` compresses it, `objcopy --add-section`
//! attaches it. Requires `eu-strip`, `xz` and `objcopy` on `PATH`
//! (binutils/elfutils; Fedora and Nobara have them).

use std::{path::PathBuf, process::Command};

use biara_loader::Image;

fn tmp() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

fn run(prog: &str, args: &[&str]) {
    let status = Command::new(prog).args(args).status().unwrap_or_else(|e| {
        panic!("{prog} missing: {e}");
    });
    assert!(status.success(), "{prog} {args:?} failed");
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
            .arg("--target=x86_64-linux-gnu")
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
    run(
        "eu-strip",
        &[
            "-f",
            dir.join("prog.debug").to_str().unwrap(),
            dir.join("prog").to_str().unwrap(),
        ],
    );
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
        "objcopy",
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
        "objcopy",
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

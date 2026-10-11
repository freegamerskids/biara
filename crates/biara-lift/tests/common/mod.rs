#![allow(dead_code)] // each test binary uses a subset
//! Building test programs with the pinned clang (BIARA_CLANG, set by
//! .cargo/config.toml).

pub mod corpus;

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

use biara_cfg::{Cfg, Discovery};
use biara_lift::{ResolveOptions, host_machine, recover_resolving};
use biara_loader::Image;
use biara_tcg::Libtcg;

pub fn tmp() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

/// A tool next to the pinned clang (`llvm-strip`, ...).
pub fn llvm_tool(name: &str) -> PathBuf {
    Path::new(env!("BIARA_CLANG")).with_file_name(name)
}

/// `ld.lld` for clang: the Rust toolchain's lld, which picks its flavour
/// from the name it is run as. Also links `lld-link` and `ld64.lld` to the
/// same binary, for the PE and Mach-O tests.
pub fn linker() -> PathBuf {
    static LD: OnceLock<PathBuf> = OnceLock::new();
    LD.get_or_init(|| {
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
        let out = Command::new(rustc)
            .args(["--print", "sysroot"])
            .output()
            .unwrap();
        let sysroot = String::from_utf8(out.stdout).unwrap();
        let rustlib = PathBuf::from(sysroot.trim()).join("lib/rustlib");
        let lld = std::fs::read_dir(&rustlib)
            .unwrap()
            .map(|e| e.unwrap().path().join("bin/rust-lld"))
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("no rust-lld under {}", rustlib.display()));
        // One per test binary: they run concurrently.
        let dir = tmp().join(concat!("ld-", env!("CARGO_CRATE_NAME")));
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["ld.lld", "lld-link", "ld64.lld"] {
            let link = dir.join(name);
            if link.symlink_metadata().is_err() {
                let _ = std::fs::remove_file(&link);
                std::os::unix::fs::symlink(&lld, &link).unwrap_or(());
            }
        }
        dir.join("ld.lld")
    })
    .clone()
}

/// The whole program, as the CLI recovers it without `--at`.
pub fn recover_program(lib: &mut Libtcg, image: &Image) -> Cfg {
    let opts = ResolveOptions {
        cfg: biara_cfg::Options {
            os: image.os,
            imports: image.imports.clone(),
            discovery: Some(Discovery {
                code: image.code.clone(),
                extents: image.function_extents(),
                data_pointers: image.code_pointers.clone(),
            }),
            function_starts: image.function_starts(),
            ..Default::default()
        },
        ..Default::default()
    };
    let starts: Vec<u64> = image.function_starts().into_iter().collect();
    recover_resolving(
        lib,
        &host_machine().unwrap(),
        &|pc| image.code_at(pc),
        &|addr, buf| image.read_const(addr, buf),
        &starts,
        opts,
    )
    .unwrap()
}

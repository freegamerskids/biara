//! Building tests/audit/prog.c for every supported format: ELF (both
//! architectures), PE (both architectures, via lld-link directly), Mach-O
//! (both architectures, chained and classic fixups). The C names of `main`
//! and the `bad_*`/`ok_*` corpus functions differ by format, which `Target`
//! hides (`c_name`); `main` on PE is the entry point by link flag rather
//! than by name.

use std::{path::PathBuf, process::Command};

use crate::common::tmp;
use std::sync::OnceLock;

fn linker() -> PathBuf {
    static LD: OnceLock<PathBuf> = OnceLock::new();
    LD.get_or_init(|| {
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
        let out = std::process::Command::new(rustc)
            .args(["--print", "sysroot"])
            .output()
            .unwrap();
        let sysroot = String::from_utf8(out.stdout).unwrap();
        let rustlib = PathBuf::from(sysroot.trim()).join("lib/rustlib");
        let lld = std::fs::read_dir(&rustlib)
            .unwrap()
            .map(|e| e.unwrap().path().join("bin/rust-lld"))
            .find(|p| p.exists())
            .unwrap();
        let dir = tmp().join("ld-audit-formats");
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["ld.lld", "lld-link", "ld64.lld"] {
            let link = dir.join(name);
            if link.symlink_metadata().is_err() {
                std::os::unix::fs::symlink(&lld, &link).unwrap_or(());
            }
        }
        dir.join("ld.lld")
    })
    .clone()
}

/// One corpus binary: how to build it, and how names look in it.
pub struct Target {
    /// For messages and output names (`pe-x86_64`, ...).
    pub name: String,
    /// `Libtcg::find` argument.
    pub qemu_arch: &'static str,
    /// `Image::os`.
    pub os: &'static str,
    /// `main`, where guests of this format call it from.
    pub main: &'static str,
    /// Build the corpus at `-O{opt}`.
    pub build: fn(u8) -> PathBuf,
    /// The C name of imports and corpus functions in this format (Mach-O
    /// adds `_`, PE decorates nothing here).
    pub c_name: fn(&str) -> String,
    /// The import name to expect for the C function `name` (PE's CRT
    /// aliases some).
    pub base: fn(String) -> String,
    /// Function names by address, for formats whose images carry no symbols
    /// (PE: parsed from the linker's .map file next to the binary).
    pub names: fn(&std::path::Path) -> std::collections::BTreeMap<u64, String>,
}

pub fn elf() -> Vec<Target> {
    vec![
        Target {
            name: "elf-x86_64".to_owned(),
            qemu_arch: "x86_64",
            os: "linux",
            main: "main",
            build: build_elf_x86_64,
            c_name: ident_str,
            base: ident_owned,
            names: no_names,
        },
        Target {
            name: "elf-aarch64".to_owned(),
            qemu_arch: "aarch64",
            os: "linux",
            main: "main",
            build: build_elf_aarch64,
            c_name: ident_str,
            base: ident_owned,
            names: no_names,
        },
    ]
}

fn build_elf_x86_64(opt: u8) -> PathBuf {
    build_elf("x86_64", opt)
}
fn build_elf_aarch64(opt: u8) -> PathBuf {
    build_elf("aarch64", opt)
}
fn build_pe_x86_64(opt: u8) -> PathBuf {
    build_pe("x86_64", opt)
}
fn build_pe_aarch64(opt: u8) -> PathBuf {
    build_pe("aarch64", opt)
}
fn ident_str(n: &str) -> String {
    n.to_owned()
}
fn ident_owned(n: String) -> String {
    n
}

pub fn pe() -> Vec<Target> {
    vec![
        Target {
            name: "pe-x86_64".to_owned(),
            qemu_arch: "x86_64",
            os: "windows",
            main: "main",
            build: build_pe_x86_64,
            c_name: ident_str,
            base: ident_owned,
            names: pe_names,
        },
        Target {
            name: "pe-aarch64".to_owned(),
            qemu_arch: "aarch64",
            os: "windows",
            main: "main",
            build: build_pe_aarch64,
            c_name: ident_str,
            base: ident_owned,
            names: pe_names,
        },
    ]
}

pub fn macho() -> Vec<Target> {
    fn x86_64_chained(opt: u8) -> PathBuf {
        build_macho("x86_64", true, opt)
    }
    fn x86_64_classic(opt: u8) -> PathBuf {
        build_macho("x86_64", false, opt)
    }
    fn arm64_chained(opt: u8) -> PathBuf {
        build_macho("arm64", true, opt)
    }
    fn arm64_classic(opt: u8) -> PathBuf {
        build_macho("arm64", false, opt)
    }
    fn under(n: &str) -> String {
        format!("_{n}")
    }
    fn ident(n: String) -> String {
        n
    }
    vec![
        Target {
            name: "macho-x86_64-chained".to_owned(),
            qemu_arch: "x86_64",
            os: "darwin",
            main: "_main",
            build: x86_64_chained,
            c_name: under,
            base: ident,
            names: no_names,
        },
        Target {
            name: "macho-x86_64-classic".to_owned(),
            qemu_arch: "x86_64",
            os: "darwin",
            main: "_main",
            build: x86_64_classic,
            c_name: under,
            base: ident,
            names: no_names,
        },
        Target {
            name: "macho-arm64-chained".to_owned(),
            qemu_arch: "aarch64",
            os: "darwin",
            main: "_main",
            build: arm64_chained,
            c_name: under,
            base: ident,
            names: no_names,
        },
        Target {
            name: "macho-arm64-classic".to_owned(),
            qemu_arch: "aarch64",
            os: "darwin",
            main: "_main",
            build: arm64_classic,
            c_name: under,
            base: ident,
            names: no_names,
        },
    ]
}

fn no_names(_: &std::path::Path) -> std::collections::BTreeMap<u64, String> {
    Default::default()
}

fn pe_names(exe: &std::path::Path) -> std::collections::BTreeMap<u64, String> {
    let map = exe.with_extension("map");
    let text =
        std::fs::read_to_string(&map).unwrap_or_else(|_| panic!("{} missing", map.display()));
    let mut out = std::collections::BTreeMap::new();
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some((i, _)) = words
            .iter()
            .enumerate()
            .find(|(_, w)| w.len() == 16 && u64::from_str_radix(w, 16).is_ok())
        else {
            continue;
        };
        let (Ok(addr), Some(name)) = (
            u64::from_str_radix(words[i], 16),
            words.get(i.saturating_sub(1)),
        ) else {
            continue;
        };
        if [
            "main",
            "bad_read",
            "bad_copy",
            "fill",
            "bad_fill",
            "bad_fmt_argv",
            "bad_fmt_args",
            "bad_fmt_filled",
            "bad_fmt_env",
            "bad_fmt_input",
            "bad_fmt_hook",
            "hook",
            "ok_fmt_wrapper",
            "mid_fmt_wrapper",
            "ok_fmt",
            "ok_fmt_choice",
            "ok_fmt_translated",
            "ok_fmt_long_double",
            "ok_fmt_after_import",
            "ok_fmt_arg_kept",
            "ok_fmt_kept",
            "ok_fmt_kept_across_leak",
            "sink",
            "set_fmt",
            "bad_fmt_escaped",
            "bad_fmt_global",
            "bad_strcpy",
            "ok_strcpy",
            "ok_read",
            "ok_copy",
            "ok_fill",
        ]
        .contains(name)
        {
            out.insert(addr, name.to_string());
        }
    }
    out
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/audit")
}

fn clang(target: &str) -> Command {
    let mut cc = Command::new(env!("BIARA_CLANG"));
    cc.arg(format!("--target={target}"));
    cc
}

fn build_elf(arch: &str, opt: u8) -> PathBuf {
    let lib_dir = tmp().join(format!("audit-elf-{arch}"));
    std::fs::create_dir_all(&lib_dir).unwrap();
    let status = clang(&format!("{arch}-linux-gnu"))
        .args([
            "-O2",
            "-fpic",
            "-nostdlib",
            "-shared",
            "-fno-stack-protector",
        ])
        .arg("-fuse-ld=lld")
        .arg(format!("--ld-path={}", linker().display()))
        .arg("-o")
        .arg(lib_dir.join("libc.so"))
        .arg(dir().join("libc.c"))
        .status()
        .unwrap();
    assert!(status.success(), "building the {arch} stand-in libc");
    let interp = match arch {
        "x86_64" => "/lib64/ld-linux-x86-64.so.2",
        _ => "/lib/ld-linux-aarch64.so.1",
    };
    let out = lib_dir.join(format!("prog-O{opt}"));
    let status = clang(&format!("{arch}-linux-gnu"))
        .args([
            "-nostdlib",
            "-fno-builtin",
            "-fno-stack-protector",
            &format!("-O{opt}"),
            "-fpie",
            "-pie",
            "-fuse-ld=lld",
        ])
        .arg(format!("-Wl,--dynamic-linker={interp}"))
        .arg("-Wno-format-security")
        .arg("-fuse-ld=lld")
        .arg(format!("--ld-path={}", linker().display()))
        .arg("-o")
        .arg(&out)
        .arg(dir().join("prog.c"))
        .arg(format!("-L{}", lib_dir.display()))
        .arg("-lc")
        .status()
        .unwrap();
    assert!(status.success(), "building the {arch} corpus at -O{opt}");
    out
}

fn build_pe(arch: &str, opt: u8) -> PathBuf {
    let lib_dir = tmp().join(format!("audit-pe-{arch}"));
    std::fs::create_dir_all(&lib_dir).unwrap();
    let (target, machine) = match arch {
        "x86_64" => ("x86_64-pc-windows-msvc", "x64"),
        _ => ("aarch64-pc-windows-msvc", "arm64"),
    };
    let lld_link = linker().with_file_name("lld-link");
    let cc = |file: &str, out: &str| {
        let status = clang(target)
            .args(["-O2", "-fno-stack-protector", "-c", "-o"])
            .arg(lib_dir.join(out))
            .arg(dir().join(file))
            .status()
            .unwrap();
        assert!(status.success(), "compiling {file} for {arch}");
    };
    // A DLL whose import library names the stand-ins.
    cc("libc.c", "libc.obj");
    let status = Command::new(&lld_link)
        .args([
            "/nologo",
            "/dll",
            "/noentry",
            &format!("/machine:{machine}"),
            "/export:printf",
            "/export:puts",
            "/export:getenv",
            "/export:read",
            "/export:memcpy",
            "/export:strcpy",
            "/export:dcgettext",
            &format!("/out:{}", lib_dir.join("libc.dll").display()),
            &format!("/implib:{}", lib_dir.join("libc.lib").display()),
            &format!("{}", lib_dir.join("libc.obj").display()),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "linking the {arch} stand-in DLL");
    let status = clang(target)
        .args(["-fno-stack-protector", &format!("-O{opt}"), "-c", "-o"])
        .arg(lib_dir.join(format!("prog-O{opt}.obj")))
        .arg(dir().join("prog.c"))
        .status()
        .unwrap();
    assert!(status.success(), "compiling the {arch} corpus at -O{opt}");
    let out = lib_dir.join(format!("prog-O{opt}.exe"));
    let status = Command::new(&lld_link)
        .args([
            "/nologo",
            &format!("/machine:{machine}"),
            "/entry:main",
            "/subsystem:console",
            "/map",
            &format!("/out:{}", out.display()),
            &format!("{}", lib_dir.join(format!("prog-O{opt}.obj")).display()),
            &format!("{}", lib_dir.join("libc.lib").display()),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "linking the {arch} corpus at -O{opt}");
    out
}

fn build_macho(arch: &str, fixups: bool, opt: u8) -> PathBuf {
    let lib_dir = tmp().join(format!("audit-macho-{arch}"));
    std::fs::create_dir_all(&lib_dir).unwrap();
    let target = format!("{arch}-apple-macos13");
    let ld64 = linker().with_file_name("ld64.lld");
    let platform = "-Wl,-platform_version,macos,13.0,13.0";
    std::fs::write(
        lib_dir.join("binder.c"),
        "void binder(void) __asm__(\"dyld_stub_binder\");\nvoid binder(void) {}\n",
    )
    .unwrap();
    let status = clang(&target)
        .args(["-O2", "-nostdlib", "-fno-stack-protector", "-dynamiclib"])
        .arg("-fuse-ld=lld")
        .arg(format!("--ld-path={}", ld64.display()))
        .arg(platform)
        .arg("-install_name")
        .arg("@rpath/libc.dylib")
        .arg("-o")
        .arg(lib_dir.join("libc.dylib"))
        .arg(dir().join("libc.c"))
        .arg(lib_dir.join("binder.c"))
        .status()
        .unwrap();
    assert!(status.success(), "building the {arch} stand-in dylib");
    let out = lib_dir.join(format!(
        "prog-O{opt}-{}",
        if fixups { "chained" } else { "classic" }
    ));
    let status = clang(&target)
        .args([
            "-nostdlib",
            "-fno-builtin",
            "-fno-stack-protector",
            &format!("-O{opt}"),
            "-Wno-format-security",
        ])
        .arg("-fuse-ld=lld")
        .arg(format!("--ld-path={}", ld64.display()))
        .arg(platform)
        .arg(if fixups {
            "-Wl,-fixup_chains"
        } else {
            "-Wl,-no_fixup_chains"
        })
        .arg("-o")
        .arg(&out)
        .arg(dir().join("prog.c"))
        .arg(lib_dir.join("libc.dylib"))
        .status()
        .unwrap();
    assert!(status.success(), "building the {arch} corpus at -O{opt}");
    out
}

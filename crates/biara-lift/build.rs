//! Compile cpp/*.cpp against the LLVM that llvm-sys links (same headers,
//! same compiler, -fno-rtti like LLVM itself).

use std::{env, path::PathBuf, process::Command};

fn llvm_config(arg: &str) -> String {
    let prefix =
        env::var("LLVM_SYS_231_PREFIX").expect("LLVM_SYS_231_PREFIX (see .cargo/config.toml)");
    let out = Command::new(PathBuf::from(prefix).join("bin/llvm-config"))
        .arg(arg)
        .output()
        .expect("run llvm-config");
    assert!(out.status.success(), "llvm-config {arg} failed");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn main() {
    println!("cargo:rerun-if-env-changed=LLVM_SYS_231_PREFIX");
    println!("cargo:rerun-if-changed=cpp/jump_tables.cpp");
    println!("cargo:rerun-if-changed=cpp/ranges.cpp");
    println!("cargo:rerun-if-changed=cpp/edge_ranges.h");
    println!("cargo:rerun-if-changed=cpp/abi_form.cpp");
    println!("cargo:rerun-if-changed=cpp/cgen.cpp");
    println!("cargo:rerun-if-changed=cpp/layouts.h");
    println!("cargo:rerun-if-changed=cpp/layouts.cpp");
    println!("cargo:rerun-if-changed=cpp/index_switches.cpp");
    println!("cargo:rerun-if-changed=cpp/trim.cpp");
    println!("cargo:rerun-if-changed=cpp/output.cpp");
    println!("cargo:rerun-if-changed=cpp/parallel.cpp");

    let bindir = PathBuf::from(llvm_config("--bindir"));
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .compiler(bindir.join("clang++"))
        .file("cpp/jump_tables.cpp")
        .file("cpp/ranges.cpp")
        .file("cpp/abi_form.cpp")
        .file("cpp/cgen.cpp")
        .file("cpp/index_switches.cpp")
        .file("cpp/trim.cpp")
        .file("cpp/output.cpp")
        .warnings(true)
        .flag_if_supported("-Wno-unused-parameter");
    let flags = llvm_config("--cxxflags");
    for flag in flags.split_whitespace() {
        build.flag(flag);
    }
    build.compile("biara_llvm_shim");

    // Fallible FFI helpers catch allocation/pass failures; worker helpers
    // also join their threads on every exit.
    let mut parallel = cc::Build::new();
    parallel
        .cpp(true)
        .compiler(bindir.join("clang++"))
        .file("cpp/parallel.cpp")
        .file("cpp/layouts.cpp")
        .warnings(true)
        .flag_if_supported("-Wno-unused-parameter");
    for flag in flags.split_whitespace() {
        parallel.flag(flag);
    }
    parallel.flag("-fexceptions").compile("biara_llvm_parallel");
}

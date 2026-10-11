// Bind the few liblzma streaming-decode symbols `xz::decode` needs.
// `pkg-config` style probing, without the `pkg-config` crate: try the
// compiler's default search paths first, then `pkg-config` if present.
fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=BIARA_LIBLZMA_DIR");
    let candidates = std::env::var_os("BIARA_LIBLZMA_DIR")
        .map(|d| vec![std::path::PathBuf::from(d)])
        .unwrap_or_default();
    for dir in candidates {
        println!("cargo::rustc-link-search=native={}", dir.display());
    }
    println!("cargo::rustc-link-lib=lzma");
}

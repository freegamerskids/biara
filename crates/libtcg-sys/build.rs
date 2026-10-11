use std::{env, path::PathBuf};

fn main() {
    let header = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../libtcg/libtcg.h")
        .canonicalize()
        .expect("libtcg/libtcg.h");
    println!("cargo:rerun-if-changed={}", header.display());

    // One shared object per guest architecture, loaded at runtime; the
    // generated `LibTcg` struct owns the libloading handle.
    bindgen::Builder::default()
        .header(header.to_str().unwrap())
        .dynamic_library_name("LibTcg")
        .dynamic_link_require_all(true)
        .allowlist_function("libtcg_.*")
        .allowlist_type("LibTcg.*")
        .wrap_unsafe_ops(true)
        .allowlist_var("LIBTCG_.*")
        .default_enum_style(bindgen::EnumVariation::Consts)
        .generate()
        .expect("bindgen libtcg.h")
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs"))
        .expect("write bindings");
}

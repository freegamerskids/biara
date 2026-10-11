//! Raw bindings to `libtcg/libtcg.h`. Load a library with
//! `unsafe { LibTcg::new(path) }`; every `libtcg_*` function is a method.
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
#![allow(clippy::missing_safety_doc, clippy::too_many_arguments)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

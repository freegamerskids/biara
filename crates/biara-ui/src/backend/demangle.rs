//! Readable names for mangled symbols.
//!
//! Three schemes cover almost everything: Rust (legacy `_ZN…17h<hash>E` and v0 `_R…`),
//! Itanium C++ (`_Z…`, also `__Z…` on Mach-O) and MSVC (`?…`). Each name gets two forms: the
//! [`full`](Demangled::full) one with parameters and the [`short`](Demangled::short) one without,
//! which is what dense views (lists, disassembly, graphs) print.

use cpp_demangle::{DemangleOptions, Symbol};

/// Longer symbols are left alone: pathological names make demanglers slow, and nothing real
/// is this long.
const MAX_LEN: usize = 4096;

/// A mangled name in readable form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Demangled {
    /// Without parameter or return types: `ns::Class::method`.
    pub short: String,
    /// With them: `ns::Class::method(int, char const*) const`.
    pub full: String,
}

/// The demangled form of `name`, or `None` if it is not a mangled name.
///
/// Decorations the UI and linkers add survive: `_ZN3foo3barEv@plt` becomes `foo::bar()@plt`.
pub fn demangle(name: &str) -> Option<Demangled> {
    if name.len() > MAX_LEN || name.len() < 3 {
        return None;
    }
    let (core, decoration) = ["@plt", "@got"]
        .iter()
        .find_map(|d| name.strip_suffix(d).map(|c| (c, *d)))
        .unwrap_or((name, ""));
    let (short, full) = if core.starts_with('?') {
        msvc(core)?
    } else if core.starts_with("_R") || core.starts_with("_ZN") || core.starts_with("__ZN") {
        rust(core).or_else(|| itanium(core))?
    } else if core.starts_with("_Z") || core.starts_with("__Z") {
        itanium(core)?
    } else {
        return None;
    };
    if full.is_empty() || full == core {
        return None;
    }
    Some(Demangled {
        short: format!("{short}{decoration}"),
        full: format!("{full}{decoration}"),
    })
}

/// Rust symbols. The hash (`::h0123456789abcdef`) is dropped: it distinguishes
/// instantiations but is noise when reading.
fn rust(name: &str) -> Option<(String, String)> {
    // Rust appends LLVM suffixes (`.llvm.123`, `.cold`) after the symbol proper.
    let core = name.split_once('.').map_or(name, |(c, _)| c);
    let core = core
        .strip_prefix('_')
        .filter(|c| c.starts_with("_ZN"))
        .unwrap_or(core);
    let d = rustc_demangle::try_demangle(core).ok()?;
    let text = format!("{d:#}");
    Some((text.clone(), text))
}

fn itanium(name: &str) -> Option<(String, String)> {
    // Mach-O prefixes every symbol with one more underscore.
    let name = name
        .strip_prefix("__Z")
        .map_or(std::borrow::Cow::Borrowed(name), |rest| {
            format!("_Z{rest}").into()
        });
    let symbol = Symbol::new(name.as_ref()).ok()?;
    let limit = |o: DemangleOptions| o.recursion_limit(96);
    let full = symbol
        .demangle_with_options(&limit(DemangleOptions::new()))
        .ok()?;
    let short = symbol
        .demangle_with_options(&limit(DemangleOptions::new().no_params().no_return_type()))
        .unwrap_or_else(|_| full.clone());
    Some((short, full))
}

fn msvc(name: &str) -> Option<(String, String)> {
    use msvc_demangler::{DemangleFlags, demangle};
    let full = demangle(name, DemangleFlags::llvm()).ok()?;
    let short = demangle(name, DemangleFlags::NAME_ONLY).unwrap_or_else(|_| full.clone());
    Some((short, full))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(name: &str) -> Demangled {
        demangle(name).unwrap_or_else(|| panic!("{name} did not demangle"))
    }

    #[test]
    fn itanium_names_have_a_short_and_a_full_form() {
        let m = d("_ZNK8geometry5Shape4areaEv");
        assert_eq!(
            (m.short.as_str(), m.full.as_str()),
            ("geometry::Shape::area", "geometry::Shape::area() const")
        );
        let v = d("_ZNSt6vectorIiSaIiEE9push_backERKi");
        assert_eq!(
            v.full,
            "std::vector<int, std::allocator<int> >::push_back(int const&)"
        );
        assert_eq!(v.short, "std::vector<int, std::allocator<int> >::push_back");
    }

    #[test]
    fn rust_legacy_hashes_are_dropped() {
        let m = d("_ZN4core3fmt5Write9write_fmt17h0123456789abcdefE");
        assert_eq!(
            (m.short.as_str(), m.full.as_str()),
            ("core::fmt::Write::write_fmt", "core::fmt::Write::write_fmt")
        );
        // An LLVM-added suffix does not defeat it.
        assert_eq!(
            d("_ZN4core3fmt5Write9write_fmt17h0123456789abcdefE.llvm.12345").short,
            "core::fmt::Write::write_fmt"
        );
    }

    #[test]
    fn rust_v0_names_demangle() {
        assert_eq!(d("_RNvCs1234_7mycrate4main").short, "mycrate::main");
    }

    #[test]
    fn msvc_names_demangle_with_and_without_signature() {
        let m = d("?area@Shape@geometry@@QEBAHXZ");
        assert!(
            m.full.contains("geometry::Shape::area") && m.full.contains("int"),
            "{}",
            m.full
        );
        assert_eq!(m.short, "geometry::Shape::area");
    }

    #[test]
    fn decorations_survive_and_clone_suffixes_are_shown() {
        assert_eq!(d("_ZN3foo3barEv@plt").short, "foo::bar@plt");
        assert_eq!(d("_ZN3foo3barEv@got").full, "foo::bar()@got");
        let cold = d("_ZN3foo3barEv.cold");
        assert!(
            cold.full.contains("foo::bar()") && cold.full.contains("cold"),
            "{}",
            cold.full
        );
        // macOS adds one underscore.
        assert_eq!(d("__ZN3foo3barEv").short, "foo::bar");
    }

    #[test]
    fn names_that_are_not_mangled_are_left_alone() {
        for name in [
            "main",
            "puts@plt",
            "_start",
            "__libc_start_main",
            "sub_401000",
            "_Z",
            "_ZZZ",
            "?",
            "",
            "_ZN",
        ] {
            assert_eq!(demangle(name), None, "{name}");
        }
        // Too long to be real.
        assert_eq!(demangle(&format!("_ZN{}E", "3foo".repeat(2000))), None);
    }
}

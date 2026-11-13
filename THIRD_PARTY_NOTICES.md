# Third-party notices

biara is MIT-licensed (`LICENSE`). It builds on, loads, or embeds the following. Rust crate
dependencies are all permissively licensed (MIT, Apache-2.0, BSD, ISC, Zlib, 0BSD, Unlicense or
similar, many as an `OR` choice); `cargo metadata` lists each one's license, and
`cargo install cargo-about && cargo about generate` produces the full attribution text to ship
with a binary release.

## Not MIT, and why it matters

| Component | License | How it is used |
| --- | --- | --- |
| QEMU 11.1.2 (`patches/`, built by `scripts/build-libtcg.sh`) | GPL-2.0-or-later | Downloaded and patched at build time, not vendored. The patch is GPL; the built `libtcg-<arch>.so` and `helpers-<arch>.bc` are GPL. See `patches/README.md`. |
| `libtcg/libtcg.c`, `libtcg/libtcg.h` | MIT | Written for this project. `libtcg.c` is compiled into the GPL QEMU build, so the shared object it becomes is GPL. The licensor asserts that it contains no code copied from QEMU. |
| `spellbook` (via Rune) | MPL-2.0 | Unmodified dependency. MPL's copyleft is per file and does not reach biara's code. |

## Embedded in `biara-ui` binaries

- **Inter** and **IBM Plex Mono** fonts (through Rune's `rune-theme-opencode`): SIL Open Font
  License 1.1. The license texts are in `licenses/`. A binary release must ship them.
- **Rune** (UI toolkit, `github.com/anomalyco/rune`): MIT, Copyright (c) 2026 Anomaly. Its
  patched forks of `winit`, `wgpu-hal`, `parley_engine`, `accesskit_windows` keep their own
  licenses (Apache-2.0 / MIT).

## Linked or loaded at run time

- **LLVM 23.1.2** (through `inkwell`, MIT): Apache-2.0 WITH LLVM-exception.
- **inkwell**: MIT.

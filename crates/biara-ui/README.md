# biara-ui

An interactive binary-analysis workbench on the biara engine, drawn with
[Rune](https://github.com/anomalyco/rune) (a GPU-rendered Rust UI toolkit). It is the
IDA-style front end for what `biara lift` computes: functions, a linear disassembly, a
control-flow graph, decompiled pseudocode, cross-references, strings and a hex view, all
navigable by address, name or click.

```sh
scripts/build-libtcg.sh x86_64 aarch64     # once: the QEMU lifters
cargo run --release -p biara-ui -- /usr/lib64/libc.so.6
cargo run --release -p biara-ui            # empty window: Open…, or drop a file on it
```

x86-64 and AArch64 binaries open (ELF, and PE as exercised on a Windows DLL); the window shows the function list (from symbols)
immediately and fills in as recovery finishes. Reopening a binary resumes from the engine's
cache, so a library that took 20 s to analyse the first time opens in about 4 s.

## Views

| View | What it shows |
| --- | --- |
| Disassembly | Every recovered instruction in address order, with function headers, labels with the jumps that reach them, string and symbol annotations, and clickable targets. |
| Graph | The current function's basic blocks as boxes of disassembly. Green is a taken branch, red a branch not taken, blue plain flow, amber a jump-table case. The current block is outlined. Pan by dragging or scrolling; zoom with Ctrl+scroll or a pinch. |
| Pseudocode | The decompiler's C. Calls and globals link to their targets; renames apply by address without decompiling again; clicking an identifier highlights every use. |
| Hex | The mapped image as 16-byte rows. Works before analysis finishes. |

The sidebar lists functions, imports, strings and segments, each filterable. The bottom panel
lists cross-references to the address under the cursor (calls, jumps and data references,
with the referring instruction) and the output log.

### Demangled names

C++ (Itanium and MSVC) and Rust (legacy and v0) symbols are shown readably everywhere a name
is printed. Dense views (function list, disassembly, graph, cross-references, pseudocode) use
the short form without parameters, `geometry::Shape::area`; a function's header in the
disassembly shows the full signature, `geometry::Shape::area() const`, with the linker's name
beside it. Pseudocode locals named after a mangled callee follow (`geometry::Shape::area_result`).
Search (go to, the sidebar filter, `--goto`) matches the demangled forms and the raw name, so
either spelling finds the symbol. A name you give with rename always wins, and the saved
annotations only ever hold raw names and your own. "Toggle demangled names" in the command
palette (`Ctrl+K`) switches to raw linker names and back.

## Keys

| Key | Action |
| --- | --- |
| `G` | Go to an address, function, import or string |
| `N` | Rename the symbol under the cursor |
| `X` | Show cross-references |
| `Space` | Toggle disassembly and graph |
| `F5` | Toggle pseudocode |
| `Up` / `Down` | Move the cursor (disassembly rows, hex rows) |
| `Esc` / `Alt+Left` | Back |
| `Alt+Right` | Forward |
| `Ctrl+K` | Command palette |
| `Ctrl+O` | Open a binary |

Names you give are saved in the engine's annotation format under
`$XDG_DATA_HOME/biara/names/`, so `biara lift --annotations <file>` reads them.

## Layout of the code

- `src/backend/` has no UI dependency and runs under `cargo test`.
  - `recovery`: opens a binary on a thread and reports stages as events. The engine's worker
    processes are copies of this executable (`main` answers `__worker`).
  - `program`: the recovered program and its indexes (functions, cross-references in both
    directions, strings, names).
  - `listing`, `flow`, `graph`: the models behind the disassembly, the per-function graph,
    and the layered layout (cycle removal, layering, crossing reduction, exact least-squares
    placement, orthogonal routing).
  - `disasm`: `iced-x86` and `yaxpeax-arm`, normalised to coloured spans with flow and targets.
  - `decomp`: a background decompiler, newest request first, results cached.
  - `names`: user renames.
  - `demangle`: Itanium, MSVC and Rust names, in a short and a full form.
- `src/ui/` is the window: state and navigation in `mod.rs`, one module per view, and the
  shell widgets. Views are plain functions of `&App`.

## Command line and headless checks

```text
biara-ui [BINARY] [--sync] [--goto ADDR|NAME] [--tab listing|graph|pseudo|hex]
```

`--sync` waits for analysis before the first frame. Rune's headless tooling then works as for
any Rune app:

```sh
biara-ui prog --sync --goto main --tab graph --snap graph.png --size 1440x880
biara-ui prog --sync --tree tree.json
```

## Tests

```sh
cargo test -p biara-ui                 # unit, backend (real compiled fixtures) and UI interaction
BIARA_UI_BIG=/usr/lib64/libc.so.6 cargo test -p biara-ui --release --test backend -- --ignored --nocapture
```

The UI tests drive the real app state through Rune's headless runtime with typed keys, clicks
and a scripted file dialog.

## Known gaps

- Mach-O has not been exercised in the UI.
- The graph view shows functions of up to 1,500 blocks; larger ones use the other views.
- Renames apply to functions and named data, not to local variables or struct fields.
- Demangled names are for reading: they are not valid C identifiers, and rename still takes
  plain identifiers. Rust's legacy scheme is covered by unit tests and an asm-labelled symbol;
  the current rustc only writes v0.
- Recovery occasionally lifts a stray byte that is not code (94 single `0x1f` bytes in libc);
  the listing shows them honestly as `db`.

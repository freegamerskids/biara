<h1 align="center">biara</h1>

<p align="center">
  <b>A binary analyser built on QEMU's lifter and LLVM.</b><br>
  Machine code in; control flow, calling conventions, types and readable C out.
</p>

<p align="center">
  <img src="docs/images/pseudocode.png" alt="biara-ui showing the decompiled pseudocode of a function with a jump table recovered as a switch" width="860">
</p>

biara reads an executable, lifts its machine code through **QEMU's TCG frontends** into **LLVM
IR**, and recovers what a reverse engineer wants from it: functions and basic blocks, jump
tables and indirect-call targets, stack frames and calling conventions, struct layouts, and
decompiled C. You can drive it from the **command line** (JSON for scripts and agents) or from
a **desktop workbench** in the spirit of IDA, drawn on the GPU.

Because the lifting is QEMU's, instruction semantics come from the same code that runs real
guests rather than from a hand-written model.

- **Formats:** ELF, PE (including DLL exports, TLS callbacks, Guard CF tables) and Mach-O
- **Architectures:** x86-64 and AArch64
- **Recovery:** jump tables, indirect-call candidates with exhaustiveness, unwind and
  function-start tables, code pointers, exports, DWARF names and parameters
- **Analyses:** ABI and stack frames, inferred struct layouts and typed signatures, call
  arguments at imports, and a security audit (format strings, writes past a frame)
- **Resumable:** recovery commits to a content-addressed SQLite store; interrupt a run and rerun
  the same command to continue, reopen a binary and it is ready in seconds
- **Names:** C++ (Itanium, MSVC) and Rust (legacy, v0) symbols are demangled in the UI

## See it work

`examples/sample` is a small program with a jump table, a table of function pointers, a
recursive function and two deliberate bugs. Build it and ask biara about it (`biara` here is
`target/release/biara`; `cargo run --release -p biara-cli --` works in its place):

```sh
examples/sample/build.sh                      # -> target/sample/sample
biara lift target/sample/sample --emit audit
```

```text
0x400856 in 0x400850 <hello>: printf: format string (argument 0) comes from the command line: [rsi@entry+0x10] in 0x4003e0 <main>; via 0x400528 in 0x4003e0 <main>
0x40088e in 0x400880 <read_name>: read: writes up to 0x40 bytes to sp-0x18, past the caller's frame
```

Those are the two planted bugs and nothing else. The `calc` function is a `switch` compiled to
a jump table; biara finds all eight targets and emits it as one:

```sh
biara lift target/sample/sample calc --emit decomp
```

```c
uint64_t calc(uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
    uint64_t value0;

    value0 = (uint32_t)arg0;
    if (value0 > 7) {
        return -1;
    }
    switch (value0) {
    case 0:
        return arg1 + arg2;
    case 1:
        return arg1 - arg2;
    case 2:
        return arg2 * arg1;
    case 3:
        if (arg2 == 0) {
            return 0;
        }
        return (uint64_t)((int64_t)arg1 / (int64_t)arg2);
    /* ... cases 4 to 6 ... */
    case 7:
    default:
        return arg1 ^ arg2;
    }
}
/* Analysis evidence:
 * ABI: converged; frame 0 bytes; balanced true; unknown SP blocks []
 * indirect at 0x40073c: candidates [4196168,4196176,...]; exhaustive true
 */
```

Every result carries its evidence, so you can tell a proven fact from a guess.

## Install

Hosts are Linux x86-64 and macOS arm64 (Apple silicon). Install the latest successful build of
`main` into `~/.local/share/biara`, with `biara` and `biara-ui` linked into `~/.local/bin` (added
to your shell's `PATH` if missing):

```sh
curl -fsSL https://raw.githubusercontent.com/freegamerskids/biara/main/scripts/install.sh | sh
biara update                     # later: the latest successful build of main
biara update --branch my-branch  # or of another branch
```

Every successful build of a branch replaces the assets of its pre-release `build-<branch>` on the
[releases page](https://github.com/freegamerskids/biara/releases), which is where the script
downloads from (no GitHub sign-in). `scripts/install.sh --help` lists its options (`--home`,
`--bin`, `--archive FILE` for an archive you already have, `--no-modify-path`).

Tagged versions are also on the [releases page](https://github.com/freegamerskids/biara/releases);
unpack one and run `biara` or `biara-ui` from it (the lifters sit next to them). On macOS, clear
the download quarantine first: `xattr -dr com.apple.quarantine biara-*-arm64-macos`.

To build, the toolchain is pinned and fetched for you:

| Piece | Version | Where it comes from |
| --- | --- | --- |
| QEMU | 11.1.2 | downloaded by `scripts/fetch-deps.sh`, patched and built as `libtcg-<arch>.so` (`.dylib` on macOS) |
| LLVM | 23.1.2 | prebuilt release, unpacked into `.deps/` (several GB) |
| Rust | recent stable (edition 2024) | your `rustup` |

You also need what QEMU's build needs: Python 3, `ninja`, glib development headers, plus `curl`
and `zstd`. On macOS: `brew install ninja glib pkgconf zstd xz`.

```sh
scripts/fetch-deps.sh                 # download and verify QEMU and LLVM into .deps/
scripts/build-libtcg.sh               # build the lifters (x86_64 and aarch64; pass names for one)
cargo build --release                 # target/release/biara and target/release/biara-ui
```

The helper bitcode (`helpers-<arch>.bc`) is built on Linux only: it is compiled for the x86-64
analysis target, and QEMU's helpers contain host-specific code. On macOS, copy the
`helpers-*.bc` of a Linux build or a release archive into `.deps/out/`, and point the pinned
clang at the SDK before building:

```sh
export SDKROOT=$(xcrun --show-sdk-path)
```

`.cargo/config.toml` points the build at `.deps/`, so `cargo run` and `cargo test` just work, and
the built binaries find the lifters in `.deps/out` (`BIARA_LIBTCG_DIR` overrides that).

## Command line

```sh
biara lift  <BINARY> [ADDR|NAME...] --emit <KIND> [--format text|json|jsonl]
biara diff  <OLD> <NEW>                # match functions between two builds by their code
biara quality <REFERENCE> <CANDIDATE>  # function and edge recall vs. a symbol-bearing oracle
biara worker [JOB.json]                # run one JSON job (for hosting the engine)
biara mcp   [BINARY]                   # serve one binary to an AI agent over MCP/stdio
biara update [--branch NAME]           # reinstall from a branch's latest build (installs only)
```

`lift` takes optional start points (an address or a symbol); with none it analyses the whole
program from the entry point, symbols, exports and unwind tables.

| `--emit` | You get |
| --- | --- |
| `llvm` (default) | LLVM IR, textual; `-O1`..`-O3` optimise it, `--link-helpers` inlines QEMU's helpers |
| `tcg` | QEMU's TCG ops per translation block |
| `c` | Compilable C with recovered calling conventions and stack frames |
| `decomp` | Readable function bodies, dependencies and the evidence behind them |
| `cfg` | Functions, blocks and their exits |
| `abi` | Per function: frame, register arguments, return values, clobbers |
| `calls` | Calls to imports and what their arguments hold |
| `types` | Inferred struct layouts and typed signatures |
| `audit` | Non-constant format strings and writes past declared objects |

Useful flags: `--database` (resume file), `--jobs`, `--memory-mib` (analysis budget, default
4096), `--annotations` (your names, local names, signatures, struct layouts and comments, JSON or
TOML; the workbench and `biara mcp` save this format), and
`--format json|jsonl` for a versioned schema with numeric addresses.

## MCP

`biara mcp` serves one open binary to an AI agent over the Model Context Protocol's stdio
transport: newline-delimited JSON-RPC 2.0 on stdout, diagnostics on stderr. It speaks the
stateless 2026-07-28 revision (`server/discover`, the protocol version in every request's
`_meta`, `resultType` and `serverInfo` on results) and the legacy `initialize` handshake of
2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05, including `ping`.

```sh
biara mcp target/sample/sample
```

An MCP client launches it as a subprocess:

```json
{
  "mcpServers": {
    "biara": {
      "command": "/path/to/biara",
      "args": ["mcp", "/path/to/binary"]
    }
  }
}
```

The binary is optional; the `open` tool switches to another one. Recovery runs in the
background, and every tool that needs the program waits for it (`wait_seconds`, default 60,
maximum 600) or returns the current stage so the agent can call again.

| Tool | What it does |
| --- | --- |
| `status` | Binary, architecture, format, entry point, stage, counts, notes file |
| `open` | Switch to another binary |
| `list_functions`, `list_imports`, `list_strings`, `list_segments` | Paged tables |
| `list_structs`, `struct_layouts` | Declared structs; the structs one function's pointers reach |
| `function_info` | Names, size, frame, arguments, signature, locals, comments, callers, callees |
| `decompile` | Pseudocode with your names and comments applied, paged by line |
| `disassemble` | Instructions with symbol and comment annotations |
| `xrefs_to`, `xrefs_from` | Cross-references, with the instruction text |
| `read_bytes`, `search_bytes` | Hex dump and wildcard byte search |
| `rename_function`, `rename_data`, `rename_local`, `set_comment` | Write names and comments |
| `set_signature`, `declare_struct`, `struct_from_param`, `rename_field` | Declare function signatures, structs and field names |
| `list_notes` | Everything written about the binary |

Names, local renames and comments apply when a line is drawn, so they show up without
re-analysis; a declared signature or struct re-decompiles affected functions. Recovered
struct names (`s1`, `f_8`) live only for one decompile: `struct_from_param` declares a struct
from the layout behind a parameter and types that parameter `struct name *`, and that
signature is what binds the declaration to the code and makes its field names visible.
Everything is saved in the same notes file the workbench uses, so a human editing in
`biara-ui` and an agent in `biara mcp` see each other's changes. The protocol stream owns
fd 1; fd 1 is pointed at stderr at startup so no engine or LLVM output can corrupt it.

## Desktop workbench

```sh
cargo run --release -p biara-ui -- /path/to/binary
cargo run --release -p biara-ui                  # empty window: Open…, or drop a file on it
```

<p align="center">
  <img src="docs/images/graph.png" alt="biara-ui control-flow graph of a recursive function" width="860">
</p>

| View | What it shows |
| --- | --- |
| Disassembly | Every recovered instruction, with function headers, labels with their incoming jumps, string and symbol annotations, clickable targets |
| Graph | The function's basic blocks as boxes with typed edges (taken, not taken, plain, jump-table case); pan and zoom |
| Pseudocode | Decompiled C; calls and globals link to their targets; renames (locals too) and comments apply instantly |
| Hex | The mapped image as 16-byte rows; works before analysis finishes |

The sidebar lists functions, imports, strings and segments, each filterable; the bottom panel
shows cross-references. `G` goes to an address or name, `N` renames, `;` comments, `Y` sets a
signature, `X` shows references,
`Space` flips between disassembly and graph, `F5` opens pseudocode, `Ctrl+K` opens a command
palette. It stays at 0% CPU when idle. See [`crates/biara-ui/README.md`](crates/biara-ui/README.md)
for every key, the architecture and the headless testing options.

## How it works

```mermaid
flowchart LR
    B[binary] --> L[loader<br>segments, symbols, imports]
    L --> T[libtcg<br>QEMU TCG frontend]
    T --> C[CFG recovery<br>jump tables, indirect calls]
    C --> I[LLVM IR lowering]
    I --> A[ABI, types, audit]
    A --> D[decompiler]
    C -.checkpoints.-> S[(SQLite store)]
    D --> O[CLI / JSON]
    D --> U[biara-ui]
```

Recovery runs in isolated worker processes, so a crash or runaway in one does not take the
engine down, and it commits translated blocks to the store as it goes. That is what makes a run
resumable and a reopen cheap. (There is no sandbox: biara never executes the binary, but its
bytes do pass through QEMU's frontends, so treat hostile input accordingly.)

| Crate | Role |
| --- | --- |
| `libtcg-sys`, `biara-tcg` | Runtime-loaded bindings to `libtcg-<arch>.so`/`.dylib` and a safe TCG IR |
| `biara-loader` | ELF, PE and Mach-O: segments, symbols, imports, function starts, DWARF |
| `biara-cfg` | Control-flow recovery over translation blocks |
| `biara-abi` | Stack frames and calling conventions |
| `biara-lift` | TCG to LLVM IR lowering, analyses, type inference, C and decompiler output |
| `biara-engine` | Persistent, process-isolated recovery with a memory budget |
| `biara-diff` | Function matching between two binaries |
| `biara-proto` | Shared formats: annotations, job bundles, diff results |
| `biara-session` | One open binary for interactive clients: background recovery, indexes, decompiler cache, notes |
| `biara-cli` | The `biara` command, including the MCP server |
| `biara-ui` | The desktop workbench, on [Rune](https://github.com/anomalyco/rune) |

`libtcg/` and `patches/` hold the small patch that turns QEMU's translator into a library.

## Performance

Cold run, release build, 6-core desktop CPU, default settings:

| Binary | Size | Work | Time |
| --- | --- | --- | --- |
| `/usr/bin/ls` | 150 KB | `--emit cfg` | 0.5 s |
| `/usr/bin/bash` | 1.5 MB | `--emit cfg` | 5 s |
| glibc (`libc.so.6`) | 2.5 MB | open in the UI, 319k instructions | about 15 s cold, about 4 s on reopen |

Very large binaries (tens of MB) can take a long time and a lot of memory. `--memory-mib` caps
the analysis and the store lets an interrupted run resume.

Decompiling one function costs about its size: a 69,000-block obfuscated function (35 MB of C)
takes under a minute, most of it in LLVM's own passes.

## Limits

biara is young.

- Mach-O loads on the command line but has not been exercised in the UI.
- The graph view handles functions up to 1,500 blocks; larger ones use the other views.
- Struct fields can be renamed only in a struct some function parameter points at: naming
  one declares it and types that parameter `struct name *` in the function's signature.
- Recovery sometimes lifts a stray non-code byte (94 in all of glibc); the listing shows `db`.
- Hosts are Linux x86-64 and macOS arm64; guests are x86-64 and AArch64.

## Tests

```sh
cargo test --workspace
BIARA_UI_BIG=/usr/lib64/libc.so.6 cargo test -p biara-ui --release --test backend -- --ignored --nocapture
```

The tests build real programs with the pinned clang and analyse them end to end, including
AArch64 cross-builds, a Windows DLL, a freestanding C++ and a `no_std` Rust binary. The UI tests
drive the app through Rune's headless runtime with typed keys and clicks.

## License

biara is [MIT](LICENSE) licensed, with one exception that matters if you distribute builds:
QEMU is GPL, so the patches in `patches/` are GPL-2.0-or-later, and the `libtcg-<arch>`
libraries and helper bitcode built from them are GPL binaries. The Rust code only loads them at run time. Details
in [`patches/README.md`](patches/README.md) and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

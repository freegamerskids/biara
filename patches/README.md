# QEMU patches: GPL-2.0-or-later

The rest of this repository is MIT (see `../LICENSE`). Everything in this directory is not.

`qemu-11.1.2/0001-libtcg.patch` modifies QEMU source files (`accel/tcg/translator.c`,
`include/exec/translator.h`, `meson.build`). QEMU is licensed under the GNU GPL, version 2 or
(for these files) any later version, and a modification of those files is a derivative work
under the same terms. The patch is therefore **GPL-2.0-or-later**, not MIT. QEMU's own license
text is in `qemu-11.1.2/COPYING`.

Consequence for distributing builds: `scripts/build-libtcg.sh` compiles `libtcg/libtcg.c`
inside the patched QEMU tree. The resulting `libtcg-<arch>.so` and the `helpers-<arch>.bc`
bitcode (compiled from QEMU's helper sources) are GPL-licensed binaries. Whoever distributes
them must also offer the corresponding source: the QEMU release tarball named in
`scripts/versions.sh`, this patch, and `libtcg/`.

The Rust code never links against QEMU. It loads `libtcg-<arch>.so` at run time (`libloading`)
across the plain C ABI in `libtcg/libtcg.h`, so the Rust binaries themselves stay MIT. The
repository does not contain QEMU's source; `scripts/fetch-deps.sh` downloads it.

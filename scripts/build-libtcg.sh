#!/usr/bin/env bash
# Build libtcg-<arch>.so and helpers-<arch>.bc from the pinned QEMU plus
# patches/qemu-<ver>/ and libtcg/. Outputs land in .deps/out/.
#
# Usage: scripts/build-libtcg.sh [target ...]   (default: x86_64 aarch64)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/versions.sh"

if (($#)); then targets=("$@"); else targets=(x86_64 aarch64); fi
target_list=$(printf '%s-linux-user,' "${targets[@]}")
target_list=${target_list%,}

[[ -x $LLVM_PREFIX/bin/clang ]] || { echo "run scripts/fetch-deps.sh first" >&2; exit 1; }
tarball="$DEPS/dl/qemu-$QEMU_VERSION.tar.xz"
[[ -f $tarball ]] || { echo "run scripts/fetch-deps.sh first" >&2; exit 1; }

# (Re)create the patched source tree when the patch set changes.
patches=("$ROOT"/patches/qemu-"$QEMU_VERSION"/*.patch)
stamp=$(cat "${patches[@]}" | sha256sum | cut -d' ' -f1)
if [[ ! -f $QEMU_SRC/.biara-stamp || $(cat "$QEMU_SRC/.biara-stamp") != "$stamp" ]]; then
    rm -rf "$QEMU_SRC" "$QEMU_BUILD"
    mkdir -p "$QEMU_SRC"
    tar -xf "$tarball" -C "$QEMU_SRC" --strip-components=1
    for p in "${patches[@]}"; do
        patch -d "$QEMU_SRC" -p1 --quiet < "$p"
    done
    ln -s "$ROOT/libtcg" "$QEMU_SRC/libtcg"
    echo "$stamp" > "$QEMU_SRC/.biara-stamp"
fi

if [[ ! -f $QEMU_BUILD/build.ninja ]] \
    || [[ $(cat "$QEMU_BUILD/.biara-targets" 2>/dev/null) != "$target_list" ]]; then
    rm -rf "$QEMU_BUILD"
    mkdir -p "$QEMU_BUILD"
    # TCI as the host backend: no host vector ops and a small optional-op
    # set, so the frontend emits the generic TCG the lifter understands.
    # b_staticpic: the target objects are linked into a shared library.
    (cd "$QEMU_BUILD" && "$QEMU_SRC/configure" \
        --target-list="$target_list" \
        --cc="$LLVM_PREFIX/bin/clang" \
        --cxx="$LLVM_PREFIX/bin/clang++" \
        --objcc="$LLVM_PREFIX/bin/clang" \
        -Db_staticpic=true \
        --without-default-features \
        --enable-tcg-interpreter \
        --disable-plugins \
        --disable-docs \
        --disable-werror)
    echo "$target_list" > "$QEMU_BUILD/.biara-targets"
fi

ninja -C "$QEMU_BUILD" $(printf 'libtcg-%s.so ' "${targets[@]}")

mkdir -p "$OUT"
for t in "${targets[@]}"; do
    cp "$QEMU_BUILD/libtcg-$t.so" "$OUT/"
    python3 "$ROOT/scripts/helper-bitcode.py" \
        --build "$QEMU_BUILD" --target "$t" \
        --clang "$LLVM_PREFIX/bin/clang" \
        --llvm-link "$LLVM_PREFIX/bin/llvm-link" \
        --out "$OUT/helpers-$t.bc"
done
ls -l "$OUT"

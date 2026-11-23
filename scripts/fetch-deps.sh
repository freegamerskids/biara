#!/usr/bin/env bash
# Download the pinned QEMU source and unpack the pinned LLVM release into .deps/.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/versions.sh"

fetch() {
    local url=$1 sha=$2 dest=$3
    if [[ -f $dest ]] && echo "$sha  $dest" | sha256_check -c --status; then
        return
    fi
    curl -fL --retry 3 -o "$dest.part" "$url"
    echo "$sha  $dest.part" | sha256_check -c --quiet
    mv "$dest.part" "$dest"
}

mkdir -p "$DEPS/dl"

fetch "$QEMU_URL" "$QEMU_SHA256" "$DEPS/dl/qemu-$QEMU_VERSION.tar.xz"

fetch "$LLVM_URL" "$LLVM_SHA256" "$DEPS/dl/$LLVM_ASSET"
if [[ ! -x $LLVM_PREFIX/bin/llvm-config ]]; then
    rm -rf "$LLVM_PREFIX"
    mkdir -p "$LLVM_PREFIX"
    # The release archive uses a 1 GiB zstd window.
    zstd -dc --long=31 "$DEPS/dl/$LLVM_ASSET" \
        | tar -x -C "$LLVM_PREFIX" --strip-components=1
fi

# The macOS release also ships its own libc++ (headers and libraries),
# libc++abi and libunwind. The link searches LLVM's lib/ first (llvm-sys) and
# would take them; its newer headers call into a libc++ macOS does not have.
# Without them the pinned clang uses the SDK's, like the system's library.
if [[ $(uname -s) == Darwin ]]; then
    rm -rf "$LLVM_PREFIX"/include/c++ "$LLVM_PREFIX"/lib/libc++* "$LLVM_PREFIX"/lib/libunwind*
    # LLVM wants zstd and biara-loader liblzma, which macOS lacks. Offer only
    # Homebrew's static archives (.cargo/config.toml searches here first), so
    # the binaries run without Homebrew.
    mkdir -p "$DEPS/macos-static"
    ln -sf "$(brew --prefix zstd)/lib/libzstd.a" "$(brew --prefix xz)/lib/liblzma.a" \
        "$DEPS/macos-static/"
fi

# llvm-sys runs $LLVM_SYS_231_PREFIX/bin/llvm-config. The release builds
# report zstd as an absolute path on their build machine; rewrite it to
# -lzstd.
mkdir -p "$LLVM_SYS_PREFIX/bin"
cat > "$LLVM_SYS_PREFIX/bin/llvm-config" <<EOF
#!/bin/sh
"$LLVM_PREFIX/bin/llvm-config" "\$@" | sed 's#[^ ]*/libzstd\.a#-lzstd#g'
EOF
chmod +x "$LLVM_SYS_PREFIX/bin/llvm-config"

echo "qemu $QEMU_VERSION: $DEPS/dl/qemu-$QEMU_VERSION.tar.xz"
echo "llvm $("$LLVM_PREFIX/bin/llvm-config" --version): $LLVM_PREFIX"

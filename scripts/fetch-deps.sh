#!/usr/bin/env bash
# Download the pinned QEMU source and unpack the pinned LLVM release into .deps/.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/versions.sh"

fetch() {
    local url=$1 sha=$2 dest=$3
    if [[ -f $dest ]] && echo "$sha  $dest" | sha256sum -c --status; then
        return
    fi
    curl -fL --retry 3 -o "$dest.part" "$url"
    echo "$sha  $dest.part" | sha256sum -c --quiet
    mv "$dest.part" "$dest"
}

mkdir -p "$DEPS/dl"

fetch "$QEMU_URL" "$QEMU_SHA256" "$DEPS/dl/qemu-$QEMU_VERSION.tar.xz"

fetch "$LLVM_URL" "$LLVM_SHA256" "$DEPS/dl/LLVM-$LLVM_VERSION-Linux-X64.tar.zst"
if [[ ! -x $LLVM_PREFIX/bin/llvm-config ]]; then
    rm -rf "$LLVM_PREFIX"
    mkdir -p "$LLVM_PREFIX"
    # The release archive uses a 1 GiB zstd window.
    zstd -dc --long=31 "$DEPS/dl/LLVM-$LLVM_VERSION-Linux-X64.tar.zst" \
        | tar -x -C "$LLVM_PREFIX" --strip-components=1
fi

# llvm-sys runs $LLVM_SYS_231_PREFIX/bin/llvm-config. The release build
# reports zstd as an absolute Ubuntu path; rewrite it to -lzstd.
mkdir -p "$LLVM_SYS_PREFIX/bin"
cat > "$LLVM_SYS_PREFIX/bin/llvm-config" <<EOF
#!/bin/sh
"$LLVM_PREFIX/bin/llvm-config" "\$@" | sed 's#[^ ]*/libzstd\.a#-lzstd#g'
EOF
chmod +x "$LLVM_SYS_PREFIX/bin/llvm-config"

echo "qemu $QEMU_VERSION: $DEPS/dl/qemu-$QEMU_VERSION.tar.xz"
echo "llvm $("$LLVM_PREFIX/bin/llvm-config" --version): $LLVM_PREFIX"

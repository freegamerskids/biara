# Pinned toolchain versions. Sourced by the other scripts.
# Bumping a version: update the sha256, rebase patches/qemu-<ver>/, and
# update LLVM_SYS_*_PREFIX / the inkwell feature in .cargo/config.toml and
# Cargo.toml.

QEMU_VERSION=11.1.2
QEMU_URL="https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz"
QEMU_SHA256=731b5681e4bb18be313231579b8efd0296c5b015fa36dc533874b639ba838016

LLVM_VERSION=23.1.2
LLVM_URL="https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/LLVM-${LLVM_VERSION}-Linux-X64.tar.zst"
LLVM_SHA256=6382de1c1a210ce5a5cc49d18bc8444d137742e7cbf9b19f4ae602bb1ab52534

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPS="$ROOT/.deps"
LLVM_PREFIX="$DEPS/llvm-$LLVM_VERSION"
# llvm-config wrapper consumed by llvm-sys (see fetch-deps.sh).
LLVM_SYS_PREFIX="$DEPS/llvm-sys-$LLVM_VERSION"
QEMU_SRC="$DEPS/build/qemu-src-$QEMU_VERSION"
QEMU_BUILD="$DEPS/build/qemu-$QEMU_VERSION"
OUT="$DEPS/out"

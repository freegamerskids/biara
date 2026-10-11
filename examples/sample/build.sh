#!/usr/bin/env bash
# Build the sample program into target/sample/: `sample` (with symbols) and
# `sample.stripped`. Uses the system C compiler and C library, so the result
# also runs. No stack protector or fortified libc calls, so the planted bugs
# stay plain calls to read/printf.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
out="$root/target/sample"
mkdir -p "$out"
"${CC:-cc}" -O2 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
    -Wno-format-security -Wno-stringop-overflow -o "$out/sample" "$root/examples/sample/sample.c"
strip -o "$out/sample.stripped" "$out/sample"
echo "$out/sample"
echo "$out/sample.stripped"

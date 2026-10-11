#!/usr/bin/env python3
"""Compile a target's TCG helper sources to LLVM bitcode and link them.

Reuses the exact compile commands meson recorded for libtcg-<target>.so
(compile_commands.json), so the bitcode matches the shared library's helpers.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor


def wanted(entry, target):
    out = entry["output"]
    src = entry["file"]
    if out.startswith(f"libqemu-{target}-linux-user.a.p/"):
        if "/target/" not in src:
            return False
        name = os.path.basename(src)
        # Translator and CPU-model glue carry no helper_* definitions.
        return name not in ("translate.c", "tcg-cpu.c", "gdbstub.c", "cpu-dump.c")
    if out.startswith("libuser.a.p/"):
        return os.path.basename(src) in ("tcg-runtime.c", "tcg-runtime-gvec.c")
    if out.startswith("libcommon.a.p/"):
        return src.endswith("fpu/softfloat.c")
    return False


def to_bitcode(entry, clang, dest):
    args = shlex.split(entry["command"])[1:]
    keep = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in ("-o", "-MQ", "-MF"):
            skip = True
            continue
        if a in ("-c", "-MD", "-g"):
            continue
        keep.append(a)
    cmd = [clang, *keep, "-c", "-emit-llvm", "-o", dest]
    r = subprocess.run(cmd, cwd=entry["directory"], capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        raise SystemExit(f"bitcode compile failed: {entry['file']}")
    return dest


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--build", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--clang", required=True)
    p.add_argument("--llvm-link", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args()

    with open(os.path.join(a.build, "compile_commands.json")) as f:
        entries = [e for e in json.load(f) if wanted(e, a.target)]
    if not entries:
        raise SystemExit(f"no helper sources for {a.target} in compile_commands.json")

    bcdir = os.path.join(a.build, f"helpers-{a.target}.bc.p")
    os.makedirs(bcdir, exist_ok=True)
    jobs = []
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        for e in entries:
            dest = os.path.join(bcdir, e["output"].replace("/", "_") + ".bc")
            jobs.append(pool.submit(to_bitcode, e, a.clang, dest))
        bcs = [j.result() for j in jobs]

    subprocess.run([a.llvm_link, *bcs, "-o", a.out], check=True)
    print(f"{a.out}: {len(bcs)} translation units")


if __name__ == "__main__":
    main()

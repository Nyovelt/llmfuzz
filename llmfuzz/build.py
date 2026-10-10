"""Compiler wrappers llmfuzz-cc / llmfuzz-c++ (in the spirit of afl-clang-fast).

Adds SanitizerCoverage + sanitizer flags, drops -fsanitize=fuzzer[-no-link]
(so OSS-Fuzz style build scripts work unchanged), and links the runtime
archive into executables. Environment:
  LLMFUZZ_CC / LLMFUZZ_CXX   real compilers (default clang / clang++)
  LLMFUZZ_SANITIZER          e.g. address (default), address,undefined, none
  LLMFUZZ_CDB                if set, append each compile command (JSON lines) to this file;
                             `llmfuzz analyze --cdb` uses it for a clang call graph
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

RT = Path(__file__).parent / "runtime"
COV = "-fsanitize-coverage=trace-pc-guard,pc-table,trace-cmp"


def runtime_objects(cc: str = "clang") -> list[str]:
    """Build (once, cached by source hash) the runtime: an object that is always
    linked (it must beat the sanitizer runtime's weak coverage stubs, which on
    Linux are linked first) and an archive whose main() is only pulled in when
    the target has none."""
    src = [RT / "llmfuzz_rt.c", RT / "llmfuzz_main.c"]
    h = hashlib.sha1(b"".join(p.read_bytes() for p in src) + cc.encode()).hexdigest()[:12]
    d = Path(os.environ.get("LLMFUZZ_CACHE", Path.home() / ".cache" / "llmfuzz")) / h
    rt, lib = d / "llmfuzz_rt.o", d / "libllmfuzz_main.a"
    if not lib.exists():
        d.mkdir(parents=True, exist_ok=True)
        for p, out in ((src[0], rt), (src[1], d / "llmfuzz_main.o")):
            tmp = d / f"{p.stem}.{os.getpid()}.o"
            subprocess.run([cc, "-O2", "-g", "-fPIC", "-c", str(p), "-o", str(tmp)], check=True)
            os.replace(tmp, out)
        tmp = d / f"lib.{os.getpid()}.a"
        subprocess.run(["ar", "rcs", str(tmp), str(d / "llmfuzz_main.o")], check=True)
        os.replace(tmp, lib)
    return [str(rt), str(lib)]


def wrap(cxx: bool, argv: list[str]) -> None:
    real = os.environ.get("LLMFUZZ_CXX" if cxx else "LLMFUZZ_CC") or ("clang++" if cxx else "clang")
    args = [a for a in argv if a not in ("-fsanitize=fuzzer", "-fsanitize=fuzzer-no-link")]
    san = os.environ.get("LLMFUZZ_SANITIZER", "address")
    flags = ["-g", "-fno-omit-frame-pointer", os.environ.get("LLMFUZZ_COV", COV)]
    flags += [] if san == "none" else [f"-fsanitize={san}", "-fno-sanitize-recover=all"]  # UBSan reports are crashes
    compile_only = any(a in ("-c", "-S", "-E", "-M", "-MM", "-fsyntax-only") for a in args)
    srcs = [a for a in args if a.endswith((".c", ".cc", ".cpp", ".cxx", ".C")) and not a.startswith("-")]
    if os.environ.get("LLMFUZZ_CDB") and "-c" in args and srcs:
        with open(os.environ["LLMFUZZ_CDB"], "a") as f:  # one line per command; appends are atomic
            f.write(json.dumps({"directory": os.getcwd(), "arguments": [real] + args, "files": srcs}) + "\n")
    shared = any(a in ("-shared", "-dynamiclib") for a in args)
    extra = []
    if args and not compile_only and not shared:
        extra = runtime_objects(os.environ.get("LLMFUZZ_CC") or "clang")
        extra += [] if sys.platform == "darwin" else ["-ldl", "-lm"]
    os.execvp(real, [real] + flags + args + extra)


def cc() -> None:
    wrap(False, sys.argv[1:])


def cxx() -> None:
    wrap(True, sys.argv[1:])

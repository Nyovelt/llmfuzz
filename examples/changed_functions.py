"""Scores for `llmfuzz run --prior FILE`: the C/C++ functions that a git diff touches.

  python examples/changed_functions.py -C path/to/repo v1.2.0 v1.3.0 > changed.json
  llmfuzz run ./fuzzer seeds/ --prior changed.json

A function with k changed lines (in the newer revision, or in the working tree if only one revision
is given) gets 1 + log(1 + k); functions the diff does not touch are neutral, so the fuzzer spends
more of its time on recently changed code.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
from collections import defaultdict

from llmfuzz.pcmap import c_functions

SOURCES = ("*.c", "*.cc", "*.cpp", "*.cxx", "*.h", "*.hh", "*.hpp")


def changed_lines(repo: str, revs: list[str]) -> dict[str, set[int]]:
    """Line numbers, in the newer version, of each changed source file."""
    diff = subprocess.run(["git", "-C", repo, "diff", "-U0", *revs, "--", *SOURCES],
                          capture_output=True, text=True, check=True).stdout
    out: dict[str, set[int]] = defaultdict(set)
    path = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None  # None: the file was deleted
        elif path and (m := re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)):
            start, n = int(m.group(1)), int(m.group(2) or 1)
            out[path].update(range(start, start + max(n, 1)))  # a pure deletion marks the line after it
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-C", dest="repo", default=".", help="git repository (default: current directory)")
    ap.add_argument("revs", nargs="+", metavar="REV", help="one revision (compared with the working tree) or two")
    a = ap.parse_args()
    scores: dict[str, float] = {}
    for path, lines in changed_lines(a.repo, a.revs[:2]).items():
        if len(a.revs) > 1:
            text = subprocess.run(["git", "-C", a.repo, "show", f"{a.revs[1]}:{path}"],
                                  capture_output=True, text=True, errors="replace", check=True).stdout
        else:
            with open(os.path.join(a.repo, path), errors="replace") as f:
                text = f.read()
        for _, first, last, name in c_functions(text):
            k = sum(first <= ln <= last for ln in lines)
            if k:
                scores[name] = max(scores.get(name, 0.0), round(1 + math.log1p(k), 3))
    print(json.dumps(dict(sorted(scores.items(), key=lambda x: -x[1])), indent=1))


if __name__ == "__main__":
    main()

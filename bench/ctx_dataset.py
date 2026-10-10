"""Build a dataset for the call-context experiment (not part of the llmfuzz core).

For each target: the scored regions of an `llmfuzz analyze` report, the source definitions and the static
call graph (pcmap.call_graph, with a clang compile database if given), the known-bug regions, and a
random sample of other regions. bench/ctx_score.py turns it into prompts with different call contexts.

  python bench/ctx_dataset.py out.json --target name=w_llm.weights.json[,cdb.jsonl] --bug name=func ...
"""
import argparse
import json
import os
import random
import sys
from collections import deque

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from llmfuzz.pcmap import call_graph  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--target", action="append", required=True, help="name=report.json[,cdb.jsonl]")
    ap.add_argument("--bug", action="append", default=[], help="name=function (qualified suffix, e.g. Buffer::Read)")
    ap.add_argument("--sample", type=int, default=120, help="non-bug regions per target")
    ap.add_argument("--max-bug", type=int, default=6, help="bug regions per target (chunks of one long function)")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    bugs = {}
    for b in a.bug:
        t, f = b.split("=", 1)
        bugs.setdefault(t, []).append(f)
    out = {}
    for spec in a.target:
        name, files = spec.split("=", 1)
        report, *cdb = files.split(",")
        regions = json.load(open(report))
        defs, edges = call_graph(sorted({r["file"] for r in regions}), cdb=cdb[0] if cdb else None)
        where = {}  # (realpath, line) -> def index (innermost definition containing the line)
        for i, (path, _, s, e, _) in enumerate(defs):
            for ln in range(s, e + 1):
                if (path, ln) not in where or s >= defs[where[(path, ln)]][2]:
                    where[(path, ln)] = i
        roots = [i for i, d in enumerate(defs) if d[1].endswith("LLVMFuzzerTestOneInput")]
        prev, q = {r: None for r in roots}, deque(roots)  # BFS tree from the harness entry
        while q:
            i = q.popleft()
            for j in edges[i]:
                if j not in prev:
                    prev[j] = i
                    q.append(j)
        regs = []
        for k, r in enumerate(regions):
            path = os.path.realpath(r["file"])
            lines = open(path, errors="replace").read().splitlines(keepends=True)
            base = r["name"].split("#")[0]
            text = "".join(lines[r["line"] - 1: r["end"]])
            if "#" in r["name"] and not r["name"].endswith("#1"):  # later chunk: prefix the signature line
                d0 = where.get((path, r["line"]))
                if d0 is not None:
                    text = lines[defs[d0][2] - 1] + "    /* ... */\n" + text
            d = where.get((path, r["line"]))
            b0 = base.split("<")[0]  # drop template arguments
            is_bug = any(b0 == f or b0.endswith("::" + f) for f in bugs.get(name, []))
            regs.append({"id": k, "name": r["name"], "file": os.path.basename(path), "path": path, "line": r["line"],
                         "text": text, "def": d, "lines": r["end"] - r["line"] + 1, "bug": is_bug, "llm4b": r["score"]})
        rnd = random.Random(a.seed)
        others, bug = [r for r in regs if not r["bug"]], [r for r in regs if r["bug"]]
        keep = rnd.sample(bug, min(a.max_bug, len(bug))) + rnd.sample(others, min(a.sample, len(others)))
        out[name] = {
            "regions": keep, "n_regions": len(regs),
            "files": {p: open(p, errors="replace").read() for p in {r["path"] for r in keep}},
            "defs": [{"q": d[1], "file": os.path.basename(d[0]), "start": d[2], "text": d[4]} for d in defs],
            "callees": edges,
            "callers": [[i for i, es in enumerate(edges) if j in es] for j in range(len(defs))],
            "parent": {str(j): p for j, p in prev.items()},  # call path from the harness: follow parents
        }
        nb = sum(r["bug"] for r in keep)
        print(f"{name}: {len(regs)} regions, kept {len(keep)} ({nb} bug), {len(defs)} defs, "
              f"{sum(map(len, edges))} edges, {len(prev)} reachable", file=sys.stderr)
    json.dump(out, open(a.out, "w"))


if __name__ == "__main__":
    main()

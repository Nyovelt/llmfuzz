"""Coverage of LLM-flagged code per configuration (needs run_eval.py --keep runs).

  python bench/hotcov.py WORKDIR target weights.json [--func NAME ...]
For every kept trial dir ev-<target>-<config>-<seed>-*/cov.txt, reports the
mean fraction of PCs covered among (a) the regions the LLM ranks in its top
10% and (b) the named functions (e.g. the known-buggy one).
"""
import argparse
import glob
import json
import os
import re
from collections import defaultdict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("work")
    ap.add_argument("target")
    ap.add_argument("report", help="w_llm.weights.json from llmfuzz analyze (ranked regions)")
    ap.add_argument("--func", action="append", default=[])
    a = ap.parse_args()
    regions = json.load(open(a.report))
    wfile = a.report[: -len(".json")]
    pcs = [line.split() for line in open(wfile) if not line.startswith("#")]
    w = {int(p, 16): float(x) for p, x in pcs}
    top = regions[: max(1, len(regions) // 10)]
    hot_thr = min(r["weight"] for r in top)
    hot = {p for p, x in w.items() if x >= hot_thr}
    # PCs of named functions: weights file has no names, so use region line ranges via a pcs dump
    named = defaultdict(set)
    if a.func:
        dump = os.path.join(a.work, "pcs_sym.json")
        if os.path.exists(dump):
            for fn, plist in json.load(open(dump)).items():
                if any(f in fn for f in a.func):
                    named[fn] |= set(plist)
    res = defaultdict(list)
    for d in glob.glob(os.path.join(a.work, f"ev-{a.target}-*")):
        m = re.match(rf"ev-{re.escape(a.target)}-(\w+)-(\d+)-", os.path.basename(d))
        if not m or not os.path.exists(os.path.join(d, "cov.txt")):
            continue
        cov = {int(x, 16) for x in open(os.path.join(d, "cov.txt")) if x.strip()}
        row = {"hot": len(cov & hot) / max(1, len(hot)), "all": len(cov)}
        for fn, s in named.items():
            row[fn] = len(cov & s) / max(1, len(s))
        res[m.group(1)].append(row)
    for cfg, rows in sorted(res.items()):
        keys = sorted({k for r in rows for k in r})
        print(f"{cfg:8s} n={len(rows):2d} " + "  ".join(f"{k[:30]}={sum(r.get(k, 0) for r in rows) / len(rows):.3f}"
                                                       for k in keys))


if __name__ == "__main__":
    main()

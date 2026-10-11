"""Median time to first crash of each config relative to plain, as a geometric mean over targets (README §4).

  python bench/tte_ratio.py results.jsonl [more.jsonl ...] --configs llm,size,shuf [--budget 900]
Trials that find nothing count as the budget. Also prints how many targets got faster and the ratio per target.
"""
import argparse
import json
import math
from collections import defaultdict


def median(v):
    v = sorted(v)
    return (v[len(v) // 2] + v[(len(v) - 1) // 2]) / 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="+")
    ap.add_argument("--configs", required=True, help="comma-separated configs to compare with --base")
    ap.add_argument("--base", default="plain")
    ap.add_argument("--budget", type=float, default=900)
    ap.add_argument("--kinds", default="crash,timeout,oom", help="crash kinds that count as a find")
    a = ap.parse_args()
    kinds = set(a.kinds.split(","))
    runs = defaultdict(list)
    for f in a.results:
        for line in open(f):
            r = json.loads(line)
            found = r["crashed"] and r["kind"] in kinds
            runs[(r["target"], r["config"])].append(min(r["tte"], a.budget) if found else a.budget)
    targets = sorted({t for t, _ in runs})
    for c in a.configs.split(","):
        ratios = [(t, median(runs[(t, c)]) / median(runs[(t, a.base)]))
                  for t in targets if (t, c) in runs and (t, a.base) in runs]
        if not ratios:
            continue
        geo = math.exp(sum(math.log(x) for _, x in ratios) / len(ratios))
        print(f"{c:10s} {geo:.2f}x  faster on {sum(x < 1 for _, x in ratios)}/{len(ratios)}  "
              + " ".join(f"{t.split('-')[0]}={x:.2f}" for t, x in ratios))


if __name__ == "__main__":
    main()

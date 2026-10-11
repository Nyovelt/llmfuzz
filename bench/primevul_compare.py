"""Compare two models' PrimeVul scores function by function (README §1).

  python bench/primevul_compare.py RESULTS/q36 RESULTS/q4 [--data DATA]
Reads PREFIX_<set>_scores.npy (rows: probe, zero-shot) written by primevul_probe.py and prints both AUCs, the
difference A - B with a 95% paired bootstrap interval (functions resampled), the correlation of the two scores
and the AUC of their standardized sum.
"""
import argparse
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from llmfuzz.lens import auc  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--data", default="data")
    ap.add_argument("--resamples", type=int, default=2000)
    a = ap.parse_args()
    rng = np.random.default_rng(0)
    for k in ("test_m", "test_nat"):
        y = np.array([int(json.loads(line)["target"]) for line in open(f"{a.data}/{k}.jsonl")])
        sa, sb = np.load(f"{a.a}_{k}_scores.npy"), np.load(f"{a.b}_{k}_scores.npy")
        for j, name in enumerate(("probe", "zero-shot")):
            diffs = []
            for _ in range(a.resamples):
                i = rng.integers(0, len(y), len(y))
                if 0 < y[i].sum() < len(i):
                    diffs.append(auc(y[i], sa[j][i]) - auc(y[i], sb[j][i]))
            lo, hi = np.percentile(diffs, [2.5, 97.5])
            print(f"{k:8s} {name:9s} A {auc(y, sa[j]):.3f}  B {auc(y, sb[j]):.3f}  A-B {auc(y, sa[j]) - auc(y, sb[j]):+.3f}"
                  f"  95% [{lo:+.3f}, {hi:+.3f}]  corr {np.corrcoef(sa[j], sb[j])[0, 1]:.2f}")
        both = sum((s[0] - s[0].mean()) / s[0].std() for s in (sa, sb))
        print(f"{k:8s} probe A+B (standardized sum) {auc(y, both):.3f}")


if __name__ == "__main__":
    main()

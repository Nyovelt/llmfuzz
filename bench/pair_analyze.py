"""Buggy vs fixed version of the same function (README §3.12; not part of the llmfuzz core).

  python bench/pair_analyze.py pairs.json run.npz [run2.npz ...]
pairs.json is in bench/ctx_think.py's input layout, one group per "target", and every region has "pair" and "bug"
(true = before the fix). For each group and mode:
  acc    share of pairs whose buggy version gets the higher yes-vs-no log-odds (zs = top-quarter J-lens layers,
         final = the model's own output; ties count half), b-w and a two-sided sign test
  P-C/V/B/R  the model's own answers (final log-odds > 0 = Yes) as PrimeVul's pair categories: both right,
         Yes on both, No on both, both wrong
  hard   acc on pairs where trivial cues fail: the fixed version has no more code / no more if-checks
  site   for runs with reasoning: how often the end of the reasoning quotes a line at the fix site (lines the fix
         removed or changed, or next to an insertion), about the buggy vs the fixed version; "ins" restricts to
         insertion-only fixes, where the site lines exist in both versions
"""
import difflib
import json
import math
import re
import sys
from collections import defaultdict

import numpy as np

from ctx_analyze import readouts

CMT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def sign_p(b, w):
    n = b + w
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(min(b, w) + 1)) / 2 ** n) if n else 1.0


def acc(v, ps, k):
    d = [v[(p, True)][k] - v[(p, False)][k] for p in ps]
    b, w = sum(x > 0 for x in d), sum(x < 0 for x in d)
    return (b + 0.5 * (len(d) - b - w)) / max(len(d), 1), b, w


def fix_site(before, after):
    """Indices of the buggy version's lines at the fix site, and whether the fix only inserted lines."""
    b, a = before.splitlines(), after.splitlines()
    site, ops = set(), set()
    for op, i1, i2, _, _ in difflib.SequenceMatcher(None, b, a, autojunk=False).get_opcodes():
        ops.add(op)
        if op in ("replace", "delete"):
            site.update(range(i1, i2))
        elif op == "insert":
            site.update({max(i1 - 1, 0), min(i1, len(b) - 1)})
    return [b[i] for i in sorted(site)], ops - {"equal"} == {"insert"}


def main():
    data = json.load(open(sys.argv[1]))
    reg = {(tn, r["id"]): r for tn, t in data.items() for r in t["regions"]}
    code = lambda s: len(re.sub(r"\s+", "", CMT.sub(" ", s)))  # noqa: E731
    nif = lambda s: len(re.findall(r"\bif\s*\(", CMT.sub(" ", s)))  # noqa: E731
    norm = lambda s: re.sub(r"\s+", "", s)  # noqa: E731
    pair = {}  # (group, pair) -> (buggy region, fixed region)
    for tn, t in data.items():
        by = defaultdict(dict)
        for r in t["regions"]:
            by[r["pair"]][r["bug"]] = r
        for p, v in by.items():
            pair[(tn, p)] = (v[True], v[False])
    for npz in sys.argv[2:]:
        meta, ro = readouts(npz)
        texts = {}
        try:
            texts = {(x["target"], x["id"]): x.get("think", "") for x in
                     map(json.loads, open(npz.rsplit(".", 1)[0] + ".texts.jsonl"))}
        except FileNotFoundError:
            pass
        s = defaultdict(dict)
        for (tn, rid, m, _), z, f in zip(meta["items"], ro["zs"], ro["final"]):
            r = reg[(tn, rid)]
            s[(tn, m)][(r["pair"], r["bug"])] = (float(z), float(f))
        print(f"== {meta['model']}  ({npz.split('/')[-1]})")
        print(f"{'group':9s} {'mode':6s} {'pairs':>5s} {'zs acc':>6s} {'b-w':>7s} {'p':>5s} {'final':>6s} {'b-w':>7s} "
              f"{'p':>5s}  P-C  P-V  P-B  P-R | hard: not longer, no added if (zs acc, n)")
        for (tn, m), v in sorted(s.items()):
            ps = sorted({p for p, _ in v if (p, True) in v and (p, False) in v})
            za, zb, zw = acc(v, ps, 0)
            fa, fb, fw = acc(v, ps, 1)
            yb = np.array([v[(p, True)][1] > 0 for p in ps])
            yf = np.array([v[(p, False)][1] > 0 for p in ps])
            cat = [np.mean(yb & ~yf), np.mean(yb & yf), np.mean(~yb & ~yf), np.mean(~yb & yf)]
            hard = []
            for cue in (lambda b, a: code(a) <= code(b), lambda b, a: nif(a) <= nif(b)):
                hp = [p for p in ps if cue(pair[(tn, p)][0]["text"], pair[(tn, p)][1]["text"])]
                hard.append(f"{acc(v, hp, 0)[0]:.2f} ({len(hp)})")
            print(f"{tn:9s} {m:6s} {len(ps):5d} {za:6.2f} {zb:>3d}-{zw:<3d} {sign_p(zb, zw):5.2f} {fa:6.2f} "
                  f"{fb:>3d}-{fw:<3d} {sign_p(fb, fw):5.2f}  " + " ".join(f"{c:.2f}" for c in cat) + " | " + ", ".join(hard))
            if m != "think" or not texts:
                continue
            for only_ins in (False, True):
                rows = []
                for p in ps:
                    b, a = pair[(tn, p)]
                    lines, ins = fix_site(b["text"], a["text"])
                    keys = [norm(x) for x in lines if len(norm(x)) >= 12]
                    if not keys or (only_ins and not ins):
                        continue
                    hit = lambda r: any(k in norm(texts[(tn, r["id"])][-2000:]) for k in keys)  # noqa: E731
                    rows.append((hit(b), hit(a)))
                if rows:
                    r = np.array(rows)
                    print(f"{'':16s} site{' ins' if only_ins else '    '}: reasoning quotes the fix site for the buggy "
                          f"version {r[:, 0].mean():.2f}, the fixed version {r[:, 1].mean():.2f} ({len(r)} pairs)")


if __name__ == "__main__":
    main()

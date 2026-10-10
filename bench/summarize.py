"""Summarize run_eval.py results: success rate, time-to-first-crash, coverage.

  python bench/summarize.py results.jsonl [--budget 900] [--base plain]
Censored runs (no crash) count as `budget` seconds. p-values: two-sided
Mann-Whitney U against the baseline config (normal approximation).
"""
import argparse
import json
import math
from collections import defaultdict


def mwu(a, b):
    """Two-sided Mann-Whitney U p-value (normal approx. with tie correction)."""
    n1, n2 = len(a), len(b)
    allv = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    ranks, i = [0.0] * len(allv), 0
    ties = 0.0
    while i < len(allv):
        j = i
        while j + 1 < len(allv) and allv[j + 1][0] == allv[i][0]:
            j += 1
        for k in range(i, j + 1):
            ranks[k] = (i + j) / 2 + 1
        t = j - i + 1
        ties += t ** 3 - t
        i = j + 1
    r1 = sum(r for r, (_, g) in zip(ranks, allv) if g == 0)
    u = r1 - n1 * (n1 + 1) / 2
    n = n1 + n2
    sd = math.sqrt(n1 * n2 / 12 * ((n + 1) - ties / (n * (n - 1)))) if n > 1 else 0
    if sd == 0:
        return 1.0
    z = (u - n1 * n2 / 2) / sd
    return math.erfc(abs(z) / math.sqrt(2))


def median(v):
    v = sorted(v)
    n = len(v)
    return (v[n // 2] + v[(n - 1) // 2]) / 2 if n else float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="+")
    ap.add_argument("--budget", type=float, default=900)
    ap.add_argument("--base", default="plain")
    ap.add_argument("--kinds", default="crash,timeout,oom", help="crash kinds that count as a find")
    ap.add_argument("--bug", help="only count crashes whose signature contains this (restart-mode events)")
    ap.add_argument("--markdown", action="store_true", help="one markdown row per target x config")
    ap.add_argument("--vs", default="shuf", help="second comparison config for --markdown / --wide")
    ap.add_argument("--wide", action="store_true", help="markdown, one row per target: found/n, median TTE per config")
    ap.add_argument("--focus", default="llm", help="config whose p-values --wide reports")
    ap.add_argument("--configs", help="comma-separated configs to show, in this order (default: all)")
    ap.add_argument("--pvals", help="--wide p-value columns as A:B pairs, e.g. llm:plain,size:plain")
    a = ap.parse_args()
    kinds = set(a.kinds.split(","))
    runs = defaultdict(list)
    for f in a.results:
        for line in open(f):
            r = json.loads(line)
            if a.bug:  # time to the first crash matching the bug signature
                ev = [e for e in r.get("events") or ([{"t": r["tte"], "kind": r["kind"], "signature": r["signature"]}]
                                                      if r["crashed"] else []) if a.bug in (e["signature"] or "")]
                r = dict(r, crashed=bool(ev), tte=ev[0]["t"] if ev else None, kind=ev[0]["kind"] if ev else None,
                         signature=ev[0]["signature"] if ev else None)
            runs[(r["target"], r["config"])].append(r)
    targets = sorted({t for t, _ in runs})
    configs = a.configs.split(",") if a.configs else sorted({c for _, c in runs}, key=lambda c: (c != a.base, c))
    def tte(rs):
        return [r["tte"] if r["crashed"] and r["kind"] in kinds else a.budget for r in rs]

    if a.wide:
        def cell(rs):
            med = median(tte(rs))
            m = f">{a.budget:.0f}" if med >= a.budget else f"{med:.1f}" if med < 10 else f"{med:.0f}"
            return f"{sum(1 for r in rs if r['crashed'] and r['kind'] in kinds)}/{len(rs)}, {m}"

        def p(t, x, o):
            return f"{mwu(tte(runs[(t, x)]), tte(runs[(t, o)])):.3f}" if (t, x) in runs and (t, o) in runs else "–"
        pairs = [q.split(":") for q in a.pvals.split(",")] if a.pvals else [(a.focus, a.base), (a.focus, a.vs)]
        print(f"| target | {' | '.join(configs)} | " + " | ".join(f"p {x} vs {o}" for x, o in pairs) + " |")
        print("|---" * (len(configs) + len(pairs) + 1) + "|")
        for t in targets:
            cells = [cell(runs[(t, c)]) if (t, c) in runs else "–" for c in configs]
            print(f"| {t} | {' | '.join(cells)} | " + " | ".join(p(t, x, o) for x, o in pairs) + " |")
        return
    if a.markdown:
        print(f"| target | config | found | median TTE (s) | p vs {a.base} | p vs {a.vs} |\n|---|---|---|---|---|---|")
        for t in targets:
            for c in configs:
                rs = runs.get((t, c))
                if not rs:
                    continue
                x = tte(rs)
                pb = mwu(x, tte(runs[(t, a.base)])) if c != a.base and (t, a.base) in runs else float("nan")
                pv = mwu(x, tte(runs[(t, a.vs)])) if c != a.vs and (t, a.vs) in runs else float("nan")
                found = sum(1 for r in rs if r["crashed"] and r["kind"] in kinds)
                fmt = lambda p: "–" if p != p else f"{p:.3f}"  # noqa: E731
                med = median(x)
                print(f"| {t} | {c} | {found}/{len(rs)} | {'>' if med >= a.budget else ''}{med:.0f} | {fmt(pb)} | {fmt(pv)} |")
        return
    print(f"{'target':28s} {'config':8s} {'found':>6s} {'median TTE':>11s} {'mean TTE':>9s} {'p vs ' + a.base:>9s} "
          f"{'cov':>7s} {'hot cov':>8s}  kinds")
    for t in targets:
        base = [r["tte"] if r["crashed"] and r["kind"] in kinds else a.budget for r in runs.get((t, a.base), [])]
        for c in configs:
            rs = runs.get((t, c))
            if not rs:
                continue
            tte = [r["tte"] if r["crashed"] and r["kind"] in kinds else a.budget for r in rs]
            found = sum(1 for r in rs if r["crashed"] and r["kind"] in kinds)
            p = mwu(tte, base) if c != a.base and base else float("nan")
            covs = [r["cov"] for r in rs if r.get("cov") is not None]
            hots = [r["hot"] for r in rs if r.get("hot") is not None]
            ks = defaultdict(int)
            for r in rs:
                if r["crashed"]:
                    fr = [f for f in (r["signature"] or "").split(" @ ")[-1].split(" < ") if f.strip()]
                    ks[(r["kind"] + ":" + (fr[0] if fr else ""))[:40]] += 1
            print(f"{t:28s} {c:8s} {found:>3d}/{len(rs):<2d} {median(tte):>11.1f} {sum(tte) / len(tte):>9.1f} {p:>9.3f} "
                  f"{sum(covs) / max(1, len(covs)):>7.0f} {sum(hots) / max(1, len(hots)):>8.0f}  "
                  f"{dict(ks)}")
        print()


if __name__ == "__main__":
    main()

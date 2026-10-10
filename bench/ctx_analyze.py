"""Rank known bugs under each context variant (reads bench/ctx_score.py output; not part of the llmfuzz core).

  python bench/ctx_analyze.py data.json scores.npz [more.npz ...] [--probe llmfuzz/probes/qwen3-4b-jlens.npz]
Readouts: zs = zero-shot J-lens yes/no log-odds averaged over the top quarter of layers, final = the same at the
last layer only, probe = the trained probe (only for the model it was trained for). For each known-bug function:
percentile of its best region among the sampled non-bug regions of the same target (lower = ranked higher).
"ctl" rows keep only regions (bug and non-bug) that got a non-empty context of that variant: context shifts the
yes/no readout for everyone who gets it, so mixing regions with and without context would rank by that shift
(bug functions without context drop out of those rows, see the n after the slash).
"-res" readouts are the residuals of a per-target linear fit on log(function lines), i.e. what is left beyond a
size prior; "+size" adds the standardized residual to the standardized size prior; the "size" row is the prior alone.
The last columns compare each row with the size prior and with the same readout on the isolated function, both
recomputed on the same regions as the row (bugs ranked higher-lower, two-sided sign test).
"""
import math
import argparse
import json
import os
import sys
from collections import defaultdict

import numpy as np


def readouts(npz, probe=None):
    z = np.load(npz)
    feats, layers, vocab = z["feats"].astype(np.float32), list(z["layers"]), list(z["vocab"])
    meta = json.loads(str(z["meta"]))
    import transformers  # token strings for the yes/no ids
    tok = transformers.AutoTokenizer.from_pretrained(meta["model"])
    word = [tok.decode([v]).strip().lower() for v in vocab]
    yes = [i for i, w in enumerate(word) if w == "yes"]
    no = [i for i, w in enumerate(word) if w == "no"]
    lse = lambda x: np.log(np.exp(x).sum(-1))  # noqa: E731
    yn = lse(feats[:, :, yes]) - lse(feats[:, :, no])  # [N, layers]
    n_top = max(1, int(round(0.25 * (2 * len(layers)))))  # stored layers are the upper half
    out = {"zs": yn[:, -n_top:].mean(1), "final": yn[:, -1]}
    if probe is not None and probe["meta"].get("lens_name", "").split("|")[0] == meta["model"]:
        li = [layers.index(l) for l in probe["layers"]]
        vi = [vocab.index(v) for v in probe["vocab"]]
        x = feats[:, li][:, :, vi].reshape(len(feats), -1)
        out["probe"] = ((x - probe["mean"]) / probe["std"]) @ probe["w"] + probe["b"]
    return meta, out


def rank_rows(data, scores, probe=None):
    """[(label, readout, variant, {target:function: percentile}, {"size"|"iso": the same on the same regions})]."""
    sys.path.insert(0, os.path.dirname(__file__))
    from ctx_score import contexts
    region = {(tn, r["id"]): r for tn, t in data.items() for r in t["regions"]}
    has_ctx = {}

    def has(tn, rid, v):
        if (tn, rid, v) not in has_ctx:
            try:
                has_ctx[(tn, rid, v)] = bool(contexts(data[tn], region[(tn, rid)], v))
            except ValueError:  # not a context variant (e.g. ctx_think.py's modes): every region has it
                has_ctx[(tn, rid, v)] = True
        return has_ctx[(tn, rid, v)]
    bugfn = {}  # (target, region id) -> bug function name
    size = {}  # (target, region id) -> log lines of the enclosing function
    for tn, t in data.items():
        for r in t["regions"]:
            if r["bug"]:
                bugfn[(tn, r["id"])] = r["name"].split("#")[0].split("<")[0].split("::")[-1]
            n = len(t["defs"][r["def"]]["text"].splitlines()) if r["def"] is not None else r["lines"]
            size[(tn, r["id"])] = np.log(max(n, 1))

    def pct_of(per_t, keep):
        """Percentile of each bug function's best kept region among the kept non-bug regions of its target."""
        pct = {}
        for tn, sc in per_t.items():
            neg = np.array([x for rid, x in sc.items() if (tn, rid) not in bugfn and keep(tn, rid)])
            best = defaultdict(lambda: -np.inf)
            for rid, x in sc.items():
                if (tn, rid) in bugfn and keep(tn, rid):
                    best[bugfn[(tn, rid)]] = max(best[bugfn[(tn, rid)]], x)
            for f, x in best.items():
                pct[f"{tn.split('-')[0]}:{f}"] = 100.0 * (np.sum(neg > x) + 0.5) / (len(neg) + 1)
        return pct

    size_t = defaultdict(dict)
    for (tn, rid), x in size.items():
        size_t[tn][rid] = x
    rows = []
    for k, npz in enumerate(scores):
        meta, outs = readouts(npz, probe)
        label = f"{meta['model'].split('/')[-1]}@{meta['budget'] // 1024}k"
        groups = defaultdict(list)  # residuals are fit per target and variant
        for i, (tn, _, v, _) in enumerate(meta["items"]):
            groups[(tn, v)].append(i)
        for ro in list(outs):
            res, both = np.empty(len(outs[ro])), np.empty(len(outs[ro]))
            for idx in groups.values():
                x = np.array([size[tuple(meta["items"][i][:2])] for i in idx])
                y = outs[ro][idx]
                r = y - np.polyval(np.polyfit(x, y, 1), x)
                res[idx] = r
                both[idx] = r / (r.std() or 1) + (x - x.mean()) / (x.std() or 1)
            outs[ro + "-res"], outs[ro + "+size"] = res, both
        if k == 0:  # the size prior alone, on all regions
            rows.append(("-", "size", "-", pct_of(size_t, lambda tn, rid: True), {}))
        for ro, s in outs.items():
            by = defaultdict(lambda: defaultdict(dict))  # variant -> target -> {region id: score}
            for (tn, rid, v, _), x in zip(meta["items"], s):
                by[v][tn][rid] = float(x)
            for v in by:
                for ctl in ((False, True) if v != "iso" else (False,)):
                    keep = (lambda tn, rid, v=v: has(tn, rid, v)) if ctl else (lambda tn, rid: True)
                    refs = {"size": pct_of(size_t, keep), "iso": pct_of(by["iso"], keep) if "iso" in by else {}}
                    rows.append((label, ro, v + (" ctl" if ctl else ""), pct_of(by[v], keep), refs))
    return rows


def sign_test(p, q):
    """Bugs ranked higher / lower in p than in q, and the two-sided sign-test p-value."""
    d = [p[k] - q[k] for k in p if k in q and abs(p[k] - q[k]) > 1e-9]
    b, w = sum(x < 0 for x in d), sum(x > 0 for x in d)
    n = b + w
    pv = min(1.0, 2 * sum(math.comb(n, i) for i in range(min(b, w) + 1)) / 2 ** n) if n else 1.0
    return b, w, pv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data")
    ap.add_argument("scores", nargs="+")
    ap.add_argument("--probe")
    a = ap.parse_args()
    probe = None
    if a.probe:
        z = np.load(a.probe)
        probe = {k: z[k] for k in ("vocab", "layers", "mean", "std", "w", "b")}
        probe["meta"] = json.loads(str(z["meta"]))
    rows = rank_rows(json.load(open(a.data)), a.scores, probe)
    names = sorted({k for _, _, _, p, _ in rows for k in p})
    print(f"{'model':12s} {'readout':10s} {'variant':17s} {'median':>6s} {'mean':>5s} {'top10%':>6s}  "
          f"{'vs size':>13s}  {'vs iso':>13s}  per bug (percentile)")
    for lb, ro, v, p, refs in rows:
        x = np.array([p.get(k, np.nan) for k in names])
        cmp = [sign_test(p, refs[r]) if refs.get(r) and not v.startswith("iso") else None for r in ("size", "iso")]
        print(f"{lb:12s} {ro:10s} {v:17s} {np.nanmedian(x):6.1f} {np.nanmean(x):5.1f} {int(np.sum(x <= 10)):>3d}/{int(np.sum(~np.isnan(x)))}  "
              + "  ".join(f"{c[0]:>2d}-{c[1]:<2d} p={c[2]:.2f}" if c else f"{'':13s}" for c in cmp) + "  "
              + " ".join(f"{k.split(':')[1][:14]}={p[k]:.0f}" for k in names if k in p))

if __name__ == "__main__":
    main()

"""Percentile of the 13 FTS bug functions in each ranking (README §2).

  python bench/fts_ranks.py llm=w_llm size=w_size shuf=w_shuf_1 [--root fts] [--json out.json]
Each NAME=PREFIX reads ROOT/<target>/PREFIX.weights.json (written by llmfuzz analyze, regions sorted by score).
A long function counts at its highest-ranked region.
"""
import argparse
import json
import re
import statistics

BUGS = [("llvm-libcxxabi-2017-01-27", "parse_floating_number"), ("llvm-libcxxabi-2017-01-27", "parse_function_type"),
        ("llvm-libcxxabi-2017-01-27", "parse_unnamed_type_name"), ("pcre2-10.00", "match"),
        ("lcms-2017-03-21", "TetrahedralInterpFloat"), ("woff2-2016-05-06", "ReconstructGlyf"),
        ("woff2-2016-05-06", "Buffer::Read"), ("re2-2014-12-09", "NFA::Search"),
        ("libxml2-v2.9.2", "xmlParseXMLDecl"), ("libxml2-v2.9.2", "xmlDictComputeFastQKey"),
        ("libxml2-v2.9.2", "xmlDictComputeFastKey"), ("libxml2-v2.9.2", "xmlCurrentChar"),
        ("openssl-1.0.1f", "tls1_process_heartbeat")]


def base(name):
    name = name.split("#")[0]
    while True:  # drop template arguments, innermost first; operator< and operator<< stay as they are
        shorter = re.sub(r"<[^<>]*>", "", name)
        if shorter == name:
            return name
        name = shorter


def percentile(funcs, bug):
    for i, f in enumerate(funcs):
        b = base(f["name"])
        if b == bug or b.endswith("::" + bug):
            return 100.0 * (i + 1) / len(funcs)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("configs", nargs="+", help="name=prefix of the weights report in each target dir")
    ap.add_argument("--root", default="fts")
    ap.add_argument("--json")
    a = ap.parse_args()
    cfgs = [c.split("=", 1) for c in a.configs]
    rows, out = [], {}
    for t, bug in BUGS:
        vals, n = [], 0
        for name, prefix in cfgs:
            try:
                funcs = json.load(open(f"{a.root}/{t}/{prefix}.weights.json"))
                n = len(funcs)
                vals.append(percentile(funcs, bug))
            except FileNotFoundError:
                vals.append(None)
        rows.append((t.split("-")[0].replace("llvm", "libcxxabi"), bug, n, vals))
        out[f"{t}:{bug}"] = dict(zip([c[0] for c in cfgs], vals), regions=n)
    print(f"{'target':10s} {'function':26s} {'n':>5s} " + " ".join(f"{c[0]:>9s}" for c in cfgs))
    for t, bug, n, vals in rows:
        print(f"{t:10s} {bug:26s} {n:5d} " + " ".join(f"{v:8.1f}%" if v is not None else f"{'-':>9s}" for v in vals))
    for label, fn in (("median", statistics.median), ("top 10%", lambda v: sum(x <= 10 for x in v))):
        cells = []
        for j in range(len(cfgs)):
            v = [r[3][j] for r in rows if r[3][j] is not None]
            cells.append(f"{'-':>9s}" if len(v) < len(rows) else
                         f"{fn(v):8.1f}%" if label == "median" else f"{fn(v):>6}/{len(v):<2d}")
        print(f"{label:43s}" + " ".join(cells))
    if a.json:
        json.dump(out, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()

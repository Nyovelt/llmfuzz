"""Where do the known-buggy functions land in each analysis ranking?

  python bench/bug_rank.py target.weights.json[,...] --bug funcname [--bug ...]
Prints rank / percentile (of functions) for each weights report.
"""
import argparse
import json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("reports", nargs="+", help="name=path/to/weights.json")
    ap.add_argument("--bug", action="append", required=True, help="substring of the buggy function name")
    a = ap.parse_args()
    for r in a.reports:
        name, path = r.split("=", 1)
        funcs = json.load(open(path))
        n = len(funcs)
        for b in a.bug:
            hits = [(i, f) for i, f in enumerate(funcs) if (f["name"].split("#")[0] == b[1:] if b.startswith("=") else b in f["name"])]
            if not hits:
                print(f"{name:10s} {b:30s} not found among {n} functions")
                continue
            i, f = hits[0]
            print(f"{name:10s} {b:30s} rank {i + 1:5d}/{n}  top {100 * (i + 1) / n:5.1f}%  "
                  f"score {f['score']:+.3f} w={f['weight']:.2f} ({f['name']})")


if __name__ == "__main__":
    main()

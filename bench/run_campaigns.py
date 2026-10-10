"""Multi-worker campaign benchmark (not part of the llmfuzz core).

Runs repeated `llmfuzz fuzz`-style campaigns (N workers sharing one corpus) and
records the time to the first crash, e.g. a mixed campaign (LLM / size / plain
workers) against an all-plain one with the same number of workers:

  python bench/run_campaigns.py --target lcms=./fuzzer,./seeds \
      --config mix=w_llm.weights:w_size.weights:none --config plain=none:none:none \
      --trials 6 --time 900 --par 7 --out campaigns.jsonl
"""
import argparse
import itertools
import json
import os
import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from llmfuzz.campaign import run  # noqa: E402


def campaign(target, binary, cfg, weights, seed, a):
    binary, *extra = binary.split(",")  # name=binary[,seed_dir[,dict]]
    out = tempfile.mkdtemp(prefix=f"cp-{target}-{cfg}-{seed}-", dir=a.work)
    ws = [w.format(target=target) for w in weights.split(":")]
    s = run(binary, out, jobs=len(ws), total_time=a.time, weights=ws, seeds=[extra[0]] if extra and extra[0] else [],
            dict_path=extra[1] if len(extra) > 1 else None, timeout=a.timeout, stop_on_crash=True, seed=seed, quiet=True)
    first = min(s["crashes"], key=lambda c: c["time"]) if s["crashes"] else None
    shutil.rmtree(out, ignore_errors=True)
    return {"target": target, "config": cfg, "seed": seed, "workers": len(ws), "crashed": bool(first),
            "kind": first and first["kind"], "tte": first and first["time"], "signature": first and first["signature"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", action="append", required=True, help="name=binary[,seed_dir[,dict]]")
    ap.add_argument("--config", action="append", required=True, help="name=w1:w2:... one weights file per worker "
                    "('none' = no weights; {target} is replaced by the target name)")
    ap.add_argument("--trials", type=int, default=6)
    ap.add_argument("--time", type=int, default=900)
    ap.add_argument("--timeout", type=float, default=5)
    ap.add_argument("--par", type=int, default=4, help="concurrent campaigns")
    ap.add_argument("--work", default=tempfile.gettempdir())
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    jobs = [(t, b, c, w, s) for s, (t, b), (c, w) in
            itertools.product(range(1, a.trials + 1), [t.split("=", 1) for t in a.target], [c.split("=", 1) for c in a.config])]
    with ThreadPoolExecutor(a.par) as ex, open(a.out, "a") as out:
        for rec in ex.map(lambda j: campaign(*j, a), jobs):
            out.write(json.dumps(rec) + "\n")
            out.flush()
            print(f"{rec['target']:12s} {rec['config']:8s} seed={rec['seed']:2d} tte={rec['tte']} {rec['signature'] or ''}",
                  flush=True)


if __name__ == "__main__":
    main()

"""Benchmark harness (not part of the llmfuzz core).

Runs repeated single-process trials of a fuzz target under several
configurations (e.g. plain / LLM weights / shuffled-weights control) and
records time-to-first-crash, crash signature and coverage.

  python bench/run_eval.py --target name=path/to/fuzzer --config plain= --config llm=path.weights \
      --trials 8 --time 600 --par 15 --out results.jsonl [--seeds dir] [--dict file] [--flag -max_len=..]
"""
import argparse
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from llmfuzz.campaign import signature  # noqa: E402

CRASH = re.compile(r"==llmfuzz== (crash|timeout|oom) after ([\d.]+)s, (\d+) execs")


def trial(target, binary, cfg, weights, seed, a):
    binary, *extra = binary.split(",")  # name=binary[,seed_dir[,dict]]
    seeds = extra[0] if extra and extra[0] else a.seeds
    dct = extra[1] if len(extra) > 1 else a.dict
    work = tempfile.mkdtemp(prefix=f"ev-{target}-{cfg}-{seed}-", dir=a.work)
    corpus = os.path.join(work, "corpus")
    os.makedirs(corpus)
    if a.engine == "libfuzzer":  # reference: stock libFuzzer binary, wall-clock TTE, no symbolization
        cmd = [binary, f"-max_total_time={a.time}", f"-seed={seed}", f"-artifact_prefix={work}/",
               f"-timeout={a.timeout}", "-print_final_stats=1", "-rss_limit_mb=2048"]
    else:
        cmd = [binary, f"-max_total_time={a.time}", f"-seed={seed}", f"-artifact_prefix={work}/",
               f"-stats={work}/stats.jsonl", f"-timeout={a.timeout}", "-print_secs=30", f"-cov_dump={work}/cov.txt"]
    cmd += [f"-weights={weights}"] if weights else []
    cmd += a.flag + ([f"-dict={dct}"] if dct else []) + [corpus] + ([seeds] if seeds else [])
    if a.restart and a.engine == "llmfuzz":
        return trial_restart(target, binary, cfg, weights, seed, a, cmd, corpus, work)
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:allocator_may_return_null=1:quarantine_size_mb=64:symbolize="
               + ("0" if a.engine == "libfuzzer" else "1") + os.environ.get("ASAN_OPTIONS_EXTRA", ""))
    t0 = time.time()
    with open(os.path.join(work, "log.txt"), "w") as log:
        subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, env=env, timeout=a.time + 600)
    text = open(os.path.join(work, "log.txt"), errors="replace").read()
    if a.engine == "libfuzzer":
        wall = time.time() - t0
        kind = ("timeout" if "libFuzzer: timeout" in text else "oom" if "out-of-memory" in text else
                "crash" if re.search(r"ERROR: (AddressSanitizer|libFuzzer: deadly)", text) else None)
        cov = re.findall(r"cov: (\d+)", text)
        rec = {"target": target, "config": cfg, "seed": seed, "wall": round(wall, 1), "crashed": bool(kind),
               "kind": kind, "tte": round(wall, 2) if kind else None, "cov": int(cov[-1]) if cov else None,
               "execs": None, "ft": None, "hot": None, "hot_total": None, "corp": None,
               "signature": (re.search(r"SUMMARY: \w+Sanitizer: ([\w-]+)", text) or re.search(r"(timeout|deadly signal)", text) or [None, None])[1] if kind else None}
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)
        return rec
    m = CRASH.search(text)
    stats = [json.loads(line) for line in open(os.path.join(work, "stats.jsonl"))] if os.path.exists(
        os.path.join(work, "stats.jsonl")) else []
    last = stats[-1] if stats else {}
    rec = {"target": target, "config": cfg, "seed": seed, "wall": round(time.time() - t0, 1),
           "crashed": bool(m), "kind": m.group(1) if m else None, "tte": float(m.group(2)) if m else None,
           "execs": int(m.group(3)) if m else last.get("execs"), "cov": last.get("cov"), "ft": last.get("ft"),
           "hot": last.get("hot"), "hot_total": last.get("hot_total"), "corp": last.get("corp"),
           "signature": signature(m.group(1), text[: m.start()]) if m else None,
           "cov_curve": [(s["t"], s["cov"]) for s in stats[:: max(1, len(stats) // 40)]]}
    if not a.keep:
        shutil.rmtree(work, ignore_errors=True)
    return rec


def trial_restart(target, binary, cfg, weights, seed, a, cmd, corpus, work):
    """Fuzz for the whole budget, restarting after each crash (corpus persists); log every crash."""
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:allocator_may_return_null=1:quarantine_size_mb=64:symbolize=1"
               + os.environ.get("ASAN_OPTIONS_EXTRA", ""))
    t0, events, k, last = time.time(), [], 0, {}
    while (rem := a.time - (time.time() - t0)) > 5:
        c = [x if not x.startswith("-max_total_time=") else f"-max_total_time={int(rem)}" for x in cmd]
        c = [x if not x.startswith("-seed=") else f"-seed={seed * 1000 + k}" for x in c]
        c = [x if not x.startswith("-stats=") else f"-stats={work}/stats{k}.jsonl" for x in c]
        start = time.time() - t0
        log = os.path.join(work, f"log{k}.txt")
        with open(log, "w") as fh:
            subprocess.run(c, stdout=fh, stderr=subprocess.STDOUT, env=env, timeout=a.time + 600)
        text = open(log, errors="replace").read()
        m = CRASH.search(text)
        st = [json.loads(line) for line in open(f"{work}/stats{k}.jsonl")] if os.path.exists(f"{work}/stats{k}.jsonl") else []
        last = st[-1] if st else last
        if not m:
            break
        events.append({"t": round(start + float(m.group(2)), 2), "kind": m.group(1),
                       "signature": signature(m.group(1), text[: m.start()])})
        k += 1
    rec = {"target": target, "config": cfg, "seed": seed, "wall": round(time.time() - t0, 1),
           "crashed": bool(events), "kind": events[0]["kind"] if events else None,
           "tte": events[0]["t"] if events else None, "events": events, "restarts": k,
           "cov": last.get("cov"), "ft": last.get("ft"), "hot": last.get("hot"), "hot_total": last.get("hot_total"),
           "corp": last.get("corp"), "signature": events[0]["signature"] if events else None}
    if not a.keep:
        shutil.rmtree(work, ignore_errors=True)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", action="append", required=True, help="name=binary[,seed_dir[,dict]]")
    ap.add_argument("--config", action="append", required=True, help="name=weights_file (empty = no weights); "
                    "{target} / {seed} in the path are replaced by the target name / trial number")
    ap.add_argument("--trials", type=int, default=8)
    ap.add_argument("--time", type=int, default=600)
    ap.add_argument("--timeout", type=float, default=5)
    ap.add_argument("--par", type=int, default=12)
    ap.add_argument("--seeds")
    ap.add_argument("--dict")
    ap.add_argument("--flag", action="append", default=[])
    ap.add_argument("--work", default=tempfile.gettempdir())
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--engine", choices=["llmfuzz", "libfuzzer"], default="llmfuzz")
    ap.add_argument("--restart", action="store_true", help="keep fuzzing after crashes; record every crash")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    targets = [t.split("=", 1) for t in a.target]
    configs = [c.split("=", 1) for c in a.config]
    jobs = [(t, b, c, w.format(target=t, seed=s) if w else None, s)
            for s, (t, b), (c, w) in itertools.product(range(1, a.trials + 1), targets, configs)]
    with ThreadPoolExecutor(a.par) as ex, open(a.out, "a") as out:
        for rec in ex.map(lambda j: trial(*j, a), jobs):
            out.write(json.dumps(rec) + "\n")
            out.flush()
            print(f"{rec['target']:12s} {rec['config']:8s} seed={rec['seed']:2d} crashed={rec['crashed']!s:5s} "
                  f"tte={rec['tte']} cov={rec['cov']} hot={rec['hot']}/{rec['hot_total']} {rec['signature'] or ''}",
                  flush=True)


if __name__ == "__main__":
    main()

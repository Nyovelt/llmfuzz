"""llmfuzz command line.

  llmfuzz-cc / llmfuzz-c++ ...           build a target (adds instrumentation + runtime)
  llmfuzz run ./target [seeds/ ...]      score its functions and fuzz until Ctrl-C (or -t SECONDS)
      --prior size                       weight code by function size (default; no model needed)
      --prior llm                        weight code by the LLM's J-lens score (needs the [llm] extra)
      --prior scores.json                weight code by your own per-function scores
      --prior none                       plain coverage-guided fuzzing
  llmfuzz analyze ./target               only write the weights (./target.weights) and show the ranking
  llmfuzz fuzz ./target -w W -j 8 -t 3600 [-- args @@]   fuzz with given weights
  llmfuzz train-probe --train a.jsonl    fit the J-lens probe for another model
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .campaign import Summary


# Spend less energy on slow inputs (AFL's speed factor). The runtime's default is off, which is how the
# experiments in bench/ ran; the CLI turns it on.
TIME_ENERGY = "-time_energy=1"


def _z(v: Sequence[float]) -> list[float]:
    mu = sum(v) / len(v)
    sd = math.sqrt(sum((x - mu) ** 2 for x in v) / len(v)) or 1.0
    return [(x - mu) / sd for x in v]


def _base(region: str) -> str:
    """'ns::parse<T>#2' -> 'ns::parse' (the function a region belongs to)."""
    return region.split("#")[0].split("<")[0]


def _matches(region: str, name: str) -> bool:
    b = _base(region)
    return b == name or b.endswith("::" + name)


def load_scores(path: str) -> dict[str, float]:
    """Per-function scores from {"name": score, ...} or [{"name": ..., "score": ...}, ...]
    (e.g. a previous BINARY.weights.json)."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        sys.exit(f"llmfuzz: cannot read scores from {path}: {e}")
    if isinstance(data, dict):
        items = list(data.items())
    elif isinstance(data, list) and all(isinstance(d, dict) and "name" in d and "score" in d for d in data):
        items = [(d["name"], d["score"]) for d in data]
    else:
        sys.exit(f"llmfuzz: {path} must be {{\"function\": score}} or a list of {{\"name\", \"score\"}}")
    out: dict[str, float] = {}
    for name, s in items:
        if not isinstance(s, (int, float)) or isinstance(s, bool) or not math.isfinite(s):
            sys.exit(f"llmfuzz: score of {name!r} in {path} is not a finite number")
        out[_base(str(name))] = float(s)
    return out


def cmd_analyze(a: argparse.Namespace) -> None:
    from . import lens as L
    from . import pcmap

    out = a.out or a.binary + ".weights"
    pcs, mods = pcmap.dump_pcs(a.binary)
    sym: list[pcmap.Frame] = []
    for m, path in sorted(mods.items()):  # symbolize each instrumented module
        obj = path if os.path.exists(path) else a.binary
        sym += pcmap.symbolize(obj, [pc[1] for pc in pcs if pc[3] == m])
    funcs, pc_func = pcmap.group_functions(pcs, sym, max_lines=a.chunk_lines)
    L.log(f"{len(pcs)} PCs -> {len(funcs)} source regions ({sum(p >= 0 for p in pc_func)} PCs mapped)")
    if not funcs:
        sys.exit("llmfuzz: no PCs could be mapped to source (build with -g and keep sources in place)")
    llm, source = [0.0] * len(funcs), f"model={a.model}"
    per_line: list[L.LineScores | None] | None = None
    if a.scores:  # the user's own predictor: matched by function name, everything else neutral
        given = load_scores(a.scores)
        hits = [next((s for n, s in given.items() if _matches(f.name, n)), None) for f in funcs]
        if not any(h is not None for h in hits):
            sys.exit(f"llmfuzz: no function of {a.binary} matches a name in {a.scores}")
        missing = sorted(n for n in given if not any(_matches(f.name, n) for f in funcs))
        if missing:
            L.log(f"{len(missing)} name(s) in {a.scores} match no function: {', '.join(missing[:5])}"
                  + (" ..." if len(missing) > 5 else ""))
        llm, source = [0.0 if h is None else h for h in hits], f"scores={os.path.basename(a.scores)}"
    elif a.control not in ("uniform", "size", "oracle"):
        lens = L.Lens(a.model, a.lens, a.device, a.dtype)
        probe = L.Probe.load(a.probe) if a.probe else L.default_probe(lens)
        llm, lines = L.score_functions([(f.file, f.text) for f in funcs], lens, probe,
                                       a.cache or a.binary + ".llmcache.json", max_tok=a.max_tok, lines=a.line_weight > 0)
        per_line = lines if a.line_weight > 0 else None
    beta = 1.0 if a.control == "size" else a.size_prior
    size = _z([math.log(1 + f.size) for f in funcs])
    for f, s, sz in zip(funcs, _z(llm), size):  # optional complexity prior: + beta * z(log #lines)
        f.score = s + beta * sz
    if a.control == "shuffle":  # random-guidance control with the same score distribution
        perm = [f.score for f in funcs]
        random.Random(a.seed).shuffle(perm)
        for f, s in zip(funcs, perm):
            f.score = s
    if a.control == "oracle":  # synthetic predictor: random scores, the --oracle functions at rank quantile Q
        rnd = random.Random(a.seed)  # (--oracle-flat: equal scores elsewhere, the --oracle functions on top)
        z = [0.0 if a.oracle_flat else rnd.gauss(0, 1) for _ in funcs]
        at = 1.0 if a.oracle_flat else sorted(z, reverse=True)[min(len(z) - 1, int(a.oracle_rank * len(z)))]
        hit = [any(_matches(f.name, o) for o in a.oracle) for f in funcs]
        if not any(hit):
            sys.exit(f"llmfuzz: no function matches --oracle {' '.join(a.oracle)}")
        for f, s, h in zip(funcs, z, hit):
            f.score = at if h else s
    hot = pcmap.assign_weights(funcs, k=a.k, wmin=a.wmin, wmax=a.wmax, hot_frac=a.hot_frac)
    pc_w = pcmap.line_weights(funcs, sym, per_line, a.line_weight, a.wmin, a.wmax) if per_line and a.control == "none" else None
    pcmap.write_weights(out, pcs, pc_func, funcs, hot, header=f"{source} control={a.control}", pc_w=pc_w)
    ranked = sorted(funcs, key=lambda f: -f.score)
    with open(f"{out}.json.tmp-{os.getpid()}", "w") as fh:
        json.dump([{"name": f.name, "file": f.file, "line": f.start, "end": f.end, "score": round(f.score, 4),
                    "weight": round(f.weight, 3), "pcs": len(f.pcs)} for f in ranked], fh, indent=1)
    os.replace(fh.name, out + ".json")
    print(f"wrote {out} (hot threshold {hot:.2f}) and {out}.json\n\ntop functions by {_ranked_by(a)}:")
    top: dict[tuple[str, str], list[pcmap.Func]] = {}  # a long function's regions: shown once, at its best
    for f in ranked:
        top.setdefault((f.file, f.name.split("#")[0]), []).append(f)
    root = os.path.commonpath([os.path.dirname(f.file) for f in funcs])
    for (file, name), fs in list(top.items())[: a.top]:
        f = fs[0]
        label = name + (f" [{len(fs)} regions]" if len(fs) > 1 else "")
        print(f"  {f.score:+7.3f}  w={f.weight:5.2f}  {label:44.44s} {os.path.relpath(file, root)}:{f.start}")


def _ranked_by(a: argparse.Namespace) -> str:
    if a.scores:
        return f"the scores in {a.scores}"
    return {"size": "size", "uniform": "nothing (uniform weights)", "oracle": "the oracle",
            "shuffle": "shuffled LLM score"}.get(a.control, "LLM bug score")


def _print_summary(s: Summary, binary: str, target_args: Sequence[str], out: str) -> None:
    from .campaign import secs

    crashes = s["crashes"]
    print(f"\n[llmfuzz] done in {secs(s['elapsed'])}, {s['execs']:,} execs: {len(crashes)} unique crash(es); "
          f"details in {out}/summary.json")
    for i, c in enumerate(crashes, 1):
        art = c["artifact"]
        if target_args:  # program mode: the input goes where @@ is, or to stdin
            args = [art if x == "@@" else x for x in target_args]
            repro = " ".join([binary] + args) + ("" if "@@" in target_args else f" < {art}")
        else:
            repro = f"{binary} {art}"
        hits = f" ({c['hits']} hits)" if c["hits"] > 1 else ""
        print(f"  #{i} {c['kind']} at {secs(c['time'])}{hits}: {c['signature']}\n     reproduce: {repro}\n"
              f"     report:    {art}.report.txt")


def cmd_fuzz(a: argparse.Namespace) -> None:
    from .campaign import run

    s = run(a.binary, a.out, jobs=a.jobs, total_time=a.time, weights=a.weights, seeds=a.seeds,
            dict_path=a.dict, timeout=a.timeout, extra=[TIME_ENERGY] + a.flag, target_args=a.args,
            stop_on_crash=a.stop_on_crash, seed=a.seed)
    _print_summary(s, a.binary, a.args, a.out)


def _fresh(path: str, *inputs: str | None) -> bool:
    """path exists and is newer than every input file."""
    return os.path.exists(path) and all(os.path.getmtime(path) >= os.path.getmtime(i) for i in inputs if i)


def cmd_run(a: argparse.Namespace) -> None:
    from .campaign import run

    if not (os.path.isfile(a.binary) and os.access(a.binary, os.X_OK)):
        sys.exit(f"llmfuzz: {a.binary} is not an executable file")
    for d in a.seeds:
        if not os.path.isdir(d):
            sys.exit(f"llmfuzz: seed corpus {d} is not a directory")
    prior = a.prior
    weights: str | None = None
    if prior == "none":
        print("[llmfuzz] plain coverage-guided fuzzing (no weights)")
    else:
        scores = prior if prior not in ("size", "llm") else None
        if scores and not os.path.isfile(scores):
            sys.exit(f"llmfuzz: --prior must be size, llm, none or a scores file; {prior} is none of these")
        tag = "scores" if scores else prior
        weights = f"{a.binary}.{tag}.weights"
        if _fresh(weights, a.binary, scores):
            print(f"[llmfuzz] reusing {weights} (delete it to recompute)")
        else:
            argv = ["analyze", a.binary, "-o", weights, "--top", str(a.top)]
            argv += ["--scores", scores] if scores else ["--control", "size" if prior == "size" else "none"]
            for opt in ("model", "lens", "device"):
                if getattr(a, opt):
                    argv += [f"--{opt}", getattr(a, opt)]
            cmd_analyze(build_parser().parse_args(argv))
    total = a.time if a.time else 1e9  # no -t: until Ctrl-C
    where = "until Ctrl-C" if not a.time else f"for {a.time:g}s"
    print(f"[llmfuzz] fuzzing {a.binary} with {a.jobs} job(s) {where}; corpus and crashes in {a.out}/", flush=True)
    s = run(a.binary, a.out, jobs=a.jobs, total_time=total, weights=weights, seeds=a.seeds, dict_path=a.dict,
            timeout=a.timeout, extra=[TIME_ENERGY], target_args=a.args, stop_on_crash=a.stop_on_crash, seed=a.seed,
            status_every=10)
    _print_summary(s, a.binary, a.args, a.out)


def cmd_train(a: argparse.Namespace) -> None:
    from . import lens as L

    L.train_probe(L.Lens(a.model, a.lens, a.device, a.dtype), a.train, a.out, a.eval, l2=a.l2, max_tok=a.max_tok)


def build_parser() -> argparse.ArgumentParser:
    from .lens import DEFAULT_LENS, DEFAULT_MODEL

    ap = argparse.ArgumentParser(prog="llmfuzz", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("cc", help="clang wrapper (same as llmfuzz-cc)")
    sub.add_parser("cxx", help="clang++ wrapper (same as llmfuzz-c++)")

    def model_args(p: argparse.ArgumentParser, defaults: bool = True) -> argparse._ArgumentGroup:
        g = p.add_argument_group("model (for the llm prior)")
        g.add_argument("--model", default=DEFAULT_MODEL if defaults else None,
                       help=f"HF causal LM (default {DEFAULT_MODEL})")
        g.add_argument("--lens", default=DEFAULT_LENS if defaults else None, help="J-lens file or hf_repo:path")
        g.add_argument("--device", help="cuda / mps / cpu (auto)")
        g.add_argument("--dtype", choices=["bf16", "fp16", "fp32"],
                       help="model precision (default fp32 on the CPU, else bf16; fp16 is twice as fast on Apple M1)")
        return g

    def fuzz_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("-o", "--out", default="llmfuzz-out", help="output directory (default %(default)s)")
        p.add_argument("-j", "--jobs", type=int, default=1, help="parallel workers sharing one corpus (default 1)")
        p.add_argument("-x", "--dict", help="AFL/libFuzzer dictionary")
        p.add_argument("--timeout", type=float, default=2.0, help="per-input timeout in seconds (default %(default)s)")
        p.add_argument("--stop-on-crash", action="store_true", help="stop at the first new crash")
        p.add_argument("--seed", type=int, default=0, help="random seed")

    p = sub.add_parser("run", help="score the target's functions and fuzz it (the simple way)",
                       description="Score the target's functions (cached next to the binary), then fuzz until Ctrl-C "
                                   "or -t. Program-mode arguments go after --, with @@ for the input file.")
    p.add_argument("binary", help="target built with llmfuzz-cc / llmfuzz-c++")
    p.add_argument("seeds", nargs="*", help="seed corpus directories")
    p.add_argument("--prior", default="size", metavar="size|llm|none|FILE",
                   help="where the weights come from: function size (default), the LLM, nothing, or a JSON file "
                        "of per-function scores ({\"name\": score})")
    p.add_argument("-t", "--time", type=float, help="stop after this many seconds (default: run until Ctrl-C)")
    fuzz_args(p)
    p.add_argument("--top", type=int, default=10, help="show this many top-weighted functions")
    model_args(p, defaults=False)
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("analyze", help="only score the target's functions and write per-PC weights")
    p.add_argument("binary")
    p.add_argument("-o", "--out", help="weights file (default BINARY.weights)")
    p.add_argument("--scores", help="JSON of per-function scores to use instead of the LLM ({\"name\": score})")
    p.add_argument("--top", type=int, default=20, help="show this many top-weighted functions")
    g = model_args(p)
    g.add_argument("--probe", help="probe .npz (default: bundled probe for the model, else zero-shot)")
    g.add_argument("--cache", help="score cache (default BINARY.llmcache.json)")
    g.add_argument("--max-tok", type=int, default=1536, help="truncate functions to this many tokens")
    g = p.add_argument_group("weights and experiments (README §3)")
    g.add_argument("--k", type=float, default=1.0, help="weight = exp(k * zscore) (default %(default)s)")
    g.add_argument("--wmin", type=float, default=0.5)
    g.add_argument("--wmax", type=float, default=8.0)
    g.add_argument("--hot-frac", type=float, default=0.1, help="fraction of functions marked hot")
    g.add_argument("--chunk-lines", type=int, default=150, help="score long functions in regions of ~N lines")
    g.add_argument("--size-prior", type=float, default=0.0,
                   help="add BETA * z(log #lines) to the z-scored score (complexity prior)")
    g.add_argument("--line-weight", type=float, default=0.0,
                   help="also weight lines inside a region by the per-token J-lens readout (exp(B*z), try 0.5)")
    g.add_argument("--control", choices=["none", "shuffle", "uniform", "size", "oracle"], default="none",
                   help="ablations: shuffled scores, uniform weights, size prior only (no LLM), or a synthetic "
                        "predictor that ranks the --oracle functions at --oracle-rank")
    g.add_argument("--oracle", action="append", default=[], help="known-bug function for --control oracle (repeatable)")
    g.add_argument("--oracle-rank", type=float, default=0.0, help="their rank quantile, 0 = top (default %(default)s)")
    g.add_argument("--oracle-flat", action="store_true", help="no random scores: only the --oracle functions stand out")
    g.add_argument("--seed", type=int, default=0)
    p.set_defaults(fn=cmd_analyze)

    p = sub.add_parser("fuzz", help="fuzz with given weight files")
    p.add_argument("binary", help="target; program-mode arguments go after --, with @@ for the input file")
    p.add_argument("-w", "--weights", action="append",
                   help="weights from `llmfuzz analyze`; repeat to give workers different weights in turn "
                        "('none' = plain coverage fuzzing, the default)")
    p.add_argument("-t", "--time", type=float, default=3600, help="seconds (default %(default)s)")
    p.add_argument("-s", "--seeds", action="append", default=[], help="seed corpus dir (repeatable)")
    p.add_argument("--flag", action="append", default=[], help="extra runtime flag, e.g. --flag=-max_len=1024")
    fuzz_args(p)
    p.set_defaults(fn=cmd_fuzz)

    p = sub.add_parser("train-probe", help="fit the J-lens bug probe on labelled functions (PrimeVul JSONL)")
    p.add_argument("--train", nargs="+", required=True)
    p.add_argument("--eval", nargs="*", default=[])
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--l2", type=float)
    g = model_args(p)
    g.add_argument("--max-tok", type=int, default=1536, help="truncate functions to this many tokens")
    p.set_defaults(fn=cmd_train)
    return ap


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in ("cc", "cxx"):
        from .build import wrap

        return wrap(sys.argv[1] == "cxx", sys.argv[2:])
    argv = sys.argv[1:]
    target_args = argv[argv.index("--") + 1:] if "--" in argv else []
    a = build_parser().parse_args(argv[: argv.index("--")] if "--" in argv else argv)
    a.args = target_args
    try:
        a.fn(a)
    except KeyboardInterrupt:  # e.g. while scoring; a campaign handles Ctrl-C itself and writes its summary
        sys.exit("\nllmfuzz: interrupted")


if __name__ == "__main__":
    main()

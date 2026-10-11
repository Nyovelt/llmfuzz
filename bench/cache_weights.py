"""Write LLM weights on a machine that cannot run the model, from a score cache made on one that can.

On the fuzzing machine (runs `llmfuzz analyze` on the cached scores; functions missing from the cache are written
to MISSES.json and the script exits with status 3 instead of loading the model):
  python bench/cache_weights.py MISSES.json -- ./fuzzer -o w_llm.weights --model M --lens L --cache C.json
On the model machine (scores the missing functions into a copy of the cache, then copy it back and rerun):
  python bench/cache_weights.py --score MISSES.json C.json --model M --lens L [--probe P.npz] [--dtype fp16]
Scores are cached by model, lens, probe, file name and function text, so a rebuild on another platform hits the
cache for every function whose source is the same. The Linux runs of the 27B redo got their weights this way.
"""
import argparse
import json
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from llmfuzz import cli  # noqa: E402
from llmfuzz import lens as L  # noqa: E402


def score(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--score", nargs=2, metavar=("MISSES", "CACHE"), required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--lens", required=True)
    ap.add_argument("--probe")
    ap.add_argument("--device")
    ap.add_argument("--dtype", choices=["bf16", "fp16", "fp32"])
    a = ap.parse_args(argv)
    lens = L.Lens(a.model, a.lens, a.device, a.dtype)
    probe = L.Probe.load(a.probe) if a.probe else L.default_probe(lens)
    with open(a.score[0]) as f:
        items = [(p, c) for p, c in json.load(f)]
    L.score_functions(items, lens, probe, a.score[1])
    print(f"scored {len(items)} functions into {a.score[1]}")


def weights(misses, argv):
    def dump(self, items, *args, **kwargs):
        with open(misses, "w") as f:
            json.dump([[p, c] for p, c in items], f)
        print(f"{len(items)} functions are not in the cache: written to {misses}", flush=True)
        sys.exit(3)

    L.Lens.features = dump
    sys.modules.setdefault("torch", types.ModuleType("torch"))  # score_functions imports torch before scoring
    sys.argv = ["llmfuzz", "analyze"] + argv
    cli.main()


if __name__ == "__main__":
    if "--score" in sys.argv:
        score(sys.argv[1:])
    elif len(sys.argv) > 3 and sys.argv[2] == "--":
        weights(sys.argv[1], sys.argv[3:])
    else:
        sys.exit(__doc__)

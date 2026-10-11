"""Train and evaluate the J-lens bug probe on PrimeVul (README §1), keeping the lens features on disk.

  python bench/primevul_probe.py --model Qwen/Qwen3.6-27B --lens SPEC --dtype fp16 --out q36          # train + test
  python bench/primevul_probe.py --model Qwen/Qwen3-4B --lens SPEC --probe P.npz --out q4               # test a probe
DATA holds train_m.jsonl, test_m.jsonl and test_nat.jsonl (PrimeVul rows: func, target, project, file_name).
The probe is fit the way `llmfuzz train-probe` fits it (vocabulary, layers, project-grouped 5-fold CV over the L2
strength). Features are saved in chunks (OUT_<set>_<start>.npy), so an interrupted run resumes where it stopped.
Writes OUT.npz, OUT_results.json (probe / zero-shot / length AUCs) and OUT_<set>_scores.npy.
"""
import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from llmfuzz.lens import CONCEPT_WORDS, SUFFIX, Lens, Probe, auc  # noqa: E402


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def load(path):
    rows = [json.loads(line) for line in open(path)]
    return ([(r.get("file_name", "x.c"), r["func"]) for r in rows], np.array([int(r["target"]) for r in rows]),
            [r.get("project", str(i)) for i, r in enumerate(rows)],
            np.array([r["func"].count("\n") + 1 for r in rows]), np.array([len(r["func"]) for r in rows]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--lens", required=True)
    ap.add_argument("--out", required=True, help="prefix of the output files")
    ap.add_argument("--probe", help="evaluate this fitted probe instead of training one")
    ap.add_argument("--device")
    ap.add_argument("--dtype", choices=["bf16", "fp16", "fp32"])
    ap.add_argument("--data", default="data")
    ap.add_argument("--max-tok", type=int, default=1536)
    ap.add_argument("--batch-tokens", type=int, default=8192)
    ap.add_argument("--chunk", type=int, default=250)
    a = ap.parse_args()

    lens = Lens(a.model, a.lens, device=a.device, dtype=a.dtype)
    L = lens.n_layers
    sets = {k: load(f"{a.data}/{k}.jsonl") for k in ("train_m", "test_m", "test_nat")}
    if a.probe:
        probe = Probe.load(a.probe)
        vocab, layers = probe.vocab, probe.layers
    else:
        layers = list(range(2 * L // 3, L))
        vpath = f"{a.out}_vocab.json"
        if os.path.exists(vpath):
            vocab = json.load(open(vpath))
        else:  # concept words + tokens the lens often surfaces at the review question
            tops = lens.features(sets["train_m"][0][:400], [], layers, max_tok=a.max_tok, top=15,
                                 batch_tokens=a.batch_tokens).top
            freq = Counter(t for row in tops for t in set(row.ravel().tolist()))
            vocab = list(dict.fromkeys(lens.vocab_ids(CONCEPT_WORDS)
                                       + [t for t, c in freq.most_common() if c >= 0.02 * len(tops)]))
            json.dump(vocab, open(vpath, "w"))
    log(f"{L} layers, probe layers {layers[0]}..{layers[-1]}, {len(vocab)} tokens")

    feats = {}
    for k in ("test_m", "test_nat") if a.probe else ("train_m", "test_m", "test_nat"):
        items, parts = sets[k][0], []
        for c in range(0, len(items), a.chunk):
            path = f"{a.out}_{k}_{c:05d}.npy"
            if not os.path.exists(path):
                t0 = time.time()
                part = lens.features(items[c: c + a.chunk], vocab, layers, max_tok=a.max_tok,
                                     batch_tokens=a.batch_tokens).logp
                np.save(path, part.astype(np.float16))
                log(f"{k} {c + len(part)}/{len(items)}: {(time.time() - t0) / len(part):.2f} s/function")
            parts.append(np.load(path).astype(np.float32))
        feats[k] = np.concatenate(parts)

    res = {"model": a.model, "lens": a.lens, "dtype": a.dtype, "layers": layers, "n_vocab": len(vocab)}
    if not a.probe:  # L2 strength by 5-fold CV AUC, folds grouped by project
        F, y, groups = feats["train_m"], sets["train_m"][1], sets["train_m"][2]
        fold_of = np.array([int(hashlib.sha1(g.encode()).hexdigest(), 16) % 5 for g in groups])
        folds = [np.flatnonzero(fold_of == k) for k in range(5)]
        best = None
        for c in [3.0, 10.0, 30.0, 100.0]:
            s = np.zeros(len(y))
            for k in range(5):
                tr = np.concatenate([folds[j] for j in range(5) if j != k])
                s[folds[k]] = Probe(vocab, layers).fit(F[tr], y[tr], l2=c).logit(F[folds[k]])
            res[f"cv_auc_l2={c:g}"] = auc(y, s)
            log(f"l2={c:g}: CV AUC {res[f'cv_auc_l2={c:g}']:.3f}")
            best = max(best or (res[f"cv_auc_l2={c:g}"], c), (res[f"cv_auc_l2={c:g}"], c))
        probe = Probe(vocab, layers, meta={"lens_name": lens.name, "suffix": SUFFIX, "max_tok": a.max_tok,
                                           "trained_on": "train_m.jsonl", "cv_auc": best[0], "l2": best[1]})
        probe.fit(F, y, l2=best[1])
        res["cv_auc"], res["l2"] = best

    # zero-shot score from the same features: P(yes) vs P(no), averaged over the last quarter of the layers
    words = [lens.tok.decode([t]).strip().lower() for t in vocab]
    yes, no = [i for i, w in enumerate(words) if w == "yes"], [i for i, w in enumerate(words) if w == "no"]
    zl = [i for i, l in enumerate(layers) if l >= int(0.75 * L)]

    def zero_shot(F):
        G = F[:, zl]
        return (np.logaddexp.reduce(G[:, :, yes], -1) - np.logaddexp.reduce(G[:, :, no], -1)).mean(1)

    def z(v):
        return (v - v.mean()) / (v.std() + 1e-9)

    for k in ("test_m", "test_nat"):
        _, y, _, lines, chars = sets[k]
        p, zs = probe.logit(feats[k]), zero_shot(feats[k])
        r = {"n": len(y), "pos": int(y.sum()), "probe": auc(y, p), "zero_shot": auc(y, zs), "lines": auc(y, lines),
             "chars": auc(y, chars), "probe+lines": auc(y, z(p) + z(np.log(lines))),
             "zero_shot+lines": auc(y, z(zs) + z(np.log(lines)))}
        res[k] = r
        np.save(f"{a.out}_{k}_scores.npy", np.stack([p, zs]))
        log(f"{k}: " + ", ".join(f"{n} {v:.3f}" if isinstance(v, float) else f"{n} {v}" for n, v in r.items()))
    if not a.probe:
        probe.meta.update({f"auc_{k}": res[k]["probe"] for k in ("test_m", "test_nat")})
        probe.save(f"{a.out}.npz")
    json.dump(res, open(f"{a.out}_results.json", "w"), indent=1)


if __name__ == "__main__":
    main()

"""Score the call-context dataset with an LLM + J-lens (not part of the llmfuzz core; needs a GPU).

For every region of bench/ctx_dataset.py's output and every context variant, builds the prompt
  [context] + "// File: x.c\\n" + region + SUFFIX
and stores the J-lens log-probs of a fixed token set at the question position for the upper half of the layers.
Variants:
  iso      the region alone (what `llmfuzz analyze` does)
  callees  the functions it calls (first lines of each)
  callers  the functions that call it (lines around the call site)
  stack    one call path from the fuzzer entry down to it (lines around each call site)
  file     the source text right before it in its file
  stack+callees
Structure-selected variants (need the fields added by bench/ctx_ast.py; --budget applies to each part):
  defs       definitions it refers to (macros, types, accessed records, globals), from the clang AST
  args       per caller, a backward slice of the statements that compute/test the call's arguments
  defs+args  both
  calleesig  signatures (and comments) of the project functions it calls
  window     fixed-length raw code around it in the same file (after-text first, then before-text)
  rand       control: as many tokens as `defs`, taken from a random place in the same file
  python bench/ctx_score.py data.json out.npz --model Qwen/Qwen3-8B --lens hf_repo:path --4bit
"""
import argparse
import json
import random
import re
import sys
import time

import numpy as np
import torch
from huggingface_hub import hf_hub_download
from transformers import AutoModelForCausalLM, AutoTokenizer

SUFFIX = "\n/* Code review. Q: Is there a bug in the function above? A:"
WORDS = "yes Yes YES no No NO".split()


def window(text, name, k):
    """Signature line plus +-k lines around the first mention of `name` (the call site)."""
    lines = text.splitlines(keepends=True)
    short = re.escape(name.split("::")[-1])
    hit = next((i for i, ln in enumerate(lines) if i and re.search(rf"\b{short}\b", ln)), None)
    if hit is None:
        return "".join(lines[: 2 * k + 1])
    a, b = max(1, hit - k), min(len(lines), hit + k + 1)
    return lines[0] + ("    /* ... */\n" if a > 1 else "") + "".join(lines[a:b]) + ("    /* ... */\n}\n" if b < len(lines) else "")


VARIANTS = ("iso", "callees", "callers", "stack", "stack+callees", "file", "defs", "args", "defs+args", "calleesig",
            "window", "rand")


def contexts(t, r, variant):
    """Context pieces (strings, nearest-first) for region r of target t; ValueError if variant is not a context."""
    if variant not in VARIANTS:
        raise ValueError(variant)
    D, d = t["defs"], r["def"]
    tag = lambda j: f"// {D[j]['file']}:{D[j]['start']}\n"  # noqa: E731
    if d is None or variant == "iso":
        return []
    if variant == "callees":
        return [tag(j) + "".join(D[j]["text"].splitlines(keepends=True)[:40]) for j in t["callees"][d]]
    if variant == "callers":
        return [tag(j) + window(D[j]["text"], D[d]["q"], 10) for j in t["callers"][d][:6]]
    if variant.startswith("stack"):
        path, k = [], t["parent"].get(str(d))
        while k is not None and len(path) < 12:
            path.append(k)
            k = t["parent"].get(str(k))
        nxt = [d] + path  # each path function is shown around its call to the next one
        out = [tag(j) + window(D[j]["text"], D[nxt[i]]["q"], 8) for i, j in enumerate(path)]
        if variant == "stack+callees":
            out = [tag(j) + "".join(D[j]["text"].splitlines(keepends=True)[:25]) for j in t["callees"][d]] + out
        return out
    if variant == "file":
        before = "".join(t["files"][r["path"]].splitlines(keepends=True)[: r["line"] - 1])
        return [before]
    if variant in ("defs", "args", "calleesig"):
        return r.get("ctx_" + variant, [])
    if variant == "defs+args":
        return r.get("ctx_defs", []) + r.get("ctx_args", [])
    if variant in ("window", "rand"):  # the rest of the file; build() cuts it to length
        before, after = around(t, r)
        return [before + after] if (before + after).strip() and (variant == "window" or r.get("ctx_defs")) else []
    raise ValueError(variant)


def around(t, r):
    """Source text of r's file before and after the region."""
    lines = t["files"][r["path"]].splitlines(keepends=True)
    return "".join(lines[: r["line"] - 1]), "".join(lines[r["line"] - 1 + r["lines"]:])


def context_ids(ids_of, t, r, variant, budget):
    """Token ids of the context pieces, nearest piece last, within budget tokens."""
    ctx, used = [], 0
    for p in contexts(t, r, variant):
        ids = ids_of(p + "\n")
        if variant == "file":
            ids = ids[-budget:]  # nearest text before the region
        if used + len(ids) > budget:
            if variant in ("defs", "args", "calleesig"):
                continue  # a smaller later piece may still fit
            break
        ctx.insert(0, ids)  # nearest piece ends up next to the region
        used += len(ids)
    return [i for c in ctx for i in c]


def build(tok, t, r, variant, budget, max_tok):
    ids_of = lambda s: tok(s, add_special_tokens=False).input_ids  # noqa: E731
    region = ids_of(f"// File: {r['file']}\n" + r["text"])[:max_tok]
    if variant == "defs+args":
        ctx = context_ids(ids_of, t, r, "args", budget) + context_ids(ids_of, t, r, "defs", budget)
    elif variant == "window":
        before, after = (ids_of(x) for x in around(t, r))
        nb = min(len(before), max(budget // 2, budget - len(after)))
        na = min(len(after), budget - nb)
        ctx = (ids_of("/* code after the function: */\n") + after[:na] if na else []) + \
            ids_of("\n/* code before the function: */\n") + before[len(before) - nb:] + ids_of("\n")
    elif variant == "rand":
        n = len(context_ids(ids_of, t, r, "defs", budget))
        rest = ids_of("".join(around(t, r))) if n else []
        start = random.Random(r["path"] + str(r["id"])).randrange(max(1, len(rest) - n + 1))
        ctx = rest[start:start + n] + (ids_of("\n") if n else [])
    else:
        ctx = context_ids(ids_of, t, r, variant, budget)
    return ctx + region + ids_of(SUFFIX)


def load(name, q4=False):
    """Tokenizer and model on the GPU (nf4 when q4)."""
    kw = dict(dtype=torch.bfloat16, device_map="cuda")
    if q4:
        from transformers import BitsAndBytesConfig
        kw["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                                       bnb_4bit_compute_dtype=torch.bfloat16)
    return AutoTokenizer.from_pretrained(name), AutoModelForCausalLM.from_pretrained(name, **kw).eval()


def vocab_ids(tok, probe_vocab=None):
    """Single-token ids of the yes/no words (with and without a leading space), plus a probe's vocabulary."""
    ids = [i for w in WORDS for v in (" " + w, w) for i in [tok(v, add_special_tokens=False).input_ids] if len(i) == 1]
    return sorted({i[0] for i in ids} | (set(np.load(probe_vocab)["vocab"].tolist()) if probe_vocab else set()))


class Readout:
    """J-lens log-probs of a token set at the last position of each sequence, for the upper half of the layers
    (the last layer is the model's own output distribution)."""

    def __init__(self, model, lens, vocab, lens_cpu=False, batch_tokens=8192):
        self.model, self.batch_tokens = model, batch_tokens
        self.dec = getattr(model.model, "language_model", model.model)  # multimodal checkpoints wrap the decoder
        n = len(self.dec.layers)
        self.layers = list(range(n // 2, n))
        repo, _, f = lens.partition(":")
        J = torch.load(hf_hub_download(repo, f), map_location="cpu", weights_only=True)["J"]
        jdev = "cpu" if lens_cpu else "cuda"
        self.J = {l: J[l].to(jdev, torch.float32 if lens_cpu else torch.bfloat16) for l in self.layers if l < n - 1}
        self.vt = torch.tensor(vocab, device="cuda")
        self.acts, self.pos = {}, {}  # pos is set only while __call__ runs, so generation passes are ignored
        for l in self.layers:
            self.dec.layers[l].register_forward_hook(lambda m, i, o, l=l: self._hook(o, l))

    def _hook(self, o, l):
        if self.pos:
            self.acts[l] = (o if torch.is_tensor(o) else o[0])[self.pos["rows"], self.pos["last"]]

    def __call__(self, seqs, pad):
        out = np.zeros((len(seqs), len(self.layers), len(self.vt)), np.float16)
        order = sorted(range(len(seqs)), key=lambda i: len(seqs[i]))
        t0, i = time.time(), 0
        with torch.no_grad():
            while i < len(order):
                j = i + 1
                while j < len(order) and len(seqs[order[j]]) * (j - i + 1) <= self.batch_tokens:
                    j += 1
                idx = order[i:j]
                w = max(len(seqs[k]) for k in idx)
                ids = torch.full((len(idx), w), pad, dtype=torch.long)
                mask = torch.zeros((len(idx), w), dtype=torch.long)
                for row, k in enumerate(idx):
                    ids[row, : len(seqs[k])] = torch.tensor(seqs[k])
                    mask[row, : len(seqs[k])] = 1
                self.pos["last"] = torch.tensor([len(seqs[k]) - 1 for k in idx], device="cuda")
                self.pos["rows"] = torch.arange(len(idx), device="cuda")
                self.dec(input_ids=ids.cuda(), attention_mask=mask.cuda(), use_cache=False)
                for li, l in enumerate(self.layers):
                    h = self.acts[l].to(torch.bfloat16)
                    if l in self.J:  # last layer: the model's own readout
                        h = (h.to(self.J[l]) @ self.J[l].T).to("cuda", torch.bfloat16)
                    lp = torch.log_softmax(self.model.lm_head(self.dec.norm(h)).float(), -1)[:, self.vt]
                    out[idx, li] = lp.cpu().numpy().astype(np.float16)
                self.acts.clear()
                i = j
                if i % 200 < len(idx) or i == len(order):
                    done = sum(len(seqs[k]) for k in order[:i])
                    print(f"{i}/{len(seqs)} prompts, {done / (time.time() - t0):.0f} tok/s", flush=True)
        self.pos.clear()
        return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data")
    ap.add_argument("out")
    ap.add_argument("--model", default="Qwen/Qwen3-8B")
    ap.add_argument("--lens", required=True, help="hf_repo:path of the J-lens .pt")
    ap.add_argument("--probe-vocab", help="probe .npz whose vocab ids to record too")
    ap.add_argument("--variants", default="iso,callees,callers,stack,file,stack+callees")
    ap.add_argument("--budget", type=int, default=3072, help="max context tokens")
    ap.add_argument("--max-tok", type=int, default=1536)
    ap.add_argument("--batch-tokens", type=int, default=8192)
    ap.add_argument("--4bit", dest="q4", action="store_true")
    ap.add_argument("--lens-cpu", action="store_true", help="keep the J matrices on the CPU (saves GPU memory)")
    a = ap.parse_args()
    tok = AutoTokenizer.from_pretrained(a.model)
    data = json.load(open(a.data))
    vocab = vocab_ids(tok, a.probe_vocab)
    items = [(tn, r["id"], v, build(tok, t, r, v, a.budget, a.max_tok))
             for tn, t in data.items() for r in t["regions"] for v in a.variants.split(",")]
    print(f"{len(items)} prompts, {sum(len(x[3]) for x in items) / 1e6:.2f}M tokens", flush=True)
    tok, model = load(a.model, a.q4)
    ro = Readout(model, a.lens, vocab, a.lens_cpu, a.batch_tokens)
    out = ro([ids for *_, ids in items], tok.pad_token_id or 0)
    meta = [(tn, rid, v, len(ids)) for tn, rid, v, ids in items]
    np.savez(a.out, feats=out, layers=np.array(ro.layers), vocab=np.array(vocab),
             meta=np.array(json.dumps({"items": meta, "model": a.model, "lens": a.lens, "budget": a.budget})))
    print("DONE", a.out, flush=True)


if __name__ == "__main__":
    main()

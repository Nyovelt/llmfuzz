"""Answer directly, think first, or write a contract first, then read the J-lens (not part of the llmfuzz core; GPU).

Every region of bench/ctx_dataset.py's output gets the same code-review question in the Qwen3.5/3.6 chat format, and
the readout (bench/ctx_score.Readout) is taken where the one-word answer would start:
  iso    the thinking block is empty: answer directly
  think  the model reasons first, up to --think-tokens; a block it has not closed by then is closed for it.
         --thoughts reuses the reasoning of an earlier run (e.g. bench/ctx_think_vllm.py's, without a token limit)
  spec   in a separate prompt the model writes a contract comment for the function (purpose, preconditions, buffer
         and index invariants) without judging it; the comment goes above the code as its docstring, then iso.
         --specs reuses the comments of an earlier run; --shuffle-specs gives every region the comment of another
         region of the same target instead (control: a docstring of the same kind but about other code)
  python bench/ctx_think.py data.json out.npz --model Qwen/Qwen3.6-27B --lens repo:path --4bit --lens-cpu
Writes out.npz in ctx_score.py's layout (the modes are its variants) and out.texts.jsonl with what was generated.
"""
import argparse
import json
import random
import time

import numpy as np
import torch

from ctx_score import Readout, load, vocab_ids

QUESTION = ("Review this C/C++ function from {file}.\n\n```c\n{code}\n```\n\n"
            "Does this function contain a bug (for example an out-of-bounds read or write, a use-after-free, "
            "an integer overflow or a logic error)? Answer with one word: Yes or No.")
SPEC = ("Write a short C comment block (at most 8 lines) documenting this function from {file}: what it does, "
        "the preconditions on its arguments, and the invariants on buffer sizes and index ranges that its callers "
        "and its implementation rely on. Describe the intended contract only; do not judge whether the code is "
        "correct.\n\n```c\n{code}\n```")


def chat(msg, thought=None):
    """Qwen3.5/3.6 chat prompt; thought=None leaves the thinking block open for generation."""
    head = f"<|im_start|>user\n{msg}<|im_end|>\n<|im_start|>assistant\n<think>\n"
    return head if thought is None else head + thought + "\n</think>\n\n"


def generate(tok, model, prompts, max_new, stop, batch, budget, sample):
    """Continuations of the prompt strings, cut before the first stop string, and whether it came. A batch holds
    at most `batch` prompts and `budget` tokens (prompt plus max_new for each)."""
    pad = tok.pad_token_id or 0
    seqs = [tok(p, add_special_tokens=False).input_ids for p in prompts]
    out, order, t0 = [None] * len(seqs), sorted(range(len(seqs)), key=lambda i: len(seqs[i])), time.time()
    kw = dict(do_sample=True, temperature=0.6, top_p=0.95, top_k=20) if sample else dict(do_sample=False)
    batches, s = [], 0
    while s < len(order):
        e = s + 1
        while e < len(order) and e - s < batch and (len(seqs[order[e]]) + max_new) * (e - s + 1) <= budget:
            e += 1
        batches.append(order[s:e])
        s = e
    for idx in batches:
        w = max(len(seqs[i]) for i in idx)
        ids = torch.full((len(idx), w), pad, dtype=torch.long)
        mask = torch.zeros((len(idx), w), dtype=torch.long)
        for row, i in enumerate(idx):  # left padding
            ids[row, w - len(seqs[i]):] = torch.tensor(seqs[i])
            mask[row, w - len(seqs[i]):] = 1
        with torch.no_grad():
            g = model.generate(input_ids=ids.cuda(), attention_mask=mask.cuda(), max_new_tokens=max_new,
                               stop_strings=[stop], tokenizer=tok, pad_token_id=pad, **kw)
        for row, i in enumerate(idx):
            text = tok.decode(g[row, w:], skip_special_tokens=False)
            for junk in ("<|im_end|>", "<|endoftext|>"):
                text = text.replace(junk, "")
            out[i] = (text.split(stop)[0], stop in text)
        print(f"generated {sum(x is not None for x in out)}/{len(order)}, {time.time() - t0:.0f}s", flush=True)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data")
    ap.add_argument("out")
    ap.add_argument("--model", default="Qwen/Qwen3.6-27B")
    ap.add_argument("--lens", required=True, help="hf_repo:path of the J-lens .pt")
    ap.add_argument("--modes", default="iso,think,spec")
    ap.add_argument("--think-tokens", type=int, default=512)
    ap.add_argument("--spec-tokens", type=int, default=200)
    ap.add_argument("--max-tok", type=int, default=1536, help="code tokens shown per region")
    ap.add_argument("--gen-batch", type=int, default=8, help="max prompts per generation batch")
    ap.add_argument("--gen-tokens", type=int, default=8192, help="max tokens per generation batch")
    ap.add_argument("--batch-tokens", type=int, default=4096)
    ap.add_argument("--4bit", dest="q4", action="store_true")
    ap.add_argument("--lens-cpu", action="store_true")
    ap.add_argument("--thoughts", help="texts.jsonl of an earlier run whose reasoning to reuse")
    ap.add_argument("--specs", help="texts.jsonl of an earlier run whose contract comments to reuse")
    ap.add_argument("--shuffle-specs", action="store_true", help="give each region another region's comment")
    a = ap.parse_args()
    torch.manual_seed(0)
    tok, model = load(a.model, a.q4)
    data = json.load(open(a.data))
    regs = [(tn, r) for tn, t in data.items() for r in t["regions"]]
    code = [tok.decode(tok(r["text"], add_special_tokens=False).input_ids[: a.max_tok]) for _, r in regs]
    ask = [QUESTION.format(file=r["file"], code=c) for (_, r), c in zip(regs, code)]
    modes, prompts, texts = a.modes.split(","), {}, [{"target": tn, "id": r["id"]} for tn, r in regs]
    if "iso" in modes:
        prompts["iso"] = [chat(q, "") for q in ask]
    if "think" in modes:
        if a.thoughts:
            old = {(x["target"], x["id"]): (x["think"], x["think_closed"]) for x in map(json.loads, open(a.thoughts))}
            res = [old[(tn, r["id"])] for tn, r in regs]
        else:
            res = generate(tok, model, [chat(q) for q in ask], a.think_tokens, "</think>", a.gen_batch, a.gen_tokens,
                           sample=True)
        prompts["think"] = [chat(q, th.rstrip()) for q, (th, _) in zip(ask, res)]
        for x, (th, closed) in zip(texts, res):
            x["think"], x["think_closed"] = th, closed
    if "spec" in modes:
        if a.specs:
            old = {(x["target"], x["id"]): x["spec"] for x in map(json.loads, open(a.specs))}
            specs = [old[(tn, r["id"])] for tn, r in regs]
        else:
            msgs = [chat(SPEC.format(file=r["file"], code=c), "") + "/*" for (_, r), c in zip(regs, code)]
            res = generate(tok, model, msgs, a.spec_tokens, "*/", a.gen_batch, a.gen_tokens, sample=False)
            specs = ["/*" + sp.rstrip() + "\n */" for sp, _ in res]
        if a.shuffle_specs:  # a derangement within each target
            rnd = random.Random(0)
            for tn in {t for t, _ in regs}:
                idx = [i for i, (t, _) in enumerate(regs) if t == tn]
                perm = idx[:]
                while any(i == j for i, j in zip(idx, perm)):
                    rnd.shuffle(perm)
                moved = [specs[j] for j in perm]
                for i, sp in zip(idx, moved):
                    specs[i] = sp
        prompts["spec"] = [chat(QUESTION.format(file=r["file"], code=sp + "\n" + c), "")
                           for (_, r), c, sp in zip(regs, code, specs)]
        for x, sp in zip(texts, specs):
            x["spec"] = sp
    items = [(tn, r["id"], m, tok(p, add_special_tokens=False).input_ids)
             for m in modes for (tn, r), p in zip(regs, prompts[m])]
    print(f"{len(items)} readouts, {sum(len(x[3]) for x in items) / 1e6:.2f}M tokens", flush=True)
    vocab = vocab_ids(tok)
    ro = Readout(model, a.lens, vocab, a.lens_cpu, a.batch_tokens)
    feats = ro([ids for *_, ids in items], tok.pad_token_id or 0)
    meta = [(tn, rid, m, len(ids)) for tn, rid, m, ids in items]
    np.savez(a.out, feats=feats, layers=np.array(ro.layers), vocab=np.array(vocab),
             meta=np.array(json.dumps({"items": meta, "model": a.model, "lens": a.lens, "budget": a.max_tok,
                                     "think_tokens": a.think_tokens})))
    with open(a.out.rsplit(".", 1)[0] + ".texts.jsonl", "w") as f:
        for x in texts:
            f.write(json.dumps(x) + "\n")
    print("DONE", a.out, flush=True)


if __name__ == "__main__":
    main()

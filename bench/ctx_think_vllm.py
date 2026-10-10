"""The reasoning of bench/ctx_think.py's "think" mode, generated with vLLM so that it can run to its end (GPU).

Same prompts as ctx_think.py (question, chat format, code cut with the readout model's tokenizer) and the same
sampling (temperature 0.6, top_p 0.95, top_k 20); vLLM only writes the reasoning, the J-lens readout is then taken
with the HF model, which closes a reasoning that is still open after --think-tokens:
  python bench/ctx_think_vllm.py data.json thoughts.jsonl --model cyankiwi/Qwen3.6-27B-AWQ-INT4 \
      --tokenizer Qwen/Qwen3.6-27B --think-tokens 8192
  python bench/ctx_think.py data.json out.npz --model Qwen/Qwen3.6-27B --lens ... --modes iso,think \
      --thoughts thoughts.jsonl --4bit --lens-cpu
"""
import argparse
import json

from transformers import AutoTokenizer
from vllm import LLM, SamplingParams

from ctx_think import QUESTION, chat


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data")
    ap.add_argument("out")
    ap.add_argument("--model", required=True, help="checkpoint vLLM runs (e.g. a 4-bit one of the readout model)")
    ap.add_argument("--tokenizer", help="the readout model's tokenizer, which cuts the code (default: --model's)")
    ap.add_argument("--think-tokens", type=int, default=8192)
    ap.add_argument("--max-tok", type=int, default=1536, help="code tokens shown per region")
    ap.add_argument("--mem", type=float, default=0.9, help="vLLM gpu_memory_utilization")
    ap.add_argument("--kv-fp8", action="store_true")
    ap.add_argument("--max-seqs", type=int, help="vLLM max_num_seqs (hybrid models reserve state per sequence)")
    ap.add_argument("--max-batched", type=int, help="vLLM max_num_batched_tokens (smaller: less activation memory)")
    ap.add_argument("--eager", action="store_true", help="no CUDA graphs (frees their memory, slower decoding)")
    ap.add_argument("--text-only", action="store_true", help="multimodal checkpoint: skip the vision encoder")
    a = ap.parse_args()
    tok = AutoTokenizer.from_pretrained(a.tokenizer or a.model)
    data = json.load(open(a.data))
    regs = [(tn, r) for tn, t in data.items() for r in t["regions"]]
    code = [tok.decode(tok(r["text"], add_special_tokens=False).input_ids[: a.max_tok]) for _, r in regs]
    prompts = [chat(QUESTION.format(file=r["file"], code=c)) for (_, r), c in zip(regs, code)]
    kw = dict(language_model_only=True) if a.text_only else {}
    if a.kv_fp8:
        kw["kv_cache_dtype"] = "fp8"
    if a.max_seqs:
        kw["max_num_seqs"] = a.max_seqs
    if a.max_batched:
        kw["max_num_batched_tokens"] = a.max_batched
    if a.eager:
        kw["enforce_eager"] = True
    llm = LLM(a.model, tokenizer=a.tokenizer or a.model, gpu_memory_utilization=a.mem, seed=0,
              max_model_len=max(len(tok(p).input_ids) for p in prompts) + a.think_tokens + 16, **kw)
    end = tok.convert_tokens_to_ids("</think>")
    sp = SamplingParams(temperature=0.6, top_p=0.95, top_k=20, max_tokens=a.think_tokens, stop=["</think>"],
                        stop_token_ids=[end])
    outs, n = llm.generate(prompts, sp), 0
    with open(a.out, "w") as f:
        for (tn, r), o in zip(regs, outs):
            c = o.outputs[0]
            closed = c.finish_reason == "stop" and c.stop_reason in ("</think>", end)
            n += closed
            f.write(json.dumps({"target": tn, "id": r["id"], "think": c.text.split("</think>")[0],
                                "think_closed": closed, "think_tokens": len(c.token_ids)}) + "\n")
    print(f"DONE {a.out}: {len(outs)} thoughts, {n} closed within {a.think_tokens} tokens", flush=True)


if __name__ == "__main__":
    main()

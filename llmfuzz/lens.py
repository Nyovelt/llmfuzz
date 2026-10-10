"""Score source functions by how buggy an LLM's hidden states say they are.

Readout: the Jacobian lens (J-lens; Anthropic, "Verbalizable Representations
Form a Global Workspace in Language Models", 2026). A residual h_l at layer l
is transported into the final-layer basis with the average Jacobian
J_l = E[dh_final/dh_l] and decoded with the model's own unembedding:
    lens_l(h) = lm_head(norm(J_l @ h)).
For each function we append a review question and read the lens at the last
position over mid/late layers. The log-probs of a fixed vocabulary of concept
tokens (" yes", " vulnerable", " overflow", ...) form a small feature vector;
a logistic-regression probe trained on PrimeVul (`llmfuzz train-probe`) maps
it to a bug logit. Without a probe, a zero-shot yes-vs-no lens score is used.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

import numpy as np
from numpy.typing import ArrayLike, NDArray

if TYPE_CHECKING:
    import torch

DEFAULT_MODEL = "Qwen/Qwen3-4B"
DEFAULT_LENS = "neuronpedia/jacobian-lens:qwen3-4b/jlens/Salesforce-wikitext/Qwen3-4B_jacobian_lens.pt"
PROBE_DIR = Path(__file__).parent / "probes"
SUFFIX = "\n/* Code review. Q: Is there a bug in the function above? A:"
CONCEPT_WORDS = (
    "yes no Yes No YES NO vulnerable vulnerability vulnerabilities unsafe insecure risk risks bug bugs buggy "
    "flaw flawed overflow overflows underflow overrun bounds buffer crash leak leaks corrupt corruption exploit "
    "dangerous incorrect incorrectly improperly missing lacks unchecked uninitialized dereference null NULL "
    "negative integer truncated fails wrong error correct correctly safe safely properly fine none"
).split()
# Per-token readout for line-level localization: lens mass on these concepts at each code token.
LINE_WORDS = (
    "overflow overflows bounds buffer out-of-bounds oob unsafe vulnerable vulnerability bug bugs crash corrupt "
    "corruption exploit dangerous unchecked uninitialized dereference null NULL negative underflow overrun "
    "leak free freed dangling invalid wrong incorrect missing check checks length size index"
).split()
LINE_LAYERS = (0.445, 0.556, 0.667, 0.778, 0.889)  # fractions of depth (16..32 of 36 for Qwen3-4B)

Item = tuple[str, str]  # (source path, code)
LineScores = list[float | None]  # per code line; None where the line has no tokens


def log(msg: str) -> None:
    print(f"[llmfuzz] {msg}", file=sys.stderr, flush=True)


def pick_device() -> str:
    import torch

    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def _fetch(spec: str) -> str:
    """Local path, or 'hf_repo:path/in/repo' on the Hugging Face Hub."""
    if os.path.exists(spec):
        return spec
    from huggingface_hub import hf_hub_download

    repo, _, fname = spec.partition(":")
    return str(hf_hub_download(repo, fname))


class Readout(NamedTuple):
    logp: NDArray[np.float32]  # [N, len(layers), len(vocab)] lens log-probs at the question
    top: NDArray[np.int64]  # [N, len(layers), top] the lens's top tokens there (if top > 0)
    lines: list[NDArray[np.float32] | None]  # per code line: max J-lens log-mass on LINE_WORDS (if lines)


class Lens:
    """A causal LM plus a fitted Jacobian lens, read out at the last position."""

    def __init__(self, model: str = DEFAULT_MODEL, lens: str = DEFAULT_LENS, device: str | None = None) -> None:
        self.model_id, self.lens_spec, self.name = model, lens, f"{model}|{lens}"
        self._device = device
        self._n_layers: int | None = None
        # torch, tokenizer and weights load on first use: cached scores need none of them
        self._tok: Any = None  # transformers tokenizer
        self.model: Any = None  # transformers causal LM
        self.decoder: Any = None  # its decoder stack (.layers, .norm)
        self._J: Any = None  # lens Jacobians, indexed by layer
        self.J: dict[int, torch.Tensor] = {}

    @property
    def device(self) -> str:
        self._device = self._device or pick_device()
        return self._device

    @property
    def tok(self) -> Any:
        if self._tok is None:
            from transformers import AutoTokenizer

            self._tok = AutoTokenizer.from_pretrained(self.model_id)
        return self._tok

    @property
    def n_layers(self) -> int:
        if self._n_layers is None:
            from transformers import AutoConfig

            self._n_layers = int(AutoConfig.from_pretrained(self.model_id).get_text_config().num_hidden_layers)
        return self._n_layers

    def _load(self) -> None:
        import torch
        from transformers import AutoModelForCausalLM

        log(f"loading {self.model_id} on {self.device} and lens {self.lens_spec}")
        dtype = torch.float32 if self.device == "cpu" else torch.bfloat16
        model: Any = AutoModelForCausalLM.from_pretrained(self.model_id, dtype=dtype)
        self.model = model.to(self.device).eval()
        self.decoder = self.model.model
        self._J = torch.load(_fetch(self.lens_spec), map_location="cpu", weights_only=True)["J"]

    def vocab_ids(self, words: Iterable[str]) -> list[int]:
        ids: list[int] = []
        for w in words:
            for v in (" " + w, w):
                t = self.tok(v, add_special_tokens=False).input_ids
                if len(t) == 1 and t[0] not in ids:
                    ids.append(int(t[0]))
        return ids

    def _transport(self, layer: int, h: torch.Tensor) -> torch.Tensor:
        if layer >= self.n_layers - 1:  # final block: the model's own readout
            return h
        if layer not in self.J:
            self.J[layer] = self._J[layer].to(self.device, h.dtype)
        return h @ self.J[layer].T

    def encode(self, path: str, code: str, max_tok: int) -> tuple[list[int], NDArray[np.int64]]:
        """Token ids of header+code+question, and the code line of each code token (-1: header)."""
        head = f"// File: {os.path.basename(path)}\n"
        enc = self.tok(head + code, add_special_tokens=False, return_offsets_mapping=True)
        ids: list[int] = list(enc.input_ids[:max_tok])
        offs: list[tuple[int, int]] = enc.offset_mapping[:max_tok]
        nl = np.cumsum([c == "\n" for c in code])
        tok_line = np.array([nl[o[0] - len(head) - 1] if o[0] > len(head) else 0 if o[0] == len(head) else -1
                             for o in offs], dtype=np.int64)
        return ids + list(self.tok(SUFFIX, add_special_tokens=False).input_ids), tok_line

    def features(self, items: Sequence[Item], vocab: Sequence[int], layers: Sequence[int], max_tok: int = 1536,
                 batch_tokens: int = 8192, top: int = 0, lines: bool = False) -> Readout:
        """Lens log-probs of `vocab` at the question for each (path, code), at each of `layers`;
        if top > 0, also the lens's top-`top` token ids per layer; if lines, a per-code-line
        bug-concept score: max over the line's tokens of the J-lens log-mass on LINE_WORDS."""
        import torch

        with torch.no_grad():
            return self._features(items, vocab, layers, max_tok, batch_tokens, top, lines)

    def _features(self, items: Sequence[Item], vocab: Sequence[int], layers: Sequence[int], max_tok: int,
                  batch_tokens: int, top: int, lines: bool) -> Readout:
        import torch

        if self.model is None:
            self._load()
        enc = [self.encode(p, c, max_tok) for p, c in items]
        seqs = [e[0] for e in enc]
        line_layers = sorted({int(f * self.n_layers) for f in LINE_LAYERS}) if lines else []
        line_vocab = torch.tensor(self.vocab_ids(LINE_WORDS) if lines else [], dtype=torch.long, device=self.device)
        line_out: list[NDArray[np.float32] | None] = [None] * len(seqs)
        layers_all = sorted(set(layers) | set(line_layers))
        out = np.zeros((len(seqs), len(layers), len(vocab)), np.float32)
        tops = np.zeros((len(seqs), len(layers), top), np.int64)
        vocab_t = torch.tensor(vocab, dtype=torch.long, device=self.device)
        acts: dict[int, torch.Tensor] = {}

        def keep(l: int) -> Any:
            return lambda m, i, o: acts.__setitem__(l, o if torch.is_tensor(o) else o[0])

        hooks = [self.decoder.layers[l].register_forward_hook(keep(l)) for l in layers_all]
        pad = self.tok.pad_token_id if self.tok.pad_token_id is not None else 0
        order = sorted(range(len(seqs)), key=lambda i: len(seqs[i]))
        done, i, next_log = 0, 0, 0
        try:
            while i < len(order):
                j = i + 1  # grow batch while padded size fits the token budget
                while j < len(order) and len(seqs[order[j]]) * (j - i + 1) <= batch_tokens:
                    j += 1
                idx = order[i:j]
                width = max(len(seqs[k]) for k in idx)
                ids = torch.full((len(idx), width), pad, dtype=torch.long)
                mask = torch.zeros((len(idx), width), dtype=torch.long)
                for r, k in enumerate(idx):
                    ids[r, : len(seqs[k])] = torch.tensor(seqs[k])
                    mask[r, : len(seqs[k])] = 1
                last = torch.tensor([len(seqs[k]) - 1 for k in idx], device=self.device)
                self.decoder(input_ids=ids.to(self.device), attention_mask=mask.to(self.device), use_cache=False)
                rows = torch.arange(len(idx), device=self.device)
                for li, l in enumerate(layers):
                    h = self._transport(l, acts[l][rows, last])
                    logits = self.model.lm_head(self.decoder.norm(h)).float()
                    out[idx, li] = torch.log_softmax(logits, -1)[:, vocab_t].cpu().numpy()
                    if top:
                        tops[idx, li] = logits.topk(top, -1).indices.cpu().numpy()
                for r, k in enumerate(idx):  # per-token readout over the code
                    tl = enc[k][1]
                    if not line_layers or not (tl >= 0).any():
                        continue
                    tok = torch.zeros(len(tl), device=self.device)
                    for l in line_layers:
                        h = self._transport(l, acts[l][r, : len(tl)])
                        lp = torch.log_softmax(self.model.lm_head(self.decoder.norm(h)).float(), -1)
                        tok += torch.logsumexp(lp[:, line_vocab], -1) / len(line_layers)
                        del lp
                    tok_np = tok.cpu().numpy()
                    per_line = np.full(items[k][1].count("\n") + 1, np.nan, np.float32)
                    for t in np.flatnonzero(tl >= 0):
                        per_line[tl[t]] = np.fmax(per_line[tl[t]], tok_np[t])
                    line_out[k] = per_line
                done += len(idx)
                if done >= next_log and len(seqs) > 100:
                    log(f"  J-lens readout {done}/{len(seqs)}")
                    next_log += len(seqs) // 10
                i = j
        finally:
            for hk in hooks:
                hk.remove()
        return Readout(out, tops, line_out)


class Probe:
    """Logistic regression over standardized J-lens features."""

    def __init__(self, vocab: Iterable[int], layers: Iterable[int], mean: NDArray[np.float64] | None = None,
                 std: NDArray[np.float64] | None = None, w: NDArray[np.float64] | None = None, b: float = 0.0,
                 meta: dict[str, Any] | None = None) -> None:
        self.vocab, self.layers = [int(v) for v in vocab], [int(v) for v in layers]
        self.mean, self.std, self.w, self.b, self.meta = mean, std, w, float(b), meta or {}

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> Probe:
        z = np.load(path, allow_pickle=False)
        return cls(z["vocab"], z["layers"], z["mean"], z["std"], z["w"], float(z["b"]), json.loads(str(z["meta"])))

    def save(self, path: str) -> None:
        if self.w is None or self.mean is None or self.std is None:
            raise ValueError("only a fitted probe can be saved")
        np.savez(path, vocab=np.array(self.vocab), layers=np.array(self.layers), mean=self.mean, std=self.std,
                 w=self.w, b=np.array(self.b), meta=np.array(json.dumps(self.meta)))

    def logit(self, feats: NDArray[np.float32]) -> NDArray[np.float64]:
        if self.w is None or self.mean is None or self.std is None:  # zero-shot: P(yes-ish) - P(no-ish), averaged over layers
            yes, no = self.meta["yes"], self.meta["no"]
            d = np.logaddexp.reduce(feats[:, :, yes], -1) - np.logaddexp.reduce(feats[:, :, no], -1)
            return np.asarray(d.mean(1), np.float64)
        x = feats.reshape(len(feats), -1)
        return np.asarray(((x - self.mean) / self.std) @ self.w + self.b, np.float64)

    def fit(self, feats: NDArray[np.float32], y: NDArray[np.int64], l2: float = 1.0, steps: int = 300) -> Probe:
        import torch

        x = feats.reshape(len(feats), -1).astype(np.float64)
        mean, std = x.mean(0), x.std(0) + 1e-6
        X = torch.tensor((x - mean) / std)
        Y = torch.tensor(y, dtype=torch.float64)
        w = torch.zeros(X.shape[1], dtype=torch.float64, requires_grad=True)
        b = torch.zeros((), dtype=torch.float64, requires_grad=True)
        opt = torch.optim.LBFGS([w, b], max_iter=steps, line_search_fn="strong_wolfe")

        def closure() -> torch.Tensor:
            opt.zero_grad()
            loss = torch.nn.functional.binary_cross_entropy_with_logits(X @ w + b, Y) + l2 * (w @ w) / len(Y)
            torch.autograd.backward(loss)
            return loss

        opt.step(closure)  # type: ignore[no-untyped-call]  # LBFGS.step is unannotated in torch
        self.mean, self.std, self.w, self.b = mean, std, w.detach().numpy(), float(b.detach())
        return self


def default_probe(lens: Lens) -> Probe:
    """Bundled probe for this model+lens if there is one, else zero-shot."""
    for f in sorted(PROBE_DIR.glob("*.npz")):
        p = Probe.load(f)
        if p.meta.get("lens_name") == lens.name:
            log(f"using probe {f.name} (trained on {p.meta.get('trained_on', '?')})")
            return p
    log("no trained probe for this model/lens: using zero-shot yes/no lens readout")
    L = lens.n_layers
    vocab = lens.vocab_ids(["yes", "Yes", "YES", "no", "No", "NO"])
    words = [lens.tok.decode([t]).strip().lower() for t in vocab]
    meta = {"yes": [i for i, w in enumerate(words) if w == "yes"], "no": [i for i, w in enumerate(words) if w == "no"]}
    return Probe(vocab, list(range(int(0.75 * L), L)), meta=meta)


def score_functions(funcs: Sequence[Item], lens: Lens, probe: Probe, cache_path: str | None = None,
                    max_tok: int = 1536, lines: bool = False) -> tuple[list[float], list[LineScores | None]]:
    """(path, code) -> bug logit, and if lines, a score per code line (else None). Cached by content."""
    key = hashlib.sha1(json.dumps([lens.name, probe.layers, probe.vocab, SUFFIX, max_tok] + ([LINE_WORDS] if lines else [])
                                  + [None if probe.w is None else float(np.abs(probe.w).sum())]).encode()).hexdigest()[:12]
    cache: dict[str, Any] = {}  # hash -> logit, or [logit, line scores] if lines
    if cache_path and os.path.exists(cache_path):
        with open(cache_path) as f:
            cache = json.load(f)
    hashes = [key + hashlib.sha1((os.path.basename(p) + "\0" + c).encode()).hexdigest() for p, c in funcs]
    todo = [i for i, h in enumerate(hashes) if h not in cache]
    if todo:
        try:
            import torch  # noqa: F401
        except ImportError:
            sys.exit(f"llmfuzz: {len(todo)} functions are not in the score cache {cache_path} and torch is not installed: "
                     "pip install 'llmfuzz[llm]', or copy the cache from the machine that scored them")
        log(f"scoring {len(todo)} functions ({len(funcs) - len(todo)} cached)")
        res = lens.features([funcs[i] for i in todo], probe.vocab, probe.layers, max_tok=max_tok, lines=lines)
        for i, s, pl in zip(todo, probe.logit(res.logp), res.lines):
            cache[hashes[i]] = [float(s), None if pl is None else [None if np.isnan(x) else round(float(x), 4)
                                                                     for x in pl]] if lines else float(s)
        if cache_path:
            with open(cache_path, "w") as f:
                json.dump(cache, f)
    if lines:
        return [float(cache[h][0]) for h in hashes], [cache[h][1] for h in hashes]
    return [float(cache[h]) for h in hashes], [None] * len(hashes)


def auc(y: ArrayLike, s: ArrayLike) -> float:
    ya, sa = np.asarray(y), np.asarray(s)
    r = np.argsort(np.argsort(sa)) + 1.0
    npos = ya.sum()
    return float((r[ya == 1].sum() - npos * (npos + 1) / 2) / (npos * (len(ya) - npos)))


def train_probe(lens: Lens, train_files: Sequence[str], out: str, eval_files: Sequence[str] = (),
                l2: float | None = None, max_tok: int = 1536) -> Probe:
    """Fit the probe on JSONL rows with fields func, target (PrimeVul format)."""
    def load(files: Sequence[str]) -> tuple[list[Item], NDArray[np.int64], list[str]]:
        rows = []
        for f in files:
            with open(f) as fh:
                rows += [json.loads(line) for line in fh]
        return ([(r.get("file_name", "x.c"), r["func"]) for r in rows], np.array([int(r["target"]) for r in rows]),
                [r.get("project", str(i)) for i, r in enumerate(rows)])

    L = lens.n_layers
    layers = list(range(2 * L // 3, L))
    items, y, groups = load(train_files)
    # vocabulary = concept words + tokens the lens often surfaces at the review position
    tops = lens.features(items[:400], [], layers, max_tok=max_tok, top=15).top
    freq = Counter(t for row in tops for t in set(row.ravel().tolist()))
    vocab = list(dict.fromkeys(lens.vocab_ids(CONCEPT_WORDS) + [t for t, c in freq.most_common() if c >= 0.02 * len(tops)]))
    log(f"train-probe: {len(y)} functions ({int(y.sum())} buggy), {len(layers)} layers x {len(vocab)} tokens")
    F = lens.features(items, vocab, layers, max_tok=max_tok).logp
    grid = [l2] if l2 else [3.0, 10.0, 30.0, 100.0]
    fold_of = np.array([int(hashlib.sha1(g.encode()).hexdigest(), 16) % 5 for g in groups])  # grouped by project
    folds = [np.flatnonzero(fold_of == k) for k in range(5)]
    best: tuple[float, float] | None = None
    for c in grid:  # pick the L2 strength by 5-fold CV AUC
        s = np.zeros(len(y))
        for k in range(5):
            tr = np.concatenate([folds[j] for j in range(5) if j != k])
            s[folds[k]] = Probe(vocab, layers).fit(F[tr], y[tr], l2=c).logit(F[folds[k]])
        a = auc(y, s)
        log(f"  l2={c:g}: CV AUC {a:.3f}")
        best = max(best or (a, c), (a, c))
    assert best is not None
    probe = Probe(vocab, layers, meta={"lens_name": lens.name, "suffix": SUFFIX, "max_tok": max_tok,
                                       "trained_on": ",".join(os.path.basename(f) for f in train_files),
                                       "cv_auc": best[0], "l2": best[1]}).fit(F, y, l2=best[1])
    for f in eval_files:
        it, ye, _ = load([f])
        a = auc(ye, probe.logit(lens.features(it, vocab, layers, max_tok=max_tok).logp))
        probe.meta[f"auc_{os.path.basename(f)}"] = a
        log(f"  eval {f}: AUC {a:.3f}")
    probe.save(out)
    log(f"saved probe to {out}")
    return probe

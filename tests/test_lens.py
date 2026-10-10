"""The J-lens readout end to end on a tiny random Qwen3 model (needs the [llm] extra; no download)."""
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest

import numpy as np

from llmfuzz.lens import Lens, Probe, auc, default_probe, score_functions

HAVE_LLM = all(importlib.util.find_spec(m) for m in ("torch", "transformers", "tokenizers"))
CODE = [("a.c", "int f(int *p) {\n  return p[0];\n}\n"),
        ("b.c", "static void g(char *s, int n) {\n  char b[4];\n  memcpy(b, s, n);\n}\n")]


@unittest.skipUnless(HAVE_LLM, "needs torch, transformers and tokenizers")
class TinyLens(unittest.TestCase):
    tmp: tempfile.TemporaryDirectory[str]

    @classmethod
    def setUpClass(cls) -> None:
        import torch
        from tokenizers import Tokenizer, decoders, models, pre_tokenizers, trainers
        from transformers import PreTrainedTokenizerFast, Qwen3Config, Qwen3ForCausalLM

        cls.tmp = tempfile.TemporaryDirectory()
        d = cls.tmp.name
        bpe = Tokenizer(models.BPE())
        bpe.pre_tokenizer = pre_tokenizers.ByteLevel(add_prefix_space=False)
        bpe.decoder = decoders.ByteLevel()
        text = [c for _, c in CODE] + [" yes no Yes No YES NO bug overflow"] * 50
        # (the constructors of tokenizers / transformers classes are unannotated: hence the ignores)
        trainer = trainers.BpeTrainer(  # type: ignore[no-untyped-call]
            vocab_size=400, special_tokens=["<pad>"], initial_alphabet=pre_tokenizers.ByteLevel.alphabet())
        bpe.train_from_iterator(text, trainer)
        tok = PreTrainedTokenizerFast(tokenizer_object=bpe, pad_token="<pad>")  # type: ignore[no-untyped-call]
        tok.save_pretrained(d)
        torch.manual_seed(0)
        cfg = Qwen3Config(vocab_size=bpe.get_vocab_size(), hidden_size=32, intermediate_size=64, num_hidden_layers=4,
                          num_attention_heads=4, num_key_value_heads=2, head_dim=8, max_position_embeddings=512)
        Qwen3ForCausalLM(cfg).save_pretrained(d)  # type: ignore[no-untyped-call]
        torch.save({"J": torch.eye(32).repeat(4, 1, 1)}, os.path.join(d, "lens.pt"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def lens(self) -> Lens:
        return Lens(self.tmp.name, os.path.join(self.tmp.name, "lens.pt"), device="cpu")

    def test_zero_shot_scores_lines_and_cache(self) -> None:
        lens = self.lens()
        probe = default_probe(lens)
        self.assertTrue(probe.meta["yes"] and probe.meta["no"])
        self.assertEqual(probe.layers, [3])
        cache = os.path.join(self.tmp.name, "cache.json")
        scores, lines = score_functions(CODE, lens, probe, cache, lines=True)
        self.assertTrue(all(np.isfinite(scores)))
        for (_, code), ls in zip(CODE, lines):
            assert ls is not None
            self.assertEqual(len(ls), code.count("\n") + 1)
            self.assertIsNone(ls[-1])  # the empty line after the last newline has no tokens
        fresh = self.lens()  # cached: no model needed
        self.assertEqual(score_functions(CODE, fresh, probe, cache, lines=True), (scores, lines))
        self.assertIsNone(fresh.model)

    def test_features_shapes(self) -> None:
        r = self.lens().features(CODE, [5, 6, 7], [1, 3], top=4)
        self.assertEqual(r.logp.shape, (2, 2, 3))
        self.assertEqual(r.top.shape, (2, 2, 4))
        self.assertTrue((r.logp <= 0).all())

    def test_probe_fit_save_load(self) -> None:
        rng = np.random.default_rng(0)
        y = np.repeat(np.array([0, 1], np.int64), 50)
        feats = (rng.normal(size=(100, 2, 3)) + y[:, None, None]).astype(np.float32)
        probe = Probe([1, 2, 3], [0, 1]).fit(feats, y, l2=1.0)
        self.assertGreater(auc(y, probe.logit(feats)), 0.9)
        path = os.path.join(self.tmp.name, "probe.npz")
        probe.save(path)
        np.testing.assert_allclose(Probe.load(path).logit(feats), probe.logit(feats))


if __name__ == "__main__":
    unittest.main()

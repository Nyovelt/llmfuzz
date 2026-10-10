"""Build the examples with llmfuzz-cc and fuzz them until the known bug is found (needs clang)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROG = r"""#include <stdio.h>
#include <string.h>
static int parse(const char *s, size_t n) {
  char buf[8];
  if (n > 2 && s[0] == 'H' && s[1] == 'I') { memcpy(buf, s, n); return buf[0]; }
  return 0;
}
int main(int argc, char **argv) {
  char data[256];
  FILE *f = argc > 1 ? fopen(argv[1], "rb") : stdin;
  if (!f) return 1;
  size_t n = fread(data, 1, sizeof data, f);
  return parse(data, n);
}
"""

CUSTOM = r"""#include <stddef.h>
#include <stdint.h>
#include <string.h>
size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);
size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) {
  size = LLVMFuzzerMutate(data, size, max_size);
  if (seed % 64 == 0 && max_size >= 8) memcpy(data, "MUTATED!", 8), size = size < 8 ? 8 : size;
  return size;
}
static uint64_t fnv(const uint8_t *p, size_t n) {
  uint64_t h = 14695981039346656037ull;
  while (n--) h = (h ^ *p++) * 1099511628211ull;
  return h;
}
static int boom(const uint8_t *data, size_t size) {
  char buf[4];
  memcpy(buf, data, size);
  return buf[size - 1];
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* a hash, so comparison feedback cannot solve it: only the custom mutator writes this prefix */
  if (size >= 8 && fnv(data, 8) == fnv((const uint8_t *)"MUTATED!", 8)) return boom(data, size);
  return 0;
}
"""

SEED_CRASH = r"""#include <stddef.h>
#include <stdint.h>
#include <string.h>
static int overflow(const uint8_t *d, size_t n) { char b[4]; memcpy(b, d, n); return b[n - 1]; }
static int seed_bug(const uint8_t *d, size_t n) { return overflow(d, n); }
static int deep_bug(const uint8_t *d, size_t n) { return overflow(d, n); }
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
  if (n >= 5 && memcmp(d, "SEED!", 5) == 0) return seed_bug(d, n);
  if (n >= 6 && d[0] == 'F') return deep_bug(d, n);
  return 0;
}
"""


def llmfuzz(*args: str, cwd: str) -> str:
    r = subprocess.run([sys.executable, "-m", "llmfuzz", *args], cwd=cwd, capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=ROOT))
    if r.returncode:
        raise AssertionError(f"llmfuzz {' '.join(args)} failed:\n{r.stdout}\n{r.stderr}")
    return r.stdout + r.stderr


def crashes(out: str) -> list[dict[str, Any]]:
    with open(os.path.join(out, "summary.json")) as f:
        found: list[dict[str, Any]] = json.load(f)["crashes"]
    return found


@unittest.skipUnless(shutil.which("clang"), "needs clang")
class EndToEnd(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_harness_with_size_prior(self) -> None:
        llmfuzz("cc", "-O1", os.path.join(ROOT, "examples", "demo.c"), "-o", "demo", cwd=self.d)
        log = llmfuzz("run", "./demo", "-t", "120", "--stop-on-crash", cwd=self.d)
        self.assertIn("top functions by size", log)
        found = crashes(os.path.join(self.d, "llmfuzz-out"))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["kind"], "crash")
        self.assertIn("@ read_record", found[0]["signature"])
        self.assertTrue(os.path.exists(os.path.join(self.d, found[0]["artifact"] + ".report.txt")))

    def test_program_mode_with_file_argument(self) -> None:
        with open(os.path.join(self.d, "prog.c"), "w") as f:
            f.write(PROG)
        os.mkdir(os.path.join(self.d, "seeds"))
        with open(os.path.join(self.d, "seeds", "a"), "w") as f:
            f.write("HI12345")
        llmfuzz("cc", "-O1", "prog.c", "-o", "prog", cwd=self.d)
        llmfuzz("run", "./prog", "seeds", "--prior", "none", "-t", "120", "--stop-on-crash", "--", "@@", cwd=self.d)
        found = crashes(os.path.join(self.d, "llmfuzz-out"))
        self.assertEqual([c["kind"] for c in found], ["crash"])  # not a timeout, however slow symbolizing is
        self.assertEqual(found[0]["signature"], "stack-buffer-overflow-WRITE @ parse")

    def test_custom_mutator(self) -> None:
        with open(os.path.join(self.d, "cm.c"), "w") as f:
            f.write(CUSTOM)
        llmfuzz("cc", "-O1", "cm.c", "-o", "cm", cwd=self.d)
        llmfuzz("run", "./cm", "--prior", "none", "-t", "120", "--stop-on-crash", cwd=self.d)
        found = crashes(os.path.join(self.d, "llmfuzz-out"))
        self.assertEqual([c["signature"] for c in found], ["stack-buffer-overflow-WRITE @ boom < LLVMFuzzerTestOneInput"])

    def test_crashing_seed_is_skipped_after_restart(self) -> None:
        with open(os.path.join(self.d, "sc.c"), "w") as f:
            f.write(SEED_CRASH)
        os.mkdir(os.path.join(self.d, "seeds"))
        with open(os.path.join(self.d, "seeds", "s"), "w") as f:
            f.write("SEED!")
        llmfuzz("cc", "-O1", "sc.c", "-o", "sc", cwd=self.d)
        llmfuzz("run", "./sc", "seeds", "--prior", "none", "-t", "20", cwd=self.d)
        found = crashes(os.path.join(self.d, "llmfuzz-out"))
        self.assertEqual(sorted(c["signature"].split(" @ ")[1] for c in found),
                         ["overflow < deep_bug < LLVMFuzzerTestOneInput", "overflow < seed_bug < LLVMFuzzerTestOneInput"])
        with open(os.path.join(self.d, "llmfuzz-out", "crashes", ".llmfuzz-skip")) as f:
            self.assertEqual([os.path.basename(line.strip()) for line in f], ["s"])

    def test_scores_file_prior(self) -> None:
        llmfuzz("cc", "-O1", os.path.join(ROOT, "examples", "demo.c"), "-o", "demo", cwd=self.d)
        with open(os.path.join(self.d, "scores.json"), "w") as f:
            json.dump({"apply": 3.0, "no_such_function": 1.0}, f)
        log = llmfuzz("analyze", "./demo", "--scores", "scores.json", cwd=self.d)
        self.assertIn("1 name(s) in scores.json match no function", log)
        with open(os.path.join(self.d, "demo.weights.json")) as f:
            ranked = json.load(f)
        self.assertEqual(ranked[0]["name"], "apply")
        self.assertGreater(ranked[0]["weight"], ranked[-1]["weight"])


if __name__ == "__main__":
    unittest.main()

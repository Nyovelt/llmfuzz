"""Source parsing, crash signatures, weights and score files (no compiler or model needed)."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from llmfuzz import cli, pcmap
from llmfuzz.campaign import signature, symbolize_report
from llmfuzz.cli import _matches, load_scores

C_SRC = """#include <stdio.h>
static int add(int a, int b) { return a + b; }
/* int fake(void) { } */
const char *s = "int not_a_func(void) {";
struct point { int x, y; };
int main(int argc, char **argv) {
  if (argc > 1) {
    return add(1, 2);
  }
  return 0;
}
"""

CPP_SRC = """namespace ns {
class Parser {
 public:
  int parse(const char *s) const {
    return s[0];
  }
};
template <typename T> T twice(T x) { return x + x; }
}  // namespace ns
"""

REPORT = """=================================================================
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602 at pc 0x55 bp 0x7f sp 0x7e
READ of size 4 at 0x602 thread T0
    #0 0x4f5c3a in __asan_memcpy (/usr/lib/libclang_rt.asan.so+0x4f5c3a)
    #1 0x55d4c8 in read_record /src/kv.c:28:3
    #2 0x55d4c8 in parse_all(char const*, unsigned long) /src/kv.c:52:9
    #3 0x55e000 in main /src/main.c:10:5
    #4 0x7f0000  (/lib/x86_64-linux-gnu/libc.so.6+0x29d90) (BuildId: 0123abcd)

0x602 is located 0 bytes after 16-byte region [0x5f2,0x602)
allocated by thread T0 here:
    #0 0x4f6000 in malloc (/usr/lib/libclang_rt.asan.so+0x4f6000)
    #1 0x55c000 in new_record /src/kv.c:12:9
"""


class Parsing(unittest.TestCase):
    def test_c_functions_skip_comments_strings_and_structs(self) -> None:
        self.assertEqual(pcmap.c_functions(C_SRC), [("add", 2, 2, "add"), ("main", 6, 11, "main")])

    def test_cpp_qualified_names(self) -> None:  # a method's region includes a preceding access specifier
        self.assertEqual([(d[3], d[1], d[2]) for d in pcmap.c_functions(CPP_SRC)],
                         [("ns::Parser::parse", 3, 6), ("ns::twice", 8, 8)])

    def test_short_name(self) -> None:
        cases = {
            "char const* ns::parse<T>(char const*, int) const": "ns::parse<T>",
            "main": "main",
            "operator<(A const&, A const&)": "operator<",
            "ns::Parser::operator()(int) const": "ns::Parser::operator()",
            "std::vector<int, std::allocator<int> >::push_back(int const&)":
                "std::vector<int, std::allocator<int> >::push_back",
        }
        for full, short in cases.items():
            self.assertEqual(pcmap.short_name(full), short)


class Weights(unittest.TestCase):
    def test_assign_weights_is_monotone_and_clipped(self) -> None:
        funcs = [pcmap.Func("a.c", 1, 2, name=f"f{i}", score=float(i)) for i in range(10)]
        hot = pcmap.assign_weights(funcs, k=3.0, wmin=0.5, wmax=8.0, hot_frac=0.2)
        w = [f.weight for f in funcs]
        self.assertEqual(w, sorted(w))
        self.assertEqual((min(w), max(w)), (0.5, 8.0))
        self.assertGreater(hot, 1.0)
        self.assertEqual(sum(x >= hot for x in w), 3)  # the top 20%, plus ties at the threshold

    def test_group_functions_splits_long_functions(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "big.c")
            body = "".join(f"  x += {i};\n" for i in range(400))
            with open(src, "w") as f:
                f.write("int big(int x) {\n" + body + "  return x;\n}\nint small(void) { return 0; }\n")
            sym = [("big", src, 2), ("big", src, 300), ("small", src, 404), ("printf", "/usr/include/stdio.h", 1)]
            pcs = [(i + 1, 0x1000 + i, 0, 0) for i in range(len(sym))]
            funcs, pc_func = pcmap.group_functions(pcs, sym, max_lines=150)
        names = sorted(f.name for f in funcs)
        self.assertEqual(names, ["big#1", "big#2", "big#3", "small"])
        self.assertEqual(pc_func[3], -1)  # system header: unweighted
        self.assertEqual(funcs[pc_func[1]].name, "big#3")
        self.assertTrue(funcs[pc_func[1]].text.startswith("int big(int x) {\n    /* ... */\n"))


class Signatures(unittest.TestCase):
    def test_signature_uses_first_trace_and_skips_runtime_frames(self) -> None:
        self.assertEqual(signature("crash", REPORT), "heap-buffer-overflow-READ @ read_record < parse_all")

    def test_timeout_signature_uses_the_outermost_frames(self) -> None:
        def report(inner: str) -> str:
            return ("==llmfuzz== timeout: input ran for 2.1s\n"
                    f"    #0 0x10 in {inner} sqlite3.c:10\n    #1 0x20 in sqlite3VdbeExec sqlite3.c:20\n"
                    "    #2 0x30 in sqlite3_step sqlite3.c:30\n    #3 0x40 in sqlite3_exec sqlite3.c:40\n"
                    "    #4 0x50 in LLVMFuzzerTestOneInput ossfuzz.c:188\n    #5 0x60 in run_inprocess llmfuzz_rt.c:1\n")
        self.assertEqual(signature("timeout", report("sqlite3BtreeInsert")),
                         "timeout @ sqlite3_step < sqlite3_exec < LLVMFuzzerTestOneInput")
        self.assertEqual(signature("timeout", report("sqlite3BtreeInsert")), signature("timeout", report("fetchPayload")))

    def test_signature_without_sanitizer_report(self) -> None:
        self.assertEqual(signature("timeout", "==llmfuzz== timeout: input ran for 2.1s\n"), "timeout @ ")

    def test_unsymbolized_frames_still_end_the_first_trace(self) -> None:
        raw = REPORT.replace("    #0 0x4f6000 in malloc (/usr/lib/libclang_rt.asan.so+0x4f6000)",
                             "    #0 0x4f6000  (/usr/lib/libclang_rt.asan.so+0x4f6000)")
        self.assertEqual(signature("crash", raw), "heap-buffer-overflow-READ @ read_record < parse_all")

    def test_symbolize_report_leaves_unknown_modules_alone(self) -> None:
        raw = "    #0 0x10  (/nonexistent/binary+0x10)\n    #1 0x20  (/nonexistent/binary+0x20)"
        self.assertEqual(symbolize_report(raw), raw)


class ScoreFiles(unittest.TestCase):
    def _write(self, d: str, data: object) -> str:
        path = os.path.join(d, "scores.json")
        with open(path, "w") as f:
            json.dump(data, f)
        return path

    def test_formats(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(load_scores(self._write(d, {"parse": 2, "ns::Lexer::next#2": -1.5})),
                             {"parse": 2.0, "ns::Lexer::next": -1.5})
            self.assertEqual(load_scores(self._write(d, [{"name": "f<int>", "score": 0.5, "file": "a.c"}])),
                             {"f": 0.5})

    def test_rejects_bad_scores(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            for bad in ({"f": "high"}, {"f": True}, {"f": float("nan")}, [1, 2], "f"):
                with self.assertRaises(SystemExit):
                    load_scores(self._write(d, bad))
            with self.assertRaises(SystemExit):
                load_scores(os.path.join(d, "missing.json"))

    def test_name_matching(self) -> None:
        self.assertTrue(_matches("ns::parse<int>#2", "parse"))
        self.assertTrue(_matches("ns::parse", "ns::parse"))
        self.assertFalse(_matches("reparse", "parse"))
        self.assertFalse(_matches("ns::parse", "other::parse"))


class RunCommand(unittest.TestCase):
    def test_model_options_reach_analyze(self) -> None:
        class Stop(Exception):
            pass

        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "target")
            with open(binary, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(binary, 0o755)
            args = cli.build_parser().parse_args(["run", binary, "--prior", "llm", "--model", "M", "--lens", "L",
                                                  "--device", "cpu", "--dtype", "fp16"])
            with mock.patch.object(cli, "cmd_analyze", side_effect=Stop) as analyze, self.assertRaises(Stop):
                cli.cmd_run(args)
            a = analyze.call_args.args[0]
            self.assertEqual((a.model, a.lens, a.device, a.dtype, a.control), ("M", "L", "cpu", "fp16", "none"))


if __name__ == "__main__":
    unittest.main()

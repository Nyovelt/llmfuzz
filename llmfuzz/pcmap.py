"""Map instrumented PCs to source functions and write per-PC LLM weights."""
from __future__ import annotations

import bisect
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

Frame = tuple[str, str, int]  # function, source file ('' if unknown), line
PC = tuple[int, int, int, int]  # guard index, unslid pc, is function entry, module
Def = tuple[str, int, int, str]  # name, first line, last line, qualified name


@dataclass
class Func:
    file: str
    start: int
    end: int
    name: str = "?"
    text: str = ""
    pcs: list[int] = field(default_factory=list)  # indices into the pc list
    score: float = 0.0
    weight: float = 1.0
    size: int = 0  # lines of the whole enclosing function (for the size prior)
    skip: int = 0  # synthetic lines prepended to text (signature context of a later region)


def is_harness(binary: str) -> bool:
    out = subprocess.run(["nm", binary], capture_output=True, text=True).stdout
    return re.search(r" T _?LLVMFuzzerTestOneInput$", out, re.M) is not None


def dump_pcs(binary: str) -> tuple[list[PC], dict[int, str]]:
    """Run the target once to dump its PC table, and the path of each instrumented module."""
    with tempfile.TemporaryDirectory() as td:
        out, env = os.path.join(td, "pcs.txt"), dict(os.environ)
        cmd = [binary]
        if is_harness(binary):
            cmd.append(f"-dump_pcs={out}")
        else:
            env["LLMFUZZ_DUMP_PCS"] = out
        subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=300)
        if not os.path.exists(out):
            sys.exit(f"llmfuzz: {binary} did not dump its PC table; was it built with llmfuzz-cc?")
        pcs: list[PC] = []
        mods: dict[int, str] = {}
        with open(out) as fh:
            for line in fh:
                if line.startswith("# module"):
                    f = line.split(maxsplit=5)
                    mods[int(f[2])] = f[5].strip()
                elif not line.startswith("#"):
                    g, pc, flag, mod = line.split()
                    pcs.append((int(g), int(pc, 16), int(flag), int(mod)))
    return pcs, mods


def _pick(frames: list[Frame]) -> Frame:
    """Innermost inlined frame that is project code (not a system/STL header)."""
    frames = [f for f in frames if f[1]] or frames or [("??", "", 0)]
    return next((f for f in frames if not SYSTEM.search(f[1])), frames[0])


def _atos(obj: str, addrs: list[int], arch: str | None = None) -> list[list[Frame]] | None:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hex(a) for a in addrs) + "\n")
    try:
        out = subprocess.run(["atos", "-fullPath", "-i", "-o", obj, "-f", f.name] + (["-arch", arch] if arch else []),
                             capture_output=True, text=True).stdout
    finally:
        os.unlink(f.name)
    groups: list[list[Frame]] = []
    cur: list[Frame] = []
    for line in out.split("\n"):  # one blank-line-terminated group of frames per address
        if line.strip():
            m = re.match(r"^(.*?) \(in .*?\) (?:\((.*):(\d+)\)|\+ \d+)$", line)  # no debug info: 'f (in lib) + 12'
            cur.append((m.group(1), m.group(2) or "", int(m.group(3) or 0)) if m else ("??", "", 0))
        elif cur:
            groups.append(cur)
            cur = []
    return groups if len(groups) == len(addrs) else None


def symbolize_chains(obj: str, addrs: list[int], arch: str | None = None) -> list[list[Frame]]:
    """For each unslid address in `obj`: its frames, innermost inlined function first ([] if unknown)."""
    tool = shutil.which("llvm-symbolizer") or next(
        (t for v in range(30, 10, -1) if (t := shutil.which(f"llvm-symbolizer-{v}"))), None)
    if tool:
        out = subprocess.run([tool, "--obj", obj, "--inlining", "--output-style=JSON"]
                             + ([f"--default-arch={arch}"] if arch else []),
                             input="\n".join(hex(a) for a in addrs), capture_output=True, text=True).stdout
        return [[(s.get("FunctionName") or "??", s.get("FileName", ""), int(s.get("Line", 0)))
                 for s in json.loads(line).get("Symbol") or []] for line in out.splitlines()]
    if sys.platform == "darwin":
        chains = _atos(obj, addrs, arch)
        if not SYSTEM.search(obj) and (chains is None or sum(any(f[1] for f in c) for c in chains) < 0.3 * len(chains)):
            subprocess.run(["dsymutil", obj], capture_output=True)  # debug map -> .dSYM
            dsym = f"{obj}.dSYM/Contents/Resources/DWARF/{os.path.basename(obj)}"
            chains = _atos(dsym, addrs, arch) if os.path.exists(dsym) else chains
        return chains or [[] for _ in addrs]
    lines = subprocess.run(["addr2line", "-a", "-f", "-i", "-C", "-e", obj] + [hex(a) for a in addrs],
                           capture_output=True, text=True).stdout.splitlines()
    res: list[list[Frame]] = []
    i = 0
    while i < len(lines):  # 0xADDR, then (function, file:line) pairs, innermost first
        i, frames = i + 1, []
        while i + 1 < len(lines) and not lines[i].startswith("0x"):
            file, _, ln = lines[i + 1].rpartition(":")
            frames.append((lines[i], file if file != "??" else "", int(re.sub(r"\D.*", "", ln) or 0)))
            i += 2
        res.append(frames)
    return res


def symbolize(obj: str, addrs: list[int]) -> list[Frame]:
    """(function, file, line) for each unslid address (see _pick)."""
    return [_pick(c) for c in symbolize_chains(obj, addrs)]


_STRIP = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|^[ \t]*#(?:[^\n]*\\\n)*[^\n]*',
                    re.S | re.M)
_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "catch", "do", "else", "defined", "case"}


def _blank(m: re.Match[str]) -> str:  # keep newlines and quotes so positions and line numbers survive
    t = m.group(0)
    if t[0] in "\"'":
        return t[0] + re.sub(r"[^\n]", " ", t[1:-1]) + t[-1]
    return re.sub(r"[^\n]", " ", t)


def _def_name(header: str) -> str | None:
    """Name of the function whose body would follow this header, or None."""
    h = header.strip()
    if "(" not in h or "=" in h.replace("==", "").split("(")[0]:
        return None
    while True:  # drop trailing qualifiers / attributes / trailing return type
        h2 = re.sub(r"(\b(const|volatile|noexcept|override|final|throw|try)\b|&&?|->\s*[\w:<>,\s\*&]+|"
                    r"__attribute__\s*\(\(.*\)\)|noexcept\s*\(.*\))\s*$", "", h).rstrip()
        if h2 == h:
            break
        h = h2
    m = re.search(r"\)\s*:\s*[\w:]+\s*[({]", h)  # constructor initializer list
    if m:
        h = h[: m.start() + 1]
    if not h.endswith(")"):
        return None
    depth, i = 0, len(h) - 1
    while i >= 0:
        depth += {")": 1, "(": -1}.get(h[i], 0)
        if depth == 0:
            break
        i -= 1
    m = re.search(r"([~\w:]+|operator\s*\S+)\s*$", h[:i])
    if not m or m.group(1).split("::")[-1] in _KEYWORDS:
        return None
    return m.group(1)


def _scope_name(kind: str, rest: str) -> str:
    """Name of a namespace / class block from the text after the keyword ('' if unnamed)."""
    while "<" in rest and rest != (r := re.sub(r"<[^<>]*>", "", rest)):  # template arguments
        rest = r
    names = re.findall(r"[A-Za-z_]\w*", re.split(r"[:{]", rest.replace("::", "."), 1)[0])
    return names[-1] if names else "(anonymous namespace)" if kind == "namespace" else ""


def c_functions(text: str) -> list[Def]:
    """Function definitions in C/C++ source: [(name, start_line, end_line, qualified_name)]."""
    s = _STRIP.sub(_blank, text)
    nl = [i for i, c in enumerate(s) if c == "\n"]

    def line(pos: int) -> int:
        return bisect.bisect_left(nl, pos) + 1

    out: list[Def] = []
    stack: list[tuple[str, str | None, int]] = []  # open braces: kind (c: scope, f: function, o: other), name, start
    seg = 0
    for m in re.finditer(r"[{};]", s):
        i, c = m.start(), m.group(0)
        if c == "{":
            kind, header = "o", s[seg:i]
            name: str | None = None
            if not stack or stack[-1][0] == "c":
                if sm := re.search(r'\b(namespace|class|struct|union)\b([^(=]*)$|\bextern\s*""\s*$', header):
                    kind, name = "c", _scope_name(sm.group(1), sm.group(2)) if sm.group(1) else ""
                elif (name := _def_name(header)) is not None:
                    kind = "f"
            start = seg + len(header) - len(header.lstrip())
            stack.append((kind, name, start))
        elif c == "}":
            if stack:
                kind, fname, start = stack.pop()
                if kind == "f" and fname is not None:
                    scope = "::".join(n for k, n, _ in stack if k == "c" and n)
                    out.append((fname, line(start), line(i), f"{scope}::{fname}" if scope else fname))
        seg = i + 1
    return out


def call_graph(files: Iterable[str], cdb: str | None = None,
               max_defs: int = 4) -> tuple[list[tuple[str, str, int, int, str]], list[list[int]]]:
    """Static call graph over every function definition in `files`: [(file, qualified name, start, end, text)]
    and, per definition, the definitions it refers to. Without `cdb`, a rough version: any reference to a
    function name (names defined more than `max_defs` times are skipped). With a compile database
    (LLMFUZZ_CDB), a function's direct calls come from clang's AST when its calls can be matched there
    (not for templates or macro-generated names), plus names used without a call (function pointers)."""
    defs: list[tuple[str, str, int, int, str]] = []
    bodies: list[str] = []
    for path in dict.fromkeys(os.path.realpath(f) for f in files):
        try:
            with open(path, errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        lines, stripped = text.splitlines(keepends=True), _STRIP.sub(_blank, text).splitlines(keepends=True)
        for _, a, b, q in c_functions(text):
            body = "".join(stripped[a - 1: b])
            defs.append((path, q, a, b, "".join(lines[a - 1: b])))
            bodies.append(body[body.find("{"):])  # skip the header: own name, parameter types
    by_name: dict[str, list[int]] = defaultdict(list)
    by_q: dict[str, list[int]] = defaultdict(list)
    for i, d in enumerate(defs):
        by_name[d[1].split("::")[-1]].append(i)
        by_q[d[1]].append(i)
    calls: list[list[int]] = [[] for _ in defs]
    refs: list[list[int]] = [[] for _ in defs]
    for i, body in enumerate(bodies):
        for m in re.finditer(r"\b[A-Za-z_]\w*\b(\s*\()?", body):
            js = by_name.get(m.group(0).rstrip("( \t\n"), [])
            if len(js) <= max_defs:
                (calls if m.group(1) else refs)[i] += [j for j in js if j != i]
    if cdb:
        def pick(q: str, tu: str) -> list[int]:  # prefer the definition in the translation unit itself
            js = by_q.get(q, [])
            same = [j for j in js if defs[j][0] == tu]
            return same or (js if len(js) <= max_defs else [])
        ast: dict[int, list[int]] = defaultdict(list)
        for tu, caller, callee in clang_call_graph(cdb):
            for i in pick(caller, tu):
                ast[i] += [j for j in pick(callee, tu) if j != i]
        calls = [ast[i] or calls[i] for i in range(len(defs))]
    return defs, [list(dict.fromkeys(c + r)) for c, r in zip(calls, refs)]


def clang_call_graph(cdb: str, jobs: int = 8) -> list[tuple[str, str, str]]:
    """Direct calls from clang's AST (macros expanded, methods resolved): runs the debug.DumpCallGraph
    checker on every compile command recorded in `cdb` (see LLMFUZZ_CDB in build.py).
    Returns (translation unit, caller, callee) with qualified names, no template arguments."""
    from concurrent.futures import ThreadPoolExecutor

    jobs_: list[tuple[str, str, list[str], str]] = []  # cwd, compiler, arguments, translation unit
    with open(cdb) as fh:
        cmds = [json.loads(line) for line in fh]
    for c in cmds:
        for src in c["files"]:
            if not os.path.isfile(os.path.join(c["directory"], src)):  # e.g. configure's conftest.c
                continue
            args, skip = [], False
            for a in c["arguments"][1:]:
                if skip or a in ("-o", "-MF", "-MT", "-MQ"):
                    skip = not skip
                    continue
                if a not in ("-c", "-MD", "-MMD", "-MP") and not a.startswith("-fsanitize") and (a not in c["files"] or a == src):
                    args.append(a)
            jobs_.append((c["directory"], c["arguments"][0], args, os.path.realpath(os.path.join(c["directory"], src))))

    def run(j: tuple[str, str, list[str], str]) -> list[tuple[str, str, str]]:
        cwd, cc, args, tu = j
        r = subprocess.run([cc, "--analyze", "--analyzer-no-default-checks", "-Xclang", "-analyzer-checker=debug.DumpCallGraph",
                            "-o", os.devnull] + args, cwd=cwd, capture_output=True, text=True)
        out: list[tuple[str, str, str]] = []
        for ln in r.stderr.replace("(anonymous namespace)", "(anonymous-namespace)").splitlines():
            m = re.match(r"\s*Function: (\S+) calls:(.*)", ln)
            if m and m.group(1) != "<":
                out += [(tu, m.group(1), c) for c in m.group(2).split()]
        return [(t, a.replace("-namespace)", " namespace)"), b.replace("-namespace)", " namespace)")) for t, a, b in out]

    with ThreadPoolExecutor(jobs) as ex:  # one run per translation unit
        return sorted({e for es in ex.map(run, {j[3]: j for j in jobs_}.values()) for e in es})


SYSTEM = re.compile(r"^/usr/(include|lib)/|/Developer/|/Xcode[^/]*\.app/|/c\+\+/v1/|/include/c\+\+/|/lib/clang/")


def short_name(fn: str) -> str:
    """'char const* ns::parse<T>(char const*, int) const' -> 'ns::parse<T>'."""
    s, depth = re.sub(r"(\s*\b(const|volatile|noexcept)\b|\s*&{1,2})+$", "", fn.strip()), 0
    cut: int | None = None
    for i in range(len(s) - 1, -1, -1):  # strip the parameter list
        depth += {")": 1, "(": -1}.get(s[i], 0)
        if s.endswith(")") and depth == 0:
            cut = i
            break
    s, depth = s[:cut], 0
    t = re.sub(r"operator\s*[^\w\s]+", lambda m: "o" * len(m.group()), s)  # operator<, operator() ...
    for i in range(len(t) - 1, -1, -1):  # strip the return type
        depth += {">": 1, "<": -1, ")": 1, "(": -1}.get(t[i], 0)
        if t[i] == " " and depth == 0 and not t[:i].endswith("operator"):
            return s[i + 1:]
    return s


def group_functions(pcs: Sequence[PC], sym: Sequence[Frame], max_lines: int = 150) -> tuple[list[Func], list[int]]:
    """Assign each PC to the source function containing its (file, line).
    Functions longer than ~max_lines are split into regions scored separately
    (each prefixed with the function's first line). Code inlined from system /
    toolchain headers is left unweighted."""
    by_file: dict[str, list[int]] = defaultdict(list)
    for i, (_, file, ln) in enumerate(sym):
        if file and ln and not SYSTEM.search(file):
            by_file[file].append(i)
    funcs: list[Func] = []
    pc_func = [-1] * len(pcs)
    for file, idxs in by_file.items():
        try:
            with open(file, errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        lines = text.splitlines(keepends=True)
        defs = sorted(c_functions(text), key=lambda d: d[1])
        starts = [d[1] for d in defs]
        local: dict[tuple[str, int | str], int] = {}  # ("def", index in defs) or ("sym", symbol) -> funcs index
        for i in idxs:
            ln = sym[i][2]
            k = bisect.bisect_right(starts, ln) - 1
            key: tuple[str, int | str]
            if k >= 0 and defs[k][1] <= ln <= defs[k][2]:
                key = ("def", k)
            else:  # not inside a parsed definition: group by symbol name
                key = ("sym", sym[i][0])
            if key not in local:
                if key[0] == "def":
                    f = Func(file, defs[k][1], defs[k][2])
                else:
                    ls = [sym[j][2] for j in idxs if sym[j][0] == key[1]]
                    f = Func(file, max(1, min(ls) - 1), max(ls))
                f.text = "".join(lines[f.start - 1: f.end])
                local[key] = len(funcs)
                funcs.append(f)
            funcs[local[key]].pcs.append(i)
            pc_func[i] = local[key]
    out: list[Func] = []
    for f in funcs:
        f.name = short_name(Counter(sym[i][0] for i in f.pcs).most_common(1)[0][0])
        n = f.size = f.end - f.start + 1
        k = math.ceil(n / max_lines) if n > 1.3 * max_lines else 1
        lines, step = f.text.splitlines(keepends=True), math.ceil(n / k)
        for c in range(k):
            a, b = f.start + c * step, min(f.end, f.start + (c + 1) * step - 1)
            g = Func(f.file, a, b, f"{f.name}#{c + 1}" if k > 1 else f.name, size=n, skip=2 if c else 0,
                     pcs=[i for i in f.pcs if a <= sym[i][2] <= b] if k > 1 else f.pcs)
            body = "".join(lines[a - f.start: b - f.start + 1])
            g.text = body if c == 0 else lines[0] + "    /* ... */\n" + body
            for i in g.pcs:
                pc_func[i] = len(out)
            out.append(g)
    return out, pc_func


def assign_weights(funcs: list[Func], k: float = 1.0, wmin: float = 0.5, wmax: float = 8.0,
                   hot_frac: float = 0.1) -> float:
    """weight = exp(k * z(score)) clipped to [wmin, wmax]; returns the hot threshold."""
    s = [f.score for f in funcs]
    mu = sum(s) / len(s)
    sd = math.sqrt(sum((x - mu) ** 2 for x in s) / len(s)) or 1.0
    for f in funcs:
        f.weight = min(wmax, max(wmin, math.exp(k * (f.score - mu) / sd)))
    ws = sorted((f.weight for f in funcs), reverse=True)
    return max(1.001, ws[min(len(ws) - 1, int(hot_frac * len(ws)))])  # weight-1 (unscored) code is never hot


def line_weights(funcs: Sequence[Func], sym: Sequence[Frame], line_scores: Sequence[Sequence[float | None] | None],
                 beta: float, wmin: float, wmax: float) -> dict[int, float]:
    """Per-PC weight = region weight * exp(beta * z), z = the PC's line score z-scored within its region."""
    out: dict[int, float] = {}
    for f, ls in zip(funcs, line_scores):
        if not ls:
            continue
        vals = [x for x in ls[f.skip:] if x is not None]
        if len(vals) < 2:
            continue
        mu = sum(vals) / len(vals)
        sd = math.sqrt(sum((x - mu) ** 2 for x in vals) / len(vals)) or 1.0
        for i in f.pcs:
            t = sym[i][2] - f.start + f.skip
            x = ls[t] if 0 <= t < len(ls) else None
            z = 0.0 if x is None else max(-2.0, min(2.0, (x - mu) / sd))
            out[i] = min(wmax, max(wmin, f.weight * math.exp(beta * z)))
    return out


def write_weights(path: str, pcs: Sequence[PC], pc_func: Sequence[int], funcs: Sequence[Func], hot: float,
                  header: str = "", pc_w: dict[int, float] | None = None) -> None:
    tmp = f"{path}.tmp-{os.getpid()}"  # written whole, then renamed: a concurrent reader never sees half a file
    with open(tmp, "w") as f:
        f.write(f"# llmfuzz-weights v1 {header}\n#hot {hot:.4f}\n")
        for i, (_, pc, _, _) in enumerate(pcs):
            if pc_func[i] >= 0:
                f.write(f"{pc:#x} {(pc_w or {}).get(i, funcs[pc_func[i]].weight):.4f}\n")
    os.replace(tmp, path)

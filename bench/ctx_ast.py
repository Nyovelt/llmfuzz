"""Add structure-selected contexts to the call-context dataset (not part of the llmfuzz core; needs libclang).

For every sampled region of bench/ctx_dataset.py's output, parses the region's translation unit with libclang (compile
commands from LLMFUZZ_CDB) and stores three context lists next to the region:
  ctx_defs       definitions the region refers to: macros, struct/union/enum/typedef/class definitions, the records
                 of accessed fields, global variables (project files only, first use first)
  ctx_calleesig  signatures (plus the comment above them) of the project functions the region calls
  ctx_args       for each caller: a backward slice by variable name of the statements before the call site that
                 compute or test the actual arguments (an approximation of data/control dependence)
  python bench/ctx_ast.py ctx_data.json out.json --cdb-dir cdb/ [--libclang /path/libclang.dylib]
"""
import argparse
import json
import os
import re
import subprocess
import sys

import clang.cindex as ci

K = ci.CursorKind
FUNCS = {K.FUNCTION_DECL, K.CXX_METHOD, K.CONSTRUCTOR, K.DESTRUCTOR, K.FUNCTION_TEMPLATE, K.CONVERSION_FUNCTION}
SCOPES = {K.NAMESPACE, K.LINKAGE_SPEC, K.CLASS_DECL, K.STRUCT_DECL, K.CLASS_TEMPLATE, K.UNEXPOSED_DECL}
RECORDS = {K.STRUCT_DECL, K.UNION_DECL, K.CLASS_DECL, K.CLASS_TEMPLATE, K.ENUM_DECL}
KEYWORDS = set("""if else for while do switch case return sizeof break continue goto default struct union enum const
volatile static unsigned signed int char short long float double void bool true false NULL nullptr new delete this
typedef auto register extern inline""".split())
MAX_LINES = 40


class Source:
    def __init__(self):
        self.cache = {}

    def lines(self, path):
        if path not in self.cache:
            self.cache[path] = open(path, errors="replace").read().splitlines()
        return self.cache[path]

    def snippet(self, path, a, b, max_lines=MAX_LINES):
        ls = self.lines(path)[a - 1: b]
        if len(ls) > max_lines:
            ls = ls[: max_lines - 1] + ["    /* ... */"]
        return f"// {os.path.basename(path)}:{a}\n" + "\n".join(ls) + "\n"


def compile_args(entry, sdk):
    """Compile command minus the compiler, outputs, dependency files, sanitizers, warnings and the source itself."""
    out, skip = [], False
    for x in entry["arguments"][1:]:
        if skip:
            skip = False
        elif x in ("-o", "-MF", "-MT", "-MQ"):
            skip = True
        elif x == "-c" or x.startswith(("-fsanitize", "-M", "-W", "-g")) or x in entry["files"]:
            pass
        else:
            out.append(x)
    return out + ["-isysroot", sdk, "-fparse-all-comments", "-Wno-everything"]


def function_cursors(cursor, path):
    for c in cursor.get_children():
        if c.kind in SCOPES:
            yield from function_cursors(c, path)
        elif c.kind in FUNCS and c.location.file and os.path.realpath(c.location.file.name) == path and c.is_definition():
            yield c


def in_project(cursor, root):
    f = cursor.location.file
    return f is not None and os.path.realpath(f.name).startswith(root)


def region_contexts(tu, fn, r, root, src):
    """(defs, callee signatures) for the lines of region r inside function cursor fn."""
    first, last = r["line"], r["line"] + r["lines"] - 1
    body = next((c for c in fn.get_children() if c.kind == K.COMPOUND_STMT), None)
    sig_end = body.extent.start.line if body is not None else fn.extent.start.line  # the signature counts too
    keep = lambda ln: first <= ln <= last or fn.extent.start.line <= ln <= sig_end  # noqa: E731
    refs = []  # (line, col, cursor of the referenced declaration, kind of use)
    for c in tu.cursor.get_children():  # macro uses live at the top of the preprocessing record
        if c.kind == K.MACRO_INSTANTIATION and c.location.file and \
                os.path.realpath(c.location.file.name) == r["path"] and keep(c.location.line) and c.referenced:
            refs.append((c.location.line, c.location.column, c.referenced, "macro"))
    for c in fn.walk_preorder():
        if c.location.file is None or not keep(c.location.line) or c.kind not in (
                K.TYPE_REF, K.MEMBER_REF_EXPR, K.DECL_REF_EXPR, K.TEMPLATE_REF, K.CALL_EXPR):
            continue
        d = c.referenced
        if d is not None:
            refs.append((c.location.line, c.location.column, d, c.kind.name))
    refs.sort(key=lambda x: x[:2])
    defs, sigs, seen = [], [], set()

    def add(d, out, how):
        d = d.get_definition() or d
        if not in_project(d, root) or d == fn:
            return
        path, a, b = os.path.realpath(d.location.file.name), d.extent.start.line, d.extent.end.line
        if (path, a) in seen:
            return
        seen.add((path, a))
        if how == "sig":
            ls = src.lines(path)[a - 1: b]
            head = []
            for ln in ls[:6]:
                head.append(ln)
                if "{" in ln or ";" in ln:
                    break
            text = "\n".join(head).split("{")[0].rstrip() + ";"
            comment = "\n".join((d.raw_comment or "").splitlines()[:4])
            out.append(f"// {os.path.basename(path)}:{a}\n" + (comment + "\n" if comment else "") + text + "\n")
        else:
            out.append(src.snippet(path, a, b, MAX_LINES if how == "record" else 8))

    for _, _, d, use in refs:
        k = d.kind
        if k == K.MACRO_DEFINITION:
            add(d, defs, "macro")
        elif k in FUNCS:
            add(d, sigs, "sig")
        elif k in RECORDS or k == K.TYPEDEF_DECL or k == K.TYPE_ALIAS_DECL:
            add(d, defs, "record")
            if k == K.TYPEDEF_DECL:  # typedef struct X Y: show struct X too
                u = d.underlying_typedef_type.get_canonical().get_declaration()
                if u is not None and u.kind in RECORDS:
                    add(u, defs, "record")
        elif k == K.FIELD_DECL and d.semantic_parent is not None:
            add(d.semantic_parent, defs, "record")
        elif k == K.ENUM_CONSTANT_DECL and d.semantic_parent is not None:
            add(d.semantic_parent, defs, "record")
        elif k == K.VAR_DECL and d.semantic_parent is not None and d.semantic_parent.kind in (
                K.TRANSLATION_UNIT, K.NAMESPACE, K.CLASS_DECL, K.STRUCT_DECL):
            add(d, defs, "var")
    return defs, sigs


def arg_slices(t, d, max_callers=6, max_lines=20):
    """For each caller of def d: signature, the statements before the first call that mention the argument variables
    (two rounds: variables on the right of those statements are followed too), and the call itself."""
    D, name = t["defs"], t["defs"][d]["q"].split("::")[-1]
    call = re.compile(rf"\b{re.escape(name)}\s*\(")
    out = []
    for j in t["callers"][d][:max_callers]:
        lines = D[j]["text"].splitlines()
        hit = next((i for i, ln in enumerate(lines) if i and call.search(ln)), None)
        if hit is None:
            continue
        rest = "\n".join(lines[hit:])[call.search(lines[hit]).end() - 1:]
        depth, k = 0, 0
        for k, ch in enumerate(rest):
            depth += {"(": 1, ")": -1}.get(ch, 0)
            if depth == 0:
                break
        args = rest[1:k]
        ident = lambda s: {w for w in re.findall(r"[A-Za-z_]\w*", s) if w not in KEYWORDS}  # noqa: E731
        calls = lambda s: set(re.findall(r"([A-Za-z_]\w*)\s*\(", s))  # noqa: E731
        want = ident(args) - calls(args)
        keep = set()
        for _ in range(2):
            for i in range(1, hit):
                if want & ident(lines[i]):
                    keep.add(i)
                    lhs, eq, rhs = lines[i].partition("=")
                    if eq and not rhs.startswith("="):
                        want |= ident(rhs) - calls(rhs)
        keep = sorted(keep)[-max_lines:]
        body, prev = [lines[0]], 0
        for i in keep + [hit]:
            if i > prev + 1:
                body.append("    /* ... */")
            body.append(lines[i])
            prev = i
        body.append("    /* ... */\n}")
        out.append(f"// {D[j]['file']}:{D[j]['start']}\n" + "\n".join(body) + "\n")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data")
    ap.add_argument("out")
    ap.add_argument("--cdb-dir", required=True, help="directory with <target>.jsonl compile databases")
    ap.add_argument("--libclang", default="/Library/Developer/CommandLineTools/usr/lib/libclang.dylib")
    a = ap.parse_args()
    ci.Config.set_library_file(a.libclang)
    sdk = subprocess.run(["xcrun", "--show-sdk-path"], capture_output=True, text=True).stdout.strip()
    data = json.load(open(a.data))
    index, src = ci.Index.create(), Source()
    for tn, t in data.items():
        cdb = {}
        for line in open(os.path.join(a.cdb_dir, tn + ".jsonl")):
            e = json.loads(line)
            for f in e["files"]:
                p = os.path.realpath(os.path.join(e["directory"], f))
                if os.path.exists(p):
                    cdb[p] = e
        root = os.path.commonpath([r["path"] for r in t["regions"]] + [os.path.realpath(e["directory"]) for e in cdb.values()])
        root = os.path.dirname(root) if os.path.isfile(root) else root
        tus, stats = {}, {"regions": 0, "parsed": 0, "defs": 0, "sigs": 0, "args": 0}

        def parse(path):  # (translation unit, its directory): relative include paths resolve against the latter
            if path not in tus:
                e = cdb.get(path)
                tus[path] = (None, None)
                if e is not None:
                    os.chdir(e["directory"])
                    tus[path] = (index.parse(path, args=compile_args(e, sdk),
                                             options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD), e["directory"])
            return tus[path]

        by_base = {}
        for p in cdb:
            by_base.setdefault(os.path.basename(p), []).append(p)
        for r in t["regions"]:
            stats["regions"] += 1
            r["ctx_defs"], r["ctx_calleesig"], r["ctx_args"] = [], [], []
            if r["def"] is None:
                continue
            r["ctx_args"] = arg_slices(t, r["def"])
            stats["args"] += bool(r["ctx_args"])
            # the region's own file, or (for header code) the files of its callers
            cands = [r["path"]] + [p for j in t["callers"][r["def"]] for p in by_base.get(t["defs"][j]["file"], [])]
            for path in cands:
                tu, cwd = parse(path)
                if tu is None:
                    continue
                os.chdir(cwd)
                fn = next((c for c in function_cursors(tu.cursor, r["path"])
                           if c.extent.start.line <= r["line"] <= c.extent.end.line), None)
                if fn is None and path != r["path"]:  # header code: search the whole TU
                    fn = next((c for c in tu.cursor.walk_preorder() if c.kind in FUNCS and c.is_definition()
                               and c.location.file and os.path.realpath(c.location.file.name) == r["path"]
                               and c.extent.start.line <= r["line"] <= c.extent.end.line), None)
                if fn is not None:
                    r["ctx_defs"], r["ctx_calleesig"] = region_contexts(tu, fn, r, root, src)
                    stats["parsed"] += 1
                    stats["defs"] += bool(r["ctx_defs"])
                    stats["sigs"] += bool(r["ctx_calleesig"])
                    break
        print(tn, stats, f"{len(tus)} TUs", file=sys.stderr, flush=True)
    json.dump(data, open(a.out, "w"))


if __name__ == "__main__":
    main()

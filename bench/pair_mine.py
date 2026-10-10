"""Mine recent single-function security fixes from a git repo: before/after text of the one changed function
(not part of the llmfuzz core). Used for the buggy-vs-fixed pairs of README §3.12; clone with e.g.
  git clone --bare --filter=blob:none --shallow-since=2026-04-01 URL repo.git
  python bench/pair_mine.py repo.git name 2026-05-01 out.jsonl"""
import json, re, subprocess, sys
from llmfuzz.pcmap import c_functions

repo, name, since, out = sys.argv[1:5]
GREP = (r"overflow|out[- ]of[- ]bounds|\boob\b|use[- ]after[- ]free|\buaf\b|heap[- ]buffer|stack[- ]buffer|oss-?fuzz|"
        r"ossfuzz|cve-20|null[- ](pointer[- ])?deref|underflow|double[- ]free|invalid (read|write)|buffer over|"
        r"\basan\b|bounds check|out of range|integer wrap|uninitiali[sz]ed")
SRC = re.compile(r"\.(c|cc|cpp|cxx)$")
SKIP = re.compile(r"(^|/)(tests?|testing|fuzz|fuzzing|unittests?|examples?|doc|docs)(/|$)|_test\.|test_", re.I)
git = lambda *a: subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True, errors="replace")  # noqa: E731


def ranges(diff):
    old, new = [], []
    for m in re.finditer(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", diff, re.M):
        a, b, c, d = int(m[1]), int(m[2] or 1), int(m[3]), int(m[4] or 1)
        old.append((a, a + max(b, 1) - 1))
        new.append((c, c + max(d, 1) - 1))
    return old, new


log = git("log", f"--since={since}", "--no-merges", "-i", "-E", f"--grep={GREP}", "--format=%H%x09%cs%x09%s")
n = 0
with open(out, "a") as fo:
    for line in log.stdout.splitlines():
        h, date, subj = line.split("\t", 2)
        stat = git("diff-tree", "--no-commit-id", "-r", "--numstat", h).stdout.split("\n")
        files = [s.split("\t") for s in stat if s.count("\t") == 2]
        code = [f for f in files if SRC.search(f[2]) and not SKIP.search(f[2])]
        if len(code) != 1 or code[0][0] == "-":
            continue
        add, dele, path = int(code[0][0]), int(code[0][1]), code[0][2]
        if add + dele > 40:
            continue
        old, new = git("show", f"{h}^:{path}"), git("show", f"{h}:{path}")
        if old.returncode or new.returncode:
            continue
        ro, rn = ranges(git("diff", "-U0", f"{h}^", h, "--", path).stdout)
        if not ro:
            continue
        fs_o, fs_n = c_functions(old.stdout), c_functions(new.stdout)
        def one(fs, rs):
            hit = set()
            for a, b in rs:
                c = [f for f in fs if f[1] <= max(a, 1) and min(b, a) <= f[2] and f[1] <= b and a <= f[2]]
                inside = [f for f in c if f[1] <= a and b <= f[2]]
                if len(inside) != 1:
                    return None
                hit.add(inside[0])
            return hit.pop() if len(hit) == 1 else None
        fo_, fn_ = one(fs_o, [r for r in ro if r[1] >= r[0]]), one(fs_n, rn)
        if not fo_ or not fn_ or fo_[3] != fn_[3]:
            continue
        lo, ln = old.stdout.splitlines(), new.stdout.splitlines()
        before, after = "\n".join(lo[fo_[1] - 1:fo_[2]]), "\n".join(ln[fn_[1] - 1:fn_[2]])
        if before == after or len(before) > 6000 or len(after) > 6000 or before.count("\n") < 4:
            continue
        fo.write(json.dumps({"project": name, "commit": h, "date": date, "subject": subj, "file": path.split("/")[-1],
                             "path": path, "func": fo_[3], "before": before, "after": after,
                             "changed": add + dele}) + "\n")
        n += 1
print(name, "candidates:", n, "of", len(log.stdout.splitlines()), "matching commits", flush=True)

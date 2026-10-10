"""Fuzzing campaigns: N workers sharing one corpus, restart on crash, triage."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TypedDict

from .pcmap import SYSTEM, Frame, is_harness, short_name, symbolize_chains

CRASH_LINE = re.compile(r"==llmfuzz== (crash|timeout|oom) after ([\d.]+)s, (\d+) execs; artifact: (\S+)(?: \(report (\S+)\))?")
FRAME = re.compile(r"^\s*#(\d+) 0x[0-9a-f]+(?: in (.+)|\s+\(.*\))$", re.M)  # symbolized or not
RAW_FRAME = re.compile(r"^(\s*)#(\d+) (0x[0-9a-f]+)\s+\((/[^()]+?)(?::(arm64e?|x86_64h?|i386))?\+(0x[0-9a-f]+)\)"
                       r"(?: \(BuildId: [0-9a-f]+\))?$")
NOISE = re.compile(r"^(__asan|__interceptor|__sanitizer|_?_?wrap_|LLVMFuzzer(RunDriver|Initialize)|llmfuzz|__assert|__GI_|_?sigtramp|"
                   r"(run_inprocess|run_fork_harness|engine_(init|next|feedback|fini)|on_alarm|on_signal|on_death|on_malloc|die_inprocess|"
                   r"main|start|_start|abort|raise|pthread_kill|__pthread\w*|mem(cpy|move|set|cmp)|"
                   r"str(n?(len|cmp|cpy|cat|dup)|casecmp|ncasecmp|chr|rchr|str|tol|toul|tod|spn|cspn|pbrk|tok)|"
                   r"free|malloc|calloc|realloc)$|start\+|__libc|operator (new|delete))")
START = re.compile(r"==llmfuzz== (crash|timeout|oom) after|^llmfuzz: \d+ edges")  # a report never spans these
DONE = re.compile(r"^#(\d+)\s+DONE\b")  # a worker process's last stats line


class Crash(TypedDict):
    kind: str  # crash, timeout or oom
    signature: str  # dedup key, see signature()
    artifact: str  # the first input that hit it (later ones are deleted)
    time: float  # seconds into the campaign
    worker: int
    execs: int  # executions of that worker process so far
    hits: int  # how many saved inputs had this signature


class Summary(TypedDict):
    binary: str
    elapsed: float
    execs: int
    jobs: int
    weights: str | Sequence[str | None] | None
    crashes: list[Crash]


def secs(t: float) -> str:
    return f"{t:.1f}s" if t < 10 else f"{t:.0f}s"


def _func_name(frame: str) -> str:
    """'char const* ns::parse<T>(char const*) file.cpp:12:3' -> 'ns::parse<T>'."""
    frame = re.sub(r"\s+\(BuildId: [0-9a-f]+\)$", "", frame.strip())
    frame = re.sub(r"\s+(\S+:\d+(:\d+)?|\(\S+\+0x[0-9a-f]+\)|\S+\+0x[0-9a-f]+)$", "", frame)
    return short_name(re.sub(r"\+0x[0-9a-f]+$", "", frame))  # unsymbolized: 'abort+0x90'


def signature(kind: str, report: str) -> str:
    """Dedup key: sanitizer error kind + top 3 frames outside runtime/libc. For a timeout, where the
    stack was stopped at a random point, the 3 outermost frames instead: the call that ran too long."""
    m = re.search(r"ERROR: \w+Sanitizer: ([\w-]+)(?: on [\w ]+)?", report)
    m2 = re.search(r"AddressSanitizer: \S+ on address \S+ .*?\n(READ|WRITE)", report, re.S)
    head = (m.group(1) if m else kind) + (f"-{m2.group(1)}" if m2 else "")
    frames, seen = [], False
    for num, fn in FRAME.findall(report):  # first stack trace only
        if num == "0" and seen:
            break
        seen = True
        frames.append(_func_name(fn) if fn else "")
    frames = [f for f in frames if f and f != "??" and not NOISE.match(f)]
    return head + " @ " + " < ".join(frames[-3:] if kind == "timeout" and not m else frames[:3])


def symbolize_report(report: str) -> str:
    """Name the frames a sanitizer left unsymbolized (workers run with ASAN_OPTIONS=symbolize=0, as in AFL++:
    symbolizing inside the target takes seconds on macOS, longer than the timeout, and most crashes are
    repeats). Frames in system libraries stay as they are."""
    want: dict[tuple[str, str], set[int]] = defaultdict(set)
    for line in report.split("\n"):
        if (m := RAW_FRAME.match(line)) and not SYSTEM.search(m.group(4)) and os.path.isfile(m.group(4)):
            want[(m.group(4), m.group(5) or "")].add(int(m.group(6), 16))
    if not want:
        return report
    chains: dict[tuple[str, int], list[Frame]] = {}
    for (mod, arch), offs in want.items():
        for off, frames in zip(sorted(offs), symbolize_chains(mod, sorted(offs), arch or None)):
            chains[(mod, off)] = [f for f in frames if f[0] != "??"]
    out: list[str] = []
    k = 0
    for line in report.split("\n"):
        m = RAW_FRAME.match(line)
        chain = chains.get((m.group(4), int(m.group(6), 16))) if m else None
        if not m or not chain:
            if f := FRAME.match(line):  # keep the numbering of a trace consistent
                k = 0 if f.group(1) == "0" else k
                line = re.sub(r"#\d+", f"#{k}", line, count=1)
                k += 1
            out.append(line)
            continue
        k = 0 if m.group(2) == "0" else k
        for fn, file, ln in chain:  # one line per inlined function, as the sanitizer prints them
            out.append(f"{m.group(1)}#{k} {m.group(3)} in {fn} " + (f"{file}:{ln}" if file else f"({m.group(4)})"))
            k += 1
    return "\n".join(out)


class Worker:
    def __init__(self, idx: int, out: Path) -> None:
        self.idx, self.log, self.stats = idx, out / "logs" / f"worker-{idx}.log", out / "logs" / f"stats-{idx}.jsonl"
        self.offset = 0  # of the unscanned part of the log
        self.stats_from = 0  # where the running process's lines start in the stats file
        self.starts = 0
        self.done_execs = 0  # executions of its finished processes (a crash in a harness ends the process)
        self.fork = False  # run each input in a child: set once it keeps dying on crashes already found
        self.proc: subprocess.Popen[bytes] | None = None
        self.tail: list[str] = []  # last lines of its log already scanned (a report may span two scans)

    def execs(self) -> int:
        """Executions so far, over all its processes."""
        st = _last_stats(self.stats, self.stats_from) if self.proc is not None and self.proc.poll() is None else None
        return self.done_execs + (st["execs"] if st else 0)


def run(binary: str, out_dir: str | Path, jobs: int = 1, total_time: float = 3600.0,
        weights: str | Sequence[str | None] | None = None, seeds: Sequence[str] = (), dict_path: str | None = None,
        timeout: float = 2.0, extra: Sequence[str] = (), target_args: Sequence[str] = (), stop_on_crash: bool = False,
        seed: int = 0, quiet: bool = False, status_every: float = 30.0) -> Summary:
    """Fuzz until total_time, a crash (stop_on_crash) or Ctrl-C; write and return the summary.
    weights: one weight file, or one per worker in turn (None / 'none': plain coverage-guided)."""
    out = Path(out_dir)
    for d in ("corpus", "crashes", "logs"):
        (out / d).mkdir(parents=True, exist_ok=True)
    harness = is_harness(binary)
    flags = [f"-artifact_prefix={out}/crashes/", f"-timeout={timeout}", "-print_secs=10"]
    wlist = [w if w and w != "none" else None for w in ([weights] if isinstance(weights, str) else weights or [None])]
    flags += [f"-dict={dict_path}"] if dict_path else []
    flags += list(extra)
    env = dict(os.environ)
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0:allocator_may_return_null=1:handle_abort=1:handle_sigill=1:symbolize=0")
    t0 = time.time()
    crashes: dict[str, Crash] = {}
    by_artifact: dict[str, str] = {}  # recorded input -> its signature
    workers = [Worker(i, out) for i in range(jobs)]

    def spawn(w: Worker) -> None:
        rem = int(total_time - (time.time() - t0))
        wt = wlist[w.idx % len(wlist)]  # several weight files: workers take turns (None = plain)
        f = flags + ([f"-weights={wt}"] if wt else []) + [f"-max_total_time={max(1, rem)}",
                     f"-seed={seed * 7919 + w.idx * 1000 + w.starts + 1}", f"-stats={w.stats}"]
        w.starts += 1
        w.stats_from = w.stats.stat().st_size if w.stats.exists() else 0
        log = open(w.log, "ab")
        w.offset = log.tell()
        if harness:
            f += ["-fork=1"] if w.fork else []
            cmd, wenv = [binary] + f + [str(out / "corpus")] + list(seeds), env
        else:  # program mode: the runtime's fork server, configured via environment
            inp = str((out / f".input-{w.idx}").resolve())
            cmd = [binary] + [inp if a == "@@" else a for a in target_args]
            f += [f"-input_file={inp}"] + ([] if "@@" in target_args else ["-stdin=1"])
            wenv = dict(env, LLMFUZZ_OPTIONS=" ".join(f + [str(out / "corpus")] + list(seeds)))
        w.proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=wenv)
        log.close()

    def scan(w: Worker) -> bool:
        """Record the new crashes in the worker's log; True if one has a new signature."""
        with open(w.log, "rb") as fh:
            fh.seek(w.offset)
            data = fh.read()
        if w.proc is not None and w.proc.poll() is None:  # only complete lines while the worker runs
            data = data[: data.rfind(b"\n") + 1]
        w.offset += len(data)
        lines, new, start = w.tail + data.decode(errors="replace").split("\n"), False, 0
        for i, line in enumerate(lines):
            m = CRASH_LINE.search(line) if i >= len(w.tail) else None
            if not m:
                start = i + 1 if START.search(line) else start
                if i >= len(w.tail) and (d := DONE.match(line)):
                    w.done_execs += int(d.group(1))
                continue
            kind, _, execs, art, rep = m.groups()
            report = (Path(rep).read_text(errors="replace") if rep and os.path.exists(rep)
                      else "\n".join(lines[max(start, i - 300): i]))  # this crash's report only
            start = i + 1
            report = symbolize_report(report)
            if kind == "timeout" and re.search(r"ERROR: \w+Sanitizer", report):  # killed while reporting
                kind = "crash"
            sig = signature(kind, report)
            if rep:  # the runtime's raw report: superseded by the symbolized ART.report.txt
                Path(rep).unlink(missing_ok=True)
            if art in by_artifact or sig in crashes:  # in-process, a shallow known bug would keep killing the worker
                if harness and not rep and not w.fork and kind != "timeout":  # (a timeout only restarts it)
                    w.fork = True
                    if not quiet:
                        print(f"[llmfuzz] worker {w.idx} hit a known crash again: it runs inputs in forked "
                              "children from now on", flush=True)
            if art in by_artifact:  # the same input again (a timeout's stack differs from run to run)
                crashes[by_artifact[art]]["hits"] += 1
                continue
            if sig in crashes:  # a repeat: keep one input per signature
                crashes[sig]["hits"] += 1
                Path(art).unlink(missing_ok=True)
                continue
            crashes[sig] = {"kind": kind, "signature": sig, "artifact": art, "time": round(time.time() - t0, 2),
                            "worker": w.idx, "execs": int(execs), "hits": 1}
            by_artifact[art] = sig
            Path(art + ".report.txt").write_text(report)
            new = True
            if not quiet:
                print(f"[llmfuzz] NEW {kind} #{len(crashes)} at {secs(time.time() - t0)}: {sig}\n          {art}", flush=True)
        w.tail = lines[-400:]
        return new

    for w in workers:
        spawn(w)
    last_print, last_execs = time.time(), 0
    try:
        while time.time() - t0 < total_time:
            time.sleep(0.2)
            stop = False
            for w in workers:
                stop |= scan(w) and stop_on_crash
                if w.proc is not None and w.proc.poll() is not None and not stop and total_time - (time.time() - t0) > 2:
                    spawn(w)
            if stop:
                break
            if not quiet and time.time() - last_print > status_every:
                st = [s for w in workers if (s := _last_stats(w.stats))]  # coverage: from any of its processes
                execs = sum(w.execs() for w in workers)
                rate = (execs - last_execs) / (time.time() - last_print)
                last_print, last_execs = time.time(), execs
                if st:
                    print(f"[llmfuzz] {time.time() - t0:6.0f}s  execs {execs:>11,} ({rate:,.0f}/s)  "
                          f"cov {max(s['cov'] for s in st)}  hot {max(s['hot'] for s in st)}/{max(s['hot_total'] for s in st)}  "
                          f"corpus {len(os.listdir(out / 'corpus'))}  crashes {len(crashes)}", flush=True)
    except KeyboardInterrupt:  # Ctrl-C ends the campaign normally (the workers got SIGINT too)
        if not quiet:
            print("\n[llmfuzz] interrupted, stopping workers", flush=True)
    finally:
        for w in workers:
            if w.proc and w.proc.poll() is None:
                w.proc.terminate()
        for w in workers:
            if w.proc:
                try:
                    w.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    w.proc.kill()
            scan(w)
    summary: Summary = {"binary": binary, "elapsed": round(time.time() - t0, 1), "execs": sum(w.done_execs for w in workers),
                        "jobs": jobs, "weights": weights, "crashes": list(crashes.values())}
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary


def _last_stats(path: Path, start: int = 0) -> dict[str, Any] | None:
    """The last line of a worker's stats file, if one was written after offset `start`."""
    try:
        with open(path, "rb") as f:
            f.seek(max(start, os.path.getsize(path) - 4096))
            st: dict[str, Any] = json.loads(f.read().decode().strip().split("\n")[-1])
            return st
    except (OSError, ValueError, IndexError):
        return None

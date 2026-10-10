"""Figures for the technical report on aaaab3n.moe (not part of the llmfuzz core; needs matplotlib).

  python bench/report_figures.py OUTDIR [contract.json] [--lang zh]
The numbers are the ones in README §2, §3.10, §3.11 and §3.12 (bench/results/*). contract.json holds the per-bug
percentiles of Qwen3.6-27B answering directly / after its own contract / after another function's contract, written by
ctx_analyze.rank_rows on the q36_spec and q36_specshuf runs; without it figure 3 is skipped.
--lang zh writes the figures of the Chinese version (fig-N-*-zh.svg; needs a CJK font, Hiragino Sans GB on macOS).
"""
import argparse
import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

INK, MUTED, GRID = "#1f1f1f", "#6b6b6b", "#e6e2da"
CLAY, SLATE, SAND, SKY = "#d97757", "#3d4a5c", "#c9c3b6", "#7a9cc6"
plt.rcParams.update({
    "font.family": "Helvetica", "font.size": 10, "text.color": INK, "axes.labelcolor": INK,
    "axes.edgecolor": MUTED, "xtick.color": MUTED, "ytick.color": INK, "axes.spines.top": False,
    "axes.spines.right": False, "svg.fonttype": "path", "figure.facecolor": "white", "axes.facecolor": "white",
})

ZH = {  # labels of the Chinese version; function and target names stay as they are
    "percentile among the target's chunks (lower = more suspicious)": "在目标所有片段中的百分位（越低越可疑）",
    "LLM (Qwen3-4B J-lens probe), median 27.0": "LLM（Qwen3-4B J-lens probe），中位数 27.0",
    "function size only, median 14.6": "只看函数大小，中位数 14.6",
    "LLM scores shuffled, median 56.2": "打乱的 LLM 分数，中位数 56.2",
    "woff2: Buffer::Read (called from ReconstructGlyf)": "woff2：Buffer::Read（由 ReconstructGlyf 调用）",
    "lcms: TetrahedralInterpFloat": "lcms：TetrahedralInterpFloat",
    "no weights": "不加权", "oracle #1, others equal": "oracle 排第 1，其余相同", "oracle #1, others random": "oracle 排第 1，其余随机",
    "oracle top 5%, others random": "oracle 在前 5%，其余随机", "oracle top 25%, others random": "oracle 在前 25%，其余随机",
    "s": "秒", "0 s": "0 秒", "300 s": "300 秒", "600 s": "600 秒", "900 s": "900 秒", "not found": "未找到",
    "time to first crash per trial (Linux, 900 s budget); bar = median": "每次试验的首次崩溃时间（Linux，预算 900 秒）；竖线为中位数",
    "percentile among the target's sampled chunks (lower = more suspicious)": "在目标抽样片段中的百分位（越低越可疑）",
    "answer directly, median 35.2": "直接回答，中位数 35.2",
    "after writing its own doc comment, median 20.1": "先写自己的注释，中位数 20.1",
    "with another function's comment, median 50.0": "用另一个函数的注释，中位数 50.0",
    "function size only, median 14.2": "只看函数大小，中位数 14.2",
    "14B, direct": "14B，直接回答", "14B, comment first": "14B，先写注释", "14B, full reasoning": "14B，完整推理",
    "27B, direct": "27B，直接回答", "27B, comment first": "27B，先写注释", "27B, full reasoning": "27B，完整推理",
    "rule: fewer if-checks": "规则：if 检查更少", "rule: less code": "规则：代码更少",
    "pair accuracy (buggy scored above fixed)": "配对准确率（有 bug 的版本得分更高）",
    "bugs fixed after release": "模型发布后修复的 bug",
    "both right": "两个都对", "Yes on both": "都说有 bug", "No on both": "都说没有", "both wrong": "两个都错",
    "the model's own Yes/No on both versions": "模型自己对两个版本的 Yes/No",
}
LANG = "en"


def tr(s):
    return ZH.get(s, s) if LANG == "zh" else s


def fname(fig):
    return f"{fig}-zh.svg" if LANG == "zh" else f"{fig}.svg"


# README §2: percentile of each FTS bug function among all regions of its target (lower = ranked higher).
RANKING = [  # (target, function, llm, size, shuffled)
    ("libcxxabi", "parse_floating_number", 2.5, 45.6, 62.0),
    ("libcxxabi", "parse_function_type", 98.7, 24.1, 19.0),
    ("libcxxabi", "parse_unnamed_type_name", 45.6, 21.5, 92.4),
    ("pcre2", "match", 3.2, 0.5, 3.2),
    ("lcms", "TetrahedralInterpFloat", 23.9, 3.3, 28.9),
    ("woff2", "ReconstructGlyf", 6.9, 3.1, 12.9),
    ("woff2", "Buffer::Read", 11.2, 50.7, 93.1),
    ("re2", "NFA::Search", 8.9, 1.6, 29.8),
    ("libxml2", "xmlParseXMLDecl", 71.2, 14.6, 73.7),
    ("libxml2", "xmlDictComputeFastQKey", 63.6, 29.8, 45.0),
    ("libxml2", "xmlDictComputeFastKey", 45.5, 50.5, 81.5),
    ("libxml2", "xmlCurrentChar", 40.1, 10.8, 76.6),
    ("openssl", "tls1_process_heartbeat", 27.0, 10.9, 56.2),
]

# README §3.10: time to first crash (s) per trial on Linux, 8 x 900 s; None = not found.
N = None
ORACLE = {
    "woff2: Buffer::Read (called from ReconstructGlyf)": [
        ("no weights", [52, 158, 222, 230, 320, 384, 390, 728], 275),
        ("oracle #1, others equal", [11, 34, 83, 142, 145, 298, 369, 469], 143),
        ("oracle #1, others random", [97, 101, 114, 188, 326, 380, 828, N], 257),
        ("oracle top 5%, others random", [2, 11, 48, 249, 274, 402, 686, N], 262),
        ("oracle top 25%, others random", [188, 342, 599, 710, 761, N, N, N], 736),
    ],
    "lcms: TetrahedralInterpFloat": [
        ("no weights", [126, 166, 356, 563, 606, N, N, N], 585),
        ("oracle #1, others equal", [198, 500, 538, 686, N, N, N, N], 793),
        ("oracle #1, others random", [223, 327, 803, N, N, N, N, N], None),
        ("oracle top 5%, others random", [197, 334, 593, N, N, N, N, N], None),
        ("oracle top 25%, others random", [304, 398, 483, N, N, N, N, N], None),
    ],
}

# README §3.12 / bench/results/pairs.txt: share of pairs whose buggy version gets the higher yes-vs-no readout.
PAIRS = [  # (label, new bugs, PrimeVul)
    ("14B, direct", 0.53, 0.51), ("14B, comment first", 0.50, 0.50), ("14B, full reasoning", 0.66, 0.51),
    ("27B, direct", 0.76, 0.60), ("27B, comment first", 0.76, 0.60), ("27B, full reasoning", 0.62, 0.55),
    ("rule: fewer if-checks", 0.71, 0.65), ("rule: less code", 0.85, 0.86),
]
VERDICTS = [  # new bugs: both right, Yes on both, No on both, both wrong
    ("14B, direct", 0.00, 1.00, 0.00, 0.00), ("14B, full reasoning", 0.20, 0.65, 0.09, 0.05),
    ("27B, direct", 0.11, 0.36, 0.51, 0.01), ("27B, comment first", 0.17, 0.41, 0.40, 0.03),
    ("27B, full reasoning", 0.22, 0.66, 0.07, 0.05),
]


def ranking(out):
    rows = sorted(RANKING, key=lambda r: r[3])
    fig, ax = plt.subplots(figsize=(7.2, 5.0))
    for i, (t, f, llm, size, shuf) in enumerate(rows):
        ax.plot([min(llm, size), max(llm, size)], [i, i], color=GRID, lw=2, zorder=1)
        ax.scatter(shuf, i, s=34, facecolor="white", edgecolor=SAND, lw=1.4, zorder=2)
        ax.scatter(size, i, s=40, color=SLATE, zorder=3)
        ax.scatter(llm, i, s=40, color=CLAY, zorder=4)
    ax.set_yticks(range(len(rows)), [f"{f}  ({t})" for t, f, *_ in rows], fontsize=8.5)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel(tr("percentile among the target's chunks (lower = more suspicious)"))
    ax.grid(axis="x", color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    ax.legend(handles=[
        Line2D([], [], marker="o", ls="", color=CLAY, label=tr("LLM (Qwen3-4B J-lens probe), median 27.0")),
        Line2D([], [], marker="o", ls="", color=SLATE, label=tr("function size only, median 14.6")),
        Line2D([], [], marker="o", ls="", markerfacecolor="white", markeredgecolor=SAND,
               label=tr("LLM scores shuffled, median 56.2")),
    ], loc="upper center", bbox_to_anchor=(0.32, -0.14), ncol=2, frameon=False, fontsize=8.5)
    fig.tight_layout()
    fig.savefig(f"{out}/{fname('fig-1-ranking')}")


def oracle(out):
    fig, axes = plt.subplots(2, 1, figsize=(7.2, 4.9), sharex=True)
    colors = [SAND, SLATE, CLAY, CLAY, CLAY]
    for ax, (title, rows) in zip(axes, ORACLE.items()):
        for i, (label, ttes, med) in enumerate(rows):
            found = sorted(t for t in ttes if t is not None)
            ax.scatter(found, [i] * len(found), s=30, color=colors[i], alpha=0.95 if i < 2 else 0.6, zorder=3,
                       edgecolor="white", lw=0.5)
            miss = len(ttes) - len(found)
            ax.scatter([960 + 24 * j for j in range(miss)], [i] * miss, s=26, facecolor="white",
                       edgecolor=colors[i], lw=1.2, zorder=3)
            if med is not None:
                ax.plot([med, med], [i - 0.3, i + 0.3], color=INK, lw=1.4, zorder=4)
            ax.text(1170, i, f"{len(found)}/8" + ("" if med is None else f"   {med} {tr('s')}"), va="center",
                    fontsize=8.5, color=MUTED)
        ax.set_yticks(range(len(rows)), [tr(r[0]) for r in rows], fontsize=8.5)
        ax.invert_yaxis()
        ax.set_title(tr(title), loc="left", fontsize=9.5, color=INK)
        ax.axvline(930, color=GRID, lw=1)
        ax.grid(axis="x", color=GRID, lw=0.8)
        ax.set_axisbelow(True)
        ax.set_xlim(0, 1290)
    axes[-1].set_xticks([0, 300, 600, 900, 1032], [tr(x) for x in ("0 s", "300 s", "600 s", "900 s", "not found")])
    axes[-1].set_xlabel(tr("time to first crash per trial (Linux, 900 s budget); bar = median"))
    fig.tight_layout()
    fig.savefig(f"{out}/{fname('fig-2-oracle')}")


def contract(out, path):
    d = json.load(open(path))
    keys = sorted(d["iso"], key=lambda k: d["iso"][k])
    fig, ax = plt.subplots(figsize=(7.2, 5.2))
    for i, k in enumerate(keys):
        iso, own, moved, size = d["iso"][k], d["own"][k], d["moved"][k], d["size"][k]
        ax.annotate("", xy=(own, i), xytext=(iso, i), arrowprops=dict(arrowstyle="-|>", color=CLAY, lw=1.3,
                                                                       shrinkA=4, shrinkB=4), zorder=2)
        ax.scatter(iso, i, s=36, color=SAND, zorder=3)
        ax.scatter(own, i, s=40, color=CLAY, zorder=4)
        ax.scatter(moved, i, s=34, marker="x", color=SKY, lw=1.4, zorder=3)
        ax.scatter(size, i, s=60, marker="|", color=SLATE, lw=1.6, zorder=3)
    ax.set_yticks(range(len(keys)), [k.split(":")[1] + f"  ({k.split(':')[0].replace('llvm', 'libcxxabi')})"
                                     for k in keys], fontsize=8.5)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel(tr("percentile among the target's sampled chunks (lower = more suspicious)"))
    ax.grid(axis="x", color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    ax.legend(handles=[
        Line2D([], [], marker="o", ls="", color=SAND, label=tr("answer directly, median 35.2")),
        Line2D([], [], marker="o", ls="", color=CLAY, label=tr("after writing its own doc comment, median 20.1")),
        Line2D([], [], marker="x", ls="", color=SKY, label=tr("with another function's comment, median 50.0")),
        Line2D([], [], marker="|", ls="", color=SLATE, markersize=9, label=tr("function size only, median 14.2")),
    ], loc="upper center", bbox_to_anchor=(0.32, -0.14), ncol=2, frameon=False, fontsize=8.5)
    fig.tight_layout()
    fig.savefig(f"{out}/{fname('fig-3-contract')}")


def pairs(out):
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.6, 3.9), gridspec_kw={"width_ratios": [1.15, 1]})
    y = range(len(PAIRS))
    a1.barh([i - 0.19 for i in y], [p[1] for p in PAIRS], height=0.36, color=[CLAY] * 6 + [SAND] * 2,
            label="148 bugs fixed after the model's release")
    a1.barh([i + 0.19 for i in y], [p[2] for p in PAIRS], height=0.36, color=[SLATE] * 6 + ["#e8e4dc"] * 2,
            label="100 PrimeVul pairs")
    a1.axvline(0.5, color=MUTED, lw=1, ls="--")
    a1.set_yticks(list(y), [tr(p[0]) for p in PAIRS], fontsize=8.5)
    a1.invert_yaxis()
    a1.set_xlim(0.4, 0.9)
    a1.set_xlabel(tr("pair accuracy (buggy scored above fixed)"))
    a1.legend(handles=[Line2D([], [], marker="s", ls="", color=CLAY, label=tr("bugs fixed after release")),
                       Line2D([], [], marker="s", ls="", color=SLATE, label="PrimeVul")],
              loc="upper center", bbox_to_anchor=(0.4, -0.2), ncol=2, frameon=False, fontsize=8)
    a1.grid(axis="x", color=GRID, lw=0.8)
    a1.set_axisbelow(True)
    cols = [("both right", CLAY), ("Yes on both", SAND), ("No on both", SKY), ("both wrong", SLATE)]
    for i, (label, *v) in enumerate(VERDICTS):
        left = 0.0
        for (name, c), x in zip(cols, v):
            a2.barh(i, x, left=left, color=c, height=0.6)
            if x >= 0.1:
                a2.text(left + x / 2, i, f"{round(100 * x)}%", ha="center", va="center", fontsize=8,
                        color="white" if c in (CLAY, SLATE) else INK)
            left += x
    a2.set_yticks(range(len(VERDICTS)), [tr(v[0]) for v in VERDICTS], fontsize=8.5)
    a2.invert_yaxis()
    a2.set_xlim(0, 1)
    a2.set_xticks([0, 0.5, 1], ["0", "50%", "100%"])
    a2.set_xlabel(tr("the model's own Yes/No on both versions"))
    a2.legend(handles=[Line2D([], [], marker="s", ls="", color=c, label=tr(n)) for n, c in cols], ncol=2,
              loc="upper center", bbox_to_anchor=(0.45, -0.2), frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(f"{out}/{fname('fig-4-pairs')}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("contract", nargs="?")
    ap.add_argument("--lang", choices=("en", "zh"), default="en")
    a = ap.parse_args()
    LANG = a.lang
    if LANG == "zh":
        plt.rcParams["font.family"] = ["Helvetica", "Hiragino Sans GB"]  # Chinese glyphs fall back to the second font
    ranking(a.out)
    oracle(a.out)
    pairs(a.out)
    if a.contract:
        contract(a.out, a.contract)

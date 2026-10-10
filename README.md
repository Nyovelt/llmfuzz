# llmfuzz

llmfuzz 是一个面向 C/C++ 的覆盖率制导 fuzzer（AFL / libFuzzer 风格，用 clang 插桩），可以把更多 fuzzing 预算花在"可疑"的代码上：
每个函数一个分数，分数变成插桩边的权重，影响种子能量和比较反馈（value profile）。分数从哪里来是可插拔的（`--prior`）：

| `--prior` | 权重来源 | 需要 |
|---|---|---|
| `size`（默认） | 函数行数：越长越可疑 | 无 |
| `llm` | LLM 读代码时的隐藏状态：Qwen3-4B 的 Jacobian lens 加一个线性 probe | `pip install -e '.[llm]'`，最好有 GPU（CUDA 或 Apple MPS） |
| `scores.json` | 你自己的分数，例如静态分析告警，或者最近改过的函数 | 无 |
| `none` | 不加权，即普通的覆盖率制导 fuzzing | 无 |

这个仓库也是一份技术报告的全部实验代码和原始数据：
[LLM 知道一点 bug 在哪，但这没让 fuzzing 变快](https://aaaab3n.moe/cn/llm-guided-fuzzing)（[English](https://aaaab3n.moe/llm-guided-fuzzing)）。
简短的结论是：LLM 的信号是真的，但很弱，用它加权并不比按函数长度加权更快找到 bug（见"评估"）。
所以默认先验是 `size`；`llm` 留给想复现或继续这项研究的人。

```
 源码 + 插桩二进制 ─► PC 表 (-dump_pcs) ─► 符号化 (llvm-symbolizer/atos/addr2line)
                                            ─► C/C++ 函数边界解析，长函数切成 ~150 行区域
                                                        │
          --prior size：log(行数)          --prior llm：Qwen3-4B 读区域代码，J-lens 读出 + probe ─► bug logit
          --prior FILE：{"函数名": 分数}    --prior none：不加权
                                                        │
                  程序内 z-score ─► 每条边权重 w = clip(exp(k·z), 0.5, 8)，前 10% 区域为 "hot"
                                                        │
 fuzz 循环：种子能量 = Σ(该种子首次发现的 feature) w(edge)^γ / sqrt(1 + hits/256)
            hot 代码里打开比较距离反馈（value profile）；10% 的选择保持均匀，防止权重错误时饿死其他代码
```

J-lens 来自 Anthropic 的 *Verbalizable Representations Form a Global Workspace in Language Models*
（2026，参考实现 `anthropics/jacobian-lens`）：`J_l = E[∂h_final/∂h_l]` 是语料上平均的输入-输出 Jacobian，
它把第 l 层的残差流"运送"到最后一层的坐标系，再用模型自己的 unembedding 解码。
llmfuzz 直接使用 Neuronpedia 预拟合的 lens（`neuronpedia/jacobian-lens`），并在其上训练 probe。

## 结论速览

- **能用**：约 2650 行的完整 fuzzer，可以直接替换 libFuzzer 编译 OSS-Fuzz 风格的 harness（支持 `LLVMFuzzerCustomMutator`），
  也能 fuzz 自带 `main()` 的程序。不加权重时，它和 libFuzzer 互有胜负（§3.6）。
- **LLM 的信号真实但弱**：J-lens probe 在去掉长度因素的 PrimeVul 测试集上 AUC 只有 0.57，
  在真实分布上不如"函数越长越可疑"（§1）。
- **制导效果因目标和平台而异**：
  - LLM 看对时（macOS 上的 libcxxabi，崩溃函数排在 79 个区域的第 2 位），找到 bug 快 8 倍，并显著快于随机权重。
  - Linux 上（两台机器）没有加速，lcms、woff2 上反而更慢。只按函数行数加权的先验反而最快：相对不加权，
    TTE 中位数的几何平均是 0.35×（§3、§4）。

## 安装

```bash
git clone https://github.com/Nyovelt/llmfuzz && cd llmfuzz
pip install -e .            # fuzz：只需要 numpy（和 clang）
pip install -e '.[llm]'     # 还要用 --prior llm 给函数打分：再装 PyTorch、transformers
```

- **环境**：需要 clang（Apple clang 或 LLVM clang，已在 Apple clang 21 / macOS arm64 和 clang 18 / Ubuntu 24.04 x86-64 上测试）
  和 Python ≥ 3.10。LLM 打分强烈建议用 GPU（CUDA 或 Apple MPS），CPU 也能跑但慢。
- **模型**：默认模型 Qwen/Qwen3-4B（约 8 GB）和 J-lens（约 460 MB）在第一次使用时从 Hugging Face 下载。
- **在 GPU 机器上打分，在别的机器上 fuzz**：
  - 同一个二进制：把 `BINARY.llm.weights` 拷过去，`llmfuzz run --prior llm` 会直接用它（比二进制新就不重算）。
  - 在 fuzz 机器上重新编译过：把 `BINARY.llmcache.json` 拷过去再跑。分数按"文件名 + 函数文本"缓存，
    命中缓存时不加载模型，也不需要 PyTorch。

## 快速上手

`examples/demo.c` 是一个 4 个函数的小解析器，其中一个函数有栈溢出：

```console
$ llmfuzz-cc -O1 examples/demo.c -o demo
$ llmfuzz run ./demo -t 20
[llmfuzz] 13 PCs -> 4 source regions (11 PCs mapped)
wrote ./demo.size.weights (hot threshold 4.08) and ./demo.size.weights.json

top functions by size:
   +1.407  w= 4.08  LLVMFuzzerTestOneInput                       demo.c:45
   +0.141  w= 1.15  read_header                                  demo.c:17
   -0.141  w= 0.87  read_record                                  demo.c:24
   -1.407  w= 0.50  apply                                        demo.c:35
[llmfuzz] fuzzing ./demo with 1 job(s) for 20s; corpus and crashes in llmfuzz-out/
[llmfuzz] NEW crash #1 at 0.2s: stack-buffer-overflow-WRITE @ read_record < LLVMFuzzerTestOneInput
          llmfuzz-out/crashes/crash-e98520bce0563c1c
[llmfuzz] worker 0 hit a known crash again: it runs inputs in forked children from now on
[llmfuzz]     10s  execs      12,116 (1,211/s)  cov 12  hot 4/4  corpus 31  crashes 1
[llmfuzz]     20s  execs      17,266 (509/s)  cov 12  hot 4/4  corpus 31  crashes 1

[llmfuzz] done in 20s, 17,266 execs: 1 unique crash(es); details in llmfuzz-out/summary.json
  #1 crash at 0.2s (2 hits): stack-buffer-overflow-WRITE @ read_record < LLVMFuzzerTestOneInput
     reproduce: ./demo llmfuzz-out/crashes/crash-e98520bce0563c1c
     report:    llmfuzz-out/crashes/crash-e98520bce0563c1c.report.txt
```

`run` 先给每个函数打分（结果缓存在 `demo.size.weights`，二进制不变就不重算），然后 fuzz 到 `-t` 秒或 Ctrl-C，
最后列出去重后的崩溃、复现命令和符号化的报告。不给 `-t` 就一直跑，Ctrl-C 也会正常收尾、写出汇总。
这个 bug 很浅，不加权重也是一秒内找到；例子只用来演示流程。

换成 LLM 打分（第一次会下载模型）：

```console
$ pip install -e '.[llm]'
$ llmfuzz run ./demo --prior llm -t 10
[llmfuzz] 13 PCs -> 4 source regions (11 PCs mapped)
[llmfuzz] using probe qwen3-4b-jlens.npz (trained on train_m.jsonl)
[llmfuzz] scoring 4 functions (0 cached)
[llmfuzz] loading Qwen/Qwen3-4B on mps and lens neuronpedia/jacobian-lens:qwen3-4b/jlens/Salesforce-wikitext/Qwen3-4B_jacobian_lens.pt
wrote ./demo.llm.weights (hot threshold 4.49) and ./demo.llm.weights.json

top functions by LLM bug score:
   +1.502  w= 4.49  read_record                                  demo.c:24
   +0.208  w= 1.23  apply                                        demo.c:35
   -0.509  w= 0.60  LLVMFuzzerTestOneInput                       demo.c:45
   -1.201  w= 0.50  read_header                                  demo.c:17
...
```

LLM 把真正有 bug 的 `read_record` 排在第一。分数缓存在 `demo.llmcache.json`，函数没改就不会再跑模型。

## 用法

### 1. 用包装器编译目标

`llmfuzz-cc` / `llmfuzz-c++` 的用法类似 `afl-clang-fast`：加上
`-g -fsanitize-coverage=trace-pc-guard,pc-table,trace-cmp -fsanitize=address`，
去掉 `-fsanitize=fuzzer[-no-link]`（OSS-Fuzz 风格的 build 脚本可以原样使用），并在链接时带上运行时。

```bash
# libFuzzer 风格 harness（定义了 LLVMFuzzerTestOneInput）：运行时提供 main()
CC=llmfuzz-cc CXX=llmfuzz-c++ ./configure --disable-shared && make
llmfuzz-c++ -O1 fuzz_target.cc libfoo.a -o fuzzer

# 任意自带 main() 的程序（AFL 风格，输入走文件或 stdin）
CC=llmfuzz-cc ./configure && make

# CMake 项目
cmake -B build -DCMAKE_C_COMPILER=llmfuzz-cc -DCMAKE_CXX_COMPILER=llmfuzz-c++ -DBUILD_SHARED_LIBS=OFF
```

- harness 可以定义 `LLVMFuzzerInitialize` 和 `LLVMFuzzerCustomMutator`（其中可以调用 `LLVMFuzzerMutate`），语义同 libFuzzer。
- `LLMFUZZ_SANITIZER=address,undefined`（或 `none`）可以换 sanitizer。
- 编译后不要移动源码：打分时通过调试信息找到并读取源码。
- 设置 `LLMFUZZ_CDB=cdb.jsonl` 时，包装器把每条编译命令追加到这个文件，`bench/ctx_dataset.py` 用它让 clang 给出精确的调用图（§3.9）。

### 2. `llmfuzz run`

```
llmfuzz run BINARY [SEED_DIR ...] [--prior size|llm|none|FILE] [-j N] [-t SECONDS] [-x DICT] [-o OUT]
                   [--timeout SECONDS] [--stop-on-crash] [-- PROGRAM_ARGS ... @@ ...]
```

| 选项 | 作用 |
|---|---|
| `SEED_DIR ...` | 种子目录，可以没有 |
| `--prior` | 权重从哪来，见开头的表；`FILE` 是 `{"函数名": 分数}` 的 JSON，没列出的函数分数为 0 |
| `-j N` | 并行 worker 数，共享一个语料目录（默认 1） |
| `-t SECONDS` | 运行时长；不给就一直跑到 Ctrl-C |
| `-x DICT` | AFL / libFuzzer 格式的字典 |
| `-o OUT` | 输出目录（默认 `llmfuzz-out`） |
| `--timeout SECONDS` | 单个输入的超时（默认 2 秒），超时也算一种发现 |
| `--stop-on-crash` | 找到第一个新崩溃就停 |
| `-- ARGS` | 程序模式：目标程序的参数，`@@` 换成输入文件；没有 `@@` 时输入从 stdin 进 |
| `--model` / `--lens` / `--device` | `--prior llm` 用的模型、lens 和设备（默认 Qwen3-4B，自动选 cuda / mps / cpu） |

输出目录：

```
llmfuzz-out/
  corpus/            所有 worker 共享的语料
  crashes/           每个去重后的崩溃一个输入，以及符号化后的报告 *.report.txt
  logs/              每个 worker 的输出（worker-N.log）和统计（stats-N.jsonl）
  summary.json       崩溃列表：类型、签名、发现时间、命中次数
```

几个行为细节：

- **去重**：崩溃按 sanitizer 报告（错误类型 + 前 3 个项目栈帧）去重，每个签名只保留第一个输入，`hits` 记命中次数。
  timeout 被打断时栈停在哪里是随机的，所以改按最外层的 3 个项目栈帧去重，也就是"哪个调用跑得太久"。
- **浅层 bug 不会拖垮 fuzzer**：harness 默认进程内执行，崩溃会结束 worker 进程，驱动器随即重启它。
  某个 worker 第二次撞上已知崩溃时，它改为每个输入 fork 一个子进程，之后重复的崩溃只损失一个子进程。
  timeout 不触发这个切换，只让 worker 重启。
- **会让 worker 死掉的语料文件只重放一次**：从磁盘重放时导致崩溃或超时的文件记在 `crashes/.llmfuzz-skip`，重启后跳过。
- **慢输入**：种子能量按执行时间打折（同 AFL：比平均慢 10 倍的输入只拿 0.1 倍能量），免得 fuzzer 一直变异慢输入。
- **超时**：超过 `--timeout`（默认 2 秒）的输入记为 timeout。有的 harness 本来就允许慢输入
  （比如 SQLite 的 ossfuzz 允许单个输入跑 10 秒），这些 timeout 不一定是 bug。
- **符号化**：worker 里关掉 sanitizer 的符号化（`ASAN_OPTIONS=...:symbolize=0`，和 AFL++ 一样），只在记录新崩溃时离线符号化。
  macOS 上 ASan 在进程内符号化一次要好几秒，比超时还长。自己设置了 `ASAN_OPTIONS` 时以你的为准。

### 3. 大型软件上的例子

下面的例子用的是写这份文档时最新的发布版，都在一台 M1 Ultra（macOS 26.7，Apple clang 21）上跑了 10 分钟
（xmllint 的速度另在 M5 Max 上测过）。换成别的版本，命令一般也能用。

**SQLite 3.54.0**：用 SQLite 自带的 libFuzzer harness `test/ossfuzz.c` 和 amalgamation，编译选项和 OSS-Fuzz 一样。

```bash
curl -LO https://www.sqlite.org/2026/sqlite-amalgamation-3540000.zip && unzip sqlite-amalgamation-3540000.zip
curl -LO https://raw.githubusercontent.com/sqlite/sqlite/version-3.54.0/test/ossfuzz.c
curl -LO https://raw.githubusercontent.com/google/oss-fuzz/master/projects/sqlite3/sql.dict
FLAGS="-O1 -DSQLITE_DEBUG=1 -DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 \
       -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_MAX_PAGE_COUNT=16384"
llmfuzz-cc $FLAGS -Isqlite-amalgamation-3540000 -c sqlite-amalgamation-3540000/sqlite3.c ossfuzz.c   # ASan 下约 2 分钟
llmfuzz-cc sqlite3.o ossfuzz.o -o sqlite3_ossfuzz
mkdir seeds && echo "CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT); INSERT INTO t VALUES(1,'x'); SELECT b, count(*) FROM t GROUP BY b;" > seeds/1.sql
llmfuzz run ./sqlite3_ossfuzz seeds -x sql.dict -j 4 -t 600
```

```console
$ llmfuzz run ./sqlite3_ossfuzz seeds -x sql.dict -j 4 -t 600
[llmfuzz] 56169 PCs -> 2855 source regions (54343 PCs mapped)
wrote ./sqlite3_ossfuzz.size.weights (hot threshold 3.90) and ./sqlite3_ossfuzz.size.weights.json

top functions by size:
   +3.546  w= 8.00  sqlite3VdbeExec [58 regions]                 sqlite3.c:97145
   +2.787  w= 8.00  sqlite3Pragma [16 regions]                   sqlite3.c:145683
   +2.577  w= 8.00  yy_reduce [11 regions]                       sqlite3.c:184456
   ...
[llmfuzz] fuzzing ./sqlite3_ossfuzz with 4 job(s) for 600s; corpus and crashes in llmfuzz-out/
[llmfuzz] NEW timeout #1 at 3.2s: timeout @ sqlite3_step < sqlite3_exec < LLVMFuzzerTestOneInput
          llmfuzz-out/crashes/timeout-70a57307345734ff
[llmfuzz]    121s  execs     573,603 (3,991/s)  cov 9228  hot 2524/10874  corpus 4031  crashes 1
...
[llmfuzz]    595s  execs   1,989,413 (2,498/s)  cov 10351  hot 2819/10874  corpus 5826  crashes 1

[llmfuzz] done in 600s, 2,016,338 execs: 1 unique crash(es); details in llmfuzz-out/summary.json
  #1 timeout at 3.2s (163 hits): timeout @ sqlite3_step < sqlite3_exec < LLVMFuzzerTestOneInput
     reproduce: ./sqlite3_ossfuzz llmfuzz-out/crashes/timeout-70a57307345734ff
     report:    llmfuzz-out/crashes/timeout-70a57307345734ff.report.txt
```

SQLite 被 OSS-Fuzz 持续 fuzz 了很多年，10 分钟没有找到崩溃。唯一的一条是 timeout：这个 harness 允许单个输入跑到 10 秒，
超过默认 2 秒的 163 个输入都记在这一条下面，它们不是 bug。想把这些慢输入和真正的卡死分开，可以加 `--timeout 10`，
代价是吞吐：同样 10 分钟，37 万次执行、9,483 条边，对比默认的 202 万次、10,351 条边。

**libxml2 2.15.4**：用 CMake 编译库，再编译仓库里的 harness `fuzz/xml.c`。这个 harness 自带 `LLVMFuzzerCustomMutator`，
种子用 libxml2 自己的 `genSeed` 从测试文件生成。

```bash
git clone --depth 1 --branch v2.15.4 https://gitlab.gnome.org/GNOME/libxml2.git
cmake -S libxml2 -B build -G Ninja -DCMAKE_C_COMPILER=llmfuzz-cc -DCMAKE_C_FLAGS=-O1 -DBUILD_SHARED_LIBS=OFF \
      -DLIBXML2_WITH_PYTHON=OFF -DLIBXML2_WITH_TESTS=OFF -DLIBXML2_WITH_DEBUG=OFF
ninja -C build                                   # 同时得到程序模式可以用的 build/xmllint
for f in fuzz xml genSeed; do llmfuzz-cc -O1 -Ilibxml2/include -Ibuild/include -Ibuild -c libxml2/fuzz/$f.c; done
LIBS="build/libxml2.a -lz -liconv -lm"           # Linux 上去掉 -liconv
llmfuzz-cc xml.o fuzz.o $LIBS -o xml
llmfuzz-cc genSeed.o fuzz.o $LIBS -o genSeed
mkdir -p seed/xml && ./genSeed xml 'libxml2/test/*' 'libxml2/test/errors/*.xml' 'libxml2/test/valid/*.xml'
llmfuzz run ./xml seed/xml -x libxml2/fuzz/xml.dict -j 4 -t 600
llmfuzz run ./xml seed/xml -x libxml2/fuzz/xml.dict -j 4 -t 600 --prior llm -o out-llm
```

两种先验的排名完全不同。按大小排，前面是 XML Schema 和 RelaxNG 里几百行的大函数；LLM 把格式化字符串的
`xmlStrVPrintf` / `xmlStrPrintf` 排在最前：

```console
$ llmfuzz run ./xml seed/xml -x libxml2/fuzz/xml.dict -j 4 -t 600
top functions by size:
   +3.286  w= 8.00  xmlSchemaValAtomicType [8 regions]           libxml2/xmlschemastypes.c:2452
   +2.858  w= 8.00  xmlRelaxNGValidateState [5 regions]          libxml2/relaxng.c:9586
   +2.726  w= 8.00  xmlParseStartTag2 [5 regions]                libxml2/parser.c:8786
   ...
[llmfuzz]    596s  execs   5,846,009 (8,653/s)  cov 6469  hot 1334/10539  corpus 16993  crashes 0

[llmfuzz] done in 600s, 5,924,444 execs: 0 unique crash(es); details in llmfuzz-out/summary.json

$ llmfuzz run ./xml seed/xml -x libxml2/fuzz/xml.dict -j 4 -t 600 --prior llm -o out-llm
[llmfuzz] 42149 PCs -> 2732 source regions (40327 PCs mapped)
[llmfuzz] using probe qwen3-4b-jlens.npz (trained on train_m.jsonl)
[llmfuzz] scoring 2732 functions (0 cached)
...
top functions by LLM bug score:
   +4.258  w= 8.00  xmlStrVPrintf                                libxml2/xmlstring.c:548
   +4.029  w= 8.00  xmlStrPrintf                                 libxml2/xmlstring.c:522
   +3.486  w= 8.00  xmlSchemaValAtomicType [8 regions]           libxml2/xmlschemastypes.c:2598
   +3.375  w= 8.00  xmlStreamPushInternal [3 regions]            libxml2/pattern.c:1720
   +3.222  w= 8.00  xmlBufferAdd                                 libxml2/buf.c:994
   ...
[llmfuzz]    596s  execs   6,350,574 (9,230/s)  cov 6444  hot 728/5033  corpus 17086  crashes 0

[llmfuzz] done in 600s, 6,429,997 execs: 0 unique crash(es); details in out-llm/summary.json
```

`[8 regions]` 表示这个函数太长，被切成 8 段分别打分，列表里只显示得分最高的一段。
给 2,732 个区域打分在 M1 Ultra 上用了 18 分钟（M1 的 GPU 没有 bf16，MPS 很慢；较新的 Apple 芯片上约 0.08 秒一个区域）；
分数缓存在 `xml.llmcache.json`，之后重新编译、重新运行都是秒级。两种先验 10 分钟后的覆盖几乎一样（6,469 对 6,444 条边），
各只跑了一次，说明不了哪种更好，见"评估"。

**只盯最近改过的函数**：`examples/changed_functions.py` 从 `git diff` 找出改动过的函数，写成 `--prior` 用的分数文件。

```bash
git -C libxml2 fetch --depth 30 origin tag v2.15.3
python examples/changed_functions.py -C libxml2 v2.15.3 v2.15.4 > changed.json   # 65 个函数
llmfuzz run ./xml seed/xml -x libxml2/fuzz/xml.dict -j 4 --prior changed.json
```

```console
[llmfuzz] 16 name(s) in changed.json match no function: htmlCheckAutoClose, main, parseInteger, testNextCatalogMissingAttr, ...
wrote ./xml.scores.weights (hot threshold 1.00) and ./xml.scores.weights.json

top functions by the scores in changed.json:
  +11.360  w= 8.00  xmlCleanupGlobalsInternal                    libxml2/globals.c:384
  +11.360  w= 8.00  xmlAttrNormalize                             libxml2/parser.c:1022
  +10.974  w= 8.00  xmlGrowArray                                 libxml2/xmlmemory.c:365
  +10.354  w= 8.00  xmlDictAddQString                            libxml2/dict.c:196
  ...
```

没对上的名字是没有链接进这个 harness 的函数（测试程序、HTML 解析器等），会提示出来；分数文件里没列出的函数都按 0 分算。

**xmllint，程序模式**：自带 `main()` 的程序，`--` 后面是它的参数，`@@` 换成输入文件。

```bash
mkdir xml-seeds && cp libxml2/test/*.xml xml-seeds/
llmfuzz run build/xmllint xml-seeds -j 2 -t 600 -- --noout @@
```

程序模式每个输入 fork 一次，速度取决于 fork 的开销：这条命令在 M5 Max（macOS 27）上约 430 exec/s，
在 M1 Ultra（macOS 26.7）上只有约 19 exec/s，因为那台机器上 ASan 进程 fork 一次要 90 ms。同一个库用 harness 模式
（上面的 `xml`）在 M1 Ultra 上每秒约一万次。所以有 harness 的时候优先用 harness。

**按执行时间调整能量的效果**：上面的 libxml2 和 SQLite 最初是在不带 `-time_energy` 的引擎上跑的（也就是 `bench/` 实验用的引擎），
吞吐低得多，因为 fuzzer 把大部分时间花在了少数慢输入上（比如 genSeed 生成的大文档、要跑好几秒的 SQL）。同样的命令、同一台机器：

| 4 个 worker，10 分钟，M1 Ultra | 不按执行时间调整（实验用的引擎） | `-time_energy=1`（`llmfuzz run` 的默认） |
|---|---|---|
| libxml2 `xml`，size 先验 | 55 万次执行，5,894 条边 | 592 万次，6,469 条边 |
| libxml2 `xml`，llm 先验 | 76 万次，5,957 条边 | 643 万次，6,444 条边 |
| SQLite，`--timeout 10` | 16 万次，8,626 条边 | 37 万次，9,483 条边 |

### 4. 分步运行：`analyze` 和 `fuzz`

`run` 等于 `analyze` 加 `fuzz`。需要更多控制时（换权重锐度、做消融、给不同 worker 不同的权重）可以分开跑：

```bash
llmfuzz analyze ./fuzzer        # LLM 打分，生成 fuzzer.weights（每个 PC 的权重）和 fuzzer.weights.json（区域排名）
llmfuzz analyze ./fuzzer --control size -o size.weights            # 只按大小
llmfuzz analyze ./fuzzer --scores scores.json -o mine.weights      # 自己的分数
llmfuzz fuzz ./fuzzer -w fuzzer.weights -j 8 -t 3600 -s seeds/ -x dict.txt
llmfuzz fuzz ./prog -w prog.weights -j 8 -- -opt @@                # 程序模式
llmfuzz fuzz ./fuzzer -w llm.weights -w size.weights -w none -j 6  # worker 轮流使用不同的权重
```

权重文件按 PC 地址对应，**重新编译后要重新 analyze**（有缓存，几乎不用再跑模型）。`analyze` 的常用选项：

| 选项 | 作用 |
|---|---|
| `--k 1.0` | 权重锐度，`w = exp(k·z)` |
| `--hot-frac 0.1` | 视为 "hot" 的区域比例 |
| `--line-weight 0.5` | 额外用逐 token 的 J-lens 读出给区域内的行加权（实验性） |
| `--size-prior 1.0` | 在 LLM 分数上叠加函数规模先验 |
| `--chunk-lines 150` | 长函数切块大小 |
| `--model` / `--lens` / `--probe` | 换模型 |
| `--control shuffle\|uniform\|size\|oracle` | 消融对照。`oracle` 是合成的预测器：把 `--oracle 函数名` 排在 `--oracle-rank Q` 分位，其余函数随机打分；加 `--oracle-flat` 时其余函数权重相同（§3.10） |

`fuzz` 的 `-w` 可以给多次，worker 依次轮流使用（`none` 表示不加权重）；各 worker 共享语料，所以哪种制导看对了，大家都能受益。

harness 二进制也可以直接用 libFuzzer 风格的参数运行：
`./fuzzer -weights=fuzzer.weights -max_total_time=600 corpus/ seeds/`；`./fuzzer crash-file` 复现崩溃。
运行时参数：`-runs -seed -max_total_time -timeout -max_len -len_control -weights -gamma -hot -uniform -time_energy
-vp(0/1/2) -dict -fork -stdin -artifact_prefix -stats -reload -rss_limit_mb -malloc_limit_mb -dump_pcs -cov_dump -close_fd_mask -verbose`。
`-time_energy=1` 按执行时间调整种子能量（比平均慢 10 倍的输入只拿 0.1 倍，快的最多 3 倍，同 AFL），
运行时默认关闭（`bench/` 的实验就是这样跑的），`llmfuzz run` 和 `llmfuzz fuzz` 会打开它。

### 5.（可选）为其它模型训练 probe

```bash
llmfuzz train-probe --model Qwen/Qwen3-8B \
    --lens neuronpedia/jacobian-lens:qwen3-8b/jlens/Salesforce-wikitext/Qwen3-8B_jacobian_lens.pt \
    --train primevul_train_matched.jsonl --eval primevul_test.jsonl -o llmfuzz/probes/qwen3-8b.npz
```

训练数据是 PrimeVul 格式的 JSONL：字段 `func`、`target`（1 表示有漏洞），可选 `file_name`、`project`。
probe 文件里带有 lens 名字，打分时会自动匹配；没有匹配的 probe 时退回零样本的 J-lens yes/no 读出。

## 仓库内容

| 路径 | 内容 |
|---|---|
| `llmfuzz/` | fuzzer 本身：编译器包装器、C 运行时、PC 到函数的映射、J-lens 打分、命令行 |
| `llmfuzz/probes/` | Qwen3-4B 的 J-lens probe（在 PrimeVul 上训练） |
| `examples/demo.c` | 快速上手用的小例子 |
| `examples/changed_functions.py` | 从 `git diff` 生成 `--prior` 分数文件：偏向最近改过的函数 |
| `tests/` | 单元测试和端到端测试 |
| `bench/` | 技术报告里所有实验的脚本（不属于 fuzzer 本身），用法见"复现" |
| `bench/results/` | 每次试验的原始结果 |

## 开发

```bash
pip install -e '.[llm,dev]'
python -m unittest          # 端到端测试需要 clang；没装 torch 时跳过 lens 的测试
mypy                        # 严格模式（pyproject.toml 里 strict = true），检查 llmfuzz/、tests/ 和 examples/
mypy --platform linux       # 在 macOS 上时再按 Linux 检查一遍（反过来用 --platform darwin），两边的代码路径不同
```

CI（`.github/workflows/ci.yml`，Ubuntu 24.04）在每次推送时跑两个平台的 mypy 和全部测试。

lens 的测试用一个随机初始化的小 Qwen3 模型在 CPU 上走完整个 J-lens 读出流程，不需要下载模型。

## 实现

| 文件 | 行数 | 内容 |
|---|---|---|
| `llmfuzz/runtime/llmfuzz_rt.c` | 1183 | fuzz 引擎（C，链接进目标） |
| `llmfuzz/runtime/llmfuzz_main.c` | 6 | harness 用的 `main()` |
| `llmfuzz/lens.py` | 382 | J-lens 读出、probe、训练、行级读出 |
| `llmfuzz/pcmap.py` | 411 | PC 表 → 符号化 → C/C++ 函数边界 → 区域 → 权重文件；静态调用图 |
| `llmfuzz/campaign.py` | 265 | 多 worker 驱动、崩溃去重和离线符号化 |
| `llmfuzz/cli.py`、`build.py` 等 | 399 | 命令行、编译器包装器 |
| **合计** | **2646** | 另有 `bench/`（评估脚本 1763 行和原始结果）、`tests/` 和 `examples/`（共 455 行） |

**运行时（`llmfuzz_rt.c`）**

- **覆盖率与特征**：`trace-pc-guard` 计数器放在 `MAP_SHARED` 内存里，进程内执行和 fork 执行共用一条路径。
  特征为"边 × 命中次数桶"（AFL 的分桶）。
- **比较反馈**：`trace-cmp` 和 sanitizer 的 `memcmp`/`strcmp` 弱钩子写入"最近比较表"（TORC），
  用于操作数替换变异和持久化自动字典。
- **变异器**：16 种 havoc 变异（位/字节/整数/算术、块删插拷、交叉、字典词、ASCII 整数、比较操作数替换等）。
- **长度控制**：类似 libFuzzer 的 `len_control`，从短输入开始，长期没有新覆盖才放宽长度上限。
  这一项让 pcre2 上的执行速度提高了约 4 倍、30 秒覆盖率提高 2.3 倍。
- **其它**：崩溃 / 超时 / OOM / malloc 上限检测，worker 之间通过语料目录同步；
  harness 定义了 `LLVMFuzzerCustomMutator` 时用它代替内置变异器，并提供 `LLVMFuzzerMutate`；
  从磁盘重放时让进程死掉的文件记进 `ARTIFACT_PREFIX.llmfuzz-skip`，重启后跳过；
  `-time_energy=1` 时种子能量再乘以 AFL 的速度系数（0.1–3 倍，按该输入的执行时间相对语料平均值），
  均匀选择的那 10% 也按这个系数拒绝采样。
- **执行模式**：
  - **harness 模式**：进程内执行，或 `-fork=1`（每个输入一个子进程）。
  - **程序模式**：构造函数里起 fork server，每个输入跑一次真实的 `main()`。
    Linux 上约 770 exec/s。macOS 上 ASan 进程 fork 一次的开销因机器差别很大：
    M5 Max（macOS 27.0）上约 3 ms（每个 worker 200–250 exec/s），M1 Ultra（macOS 26.7）上约 90 ms（每个 worker 约 10 exec/s），
    而不带 ASan 的进程两台都不到 1 ms。fork 慢的机器上请用 harness 模式。
- **链接方式**：运行时以目标文件形式链接（必须压过 Linux 上先链接的 ASan 运行时里的弱 sancov 桩），
  `main()` 放在归档里，只有目标没有 `main` 时才会被拉进来。

**LLM 侧**

1. **PC 表**：`-dump_pcs` 导出去掉 ASLR 偏移后的 PC 表。
2. **符号化**：`pcmap.py` 用 llvm-symbolizer / atos / addr2line 符号化。对内联帧，取**最内层的项目代码帧**，
   这样内联进来的 STL 模板代码算到调用它的项目函数上，系统头文件里的代码不加权。
3. **区域划分**：用一个小的括号匹配解析器找出 C/C++ 函数边界，每个 PC 归属到包含它那一行的函数；
   超过约 150 行的函数切成多段分别打分。
4. **打分**：`lens.py` 在区域代码后面接一个审查问题，在最后位置读第 24..35 层的 J-lens。
   probe 是在 3000 个 PrimeVul 函数上训练的 logistic 回归：漏洞函数和同项目、同长度（±15%）的非漏洞函数配对，
   刻意去掉"函数越长越像有 bug"这个捷径。
5. **权重**：分数在程序内 z-score 化，映射成 `w = clip(exp(k·z), 0.5, 8)`。

**fuzz 循环里的两个机制**（不给权重时两者都消失，所以基线就是同一个引擎）：

- **能量**：每个种子"拥有"它第一个发现的 feature，选择权重为 `Σ w(edge)^γ / sqrt(1 + hits/256)`。
  可疑函数前沿的种子被变异得更多，并且保持吸引力的时间长约 w² 倍。
- **hot 区的 value profile**：只在 LLM 标为 hot 的代码里，把比较操作数的汉明距离也当覆盖率。
  于是 fuzzer 会保留"更接近满足可疑代码里某个分支"的输入；其它代码里不开，避免语料膨胀。

## 评估

先回答两个问题：LLM 的隐藏状态能不能认出有 bug 的代码（§1、§2）；用它制导 fuzzing 能不能更快找到 bug（§3）。
每次试验的原始结果在 `bench/results/`，脚本见"复现"一节。

### 1. LLM 能否认出有 bug 的代码？（PrimeVul）

数据来自 PrimeVul 的 C/C++ 函数。正样本是漏洞修复提交改动过的函数（修复前版本），负样本是其它函数。

- **训练集**：3000 个函数，来自 314 个项目。1500 个漏洞函数，各配一个同项目、行数相差 ±15% 以内的非漏洞函数。
- **调参**：按项目分组做 5 折交叉验证选正则（CV AUC 0.673）。
- **测试集**：取自 PrimeVul 的测试划分。

| 评测集 | 规模 | J-lens probe | 零样本 J-lens（yes/no） | 只看长度 |
|---|---|---|---|---|
| 函数级·长度配对 | 600 个（300 对，103 个项目） | **0.569** | 0.548 | ≈0.5（按构造） |
| 函数级·自然分布 | 1000 个（15% 有漏洞） | 0.615 | 0.685 | **0.790** |
| 行级：在漏洞函数里找出被修复的行 | 368 个函数，平均 74 行 | **0.671**（零样本概念读出） | – | 0.632（行长度） |

数值是 ROC AUC，随机为 0.5；行级是每个函数内部的 AUC 再取平均。

- **有信号，但很弱**：在配对集上 0.57 > 0.5，行级 0.671 > 0.632，说明隐藏状态里确实有超出"代码长度"的 bug 信号。
- **自然分布上长度更强**：长函数本来就更容易有漏洞，这个简单先验（0.79）远强于 probe；
  probe 和长度合用也不比只用长度好（0.784 vs 0.790）。
- **零样本读出在自然分布上偏高**：零样本 yes/no 在自然分布上的 0.685 高于 probe，主要是因为它和长度相关；在配对集上它只有 0.548。

### 2. 已知 bug 在排名中的位置（FTS）

下表是 Google fuzzer-test-suite（FTS）7 个目标中已知 bug 所在函数的排名百分位：越小越靠前，长函数取它排得最靠前的那一段。

| 目标 | bug 所在函数 | 区域数 | llm | size | llmsize | shuf |
|---|---|---|---|---|---|---|
| libcxxabi | `parse_floating_number` | 79 | **2.5%** | 45.6% | 7.6% | 62.0% |
| libcxxabi | `parse_function_type` | 79 | 98.7% | 24.1% | 73.4% | 19.0% |
| libcxxabi | `parse_unnamed_type_name` | 79 | 45.6% | 21.5% | 24.1% | 92.4% |
| pcre2 | `match` | 221 | 3.2% | 0.5% | 1.4% | 3.2% |
| lcms | `TetrahedralInterpFloat` | 897 | 23.9% | 3.3% | 4.2% | 28.9% |
| woff2 | `ReconstructGlyf` | 448 | 6.9% | 3.1% | 1.3% | 12.9% |
| woff2 | `Buffer::Read` | 448 | 11.2% | 50.7% | 17.2% | 93.1% |
| re2 | `NFA::Search` | 436 | 8.9% | 1.6% | 1.1% | 29.8% |
| libxml2 | `xmlParseXMLDecl` | 2926 | 71.2% | 14.6% | 35.4% | 73.7% |
| libxml2 | `xmlDictComputeFastQKey` | 2926 | 63.6% | 29.8% | 45.4% | 45.0% |
| libxml2 | `xmlDictComputeFastKey` | 2926 | 45.5% | 50.5% | 47.6% | 81.5% |
| libxml2 | `xmlCurrentChar` | 2926 | 40.1% | 10.8% | 15.7% | 76.6% |
| openssl | `tls1_process_heartbeat` | 4355 | 27.0% | 10.9% | 13.8% | 56.2% |
| **中位数** | | | 27.0% | **14.6%** | 15.7% | 56.2% |
| 进入前 10% | | | 4/13 | 4/13 | **5/13** | 1/13 |

- **LLM 有时排得很准**：把 13 个中的 4 个排进前 10%，例如 libcxxabi 的 `parse_floating_number`（2.5%，规模先验只排在 45.6%）。
- **有时完全看错**：libcxxabi 的 `parse_function_type` 排在倒数（98.7%），libxml2 的 4 个 bug 函数都在中后段。
- **规模先验更稳**：只看函数规模（`size`）的中位数是 14.6%，好于 LLM 的 27.0%。
- **排名不是巧合**：把 LLM 分数随机打乱（`shuf`）后中位数是 56%，接近随机。
- **pcre2 的特例**：`match` 是 5687 行的大函数，被切成 38 段，随机打乱也很容易有一段排得靠前（`shuf` 同样是 3.2%）。

### 3. Fuzzing 实验

**设置**：FTS 的 7 个目标，即 libcxxabi、pcre2、lcms、woff2、openssl-1.0.1f（Heartbleed）、re2、libxml2，全部用 ASan、`-O1` 编译。
引擎和二进制都一样，只换权重文件：

| 配置 | 含义 |
|---|---|
| `plain` | 不给权重，即普通的覆盖率 fuzzing（基线） |
| `llm` | `llmfuzz analyze` 默认参数（k=1） |
| `shuf` | 把 LLM 分数在区域间随机打乱（固定一个排列）：权重分布和 hot 区域的个数完全相同，只是不含 LLM 的判断 |
| `shufN` | 同上，但每次试验换一个随机排列 |
| `size` | 只用函数规模先验，不用 LLM（`--control size`） |
| `llmsize` | LLM 加规模先验，等权（`--size-prior 1`） |
| `size3` | 以规模为主、LLM 为辅（`--size-prior 3`） |
| `mild` | LLM，权重减半（k=0.5） |
| `lines` | LLM，加行级权重（`--line-weight 0.5`） |
| `libFuzzer` | clang 自带的 libFuzzer，同一 harness、同样的种子和字典（参考） |

- **一次试验**：单进程，记录到第一次崩溃的时间（TTE）；超时、OOM 也算发现，没找到就记为预算时间。
- **统计**：p 值为双侧 Mann-Whitney U。
- **表格格式**：每格是"找到次数/试验次数, TTE 中位数（秒）"。

#### 3.1 Linux x86-64（主实验，900 秒）

`plain`/`llm`/`shuf` 各 10 次，`size`/`llmsize` 各 6 次。

| 目标 | plain | llm | shuf | size | llmsize | p llm vs plain | p llm vs shuf | p size vs plain |
|---|---|---|---|---|---|---|---|---|
| lcms | 7/10, 486 | 5/10, 878 | 0/10, >900 | 4/6, 478 | 3/6, 685 | 0.093 | 0.013 | 0.912 |
| libcxxabi | 5/10, 837 | 8/10, 436 | 5/10, 740 | 6/6, 82 | 5/6, 424 | 0.315 | 0.396 | 0.036 |
| openssl | 10/10, 6.5 | 10/10, 4.6 | 10/10, 5.5 | 6/6, 3.1 | 6/6, 8.3 | 0.705 | 0.705 | 0.233 |
| pcre2 | 10/10, 3.5 | 10/10, 4.7 | 10/10, 12 | 6/6, 0.8 | 6/6, 5.3 | 0.821 | 0.034 | 0.039 |
| woff2 | 9/10, 342 | 9/10, 372 | 9/10, 323 | 5/6, 171 | 5/6, 468 | 0.970 | 0.850 | 0.254 |

- **LLM 制导在 Linux 上没有显著胜利**：libcxxabi 方向有利（8/10 vs 5/10），lcms 方向不利（878 s vs 486 s，p=0.09），其余持平。
- **浅 bug 没有制导的空间**：openssl（Heartbleed）和 pcre2 几秒内就被找到。
- **规模先验最强**：`size` 在 libcxxabi（82 s vs 837 s，p=0.036）和 pcre2（0.8 s vs 3.5 s，p=0.039）上显著快于 `plain`，其余也不慢。
- **在 Linux 上，LLM 会稀释规模信号**：`llmsize` 不比 `llm` 好，明显不如 `size`。macOS 上正相反，见 §3.2。
- **错误的权重可以很有害**：`shuf` 在 lcms 上 0/10。这个随机排列把能量引到了慢输入上，执行速度只有 `plain` 的约 1/10（329 vs 3168 exec/s）。

**以规模为主、LLM 为辅（`size3`，6 次）**：

| 目标 | plain | llm | size | size3 | p size3 vs plain | p size3 vs size |
|---|---|---|---|---|---|---|
| lcms | 7/10, 486 | 5/10, 878 | 4/6, 478 | 3/6, 828 | 0.133 | 0.245 |
| libcxxabi | 5/10, 837 | 8/10, 436 | 6/6, 82 | 4/6, 796 | 0.734 | 0.004 |
| openssl | 10/10, 6.5 | 10/10, 4.6 | 6/6, 3.1 | 6/6, 5.4 | 1.000 | 0.261 |
| pcre2 | 10/10, 3.5 | 10/10, 4.7 | 6/6, 0.8 | 6/6, 3.4 | 0.588 | 0.150 |
| woff2 | 9/10, 342 | 9/10, 372 | 5/6, 171 | 5/6, 438 | 0.551 | 0.173 |

- **加入少量 LLM 分数，规模先验的优势就消失了**：LLM 在合成分数里只占 1/4（`--size-prior 3`），
  libcxxabi 就从 `size` 的 82 s 退回到 796 s（p=0.004），其余目标也回到 `plain` 的水平。
- **结果对排序非常敏感**：哪几个区域拿到高权重，会让同一个目标上的 TTE 相差 10 倍。

#### 3.2 macOS arm64（8 次 × 900 秒）

| 目标 | plain | llm | shuf | shufN | size | llmsize | p llm vs plain | p llm vs shufN | p size vs plain | p llmsize vs plain |
|---|---|---|---|---|---|---|---|---|---|---|
| lcms | 5/8, 828 | 7/8, 351 | 3/8, >900 | 6/8, 511 | 6/8, 402 | 7/8, 289 | 0.023 | 0.399 | 0.110 | 0.017 |
| libcxxabi | 8/8, 4.7 | 8/8, 0.6 | 8/8, 5.6 | 8/8, 2.7 | 8/8, 13 | 8/8, 0.5 | 0.001 | 0.036 | 0.345 | 0.002 |
| woff2 | 6/8, 424 | 8/8, 221 | 8/8, 54 | 7/8, 330 | 7/8, 206 | 7/8, 208 | 0.344 | 0.916 | 0.206 | 0.206 |

- **LLM 最清楚的一次胜利是 libcxxabi**：0.6 s vs 4.7 s（p=0.001），而且显著快于每次换一个随机排列的 `shufN`（2.7 s，p=0.036）。
  崩溃点在 `parse_floating_number<long double>`，LLM 把它排在 79 个区域的第 2 位，规模先验只排在 45.6%。
  这个栈溢出只在 Apple arm64 上存在：那里 `long double` 只有 8 字节，而 libcxxabi 按 AArch64 的 16 字节解析。
  所以 Linux 上 libcxxabi 找到的是另一类问题（OOM）。
- **lcms 的方向随平台翻转**：macOS 上 LLM 更快（351 s vs 828 s，p=0.023），Linux 上反而更慢，说明这不是稳健的效果。
- **随机权重也略有加速，但不显著**：每次换排列时（`shufN`），三个目标都比 `plain` 快一些（p 0.2–0.34）。
  固定排列的 `shuf` 只是一次抽样，好坏都可能很极端（woff2 上 54 s，lcms 上 3/8）。
- **规模先验在 macOS 上不稳**：`size` 在 libcxxabi 上反而变慢（13 s vs 4.7 s），因为崩溃函数不大（规模排名 45.6%）。
- **LLM 加规模在 macOS 上最好**：`llmsize` 在三个目标上都是最快或并列最快（lcms 289 s，p=0.017；libcxxabi 0.5 s，p=0.002）。

#### 3.3 行级加权（macOS）

| 目标 | plain | llm | lines | p lines vs llm |
|---|---|---|---|---|
| lcms | 5/8, 828 | 7/8, 351 | 3/8, >900 | 0.027 |
| libcxxabi | 8/8, 4.7 | 8/8, 0.6 | 8/8, 0.6 | 0.674 |
| woff2 | 6/8, 424 | 8/8, 221 | 6/8, 694 | 0.059 |

行级的零样本信号（§1 中 AUC 0.671）没有转化成 fuzzing 收益：在 lcms、woff2 上比只用函数级权重更差，所以默认关闭。

#### 3.4 难目标长跑：libxml2 和 re2（Linux，5 次 × 1800 秒）

| 目标 | plain | llm | shuf | size | libFuzzer | p llm vs plain | p size vs plain | p plain vs libFuzzer |
|---|---|---|---|---|---|---|---|---|
| libxml2 | 0/5, >1800 | 2/5, >1800 | 3/5, 979 | 3/5, 1799 | 2/5, >1800 | 0.136 | 0.054 | 0.136 |
| re2 | 1/5, >1800 | 0/5, >1800 | 0/5, >1800 | 2/5, >1800 | 0/5, >1800 | 0.317 | 0.700 | 0.317 |

- **libxml2**：所有加权配置（`llm` 2/5、`shuf` 3/5、`size` 3/5）都比 `plain`（0/5）好，彼此差不多。
  起作用的可能是"有权重"本身（hot 区的 value profile），而不是 LLM 的判断。
- **re2**：1800 秒内谁都没找到已知 bug，只有超时。
- **最终覆盖没有变化**：LLM 标记为 hot 的代码最终被覆盖的比例在各配置间没有区别（libxml2 都是 6.4%，re2 约 40%）。
  制导改变的是探索顺序，而不是能到达的范围；libxml2 的 hot 代码大多根本无法从这个 harness 到达。

#### 3.5 第二台 Linux 机器上的复现，以及 k=0.5（8 次 × 900 秒）

在第二台 x86-64 Linux 机器上重跑 `plain` / `llm`，并加上权重减半的 `mild`（k=0.5），原始数据在 `bench/results/linux_mild_2nd_machine.jsonl`：

| 目标 | plain | llm | mild | p llm vs plain | p mild vs plain | p mild vs llm |
|---|---|---|---|---|---|---|
| lcms | 5/8, 768 | 1/8, >900 | 3/8, >900 | 0.061 | 0.537 | 0.241 |
| libcxxabi | 5/8, 577 | 6/8, 579 | 5/8, 653 | 0.670 | 0.872 | 0.749 |
| openssl | 8/8, 4.2 | 8/8, 6.1 | 8/8, 6.0 | 0.834 | 0.462 | 0.916 |
| pcre2 | 8/8, 5.6 | 8/8, 6.3 | 8/8, 13 | 0.600 | 0.345 | 0.401 |
| woff2 | 8/8, 109 | 5/8, 562 | 6/8, 354 | 0.015 | 0.115 | 0.241 |

- **复现了 Linux 上的负面结果**：LLM 制导在 woff2 上显著更慢（562 s vs 109 s，p=0.015），lcms 上 1/8 vs 5/8（p=0.061），
  方向和 §3.1 一致。5 个目标的 TTE 中位数几何平均是 `plain` 的 1.58×，没有一个目标更快。
- **k=0.5 没有找到更好的折中**：`mild` 的结果大致落在 `plain` 和 `llm` 之间（几何平均 1.71×）。

#### 3.6 与 libFuzzer 对比

| 目标 | libFuzzer | plain | llm | size | p plain vs libFuzzer | p size vs libFuzzer |
|---|---|---|---|---|---|---|
| lcms | 0/6, >900 | 7/10, 486 | 5/10, 878 | 4/6, 478 | 0.012 | 0.022 |
| libcxxabi | 6/6, 74 | 5/10, 837 | 8/10, 436 | 6/6, 82 | 0.021 | 0.631 |
| openssl | 6/6, 4.0 | 10/10, 6.5 | 10/10, 4.6 | 6/6, 3.1 | 0.193 | 0.873 |
| pcre2 | 6/6, 21 | 10/10, 3.5 | 10/10, 4.7 | 6/6, 0.8 | 0.039 | 0.006 |
| woff2 | 6/6, 256 | 9/10, 342 | 9/10, 372 | 5/6, 171 | 0.386 | 0.423 |

- **不加权重时与 libFuzzer 互有胜负**：
  - lcms（7/10 vs 0/6，p=0.012）和 pcre2（3.5 s vs 21 s，p=0.039）上 llmfuzz 更快。
  - libcxxabi 上更慢（837 s vs 74 s，p=0.021）：libFuzzer 找到的是深递归导致的栈溢出，llmfuzz 找到的多是 OOM。
    这些 OOM 是真问题：一个 370 字节的输入能让 demangler 占用 6.9 GB 内存。
  - openssl、woff2 上没有显著差别。
- **长跑**：1800 秒的 libxml2/re2 上，libFuzzer 分别是 2/5 和 0/5（见 §3.4）。
- **计时口径略有不同**：libFuzzer 的 TTE 是进程墙钟时间，llmfuzz 是运行时内部计时，相差约 1 秒的启动时间。

#### 3.7 早期 macOS 实验（引擎 v1，没有长度控制）

| 目标 | plain | llm | shuf | size | llmsize | p llm vs plain | p llm vs shuf |
|---|---|---|---|---|---|---|---|
| lcms | 5/8, 681 | 7/8, 435 | 0/8, >900 | 2/8, >900 | 5/8, 769 | 0.153 | 0.001 |
| libcxxabi | 8/8, 10 | 8/8, 2.3 | 8/8, 76 | 8/8, 23 | 8/8, 2.2 | 0.059 | 0.002 |
| openssl | 6/6, 5.5 | 6/6, 12 | 6/6, 9.5 | 6/6, 11 | 6/6, 6.7 | 0.010 | 0.749 |
| pcre2 | 6/8, 462 | 6/8, 297 | 7/8, 303 | 5/8, 130 | 6/8, 360 | 1.000 | 1.000 |
| woff2 | 4/6, 367 | 4/6, 416 | 5/6, 50 | 6/6, 235 | 5/6, 126 | 1.000 | 0.147 |
| libxml2 | 0/6, >900 | 1/6, >900 | 0/6, >900 | 3/6, 670 | 1/6, >900 | 0.317 | 0.317 |
| re2 | 0/6, >900 | 0/6, >900 | 0/6, >900 | 0/6, >900 | 0/6, >900 | – | – |

v1 引擎没有长度控制，输入膨胀到数 KB，所以 pcre2 等目标比最终版慢得多。结论与最终版一致：

- libcxxabi 上 LLM 显著好于随机权重。
- openssl 上 LLM 反而更慢（12 s vs 5.5 s，p=0.01）。

#### 3.8 混合权重的 campaign（Linux，3 个 worker，6 次 × 900 秒）

既然不同的权重在不同目标上各有胜负，自然的想法是在一个 campaign 里混用：3 个 worker 共享语料，
分别使用 `llm`、`size` 和不加权重（`-w w_llm.weights -w w_size.weights -w none`），对照组是 3 个都不加权重的 worker。

| 目标 | plain | mix | p mix vs plain |
|---|---|---|---|
| lcms | 5/6, 380 | 6/6, 252 | 0.522 |
| libcxxabi | 6/6, 11 | 6/6, 149 | 0.261 |
| woff2 | 6/6, 182 | 6/6, 106 | 0.631 |

- **混合在 lcms、woff2 上更快，在 libcxxabi 上更慢，差别都不显著**。
- **libcxxabi 的中位数有误导性**：3 个不加权重的 worker 常常在 5–11 秒内就碰到那个 OOM，但两组的平均值接近（159 s vs 187 s）。
- 这个小实验既不能说明混合更好，也不能说明它更差。

#### 3.9 调用上下文能不能帮 LLM 认出 bug？（离线排名，13 个 bug 函数）

只看孤立的函数，很多 bug 本来就判断不了，所以试了在函数前面加上下文。设置：

- **数据**：§2 的 13 个 bug 函数，每个目标再随机抽 80 个其它区域。
- **上下文**：放在区域代码前面，最多 3K token（8B 另跑了 8K）：
  - **被调用者**：它调用的每个函数的前 40 行。
  - **调用者**：调用它的函数里，调用点前后各 10 行。
  - **调用栈**：从 `LLVMFuzzerTestOneInput` 到它的一条调用路径，每层取调用点附近的代码。
  - **文件前文**：同一个文件里它前面的代码。
- **调用图**：来自 clang AST（用 `LLMFUZZ_CDB` 记录的编译命令），AST 漏掉的调用（模板、宏生成的名字）用按名字匹配补上。
- **读出**：零样本 J-lens yes/no，取最后四分之一层的平均。
- **对照**：上下文会整体拉低模型的 yes/no 读数（同长度随机代码拉低 1.5–2.8，见下），所以有上下文和没上下文的区域不能放在一起排。
  每种上下文只在"拿到了这种上下文"的区域里排名，bug 函数和其它区域都一样；没提取到的 bug 函数从这一行里去掉。

表中是 bug 函数排名百分位的中位数，以及进入前 10% 的个数 / 参与的 bug 函数数（越小、越多越好）。
"只看函数规模"是 14.2%、5/13。

| 模型 | 孤立 | 被调用者 | 调用栈 + 被调用者 | 文件前文 |
|---|---|---|---|---|
| Qwen3-4B | 16.7%，2/13 | 28.7%，3/10 | 33.6%，2/13 | 18.0%，3/13 |
| Qwen3-8B（4-bit） | 43.8%，2/13 | 44.8%，2/10 | 17.6%，4/13 | 16.7%，5/13 |
| Qwen3-14B（4-bit） | 54.9%，2/13 | 58.7%，1/10 | 26.9%，5/13 | 18.8%，6/13 |
| Qwen3.6-27B（4-bit） | 30.5%，4/13 | 28.9%，3/10 | 25.0%，3/13 | **9.3%，7/13** |

（早先的分析只对其它区域做了这个限制，没提取到上下文的 bug 函数仍用孤立的分数，排名被抬高；
例如 4B 的"被调用者"曾算成 14.6%，修正后是 28.7%。）

- **孤立打分不如规模先验，模型变大也不变好**：4B 的 16.7% 主要来自它的分数和函数长度相关，扣掉规模后只剩约 27%。
- **调用者上下文没有帮助**：4B 上变差（43.5%，3 胜 10 负，p=0.09），8B 上持平，所以大模型没有再测。
- **文件前文在大模型上中位数改善明显**：8B、14B、27B 都好于孤立打分。
  27B + 文件前文是所有方案里最好的，平均百分位 12.4%（规模先验是 19.3%），扣掉规模后仍有 18%（孤立时扣掉规模约 51%，即随机）。
  但第二轮的固定窗口没能重现它（见下）。
- **还不能下结论**：
  - 只有 13 个 bug，又从几十种组合里挑最好的。和规模先验逐个比，27B + 文件前文是 7 个更靠前、6 个更靠后，不显著。
  - 在同一批 bug 函数和区域上逐个和孤立打分比，没有一个上下文显著更好（最好的是 8B 的调用栈 9 胜 2 负，p=0.07；
    14B、27B 的文件前文都是 9 胜 3 负，p=0.15）。
  - FTS 的 bug 都是 2014–2017 年的老 bug，大模型可能见过。Heartbleed 在 27B 上有没有上下文都排第 1，
    更多上下文也可能只是帮模型"认出"这段代码。要验证需要模型训练截止之后的新 bug。
- 所以 `analyze` 暂时仍只给函数本身打分。全部组合（另含"规模 + LLM"等读出）见 `bench/results/ctx_rankings.txt`。

**第二轮：用 clang AST / 数据依赖挑上下文**（`bench/ctx_ast.py`，每部分最多 1.5K token）

- **定义**：函数里引用到的宏、类型、结构体、全局变量的定义。
- **调用者实参切片**：每个调用者里，调用点之前计算或检查实参的语句（按变量名追两层，近似数据依赖）。
- **被调用者签名**：调用到的项目函数的签名和上方注释。
- **固定窗口**：同文件里函数前后的代码，长度固定，排除"位置不同长度就不同"的问题。
- **随机代码（对照）**：和"定义"一样长的同文件随机片段。

下表在完全相同的 bug 函数和区域上，把每种上下文和孤立打分逐个比较（中位数百分位，以及"更靠前-更靠后"的 bug 函数数）：

| 模型 | 定义（11 个） | 调用者实参切片（10 个） | 被调用者签名（7 个） | 固定窗口（13 个） | 随机代码（11 个） |
|---|---|---|---|---|---|
| Qwen3-4B | 19.0 vs 17.4，5-6 | 31.0 vs 36.2，6-4 | 35.9 vs 33.7，2-5 | 21.2 vs 16.4，6-7 | 22.9 vs 17.4，6-4 |
| Qwen3-8B | 29.9 vs 32.6，5-5 | 48.6 vs 50.3，6-4 | 48.9 vs 46.6，3-3 | 19.1 vs 42.6，8-5 | 24.3 vs 32.6，7-4 |
| Qwen3-14B | 61.8 vs 65.5，7-3 | 42.9 vs 70.4，6-3 | 64.3 vs 68.6，4-2 | 16.0 vs 64.6，9-3 | **32.1 vs 65.5，9-0** |
| Qwen3.6-27B | 6.2 vs 27.1，5-4 | 45.3 vs 34.9，5-4 | 16.1 vs 31.8，3-4 | 30.2 vs 33.6，5-7 | 14.2 vs 27.1，6-3 |

- **结构化的上下文不比随机代码好**：唯一显著的改进出现在 14B 上，而且是随机代码（9 胜 0 负，p=0.004）和"定义 + 实参切片"（10 胜 2 负，p=0.04）。
  14B 孤立打分本来就比随机还差（65%），加什么代码都有帮助，内容是否相关不重要。
- **27B 的中位数差距看起来大，但逐个比较是持平的**（定义 5 胜 4 负）：13 个以内的样本里，中位数很容易被少数几个 bug 左右。
- **固定窗口在 27B 上没有重现"文件前文"的 9.3%**（30.2%），所以第一轮里那个结果很可能来自长度随位置变化的伪影，或者噪声。
- 原始数据：`bench/results/ctx_rankings_ast.txt`。复现：`python bench/ctx_ast.py ctx.json ctx_ast.json --cdb-dir cdb/`，
  再用 `--variants iso,defs,args,defs+args,calleesig,window,rand --budget 1536` 跑 `bench/ctx_score.py`。

#### 3.10 如果排名完全正确，fuzzing 能快多少？（oracle，Linux，8 次 × 900 秒）

用 `--control oracle` 构造一个"知道答案"的预测器，把真实崩溃所在的函数（lcms 的 `TetrahedralInterpFloat`，
woff2 的 `Buffer::Read` 和 `ReconstructGlyf`）放在指定的排名分位，其余函数的分数随机，每次试验重新抽；
"干净 oracle"只抬高 bug 函数，其余函数权重相同。

| 目标 | plain | 干净 oracle | 排第 1，其余随机 | 前 5% | 前 25% |
|---|---|---|---|---|---|
| lcms | 5/8, 585 | 4/8, 793 | 3/8, >900 | 3/8, >900 | 3/8, >900 |
| woff2 | 8/8, 275 | 8/8, 143 | 7/8, 257 | 7/8, 262 | 5/8, 736 |

- **完全正确的定位最多带来约 2 倍**：woff2 的干净 oracle 快了约 1.9 倍（p=0.17，8 次里有 1 次找到的是 OOM 而不是这个 bug）。
  lcms 没有收益：bug 函数在插值的内层循环里，标成 hot 后开了比较追踪，执行速度降了 26%。
- **排名其余部分的噪声就能把收益抵消**：woff2 从 143 s 退回 257 s；bug 函数只排到前 25% 时显著变慢（736 s，p=0.03）。
- **这两个 bug 的瓶颈主要不在"走到出错的函数"，而在"造出触发条件"**：普通 fuzzing 很快就覆盖到这两个函数。
  所以预测器再准，通过加权能拿到的收益也有限。这和 AIJon、LibAFLGo 用真实 bug 位置得到的结论一致。
- 只有 2 个目标、8 次、900 秒，是初步结果。

#### 3.11 先推理再判断：在线推理能不能补上离线读出？（13 个 bug 函数）

让 LLM agent 写测试时，模型常常在写测试之前就说出了 bug 在哪；而上面的读出只看一次前向。
差别可能在于"在线"：模型先推理、再下结论。这里在 §3.9 的同一批区域上比较三种做法（`bench/ctx_think.py`）：

- **直接回答**：聊天格式，问"这个函数有没有 bug（越界读写、释放后使用、整数溢出、逻辑错误）？只答 Yes 或 No"，
  思考块为空，在回答的第一个 token 处读 J-lens。
- **先思考**：模型先推理（采样，temperature 0.6），在同样的位置读出。
  - 推理上限 512 token 时几乎全被截断（14B 只有 9% 想完，27B 是 0%）。
  - 所以又用 vLLM 生成了完整推理（`bench/ctx_think_vllm.py`，4-bit AWQ 权重，上限 8192 token），再用原模型读出。
    14B 的 576 个区域有 572 个想完，推理长度中位约 1700 token。
  - 27B 想得长得多（中位约 4000 token，20% 到上限），4090 上只跑了子样本：20 个 bug 区域，加上每个目标 40 个其它区域。
- **先写契约**：另起一个提示，让模型为函数写一段契约注释（作用、参数前提、缓冲区和下标的不变式，并要求"不要判断代码对不对"），
  放在代码上方，再直接回答。
  **对照**：把同一目标里其它函数的契约换过来，长度和格式相同，只是内容对不上。

表中是 bug 函数排名百分位的中位数（零样本 yes/no 读出），括号里是在同一批区域上和"直接回答"逐个比较的"更靠前-更靠后"。
规模先验在全集上是 14.2%，在子样本上是 15.9%。

| 模型 | 直接回答 | 先思考（≤512 token） | 先思考（完整） | 先写契约 | 换成别的函数的契约 |
|---|---|---|---|---|---|
| Qwen3-14B（4-bit） | 17.9% | 27.8%（7-6） | 15.4%（7-6） | 17.9%（7-5） | – |
| Qwen3.6-27B（4-bit） | 35.2% | 24.1%（5-8） | 18.3%（4-8，子样本，直接回答 32.9%） | **20.1%（10-1，p=0.01）** | 50.0%（自己的比换来的 11-0，p=0.001） |

- **27B 先写契约有效，而且靠的是内容**：
  - 自己写的契约把中位排名从 35.2% 提到 20.1%；换成别的函数的契约反而更差（50.0%），所以不是"多了一段注释"的格式效应。
  - 契约里常常直接写出了被违反的条件。Heartbleed 的契约写着 "payload must be <= s->s3->rrec.length - 3"，
    woff2 `Buffer::Read` 的契约写着"调用者必须保证 buffer 至少有 n_bytes 可写空间"。
  - 14B 写契约没有效果。
- **完整推理让 14B 的读数有了超出规模的信号，但 27B 没有**：
  - 14B 直接回答的读数扣掉规模后是 66%，比随机还差，几乎只反映函数长度；完整推理后是 33%（12-1，p=0.003）。
  - 27B 完整推理后，中位数看起来从 32.9% 提到 18.3%，但逐个比是 4 个更靠前、8 个更靠后；扣掉规模后从 38% 变成 55%。
  - 两个模型推理后都更有区分度，但区分不大。14B 直接回答时对 100% 的 bug 区域、86% 的其它区域都说有 bug，推理后是 80% 对 50%；
    27B 从 25% 对 15% 变成 75% 对 55%。
- **推理说中真实原因的不多，而且有记忆的痕迹**：
  - 14B 对 Heartbleed（payload 长度没有和实际收到的长度比较）和 `xmlDictComputeFastQKey`（`len - (plen + 2)` 可能是负下标）
    说出了真实原因，对其它多数 bug 给的理由是错的（例如把 `NFA::Search` 说成死循环）。
  - 27B 的推理里直接出现了"This is exactly Heartbleed"、"I found a reference to a bug in LittleCMS"、
    "these prompts come from a dataset of known bugs"，它是在认出代码，而不是在推导。
- **截断的推理没有用**：512 token 的推理在两个模型上都没有改善排名。
- **没有一种做法胜过规模先验**：和"只看函数规模"逐个比，27B 先写契约是 8-5，14B 完整推理是 5-8，27B 完整推理是 5-8，都不显著；
  27B 先写契约扣掉规模后也不显著（8-4，p=0.39）。
- **局限**：
  - 只有 13 个 bug，都是 2014–2017 年的老 bug，记忆的影响无法排除（Heartbleed 在所有条件下都排第 1）。
  - 每个函数只采样一次推理；推理由 AWQ 权重生成，读出用 nf4 权重；27B 的完整推理只跑了子样本，且 9 个 bug 区域推理到上限被截断。
- 原始数据：`bench/results/ctx_think.txt`（各读出的完整排名表），`bench/results/think/`（推理文本和契约，gzip）。

#### 3.12 修复前后配对：模型分得清同一个函数有 bug 和没 bug 的版本吗？

§3.11 里推理有时能准确说出 bug，但 13 个老 bug 分不清"知道"和"记得"。这里改用配对测试：
同一个函数修复前、修复后各问一次，真知道的话，应该对修复前说有 bug、对修复后说没有。

- **数据**（`bench/pair_mine.py`，清单见 `bench/results/pairs_index.jsonl`）：
  - **新 bug，148 对**：30 个活跃 C/C++ 项目（OpenSSL、curl、qemu、FFmpeg、sqlite、php-src、radare2、libheif、wireshark 等）
    在 2026-05-02 到 2026-10-08 之间的修复提交。Qwen3.6-27B 发布于 2026-04-21，不可能见过这些修复。
    条件：提交信息是内存安全类修复，只改一个函数，改动不超过 20 行；人工看过提交信息，去掉了 8 个不是修 bug 的。
  - **老 bug，100 对**：PrimeVul 的配对测试集（每个项目最多 6 对），可能在训练数据里。
  - **知名 bug，2 对**：Heartbleed、`xmlDictComputeFastQKey`。
- **做法**：与 §3.11 相同的三种问法（直接回答、先写契约、完整推理），14B 和 27B。
- **配对准确率**：修复前那一版的 yes/no 读数更高的配对比例，0.5 是随机。

| | 新 bug（148 对） | PrimeVul（100 对） |
|---|---|---|
| 14B 直接回答 / 先写契约 / 完整推理 | 0.53 / 0.50 / **0.66** | 0.51 / 0.50 / 0.51 |
| 27B 直接回答 / 先写契约 / 完整推理 | **0.76** / **0.76** / 0.62 | 0.60 / 0.60 / 0.55 |
| 规则：代码更少的那一版有 bug | 0.85 | 0.86 |
| 规则：`if` 更少的那一版有 bug | 0.71 | 0.65 |

- **最简单的规则最强，因为修复几乎总是在加代码**。这是配对测试本身的偏差；在真实代码库里排函数时，没有一个修复版可以对照。
- **27B 有超出这些线索的信号，而且不是记忆**：
  - 只看修复没让代码变多的 24 对，27B 直接回答仍有 0.75；只看修复没多加 `if` 的 82 对，有 0.73。
  - 新 bug 反而比 PrimeVul 好认（0.76 对 0.60）。可能的原因有两个：PrimeVul 标签噪声大；挖到的新修复多是"少了一个检查"这类局部问题。
  - 14B 直接回答没有信号，完整推理后才有（0.66，在上面两个子集上是 0.62–0.63）。
- **但模型自己的结论大多不能用**：
  - 27B 直接回答时，两版都答对（修复前 Yes、修复后 No）的只有 11%，两版都说没 bug 的有 51%。
  - 完整推理后，两版都答对升到 22%，但两版都说有 bug 也升到 66%；读数的配对准确率反而降到 0.62。
  - 14B 完整推理：两版都答对 20%，两版都说有 bug 65%。
- **推理指到修复位置的情况有，但不多**：
  - 27B 推理的结尾引用到修复改动那几行的比例：修复前版本 36%，修复后版本 14%。
  - 只看纯插入的修复（这些行两版都有，对照更公平），是 40% 对 29%（35 对）。
  - 两版都答对的 33 对新 bug 里，多数推理说中了真实原因，例如 OpenSSL OCSP 的 `bs` 重复释放、libheif 的 `get_width() - x0` 下溢、
    radare2 `r_str_escape_raw` 的 `sz * 4` 溢出、expat `xcsdup` 的整数溢出。
- **结论**：27B 对模型发布之后才修复的 bug 确实有一部分"看代码就知道"的能力，在配对比较中显著高于随机，也不能用长度或检查数量解释。
  但单独看一个函数时，它对有 bug 和没 bug 的代码给出的结论差别很小：推理让它更敢说"有 bug"，却没有让它更准。
  所以在 trace 里看到的"先知道 bug 再写测试"是真实存在的，只是同样自信的错误判断也很多。
- 原始数据：`bench/results/pairs.txt`，推理文本和数据集在 `bench/results/think/pairs*`。

### 4. 结论与局限

**各配置相对 `plain` 的 TTE**：每个目标取 TTE 中位数之比，再在目标间取几何平均。越小越快，没找到的按预算时间算；括号里是更快的目标数。

| 配置 | Linux（主实验，5 个目标） | Linux（第二台机器复现，5 个目标） | macOS（3 个目标） |
|---|---|---|---|
| `llm`（默认，k=1） | 1.00×（2/5） | 1.58×（0/5） | **0.30×**（3/3） |
| `mild`（k=0.5） | – | 1.71×（0/5） | – |
| `size` | **0.35×**（5/5） | – | 0.86×（2/3） |
| `llmsize` | 1.14×（1/5） | – | **0.27×**（3/3） |
| `size3` | 1.11×（3/5） | – | – |
| `shuf`（固定随机排列） | 1.36×（3/5） | – | 0.55×（1/3） |
| `shufN`（每次换排列） | – | – | 0.65×（3/3） |
| libFuzzer | 0.86×（3/5） | – | – |

**结论**

1. **fuzzer 本身是可用的**：不加权重时，在同样的 harness、种子和预算下和 libFuzzer 互有胜负。
2. **Qwen3-4B 的隐藏状态里有 bug 信号，但很弱**：去掉长度因素后函数级 AUC 只有 0.57，在真实分布上不如"函数越长越可疑"这个简单先验。
3. **LLM 制导的效果强烈依赖目标和平台**：
   - **LLM 看对时收益很大**：macOS 上 libcxxabi 的崩溃函数被排在 79 个区域的第 2 位，找到 bug 快 8 倍，并显著快于随机权重。
   - **Linux 上没有收益，甚至有害**：两台机器上都没有加速（1.00×、1.58×），lcms 和 woff2 都是 LLM 更慢。
     同一个 lcms 在 macOS 上却是 LLM 更快，原因还不清楚。
   - **规模先验在 Linux 上最强**（0.35×），在 macOS 上较弱。
   - **结果对排序非常敏感**：在规模先验里只混入 1/4 的 LLM 分数（`size3`），优势就没了。小样本下，各配置的优劣排序并不稳定。
4. **权重本身也会改变探索**：每次换一个随机排列，平均也有一些加速（macOS 0.65×，单个目标都不显著）；
   但一个糟糕的固定排列可以把执行速度拖到 1/10。
   LLM 的权重只在 libcxxabi 上显著好于随机权重。
5. **行级读出没有用**：它在 PrimeVul 上的 AUC 是 0.67，但没有转化为 fuzzing 收益。
6. **调用上下文帮不上忙**（§3.9）：原样贴入的调用上下文、AST 挑出的定义和数据依赖切片，都不比同长度的随机代码好；
   即使排名完全正确，加权在两个目标上也最多快约 2 倍（§3.10）。
7. **先推理也没有超过规模先验**（§3.11）：27B 先写契约能显著提高排名（契约换成别的函数的就不行），
   14B 完整推理后读数有了超出长度的信号，但没有一种做法在逐个比较中胜过"函数越长越可疑"，27B 的推理还带着明显的记忆痕迹。
8. **在模型没见过的新 bug 上，27B 能部分分清修复前后的同一个函数**（§3.12）：配对准确率 0.76，不能用长度或检查数量解释；
   但它对单个函数的结论区分度很低，推理让它更敢说"有 bug"，却没有更准。

**怎么用**

- **默认**：`llmfuzz run` 用规模先验（`--prior size`，即 `analyze --control size`）。这组实验里它最稳，
  8 组"平台 × 目标"中 7 组比不加权更快；但它在 macOS 的 libcxxabi 上慢了 2.8 倍，正是 LLM 看对的那个目标。
- **LLM 制导**：`--prior llm`（`llmfuzz analyze` 的默认，k=1）是这个项目要验证的方法。
  它在 macOS 的 3 个目标上都更快，在 Linux 上没有收益，个别目标更慢。
- **想要对冲**：多核时可以混用不同的权重（`llmfuzz fuzz -w w_llm.weights -w w_size.weights -w none`）。
  每种权重只分到一部分算力，§3.8 的小实验里没有显著好坏。
- **不建议**：行级加权（`--line-weight`），以及把 LLM 和规模按固定比例相加（`--size-prior`）。
  后者在 macOS 上很好、在 Linux 上不好，结果对比例非常敏感。

**局限**

- **probe**：只在 PrimeVul（CVE 修复）上训练，只用了 Qwen3-4B。更大的模型可能更准，分析开销也更大。
  Qwen3-4B 在 Apple GPU 上约 0.08 秒/区域，re2 的 436 个区域冷启动共 47 秒。
- **实验规模小**：7 个目标，每个配置 5–10 次试验，900–1800 秒。做了很多对比，个别 p<0.05 可能是偶然。
- **语言和构建要求**：只支持 C/C++（括号匹配的函数解析），需要调试信息和原地的源码。
- **实验里的能量不考虑执行时间**：错误的权重可能把 fuzzer 困在慢输入上，例如 Linux lcms 上的 `shuf`。
  后来加了 AFL 式的速度系数（运行时参数 `-time_energy=1`，`llmfuzz run` / `fuzz` 默认打开），上面的实验都没有用它。
  在 libxml2 和 SQLite 上，它让吞吐提高了 2–11 倍（见"大型软件上的例子"），所以这些实验是在一个吞吐偏低的引擎上做的；
  换成更强的引擎，各种加权之间的相对快慢可能会变。
- **多模块**：权重文件只按 PC 地址索引、不区分模块，有多个插桩的动态库时地址可能冲突；运行中 `dlopen` 的插桩模块不计覆盖。
- **执行速度**：程序模式没有 persistent 模式，每个输入 fork 一次；macOS 上 ASan 进程 fork 的开销因机器而异（3–90 ms，见"实现"）。
- **漏报**：不做内存泄漏检测（驱动默认 `detect_leaks=0`）。

## 复现

FTS 目标按各自的 `build.sh` 编译，只是把编译器换成包装器：
`CC=llmfuzz-cc CXX=llmfuzz-c++ CFLAGS="-O1 -ffp-contract=off" LIB_FUZZING_ENGINE=""`。
libFuzzer 参考版用 `clang -fsanitize=address,fuzzer`，其它参数相同。

```bash
# 每个目标生成各配置的权重（LLM 分数有缓存，只有第一次需要跑模型）
llmfuzz analyze ./fuzzer -o w_llm.weights
llmfuzz analyze ./fuzzer -o w_shuf.weights --control shuffle --seed 1
llmfuzz analyze ./fuzzer -o w_size.weights --control size
llmfuzz analyze ./fuzzer -o w_llmsize.weights --size-prior 1

# 重复试验：{target} 替换为目标名，{seed} 替换为试验编号（例如每次试验一个随机排列）
python bench/run_eval.py --target lcms=./fuzzer,./seeds --config plain= --config llm=w_llm.weights \
    --config shuf=w_shuf.weights --trials 10 --time 900 --par 16 --out results.jsonl

# 汇总
python bench/summarize.py results.jsonl --budget 900 --wide --configs plain,llm,shuf --pvals llm:plain,llm:shuf
python bench/bug_rank.py llm=w_llm.weights.json size=w_size.weights.json --bug =TetrahedralInterpFloat
```

- **原始结果**：都在 `bench/results/*.jsonl`（每行一次试验），表格可以直接重算，例如
  `python bench/summarize.py bench/results/linux_core.jsonl bench/results/linux_size.jsonl --budget 900 --wide`。
- `run_eval.py --engine libfuzzer` 用同样的方式跑 libFuzzer 二进制。
- `run_eval.py --keep` 保留每次试验的语料和覆盖。
- `bench/run_campaigns.py` 跑多 worker 的完整 campaign（例如混合权重 vs 全部不加权）。
- `bench/hotcov.py` 统计各配置对 LLM 标记的 hot 代码的覆盖。

```bash
# 调用上下文（§3.9）：编译时记录编译命令 → 数据集 → GPU 上打分 → 汇总
LLMFUZZ_CDB=$PWD/cdb.jsonl CC=llmfuzz-cc CXX=llmfuzz-c++ ./build.sh
python bench/ctx_dataset.py ctx.json --target woff2=w_llm.weights.json,cdb.jsonl \
    --bug woff2=Buffer::Read --bug woff2=ReconstructGlyf --sample 80
python bench/ctx_score.py ctx.json q8b.npz --model Qwen/Qwen3-8B --4bit \
    --lens neuronpedia/jacobian-lens:qwen3-8b/jlens/Salesforce-wikitext/Qwen3-8B_jacobian_lens.pt
python bench/ctx_analyze.py ctx.json q8b.npz        # 排名表；结果见 bench/results/ctx_rankings.txt

# oracle（§3.10）：每次试验一个随机排名，{seed} 由 run_eval.py 替换
for s in $(seq 1 8); do llmfuzz analyze ./fuzzer -o w_or5_$s.weights --control oracle --oracle-rank 0.05 --seed $s \
    --oracle TetrahedralInterpFloat --top 0; done
llmfuzz analyze ./fuzzer -o w_orflat.weights --control oracle --oracle-flat --oracle TetrahedralInterpFloat
python bench/run_eval.py --target lcms=./fuzzer,./seeds --config plain= --config or5=w_or5_{seed}.weights \
    --config orflat=w_orflat.weights --trials 8 --time 900 --out oracle.jsonl
```

原始结果：`bench/results/linux_oracle.jsonl`、`linux_oracle_flat.jsonl`。

```bash
# 先思考 / 先写契约（§3.11）：同一个数据集，聊天格式的问题
python bench/ctx_think.py ctx.json q14.npz --model Qwen/Qwen3-14B --4bit --lens-cpu --modes iso,spec,think --think-tokens 512 \
    --lens neuronpedia/jacobian-lens:qwen3-14b/jlens/Salesforce-wikitext/Qwen3-14B_jacobian_lens.pt
python bench/ctx_think.py ctx.json q14_shuf.npz ... --modes iso,spec --specs q14.texts.jsonl --shuffle-specs   # 契约对照
# 完整推理：vLLM 先生成推理（不截断），再用 --thoughts 读出
python bench/ctx_think_vllm.py ctx.json q14_full.thoughts.jsonl --model Qwen/Qwen3-14B-AWQ --think-tokens 8192
python bench/ctx_think.py ctx.json q14_full.npz ... --modes iso,think --thoughts q14_full.thoughts.jsonl
python bench/ctx_analyze.py ctx.json q14_full.npz
```

```bash
# 修复前后配对（§3.12）：挖提交 → 组成 ctx_think.py 的输入（每个区域带 pair、bug）→ 同上三种问法 → 配对分析
git clone --bare --filter=blob:none --shallow-since=2026-04-01 https://github.com/openssl/openssl.git openssl.git
python bench/pair_mine.py openssl.git openssl 2026-05-01 fixes.jsonl
python bench/pair_analyze.py pairs.json p36_spec.npz p36_think.npz
```

27B 在 24 GB 显卡上的 vLLM 参数：`--model cyankiwi/Qwen3.6-27B-AWQ-INT4 --tokenizer Qwen/Qwen3.6-27B --text-only --kv-fp8 --max-seqs 16
--max-batched 512 --mem 0.965`（权重约 18.5 GB，剩约 1.5 GB 给 KV cache，约 150 token/s）。

## 参考

- J-lens：Anthropic，*Verbalizable Representations Form a Global Workspace in Language Models*（2026），
  参考实现 `anthropics/jacobian-lens`；预拟合 lens：Hugging Face `neuronpedia/jacobian-lens`
- 模型：Qwen3-4B（`Qwen/Qwen3-4B`）；§3.9 另用了 Qwen3-8B、Qwen3-14B、Qwen3.6-27B
- PrimeVul：Ding et al., *Vulnerability Detection with Code Language Models: How Far Are We?*（ICSE 2025）
- Google fuzzer-test-suite：<https://github.com/google/fuzzer-test-suite>
- libFuzzer（value profile、TORC、len_control）、AFL（命中次数分桶、fork server）、AFLFast / Entropic（能量调度）

## 许可证

代码采用 MIT 许可证，见 `LICENSE`。`bench/results/think/` 里的配对数据（`pairs.json.gz`）包含从各开源项目的提交中截取的函数代码，
版权归原项目所有，按各自的许可证使用；同一目录下的推理和契约文本由 Qwen3 / Qwen3.6 生成。

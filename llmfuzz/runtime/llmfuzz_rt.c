/* llmfuzz_rt.c -- coverage-guided fuzzing runtime whose seed scheduling is
 * biased by per-edge "bug likelihood" weights read from an LLM's hidden
 * states (see llmfuzz/lens.py).
 *
 * Link into a target compiled with
 *     -fsanitize-coverage=trace-pc-guard,pc-table,trace-cmp
 * (`llmfuzz cc` / `llmfuzz cxx` do this). Two ways to run:
 *   harness : the target defines LLVMFuzzerTestOneInput; llmfuzz_main.o
 *             provides main(). Inputs run in-process (or forked, -fork=1).
 *   program : the target has its own main(). If LLMFUZZ_OPTIONS is set, a
 *             constructor turns the process into a fork server that runs the
 *             program once per input (via -input_file=PATH, or stdin).
 * Flags follow libFuzzer's -name=value style; see parse_flag().
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <libproc.h>
#include <mach-o/dyld.h>
#else
#include <link.h>
#endif

#define MAP_CAP (1u << 23) /* max instrumented edges */
#define VP_BITS (1u << 22) /* value-profile feature space */
#define VP_FLAG 0x80000000u
#define VPL_CAP 4096
#define TORC_N 512
#define MEMC_N 128
#define MEMC_LEN 32
#define MAX_MODS 64

/* Optional symbols: dlsym on Darwin (weak-undefined needs linker flags there),
 * weak references elsewhere. */
int LLVMFuzzerTestOneInput(const uint8_t *, size_t) __attribute__((weak));
int LLVMFuzzerInitialize(int *, char ***) __attribute__((weak));
size_t LLVMFuzzerCustomMutator(uint8_t *, size_t, size_t, unsigned int) __attribute__((weak));
void __sanitizer_set_death_callback(void (*)(void)) __attribute__((weak));
void __sanitizer_print_stack_trace(void) __attribute__((weak));
int __asan_report_present(void) __attribute__((weak));
int __sanitizer_install_malloc_and_free_hooks(void (*)(const volatile void *, size_t),
                                              void (*)(const volatile void *)) __attribute__((weak));
#ifdef __APPLE__
#define EXT(f) ((__typeof__(&f))dlsym(RTLD_DEFAULT, #f))
#else
#define EXT(f) (&f)
#endif

/* ------------------------------------------------------------------------ */
/* Coverage state. Lives in a MAP_SHARED region so forked children write it. */
typedef struct { uint64_t a, b; uint32_t sz; } cmp_pair;
typedef struct { uint8_t a[MEMC_LEN], b[MEMC_LEN]; uint32_t la, lb; } mem_pair;
typedef struct {
  volatile uint32_t crashed;
  uint32_t vp_n;
  uint32_t vp[VPL_CAP];   /* value-profile features hit by this execution */
  cmp_pair torc[TORC_N];  /* table of recent integer compares */
  mem_pair memc[MEMC_N];  /* table of recent memory/string compares */
  uint8_t cnt[MAP_CAP] __attribute__((aligned(64))); /* edge hit counters; [0] = uninitialised guard */
} shm_t;

static shm_t *S;
static uint8_t dummy_cnt[1];
static uint8_t *CNT = dummy_cnt;
static uint32_t n_guards, last_guard;
static int guards_frozen; /* per-edge arrays are sized: ignore modules loaded later */
static uint8_t *Hot;  /* per edge: LLM weight >= hot threshold */
static int vp_mode = 1; /* value profile: 0 off, 1 LLM-hot code only (default), 2 everywhere */

static uint32_t mod_first[MAX_MODS], mod_n[MAX_MODS], n_mods;
static const uintptr_t *mod_pcs[MAX_MODS];
static uintptr_t mod_slide[MAX_MODS];
static const char *mod_path[MAX_MODS];

static void shm_init(void) {
  if (S) return;
  S = mmap(NULL, sizeof(shm_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  if (S == MAP_FAILED) { perror("llmfuzz: mmap"); _exit(1); }
  CNT = S->cnt;
}

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
  if (start == stop || *start || n_mods == MAX_MODS || guards_frozen) return;
  shm_init();
  mod_first[n_mods] = n_guards + 1;
  for (uint32_t *p = start; p < stop; p++) *p = n_guards + 1 < MAP_CAP ? ++n_guards : 0;
  mod_n[n_mods] = n_guards + 1 - mod_first[n_mods];
  n_mods++;
}

/* Address of a pc as the symbolizer sees it (undo ASLR slide). */
static uintptr_t image_slide(const void *pc, const char **path) {
  Dl_info di;
  if (!dladdr(pc, &di)) return 0;
  *path = di.dli_fname;
#ifdef __APPLE__
  for (uint32_t i = 0; i < _dyld_image_count(); i++)
    if ((const void *)_dyld_get_image_header(i) == di.dli_fbase) return _dyld_get_image_vmaddr_slide(i);
  return 0;
#else
  return ((const ElfW(Ehdr) *)di.dli_fbase)->e_type == ET_DYN ? (uintptr_t)di.dli_fbase : 0;
#endif
}

void __sanitizer_cov_pcs_init(const uintptr_t *beg, const uintptr_t *end) {
  (void)end;
  for (uint32_t m = 0; m < n_mods; m++)
    if (mod_pcs[m] == beg) return; /* Darwin calls this once per TU */
  for (int m = (int)n_mods - 1; m >= 0; m--)
    if (!mod_pcs[m]) {
      mod_pcs[m] = beg;
      if ((uint32_t)((end - beg) / 2) < mod_n[m]) mod_n[m] = (uint32_t)((end - beg) / 2);
      mod_slide[m] = image_slide((const void *)beg[0], &mod_path[m]);
      return;
    }
}

void __sanitizer_cov_trace_pc_guard(uint32_t *g) {
  uint32_t i = *g;
  uint8_t c = CNT[i];
  CNT[i] = c + 1 + (c == 255); /* never wraps to zero */
  last_guard = i;
}

/* Compare tracing: feeds the mutator (TORC) and, in LLM-hot code, the
 * value-profile features that reward getting closer to satisfying a branch. */
static inline void cmp_hook(uint64_t a, uint64_t b, uint32_t sz, uintptr_t pc) {
  if (!S) return;
  if (vp_mode && (vp_mode == 2 || (Hot && Hot[last_guard])) && S->vp_n < VPL_CAP) {
    uint32_t site = (uint32_t)((pc * 0x9E3779B97F4A7C15ull) >> 40);
    S->vp[S->vp_n++] = (site * 65u + (uint32_t)__builtin_popcountll(a ^ b)) & (VP_BITS - 1);
  }
  if (a != b) S->torc[((a ^ (b << 1)) * 0x9E3779B97F4A7C15ull >> 50) % TORC_N] = (cmp_pair){a, b, sz};
}
#define CMP_HOOK(name, T) \
  void name(T a, T b) { cmp_hook(a, b, sizeof(T), (uintptr_t)__builtin_return_address(0)); }
CMP_HOOK(__sanitizer_cov_trace_cmp1, uint8_t)
CMP_HOOK(__sanitizer_cov_trace_cmp2, uint16_t)
CMP_HOOK(__sanitizer_cov_trace_cmp4, uint32_t)
CMP_HOOK(__sanitizer_cov_trace_cmp8, uint64_t)
CMP_HOOK(__sanitizer_cov_trace_const_cmp1, uint8_t)
CMP_HOOK(__sanitizer_cov_trace_const_cmp2, uint16_t)
CMP_HOOK(__sanitizer_cov_trace_const_cmp4, uint32_t)
CMP_HOOK(__sanitizer_cov_trace_const_cmp8, uint64_t)

void __sanitizer_cov_trace_switch(uint64_t v, uint64_t *cases) {
  if (!S || !cases[0]) return;
  uint32_t sz = (uint32_t)cases[1] / 8;
  uint64_t best = cases[2];
  for (uint64_t i = 0; i < cases[0]; i++) {
    uint64_t c = cases[2 + i];
    if (i < 16 && v != c) S->torc[((v ^ (c << 1)) * 0x9E3779B97F4A7C15ull >> 50) % TORC_N] = (cmp_pair){v, c, sz};
    if (__builtin_popcountll(v ^ c) < __builtin_popcountll(v ^ best)) best = c;
  }
  cmp_hook(v, best, sz, (uintptr_t)__builtin_return_address(0));
}

static size_t bounded_len(const char *s, size_t n) {
  size_t i = 0;
  while (i < n && s[i]) i++;
  return i;
}
static void memc_add(const void *a, size_t la, const void *b, size_t lb) {
  if (!S || !la || !lb) return;
  if (la > MEMC_LEN) la = MEMC_LEN;
  if (lb > MEMC_LEN) lb = MEMC_LEN;
  const uint8_t *pa = a, *pb = b;
  mem_pair *m = &S->memc[(pa[0] * 31u + pb[0] * 7u + (uint32_t)la * 131u + (uint32_t)lb * 17u + pb[lb - 1]) % MEMC_N];
  for (size_t i = 0; i < la; i++) m->a[i] = pa[i];
  for (size_t i = 0; i < lb; i++) m->b[i] = pb[i];
  m->la = (uint32_t)la, m->lb = (uint32_t)lb;
}
void __sanitizer_weak_hook_memcmp(void *pc, const void *a, const void *b, size_t n, int r) {
  (void)pc;
  if (r && n > 1) memc_add(a, n, b, n);
}
void __sanitizer_weak_hook_strncmp(void *pc, const char *a, const char *b, size_t n, int r) {
  (void)pc;
  if (r) memc_add(a, bounded_len(a, n), b, bounded_len(b, n));
}
void __sanitizer_weak_hook_strcmp(void *pc, const char *a, const char *b, int r) {
  (void)pc;
  if (r) memc_add(a, bounded_len(a, MEMC_LEN), b, bounded_len(b, MEMC_LEN));
}
void __sanitizer_weak_hook_strncasecmp(void *pc, const char *a, const char *b, size_t n, int r) {
  __sanitizer_weak_hook_strncmp(pc, a, b, n, r);
}
void __sanitizer_weak_hook_strcasecmp(void *pc, const char *a, const char *b, int r) {
  __sanitizer_weak_hook_strcmp(pc, a, b, r);
}
void __sanitizer_weak_hook_strstr(void *pc, const char *a, const char *b, char *r) {
  (void)pc, (void)a, (void)r;
  memc_add(b, bounded_len(b, MEMC_LEN), b, bounded_len(b, MEMC_LEN));
}
void __sanitizer_weak_hook_strcasestr(void *pc, const char *a, const char *b, char *r) {
  __sanitizer_weak_hook_strstr(pc, a, b, r);
}
void __sanitizer_weak_hook_memmem(void *pc, const void *a, size_t la, const void *b, size_t lb, void *r) {
  (void)pc, (void)a, (void)la, (void)r;
  memc_add(b, lb, b, lb);
}

/* ------------------------------------------------------------------------ */
/* Options.                                                                  */
static struct {
  uint64_t runs, seed;
  double max_time, timeout, gamma, hot, uniform, print_secs, reload;
  size_t max_len, len_control;
  long rss_limit_mb, malloc_limit_mb;
  int fork, use_stdin, close_stdout, verbose, max_len_set, hot_set, time_energy;
  const char *dict, *weights, *artifact_prefix, *stats, *input_file, *dump_pcs, *cov_dump;
} O = {.timeout = 2, .gamma = 1, .hot = 2, .uniform = 0.1, .print_secs = 5, .reload = 10,
       .max_len = 4096, .len_control = 100, .rss_limit_mb = 2048, .artifact_prefix = "./"};
static const char *paths[256];
static int n_paths;

static int parse_flag(const char *a) {
  const char *eq = strchr(a, '=');
  if (a[0] != '-' || !eq) return 0;
  const char *k = a + 1, *v = eq + 1;
  size_t kl = (size_t)(eq - k);
#define IS(name) (kl == sizeof(name) - 1 && !strncmp(k, name, kl))
  if (IS("runs")) O.runs = strtoull(v, 0, 10);
  else if (IS("seed")) O.seed = strtoull(v, 0, 10);
  else if (IS("max_total_time")) O.max_time = atof(v);
  else if (IS("timeout")) O.timeout = atof(v);
  else if (IS("max_len")) O.max_len = strtoull(v, 0, 10), O.max_len_set = 1;
  else if (IS("len_control")) O.len_control = strtoull(v, 0, 10);
  else if (IS("gamma")) O.gamma = atof(v);
  else if (IS("hot")) O.hot = atof(v), O.hot_set = 1;
  else if (IS("uniform")) O.uniform = atof(v);
  else if (IS("time_energy")) O.time_energy = atoi(v);
  else if (IS("vp")) vp_mode = atoi(v);
  else if (IS("print_secs")) O.print_secs = atof(v);
  else if (IS("reload")) O.reload = atof(v);
  else if (IS("rss_limit_mb")) O.rss_limit_mb = atol(v);
  else if (IS("malloc_limit_mb")) O.malloc_limit_mb = atol(v);
  else if (IS("fork")) O.fork = atoi(v);
  else if (IS("stdin")) O.use_stdin = atoi(v);
  else if (IS("close_fd_mask")) O.close_stdout = atoi(v) & 1;
  else if (IS("verbose")) O.verbose = atoi(v);
  else if (IS("dict")) O.dict = v;
  else if (IS("weights")) O.weights = v;
  else if (IS("artifact_prefix")) O.artifact_prefix = v;
  else if (IS("stats")) O.stats = v;
  else if (IS("input_file")) O.input_file = v;
  else if (IS("dump_pcs")) O.dump_pcs = v;
  else if (IS("cov_dump")) O.cov_dump = v;
  else fprintf(stderr, "llmfuzz: ignoring unknown flag %s\n", a);
#undef IS
  return 1;
}

/* ------------------------------------------------------------------------ */
/* Small utilities.                                                          */
static uint64_t rs = 0x9E3779B97F4A7C15ull;
static inline uint64_t rnd64(void) {
  rs ^= rs << 13, rs ^= rs >> 7, rs ^= rs << 17;
  return rs;
}
static inline size_t rnd(size_t n) { return n ? (size_t)(rnd64() % n) : 0; }
static double now(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec * 1e-6;
}
static uint64_t hash64(const uint8_t *d, size_t n) {
  uint64_t h = 0xcbf29ce484222325ull;
  for (size_t i = 0; i < n; i++) h = (h ^ d[i]) * 0x100000001b3ull;
  return h;
}
static int write_file(const char *path, const uint8_t *d, size_t n) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return -1;
  for (size_t off = 0; off < n;) {
    ssize_t w = write(fd, d + off, n - off);
    if (w <= 0) break;
    off += (size_t)w;
  }
  close(fd);
  return 0;
}
static uint8_t *read_file(const char *path, size_t *n, size_t cap) {
  FILE *f = fopen(path, "rb");
  struct stat st;
  if (!f) return NULL;
  size_t sz = fstat(fileno(f), &st) ? 0 : (size_t)st.st_size;
  uint8_t *d = malloc((sz < cap ? sz : cap) + 1);
  *n = fread(d, 1, sz < cap ? sz : cap, f);
  fclose(f);
  return d;
}
static uint8_t *exact_copy(const uint8_t *d, size_t n) { /* exact-size heap copy: ASan sees overflows */
  uint8_t *c = malloc(n);
  if (!c) c = malloc(1);
  if (n) memcpy(c, d, n);
  return c;
}
static long rss_mb(void) {
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
#ifdef __APPLE__
  return ru.ru_maxrss >> 20;
#else
  return ru.ru_maxrss >> 10;
#endif
}
static int find_sub(const uint8_t *d, size_t n, const uint8_t *s, size_t m, size_t start) {
  if (!m || m > n) return -1;
  for (size_t k = 0; k + m <= n; k++) {
    size_t p = (start + k) % (n - m + 1), j = 0;
    while (j < m && d[p + j] == s[j]) j++;
    if (j == m) return (int)p;
  }
  return -1;
}

/* Hash set of 64-bit keys (content hashes of known inputs, file names). */
static uint64_t *hs_tab;
static size_t hs_cap, hs_n;
static int hs_add(uint64_t k) { /* returns 1 if newly inserted */
  if (!k) k = 1;
  if (2 * (hs_n + 1) > hs_cap) {
    uint64_t *old = hs_tab;
    size_t oc = hs_cap;
    hs_cap = hs_cap ? 2 * hs_cap : 4096, hs_tab = calloc(hs_cap, 8), hs_n = 0;
    for (size_t i = 0; i < oc; i++)
      if (old[i]) hs_add(old[i]);
    free(old);
  }
  size_t i = (size_t)(k * 0x9E3779B97F4A7C15ull) & (hs_cap - 1);
  for (; hs_tab[i]; i = (i + 1) & (hs_cap - 1))
    if (hs_tab[i] == k) return 0;
  hs_tab[i] = k, hs_n++;
  return 1;
}

/* ------------------------------------------------------------------------ */
/* PC table and LLM weights.                                                 */
static uintptr_t *PCU; /* per edge: unslid pc */
static uint8_t *PCF;   /* per edge: 1 = function entry */
static float *W, *Wg;  /* per edge: LLM weight, weight^gamma */
static uint32_t n_hot;

static void build_pc_table(void) {
  guards_frozen = 1;
  if (PCU) return;
  PCU = calloc(n_guards + 1, sizeof *PCU), PCF = calloc(n_guards + 1, 1);
  for (uint32_t m = 0; m < n_mods; m++)
    for (uint32_t i = 0; mod_pcs[m] && i < mod_n[m]; i++)
      PCU[mod_first[m] + i] = mod_pcs[m][2 * i] - mod_slide[m], PCF[mod_first[m] + i] = mod_pcs[m][2 * i + 1] & 1;
}

static void dump_pcs(const char *path) {
  build_pc_table();
  FILE *f = fopen(path, "w");
  if (!f) { perror(path); _exit(1); }
  fprintf(f, "# llmfuzz-pcs v1 %u\n", n_guards);
  for (uint32_t m = 0; m < n_mods; m++)
    fprintf(f, "# module %u %u %u %s\n", m, mod_first[m], mod_n[m], mod_path[m] ? mod_path[m] : "?");
  for (uint32_t m = 0; m < n_mods; m++)
    for (uint32_t i = 0; i < mod_n[m]; i++)
      fprintf(f, "%u 0x%lx %u %u\n", mod_first[m] + i, (unsigned long)PCU[mod_first[m] + i], PCF[mod_first[m] + i], m);
  fclose(f);
}

typedef struct { uintptr_t pc; float w; } pcw;
static int pcw_cmp(const void *a, const void *b) {
  uintptr_t x = ((const pcw *)a)->pc, y = ((const pcw *)b)->pc;
  return x < y ? -1 : x > y;
}
static void load_weights(void) {
  build_pc_table();
  W = malloc((n_guards + 1) * sizeof *W), Wg = malloc((n_guards + 1) * sizeof *Wg), Hot = calloc(n_guards + 1, 1);
  for (uint32_t e = 0; e <= n_guards; e++) W[e] = 1;
  if (O.weights) {
    FILE *f = fopen(O.weights, "r");
    if (!f) { perror(O.weights); exit(1); }
    size_t n = 0, cap = 1 << 16;
    pcw *v = malloc(cap * sizeof *v);
    char line[256];
    while (fgets(line, sizeof line, f)) {
      unsigned long pc;
      float w;
      if (!strncmp(line, "#hot ", 5) && !O.hot_set) O.hot = atof(line + 5);
      if (line[0] == '#' || sscanf(line, "%lx %f", &pc, &w) != 2) continue;
      if (n == cap) v = realloc(v, (cap *= 2) * sizeof *v);
      v[n++] = (pcw){(uintptr_t)pc, w};
    }
    fclose(f);
    qsort(v, n, sizeof *v, pcw_cmp);
    uint32_t matched = 0;
    for (uint32_t e = 1; e <= n_guards; e++) {
      size_t lo = 0, hi = n;
      while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (v[mid].pc < PCU[e]) lo = mid + 1; else hi = mid;
      }
      if (lo < n && v[lo].pc == PCU[e]) W[e] = v[lo].w, matched++;
    }
    free(v);
    fprintf(stderr, "llmfuzz: weights %s: matched %u/%u edges\n", O.weights, matched, n_guards);
  }
  for (uint32_t e = 1; e <= n_guards; e++) {
    Wg[e] = powf(W[e], (float)O.gamma);
    if (O.weights && W[e] >= O.hot - 1e-5) Hot[e] = 1, n_hot++;  /* float vs the 4-decimal threshold */
  }
  Wg[0] = 0;
}

/* ------------------------------------------------------------------------ */
/* Corpus and scheduling.                                                    */
typedef struct {
  uint8_t *data;
  uint32_t size, nown, fuzzed, found;
  uint32_t *own; /* features first discovered by this input */
  float maxw;    /* max weight^gamma over edges it executes */
  float us;      /* its execution time when added, in microseconds */
} entry_t;

static entry_t *corp;
static uint32_t ncorp, capcorp;
static double *cum, cum_total;
static uint32_t n_cum;
static uint64_t last_energy;
static int energy_dirty, inited;
static uint32_t *fhits;   /* per feature (edge*8+bucket): #executions hitting it */
static uint8_t *fseen, *eseen, *crash_seen, *vpseen;
static uint16_t *vphits;
static uint32_t *cur_ft, cur_nft, *new_ft, n_new;
static uint32_t n_cov, n_ft, n_hot_cov, n_crashes, n_vp;
static uint8_t bucket[256];

static uint8_t *cur, *tmp;  /* current input, scratch */
static size_t mut_cap;       /* current max mutation length (grows, libFuzzer-style len_control) */
static uint64_t last_new_exec;
static size_t cur_n;
static uint32_t cur_parent;
static int cur_from_disk;
static uint64_t execs;
static double t_start, t_last_print, t_last_reload, run_start;
static volatile int running, stop_req;
static FILE *stats_f;
static const char *out_dir;
static char **queue;
static size_t nqueue, qpos, capqueue;
static struct { uint8_t *d; size_t n; } dict[4096];
static size_t ndict;
static uint8_t last_word[64]; /* last dictionary/compare word used by mutate() */
static size_t last_word_n;

static void collect(void) {
  cur_nft = n_new = 0;
  const uint64_t *w = (const uint64_t *)CNT;
  for (uint32_t i = 0, nw = (n_guards + 8) / 8; i < nw; i++) {
    uint64_t v = w[i];
    for (uint32_t e = i * 8; v; v >>= 8, e++) {
      uint8_t c = (uint8_t)v;
      if (!c || !e || e > n_guards) continue;
      uint32_t f = e * 8 + bucket[c];
      cur_ft[cur_nft++] = f;
      if (fhits[f] != UINT32_MAX) fhits[f]++;
      if (!fseen[f]) new_ft[n_new++] = f;
    }
  }
  for (uint32_t k = 0; k < S->vp_n; k++) {
    uint32_t idx = S->vp[k];
    if (vphits[idx] != UINT16_MAX) vphits[idx]++;
    if (!(vpseen[idx >> 3] & (1 << (idx & 7)))) new_ft[n_new++] = VP_FLAG | idx;
  }
}

static void print_stats(const char *tag) {
  double t = now() - t_start;
  fprintf(stderr, "#%llu\t%s cov: %u ft: %u hot: %u/%u corp: %u exec/s: %.0f crashes: %u rss: %ldMb t: %.0fs\n",
          (unsigned long long)execs, tag, n_cov, n_ft + n_vp, n_hot_cov, n_hot, ncorp, execs / (t > 0 ? t : 1),
          n_crashes, rss_mb(), t);
  if (stats_f)
    fprintf(stats_f, "{\"t\":%.2f,\"execs\":%llu,\"cov\":%u,\"ft\":%u,\"hot\":%u,\"hot_total\":%u,\"corp\":%u,\"crashes\":%u}\n",
            t, (unsigned long long)execs, n_cov, n_ft + n_vp, n_hot_cov, n_hot, ncorp, n_crashes), fflush(stats_f);
}

static void add_entry(void) {
  if (!hs_add(hash64(cur, cur_n) ^ 0x5bd1e995)) return; /* duplicate content */
  if (ncorp == capcorp) {
    capcorp = capcorp ? 2 * capcorp : 1024;
    corp = realloc(corp, capcorp * sizeof *corp), cum = realloc(cum, capcorp * sizeof *cum);
  }
  entry_t *e = &corp[ncorp];
  memset(e, 0, sizeof *e);
  e->own = malloc((n_new ? n_new : 1) * sizeof *e->own);
  for (uint32_t k = 0; k < n_new; k++) {
    uint32_t f = new_ft[k];
    if (f & VP_FLAG) {
      uint32_t idx = f & ~VP_FLAG;
      if (vpseen[idx >> 3] & (1 << (idx & 7))) continue;
      vpseen[idx >> 3] |= 1 << (idx & 7), n_vp++;
    } else {
      if (fseen[f]) continue;
      fseen[f] = 1, n_ft++;
      uint32_t ed = f >> 3;
      if (!eseen[ed]) eseen[ed] = 1, n_cov++, n_hot_cov += Hot[ed];
    }
    e->own[e->nown++] = f;
  }
  if (!e->nown && ncorp) { free(e->own); return; }
  e->maxw = 1;
  for (uint32_t k = 0; k < cur_nft; k++)
    if (Wg[cur_ft[k] >> 3] > e->maxw) e->maxw = Wg[cur_ft[k] >> 3];
  e->us = (float)((now() - run_start) * 1e6);
  e->size = (uint32_t)cur_n;
  e->data = malloc(cur_n ? cur_n : 1);
  memcpy(e->data, cur, cur_n);
  if (cur_parent < ncorp) corp[cur_parent].found++;
  if (cur_parent < ncorp && last_word_n && ndict < sizeof dict / sizeof *dict &&
      hs_add(hash64(last_word, last_word_n) ^ 0xa11d1c7)) /* persistent auto-dictionary */
    dict[ndict].d = malloc(last_word_n), memcpy(dict[ndict].d, last_word, last_word_n), dict[ndict++].n = last_word_n;
  ncorp++, energy_dirty = 1, last_new_exec = execs;
  if (out_dir && !cur_from_disk) {
    char p[4096], t[4200];
    snprintf(p, sizeof p, "%s/%016llx", out_dir, (unsigned long long)hash64(cur, cur_n));
    snprintf(t, sizeof t, "%s/.tmp-%d", out_dir, (int)getpid());
    hs_add(hash64((const uint8_t *)p, strlen(p)));
    if (!write_file(t, cur, cur_n)) rename(t, p); /* other workers never see a partial file */
  }
  if (O.verbose) print_stats("NEW ");
}

/* Energy of a seed = sum over the features it owns of
 *     weight(edge)^gamma / sqrt(1 + hits(feature) / 256)
 * i.e. seeds at the rarely-exercised frontier get fuzzed more, and frontier
 * features inside code the LLM considers buggy count gamma-times more. */
/* -time_energy=1: AFL's speed factor, relative to the corpus's mean execution time */
static double speed_factor(double us, double avg) {
  return us * 0.1 > avg ? 0.1 : us * 0.25 > avg ? 0.25 : us * 0.5 > avg ? 0.5 : us * 0.75 > avg ? 0.75
       : us * 4 < avg ? 3 : us * 3 < avg ? 2 : us * 2 < avg ? 1.5 : 1;
}
static double avg_us; /* mean execution time over the corpus (-time_energy) */
static void recompute_energy(void) {
  avg_us = 0;
  for (uint32_t i = 0; O.time_energy && i < ncorp; i++) avg_us += corp[i].us / ncorp;
  cum_total = 0;
  for (uint32_t i = 0; i < ncorp; i++) {
    entry_t *e = &corp[i];
    double s = 0;
    for (uint32_t k = 0; k < e->nown; k++) {
      uint32_t f = e->own[k];
      if (f & VP_FLAG) s += e->maxw / sqrt(1.0 + vphits[f & ~VP_FLAG] / 256.0);
      else s += Wg[f >> 3] / sqrt(1.0 + fhits[f] / 256.0);
    }
    if (O.time_energy) s *= speed_factor(e->us, avg_us);
    cum_total += s > 1e-3 ? s : 1e-3;
    cum[i] = cum_total;
  }
  n_cum = ncorp, energy_dirty = 0, last_energy = execs;
}

static uint32_t choose_seed(void) {
  if (rnd(1000) < O.uniform * 1000) { /* uniform pick; with -time_energy, slow inputs are mostly redrawn */
    uint32_t i = (uint32_t)rnd(ncorp);
    for (int t = 0; O.time_energy && t < 8 && rnd(1000) >= 1000 * speed_factor(corp[i].us, avg_us); t++)
      i = (uint32_t)rnd(ncorp);
    return i;
  }
  double r = (double)(rnd64() >> 11) / 9007199254740992.0 * cum_total;
  uint32_t lo = 0, hi = n_cum - 1;
  while (lo < hi) {
    uint32_t mid = (lo + hi) / 2;
    if (cum[mid] < r) lo = mid + 1; else hi = mid;
  }
  return lo;
}

/* ------------------------------------------------------------------------ */
/* Mutator.                                                                  */
static const int64_t interesting[] = {0, 1, -1, 2, 7, 8, 16, 32, 64, 100, 127, -128, 128, 255, 256, 512,
                                      1000, 1024, 4096, 32767, -32768, 65535, 65536, 0x7fffffff,
                                      -0x7fffffff - 1, 0xffffffffll, 0x100000000ll, 0x7fffffffffffffffll};
#define N_INTERESTING (sizeof interesting / sizeof *interesting)

static void put_int(uint8_t *d, uint64_t v, size_t w, int be) {
  for (size_t i = 0; i < w; i++) d[be ? w - 1 - i : i] = (uint8_t)(v >> (8 * i));
}
static uint64_t get_int(const uint8_t *d, size_t w, int be) {
  uint64_t v = 0;
  for (size_t i = 0; i < w; i++) v |= (uint64_t)d[be ? w - 1 - i : i] << (8 * i);
  return v;
}
static size_t blen(size_t lim) { /* block length biased towards small */
  static const size_t caps[] = {4, 16, 64, (size_t)1 << 30};
  size_t c = caps[rnd(4)];
  return lim ? 1 + rnd(c < lim ? c : lim) : 0;
}
/* Replace d[pos, pos+old) by src[0, len); src must not alias d. */
static size_t repl(uint8_t *d, size_t n, size_t pos, size_t old, const uint8_t *src, size_t len) {
  size_t cap = mut_cap > n ? mut_cap : n;
  if (n - old + len > cap) len = n - old < cap ? cap - (n - old) : 0;
  memmove(d + pos + len, d + pos + old, n - pos - old);
  memcpy(d + pos, src, len);
  return n - old + len;
}
static size_t put_word(uint8_t *d, size_t n, const uint8_t *w, size_t len) {
  if (len >= 2 && len <= sizeof last_word) memcpy(last_word, w, len), last_word_n = len;
  if (n >= len && rnd(2)) {
    memcpy(d + rnd(n - len + 1), w, len);
    return n;
  }
  return repl(d, n, rnd(n + 1), 0, w, len);
}

static size_t mut_torc_int(uint8_t *d, size_t n) {
  size_t i = rnd(TORC_N), k = 0;
  while (k < TORC_N && !S->torc[(i + k) % TORC_N].sz) k++; /* next filled slot */
  cmp_pair c = S->torc[(i + k) % TORC_N];
  if (!c.sz) return n;
  uint64_t a = c.a, b = c.b;
  if (rnd(2)) a = c.b, b = c.a;
  b += rnd(4) ? 0 : (rnd(2) ? 1 : -1);
  if (rnd(4) == 0) { /* textual form */
    char sa[24], sb[24];
    int la = snprintf(sa, sizeof sa, "%llu", (unsigned long long)a), lb = snprintf(sb, sizeof sb, "%llu", (unsigned long long)b);
    int p = find_sub(d, n, (uint8_t *)sa, (size_t)la, rnd(n + 1));
    return p >= 0 ? repl(d, n, (size_t)p, (size_t)la, (uint8_t *)sb, (size_t)lb) : put_word(d, n, (uint8_t *)sb, (size_t)lb);
  }
  size_t w = c.sz > 8 ? 8 : c.sz;
  int be = (int)rnd(2);
  uint8_t pa[8], pb[8];
  put_int(pa, a, w, be), put_int(pb, b, w, be);
  int p = find_sub(d, n, pa, w, rnd(n + 1));
  if (p >= 0) {
    memcpy(d + p, pb, w);
    if (w >= 2) memcpy(last_word, pb, w), last_word_n = w;
    return n;
  }
  return put_word(d, n, pb, w);
}
static size_t mut_torc_mem(uint8_t *d, size_t n) {
  size_t i = rnd(MEMC_N), k = 0;
  while (k < MEMC_N && !S->memc[(i + k) % MEMC_N].lb) k++;
  mem_pair *m = &S->memc[(i + k) % MEMC_N];
  if (!m->lb) return n;
  uint8_t a[MEMC_LEN], b[MEMC_LEN];
  size_t la = m->la, lb = m->lb;
  memcpy(a, m->a, la), memcpy(b, m->b, lb);
  if (rnd(2)) {
    uint8_t t[MEMC_LEN];
    size_t lt = la;
    memcpy(t, a, la), memcpy(a, b, lb), la = lb, memcpy(b, t, lt), lb = lt;
  }
  int p = find_sub(d, n, a, la, rnd(n + 1));
  if (p >= 0 && rnd(4)) {
    if (lb >= 2) memcpy(last_word, b, lb), last_word_n = lb;
    return repl(d, n, (size_t)p, la, b, lb);
  }
  return put_word(d, n, b, lb);
}
static size_t mut_ascii_num(uint8_t *d, size_t n) {
  size_t i = rnd(n), j;
  while (i < n && (d[i] < '0' || d[i] > '9')) i++;
  if (i >= n) return n;
  int64_t v = 0;
  for (j = i; j < n && j - i < 18 && d[j] >= '0' && d[j] <= '9'; j++) v = v * 10 + (d[j] - '0');
  switch (rnd(6)) {
  case 0: v++; break;
  case 1: v--; break;
  case 2: v *= 2; break;
  case 3: v /= 2; break;
  case 4: v = (int64_t)rnd(1000); break;
  default: v = interesting[rnd(N_INTERESTING)];
  }
  char s[24];
  int l = snprintf(s, sizeof s, "%lld", (long long)v);
  return repl(d, n, i, j - i, (uint8_t *)s, (size_t)l);
}

static size_t mutate(uint8_t *d, size_t n) {
  last_word_n = 0;
  for (int it = 0, iters = 1 << rnd(5); it < iters; it++) {
    size_t pos, len, w;
    int be = (int)rnd(2);
    switch (n ? rnd(16) : 5) {
    case 0: d[rnd(n)] ^= (uint8_t)(1u << rnd(8)); break;
    case 1: d[rnd(n)] = (uint8_t)rnd(256); break;
    case 2:
      w = (size_t)1 << rnd(4);
      if (n >= w) put_int(d + rnd(n - w + 1), (uint64_t)interesting[rnd(N_INTERESTING)], w, be);
      break;
    case 3:
      w = (size_t)1 << rnd(4);
      if (n >= w) {
        pos = rnd(n - w + 1);
        put_int(d + pos, get_int(d + pos, w, be) + (rnd(2) ? 1 : -1) * (int64_t)(1 + rnd(35)), w, be);
      }
      break;
    case 4:
      if (n > 1) len = blen(n - 1), pos = rnd(n - len + 1), memmove(d + pos, d + pos + len, n - pos - len), n -= len;
      break;
    case 5:
      if (n < mut_cap) {
        len = blen(mut_cap - n < 128 ? mut_cap - n : 128);
        if (rnd(2)) memset(tmp, (int)rnd(256), len);
        else for (size_t k = 0; k < len; k++) tmp[k] = (uint8_t)rnd(256);
        n = repl(d, n, rnd(n + 1), 0, tmp, len);
      }
      break;
    case 6:
      if (n > 1) len = blen(n - 1), memmove(d + rnd(n - len + 1), d + rnd(n - len + 1), len);
      break;
    case 7:
      len = blen(n), pos = rnd(n - len + 1), memcpy(tmp, d + pos, len), n = repl(d, n, rnd(n + 1), 0, tmp, len);
      break;
    case 8:
    case 9: {
      if (!ncorp) break;
      entry_t *o = &corp[rnd(ncorp)];
      if (!o->size) break;
      len = blen(o->size), pos = rnd(o->size - len + 1);
      if (rnd(2) && n >= len) memcpy(d + rnd(n - len + 1), o->data + pos, len);
      else n = repl(d, n, rnd(n + 1), 0, o->data + pos, len);
      break;
    }
    case 10:
      if (ndict) {
        size_t k = rnd(ndict);
        n = put_word(d, n, dict[k].d, dict[k].n);
        break;
      }
      /* fallthrough */
    case 11: n = mut_torc_int(d, n); break;
    case 12:
    case 13: n = mut_torc_mem(d, n); break;
    case 14: n = mut_ascii_num(d, n); break;
    case 15:
      if (n > 2) {
        len = blen(n < 8 ? n : 8), pos = rnd(n - len + 1);
        for (size_t k = len - 1; k > 0; k--) {
          size_t j = rnd(k + 1);
          uint8_t t = d[pos + k];
          d[pos + k] = d[pos + j], d[pos + j] = t;
        }
      }
      break;
    }
  }
  return n;
}

/* libFuzzer API for custom mutators (LLVMFuzzerCustomMutator): one round of the
 * built-in mutations, in place, keeping the input at most max_size bytes. */
size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size) {
  size_t cap = mut_cap;
  mut_cap = max_size < O.max_len ? max_size : O.max_len; /* tmp holds O.max_len bytes */
  size_t n = mutate(data, size < mut_cap ? size : mut_cap);
  mut_cap = cap;
  return n;
}

/* AFL/libFuzzer dictionary: lines of  [name=]"value"  with \xNN escapes. */
static void load_dict(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) { perror(path); exit(1); }
  char line[4096];
  while (fgets(line, sizeof line, f) && ndict < sizeof dict / sizeof *dict) {
    char *q = strchr(line, '"'), *e = strrchr(line, '"');
    if (!q || e == q || line[strspn(line, " \t")] == '#') continue;
    uint8_t buf[4096];
    size_t n = 0;
    for (char *p = q + 1; p < e; p++) {
      if (*p == '\\' && p[1] == 'x' && e - p > 3) {
        unsigned v;
        sscanf(p + 2, "%2x", &v), buf[n++] = (uint8_t)v, p += 3;
      } else if (*p == '\\' && p + 1 < e) buf[n++] = (uint8_t) * ++p;
      else buf[n++] = (uint8_t)*p;
    }
    if (n) dict[ndict].d = malloc(n), memcpy(dict[ndict].d, buf, n), dict[ndict++].n = n;
  }
  fclose(f);
  fprintf(stderr, "llmfuzz: dictionary %s: %zu entries\n", path, ndict);
}

/* ------------------------------------------------------------------------ */
/* Crashes, timeouts, signals.                                               */
typedef int (*test_fn)(const uint8_t *, size_t);
static test_fn TestOneInput;
static size_t (*CustomMutator)(uint8_t *, size_t, size_t, unsigned int); /* the harness's, if it has one */
static volatile pid_t child_pid;
static volatile int child_timed_out, child_oom;
static const char *child_err = "/dev/null";

static void save_artifact(const char *kind, char *path, size_t pathsz) {
  snprintf(path, pathsz, "%s%s-%016llx", O.artifact_prefix, kind, (unsigned long long)hash64(cur, cur_n));
  write_file(path, cur, cur_n);
}

/* Inputs replayed from disk that killed a run (crash, timeout, oom) are listed in
 * ARTIFACT_PREFIX.llmfuzz-skip, so that a restarted worker does not die on them again. */
static void skip_path(char *out, size_t n) { snprintf(out, n, "%s.llmfuzz-skip", O.artifact_prefix); }
static void load_skips(void) {
  char p[4096], line[4200];
  skip_path(p, sizeof p);
  FILE *f = fopen(p, "r");
  if (!f) return;
  while (fgets(line, sizeof line, f)) {
    line[strcspn(line, "\n")] = 0;
    if (line[0]) hs_add(hash64((const uint8_t *)line, strlen(line)));
  }
  fclose(f);
}

static volatile int dying;
static void die_inprocess(const char *kind, int code) {
  if (dying++) return;
  char p[4096];
  if (cur_from_disk && qpos > 0) {
    skip_path(p, sizeof p);
    int fd = open(p, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
      char line[4200];
      int k = snprintf(line, sizeof line, "%s\n", queue[qpos - 1]);
      if (k > 0 && write(fd, line, (size_t)k) < 0) {}
      close(fd);
    }
  }
  save_artifact(kind, p, sizeof p);
  n_crashes++;
  fprintf(stderr, "==llmfuzz== %s after %.2fs, %llu execs; artifact: %s\n", kind, run_start - t_start,
          (unsigned long long)execs, p);
  print_stats("DONE ");
  if (code) _exit(code);
}
static void on_death(void) { die_inprocess("crash", 0); }
static void on_signal(int sig) {
  if ((sig == SIGINT || sig == SIGTERM) && !running) { stop_req = 1; return; }
  if (sig == SIGINT || sig == SIGTERM) {
    if (child_pid > 0) kill(-child_pid, SIGKILL), kill(child_pid, SIGKILL);
    print_stats("DONE ");
    _exit(0);
  }
  fprintf(stderr, "==llmfuzz== deadly signal %d\n", sig);
  if (EXT(__sanitizer_print_stack_trace)) EXT(__sanitizer_print_stack_trace)();
  die_inprocess("crash", 0);
  signal(sig, SIG_DFL);
  raise(sig);
}
static long child_rss_mb(pid_t pid) {
#ifdef __APPLE__
  struct proc_taskinfo ti;
  return proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, sizeof ti) == (int)sizeof ti ? (long)(ti.pti_resident_size >> 20) : 0;
#else
  char p[64], b[128];
  snprintf(p, sizeof p, "/proc/%d/statm", (int)pid);
  int fd = open(p, O_RDONLY);
  ssize_t k = fd < 0 ? -1 : read(fd, b, sizeof b - 1);
  if (fd >= 0) close(fd);
  if (k <= 0) return 0;
  b[k] = 0;
  char *r = strchr(b, ' ');
  return r ? strtol(r + 1, NULL, 10) * (sysconf(_SC_PAGESIZE) >> 10) >> 10 : 0;
#endif
}
static void on_alarm(int sig) {
  (void)sig;
  double el = now() - run_start;
  if (O.fork) {
    if (child_pid > 0 && el > O.timeout) child_timed_out = 1, kill(-child_pid, SIGKILL), kill(child_pid, SIGKILL);
    else if (child_pid > 0 && O.rss_limit_mb && child_rss_mb(child_pid) > O.rss_limit_mb)
      child_oom = 1, kill(-child_pid, SIGKILL), kill(child_pid, SIGKILL);
    return;
  }
  if (dying || (EXT(__asan_report_present) && EXT(__asan_report_present)())) return; /* report in progress */
  if (running && el > O.timeout) {
    fprintf(stderr, "==llmfuzz== timeout: input ran for %.1fs\n", el);
    if (EXT(__sanitizer_print_stack_trace)) EXT(__sanitizer_print_stack_trace)();
    die_inprocess("timeout", 70);
  }
  if (O.rss_limit_mb && rss_mb() > O.rss_limit_mb) {
    fprintf(stderr, "==llmfuzz== out-of-memory: rss %ldMb > %ldMb\n", rss_mb(), O.rss_limit_mb);
    die_inprocess("oom", 71);
  }
}
static void on_malloc(const volatile void *p, size_t sz) {
  (void)p;
  if (running && O.malloc_limit_mb && sz > (size_t)O.malloc_limit_mb << 20) {
    static volatile int in;
    if (in++) return;
    fprintf(stderr, "==llmfuzz== out-of-memory: malloc(%zu)\n", sz);
    if (EXT(__sanitizer_print_stack_trace)) EXT(__sanitizer_print_stack_trace)();
    if (O.fork) S->crashed = 3, _exit(71); /* fork child: the parent records the oom */
    die_inprocess("oom", 71);
  }
}
static void on_free(const volatile void *p) { (void)p; }
static void child_death(void) { S->crashed = 1; }

static void install_handlers(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_alarm;
  sa.sa_flags = SA_RESTART; /* don't break the sanitizer's symbolizer pipes */
  sigaction(SIGALRM, &sa, NULL);
  double iv = O.fork ? (O.timeout < 1 ? O.timeout / 4 : 0.1) : (O.timeout < 2 ? O.timeout / 2 : 1);
  struct itimerval it = {{(long)iv, (long)((iv - (long)iv) * 1e6)}, {(long)iv, (long)((iv - (long)iv) * 1e6)}};
  setitimer(ITIMER_REAL, &it, NULL);
  sa.sa_handler = on_signal;
  sigaction(SIGINT, &sa, NULL), sigaction(SIGTERM, &sa, NULL);
  if (O.fork) return;
  if (EXT(__sanitizer_set_death_callback)) EXT(__sanitizer_set_death_callback)(on_death);
  if (O.malloc_limit_mb && EXT(__sanitizer_install_malloc_and_free_hooks))
    EXT(__sanitizer_install_malloc_and_free_hooks)(on_malloc, on_free);
  int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT};
  for (size_t i = 0; i < sizeof sigs / sizeof *sigs; i++) { /* keep sanitizer handlers */
    struct sigaction old;
    if (!sigaction(sigs[i], NULL, &old) && old.sa_handler == SIG_DFL) sigaction(sigs[i], &sa, NULL);
  }
}

/* Child side of fork mode: quiet stdout, capture stderr, flag crashes. */
static void child_setup(void) {
  struct itimerval off = {{0, 0}, {0, 0}};
  setitimer(ITIMER_REAL, &off, NULL);
  signal(SIGALRM, SIG_DFL), signal(SIGINT, SIG_DFL), signal(SIGTERM, SIG_DFL);
  setpgid(0, 0);
  int fd = open("/dev/null", O_RDWR);
  if (fd >= 0) dup2(fd, 1), close(fd);
  fd = open(child_err, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) dup2(fd, 2), close(fd);
  if (O.use_stdin && O.input_file && (fd = open(O.input_file, O_RDONLY)) >= 0) dup2(fd, 0), close(fd);
  if (EXT(__sanitizer_set_death_callback)) EXT(__sanitizer_set_death_callback)(child_death);
  if (O.malloc_limit_mb && EXT(__sanitizer_install_malloc_and_free_hooks))
    EXT(__sanitizer_install_malloc_and_free_hooks)(on_malloc, on_free);
}
static int wait_child(pid_t pid) { /* 0 ok, 1 crash, 2 timeout, 3 oom */
  int st = 0;
  child_pid = pid;
  while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
  child_pid = 0, running = 0;
  if (child_timed_out) return 2;
  if (child_oom || S->crashed == 3) return 3;
  if (S->crashed || (WIFSIGNALED(st) && WTERMSIG(st) != SIGPIPE && WTERMSIG(st) != SIGKILL)) return 1;
  return 0;
}
static void prepare_run(void) {
  memset(CNT, 0, n_guards + 1);
  S->vp_n = 0, S->crashed = 0, child_timed_out = 0, child_oom = 0;
  run_start = now(), running = 1;
}

/* ------------------------------------------------------------------------ */
/* Engine: next input / feedback.                                            */
static void queue_push(const char *path) {
  if (nqueue == capqueue) queue = realloc(queue, (capqueue = capqueue ? 2 * capqueue : 256) * sizeof *queue);
  queue[nqueue++] = strdup(path);
}
static void scan_dir(const char *dir, int initial) {
  DIR *dd = opendir(dir);
  if (!dd) return;
  struct dirent *de;
  char p[4096];
  struct stat st;
  while ((de = readdir(dd))) {
    snprintf(p, sizeof p, "%s/%s", dir, de->d_name);
    if (de->d_name[0] == '.' || !hs_add(hash64((const uint8_t *)p, strlen(p)))) continue;
    if (stat(p, &st) || !S_ISREG(st.st_mode)) continue;
    if (initial && !O.max_len_set && (size_t)st.st_size > O.max_len)
      O.max_len = st.st_size < (1 << 20) ? (size_t)st.st_size : (1 << 20);
    queue_push(p);
  }
  closedir(dd);
}

static void engine_init(void) {
  rs = ((O.seed ? O.seed : (uint64_t)time(NULL) * 2654435761u ^ (uint64_t)getpid()) * 0x9E3779B97F4A7C15ull) | 1;
  guards_frozen = 1;
  if (!n_guards) fprintf(stderr, "llmfuzz: no coverage instrumentation found (build with llmfuzz-cc)\n"), exit(1);
  load_weights();
  size_t nf = 8 * ((size_t)n_guards + 1);
  fhits = calloc(nf, 4), fseen = calloc(nf, 1), eseen = calloc(n_guards + 1, 1), crash_seen = calloc(n_guards + 1, 1);
  cur_ft = malloc((n_guards + 1) * 4), new_ft = malloc((n_guards + 1 + VPL_CAP) * 4);
  vpseen = calloc(VP_BITS / 8, 1), vphits = calloc(VP_BITS, 2);
  for (int c = 1; c < 256; c++) bucket[c] = c < 4 ? c - 1 : c < 8 ? 3 : c < 16 ? 4 : c < 32 ? 5 : c < 128 ? 6 : 7;
  load_skips();
  for (int i = 0; i < n_paths; i++) {
    struct stat st;
    if (stat(paths[i], &st)) continue;
    if (S_ISDIR(st.st_mode)) {
      if (!out_dir) out_dir = paths[i];
      scan_dir(paths[i], 1);
    } else queue_push(paths[i]);
  }
  cur = malloc(O.max_len + 1), tmp = malloc(O.max_len + 1);
  if (O.dict) load_dict(O.dict);
  if (O.stats) stats_f = fopen(O.stats, "a");
  static char errpath[4096];
  if (O.fork) snprintf(errpath, sizeof errpath, "%s.stderr-%d", O.artifact_prefix, (int)getpid()), child_err = errpath;
  CustomMutator = EXT(LLVMFuzzerCustomMutator);
  install_handlers();
  fprintf(stderr, "llmfuzz: %u edges, %u hot (w>=%.1f), gamma=%.2f vp=%d max_len=%zu mode=%s%s seed=%llu\n", n_guards,
          n_hot, O.hot, O.gamma, vp_mode, O.max_len, O.fork ? "fork" : "in-process",
          CustomMutator ? " custom-mutator" : "", (unsigned long long)rs);
  t_start = t_last_print = t_last_reload = now();
}

static int engine_next(void) {
  double t = now();
  if (stop_req || (O.runs && execs >= O.runs) || (O.max_time && t - t_start >= O.max_time)) return 0;
  if (t - t_last_print >= O.print_secs) print_stats("pulse"), t_last_print = t;
  if (out_dir && O.reload > 0 && t - t_last_reload >= O.reload) scan_dir(out_dir, 0), t_last_reload = t;
  cur_parent = UINT32_MAX;
  if (qpos < nqueue) {
    uint8_t *d = read_file(queue[qpos++], &cur_n, O.max_len);
    if (!d) cur_n = 0;
    else memcpy(cur, d, cur_n), free(d);
    cur_from_disk = 1;
    if (qpos == nqueue && ncorp && !inited) inited = 1, print_stats("INITED");
    return 1;
  }
  cur_from_disk = 0;
  if (!ncorp) { /* nothing kept yet (fork mode: every input so far crashed): try small random inputs */
    size_t m = O.max_len < 16 ? O.max_len : 16;
    cur_n = execs && m ? 1 + rnd(m) : 0;
    for (size_t k = 0; k < cur_n; k++) cur[k] = (uint8_t)rnd(256);
    return 1;
  }
  if (!mut_cap) { /* start small: max(4, largest corpus input) */
    mut_cap = 4;
    for (uint32_t k = 0; k < ncorp; k++) mut_cap = corp[k].size > mut_cap ? corp[k].size : mut_cap;
    if (!O.len_control || mut_cap > O.max_len) mut_cap = O.max_len;
    last_new_exec = execs;
  }
  size_t lg = 64 - (size_t)__builtin_clzll(mut_cap | 1);
  if (mut_cap < O.max_len && execs - last_new_exec > O.len_control * lg) /* stuck: allow longer inputs */
    mut_cap = mut_cap + lg < O.max_len ? mut_cap + lg : O.max_len, last_new_exec = execs;
  if (!n_cum || (energy_dirty && execs - last_energy >= 128) || execs - last_energy >= 4096) recompute_energy();
  cur_parent = choose_seed();
  entry_t *e = &corp[cur_parent];
  e->fuzzed++;
  memcpy(cur, e->data, e->size);
  if (CustomMutator) { /* libFuzzer semantics: the harness's mutator replaces ours (it may call LLVMFuzzerMutate) */
    size_t cap = mut_cap > e->size ? mut_cap : e->size;
    cur_n = CustomMutator(cur, e->size, cap, (unsigned int)rnd(UINT32_MAX));
    if (cur_n > cap) cur_n = cap;
  } else cur_n = mutate(cur, e->size);
  return 1;
}

static void engine_feedback(int status) {
  execs++;
  collect();
  if (status) { /* fork mode: crash (1), timeout (2) or oom (3); keep coverage-unique ones */
    int uniq = 0;
    for (uint32_t k = 0; k < cur_nft; k++)
      if (!crash_seen[cur_ft[k] >> 3]) crash_seen[cur_ft[k] >> 3] = 1, uniq = 1;
    if (!uniq) return;
    char p[4096], q[4200];
    const char *kind = status == 1 ? "crash" : status == 2 ? "timeout" : "oom";
    save_artifact(kind, p, sizeof p);
    snprintf(q, sizeof q, "%s.txt", p);
    rename(child_err, q);
    n_crashes++;
    fprintf(stderr, "==llmfuzz== %s after %.2fs, %llu execs; artifact: %s (report %s)\n", kind, now() - t_start,
            (unsigned long long)execs, p, q);
    return;
  }
  if (n_new || !ncorp) add_entry();
}

static void engine_fini(void) {
  print_stats("DONE ");
  if (O.cov_dump) {
    FILE *f = fopen(O.cov_dump, "w");
    for (uint32_t e = 1; f && e <= n_guards; e++)
      if (eseen[e]) fprintf(f, "0x%lx\n", (unsigned long)PCU[e]);
    if (f) fclose(f);
  }
  if (stats_f) fclose(stats_f);
}

/* ------------------------------------------------------------------------ */
/* Entry points.                                                             */
static int run_inprocess(void) {
  uint8_t *copy = exact_copy(cur, cur_n);
  prepare_run();
  TestOneInput(copy, cur_n);
  running = 0;
  free(copy);
  return 0;
}
static int run_fork_harness(void) {
  prepare_run();
  pid_t pid = fork();
  if (pid == 0) {
    child_setup();
    TestOneInput(exact_copy(cur, cur_n), cur_n);
    _exit(0);
  }
  return pid < 0 ? 0 : wait_child(pid);
}

int LLVMFuzzerRunDriver(int *argc, char ***argv, int (*cb)(const uint8_t *, size_t)) {
  TestOneInput = cb;
  if (!TestOneInput) {
    fprintf(stderr, "llmfuzz: LLVMFuzzerTestOneInput not found\n");
    return 1;
  }
  int n_files = 0;
  for (int i = 1; i < *argc; i++) {
    const char *a = (*argv)[i];
    if (parse_flag(a)) continue;
    struct stat st;
    if (n_paths < 256) paths[n_paths++] = a;
    if (!stat(a, &st) && S_ISREG(st.st_mode)) n_files++;
  }
  if (O.dump_pcs) { dump_pcs(O.dump_pcs); return 0; }
  if (EXT(LLVMFuzzerInitialize)) EXT(LLVMFuzzerInitialize)(argc, argv);
  if (n_files && n_files == n_paths) { /* reproduce mode: run the given files once */
    for (int i = 0; i < n_paths; i++) {
      size_t n;
      uint8_t *f = read_file(paths[i], &n, 1 << 30), *d = f ? exact_copy(f, n) : NULL;
      if (!d) continue;
      free(f);
      fprintf(stderr, "llmfuzz: running %s (%zu bytes)\n", paths[i], n);
      double t0 = now();
      TestOneInput(d, n);
      fprintf(stderr, "llmfuzz: executed %s in %.0f ms\n", paths[i], (now() - t0) * 1e3);
      free(d);
    }
    return 0;
  }
  engine_init();
  if (O.close_stdout) {
    int fd = open("/dev/null", O_WRONLY);
    if (fd >= 0) dup2(fd, 1), close(fd);
  }
  while (engine_next()) engine_feedback(O.fork ? run_fork_harness() : run_inprocess());
  engine_fini();
  return 0;
}

/* Program mode: fork server started before main(). Each child returns from
 * this constructor and runs the real main() on the current input. */
__attribute__((constructor)) static void llmfuzz_program_mode(void) {
  if (EXT(LLVMFuzzerTestOneInput)) return;
  const char *dp = getenv("LLMFUZZ_DUMP_PCS");
  if (dp) { dump_pcs(dp); _exit(0); }
  const char *env = getenv("LLMFUZZ_OPTIONS");
  if (!env) return;
  char *opts = strdup(env), *save = NULL;
  for (char *t = strtok_r(opts, " ", &save); t; t = strtok_r(NULL, " ", &save))
    if (!parse_flag(t) && n_paths < 256) paths[n_paths++] = t;
  O.fork = 1;
  if (!O.input_file) O.use_stdin = 1, O.input_file = ".llmfuzz_cur_input";
  if (!O.input_file[0]) O.input_file = ".llmfuzz_cur_input";
  engine_init();
  while (engine_next()) {
    write_file(O.input_file, cur, cur_n);
    prepare_run();
    pid_t pid = fork();
    if (pid == 0) {
      child_setup();
      unsetenv("LLMFUZZ_OPTIONS");
      return; /* continue into the target's main() */
    }
    engine_feedback(pid < 0 ? 0 : wait_child(pid));
  }
  engine_fini();
  _exit(0);
}

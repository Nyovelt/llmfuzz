// A tiny key/value record parser used as the quick-start example (see README).
#include <stdint.h>
#include <string.h>

struct rec {
  char key[16];
  uint8_t type;
  uint32_t value;
};

static uint32_t fnv1a(const uint8_t *p, size_t n) {
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 16777619u;
  return h;
}

static int read_header(const uint8_t *p, size_t n, unsigned *count) {
  if (n < 8 || memcmp(p, "KVDB", 4) != 0) return -1;
  *count = p[4] | p[5] << 8;
  if (*count == 0 || *count > 64) return -1;
  return 8;
}

static int read_record(const uint8_t *p, size_t n, struct rec *r) {
  if (n < 6) return -1;
  size_t klen = p[0];
  if (klen == 0 || n < klen + 6) return -1;
  memcpy(r->key, p + 1, klen);
  r->key[klen] = 0;
  r->type = p[klen + 1];
  memcpy(&r->value, p + klen + 2, 4);
  return (int)klen + 6;
}

static int apply(const struct rec *r, uint32_t *acc) {
  switch (r->type) {
  case 1: *acc += r->value; break;
  case 2: *acc ^= r->value; break;
  case 3: *acc = fnv1a((const uint8_t *)r->key, strlen(r->key)); break;
  default: return -1;
  }
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned count;
  int off = read_header(data, size, &count);
  if (off < 0) return 0;
  uint32_t acc = 0;
  for (unsigned i = 0; i < count && (size_t)off < size; i++) {
    struct rec r;
    int k = read_record(data + off, size - off, &r);
    if (k < 0 || apply(&r, &acc) < 0) break;
    off += k;
  }
  return 0;
}

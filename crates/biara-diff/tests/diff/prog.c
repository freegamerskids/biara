// Two variants of one program (tests/diff.rs): `v1` and `v2` differ in
// exactly one function body (`total`: a wider buffer and doubled sum), one
// function exists only in v1 (`gone`), and one only in v2 (`fresh`).
// Everything else (`show`, `_start` aside: it calls different functions)
// is byte-identical code.

#define NOINLINE __attribute__((noinline))

int printf(const char *f, ...);
void _start(void);

static void *my_memcpy(void *d, const void *s, unsigned long n) {
  char *a = d;
  const char *b = s;
  for (unsigned long i = 0; i < n; i++)
    a[i] = b[i];
  return d;
}
#define memcpy my_memcpy

#ifdef V2
__attribute__((noinline)) long total(const char *s, unsigned long n) {
  char b[64];
  memcpy(b, s, n & 0x3f);
  long t = 0;
  for (unsigned i = 0; i < 64; i++)
    t += 2 * b[i];
  return t;
}
#else
__attribute__((noinline)) long total(const char *s, unsigned long n) {
  char b[32];
  memcpy(b, s, n & 0x1f);
  long t = 0;
  for (unsigned i = 0; i < 32; i++)
    t += b[i];
  return t;
}
#endif

__attribute__((noinline)) void show(const char *s) { printf("%s\n", s); }

NOINLINE long fib(long n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

#ifdef V2
NOINLINE long scale(long x, long y) { return x ^ y; }
#else
NOINLINE long scale(long x, long y) { return x + y; }
#endif

#ifdef V2
NOINLINE long sel(long x) {
  long t = 0;
  if (x > 0) {
    for (long i = 0; i < x; i++)
      t += 2;
  } else {
    for (long i = 0; i < -x; i++)
      t += 1;
  }
  return t;
}
#else
NOINLINE long sel(long x) {
  long t = 0;
  if (x > 0) {
    for (long i = 0; i < x; i++)
      t += 1;
  } else {
    for (long i = 0; i < -x; i++)
      t += 2;
  }
  return t;
}
#endif

#ifndef V2
NOINLINE long gone(long x) { long t = 0; for (long i = 0; i < x; i++) t += i; return t + 1; }
#else
NOINLINE long fresh(long x) { return (x | 7) ^ (x >> 2); }
#endif

void _start(void) {
  (void)fib(10);
  (void)scale(3, 4);
  (void)sel(3);
  show("hi");
  total("ab", 2);
#ifdef V2
  fresh(4);
#else
  gone(4);
#endif
  for (;;) {
  }
}

// Edge-range regression corpus (tests/edge_ranges.rs). Each function has a
// matching test assertion. `main` calls every function with fixed boundary
// inputs and exits nonzero unless the computed lengths match their expected
// sum, so native exit 0 is concrete ground truth (not just "it ran").
//
// Build: dynamic libc via the compiler default (like tests/audit/objects.c:
// -O{0,2} -fno-builtin -fno-stack-protector -fno-pie -no-pie), so `memcpy`
// and `main(argc, argv)` are real imports the lifter recognizes.
#include <stddef.h>
#include <string.h>

#define NOINLINE __attribute__((noinline))

// Branch-derived arithmetic bound through multiplication: `n < 48` checked,
// `n * 2` passed. Baseline LVI sees no comparison on `n * 2` itself (full);
// the edge walk must transfer the guard: [0, 94] (n = 0 gives 0, n = 47
// gives 94). Non-tautological: an `n + 8` variant is already [8, 56) at
// baseline and would not catch a missing refinement.
NOINLINE unsigned guard_mul(char *dst, const char *src, unsigned n) {
  if (n >= 48)
    return 0;
  unsigned m = n * 2;
  memcpy(dst, src, m);
  return m;
}

// Branch-derived bound through xor: `n < 48` checked, `n ^ 63` passed.
// x in [0, 48) maps to [16, 63] (63 - x on the low 6 bits). Baseline full;
// refined [16, 63].
NOINLINE unsigned guard_xor(char *dst, const char *src, unsigned n) {
  if (n >= 48)
    return 0;
  unsigned m = n ^ 63u;
  memcpy(dst, src, m);
  return m;
}

// Import-write length through a guarded bound: `n < 24` checked, `n * 2`
// written: refined length within [0, 46].
NOINLINE unsigned audit_edge(char *dst, const char *src, unsigned n) {
  if (n >= 24)
    return 0;
  unsigned m = n * 2;
  memcpy(dst, src, m);
  return m;
}

// Disjunction with genuinely distinct arms: arm A only admits 0, arm B only
// 64. The joined length must hull to cover both (lo 0 and hi 64 feasible),
// never narrow to one arm.
NOINLINE unsigned disjoined(char *dst, const char *src, unsigned n, int which) {
  unsigned m;
  if (which)
    m = n - n + 64; // 64 for every input on this arm
  else
    m = n - n; // 0 for every input on this arm
  if (m != 0 && m != 64)
    return 0;
  memcpy(dst, src, m);
  return m;
}

// Signed narrow check over the full width: the guard `(signed char)n >= 0`
// excludes low bytes [128, 255] but the copied value is the full `n`, so
// n = 256 and n = 257 are both feasible and must stay contained. A tight
// contiguous [0, 127] full-width bound would be unsound. (Backing below is
// 1024 bytes so these copies are in-bounds at runtime.)
NOINLINE unsigned signed_wrap(char *dst, const char *src, unsigned n) {
  signed char c = (signed char)n;
  if (c < 0)
    return 0;
  memcpy(dst, src, n);
  return n;
}

// Loop clamp: `i` counts up to `n` but saturates at 32. The loop walk must
// converge (bounded work) with the length within [0, 32]; i = 0 (n = 0)
// and i = 32 (large n) are both feasible.
NOINLINE unsigned loop_clamp(char *dst, const char *src, unsigned n) {
  unsigned i = 0;
  while (i < n && i < 32)
    i++;
  memcpy(dst, src, i);
  return i;
}

// Unbounded loop: no clamp; the length stays unknown (or at least wide
// enough to contain large n) and must not become a spurious tight bound.
NOINLINE unsigned loop_open(char *dst, const char *src, unsigned n) {
  unsigned i = 0;
  while (i < n)
    i++;
  memcpy(dst, src, i);
  return i;
}

// Jump-table index through a guard: `n < 3` guards `table[n]`. Recovery must
// find exactly {a, b, c} as exhaustive.
typedef void (*Handler)(void);
NOINLINE void handle_a(void) {}
NOINLINE void handle_b(void) {}
NOINLINE void handle_c(void) {}
NOINLINE void table_edge(unsigned n) {
  if (n >= 3)
    return;
  static Handler const table[] = {handle_a, handle_b, handle_c};
  unsigned m = n + 0;
  Handler h = table[m];
  __asm__ volatile("" : "+r"(h));
  h();
}

// Sparse switch with a default arm over gaps: cases {1, 3} plus default.
// The default arm's complement fact must not exclude the gap value 2: the
// value reaching the sink on the default path with n = 2 is 2.
static volatile unsigned sparse_value;
NOINLINE void sparse_sink(unsigned v) { sparse_value = v; }
NOINLINE void sparse_switch(unsigned n) {
  unsigned v;
  switch (n) {
  case 1:
    v = 7;
    break;
  case 3:
    v = 11;
    break;
  default:
    v = n;
    break;
  }
  sparse_sink(v);
}

char backing[1024];
char sink_backing[1024];

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  // Boundary inputs whose lengths the test requires the recovered bounds to
  // contain. The summed return values pin them: exit 0 iff every length
  // below is exactly as stated (0+94 + 63+16 + 2+46 + 0+64 + 256+257 +
  // 0+32 + 300 = 1130).
  unsigned sum = 0;
  sum += guard_mul(backing, backing, 0);    // 0
  sum += guard_mul(backing, backing, 47);   // 94
  sum += guard_xor(backing, backing, 0);    // 63
  sum += guard_xor(backing, backing, 47);   // 16
  sum += audit_edge(backing, backing, 1);   // 2
  sum += audit_edge(backing, backing, 23);  // 46
  sum += disjoined(backing, backing, 5, 0); // 0
  sum += disjoined(backing, backing, 5, 1); // 64
  sum += signed_wrap(backing, backing, 256); // 256
  sum += signed_wrap(backing, backing, 257); // 257
  sum += loop_clamp(backing, backing, 0);   // 0
  sum += loop_clamp(backing, backing, 100); // 32
  sum += loop_open(backing, backing, 300);  // 300
  table_edge(0);
  table_edge(2);
  sparse_switch(2); // gap value through default
  if (sparse_value != 2) return 2;
  sparse_switch(9); // far default value
  memcpy(sink_backing, backing, 1);
  return sum == 1130 && sparse_value == 9 ? 0 : 1;
}

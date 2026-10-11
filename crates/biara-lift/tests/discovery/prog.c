// Function discovery corpus (tests/discovery.rs): every function here must
// be found in the stripped binary, each in its own way, and nothing else.

typedef long (*binop)(long, long);

#define NOINLINE __attribute__((noinline))

// Only referenced from a table of pointers in data.
NOINLINE static long add(long a, long b) { return a + b; }
NOINLINE static long sub(long a, long b) { return a - b; }
NOINLINE static long mul(long a, long b) { return a * b ^ b; }
// Writable and external: the compiler cannot turn the calls direct.
binop ops[] = {add, sub, mul};

// Only referenced as a pointer passed to another function.
NOINLINE static long twice(long a, long b) { return 2 * a + b; }

// Only referenced as a pointer stored to memory.
NOINLINE static long mix(long a, long b) { return a ^ (b << 3); }
binop volatile hook;

// Called directly (external, so the pointer argument stays one).
NOINLINE long apply(binop f, long a, long b) { return f(a, b); }

// Label addresses in data are code pointers too, but not functions.
NOINLINE long dispatch(long op) {
  static void *const labels[] = {&&one, &&two};
  goto *labels[op & 1];
one:
  return op + 1;
two:
  return op * 3;
}

// Never referenced: only unwind information tells it is there.
NOINLINE long orphan(long x) { return x * 7 + 1; }

NOINLINE long run(long n) {
  long acc = 0;
  for (long i = 0; i < n; i++)
    acc = ops[i % 3](acc, i);
  hook = mix;
  acc = apply(twice, acc, n) + dispatch(acc);
  return hook(acc, n);
}

// The entry point.
void _start(void) {
  volatile long sink = run(10);
  (void)sink;
  for (;;) {
  }
}

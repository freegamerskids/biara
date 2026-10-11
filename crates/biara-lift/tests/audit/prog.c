// Audit corpus (tests/audit.rs): each `bad_*` function has exactly the
// finding its comment names (at its own calls or, for `bad_fill`, at the
// call it leads to in `fill`), each `ok_*` function none.

typedef __SIZE_TYPE__ size_t;
typedef long ssize_t;

int printf(const char *fmt, ...);
int puts(const char *s);
ssize_t read(int fd, void *buf, size_t n);
void *memcpy(void *dst, const void *src, size_t n);
char *strcpy(char *dst, const char *src);
char *dcgettext(const char *domain, const char *msgid, int category);
char *getenv(const char *name);
int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv,
                      void (*init)(void), void (*fini)(void),
                      void (*rtld_fini)(void), void *stack_end);

#define NOINLINE __attribute__((noinline))

#ifdef _WIN32
// The corpus uses floating point but links without the CRT.
int _fltused;
#endif

void sink(char *p);

char global_buf[64];
char *fmt_global;

// Overflow: 64 bytes into a 16-byte buffer.
NOINLINE long bad_read(void) {
  char buf[16];
  read(0, buf, 64);
  return buf[3];
}

NOINLINE long ok_read(void) {
  char buf[64];
  read(0, buf, sizeof buf);
  return buf[3];
}

// Overflow: up to 255 bytes into a 32-byte buffer.
NOINLINE long bad_copy(const char *s, size_t n) {
  char buf[32];
  memcpy(buf, s, n & 0xff);
  return buf[1];
}

NOINLINE long ok_copy(const char *s, size_t n) {
  char buf[32];
  memcpy(buf, s, n & 0x1f);
  return buf[1];
}

// Reads into its caller's buffer: fine or not depending on the caller.
NOINLINE void fill(char *p, size_t n) { read(0, p, n); }

// Overflow (at the read in fill): 64 bytes into this 16-byte buffer.
NOINLINE long bad_fill(void) {
  char buf[16];
  fill(buf, 64);
  return buf[2];
}

NOINLINE long ok_fill(void) {
  char buf[64];
  fill(buf, 64);
  return buf[2];
}

// Format: the command line (main passes argv[1]).
NOINLINE void bad_fmt_argv(const char *s) { printf(s); }

// Format: the command line (main passes argv).
NOINLINE void bad_fmt_args(char **args) { printf(args[2]); }

// Format: input that fill reads into this buffer.
NOINLINE void bad_fmt_filled(void) {
  char buf[64];
  fill(buf, sizeof buf);
  printf(buf);
}

// Format: the environment.
NOINLINE void bad_fmt_env(void) { printf(getenv("FMT")); }

// Format: input read into the stack.
NOINLINE void bad_fmt_input(void) {
  char buf[64];
  read(0, buf, sizeof buf);
  printf(buf);
}

// Format: called through a pointer, by callers unknown (main's direct
// call with a constant is not all).
NOINLINE void bad_fmt_hook(const char *s) { printf(s); }

// Format: loaded from a global, whose value no caller context can supply
// (globals are not tracked). Unresolvable by design: must stay a finding.
NOINLINE void bad_fmt_global(void) { printf(fmt_global); }
void (*volatile hook)(const char *) = bad_fmt_hook;

// A format wrapper whose callers all pass constants.
NOINLINE void ok_fmt_wrapper(const char *fmt) { printf(fmt); }

// A wrapper called with both constant and input formats: only the input
// call is a finding, and it names the input.
NOINLINE void mid_fmt_wrapper(const char *fmt) { printf(fmt); }

NOINLINE void ok_fmt(const char *s) { printf("%s\n", s); }

NOINLINE void ok_fmt_choice(const char *s, int loud) { printf(loud ? "%s!\n" : "%s\n", s); }

NOINLINE void ok_fmt_translated(const char *s) { printf(dcgettext(0, "hello %s\n", 5), s); }

// A translation stored before a call that leaks another slot: the load
// after the call must see through `sink(buf)` via the per-call check (`buf`
// sits below `fmt`, and no argument aliases `fmt`). Same shape as
// `ok_fmt_arg_kept`, with a returned value instead of an incoming one.
NOINLINE void ok_fmt_after_import(const char *s) {
  const char *fmt = dcgettext(0, "after %s\n", 5);
  char buf[32];
  sink(buf);
  printf(fmt, s);
  (void)buf;
}

// A translation across x87 traffic: the `volatile long double` spill and
// argument passing lower to FPU helpers (`fldt_ST0`, `fstt_ST0`, `fpop`,
// ...), and the format must survive them. The stack-only helpers
// (`fpush`/`fpop`/`fincstp`/`fdecstp`) leave every register global alone;
// the rest only touch their operand slot and FPU state. (No arithmetic:
// TFmode arithmetic would need soft-float calls on AArch64, which the
// stand-in link has no room for.)
NOINLINE void ok_fmt_long_double(void) {
  const char *fmt = dcgettext(0, "ld %Lf\n", 5);
  volatile long double t = 1.5L;
  printf(fmt, t);
}

// A caller argument across calls that leak another slot: `sink(buf)` hands
// out `buf`, so `a`'s slot needs the per-call check (no argument aliases
// it, and it lies above the stack pointer at each call); the second `sink`
// clobbers the argument registers on top of that. `a` is the format, so it
// is always in the first argument register.
NOINLINE void ok_fmt_arg_kept(const char *a) {
  char buf[32];
  sink(buf);
  sink((char *)a);
  printf(a);
  (void)buf;
}

// The translation stays in a callee-saved register across the calls (at
// -O2; at -O0 in a stack slot no call can reach).
NOINLINE void ok_fmt_kept(const char *s, int n) {
  const char *fmt = dcgettext(0, "%s again\n", 5);
  for (int i = 0; i < n; i++)
    printf(fmt, s);
}

// Handed a caller buffer; reads it (but the analyser cannot know the
// callee leaves it alone: the call below may clobber what was passed).
// The store keeps the call even where `printf(fmt, "x")` folds to puts.
NOINLINE void sink(char *p) { puts("sink"); global_buf[0] = p[0]; }

// The format slot survives a call that leaks a lower slot: the callee gets
// `s.buf`, so it cannot address `s.fmt`, and `s.fmt` lies above the stack
// pointer at the call, so the callee's own frame cannot reach it either.
// (At -O0 both are stack slots; at -O2 both tend to stay in registers.
// The struct forces the layout: a plain second local may end up adjacent
// above the first, which the function-wide rule already covers.)
NOINLINE void ok_fmt_kept_across_leak(void) {
  struct {
    char buf[32];
    const char *fmt;
  } s;
  s.fmt = "%s\n";
  sink(s.buf);
  printf(s.fmt, "x");
}

NOINLINE void set_fmt(const char **p) { *p = getenv("FMT"); }

// Format: the callee is handed the stack slot and changes it.
NOINLINE void bad_fmt_escaped(void) {
  const char *fmt = "%s\n";
  set_fmt(&fmt);
  printf(fmt, "x");
}

// Unbounded: strcpy into the stack.
NOINLINE long bad_strcpy(const char *s) {
  char buf[32];
  strcpy(buf, s);
  return buf[2];
}

NOINLINE void ok_strcpy(const char *s) { strcpy(global_buf, s); }

int main(int argc, char **argv, char **envp) {
  bad_read();
  ok_read();
  bad_copy("a", (size_t)argc);
  ok_copy("b", 4);
  bad_fill();
  ok_fill();
  bad_fmt_env();
  bad_fmt_input();
  hook("c");
  bad_fmt_hook("c");
  fmt_global = "g\n";
  bad_fmt_global();
  bad_fmt_filled();
  ok_fmt_wrapper("d\n");
  ok_fmt_wrapper("e\n");
  mid_fmt_wrapper("constant %d\n");
  mid_fmt_wrapper(argv[1]);
  ok_fmt("d");
  ok_fmt_after_import("f");
  ok_fmt_long_double();
  ok_fmt_choice("e", 1);
  ok_fmt_arg_kept("e");
  ok_fmt_translated("f");
  ok_fmt_kept("f", 2);
  ok_fmt_kept_across_leak();
  bad_strcpy("g");
  ok_strcpy("h");
  bad_fmt_escaped();
  // Last: at -O0 argv comes back from its stack slot after all the calls.
  bad_fmt_argv(argv[1]);
  bad_fmt_args(argv);
  return 0;
}

#ifndef _WIN32
void _start(void) {
  __libc_start_main(main, 0, 0, 0, 0, 0, 0);
  for (;;) {
  }
}
#endif

// Recovery fixtures are executable checks, not a vulnerability oracle.
// fib mirrors the recursion in the diff corpus; checks exercises both bounds
// branches without invoking the undefined overflows in the audit corpus.
#include <stdio.h>
#include <string.h>

#define KEEP __attribute__((noinline))
typedef long (*operation)(long);

KEEP long fib(long n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
KEEP long plus(long n) { return n + 3; }
KEEP long quality_multiply(long n) { return n * 2; }

operation const operations[] = { plus, quality_multiply };
operation volatile external_hook = plus;

KEEP long dispatch(unsigned index, long n) {
    return operations[index & 1](n);
}
KEEP long callback(operation op, long n) { return op(n); }
KEEP long unknown_callback(long n) { return external_hook(n); }

KEEP int checks(const char *s, unsigned long n) {
    char buf[8];
    if (n >= sizeof buf) return -1;
    memcpy(buf, s, n);
    buf[n] = 0;
    return strcmp(buf, "ok") == 0;
}

int main(void) {
    long a = fib(10);
    long b = dispatch(0, 4);
    long c = dispatch(1, 4);
    long d = callback(plus, 9);
    long e = callback(quality_multiply, 9);
    long f = unknown_callback(4);
    int g = checks("ok", 2);
    int h = checks("ignored", 8);
    printf("%ld %ld %ld %ld %ld %ld %d %d\n", a, b, c, d, e, f, g, h);
    return !(a == 55 && b == 7 && c == 8 && d == 12 && e == 18 && f == 7 && g == 1 && h == -1);
}

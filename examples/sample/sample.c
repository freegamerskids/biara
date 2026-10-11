/*
 * A small program to try biara on (examples/sample/build.sh).
 *
 *   ./sample calc 7 5      arithmetic through a switch (a jump table)
 *   ./sample apply 3 4     a handler picked from a table of function pointers
 *   ./sample hello NAME    greets NAME           (format-string bug)
 *   ./sample name          reads a name from stdin (stack buffer overflow)
 *   ./sample fib N         recursion
 *
 * The two bugs are deliberate: `biara lift sample --emit audit` reports
 * them, and nothing else.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef long (*handler)(long, long);

static long add(long a, long b) { return a + b; }
static long sub(long a, long b) { return a - b; }
static long mul(long a, long b) { return a * b; }
static long mix(long a, long b) { return (a ^ b) << 2; }

/* Reached only through this table: no direct calls. */
static handler handlers[] = {add, sub, mul, mix};

/* A dense switch: compiled to a jump table. */
__attribute__((noinline)) long calc(int op, long a, long b)
{
    switch (op) {
    case 0: return a + b;
    case 1: return a - b;
    case 2: return a * b;
    case 3: return b ? a / b : 0;
    case 4: return b ? a % b : 0;
    case 5: return a & b;
    case 6: return a | b;
    case 7: return a ^ b;
    default: return -1;
    }
}

__attribute__((noinline)) long apply(unsigned which, long a, long b)
{
    return handlers[which % 4](a, b);
}

__attribute__((noinline)) long fib(long n)
{
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

/* Bug: the user's string is the format. */
__attribute__((noinline)) void hello(const char *name)
{
    printf(name);
    putchar('\n');
}

/* Fine: a constant format. */
__attribute__((noinline)) void hello_safe(const char *name)
{
    printf("hello, %s\n", name);
}

/* Bug: up to 64 bytes into a 16-byte buffer. */
__attribute__((noinline)) void read_name(void)
{
    char buf[16];
    ssize_t n = read(0, buf, 64);
    if (n > 0)
        printf("read %zd bytes: %.*s\n", n, (int)n, buf);
}

/* Fine: the read fits. */
__attribute__((noinline)) void read_name_safe(void)
{
    char buf[64];
    ssize_t n = read(0, buf, sizeof buf);
    if (n > 0)
        printf("read %zd bytes: %.*s\n", n, (int)n, buf);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s calc|apply|hello|name|fib ...\n", argv[0]);
        return 2;
    }
    long a = argc > 2 ? atol(argv[2]) : 6;
    long b = argc > 3 ? atol(argv[3]) : 7;
    if (!strcmp(argv[1], "calc")) {
        for (int op = 0; op < 8; op++)
            printf("op %d: %ld\n", op, calc(op, a, b));
    } else if (!strcmp(argv[1], "apply")) {
        for (unsigned i = 0; i < 4; i++)
            printf("handler %u: %ld\n", i, apply(i, a, b));
    } else if (!strcmp(argv[1], "hello")) {
        const char *who = argc > 2 ? argv[2] : "world";
        hello(who);
        hello_safe(who);
    } else if (!strcmp(argv[1], "name")) {
        read_name_safe();
        read_name();
    } else if (!strcmp(argv[1], "fib")) {
        printf("fib(%ld) = %ld\n", a, fib(a));
    } else {
        return 2;
    }
    return 0;
}

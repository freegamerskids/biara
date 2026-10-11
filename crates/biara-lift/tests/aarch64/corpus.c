/*
 * Test corpus for tests/aarch64.rs (AArch64 JIT) and tests/decompile.rs
 * (C output, AArch64 and x86-64). Built with the pinned clang at -O0 and
 * -O2, without libc. Every t_* function has a Rust reference in
 * tests/common/corpus.rs; keep the two in sync.
 */
typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef int i32;

#define T __attribute__((noinline)) u64

T t_arith(u64 a, u64 b)
{
    return a * 3 + (b >> 2) - (a ^ b) + (u64)((i64)a >> 7);
}

T t_loop(u64 a, u64 b)
{
    u64 s = 0;
    for (u64 i = 0; i < (b & 63); i++) {
        s += (i * a) ^ (s >> 3);
    }
    return s;
}

T t_cond(u64 a, u64 b)
{
    u64 r = 0;
    if ((i64)a < (i64)b) r |= 1;
    if (a < b) r |= 2;
    if (a == b) r |= 4;
    if ((i32)a > (i32)b) r |= 8;
    if ((u32)a >= (u32)b) r |= 16;
    return r + (a > b ? a - b : b - a);
}

T t_muldiv(u64 a, u64 b)
{
    unsigned __int128 p = (unsigned __int128)a * b;
    __int128 q = (__int128)(i64)a * (i64)b;
    u64 d = b | 1;
    i64 sa = (i64)a, sd = (i64)(b | 1);
    if (sd == -1) {
        sd = 3;
    }
    return (u64)(p >> 64) ^ (u64)(q >> 64) ^ (a / d) ^ (a % d) ^ (u64)(sa / sd) ^
           (u64)(sa % sd) ^ (u64)((u32)a / ((u32)b | 1));
}

T t_bits(u64 a, u64 b)
{
    u64 n = b & 63;
    u64 counts = (a ? __builtin_clzll(a) : 64) + 100 * (b ? __builtin_ctzll(b) : 64) +
                 10000 * __builtin_popcountll(a ^ b);
    u64 rot = (a << n) | (a >> ((64 - n) & 63));
    return counts ^ __builtin_bswap64(a) ^ rot ^ __builtin_bitreverse64(b);
}

T t_flags(u64 a, u64 b)
{
    i64 s;
    u64 d;
    u64 r = __builtin_add_overflow((i64)a, (i64)b, &s);
    r |= (u64)__builtin_sub_overflow(a, b, &d) << 1;
    unsigned __int128 x = ((unsigned __int128)a << 64 | b) + ((unsigned __int128)b << 64 | a);
    return r ^ (u64)s ^ (d << 2) ^ (u64)(x >> 64) ^ (u64)x;
}

T t_switch(u64 a, u64 b)
{
    switch (a & 15) {
    case 0: return b + 11;
    case 1: return b * 23;
    case 2: return b - 37;
    case 3: return b ^ 0x55;
    case 4: return b << 3;
    case 5: return b >> 5;
    case 6: return -b;
    case 7: return b | 0x100;
    case 8: return b & 0xff;
    case 9: return ~b;
    case 10: return b * b;
    }
    return a;
}

/* The index is a byte loaded from memory: the bound is a 32-bit compare
 * whose flags the lifted code also keeps, `x > 12 && x - 13 != 0`. */
static volatile unsigned char token;

T t_byteswitch(u64 a, u64 b)
{
    token = (unsigned char)a;
    switch (token) {
    case 0: return b + 3;
    case 1: return b * 5;
    case 2: return b - 7;
    case 3: return b ^ 0x99;
    case 4: return b << 2;
    case 5: return b >> 3;
    case 7: return b * b;
    case 8: return ~b;
    case 9: return b + 0x1234;
    case 10: return b * 9;
    case 11: return b | 0xf0;
    case 13: return b & 0x0f;
    }
    return a;
}

/* Two paths that bound the byte index separately share the dispatch (as
 * GCC's tail merging leaves them): neither bound dominates the jump.
 * AArch64 only (the corpus is also built for x86-64, tests/decompile.rs). */
#if defined(__aarch64__)
__asm__(".globl t_merged\n"
        ".type t_merged, %function\n"
        "t_merged:\n"
        "    adrp x9, token\n"
        "    add x9, x9, :lo12:token\n"
        "    strb w0, [x9]\n"
        "    tbnz x1, #0, 1f\n"
        "    ldrb w8, [x9]\n"
        "    cmp w8, #3\n"
        "    b.hi 9f\n"
        "    b 2f\n"
        "1:  ldrb w8, [x9]\n"
        "    cmp w8, #3\n"
        "    b.ls 2f\n"
        "9:  mov x0, x1\n"
        "    ret\n"
        "2:  adr x10, 3f\n"
        "    ldrb w11, [x10, x8]\n"
        "    adr x12, 4f\n"
        "    add x12, x12, x11, lsl #2\n"
        "    br x12\n"
        "3:  .byte 0, 2, 4, 6\n"
        "4:  add x0, x1, #1\n"
        "    ret\n"
        "    sub x0, x1, #1\n"
        "    ret\n"
        "    eor x0, x1, #7\n"
        "    ret\n"
        "    lsl x0, x1, #1\n"
        "    ret\n"
        ".size t_merged, . - t_merged\n");
#endif

static __attribute__((noinline)) u64 many(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f,
                                          u64 g, u64 h, u64 i, u64 j)
{
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h + 9 * i + 10 * j;
}

static __attribute__((noinline)) u64 fib(u64 n)
{
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

T t_calls(u64 a, u64 b)
{
    return many(a, b, a ^ b, a + b, a * b, a - b, b - a, a | b, a & b, ~a) + fib(b & 15);
}

T t_memory(u64 a, u64 b)
{
    volatile u64 buf[16];
    for (int i = 0; i < 16; i++) {
        buf[i] = a * i + b;
    }
    u64 s = 0;
    for (int i = 0; i < 16; i++) {
        s ^= buf[(i * 7 + b) & 15] << (i & 7);
    }
    return s;
}

T t_narrow(u64 a, u64 b)
{
    volatile union {
        u64 q;
        unsigned char c[8];
        signed char s[8];
        unsigned short h[4];
        short sh[4];
        u32 w[2];
        i32 sw[2];
    } u;
    u.q = a;
    u.c[b & 7] = (unsigned char)b;
    return (u64)(i64)u.s[1] + u.h[2] + (u64)(i64)u.sh[3] + u.w[0] + (u64)(i64)u.sw[1] + u.q;
}

T t_float(u64 a, u64 b)
{
    double x = (double)(i64)a, y = (double)(b | 1);
    double r = __builtin_sqrt(x * x + y) / y + x * 0.5;
    float f = (float)(u32)a * 1.5f - (float)(u32)b;
    return (u64)(i64)r ^ (u64)(i64)f;
}

T t_w32(u64 a, u64 b)
{
    u32 x = (u32)a, y = (u32)b, n = y & 31;
    u32 r = x * 7 + (y >> 3) - (x ^ y);
    r = (r << n) | (r >> ((32 - n) & 31));
    return (u64)(i64)(i32)r + (u64)((i32)x >> n);
}

T t_atomic(u64 a, u64 b)
{
    static u64 cell;
    cell = a;
    u64 old = __atomic_fetch_add(&cell, b, __ATOMIC_SEQ_CST);
    u64 expected = a + b;
    int ok = __atomic_compare_exchange_n(&cell, &expected, a ^ b, 0, __ATOMIC_SEQ_CST,
                                         __ATOMIC_SEQ_CST);
    return old ^ cell ^ (u64)ok;
}

T t_tail(u64 a, u64 b)
{
    return t_arith(b, a + 1);
}

/* Structs through pointers: a list walked by a callee, and a struct in the
 * caller's frame that a callee fills (tests/decompile.rs recovers both). */
struct node {
    struct node *next;
    u64 value;
    u32 tag;
};

struct point {
    u32 x, y;
    u64 z;
};

static __attribute__((noinline)) u64 walk(struct node *n)
{
    u64 s = 0;
    while (n) {
        s += n->value * n->tag;
        n = n->next;
    }
    return s;
}

static __attribute__((noinline)) void fill(struct point *p, u64 k)
{
    p->x = (u32)k;
    p->y = (u32)k * 2;
    p->z = k << 33;
}

T t_structs(u64 a, u64 b)
{
    struct node c = {0, a, 3}, m = {&c, b, 5}, h = {&m, a ^ b, 7};
    struct point p;
    fill(&p, a + b);
    return walk(&h) + p.x + p.y + p.z;
}

/* A trampoline through a function pointer: its arguments pass through
 * untouched, so only its callers show it takes them. */
static u64 (*volatile hook)(u64, u64) = t_arith;

static __attribute__((noinline)) u64 tramp(u64 a, u64 b)
{
    return hook(a, b);
}

T t_tramp(u64 a, u64 b)
{
    return tramp(b, a) + 1;
}

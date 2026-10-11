// Binary facts in tests/objects.rs are derived from real imported libc calls,
// ELF data symbols, and compiler-generated DWARF, never source matching.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define KEEP __attribute__((noinline))
char object_global[16];

KEEP char *allocate_offset(size_t n) { return (char *)malloc(n) + 2; }
KEEP char *argument_offset(char *p) { return p + 3; }
KEEP const char *format_offset(const char *p) { return p + 1; }
KEEP void copy_wrapper(char *p, const char *s, size_t n) { memcpy(p, s, n); }

KEEP void bad_heap(const char *s) { memcpy(malloc(16), s, 17); }
KEEP void bad_interior(const char *s) { memcpy((char *)malloc(16) + 4, s, 13); }
KEEP void ok_interior(const char *s) { memcpy((char *)malloc(16) + 4, s, 12); }
KEEP void bad_calloc(const char *s) { memcpy(calloc(4, 4), s, 17); }
KEEP void unknown_calloc(const char *s) {
    memcpy(calloc(SIZE_MAX / 2 + 1, 2), s, 1);
}
KEEP void bad_allocation_wrapper(const char *s) { memcpy(allocate_offset(16), s, 15); }
KEEP void bad_argument_wrapper(const char *s) { memcpy(argument_offset(malloc(16)), s, 14); }
KEEP void bad_copy_wrapper(const char *s) { copy_wrapper(malloc(16), s, 17); }
KEEP void bad_realloc(const char *s, char *p) { memcpy(realloc(p, 16), s, 17); }
KEEP void bad_global(const char *s) { memcpy(object_global, s, 17); }
KEEP int bad_adjacent_stack(const char *s) {
    char small[8];
    volatile char adjacent[64];
    adjacent[0] = 1;
    memcpy(small, s, 9);
    return small[0] + adjacent[0];
}
KEEP void bad_unbounded(const char *s) { strcpy(malloc(16), s); }
KEEP void ok_format_wrapper(void) { printf(format_offset("x%s"), "safe"); }
KEEP void bad_environment_wrapper(void) { printf(format_offset(getenv("OBJECT_FORMAT"))); }
KEEP void bad_input_wrapper(void) {
    char buf[16];
    read(0, buf, sizeof buf);
    printf(format_offset(buf));
}

int main(int argc, char **argv) {
    const char *s = argv[0];
    bad_heap(s); bad_interior(s); ok_interior(s); bad_calloc(s);
    unknown_calloc(s); bad_allocation_wrapper(s); bad_argument_wrapper(s);
    bad_copy_wrapper(s); bad_realloc(s, 0); bad_global(s);
    bad_adjacent_stack(s); bad_unbounded(s); ok_format_wrapper();
    bad_environment_wrapper(); bad_input_wrapper();
    return argc;
}

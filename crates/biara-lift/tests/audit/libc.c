// Stand-in C library for tests/audit/prog.c: just the imported symbols.
typedef __SIZE_TYPE__ size_t;
typedef long ssize_t;

int printf(const char *fmt, ...) { return 0; }
int puts(const char *s) { return 0; }
ssize_t read(int fd, void *buf, size_t n) { return 0; }
void *memcpy(void *dst, const void *src, size_t n) { return dst; }
char *strcpy(char *dst, const char *src) { return dst; }
char *dcgettext(const char *domain, const char *msgid, int category) { return (char *)msgid; }
char *getenv(const char *name) { return 0; }
int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv,
                      void (*init)(void), void (*fini)(void),
                      void (*rtld_fini)(void), void *stack_end) {
  return main(argc, argv, 0);
}

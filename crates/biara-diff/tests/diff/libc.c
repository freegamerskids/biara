// Stand-in shared C library for tests/diff/prog.c: just `printf`, so the
// corpus has a PLT stub (matched pairs skip stubs).
int printf(const char *fmt, ...) { return 0; }

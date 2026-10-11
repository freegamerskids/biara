// This function is listed by symbols and unwind information but never run.
// Its direct branch leaves every executable mapping, so recovery must record
// a failed translation target rather than confuse it with an indirect edge.
__attribute__((noinline)) void missing_code(void) {
#if defined(__x86_64__)
    __asm__ volatile("jmp . - 0x100000");
#elif defined(__aarch64__)
    __asm__ volatile("b . - 0x100000");
#else
#error Unsupported quality test architecture
#endif
}

int main(void) { return 0; }

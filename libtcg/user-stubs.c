/* SPDX-License-Identifier: MIT */
/*
 * What the translator links against from linux-user/ and common-user/, for
 * hosts that cannot build those (macOS). libtcg only translates: it never
 * runs guest code, so the syscall, signal and guest-memory entry points are
 * never reached and abort. The globals keep the values a linux-user build
 * has before its main() runs, which is all libtcg ever sees on Linux.
 */
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

uintptr_t guest_base;
unsigned long guest_addr_max;
int host_interrupt_signal;
__thread void *thread_cpu;

bool qemu_cpu_is_self(void *cpu)
{
    return thread_cpu == cpu;
}

static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread int mmap_lock_count;

void mmap_lock(void)
{
    if (mmap_lock_count++ == 0) {
        pthread_mutex_lock(&mmap_mutex);
    }
}

void mmap_unlock(void)
{
    if (mmap_lock_count <= 0) {
        abort();
    }
    if (--mmap_lock_count == 0) {
        pthread_mutex_unlock(&mmap_mutex);
    }
}

bool have_mmap_lock(void)
{
    return mmap_lock_count > 0;
}

/* Guest execution only. */
#define UNREACHABLE(name) \
    void name(void);      \
    void name(void)       \
    {                     \
        abort();          \
    }

UNREACHABLE(cpu_loop_exit_sigsegv)
UNREACHABLE(cpu_loop_exit_sigbus)
UNREACHABLE(target_to_host_signal)
UNREACHABLE(do_guest_openat)
UNREACHABLE(do_guest_readlink)
UNREACHABLE(do_brk)
UNREACHABLE(copy_from_user)
UNREACHABLE(lock_user)
UNREACHABLE(lock_user_string)
UNREACHABLE(target_strlen)
UNREACHABLE(qemu_semihosting_console_read)
UNREACHABLE(qemu_semihosting_console_write)
UNREACHABLE(cpu_get_tsc)              /* x86_64 */
UNREACHABLE(arm_set_tagged_addr_ctrl) /* aarch64 */

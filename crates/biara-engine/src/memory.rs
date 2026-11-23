//! Memory budgets are `RLIMIT_AS` caps (see the crate docs). macOS accepts
//! the limit but never enforces it, so there a watchdog thread stands in: the
//! process exits once its physical footprint passes its current `RLIMIT_AS`,
//! as a Linux process dies when an allocation fails under the cap. The
//! coordinator then sees a worker exit, exactly as on Linux.

/// Enforce this process's `RLIMIT_AS` where the kernel does not (macOS); a
/// no-op elsewhere. Call it after setting the limit; later changes to the
/// limit are followed.
pub fn enforce_address_space_limit() {
    #[cfg(target_os = "macos")]
    macos::start();
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{sync::Once, thread, time::Duration};

    static STARTED: Once = Once::new();

    pub(super) fn start() {
        STARTED.call_once(|| {
            let _ = thread::Builder::new()
                .name("memory-limit".into())
                .spawn(watch);
        });
    }

    fn watch() {
        loop {
            if let (Some(cap), Some(used)) = (limit(), footprint())
                && used > cap
            {
                eprintln!(
                    "biara: memory footprint {} MiB exceeds the {} MiB budget; exiting",
                    used >> 20,
                    cap >> 20
                );
                // As the kernel's OOM kill would: no unwinding, no atexit handlers.
                unsafe { libc::_exit(137) };
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn limit() -> Option<u64> {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut limit) };
        (rc == 0 && limit.rlim_cur != libc::RLIM_INFINITY).then_some(limit.rlim_cur as u64)
    }

    fn footprint() -> Option<u64> {
        let mut info = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
        let rc = unsafe {
            libc::proc_pid_rusage(
                libc::getpid(),
                libc::RUSAGE_INFO_V2,
                info.as_mut_ptr().cast(),
            )
        };
        (rc == 0).then(|| unsafe { info.assume_init() }.ri_phys_footprint)
    }
}

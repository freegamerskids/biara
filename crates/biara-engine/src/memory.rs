//! Memory budgets (see the crate docs). On Linux they are `RLIMIT_AS` caps:
//! an allocation past one fails and the process dies. macOS refuses to set
//! `RLIMIT_AS`, so there a watchdog thread stands in: the process exits once
//! its physical footprint passes its cap, which a parent hands its child in
//! [`LIMIT_ENV`]. Either way the coordinator sees a worker exit.

use std::{io, process::Command};

/// The cap a macOS child takes over at startup ([`inherit_memory_limit`]).
#[cfg(target_os = "macos")]
const LIMIT_ENV: &str = "BIARA_MEMORY_LIMIT";

/// Cap this process at `bytes` (only ever lowering an inherited cap).
pub fn limit_memory(bytes: u64) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::lower(bytes);
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
        limit.rlim_cur = (bytes as libc::rlim_t).min(limit.rlim_max);
        limit.rlim_max = limit.rlim_cur;
        if unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Spawn `command` capped at `bytes`, and without core dumps.
pub fn limit_child_memory(command: &mut Command, bytes: u64) {
    use std::os::unix::process::CommandExt;
    #[cfg(target_os = "macos")]
    command.env(LIMIT_ENV, bytes.to_string());
    unsafe {
        command.pre_exec(move || {
            #[cfg(not(target_os = "macos"))]
            {
                let limit = libc::rlimit {
                    rlim_cur: bytes as libc::rlim_t,
                    rlim_max: bytes as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_AS, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            #[cfg(target_os = "macos")]
            let _ = bytes;
            let core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Take over the cap the parent set ([`limit_child_memory`]): on Linux the
/// kernel already holds it; on macOS this starts the watchdog.
pub fn inherit_memory_limit() {
    #[cfg(target_os = "macos")]
    if let Some(bytes) = std::env::var(LIMIT_ENV).ok().and_then(|v| v.parse().ok()) {
        macos::lower(bytes);
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{
        sync::{
            Once,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::Duration,
    };

    static CAP: AtomicU64 = AtomicU64::new(u64::MAX);
    static STARTED: Once = Once::new();

    pub(super) fn lower(bytes: u64) {
        CAP.fetch_min(bytes, Ordering::Relaxed);
        STARTED.call_once(|| {
            let _ = thread::Builder::new()
                .name("memory-limit".into())
                .spawn(watch);
        });
    }

    fn watch() {
        loop {
            let cap = CAP.load(Ordering::Relaxed);
            if let Some(used) = footprint()
                && used > cap
            {
                eprintln!(
                    "biara: memory footprint {} MiB exceeds the {} MiB budget; exiting",
                    used >> 20,
                    cap >> 20
                );
                // As an allocation failure under RLIMIT_AS would end it: no
                // unwinding, no atexit handlers.
                unsafe { libc::_exit(137) };
            }
            thread::sleep(Duration::from_millis(50));
        }
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

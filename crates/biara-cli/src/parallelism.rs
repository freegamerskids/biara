//! Shared bounded analysis parallelism for the CLI.
//!
//! The worker budget leaves one CPU free when possible and never drops below
//! one worker; oversized `--jobs` requests clamp to that budget, and `--jobs
//! 0` is rejected by argument parsing. On Linux the calling thread's CPU
//! affinity is additionally confined to the budgeted number of allowed CPUs
//! before recovery and runtime initialization, so worker processes and native
//! threads inherit the same mask. Recovery/resolution use isolated processes;
//! ABI rounds and function-local LLVM passes use bounded threads. Other
//! platforms rely on those bounded computation pools.

use std::num::NonZeroUsize;

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::Result;

/// Resolve an optional `--jobs` request into capped options, confining Linux
/// CPU affinity to the budgeted CPUs first.
///
/// The options are captured before affinity is touched and are never
/// recomputed afterwards: shrinking the mask must not shrink the budget.
pub(crate) fn resolve(
    requested: Option<NonZeroUsize>,
    memory_bytes: u64,
) -> Result<biara_lift::DecompileOptions> {
    if memory_bytes < biara_proto::MIN_MEMORY_BYTES {
        anyhow::bail!("analysis memory budget must be at least 2 GiB");
    }
    // Match the engine pool's minimum worker share; ABI and LLVM threads
    // must not retain the larger CPU-only request after recovery clamps it.
    let memory_workers =
        usize::try_from(memory_bytes / 2 / biara_proto::MIN_WORKER_BYTES).unwrap_or(usize::MAX);
    let limit = NonZeroUsize::new(memory_workers).unwrap();
    let options =
        biara_lift::DecompileOptions::with_workers(requested.map_or(limit, |n| n.min(limit)));
    #[cfg(target_os = "linux")]
    cap_affinity(options.workers()).context("cannot confine CPU affinity to the job budget")?;
    Ok(options)
}

/// Confine the calling thread to the first `workers` currently allowed CPUs.
///
/// Reads the present affinity mask (honouring container and cpuset
/// restrictions), keeps the lowest-numbered allowed CPUs up to `workers`,
/// and applies the shrunken mask so later-spawned threads inherit it. Masks
/// already within budget are left untouched. Kernel errors are returned to
/// the caller; this never pretends the cap applied.
#[cfg(target_os = "linux")]
fn cap_affinity(workers: usize) -> Result<()> {
    let (size, mut mask) = current_mask()?;
    if !narrow_mask(&mut mask, workers) {
        return Ok(());
    }
    // SAFETY: `mask` holds `size` bytes of plain mask bits, and only the
    // calling thread's mask is replaced with a subset of its current CPUs.
    let rc = unsafe { libc::sched_setaffinity(0, size, mask.as_ptr().cast()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("sched_setaffinity rejected the narrowed CPU mask");
    }
    Ok(())
}

/// Read the calling thread's current affinity mask with a dynamically grown
/// buffer, so large (and cpuset-restricted) masks are honored.
#[cfg(target_os = "linux")]
fn current_mask() -> Result<(libc::size_t, Vec<u64>)> {
    // Start at 1024 CPUs; EINVAL means the kernel needs a larger mask.
    let mut size: libc::size_t = 128;
    loop {
        let mut words = vec![0u64; size / 8];
        // SAFETY: `words` holds `size` initialized bytes for the kernel.
        let rc = unsafe { libc::sched_getaffinity(0, size, words.as_mut_ptr().cast()) };
        if rc == 0 {
            return Ok((size, words));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINVAL) && size < 1 << 20 {
            size *= 2;
            continue;
        }
        return Err(err).context("sched_getaffinity failed");
    }
}

/// Keep at most `workers` existing CPU bits, without allocating another mask.
#[cfg(target_os = "linux")]
fn narrow_mask(mask: &mut [u64], mut workers: usize) -> bool {
    let mut changed = false;
    for word in mask {
        let count = word.count_ones() as usize;
        if count <= workers {
            workers -= count;
            continue;
        }
        let mut kept = 0;
        for _ in 0..workers {
            let bit = word.trailing_zeros();
            kept |= 1u64 << bit;
            *word &= *word - 1;
        }
        *word = kept;
        workers = 0;
        changed = true;
    }
    changed
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::narrow_mask;

    #[test]
    fn sparse_cpu_sets_stay_subsets_across_word_boundaries() {
        let initial = [1u64 << 63, (1u64 << 1) | (1u64 << 60), 1u64 << 5];
        for (workers, expected) in [
            (1, [1u64 << 63, 0, 0]),
            (2, [1u64 << 63, 1u64 << 1, 0]),
            (3, [1u64 << 63, (1u64 << 1) | (1u64 << 60), 0]),
            (4, initial),
            (8, initial),
        ] {
            let mut mask = initial;
            assert_eq!(narrow_mask(&mut mask, workers), workers < 4);
            assert_eq!(mask, expected);
            assert!(mask.iter().zip(initial).all(|(now, old)| now & !old == 0));
        }
    }
}

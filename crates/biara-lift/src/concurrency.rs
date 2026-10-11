//! CPU budget for function-local decompilation work. One CPU is left free when
//! possible; a single available CPU still permits one computation worker.
//!
//! `Default` uses `max(1, available logical CPUs - 1)`, respecting the OS
//! parallelism estimate (including affinity/container limits where supported).
//! `with_workers` clamps a nonzero request to that same budget. The calling
//! thread occupies one computation slot. Library callers retain responsibility
//! for affinity and unrelated threads; the Linux CLI additionally confines
//! itself and subsequently created native threads to its budgeted CPU subset.
use std::num::NonZeroUsize;

/// Bounded decompilation concurrency, captured before any caller CPU-affinity
/// restriction. Workers own isolated LLVM contexts and target machines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecompileOptions {
    workers: usize,
}

impl Default for DecompileOptions {
    fn default() -> Self {
        Self::configured(None)
    }
}

impl DecompileOptions {
    /// Request fewer workers, or cap an oversized request to the available-CPU
    /// budget. Zero cannot be requested.
    pub fn with_workers(requested: NonZeroUsize) -> Self {
        Self::configured(Some(requested))
    }

    fn configured(requested: Option<NonZeroUsize>) -> Self {
        let available = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        Self {
            workers: budget(available, requested),
        }
    }

    /// Maximum computation workers, including the calling thread.
    pub fn workers(self) -> usize {
        self.workers
    }
}

fn budget(available: usize, requested: Option<NonZeroUsize>) -> usize {
    let maximum = available.saturating_sub(1).max(1);
    requested.map_or(maximum, |n| n.get().min(maximum))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserves_one_cpu_without_disabling_single_cpu_hosts() {
        for (available, expected) in [(0, 1), (1, 1), (2, 1), (3, 2), (8, 7)] {
            assert_eq!(budget(available, None), expected);
        }
    }

    #[test]
    fn requested_workers_never_exceed_budget() {
        assert_eq!(budget(8, NonZeroUsize::new(1)), 1);
        assert_eq!(budget(8, NonZeroUsize::new(3)), 3);
        assert_eq!(budget(8, NonZeroUsize::new(100)), 7);
        assert_eq!(budget(1, NonZeroUsize::new(100)), 1);
        assert_eq!(
            budget(usize::MAX, NonZeroUsize::new(usize::MAX)),
            usize::MAX - 1
        );
    }
}

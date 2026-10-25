//! Low-overhead operational counters.
//!
//! All counters are monotonic `AtomicU64`s updated with relaxed ordering;
//! they are diagnostics, not synchronisation. `files_monitored` is a gauge.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! counters {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
        #[derive(Debug, Default)]
        pub struct Metrics {
            $($(#[$doc])* pub $name: AtomicU64,)*
        }

        /// A point-in-time copy of all counters.
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct Snapshot {
            $(pub $name: u64,)*
        }

        impl Metrics {
            pub fn snapshot(&self) -> Snapshot {
                Snapshot {
                    $($name: self.$name.load(Ordering::Relaxed),)*
                }
            }
        }

        impl fmt::Display for Snapshot {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut first = true;
                $(
                    if !first {
                        f.write_str(" ")?;
                    }
                    first = false;
                    write!(f, concat!(stringify!($name), "={}"), self.$name)?;
                )*
                let _ = first;
                Ok(())
            }
        }
    };
}

counters! {
    /// Gauge: files currently open for reading (excluding draining ones).
    files_monitored,
    bytes_read,
    lines_processed,
    /// Lines longer than `max_line_bytes`, emitted cut to that length.
    lines_truncated,
    /// Bytes beyond `max_line_bytes` that were not passed to the rules.
    bytes_skipped,
    /// Incomplete trailing lines emitted because their file was truncated,
    /// rotated or deleted before a newline arrived.
    partial_lines_flushed,
    /// Lines that matched an `ignore` rule.
    lines_ignored,
    rule_matches,
    events_emitted,
    /// Events dropped because the output queue was full (`on_full = "drop"`).
    events_dropped,
    events_rate_limited,
    events_deduplicated,
    output_errors,
    read_errors,
    notify_overflows,
    rotations,
    truncations,
    /// Successful writes of the offset state file.
    state_saves,
    /// Failed writes of the offset state file (retried later).
    state_save_errors,
    /// Files matching a glob that were not followed because the glob had
    /// reached `general.max_glob_files`. Each file is counted once while it
    /// stays refused (beyond `max_glob_files` refused files, on every
    /// directory listing).
    glob_matches_refused,
    /// Journal entries that could not be parsed or were too long.
    journal_entries_skipped,
    /// Times journalctl was started again after it exited or failed to start.
    journal_restarts,
    /// Configuration reloads applied (SIGHUP).
    config_reloads,
    /// Configuration reloads rejected; the running configuration was kept.
    config_reload_failures,
}

#[inline]
pub fn add(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

#[inline]
pub fn inc(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn dec(counter: &AtomicU64) {
    counter.fetch_sub(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_and_display() {
        let m = Metrics::default();
        add(&m.bytes_read, 10);
        inc(&m.lines_processed);
        inc(&m.files_monitored);
        dec(&m.files_monitored);
        let s = m.snapshot();
        assert_eq!(s.bytes_read, 10);
        assert_eq!(s.lines_processed, 1);
        assert_eq!(s.files_monitored, 0);
        let text = s.to_string();
        assert!(text.starts_with("files_monitored=0 bytes_read=10 lines_processed=1 "));
    }
}

//! Wiring: signals, the monitor loop, rule evaluation and output.
//!
//! Threads:
//! * main: the monitor loop (reading, matching, limiting, enqueueing)
//! * `output`: formats and writes events
//! * `signals`: waits synchronously for SIGTERM/SIGINT/SIGUSR1/SIGHUP
//! * `stats`: periodic statistics diagnostics (`stats_interval_secs`)
//! * `state` (optional): saves read offsets (`general.state_file`)
//! * the notify crate's inotify thread
//!
//! SIGHUP reloads the configuration: the signal thread sets a flag, and the
//! monitor thread applies the new configuration between polls (see
//! [`apply_reload`]).
//!
//! Signals are blocked in every thread (the mask is set before any thread is
//! spawned and is inherited) and consumed only by `sigwait` in the signal
//! thread, so no code runs in async-signal context.

use std::cell::RefCell;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use tracing::{info, warn};

use crate::config::{self, Config, Destination};
use crate::detect::{Detector, Verdict};
use crate::dispatcher::{Admit, Dispatcher, Limiter, Meta, Tables};
use crate::engine::Engine;
use crate::error::RuntimeError;
use crate::event::{Event, excerpt};
use crate::metrics::{self, Metrics, RuleCounters, RuleStats};
use crate::monitor::{Monitor, Stopped};
use crate::reader::Line;
use crate::state::{self, Checkpoint, StateWriter};
use crate::watcher::Waker;

/// Runs the daemon until a termination signal or an output failure.
/// `config_path` is read again on SIGHUP.
pub fn run(cfg: Config, config_path: &Path) -> Result<(), RuntimeError> {
    let signals = block_signals(&HANDLED).map_err(RuntimeError::Startup)?;

    let metrics = Arc::new(Metrics::default());
    let shutdown = Arc::new(AtomicBool::new(false));
    let reload = Arc::new(AtomicBool::new(false));
    let rule_stats = Arc::new(RuleStats::new(&cfg.rules));
    let mut monitor = Monitor::new(&cfg, Arc::clone(&metrics), true);
    let mut journal_cursor = None;
    if let Some(path) = &cfg.general.state_file {
        let saved = state::load(path);
        monitor.resume(saved.files);
        journal_cursor = saved.journal_cursor;
    }
    monitor
        .start_journal(&cfg, journal_cursor)
        .map_err(RuntimeError::Startup)?;
    let waker = monitor.waker();

    spawn_signal_thread(
        signals,
        Arc::clone(&shutdown),
        Arc::clone(&reload),
        waker.clone(),
        Arc::clone(&metrics),
        Arc::clone(&rule_stats),
    )
    .map_err(RuntimeError::Startup)?;
    let stats_interval = Arc::new(AtomicU64::new(cfg.general.stats_interval_secs));
    spawn_stats_thread(
        Arc::clone(&stats_interval),
        Arc::clone(&metrics),
        Arc::clone(&rule_stats),
    )
    .map_err(RuntimeError::Startup)?;

    let meta = Meta::current();
    let tables = Arc::new(Tables {
        rules: cfg.rules.clone(),
        meta: meta.clone(),
    });
    let writer: Box<dyn io::Write + Send> = match cfg.output.destination {
        Destination::Stdout => Box::new(io::stdout()),
        Destination::Stderr => Box::new(io::stderr()),
    };
    let dispatcher = Dispatcher::spawn(
        &cfg,
        tables,
        writer,
        Arc::clone(&metrics),
        Arc::clone(&shutdown),
        waker,
    )
    .map_err(RuntimeError::Output)?;
    let progress = dispatcher.progress();
    let state_flush = Duration::from_millis(cfg.general.state_flush_ms);
    let state_writer = match &cfg.general.state_file {
        Some(path) => Some(
            StateWriter::spawn(
                path.clone(),
                state_flush,
                Arc::clone(&progress),
                Arc::clone(&metrics),
            )
            .map_err(RuntimeError::Startup)?,
        ),
        None => None,
    };
    let pipeline = Pipeline {
        engine: Engine::new(cfg.rules.clone()),
        limiter: Limiter::new(&cfg.limits, cfg.rules.len()),
        detector: Detector::new(&cfg, Arc::clone(&metrics)),
        dispatcher,
        metrics: Arc::clone(&metrics),
        rule_counts: rule_stats.table(),
        rule_stats: Arc::clone(&rule_stats),
        meta,
        max_excerpt: cfg.output.max_excerpt_bytes,
        no_file: Arc::from(Path::new("")),
    };

    info!(
        version = env!("LOGWIZZ_VERSION"),
        files = monitor.files(),
        globs = cfg.globs.len(),
        rules = cfg.rules.len(),
        "logwizz started"
    );

    let mut running = cfg;
    // Shared by the line and tick callbacks, which never run at once.
    let pipeline = RefCell::new(pipeline);
    loop {
        let mut record = |files, journal| {
            if let Some(w) = &state_writer {
                w.record(Checkpoint {
                    events: progress.sent(),
                    files,
                    journal,
                });
            }
        };
        let checkpoints = state_writer
            .as_ref()
            .map(|_| (state_flush, &mut record as &mut dyn FnMut(_, _)));
        // Only silence rules need the clock; without them the loop sleeps
        // until an input changes.
        let watching = pipeline.borrow().detector.watches_silence();
        let mut tick = || pipeline.borrow_mut().tick();
        let stopped = monitor.run_with(
            &shutdown,
            Some(&reload),
            &mut |file, line| pipeline.borrow_mut().line(file, line),
            checkpoints,
            watching.then_some(&mut tick as &mut dyn FnMut()),
        );
        if stopped == Stopped::Shutdown {
            break;
        }
        apply_reload(
            config_path,
            &mut running,
            &mut monitor,
            &mut pipeline.borrow_mut(),
            &stats_interval,
        );
    }
    let pipeline = pipeline.into_inner();

    info!("shutting down; flushing queued events");
    let final_checkpoint = Checkpoint {
        events: progress.sent(),
        files: monitor.checkpoint(),
        journal: monitor.journal_cursor(),
    };
    let result = pipeline.dispatcher.finish();
    if let Some(w) = state_writer {
        // Saved only if the output really flushed everything.
        w.record(final_checkpoint);
        w.finish();
    }
    info!(rules = %rule_stats, "rule counts");
    info!(stats = %metrics.snapshot(), "logwizz stopped");
    result.map_err(RuntimeError::Output)
}

/// Everything a line passes through on the monitor thread: matching,
/// sequences, thresholds, limiting and queueing.
struct Pipeline {
    engine: Engine,
    limiter: Limiter,
    detector: Detector,
    dispatcher: Dispatcher,
    metrics: Arc<Metrics>,
    /// The current table of `rule_stats`, indexed like the engine's rules.
    rule_counts: Arc<[RuleCounters]>,
    rule_stats: Arc<RuleStats>,
    meta: Meta,
    max_excerpt: Option<usize>,
    /// The `file` of events that no line produced (reported silences).
    no_file: Arc<Path>,
}

impl Pipeline {
    /// Reports the silence rules that have now waited long enough. Not
    /// subject to `[limits]`: a silence is reported once until a match.
    fn tick(&mut self) {
        for rule in self.detector.silent(self.engine.rules(), Instant::now()) {
            metrics::inc(&self.metrics.silences_reported);
            metrics::inc(&self.rule_counts[rule].events);
            self.dispatcher.send(Event {
                time: SystemTime::now(),
                file: Arc::clone(&self.no_file),
                rule,
                line: Box::default(),
                truncated: false,
                fields: Vec::new(),
                threshold: None,
            });
        }
    }

    fn line(&mut self, file: &Arc<Path>, line: Line<'_>) {
        let Pipeline {
            engine,
            limiter,
            detector,
            dispatcher,
            metrics,
            rule_counts,
            max_excerpt,
            ..
        } = self;
        // Windows count in log time where the source records it, so that
        // catching up on a backlog does not look like a burst.
        let now = line.time.map_or_else(Instant::now, instant_of);
        let ignored = engine.for_each_match(file, line.bytes, |rule| {
            metrics::inc(&metrics.rule_matches);
            metrics::inc(&rule_counts[rule].matches);
            let r = &engine.rules()[rule];
            let fields = r.matcher.fields(line.bytes);
            let threshold = match detector.judge(rule, r, file, &fields, now) {
                Verdict::Event(threshold) => threshold,
                Verdict::Excluded => return metrics::inc(&metrics.matches_excluded),
                Verdict::Mistyped => return metrics::inc(&metrics.matches_mistyped),
                Verdict::Seen => return metrics::inc(&metrics.silence_matches),
                Verdict::Unsequenced => return metrics::inc(&metrics.after_unmatched),
                Verdict::Absorbed => return metrics::inc(&metrics.threshold_absorbed),
            };
            if threshold.is_some() {
                metrics::inc(&metrics.threshold_fired);
            }
            metrics::inc(&rule_counts[rule].events);
            match limiter.admit(rule, &r.id, line.bytes, now) {
                Admit::Yes => {}
                Admit::RateLimited => {
                    metrics::inc(&metrics.events_rate_limited);
                    return;
                }
                Admit::Duplicate => {
                    metrics::inc(&metrics.events_deduplicated);
                    return;
                }
            }
            let (bytes, cut) = excerpt(line.bytes, *max_excerpt);
            dispatcher.send(Event {
                time: SystemTime::now(),
                file: Arc::clone(file),
                rule,
                line: bytes.into(),
                truncated: line.truncated || cut,
                fields,
                threshold,
            });
        });
        if let Some(rule) = ignored {
            metrics::inc(&rule_counts[rule].matches);
            metrics::inc(&metrics.lines_ignored);
        }
    }
}

/// The monotonic time at which the wall clock read `at`, assuming the
/// clock was not changed since. Never later than now. On Linux an
/// `Instant` holds signed seconds, so times before boot (entries replayed
/// from a saved cursor after a reboot) keep their spacing; only a time
/// beyond that range would become now.
fn instant_of(at: SystemTime) -> Instant {
    let now = Instant::now();
    match SystemTime::now().duration_since(at) {
        Ok(ago) => now.checked_sub(ago).unwrap_or(now),
        Err(_) => now,
    }
}

/// Reads and validates the configuration again and, only if that fully
/// succeeds, applies it; otherwise the running configuration stays as it
/// is. Runs on the monitor thread between polls, so no line is matched
/// against a partly applied configuration.
fn apply_reload(
    path: &Path,
    running: &mut Config,
    monitor: &mut Monitor,
    pipeline: &mut Pipeline,
    stats_interval: &AtomicU64,
) {
    let new = match config::load(path) {
        Ok(cfg) => keep_restart_only(running, cfg),
        Err(e) => {
            metrics::inc(&pipeline.metrics.config_reload_failures);
            warn!(error = %e, "configuration reload failed; keeping the running configuration");
            return;
        }
    };
    // Lines still pending in removed files are matched with the old rules.
    monitor.reconfigure(&new, &mut |file, line| pipeline.line(file, line));
    let kept: Vec<Option<usize>> = new
        .rules
        .iter()
        .map(|r| running.rules.iter().position(|old| old.same_definition(r)))
        .collect();
    pipeline.limiter.reconfigure(&new.limits, &kept);
    pipeline.detector.reconfigure(&new, &kept);
    pipeline.rule_counts = pipeline.rule_stats.replace(&new.rules, &kept);
    pipeline.engine = Engine::new(new.rules.clone());
    pipeline.max_excerpt = new.output.max_excerpt_bytes;
    pipeline.dispatcher.set_policy(&new.output);
    pipeline.dispatcher.set_tables(Arc::new(Tables {
        rules: new.rules.clone(),
        meta: pipeline.meta.clone(),
    }));
    stats_interval.store(new.general.stats_interval_secs, Ordering::Relaxed);
    metrics::inc(&pipeline.metrics.config_reloads);
    info!(
        files = monitor.files(),
        globs = new.globs.len(),
        rules = new.rules.len(),
        rules_unchanged = kept.iter().flatten().count(),
        "configuration reloaded"
    );
    *running = new;
}

/// Settings that only take effect at startup keep their running values,
/// with a warning naming the ones that changed.
fn keep_restart_only(running: &Config, mut new: Config) -> Config {
    let mut kept = Vec::new();
    macro_rules! keep {
        ($($section:ident . $field:ident),* $(,)?) => {$(
            if new.$section.$field != running.$section.$field {
                kept.push(concat!(stringify!($section), ".", stringify!($field)));
                new.$section.$field = running.$section.$field.clone();
            }
        )*};
    }
    keep!(
        general.startup_mode,
        general.max_line_bytes,
        general.diagnostics,
        general.state_file,
        general.state_flush_ms,
        output.format,
        output.destination,
        output.queue_capacity,
        output.syslog_prefix,
    );
    if new.journal != running.journal {
        kept.push("journal");
        new.journal = running.journal.clone();
    }
    if !kept.is_empty() {
        warn!(
            settings = %kept.join(", "),
            "changed settings take effect only after a restart; keeping their running values"
        );
    }
    new
}

fn log_statistics(metrics: &Metrics, rule_stats: &RuleStats) {
    info!(stats = %metrics.snapshot(), "statistics");
    info!(rules = %rule_stats, "rule counts");
}

/// Signals handled by the signal thread.
const HANDLED: [libc::c_int; 4] = [libc::SIGTERM, libc::SIGINT, libc::SIGUSR1, libc::SIGHUP];

/// An initialised signal set. `sigset_t` is plain data, so this is `Send`
/// without any `unsafe impl`.
pub(crate) struct SigSet(libc::sigset_t);

impl SigSet {
    /// Waits for one of the signals in the set.
    pub(crate) fn wait(&self) -> io::Result<libc::c_int> {
        let mut sig: libc::c_int = 0;
        // SAFETY: `self.0` is an initialised sigset_t and `sig` is a valid
        // out-pointer.
        let rc = unsafe { libc::sigwait(&self.0, &mut sig) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        Ok(sig)
    }
}

/// Blocks `signals` in the calling thread (and so in every thread spawned
/// afterwards). Must be called before any other thread exists.
pub(crate) fn block_signals(signals: &[libc::c_int]) -> io::Result<SigSet> {
    // SAFETY: sigset_t is a plain C struct initialised by sigemptyset before
    // use; all pointers passed are valid for the duration of each call.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &sig in signals {
            libc::sigaddset(&mut set, sig);
        }
        let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        Ok(SigSet(set))
    }
}

fn spawn_signal_thread(
    set: SigSet,
    shutdown: Arc<AtomicBool>,
    reload: Arc<AtomicBool>,
    waker: Waker,
    metrics: Arc<Metrics>,
    rule_stats: Arc<RuleStats>,
) -> io::Result<()> {
    thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            let set = set;
            loop {
                let sig = match set.wait() {
                    Ok(sig) => sig,
                    Err(e) => {
                        warn!(error = %e, "sigwait failed");
                        thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                };
                match sig {
                    libc::SIGTERM | libc::SIGINT => {
                        info!(signal = sig, "termination requested");
                        shutdown.store(true, Ordering::Relaxed);
                        waker.wake();
                    }
                    libc::SIGUSR1 => log_statistics(&metrics, &rule_stats),
                    libc::SIGHUP => {
                        info!("configuration reload requested");
                        reload.store(true, Ordering::Relaxed);
                        waker.wake();
                    }
                    _ => {}
                }
            }
        })?;
    Ok(())
}

/// Logs statistics every `interval` seconds (0 = never). The interval is
/// re-read every second, so a reload takes effect without a restart.
fn spawn_stats_thread(
    interval: Arc<AtomicU64>,
    metrics: Arc<Metrics>,
    rule_stats: Arc<RuleStats>,
) -> io::Result<()> {
    thread::Builder::new().name("stats".into()).spawn(move || {
        let mut waited = 0u64;
        loop {
            thread::sleep(Duration::from_secs(1));
            waited += 1;
            let every = interval.load(Ordering::Relaxed);
            if every > 0 && waited >= every {
                log_statistics(&metrics, &rule_stats);
                waited = 0;
            }
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_times_before_boot_keep_their_spacing() {
        // Far longer ago than any machine's uptime.
        let long_ago = SystemTime::now() - Duration::from_secs(400 * 86_400);
        let a = instant_of(long_ago);
        let b = instant_of(long_ago + Duration::from_secs(30));
        let spacing = b.duration_since(a).as_secs_f64();
        assert!((spacing - 30.0).abs() < 1.0, "{spacing}");
        assert!(Instant::now().duration_since(a) > Duration::from_secs(399 * 86_400));
        // A time in the future (clock skew) is now.
        let future = instant_of(SystemTime::now() + Duration::from_secs(60));
        assert!(future <= Instant::now());
    }
}

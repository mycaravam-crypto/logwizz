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

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use tracing::{info, warn};

use crate::config::{self, Config, Destination};
use crate::dispatcher::{Admit, Dispatcher, Limiter, Meta, Tables};
use crate::engine::Engine;
use crate::error::RuntimeError;
use crate::event::{Event, excerpt};
use crate::metrics::{self, Metrics};
use crate::monitor::{Monitor, Stopped};
use crate::reader::Line;
use crate::state::{self, Checkpoint, StateWriter};
use crate::threshold::Thresholds;
use crate::watcher::Waker;

/// Runs the daemon until a termination signal or an output failure.
/// `config_path` is read again on SIGHUP.
pub fn run(cfg: Config, config_path: &Path) -> Result<(), RuntimeError> {
    let signals = block_signals().map_err(RuntimeError::Startup)?;

    let metrics = Arc::new(Metrics::default());
    let shutdown = Arc::new(AtomicBool::new(false));
    let reload = Arc::new(AtomicBool::new(false));
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
    )
    .map_err(RuntimeError::Startup)?;
    let stats_interval = Arc::new(AtomicU64::new(cfg.general.stats_interval_secs));
    spawn_stats_thread(Arc::clone(&stats_interval), Arc::clone(&metrics))
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
    let mut pipeline = Pipeline {
        engine: Engine::new(cfg.rules.clone()),
        limiter: Limiter::new(&cfg.limits, cfg.rules.len()),
        thresholds: Thresholds::new(
            cfg.rules.len(),
            cfg.limits.threshold_max_groups,
            Arc::clone(&metrics),
        ),
        dispatcher,
        metrics: Arc::clone(&metrics),
        meta,
        max_excerpt: cfg.output.max_excerpt_bytes,
    };

    info!(
        version = env!("CARGO_PKG_VERSION"),
        files = monitor.files(),
        globs = cfg.globs.len(),
        rules = cfg.rules.len(),
        "logwizz started"
    );

    let mut running = cfg;
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
        let stopped = monitor.run_with(
            &shutdown,
            Some(&reload),
            &mut |file, line| pipeline.line(file, line),
            checkpoints,
        );
        if stopped == Stopped::Shutdown {
            break;
        }
        apply_reload(
            config_path,
            &mut running,
            &mut monitor,
            &mut pipeline,
            &stats_interval,
        );
    }

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
    info!(stats = %metrics.snapshot(), "logwizz stopped");
    result.map_err(RuntimeError::Output)
}

/// Everything a line passes through on the monitor thread: matching,
/// thresholds, limiting and queueing.
struct Pipeline {
    engine: Engine,
    limiter: Limiter,
    thresholds: Thresholds,
    dispatcher: Dispatcher,
    metrics: Arc<Metrics>,
    meta: Meta,
    max_excerpt: Option<usize>,
}

impl Pipeline {
    fn line(&mut self, file: &Arc<Path>, line: Line<'_>) {
        let Pipeline {
            engine,
            limiter,
            thresholds,
            dispatcher,
            metrics,
            max_excerpt,
            ..
        } = self;
        let ignored = engine.for_each_match(line.bytes, |rule| {
            metrics::inc(&metrics.rule_matches);
            let r = &engine.rules()[rule];
            let now = Instant::now();
            let fields = r.matcher.fields(line.bytes);
            let threshold = match &r.threshold {
                None => None,
                Some(t) => match thresholds.observe(rule, &r.id, t, file, &fields, now) {
                    Some(fired) => {
                        metrics::inc(&metrics.threshold_fired);
                        Some(Box::new(fired))
                    }
                    None => {
                        metrics::inc(&metrics.threshold_absorbed);
                        return;
                    }
                },
            };
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
        if ignored {
            metrics::inc(&metrics.lines_ignored);
        }
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
    pipeline
        .thresholds
        .reconfigure(new.limits.threshold_max_groups, &kept);
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

/// Signals handled by the signal thread.
const HANDLED: [libc::c_int; 4] = [libc::SIGTERM, libc::SIGINT, libc::SIGUSR1, libc::SIGHUP];

/// An initialised signal set. `sigset_t` is plain data, so this is `Send`
/// without any `unsafe impl`.
struct SigSet(libc::sigset_t);

/// Blocks the handled signals in the calling thread (and so in every thread
/// spawned afterwards). Must be called before any other thread exists.
fn block_signals() -> io::Result<SigSet> {
    // SAFETY: sigset_t is a plain C struct initialised by sigemptyset before
    // use; all pointers passed are valid for the duration of each call.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for sig in HANDLED {
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
) -> io::Result<()> {
    thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            let set = set;
            loop {
                let mut sig: libc::c_int = 0;
                // SAFETY: `set` is an initialised sigset_t and `sig` is a valid
                // out-pointer.
                let rc = unsafe { libc::sigwait(&set.0, &mut sig) };
                if rc != 0 {
                    warn!(error = %io::Error::from_raw_os_error(rc), "sigwait failed");
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
                match sig {
                    libc::SIGTERM | libc::SIGINT => {
                        info!(signal = sig, "termination requested");
                        shutdown.store(true, Ordering::Relaxed);
                        waker.wake();
                    }
                    libc::SIGUSR1 => info!(stats = %metrics.snapshot(), "statistics"),
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
fn spawn_stats_thread(interval: Arc<AtomicU64>, metrics: Arc<Metrics>) -> io::Result<()> {
    thread::Builder::new().name("stats".into()).spawn(move || {
        let mut waited = 0u64;
        loop {
            thread::sleep(Duration::from_secs(1));
            waited += 1;
            let every = interval.load(Ordering::Relaxed);
            if every > 0 && waited >= every {
                info!(stats = %metrics.snapshot(), "statistics");
                waited = 0;
            }
        }
    })?;
    Ok(())
}

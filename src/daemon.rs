//! Wiring: signals, the monitor loop, rule evaluation and output.
//!
//! Threads:
//! * main: the monitor loop (reading, matching, limiting, enqueueing)
//! * `output`: formats and writes events
//! * `signals`: waits synchronously for SIGTERM/SIGINT/SIGUSR1/SIGHUP
//! * `stats` (optional): periodic statistics diagnostics
//! * the notify crate's inotify thread
//!
//! Signals are blocked in every thread (the mask is set before any thread is
//! spawned and is inherited) and consumed only by `sigwait` in the signal
//! thread, so no code runs in async-signal context.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use tracing::{info, warn};

use crate::config::{Config, Destination};
use crate::dispatcher::{Admit, Dispatcher, Limiter, Meta, Tables};
use crate::engine::Engine;
use crate::error::RuntimeError;
use crate::event::{Event, excerpt};
use crate::metrics::{self, Metrics};
use crate::monitor::Monitor;
use crate::watcher::Waker;

/// Runs the daemon until a termination signal or an output failure.
pub fn run(cfg: Config) -> Result<(), RuntimeError> {
    let signals = block_signals().map_err(RuntimeError::Startup)?;

    let metrics = Arc::new(Metrics::default());
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut monitor = Monitor::new(&cfg, Arc::clone(&metrics), true);
    let waker = monitor.waker();

    spawn_signal_thread(
        signals,
        Arc::clone(&shutdown),
        waker.clone(),
        Arc::clone(&metrics),
    )
    .map_err(RuntimeError::Startup)?;
    if cfg.general.stats_interval_secs > 0 {
        spawn_stats_thread(
            Duration::from_secs(cfg.general.stats_interval_secs),
            Arc::clone(&metrics),
        )
        .map_err(RuntimeError::Startup)?;
    }

    let engine = Engine::new(cfg.rules.clone());
    let tables = Arc::new(Tables {
        files: cfg.files.clone(),
        rules: cfg.rules.clone(),
        meta: Meta::current(),
    });
    let writer: Box<dyn io::Write + Send> = match cfg.output.destination {
        Destination::Stdout => Box::new(io::stdout()),
        Destination::Stderr => Box::new(io::stderr()),
    };
    let mut dispatcher = Dispatcher::spawn(
        &cfg,
        tables,
        writer,
        Arc::clone(&metrics),
        Arc::clone(&shutdown),
        waker,
    )
    .map_err(RuntimeError::Output)?;
    let mut limiter = Limiter::new(&cfg.limits, engine.rules().len());
    let max_excerpt = cfg.output.max_excerpt_bytes;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        files = cfg.files.len(),
        rules = engine.rules().len(),
        "logwizz started"
    );

    monitor.run(&shutdown, &mut |file, line| {
        engine.for_each_match(line.bytes, |rule| {
            metrics::inc(&metrics.rule_matches);
            let id = &engine.rules()[rule].id;
            match limiter.admit(rule, id, line.bytes, Instant::now()) {
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
            let (bytes, cut) = excerpt(line.bytes, max_excerpt);
            dispatcher.send(Event {
                time: SystemTime::now(),
                file,
                rule,
                line: bytes.into(),
                truncated: line.truncated || cut,
            });
        });
    });

    info!("shutting down; flushing queued events");
    let result = dispatcher.finish();
    info!(stats = %metrics.snapshot(), "logwizz stopped");
    result.map_err(RuntimeError::Output)
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
                    libc::SIGHUP => warn!(
                        "SIGHUP received: configuration reload is not supported in this version; \
                     restart the service to apply changes"
                    ),
                    _ => {}
                }
            }
        })?;
    Ok(())
}

fn spawn_stats_thread(interval: Duration, metrics: Arc<Metrics>) -> io::Result<()> {
    thread::Builder::new().name("stats".into()).spawn(move || {
        loop {
            thread::sleep(interval);
            info!(stats = %metrics.snapshot(), "statistics");
        }
    })?;
    Ok(())
}

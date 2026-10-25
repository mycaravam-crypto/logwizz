use std::io::IsTerminal;
use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::filter::LevelFilter;

use logwizz::cli::Cli;
use logwizz::config::{self, DiagnosticLevel};
use logwizz::daemon;

/// Exit code for runtime failures (e.g. the output became unwritable).
const EXIT_RUNTIME: u8 = 1;
/// Exit code for configuration errors.
const EXIT_CONFIG: u8 = 2;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let cfg = match config::load(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("logwizz: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };

    if cli.check_config {
        println!(
            "configuration OK: {} file(s), {} glob(s) ({} disabled), {} rule(s) ({} disabled)",
            cfg.files.len(),
            cfg.globs.len(),
            cfg.disabled_files,
            cfg.rules.len(),
            cfg.disabled_rules,
        );
        return ExitCode::SUCCESS;
    }

    let level = match cfg.general.diagnostics {
        DiagnosticLevel::Error => LevelFilter::ERROR,
        DiagnosticLevel::Warn => LevelFilter::WARN,
        DiagnosticLevel::Info => LevelFilter::INFO,
        DiagnosticLevel::Debug => LevelFilter::DEBUG,
        DiagnosticLevel::Trace => LevelFilter::TRACE,
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_target(false)
        .init();

    match daemon::run(cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::from(EXIT_RUNTIME)
        }
    }
}

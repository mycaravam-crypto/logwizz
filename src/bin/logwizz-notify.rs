use std::io::IsTerminal;
use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::filter::LevelFilter;

use logwizz::notify::{self, Exit, Settings};

/// Exit code for configuration errors.
const EXIT_CONFIG: u8 = 2;

/// Aggregates logwizz detections from the journal and sends summaries to
/// Telegram, ntfy or a webhook. Configured through the environment; see
/// packaging/notify.env.example.
#[derive(Debug, Parser)]
#[command(name = "logwizz-notify", version = env!("LOGWIZZ_VERSION"), about)]
struct Cli {}

fn main() -> ExitCode {
    Cli::parse();
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::INFO)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_target(false)
        .init();

    let settings = match Settings::from_env(|k| std::env::var(k).ok()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("logwizz-notify: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    match notify::run(settings) {
        Ok(Exit::Clean) => ExitCode::SUCCESS,
        // systemd restarts the service; pending summaries are on disk.
        Ok(Exit::Pending | Exit::JournalEnded) => ExitCode::FAILURE,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

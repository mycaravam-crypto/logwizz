use std::process::ExitCode;

use clap::Parser;

use logwizz::cli::Cli;
use logwizz::config;

/// Exit code for configuration errors (distinct from runtime failures).
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
            "configuration OK: {} file(s) ({} disabled), {} rule(s) ({} disabled)",
            cfg.files.len(),
            cfg.disabled_files,
            cfg.rules.len(),
            cfg.disabled_rules,
        );
        return ExitCode::SUCCESS;
    }

    eprintln!("logwizz: monitoring is not implemented yet");
    ExitCode::FAILURE
}

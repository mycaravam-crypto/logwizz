//! Command-line interface.

use std::path::PathBuf;

use clap::Parser;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/logwizz/logwizz.toml";

/// Minimalist, high-performance Linux log monitoring daemon.
#[derive(Debug, Parser)]
#[command(name = "logwizz", version = env!("LOGWIZZ_VERSION"), about)]
pub struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, value_name = "PATH", default_value = DEFAULT_CONFIG_PATH)]
    pub config: PathBuf,

    /// Validate the configuration and exit without starting the monitor.
    #[arg(long)]
    pub check_config: bool,
}

//! Error types shared across modules.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Errors raised while loading or validating configuration.
///
/// These are always fatal at startup: the daemon never runs with a partially
/// valid configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration file {}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },

    #[error("configuration file {} exceeds the maximum size of {limit} bytes", path.display())]
    TooLarge { path: PathBuf, limit: u64 },

    #[error("configuration file {} is not valid UTF-8", path.display())]
    NotUtf8 { path: PathBuf },

    #[error("cannot parse configuration file {}: {source}", path.display())]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },

    #[error("invalid configuration in {}:{}", path.display(), format_problems(problems))]
    Invalid {
        path: PathBuf,
        problems: Vec<String>,
    },
}

fn format_problems(problems: &[String]) -> String {
    let mut out = String::new();
    for problem in problems {
        out.push_str("\n  - ");
        out.push_str(problem);
    }
    out
}

/// Errors that stop the running daemon.
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error("filesystem watcher failed: {0}")]
    Watcher(String),

    #[error("cannot install signal handler: {0}")]
    Signal(io::Error),

    #[error("output failed: {0}")]
    Output(io::Error),
}

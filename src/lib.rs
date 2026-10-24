//! logwizz: a minimalist, high-performance Linux log monitoring daemon.
//!
//! The binary in `main.rs` is a thin wrapper; all logic lives in these
//! modules so that it can be exercised directly by integration tests.

pub mod cli;
pub mod config;
pub mod daemon;
pub mod dispatcher;
pub mod engine;
pub mod error;
pub mod event;
pub mod metrics;
pub mod monitor;
pub mod reader;
pub mod state;
pub mod watcher;

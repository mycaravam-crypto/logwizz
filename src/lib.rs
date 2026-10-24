//! logwizz: a minimalist, high-performance Linux log monitoring daemon.
//!
//! The binary in `main.rs` is a thin wrapper; all logic lives in these
//! modules so that it can be exercised directly by integration tests.

pub mod cli;
pub mod config;
pub mod engine;
pub mod error;
pub mod event;

//! Helpers shared by integration tests.
#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use logwizz::config::StartupMode;
use logwizz::metrics::Metrics;
use logwizz::reader::{READ_BUF_BYTES, ReaderOptions, TailedFile};

pub struct Harness {
    pub file: TailedFile,
    pub metrics: Metrics,
    buf: Vec<u8>,
    pub now: Instant,
}

impl Harness {
    pub fn new(path: PathBuf, startup: StartupMode) -> Self {
        Self::with_opts(
            path,
            startup,
            ReaderOptions {
                max_line_bytes: 1024,
                read_budget: 1 << 20,
                drain_grace: Duration::from_secs(5),
            },
        )
    }

    pub fn with_opts(path: PathBuf, startup: StartupMode, opts: ReaderOptions) -> Self {
        Harness {
            file: TailedFile::new(path, startup, opts),
            metrics: Metrics::default(),
            buf: vec![0; READ_BUF_BYTES],
            now: Instant::now(),
        }
    }

    /// Polls until no more data is pending and returns the lines produced.
    pub fn poll(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            let more = self
                .file
                .poll(self.now, &mut self.buf, &self.metrics, &mut |l| {
                    let mut s = String::from_utf8_lossy(l.bytes).into_owned();
                    if l.truncated {
                        s.push('~');
                    }
                    out.push(s);
                });
            if !more {
                return out;
            }
        }
    }

    pub fn advance(&mut self, d: Duration) {
        self.now += d;
    }
}

pub fn append(path: &Path, data: &str) {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    f.write_all(data.as_bytes()).unwrap();
}

pub fn write_new(path: &Path, data: &str) {
    let mut f = File::create(path).unwrap();
    f.write_all(data.as_bytes()).unwrap();
}

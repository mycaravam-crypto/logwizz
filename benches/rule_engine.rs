//! Rule matching and read-pipeline throughput.
//!
//! * `match/*` measures rule evaluation only, over an in-memory set of
//!   realistic syslog-style lines (~100 bytes each).
//! * `pipeline/*` measures reading a page-cached file, splitting lines and
//!   evaluating rules: everything except event formatting and output.
//! * `limiter/*` measures deduplication with a full table whose entries
//!   have not expired, fed a stream of unique lines (the worst case).
//! * `threshold/*` measures one firewall-log match through capture
//!   extraction and a `group_by` + `distinct` threshold: a single scanner
//!   (one group), and a flood from new sources into a full group table.
//!
//! Run with `cargo bench --bench rule_engine`.

use std::hint::black_box;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use logwizz::config::{self, GroupBy, Limits, StartupMode, Threshold};
use logwizz::dispatcher::Limiter;
use logwizz::engine::Engine;
use logwizz::metrics::Metrics;
use logwizz::reader::{READ_BUF_BYTES, ReaderOptions, TailedFile};
use logwizz::threshold::Thresholds;

const LINES: &[&str] = &[
    "Oct 24 08:15:30 host sshd[1234]: Accepted publickey for deploy from 10.0.0.5 port 52144 ssh2",
    "Oct 24 08:15:31 host systemd[1]: Started Session 42 of user deploy.",
    "Oct 24 08:15:32 host CRON[5678]: (root) CMD (/usr/local/bin/backup --incremental)",
    "Oct 24 08:15:33 host kernel: [12345.678901] eth0: link up, 1000Mbps, full-duplex",
    "Oct 24 08:15:34 host nginx[910]: 10.0.0.9 - - \"GET /healthz HTTP/1.1\" 200 2 \"-\" \"probe\"",
    "Oct 24 08:15:35 host sshd[1240]: Failed password for invalid user admin from 192.0.2.7",
    "Oct 24 08:15:36 host postfix/smtpd[2222]: connect from mail.example.org[198.51.100.3]",
    "Oct 24 08:15:37 host dbus-daemon[700]: [system] Successfully activated service 'org.x'",
];

fn engine(n: usize, kind: &str) -> Engine {
    let mut text = String::from("[[files]]\npath = \"/x\"\n");
    for i in 0..n {
        let pattern = match kind {
            "literal" => format!("no such token {i}"),
            _ => format!(r"(?i)error code \d+ in module{i}\b"),
        };
        text.push_str(&format!(
            "[[rules]]\nid = \"r{i}\"\nmatch_type = \"{kind}\"\npattern = '{pattern}'\nseverity = \"info\"\n"
        ));
    }
    // One rule that hits 1 in 8 lines, so match cost is represented too.
    text.push_str(
        "[[rules]]\nid = \"hit\"\nmatch_type = \"literal\"\npattern = \"Failed password\"\nseverity = \"warning\"\n",
    );
    Engine::new(config::parse(&text, Path::new("bench")).unwrap().rules)
}

fn bench_match(c: &mut Criterion) {
    let lines: Vec<&[u8]> = LINES.iter().map(|l| l.as_bytes()).collect();
    let bytes: usize = lines.iter().map(|l| l.len()).sum();
    let mut g = c.benchmark_group("match");
    g.throughput(Throughput::Elements(lines.len() as u64));
    for kind in ["literal", "regex"] {
        for n in [1, 10, 50] {
            let e = engine(n, kind);
            g.bench_with_input(BenchmarkId::new(kind, n), &e, |b, e| {
                b.iter(|| {
                    let mut hits = 0;
                    for l in &lines {
                        e.for_each_match(black_box(l), |_| hits += 1);
                    }
                    hits
                })
            });
        }
    }
    g.finish();
    let _ = bytes;
}

fn bench_pipeline(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench.log");
    let mut f = std::fs::File::create(&path).unwrap();
    let mut total_lines = 0u64;
    let mut total_bytes = 0u64;
    while total_bytes < 32 * 1024 * 1024 {
        for l in LINES {
            f.write_all(l.as_bytes()).unwrap();
            f.write_all(b"\n").unwrap();
            total_bytes += l.len() as u64 + 1;
            total_lines += 1;
        }
    }
    drop(f);

    let mut g = c.benchmark_group("pipeline");
    g.throughput(Throughput::Elements(total_lines));
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(10));
    for (kind, n) in [("literal", 10), ("regex", 10)] {
        let e = engine(n, kind);
        g.bench_function(BenchmarkId::new(kind, n), |b| {
            let mut buf = vec![0; READ_BUF_BYTES];
            b.iter(|| {
                let m = Metrics::default();
                let opts = ReaderOptions {
                    max_line_bytes: 64 * 1024,
                    read_budget: usize::MAX,
                    drain_grace: Duration::from_secs(1),
                };
                let mut tf = TailedFile::new(path.clone(), StartupMode::Beginning, opts);
                let mut hits = 0u64;
                tf.poll(std::time::Instant::now(), &mut buf, &m, &mut |line| {
                    e.for_each_match(line.bytes, |_| hits += 1);
                });
                assert_eq!(m.snapshot().lines_processed, total_lines);
                hits
            })
        });
    }
    g.finish();
}

fn bench_limiter(c: &mut Criterion) {
    let mut g = c.benchmark_group("limiter");
    g.throughput(Throughput::Elements(1));
    for entries in [4096, 262_144] {
        let limits = Limits {
            rate_limit_events: 0,
            rate_limit_window_secs: 60,
            dedup_window_secs: 3600,
            dedup_max_entries: entries,
            ..Limits::default()
        };
        let mut l = Limiter::new(&limits, 1);
        let start = Instant::now();
        let mut n = 0u64;
        // Fill the table; nothing expires within the benchmark.
        while (n as usize) < entries {
            l.admit(0, "r", &n.to_le_bytes(), start);
            n += 1;
        }
        g.bench_function(BenchmarkId::new("dedup_full_unique", entries), |b| {
            b.iter(|| {
                n += 1;
                l.admit(0, "r", black_box(&n.to_le_bytes()), start)
            })
        });
    }
    g.finish();
}

fn bench_threshold(c: &mut Criterion) {
    let mut g = c.benchmark_group("threshold");
    g.throughput(Throughput::Elements(1));
    let cfg = config::parse(
        "[[files]]\npath = \"/x\"\n[[rules]]\nid = \"scan\"\nmatch_type = \"regex\"\n\
         pattern = 'logwizz-drop: .*SRC=(?P<src>\\S+) .*DPT=(?P<dpt>\\d+)'\nseverity = \"critical\"\n",
        Path::new("bench"),
    )
    .unwrap();
    let matcher = &cfg.rules[0].matcher;
    let t = Threshold {
        group_by: GroupBy::Capture(1),
        distinct: Some(2),
        count: 20,
        window: Duration::from_secs(10),
        cooldown: Duration::from_secs(300),
    };
    let line = |src: u32, dpt: u32| {
        format!(
            "Oct 25 10:00:00 web1 kernel: logwizz-drop: IN=eth0 OUT= SRC=10.{}.{}.{} \
             DST=198.51.100.1 LEN=44 PROTO=TCP SPT=40000 DPT={dpt} SYN",
            src >> 16 & 255,
            src >> 8 & 255,
            src & 255
        )
    };
    let m = Metrics::default();
    let now = Instant::now();
    let mut th = Thresholds::new(1, 4096);
    let lines: Vec<String> = (0..1000).map(|p| line(1, p)).collect();
    let mut i = 0;
    g.bench_function("one_scanner", |b| {
        b.iter(|| {
            i = (i + 1) % lines.len();
            let l = lines[i].as_bytes();
            let fields = matcher.fields(black_box(l));
            th.observe(0, "scan", &t, 0, &fields, now, &m)
        })
    });
    let mut th = Thresholds::new(1, 4096);
    let mut src = 0u32;
    g.bench_function("new_sources_full_table", |b| {
        b.iter(|| {
            src = src.wrapping_add(1);
            let l = line(src, 22);
            let fields = matcher.fields(black_box(l.as_bytes()));
            th.observe(0, "scan", &t, 0, &fields, now, &m)
        })
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_match,
    bench_pipeline,
    bench_limiter,
    bench_threshold
);
criterion_main!(benches);

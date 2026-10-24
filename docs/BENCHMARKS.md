# Benchmarks

The numbers below are from real runs. They are only meaningful together
with the system they were measured on, so re-run the commands on your own
hardware before relying on them.

## Reference system (2026-10-24)

| | |
|---|---|
| CPU | Intel Xeon @ 2.10 GHz, 4 vCPUs (cloud VM) |
| Memory | 15 GiB |
| OS / kernel | Ubuntu 24.04.5 LTS, Linux 6.18.44 |
| Filesystem | ext4 (log files in page cache) |
| Toolchain | rustc 1.97.0, release profile (`lto = "thin"`, `codegen-units = 1`) |
| logwizz | 0.1.0 (the commit that added this file) |

The VM was shared and not otherwise isolated, so expect some variance.

## End-to-end load test

Command:

```sh
cargo test --release --test load -- --ignored --nocapture --test-threads=1
```

Setup:

- One monitored file in `tail` mode, default configuration (reconcile
  1000 ms, queue 4096, `on_full = "block"`), and JSON output to a pipe read by
  the test.
- Lines average 84 bytes (maximum 94) plus newline, in syslog style. One line in
  eight matches the literal rule `Failed password`. The other rules are
  case-insensitive regexes that never match, which is the worst case for
  them, since every one must scan the whole line.
- Measured from the writer's first `write()` to the arrival of the last JSON
  event on the test's end of the pipe. This covers detection, reading,
  matching, JSON formatting and output, end to end.

### Throughput (2,000,000 lines, 250,000 events)

| Rules | Run 1 | Run 2 | Run 3 | Peak RSS |
|---|---|---|---|---|
| 1 literal | 5.76 M lines/s | 5.26 M lines/s | 7.95 M lines/s | 4.9 MiB |
| 1 literal + 10 regex | 1.29 M lines/s | 1.61 M lines/s | 1.46 M lines/s | 6.0 – 6.2 MiB |

### Detection latency

1000 samples. Each is a single `write()` of one matching line followed by a
10 ms pause, timed from the write to the arrival of the event (11 rules):

| Run | p50 | p95 | p99 | max |
|---|---|---|---|---|
| 1 | 0.47 ms | 0.73 ms | 1.58 ms | 4.1 ms |
| 2 | 0.47 ms | 0.75 ms | 1.93 ms | 55.1 ms |
| 3 | 0.48 ms | 0.87 ms | 2.00 ms | 3.9 ms |

### Idle CPU and memory

The daemon was idle for 10 s with one file, 11 rules and the default 1 s
reconcile interval. `/proc/<pid>/stat` showed **0 clock ticks**
(`CLK_TCK = 100`) in all three runs, which is below the 0.1% resolution of
this measurement. RSS stayed at about 5.8 MiB at idle and after the latency
test.

### Against the NFR-001 targets

| Target | Result on the reference system |
|---|---|
| Idle CPU < 1% of a core | < 0.1% (below measurement resolution) |
| RSS < 20 MiB, small configuration | ≈ 5.8 MiB, peak 6.2 MiB |
| p95 detection latency < 100 ms | 0.73 – 0.87 ms |
| ≥ 100,000 short lines/s | 1.3 – 8.0 M lines/s, depending on rules |

## Micro-benchmarks (criterion)

```sh
cargo bench --bench rule_engine
```

`match/*` covers rule evaluation only, over 8 in-memory lines (83 bytes on
average); one extra literal rule hits one line in eight. `pipeline/*` covers
reading a 32 MiB page-cached file, splitting it into lines and evaluating
rules, without formatting or output. Each figure is the median estimate.

| Benchmark | Time per 8 lines | Throughput |
|---|---|---|
| match/literal/1 | 164 ns | 48.9 M lines/s |
| match/literal/10 | 837 ns | 9.6 M lines/s |
| match/literal/50 | 4.06 µs | 2.0 M lines/s |
| match/regex/1 | 293 ns | 27.3 M lines/s |
| match/regex/10 | 2.76 µs | 2.9 M lines/s |
| match/regex/50 | 16.1 µs | 0.50 M lines/s |

| Benchmark | Time (≈ 400k lines) | Throughput |
|---|---|---|
| pipeline/literal/10 | 58.7 ms | 6.8 M lines/s |
| pipeline/regex/10 | 151 ms | 2.6 M lines/s |

Cost grows linearly with the number of rules, because every rule is
evaluated against every line. Even 50 never-matching case-insensitive regex
rules stay well above the throughput target, so combining rules into a
`RegexSet` has not been justified yet.

//! `--test`: a sample log run through the rules once.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use logwizz::config;
use logwizz::testrun::{self, Report};

const CONFIG: &str = r#"
[[files]]
path = "/var/log/auth.log"
[[files]]
path = "/var/log/web.log"

[[rules]]
id = "failed"
match_type = "regex"
pattern = 'Failed password for (?P<user>\S+) from (?P<src>\S+)'
severity = "warning"
files = ["/var/log/auth.log"]
[rules.exclude]
src = ["10.0.0.0/8"]
[rules.types]
src = "ip"

[[rules]]
id = "bruteforce"
match_type = "regex"
pattern = 'Failed password for \S+ from (?P<src>\S+)'
severity = "critical"
[rules.threshold]
group_by = "src"
count = 3
window_secs = 60
cooldown_secs = 600

[[rules]]
id = "login"
match_type = "regex"
pattern = 'Accepted \S+ for \S+ from (?P<src>\S+)'
severity = "critical"
[rules.after]
rules = ["bruteforce"]
field = "src"
within_secs = 600

[[rules]]
id = "cron"
match_type = "literal"
pattern = "CRON"
action = "ignore"

[[rules]]
id = "web"
match_type = "literal"
pattern = "GET"
severity = "info"
files = ["/var/log/web.log"]
"#;

const SAMPLE: &str = "\
sshd: Failed password for root from 192.0.2.7 port 1\n\
sshd: Failed password for root from 192.0.2.7 port 2\n\
sshd: Accepted publickey for root from 192.0.2.7 port 3\n\
sshd: Failed password for root from 192.0.2.7 port 4\n\
sshd: Failed password for root from 192.0.2.7 port 5\n\
sshd: Failed password for \u{1b}[31m from 10.1.2.3 port 6\n\
sshd: Accepted publickey for root from 192.0.2.7 port 7\n\
CRON[9]: Failed password for nobody from 192.0.2.9\n\
sshd: Failed password for x from y from 192.0.2.7 port 8\n\
kernel: unrelated\n";

fn report(input: &str) -> (config::Config, Report) {
    let cfg = config::parse(CONFIG, Path::new("t")).unwrap();
    let report = testrun::run(&cfg, &mut SAMPLE.as_bytes(), Path::new(input)).unwrap();
    (cfg, report)
}

fn rule<'a>(cfg: &config::Config, report: &'a Report, id: &str) -> &'a testrun::RuleReport {
    &report.rules[cfg.rules.iter().position(|r| r.id == id).unwrap()]
}

#[test]
fn counts_follow_the_daemons_pipeline() {
    let (cfg, report) = report("/var/log/auth.log");
    assert_eq!(
        (
            report.lines,
            report.truncated,
            report.ignored,
            report.unmatched
        ),
        (10, 0, 1, 1)
    );

    let failed = rule(&cfg, &report, "failed");
    // The CRON line: an earlier rule still sees a line a later one ignores.
    // "x from y": the client's user name put text where the address goes.
    assert_eq!(
        (
            failed.matches,
            failed.mistyped,
            failed.excluded,
            failed.events
        ),
        (7, 1, 1, 5)
    );
    let (line, fields) = failed.first.as_ref().unwrap();
    assert_eq!(*line, 1);
    assert_eq!(
        fields[..],
        [
            ("user".into(), "root".into()),
            ("src".into(), "192.0.2.7".into())
        ]
    );

    // One report for the source, then its cooldown; the others never reach 3.
    let brute = rule(&cfg, &report, "bruteforce");
    assert_eq!((brute.matches, brute.absorbed, brute.events), (7, 6, 1));
    assert_eq!(brute.reports, [(4, Some("192.0.2.7".to_string()), 3)]);

    // The login before the report does not count, the one after it does.
    let login = rule(&cfg, &report, "login");
    assert_eq!((login.matches, login.unsequenced, login.events), (2, 1, 1));

    assert_eq!(rule(&cfg, &report, "cron").matches, 1);
    assert_eq!(rule(&cfg, &report, "web").matches, 0);
}

#[test]
fn scoped_rules_follow_the_named_input() {
    let (cfg, report) = report("/var/log/web.log");
    assert_eq!(rule(&cfg, &report, "failed").matches, 0);
    assert_eq!(rule(&cfg, &report, "bruteforce").matches, 7);

    let mut out = Vec::new();
    report
        .write(
            &mut out,
            &cfg.rules,
            "sample",
            Path::new("/var/log/web.log"),
        )
        .unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(
        out.contains("note: 1 rule(s) are limited to other inputs"),
        "{out}"
    );
    assert!(!out.contains("\nfailed "), "{out}");
}

#[test]
fn command_prints_the_report_and_touches_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("logwizz.toml");
    std::fs::write(&config, CONFIG).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_logwizz"))
        .args(["--config", config.to_str().unwrap(), "--test", "-"])
        .args(["--as", "/var/log/auth.log"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(SAMPLE.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();

    assert!(
        text.starts_with("sample: -, read as /var/log/auth.log\n"),
        "{text}"
    );
    assert!(text.contains("lines: 10 read, 0 truncated, 1 ignored, 1 matched no rule\n"));
    let row = |id: &str| -> Vec<String> {
        let line = text.lines().find(|l| l.starts_with(id)).unwrap();
        line.split_whitespace().map(str::to_string).collect()
    };
    assert_eq!(row("failed"), ["failed", "7", "1", "1", "-", "-", "5"]);
    assert_eq!(
        row("bruteforce"),
        ["bruteforce", "7", "-", "-", "-", "6", "1"]
    );
    assert_eq!(row("login"), ["login", "2", "-", "-", "1", "-", "1"]);
    assert_eq!(
        row("cron"),
        ["cron", "1", "-", "-", "-", "-", "-", "(ignore)"]
    );
    assert!(
        text.contains("bruteforce  line 4: 192.0.2.7, count 3\n"),
        "{text}"
    );
    // Text the other side controls is escaped, and no log line is echoed.
    assert!(!text.contains('\u{1b}'), "{text}");
    assert!(!text.contains("port 1"), "{text}");
}

#[test]
fn unreadable_sample_is_a_runtime_failure() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("logwizz.toml");
    std::fs::write(&config, CONFIG).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_logwizz"))
        .args(["--config", config.to_str().unwrap(), "--test"])
        .arg(dir.path().join("missing.log"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}

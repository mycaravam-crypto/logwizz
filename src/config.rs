//! Configuration loading, validation and rule compilation.
//!
//! Loading is all-or-nothing: [`load`] either returns a fully validated
//! [`Config`] with every rule compiled, or an error that lists every problem
//! found. Nothing is activated from a partially valid file.

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use memchr::memmem;
use regex::bytes::RegexBuilder;
use serde::Deserialize;

use crate::engine::{MatchType, Matcher};
use crate::error::ConfigError;
use crate::event::Severity;

/// Configuration files larger than this are rejected before parsing.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

pub const MIN_LINE_BYTES: usize = 256;
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
pub const MIN_RECONCILE_MS: u64 = 50;
pub const MAX_RECONCILE_MS: u64 = 600_000;
pub const MIN_STATE_FLUSH_MS: u64 = 100;
pub const MAX_QUEUE_CAPACITY: usize = 1 << 20;
pub const MAX_FILES: usize = 1024;
pub const MAX_RULES: usize = 1024;
pub const MAX_PATTERN_BYTES: usize = 4096;
pub const MAX_RULE_ID_BYTES: usize = 64;
pub const MIN_EXCERPT_BYTES: usize = 16;
pub const MAX_WINDOW_SECS: u64 = 86_400;
pub const MAX_DEDUP_ENTRIES: usize = 1 << 20;
/// Upper bound on the compiled size of a single regex, so that a pathological
/// pattern cannot consume unbounded memory at load time.
pub const REGEX_SIZE_LIMIT: usize = 2 * 1024 * 1024;

/// Where reading starts for files that exist when monitoring begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StartupMode {
    /// Start at the current end of each file; only new lines are processed.
    #[default]
    Tail,
    /// Process existing content from offset 0.
    Beginning,
}

/// Verbosity of logwizz's own diagnostics (written to stderr).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticLevel {
    Error,
    #[default]
    Warn,
    Info,
    Debug,
    Trace,
}

impl DiagnosticLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            DiagnosticLevel::Error => "error",
            DiagnosticLevel::Warn => "warn",
            DiagnosticLevel::Info => "info",
            DiagnosticLevel::Debug => "debug",
            DiagnosticLevel::Trace => "trace",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Human,
    #[default]
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Destination {
    #[default]
    Stdout,
    Stderr,
}

/// What happens when the output queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnFull {
    /// Stop reading until the output consumer catches up. No events are
    /// lost while the process runs, but detection latency grows.
    #[default]
    Block,
    /// Drop the event and count it in `events_dropped`.
    Drop,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    pub startup_mode: StartupMode,
    pub max_line_bytes: usize,
    pub reconcile_interval_ms: u64,
    pub diagnostics: DiagnosticLevel,
    /// Interval for periodic statistics diagnostics; 0 disables them.
    pub stats_interval_secs: u64,
    /// After rotation, keep reading the old file until it has been idle
    /// for this long.
    pub rotation_drain_ms: u64,
    /// Where read offsets are persisted across restarts; unset disables
    /// persistence.
    pub state_file: Option<PathBuf>,
    /// Minimum time between writes of `state_file`.
    pub state_flush_ms: u64,
}

impl Default for General {
    fn default() -> Self {
        General {
            startup_mode: StartupMode::Tail,
            max_line_bytes: 64 * 1024,
            reconcile_interval_ms: 1000,
            diagnostics: DiagnosticLevel::Warn,
            stats_interval_secs: 0,
            rotation_drain_ms: 5000,
            state_file: None,
            state_flush_ms: 1000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Output {
    pub format: OutputFormat,
    pub destination: Destination,
    pub queue_capacity: usize,
    pub on_full: OnFull,
    /// Maximum number of bytes of the matching line included in an event.
    /// Unset means the whole (already length-limited) line.
    pub max_excerpt_bytes: Option<usize>,
}

impl Default for Output {
    fn default() -> Self {
        Output {
            format: OutputFormat::Json,
            destination: Destination::Stdout,
            queue_capacity: 4096,
            on_full: OnFull::Block,
            max_excerpt_bytes: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Maximum events per rule within `rate_limit_window_secs`; 0 = unlimited.
    pub rate_limit_events: u32,
    pub rate_limit_window_secs: u64,
    /// Suppress identical (rule, line) events within this window; 0 disables.
    pub dedup_window_secs: u64,
    /// Upper bound on remembered (rule, line) pairs for deduplication.
    pub dedup_max_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            rate_limit_events: 0,
            rate_limit_window_secs: 60,
            dedup_window_secs: 0,
            dedup_max_entries: 4096,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    path: PathBuf,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_true")]
    enabled: bool,
    match_type: MatchType,
    pattern: String,
    severity: Severity,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    general: General,
    #[serde(default)]
    output: Output,
    #[serde(default)]
    limits: Limits,
    #[serde(default)]
    files: Vec<RawFile>,
    #[serde(default)]
    rules: Vec<RawRule>,
}

/// A validated, compiled rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub match_type: MatchType,
    pub pattern: String,
    pub severity: Severity,
    pub matcher: Matcher,
}

/// A fully validated configuration. Only enabled files and rules are kept.
#[derive(Debug, Clone)]
pub struct Config {
    pub general: General,
    pub output: Output,
    pub limits: Limits,
    pub files: Vec<PathBuf>,
    pub rules: Vec<Rule>,
    pub disabled_files: usize,
    pub disabled_rules: usize,
}

/// Reads, parses and validates the configuration file at `path`.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text = read_bounded(path)?;
    parse(&text, path)
}

/// Parses and validates configuration text. `origin` is used in messages.
pub fn parse(text: &str, origin: &Path) -> Result<Config, ConfigError> {
    let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError::Parse {
        path: origin.to_path_buf(),
        source: Box::new(e),
    })?;
    validate(raw).map_err(|problems| ConfigError::Invalid {
        path: origin.to_path_buf(),
        problems,
    })
}

fn read_bounded(path: &Path) -> Result<String, ConfigError> {
    let io_err = |source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    };
    let file = File::open(path).map_err(io_err)?;
    // Anyone who can write the configuration controls what is monitored
    // and reported, so a world-writable file is refused outright.
    let mode = file.metadata().map_err(io_err)?.mode();
    if mode & 0o002 != 0 {
        return Err(ConfigError::WorldWritable {
            path: path.to_path_buf(),
            mode: mode & 0o7777,
        });
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_err)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge {
            path: path.to_path_buf(),
            limit: MAX_CONFIG_BYTES,
        });
    }
    String::from_utf8(bytes).map_err(|_| ConfigError::NotUtf8 {
        path: path.to_path_buf(),
    })
}

fn validate(raw: RawConfig) -> Result<Config, Vec<String>> {
    let mut problems = Vec::new();
    let RawConfig {
        general,
        output,
        limits,
        files: raw_files,
        rules: raw_rules,
    } = raw;

    check_range(
        &mut problems,
        "general.max_line_bytes",
        general.max_line_bytes,
        MIN_LINE_BYTES,
        MAX_LINE_BYTES,
    );
    check_range(
        &mut problems,
        "general.reconcile_interval_ms",
        general.reconcile_interval_ms,
        MIN_RECONCILE_MS,
        MAX_RECONCILE_MS,
    );
    check_range(
        &mut problems,
        "general.rotation_drain_ms",
        general.rotation_drain_ms,
        0,
        MAX_RECONCILE_MS,
    );
    check_range(
        &mut problems,
        "general.state_flush_ms",
        general.state_flush_ms,
        MIN_STATE_FLUSH_MS,
        MAX_RECONCILE_MS,
    );
    check_range(
        &mut problems,
        "general.stats_interval_secs",
        general.stats_interval_secs,
        0,
        MAX_WINDOW_SECS,
    );
    check_range(
        &mut problems,
        "output.queue_capacity",
        output.queue_capacity,
        1,
        MAX_QUEUE_CAPACITY,
    );
    if let Some(n) = output.max_excerpt_bytes {
        check_range(
            &mut problems,
            "output.max_excerpt_bytes",
            n,
            MIN_EXCERPT_BYTES,
            MAX_LINE_BYTES,
        );
    }
    check_range(
        &mut problems,
        "limits.rate_limit_window_secs",
        limits.rate_limit_window_secs,
        1,
        MAX_WINDOW_SECS,
    );
    check_range(
        &mut problems,
        "limits.dedup_window_secs",
        limits.dedup_window_secs,
        0,
        MAX_WINDOW_SECS,
    );
    check_range(
        &mut problems,
        "limits.dedup_max_entries",
        limits.dedup_max_entries,
        1,
        MAX_DEDUP_ENTRIES,
    );

    if raw_files.len() > MAX_FILES {
        problems.push(format!(
            "too many [[files]] entries: {} (maximum {MAX_FILES})",
            raw_files.len()
        ));
    }
    let mut seen_paths = HashSet::new();
    let mut files = Vec::new();
    let mut disabled_files = 0;
    for (i, f) in raw_files.into_iter().enumerate() {
        let label = format!("files[{i}] ({})", f.path.display());
        if let Err(msg) = check_path(&f.path) {
            problems.push(format!("{label}: {msg}"));
        }
        if !seen_paths.insert(f.path.clone()) {
            problems.push(format!("{label}: duplicate path"));
        }
        if f.enabled {
            files.push(f.path);
        } else {
            disabled_files += 1;
        }
    }
    if files.is_empty() {
        problems.push("no enabled [[files]] entries".to_string());
    }
    if let Some(state) = &general.state_file {
        let label = format!("general.state_file ({})", state.display());
        if let Err(msg) = check_path(state) {
            problems.push(format!("{label}: {msg}"));
        }
        if seen_paths.contains(state) {
            problems.push(format!("{label}: must not be a monitored file"));
        }
    }

    if raw_rules.len() > MAX_RULES {
        problems.push(format!(
            "too many [[rules]] entries: {} (maximum {MAX_RULES})",
            raw_rules.len()
        ));
    }
    let mut seen_ids = HashSet::new();
    let mut rules = Vec::new();
    let mut disabled_rules = 0;
    for (i, r) in raw_rules.into_iter().enumerate() {
        let label = if r.id.is_empty() {
            format!("rules[{i}]")
        } else {
            format!("rules[{i}] ({})", r.id)
        };
        if let Err(msg) = check_rule_id(&r.id) {
            problems.push(format!("{label}: {msg}"));
        } else if !seen_ids.insert(r.id.clone()) {
            problems.push(format!("{label}: duplicate rule id"));
        }
        // Disabled rules are still compiled so that mistakes surface now,
        // not when someone later flips `enabled = true`.
        match compile(r.match_type, &r.pattern) {
            Ok(matcher) if r.enabled => rules.push(Rule {
                id: r.id,
                description: r.description,
                match_type: r.match_type,
                pattern: r.pattern,
                severity: r.severity,
                matcher,
            }),
            Ok(_) => disabled_rules += 1,
            Err(msg) => problems.push(format!("{label}: {msg}")),
        }
    }
    if rules.is_empty() && problems.is_empty() {
        problems.push("no enabled [[rules]] entries".to_string());
    }

    if problems.is_empty() {
        Ok(Config {
            general,
            output,
            limits,
            files,
            rules,
            disabled_files,
            disabled_rules,
        })
    } else {
        Err(problems)
    }
}

fn check_range<T: PartialOrd + std::fmt::Display>(
    problems: &mut Vec<String>,
    name: &str,
    value: T,
    min: T,
    max: T,
) {
    if value < min || value > max {
        problems.push(format!(
            "{name} = {value} is out of range (allowed {min}..={max})"
        ));
    }
}

/// Paths must be absolute and free of `.`/`..` components so that the path
/// we watch is exactly the path we compare filesystem notifications against.
fn check_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("path must be absolute".to_string());
    }
    let text = path.as_os_str().as_encoded_bytes();
    if text.ends_with(b"/") {
        return Err("path must name a file, not a directory".to_string());
    }
    // `components()` silently drops interior `.`; check the raw text too.
    if text.windows(3).any(|w| w == b"/./") || text.ends_with(b"/.") {
        return Err("path must not contain '.' components".to_string());
    }
    for c in path.components() {
        if matches!(c, Component::ParentDir | Component::CurDir) {
            return Err("path must not contain '.' or '..' components".to_string());
        }
    }
    if text.windows(2).any(|w| w == b"//") {
        return Err("path must not contain empty components ('//')".to_string());
    }
    if path.file_name().is_none() || path.parent().is_none() {
        return Err("path must name a file".to_string());
    }
    Ok(())
}

fn check_rule_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("rule id must not be empty".to_string());
    }
    if id.len() > MAX_RULE_ID_BYTES {
        return Err(format!("rule id is longer than {MAX_RULE_ID_BYTES} bytes"));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
    {
        return Err(
            "rule id may only contain ASCII letters, digits, '_', '-', '.' and ':'".to_string(),
        );
    }
    Ok(())
}

fn compile(match_type: MatchType, pattern: &str) -> Result<Matcher, String> {
    if pattern.is_empty() {
        return Err("pattern must not be empty".to_string());
    }
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(format!("pattern is longer than {MAX_PATTERN_BYTES} bytes"));
    }
    match match_type {
        MatchType::Literal => Ok(Matcher::Literal(Box::new(
            memmem::Finder::new(pattern.as_bytes()).into_owned(),
        ))),
        MatchType::Regex => RegexBuilder::new(pattern)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map(Matcher::Regex)
            .map_err(|e| format!("invalid regex: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [[files]]
        path = "/var/log/syslog"

        [[rules]]
        id = "oom"
        match_type = "literal"
        pattern = "Out of memory"
        severity = "critical"
    "#;

    fn parse_str(text: &str) -> Result<Config, ConfigError> {
        parse(text, Path::new("test.toml"))
    }

    fn problems(text: &str) -> Vec<String> {
        match parse_str(text) {
            Err(ConfigError::Invalid { problems, .. }) => problems,
            other => panic!("expected validation failure, got {other:?}"),
        }
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let cfg = parse_str(MINIMAL).unwrap();
        assert_eq!(cfg.general.startup_mode, StartupMode::Tail);
        assert_eq!(cfg.general.max_line_bytes, 64 * 1024);
        assert_eq!(cfg.general.reconcile_interval_ms, 1000);
        assert_eq!(cfg.general.diagnostics, DiagnosticLevel::Warn);
        assert_eq!(cfg.output.format, OutputFormat::Json);
        assert_eq!(cfg.output.destination, Destination::Stdout);
        assert_eq!(cfg.output.on_full, OnFull::Block);
        assert_eq!(cfg.limits.rate_limit_events, 0);
        assert_eq!(cfg.files, vec![PathBuf::from("/var/log/syslog")]);
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.rules[0].severity, Severity::Critical);
    }

    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../config/logwizz.example.toml");
        let cfg = parse_str(text).unwrap();
        assert!(!cfg.files.is_empty());
        assert!(!cfg.rules.is_empty());
    }

    #[test]
    fn disabled_entries_are_counted_not_kept() {
        let text = format!(
            "{MINIMAL}
            [[files]]
            path = \"/var/log/other\"
            enabled = false

            [[rules]]
            id = \"off\"
            enabled = false
            match_type = \"regex\"
            pattern = \"x+\"
            severity = \"info\"
            "
        );
        let cfg = parse_str(&text).unwrap();
        assert_eq!(cfg.files.len(), 1);
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.disabled_files, 1);
        assert_eq!(cfg.disabled_rules, 1);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let text = format!("{MINIMAL}\n[general]\nstartup = \"tail\"\n");
        assert!(matches!(parse_str(&text), Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn invalid_enum_value_is_rejected() {
        let text = MINIMAL.replace("\"critical\"", "\"catastrophic\"");
        assert!(matches!(parse_str(&text), Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn invalid_regex_is_reported() {
        let text = MINIMAL
            .replace("\"literal\"", "\"regex\"")
            .replace("Out of memory", "(unclosed");
        let p = problems(&text);
        assert_eq!(p.len(), 1);
        assert!(p[0].contains("rules[0] (oom): invalid regex"), "{p:?}");
    }

    #[test]
    fn invalid_regex_in_disabled_rule_is_reported() {
        let text = format!(
            "{MINIMAL}
            [[rules]]
            id = \"broken\"
            enabled = false
            match_type = \"regex\"
            pattern = \"[\"
            severity = \"info\"
            "
        );
        assert!(problems(&text)[0].contains("broken"));
    }

    #[test]
    fn state_file_is_optional_and_validated() {
        let cfg = parse_str(MINIMAL).unwrap();
        assert_eq!(cfg.general.state_file, None);
        assert_eq!(cfg.general.state_flush_ms, 1000);

        let ok = format!(
            "[general]\nstate_file = \"/var/lib/logwizz/offsets.json\"\nstate_flush_ms = 250\n{MINIMAL}"
        );
        let cfg = parse_str(&ok).unwrap();
        assert_eq!(
            cfg.general.state_file.as_deref(),
            Some(Path::new("/var/lib/logwizz/offsets.json"))
        );
        assert_eq!(cfg.general.state_flush_ms, 250);

        let bad =
            format!("[general]\nstate_file = \"/var/log/syslog\"\nstate_flush_ms = 10\n{MINIMAL}");
        let p = problems(&bad);
        assert!(
            p.iter().any(|m| m.contains("must not be a monitored file")),
            "{p:?}"
        );
        assert!(
            p.iter().any(|m| m.contains("general.state_flush_ms")),
            "{p:?}"
        );
        let rel = format!("[general]\nstate_file = \"offsets.json\"\n{MINIMAL}");
        assert!(problems(&rel)[0].contains("must be absolute"));
    }

    #[test]
    fn oversized_regex_is_rejected() {
        let text = MINIMAL
            .replace("\"literal\"", "\"regex\"")
            .replace("Out of memory", r"\\w{1000}\\w{1000}");
        assert!(problems(&text)[0].contains("invalid regex"));
    }

    #[test]
    fn empty_pattern_and_bad_id_are_reported_together() {
        let text = MINIMAL
            .replace("Out of memory", "")
            .replace("\"oom\"", "\"has space\"");
        let p = problems(&text);
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p.iter().any(|m| m.contains("rule id may only contain")));
        assert!(p.iter().any(|m| m.contains("pattern must not be empty")));
    }

    #[test]
    fn duplicate_rule_ids_and_paths_are_rejected() {
        let text = format!("{MINIMAL}{MINIMAL}");
        let p = problems(&text);
        assert!(p.iter().any(|m| m.contains("duplicate path")), "{p:?}");
        assert!(p.iter().any(|m| m.contains("duplicate rule id")), "{p:?}");
    }

    #[test]
    fn relative_and_unnormalized_paths_are_rejected() {
        for bad in [
            "var/log/x",
            "/var/log/../x",
            "/var/./log/x",
            "/var/log/",
            "/var//log/x",
            "/",
        ] {
            let text = MINIMAL.replace("/var/log/syslog", bad);
            let p = problems(&text);
            assert!(p[0].starts_with("files[0]"), "{bad}: {p:?}");
        }
    }

    #[test]
    fn out_of_range_values_are_rejected() {
        let text = format!(
            "{MINIMAL}
            [general]
            max_line_bytes = 10
            reconcile_interval_ms = 0

            [output]
            queue_capacity = 0
            "
        );
        let p = problems(&text);
        assert_eq!(p.len(), 3, "{p:?}");
    }

    #[test]
    fn no_files_or_rules_is_rejected() {
        let p = problems("");
        assert!(p.iter().any(|m| m.contains("no enabled [[files]]")));
    }

    #[test]
    fn literal_and_regex_matchers_work() {
        let text = format!(
            "{MINIMAL}
            [[rules]]
            id = \"re\"
            match_type = \"regex\"
            pattern = \"(?i)kernel panic\"
            severity = \"error\"
            "
        );
        let cfg = parse_str(&text).unwrap();
        assert!(cfg.rules[0].matcher.is_match(b"xx Out of memory: Kill"));
        assert!(!cfg.rules[0].matcher.is_match(b"out of memory"));
        assert!(cfg.rules[1].matcher.is_match(b"KERNEL PANIC - not syncing"));
        assert!(cfg.rules[1].matcher.is_match(b"\xff\xfe Kernel Panic"));
    }
}

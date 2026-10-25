//! Configuration loading, validation and rule compilation.
//!
//! Loading is all-or-nothing: [`load`] either returns a fully validated
//! [`Config`] with every rule compiled, or an error that lists every problem
//! found. Nothing is activated from a partially valid file.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use memchr::memmem;
use regex::bytes::RegexBuilder;
use serde::Deserialize;

use crate::engine::{MAX_FIELDS, MatchType, Matcher};
use crate::error::ConfigError;
use crate::event::Severity;
use crate::glob::Pattern;

/// Configuration files larger than this are rejected before parsing.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

pub const MIN_LINE_BYTES: usize = 256;
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
pub const MIN_RECONCILE_MS: u64 = 50;
pub const MAX_RECONCILE_MS: u64 = 600_000;
pub const MIN_STATE_FLUSH_MS: u64 = 100;
pub const MAX_QUEUE_CAPACITY: usize = 1 << 20;
pub const MIN_QUEUE_BYTES: usize = 64 * 1024;
pub const MAX_QUEUE_BYTES: usize = 1 << 30;
pub const MAX_FILES: usize = 1024;
pub const MAX_GLOB_FILES: usize = 4096;
pub const MAX_RULES: usize = 1024;
pub const MAX_PATTERN_BYTES: usize = 4096;
pub const MAX_RULE_ID_BYTES: usize = 64;
pub const MIN_EXCERPT_BYTES: usize = 16;
pub const MAX_WINDOW_SECS: u64 = 86_400;
pub const MAX_DEDUP_ENTRIES: usize = 1 << 20;
pub const MAX_THRESHOLD_GROUPS: usize = 1 << 20;
pub const MAX_THRESHOLD_COUNT: u32 = 10_000;
/// Cap on the `exclude` values of one rule.
pub const MAX_EXCLUDE_VALUES: usize = 1024;
/// Cap on the distinct-value state one threshold rule may hold.
pub const MAX_DISTINCT_BYTES: u64 = 64 << 20;
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
    /// Maximum number of files followed for one `[[files]] glob`.
    pub max_glob_files: usize,
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
            max_glob_files: 256,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Output {
    pub format: OutputFormat,
    pub destination: Destination,
    pub queue_capacity: usize,
    /// Upper bound on the memory held by queued events. The queue counts as
    /// full when either limit is reached.
    pub max_queue_bytes: usize,
    pub on_full: OnFull,
    /// Maximum number of bytes of the matching line included in an event.
    /// Unset means the whole (already length-limited) line.
    pub max_excerpt_bytes: Option<usize>,
    /// Start each event line with the sd-daemon `<N>` prefix for its
    /// severity, so that journald records it as the entry's priority.
    pub syslog_prefix: bool,
}

impl Default for Output {
    fn default() -> Self {
        Output {
            format: OutputFormat::Json,
            destination: Destination::Stdout,
            queue_capacity: 4096,
            max_queue_bytes: 8 * 1024 * 1024,
            on_full: OnFull::Block,
            max_excerpt_bytes: None,
            syslog_prefix: false,
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
    /// Upper bound on the groups each threshold rule tracks.
    pub threshold_max_groups: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            rate_limit_events: 0,
            rate_limit_window_secs: 60,
            dedup_window_secs: 0,
            dedup_max_entries: 4096,
            threshold_max_groups: 4096,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    path: Option<PathBuf>,
    glob: Option<String>,
    exclude: Option<String>,
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
    severity: Option<Severity>,
    #[serde(default)]
    action: Action,
    threshold: Option<RawThreshold>,
    /// Capture group name -> values whose matches are discarded.
    #[serde(default)]
    exclude: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawThreshold {
    group_by: Option<String>,
    distinct: Option<String>,
    count: u32,
    window_secs: u64,
    #[serde(default)]
    cooldown_secs: u64,
}

/// What a threshold rule groups its matches by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    /// One group for all matches.
    All,
    /// One group per monitored file.
    File,
    /// One group per value of this capture group (index).
    Capture(usize),
}

/// A validated `[rules.threshold]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Threshold {
    pub group_by: GroupBy,
    /// Count distinct values of this capture group instead of matches.
    pub distinct: Option<usize>,
    pub count: u32,
    pub window: Duration,
    pub cooldown: Duration,
}

/// Matches whose capture group `group` has one of `values` are discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exclusion {
    pub group: usize,
    pub values: Vec<ExcludeValue>,
}

/// One `exclude` value: an IP address or network, or any other exact text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExcludeValue {
    Net(IpNet),
    Text(String),
}

/// An IP network. A single address is a network with the full prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Parses `192.0.2.0/24`, `2001:db8::/32` or a single address. Host bits
    /// below the prefix are cleared.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (addr, prefix) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("`{text}` is not an IP address or network"))?;
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => match p.parse::<u8>() {
                Ok(p) if p <= max => p,
                _ => return Err(format!("`{text}`: prefix length must be 0..={max}")),
            },
        };
        Ok(IpNet {
            addr: mask(addr, prefix),
            prefix,
        })
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        let addr = addr.to_canonical();
        addr.is_ipv4() == self.addr.is_ipv4() && mask(addr, self.prefix) == self.addr
    }
}

fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let m = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4((u32::from(a) & m).into())
        }
        IpAddr::V6(a) => {
            let m = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6((u128::from(a) & m).into())
        }
    }
}

/// What a matching rule does with the line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Emit an event.
    #[default]
    Emit,
    /// Emit nothing and skip all later rules for this line.
    Ignore,
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
    journal: Option<RawJournal>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawJournal {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    matches: Vec<String>,
}

/// A validated `[journal]` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Journal {
    /// journalctl match arguments: `FIELD=value`, or `+` between groups.
    pub matches: Vec<String>,
}

/// A validated, compiled rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub match_type: MatchType,
    pub pattern: String,
    /// Unused for `Action::Ignore` rules, which emit nothing.
    pub severity: Severity,
    pub action: Action,
    /// Set: the rule emits one event per reached threshold, not per match.
    pub threshold: Option<Threshold>,
    /// Matches with these capture values are discarded before thresholds.
    pub exclude: Vec<Exclusion>,
    pub matcher: Matcher,
}

impl Rule {
    /// Same id and definition; the compiled matcher follows from these.
    pub fn same_definition(&self, other: &Rule) -> bool {
        self.id == other.id
            && self.description == other.description
            && self.match_type == other.match_type
            && self.pattern == other.pattern
            && self.severity == other.severity
            && self.action == other.action
            && self.threshold == other.threshold
            && self.exclude == other.exclude
    }

    /// Whether a match with these capture values (from
    /// [`Matcher::fields`]) is discarded by `exclude`.
    pub fn excludes(&self, fields: &[(usize, Box<[u8]>)]) -> bool {
        self.exclude.iter().any(|ex| {
            let Some((_, value)) = fields.iter().find(|(g, _)| *g == ex.group) else {
                return false;
            };
            let Ok(text) = std::str::from_utf8(value) else {
                return false;
            };
            let ip = text.parse::<IpAddr>().ok();
            ex.values.iter().any(|v| match v {
                ExcludeValue::Net(net) => ip.is_some_and(|ip| net.contains(ip)),
                ExcludeValue::Text(t) => t == text,
            })
        })
    }
}

/// A validated `[[files]] glob` entry.
#[derive(Debug, Clone)]
pub struct Glob {
    /// The glob as configured, for messages.
    pub text: String,
    /// The directory searched for matches.
    pub dir: PathBuf,
    /// Pattern for the names of files in `dir`.
    pub pattern: Pattern,
    pub exclude: Option<Pattern>,
}

impl Glob {
    /// Whether a file named `name` in `dir` is followed.
    pub fn matches(&self, name: &[u8]) -> bool {
        self.pattern.matches(name) && !self.exclude.as_ref().is_some_and(|e| e.matches(name))
    }

    /// Whether `path` is (or would be) followed for this glob.
    pub fn matches_path(&self, path: &Path) -> bool {
        path.parent() == Some(self.dir.as_path())
            && path
                .file_name()
                .is_some_and(|name| self.matches(name.as_bytes()))
    }
}

/// A fully validated configuration. Only enabled files and rules are kept.
#[derive(Debug, Clone)]
pub struct Config {
    pub general: General,
    pub output: Output,
    pub limits: Limits,
    /// Files configured with `path`.
    pub files: Vec<PathBuf>,
    /// Entries configured with `glob`.
    pub globs: Vec<Glob>,
    pub rules: Vec<Rule>,
    /// Set: also read the systemd journal. Its events name the file
    /// [`JOURNAL_SOURCE`].
    pub journal: Option<Journal>,
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
        journal: raw_journal,
    } = raw;
    let journal = match raw_journal {
        Some(j) if j.enabled => match check_journal_matches(&j.matches) {
            Ok(()) => Some(Journal { matches: j.matches }),
            Err(msg) => {
                problems.push(format!("journal.matches: {msg}"));
                None
            }
        },
        _ => None,
    };

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
        "general.max_glob_files",
        general.max_glob_files,
        1,
        MAX_GLOB_FILES,
    );
    check_range(
        &mut problems,
        "output.queue_capacity",
        output.queue_capacity,
        1,
        MAX_QUEUE_CAPACITY,
    );
    check_range(
        &mut problems,
        "output.max_queue_bytes",
        output.max_queue_bytes,
        MIN_QUEUE_BYTES,
        MAX_QUEUE_BYTES,
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
    check_range(
        &mut problems,
        "limits.threshold_max_groups",
        limits.threshold_max_groups,
        1,
        MAX_THRESHOLD_GROUPS,
    );

    if raw_files.len() > MAX_FILES {
        problems.push(format!(
            "too many [[files]] entries: {} (maximum {MAX_FILES})",
            raw_files.len()
        ));
    }
    let mut seen_paths = HashSet::new();
    let mut seen_globs = HashSet::new();
    let mut files = Vec::new();
    let mut globs = Vec::new();
    let mut disabled_files = 0;
    for (i, f) in raw_files.into_iter().enumerate() {
        match (f.path, f.glob) {
            (Some(path), None) => {
                let label = format!("files[{i}] ({})", path.display());
                if let Err(msg) = check_path(&path) {
                    problems.push(format!("{label}: {msg}"));
                }
                if f.exclude.is_some() {
                    problems.push(format!("{label}: 'exclude' requires 'glob'"));
                }
                if !seen_paths.insert(path.clone()) {
                    problems.push(format!("{label}: duplicate path"));
                }
                if f.enabled {
                    files.push(path);
                } else {
                    disabled_files += 1;
                }
            }
            (None, Some(text)) => {
                let label = format!("files[{i}] ({text})");
                if !seen_globs.insert(text.clone()) {
                    problems.push(format!("{label}: duplicate glob"));
                }
                match check_glob(&text, f.exclude.as_deref()) {
                    Ok(glob) if f.enabled => globs.push(glob),
                    Ok(_) => disabled_files += 1,
                    Err(msg) => problems.push(format!("{label}: {msg}")),
                }
            }
            (Some(path), Some(_)) => problems.push(format!(
                "files[{i}] ({}): set either 'path' or 'glob', not both",
                path.display()
            )),
            (None, None) => problems.push(format!("files[{i}]: 'path' or 'glob' is required")),
        }
    }
    if files.is_empty() && globs.is_empty() && journal.is_none() {
        problems.push("no enabled [[files]] entries and no [journal]".to_string());
    }
    if let Some(state) = &general.state_file {
        let label = format!("general.state_file ({})", state.display());
        if let Err(msg) = check_path(state) {
            problems.push(format!("{label}: {msg}"));
        }
        let mut tmp = state.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        if seen_paths.contains(state)
            || globs
                .iter()
                .any(|g| g.matches_path(state) || g.matches_path(&tmp))
        {
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
        let severity = match (r.action, r.severity) {
            (Action::Emit, Some(s)) => s,
            (Action::Emit, None) => {
                problems.push(format!("{label}: missing field `severity`"));
                Severity::Debug
            }
            (Action::Ignore, Some(_)) => {
                problems.push(format!(
                    "{label}: an ignore rule emits nothing, so it takes no severity"
                ));
                Severity::Debug
            }
            (Action::Ignore, None) => Severity::Debug,
        };
        // Disabled rules are still compiled so that mistakes surface now,
        // not when someone later flips `enabled = true`.
        let compiled = compile(r.match_type, &r.pattern).and_then(|matcher| {
            let threshold = match &r.threshold {
                Some(t) => Some(check_threshold(t, r.action, &matcher, &limits)?),
                None => None,
            };
            let exclude = check_exclude(&r.exclude, r.action, &matcher)?;
            Ok((matcher, threshold, exclude))
        });
        match compiled {
            Ok((matcher, threshold, exclude)) if r.enabled => rules.push(Rule {
                id: r.id,
                description: r.description,
                match_type: r.match_type,
                pattern: r.pattern,
                severity,
                action: r.action,
                threshold,
                exclude,
                matcher,
            }),
            Ok(_) => disabled_rules += 1,
            Err(msg) => problems.push(format!("{label}: {msg}")),
        }
    }
    if problems.is_empty() && !rules.iter().any(|r| r.action == Action::Emit) {
        problems.push("no enabled [[rules]] entries that emit events".to_string());
    }

    if problems.is_empty() {
        Ok(Config {
            general,
            output,
            limits,
            files,
            globs,
            rules,
            journal,
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

/// A glob must be a valid path whose wildcards are all in the final
/// component, so that one non-recursive directory listing finds every match.
fn check_glob(text: &str, exclude: Option<&str>) -> Result<Glob, String> {
    let path = Path::new(text);
    check_path(path)?;
    // check_path guarantees both parts exist.
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err("glob must name files".to_string());
    };
    if dir
        .as_os_str()
        .as_bytes()
        .iter()
        .any(|&b| b == b'*' || b == b'?')
    {
        return Err("wildcards are allowed in the final path component only".to_string());
    }
    // `name` came from a `&str`, so it is valid UTF-8.
    let pattern = Pattern::new(&name.to_string_lossy())?;
    if !pattern.has_wildcard() {
        return Err("glob has no '*' or '?'; use 'path' for a single file".to_string());
    }
    let exclude = exclude
        .map(|e| Pattern::new(e).map_err(|msg| format!("exclude: {msg}")))
        .transpose()?;
    Ok(Glob {
        text: text.to_string(),
        dir: dir.to_path_buf(),
        pattern,
        exclude,
    })
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

fn check_threshold(
    t: &RawThreshold,
    action: Action,
    matcher: &Matcher,
    limits: &Limits,
) -> Result<Threshold, String> {
    if action == Action::Ignore {
        return Err("an ignore rule emits nothing, so it takes no threshold".to_string());
    }
    let capture = |key: &str, name: &str| {
        matcher.group_index(name).ok_or_else(|| {
            format!("threshold.{key}: the pattern has no capture group named `{name}`")
        })
    };
    let group_by = match t.group_by.as_deref() {
        None => GroupBy::All,
        Some("file") => GroupBy::File,
        Some(name) => GroupBy::Capture(capture("group_by", name)?),
    };
    let distinct = t
        .distinct
        .as_deref()
        .map(|n| capture("distinct", n))
        .transpose()?;
    if !(1..=MAX_THRESHOLD_COUNT).contains(&t.count) {
        return Err(format!(
            "threshold.count must be between 1 and {MAX_THRESHOLD_COUNT}, got {}",
            t.count
        ));
    }
    if !(1..=MAX_WINDOW_SECS).contains(&t.window_secs) {
        return Err(format!(
            "threshold.window_secs must be between 1 and {MAX_WINDOW_SECS}, got {}",
            t.window_secs
        ));
    }
    if t.cooldown_secs > MAX_WINDOW_SECS {
        return Err(format!(
            "threshold.cooldown_secs must be at most {MAX_WINDOW_SECS}, got {}",
            t.cooldown_secs
        ));
    }
    // Distinct values are kept as 8-byte hashes in hash sets: about 16 bytes
    // each, for up to `count` values per group.
    let distinct_bytes = limits.threshold_max_groups as u64 * u64::from(t.count) * 16;
    if distinct.is_some() && distinct_bytes > MAX_DISTINCT_BYTES {
        return Err(format!(
            "threshold.count × limits.threshold_max_groups is too large for `distinct` \
             (about {} MiB of state; maximum {} MiB)",
            distinct_bytes >> 20,
            MAX_DISTINCT_BYTES >> 20
        ));
    }
    Ok(Threshold {
        group_by,
        distinct,
        count: t.count,
        window: Duration::from_secs(t.window_secs),
        cooldown: Duration::from_secs(t.cooldown_secs),
    })
}

fn check_exclude(
    raw: &BTreeMap<String, Vec<String>>,
    action: Action,
    matcher: &Matcher,
) -> Result<Vec<Exclusion>, String> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    if action == Action::Ignore {
        return Err("an ignore rule emits nothing, so it takes no exclude".to_string());
    }
    let total: usize = raw.values().map(Vec::len).sum();
    if total > MAX_EXCLUDE_VALUES {
        return Err(format!(
            "exclude: too many values: {total} (maximum {MAX_EXCLUDE_VALUES})"
        ));
    }
    raw.iter()
        .map(|(name, values)| {
            let group = matcher.group_index(name).ok_or_else(|| {
                format!("exclude.{name}: the pattern has no capture group named `{name}`")
            })?;
            let values = values
                .iter()
                .map(|v| {
                    if v.is_empty() {
                        Err(format!("exclude.{name}: values must not be empty"))
                    } else if v.contains('/') || v.parse::<IpAddr>().is_ok() {
                        IpNet::parse(v)
                            .map(ExcludeValue::Net)
                            .map_err(|msg| format!("exclude.{name}: {msg}"))
                    } else {
                        Ok(ExcludeValue::Text(v.clone()))
                    }
                })
                .collect::<Result<_, _>>()?;
            Ok(Exclusion { group, values })
        })
        .collect()
}

/// Name used as the event `file` of journal entries.
pub const JOURNAL_SOURCE: &str = "journal";
pub const MAX_JOURNAL_MATCHES: usize = 64;

/// `FIELD=value` with a journal field name (upper-case letters, digits,
/// `_`; not starting with a digit), or `+`. logwizz's own namespace is
/// never read: its events are not in the system journal.
fn check_journal_matches(matches: &[String]) -> Result<(), String> {
    if matches.len() > MAX_JOURNAL_MATCHES {
        return Err(format!("at most {MAX_JOURNAL_MATCHES} entries"));
    }
    for m in matches {
        if m == "+" {
            continue;
        }
        let Some((field, value)) = m.split_once('=') else {
            return Err(format!("`{m}` is not FIELD=value or +"));
        };
        let valid_field = !field.is_empty()
            && field.len() <= 64
            && !field.starts_with(|c: char| c.is_ascii_digit())
            && field
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        if !valid_field {
            return Err(format!("`{field}` is not a journal field name"));
        }
        if value.len() > 1024 || value.contains(['\n', '\0']) {
            return Err(format!(
                "the value of `{field}` is too long or has a newline"
            ));
        }
        if field == "_NAMESPACE" {
            return Err(
                "logwizz never reads journal namespaces (its own events are in one)".into(),
            );
        }
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
        MatchType::Regex => {
            let re = RegexBuilder::new(pattern)
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(|e| format!("invalid regex: {e}"))?;
            let named = re.capture_names().flatten().count();
            if named > MAX_FIELDS {
                return Err(format!(
                    "regex has {named} named capture groups (maximum {MAX_FIELDS})"
                ));
            }
            Ok(Matcher::Regex(re))
        }
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
        assert_eq!(cfg.output.max_queue_bytes, 8 * 1024 * 1024);
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
    fn ignore_rules_take_no_severity_and_cannot_stand_alone() {
        let ignore = MINIMAL.replace("severity = \"critical\"", "action = \"ignore\"");
        let p = problems(&ignore);
        assert_eq!(p, ["no enabled [[rules]] entries that emit events"]);
        let both = MINIMAL.replace("severity", "action = \"ignore\"\nseverity");
        assert!(problems(&both)[0].contains("takes no severity"));
        let none = MINIMAL.replace("severity = \"critical\"", "");
        assert!(problems(&none)[0].contains("missing field `severity`"));
        let ok = format!(
            "{ignore}\n[[rules]]\nid = \"all\"\nmatch_type = \"regex\"\npattern = \"^\"\nseverity = \"notice\"\n"
        );
        let cfg = parse_str(&ok).unwrap();
        assert_eq!(cfg.rules[0].action, Action::Ignore);
        assert_eq!(cfg.rules[1].action, Action::Emit);
    }

    #[test]
    fn threshold_validation() {
        let rule = |pattern: &str, extra: &str, threshold: &str| {
            format!(
                "[[files]]\npath = \"/var/log/kern.log\"\n[[rules]]\nid = \"scan\"\n\
                 match_type = \"regex\"\npattern = '{pattern}'\n{extra}\n[rules.threshold]\n{threshold}\n\
                 [[rules]]\nid = \"other\"\nmatch_type = \"literal\"\npattern = \"x\"\nseverity = \"info\"\n"
            )
        };
        let fw = r"SRC=(?P<src>\S+) DPT=(?P<dpt>\d+)";
        let sev = "severity = \"critical\"";
        let cfg = parse_str(&rule(
            fw,
            sev,
            "group_by = \"src\"\ndistinct = \"dpt\"\ncount = 20\nwindow_secs = 10\ncooldown_secs = 300",
        ))
        .unwrap();
        let t = cfg.rules[0].threshold.as_ref().unwrap();
        assert_eq!(
            (t.group_by, t.distinct, t.count),
            (GroupBy::Capture(1), Some(2), 20)
        );
        assert_eq!(
            (t.window, t.cooldown),
            (Duration::from_secs(10), Duration::from_secs(300))
        );
        let file = parse_str(&rule(
            "^",
            sev,
            "group_by = \"file\"\ncount = 1\nwindow_secs = 1",
        ))
        .unwrap();
        assert_eq!(
            file.rules[0].threshold.as_ref().unwrap().group_by,
            GroupBy::File
        );

        let p = |pattern: &str, extra: &str, t: &str| problems(&rule(pattern, extra, t)).join("; ");
        let base = "count = 5\nwindow_secs = 10";
        assert!(
            p(fw, sev, &format!("group_by = \"nope\"\n{base}"))
                .contains("no capture group named `nope`")
        );
        assert!(p(fw, sev, &format!("distinct = \"x\"\n{base}")).contains("threshold.distinct"));
        assert!(p(fw, sev, "count = 0\nwindow_secs = 10").contains("threshold.count"));
        assert!(p(fw, sev, "count = 10001\nwindow_secs = 10").contains("threshold.count"));
        assert!(p(fw, sev, "count = 5\nwindow_secs = 0").contains("threshold.window_secs"));
        assert!(p(fw, sev, &format!("{base}\ncooldown_secs = 86401")).contains("cooldown_secs"));
        assert!(p(fw, "action = \"ignore\"", base).contains("takes no threshold"));
        assert!(parse_str(&rule(fw, sev, &format!("{base}\nbogus = 1"))).is_err());
        // distinct state is bounded: 4096 groups × 10000 values is too much.
        assert!(
            p(
                fw,
                sev,
                "group_by = \"src\"\ndistinct = \"dpt\"\ncount = 10000\nwindow_secs = 10"
            )
            .contains("too large for `distinct`")
        );
    }

    #[test]
    fn exclude_values() {
        let rule = |extra: &str| {
            format!(
                "[[files]]\npath = \"/var/log/auth.log\"\n[[rules]]\nid = \"ssh\"\n\
                 match_type = \"regex\"\npattern = 'from (?P<src>\\S+) user (?P<user>\\S+)'\n\
                 severity = \"warning\"\n{extra}\n"
            )
        };
        let cfg = parse_str(&rule(
            "[rules.exclude]\nsrc = [\"192.0.2.10\", \"10.0.0.0/8\", \"2001:db8::/32\"]\n\
             user = [\"backup\"]",
        ))
        .unwrap();
        let r = &cfg.rules[0];
        let excluded = |line: &str| r.excludes(&r.matcher.fields(line.as_bytes()));
        assert!(excluded("from 192.0.2.10 user root"));
        assert!(excluded("from 10.200.3.4 user root"));
        assert!(excluded("from ::ffff:10.1.1.1 user root"), "IPv4-mapped");
        assert!(excluded("from 2001:db8:1::5 user root"));
        assert!(excluded("from 198.51.100.1 user backup"), "text value");
        assert!(!excluded("from 192.0.2.11 user root"));
        assert!(!excluded("from 11.0.0.1 user root"));
        assert!(!excluded("from 2001:db9::1 user root"));
        assert!(!excluded("from 10.0.0.1x user root"), "not an address");
        assert!(!excluded("from 192.0.2.11 user backups"));

        // Host bits are cleared; /0 matches every address of its family.
        let net = IpNet::parse("192.0.2.77/24").unwrap();
        assert!(net.contains("192.0.2.1".parse().unwrap()));
        assert!(
            IpNet::parse("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
        assert!(
            !IpNet::parse("0.0.0.0/0")
                .unwrap()
                .contains("::1".parse().unwrap())
        );

        let p = |extra: &str| problems(&rule(extra)).join("; ");
        assert!(p("[rules.exclude]\nnope = [\"x\"]").contains("no capture group named `nope`"));
        assert!(p("[rules.exclude]\nsrc = [\"10.0.0.0/33\"]").contains("prefix length"));
        assert!(p("[rules.exclude]\nsrc = [\"10.0.0/8\"]").contains("not an IP address"));
        assert!(p("[rules.exclude]\nsrc = [\"\"]").contains("must not be empty"));
        let many = vec!["\"x\""; MAX_EXCLUDE_VALUES + 1].join(",");
        assert!(p(&format!("[rules.exclude]\nsrc = [{many}]")).contains("too many values"));
        let ignore = "[[files]]\npath = \"/x\"\n[[rules]]\nid = \"i\"\nmatch_type = \"regex\"\n\
                      pattern = '(?P<src>x)'\naction = \"ignore\"\n[rules.exclude]\nsrc = [\"x\"]\n\
                      [[rules]]\nid = \"e\"\nmatch_type = \"literal\"\npattern = \"y\"\nseverity = \"info\"\n";
        assert!(problems(ignore).join("; ").contains("takes no exclude"));
    }

    #[test]
    fn journal_section() {
        let rules = "[[rules]]\nid = \"r\"\nmatch_type = \"literal\"\npattern = \"x\"\nseverity = \"info\"\n";
        // The journal alone is a valid source.
        let cfg = parse_str(&format!(
            "[journal]\nmatches = [\"_TRANSPORT=kernel\", \"+\", \"SYSLOG_IDENTIFIER=sshd\"]\n{rules}"
        ))
        .unwrap();
        assert!(cfg.files.is_empty());
        assert_eq!(cfg.journal.unwrap().matches.len(), 3);
        assert!(
            parse_str(&format!("[journal]\n{rules}"))
                .unwrap()
                .journal
                .is_some()
        );
        assert!(
            parse_str(&format!("{MINIMAL}\n[journal]\nenabled = false\n"))
                .unwrap()
                .journal
                .is_none()
        );
        let p = |m: &str| problems(&format!("{MINIMAL}\n[journal]\nmatches = [{m}]\n")).join("; ");
        assert!(p("\"sshd\"").contains("not FIELD=value"));
        assert!(p("\"syslog_identifier=sshd\"").contains("not a journal field name"));
        assert!(p("\"1X=a\"").contains("not a journal field name"));
        assert!(p("\"MESSAGE=a\\nb\"").contains("newline"));
        assert!(p("\"_NAMESPACE=logwizz\"").contains("never reads journal namespaces"));
        let many = vec!["\"+\""; MAX_JOURNAL_MATCHES + 1].join(", ");
        assert!(p(&many).contains("at most"));
        assert!(
            problems(&format!("[journal]\nenabled = false\n{rules}"))[0].contains("no [journal]")
        );
    }

    #[test]
    fn named_group_limit() {
        let groups = |n: usize| -> String {
            let pattern: String = (0..n).map(|i| format!("(?P<g{i}>x)?")).collect();
            MINIMAL
                .replace("\"literal\"", "\"regex\"")
                .replace("Out of memory", &pattern)
        };
        assert!(parse_str(&groups(MAX_FIELDS)).is_ok());
        let p = problems(&groups(MAX_FIELDS + 1));
        assert!(
            p[0].contains("17 named capture groups (maximum 16)"),
            "{p:?}"
        );
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
            max_queue_bytes = 1024
            "
        );
        let p = problems(&text);
        assert_eq!(p.len(), 4, "{p:?}");
        assert!(p.iter().any(|m| m.starts_with("output.max_queue_bytes")));
    }

    #[test]
    fn no_files_or_rules_is_rejected() {
        let p = problems("");
        assert!(p.iter().any(|m| m.contains("no enabled [[files]]")));
    }

    #[test]
    fn glob_entries_are_parsed() {
        let text = MINIMAL.replace(
            "path = \"/var/log/syslog\"",
            "glob = \"/var/log/app/*.log*\"\nexclude = \"*.log.*\"",
        );
        let cfg = parse_str(&format!("[general]\nmax_glob_files = 8\n{text}")).unwrap();
        assert!(cfg.files.is_empty());
        assert_eq!(cfg.general.max_glob_files, 8);
        let g = &cfg.globs[0];
        assert_eq!(g.dir, Path::new("/var/log/app"));
        assert!(g.matches(b"api.log"));
        assert!(!g.matches(b"api.log.1"), "excluded");
        assert!(g.matches_path(Path::new("/var/log/app/x.log")));
        assert!(!g.matches_path(Path::new("/var/log/x.log")));
        assert_eq!(parse_str(MINIMAL).unwrap().general.max_glob_files, 256);
    }

    #[test]
    fn invalid_globs_are_rejected() {
        for (glob, why) in [
            ("/var/log/**", "'**'"),
            ("/var/*/app.log", "final path component only"),
            ("/var/log/app.log", "no '*' or '?'"),
            ("/var/log/[ab].log", "only the '*' and '?'"),
            ("var/log/*.log", "must be absolute"),
            ("/var/log/../*.log", "'..'"),
        ] {
            let text = MINIMAL.replace("path = \"/var/log/syslog\"", &format!("glob = {glob:?}"));
            let p = problems(&text);
            assert!(p[0].contains(why), "{glob}: {p:?}");
        }
        let both = MINIMAL.replace(
            "path = \"/var/log/syslog\"",
            "path = \"/x\"\nglob = \"/var/*.log\"",
        );
        assert!(problems(&both)[0].contains("not both"));
        let neither = MINIMAL.replace("path = \"/var/log/syslog\"", "enabled = true");
        assert!(problems(&neither)[0].contains("'path' or 'glob' is required"));
        let stray = MINIMAL.replace(
            "path = \"/var/log/syslog\"",
            "path = \"/x\"\nexclude = \"*.1\"",
        );
        assert!(problems(&stray)[0].contains("'exclude' requires 'glob'"));
        let bad_exclude = MINIMAL.replace(
            "path = \"/var/log/syslog\"",
            "glob = \"/var/*.log\"\nexclude = \"a/b\"",
        );
        assert!(problems(&bad_exclude)[0].contains("exclude: pattern must not contain '/'"));
        let dup = format!("{MINIMAL}[[files]]\nglob = \"/a/*\"\n[[files]]\nglob = \"/a/*\"\n");
        assert!(problems(&dup).iter().any(|m| m.contains("duplicate glob")));
        let limit = format!("[general]\nmax_glob_files = 0\n{MINIMAL}");
        assert!(problems(&limit)[0].starts_with("general.max_glob_files"));
    }

    #[test]
    fn state_file_must_not_match_a_glob() {
        let text = MINIMAL.replace(
            "path = \"/var/log/syslog\"",
            "glob = \"/var/lib/logwizz/*\"",
        );
        let text = format!("[general]\nstate_file = \"/var/lib/logwizz/offsets.json\"\n{text}");
        assert!(problems(&text)[0].contains("must not be a monitored file"));
        // Its temporary file must not match either.
        let tmp = text.replace("/var/lib/logwizz/*\"", "/var/lib/logwizz/*.tmp\"");
        assert!(problems(&tmp)[0].contains("must not be a monitored file"));
        let ok = text.replace("/var/lib/logwizz/*\"", "/var/lib/logwizz/*.log\"");
        assert!(parse_str(&ok).is_ok());
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

//! Runs the `logwizz` binary with `--check-config` against valid and invalid
//! configuration files.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const VALID: &str = r#"
[[files]]
path = "/var/log/syslog"

[[rules]]
id = "oom"
match_type = "literal"
pattern = "Out of memory"
severity = "critical"
"#;

fn check(config: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_logwizz"))
        .arg("--check-config")
        .arg("--config")
        .arg(config)
        .output()
        .expect("failed to run logwizz")
}

fn check_text(text: &str) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("logwizz.toml");
    fs::write(&path, text).unwrap();
    check(&path)
}

#[test]
fn valid_config_exits_zero() {
    let out = check_text(VALID);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("configuration OK: 1 file(s)"), "{stdout}");
}

#[test]
fn example_config_passes() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/logwizz.example.toml");
    let out = check(&path);
    assert!(out.status.success(), "{out:?}");
}

#[test]
fn invalid_regex_exits_nonzero_with_diagnostic() {
    let text = VALID
        .replace("\"literal\"", "\"regex\"")
        .replace("Out of memory", "(oops");
    let out = check_text(&text);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("rules[0] (oom): invalid regex"), "{stderr}");
}

#[test]
fn syntax_error_exits_nonzero_with_location() {
    let out = check_text("[general\n");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot parse configuration file"),
        "{stderr}"
    );
    assert!(stderr.contains("line 1"), "{stderr}");
}

#[test]
fn missing_file_exits_nonzero() {
    let out = check(Path::new("/nonexistent/logwizz.toml"));
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot read configuration file"),
        "{stderr}"
    );
}

#[test]
fn oversized_file_is_rejected() {
    let mut text = String::from(VALID);
    text.push('#');
    text.push_str(&"x".repeat(1024 * 1024));
    let out = check_text(&text);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("exceeds the maximum size"));
}

#[test]
fn version_and_help_work() {
    let bin = env!("CARGO_BIN_EXE_logwizz");
    let out = Command::new(bin).arg("--version").output().unwrap();
    assert!(out.status.success());
    // build.rs sets LOGWIZZ_VERSION: the stamped Cargo.toml version in a release build, else from git describe.
    let expected = format!("logwizz {}\n", env!("LOGWIZZ_VERSION"));
    assert_eq!(String::from_utf8_lossy(&out.stdout), expected);
    if option_env!("LOGWIZZ_RELEASE") == Some("1") {
        assert_eq!(env!("LOGWIZZ_VERSION"), env!("CARGO_PKG_VERSION"));
    }

    let out = Command::new(bin).arg("--help").output().unwrap();
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("--config") && help.contains("--check-config"));
}

#[test]
fn world_writable_config_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("logwizz.toml");
    fs::write(&path, VALID).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    let out = check(&path);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("writable by all users"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
    assert!(check(&path).status.success());
}

//! The rules in config/web.toml against access log lines.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use logwizz::config::{self, Config};
use logwizz::metrics::Metrics;
use logwizz::threshold::Thresholds;

fn web() -> Config {
    config::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("config/web.toml")).unwrap()
}

/// Rule ids matching `line`, each with its captured source.
fn hits(cfg: &Config, line: &str) -> Vec<String> {
    cfg.rules
        .iter()
        .filter(|r| r.matcher.is_match(line.as_bytes()))
        .map(|r| {
            let fields = r.matcher.fields(line.as_bytes());
            assert_eq!(fields.len(), 1, "{}: only src is captured", r.id);
            format!("{} {}", r.id, String::from_utf8_lossy(&fields[0].1))
        })
        .collect()
}

/// A combined-format line from 192.0.2.9.
fn combined(request: &str, status: u16) -> String {
    format!(
        r#"192.0.2.9 - - [25/Oct/2026:10:00:04 +0000] "{request}" {status} 153 "-" "Mozilla/5.0""#
    )
}

/// A Caddy JSON access log line from 192.0.2.9.
fn caddy(method: &str, uri: &str, status: u16) -> String {
    let uri = serde_json::to_string(uri).unwrap();
    format!(
        r#"{{"level":"info","ts":1761398404.5,"logger":"http.log.access","msg":"handled request","request":{{"remote_ip":"192.0.2.9","remote_port":"51000","client_ip":"192.0.2.9","proto":"HTTP/1.1","method":"{method}","host":"example.org","uri":{uri},"headers":{{"User-Agent":["Mozilla/5.0"]}}}},"bytes_read":0,"duration":0.001,"size":153,"status":{status}}}"#
    )
}

/// Both formats of one request.
fn both(method: &str, uri: &str, status: u16) -> [String; 2] {
    [
        combined(&format!("{method} {uri} HTTP/1.1"), status),
        caddy(method, uri, status),
    ]
}

#[test]
fn attacks_match_in_both_formats() {
    let cfg = web();
    let cases: &[(&str, &str, u16, &[&str])] = &[
        (
            "GET",
            "/static/../../../etc/passwd",
            400,
            &["web_path_traversal", "web_error_burst"],
        ),
        (
            "GET",
            "/download?file=..%2F..%2Fsecret",
            200,
            &["web_path_traversal"],
        ),
        (
            "GET",
            "/%2e%2e/%2e%2e/etc/shadow",
            404,
            &["web_path_traversal", "web_error_burst"],
        ),
        (
            "GET",
            "/view?page=/etc/passwd",
            200,
            &["web_path_traversal"],
        ),
        (
            "GET",
            "/.env",
            404,
            &["web_sensitive_probe", "web_error_burst"],
        ),
        ("GET", "/app/.env.production", 200, &["web_sensitive_probe"]),
        (
            "GET",
            "/.git/config",
            403,
            &["web_sensitive_probe", "web_error_burst"],
        ),
        (
            "HEAD",
            "/.aws/credentials",
            404,
            &["web_sensitive_probe", "web_error_burst"],
        ),
        (
            "GET",
            "/wp-config.php.bak",
            404,
            &["web_sensitive_probe", "web_error_burst"],
        ),
        (
            "GET",
            "/backup/site.sql.gz?x=1",
            200,
            &["web_sensitive_probe"],
        ),
        ("GET", "/phpinfo.php", 200, &["web_sensitive_probe"]),
        ("POST", "/wp-login.php", 200, &["web_login_bruteforce"]),
        ("POST", "/blog/xmlrpc.php", 200, &["web_login_bruteforce"]),
        ("GET", "/missing", 404, &["web_error_burst"]),
        ("GET", "/admin", 401, &["web_error_burst"]),
    ];
    for (method, uri, status, rules) in cases {
        let expected: Vec<String> = rules.iter().map(|r| format!("{r} 192.0.2.9")).collect();
        for line in both(method, uri, *status) {
            assert_eq!(hits(&cfg, &line), expected, "{line}");
        }
    }
}

#[test]
fn normal_requests_match_nothing() {
    let cfg = web();
    let cases = [
        ("GET", "/", 200),
        ("GET", "/.well-known/acme-challenge/token", 200),
        ("GET", "/docs/v1.2/setup..html", 200),
        ("GET", "/search?q=environment+.env+files", 200),
        ("GET", "/blog/what-is-a-.git-directory", 200),
        ("GET", "/wp-login.php", 200),
        ("GET", "/files/report.sqlite", 200),
        ("GET", "/api/items", 429),
        ("GET", "/old", 301),
        ("POST", "/api/login", 200),
        ("GET", "/status/404", 200),
    ];
    for (method, uri, status) in cases {
        for line in both(method, uri, status) {
            assert!(
                hits(&cfg, &line).is_empty(),
                "{line}: {:?}",
                hits(&cfg, &line)
            );
        }
    }
}

#[test]
fn the_source_is_the_servers_not_the_requests() {
    let cfg = web();
    // The request, referrer and user agent are the client's text.
    let forged = r#"192.0.2.9 - - [25/Oct/2026:10:00:04 +0000] "GET /.env?"remote_ip":"203.0.113.99" HTTP/1.1" 404 153 "203.0.113.99 - - \"GET /.env" "203.0.113.99""#;
    for hit in hits(&cfg, forged) {
        assert!(hit.ends_with(" 192.0.2.9"), "{hit}");
    }
    assert!(!hits(&cfg, forged).is_empty());
    let line = caddy(
        "GET",
        r#"/.env?"remote_ip":"203.0.113.99","status":404"#,
        200,
    );
    assert_eq!(hits(&cfg, &line), ["web_sensitive_probe 192.0.2.9"]);
    // A status in the request does not make a 200 an error.
    let line = caddy("GET", r#"/x?"status":404"#, 200);
    assert!(hits(&cfg, &line).is_empty(), "{:?}", hits(&cfg, &line));
}

#[test]
fn every_rule_fires_at_its_count_per_source() {
    let cfg = web();
    let m = Arc::new(Metrics::default());
    let mut th = Thresholds::new(cfg.rules.len(), cfg.limits.threshold_max_groups, m);
    let now = Instant::now();
    let lines = [
        (
            "web_path_traversal",
            combined("GET /a/../../etc/passwd HTTP/1.1", 400),
        ),
        ("web_sensitive_probe", combined("GET /.env HTTP/1.1", 404)),
        (
            "web_login_bruteforce",
            combined("POST /wp-login.php HTTP/1.1", 200),
        ),
        ("web_error_burst", combined("GET /nope HTTP/1.1", 404)),
    ];
    for (id, line) in lines {
        let i = cfg.rules.iter().position(|r| r.id == id).unwrap();
        let rule = &cfg.rules[i];
        let t = rule.threshold.as_ref().unwrap();
        let mut observe = |line: &str| {
            let fields = rule.matcher.fields(line.as_bytes());
            th.observe(
                i,
                id,
                t,
                Path::new("/var/log/nginx/access.log"),
                &fields,
                now,
            )
        };
        for n in 1..t.count {
            assert!(observe(&line).is_none(), "{id} fired early at {n}");
            // Another client's requests are counted on their own.
            assert!(observe(&line.replace("192.0.2.9", "192.0.2.10")).is_none());
        }
        let fired = observe(&line).unwrap_or_else(|| panic!("{id} did not fire"));
        assert_eq!(fired.group.as_deref(), Some(&b"192.0.2.9"[..]), "{id}");
    }
}

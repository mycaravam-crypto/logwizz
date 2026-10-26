//! The rules in config/runtime.toml against audit log lines.

use std::path::Path;

use logwizz::config::{self, Config};

fn runtime() -> Config {
    config::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("config/runtime.toml")).unwrap()
}

/// Rule ids matching `line`, with their captured fields as name=value.
fn hits(cfg: &Config, line: &str) -> Vec<String> {
    cfg.rules
        .iter()
        .filter(|r| r.matcher.is_match(line.as_bytes()))
        .map(|r| {
            let fields: Vec<String> = r
                .matcher
                .fields(line.as_bytes())
                .iter()
                .map(|(i, v)| {
                    let name = r.matcher.group_name(*i).unwrap();
                    format!("{name}={}", String::from_utf8_lossy(v))
                })
                .collect();
            format!("{} {}", r.id, fields.join(" "))
        })
        .collect()
}

// auditd's default ENRICHED format appends the resolved names after a 0x1d byte.
const ENRICHED: &str =
    "\u{1d}ARCH=x86_64 SYSCALL=execve AUID=\"unset\" UID=\"www-data\" GID=\"www-data\"";

#[test]
fn rules_match_audit_records() {
    let cfg = runtime();
    let exec = format!(
        "type=SYSCALL msg=audit(1761400000.123:4242): arch=c000003e syscall=59 success=yes exit=0 \
         a0=55d0c8a3b2a0 a1=55d0c8a3b2f0 a2=55d0c8a3b300 a3=0 items=2 ppid=812 pid=4321 \
         auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 \
         tty=(none) ses=4294967295 comm=\"sh\" exe=\"/usr/bin/dash\" subj=unconfined \
         key=\"logwizz_service_exec\"{ENRICHED}"
    );
    assert_eq!(
        hits(&cfg, &exec),
        [
            "service_exec serial=4242 ppid=812 pid=4321 auid=4294967295 uid=33 exe=/usr/bin/dash \
             auid_name=unset uid_name=www-data"
        ]
    );
    // A path with a space is hex-encoded: still reported, without exe.
    let hex = exec.replace("exe=\"/usr/bin/dash\"", "exe=2F746D702F6120622F7368");
    assert_eq!(
        hits(&cfg, &hex),
        [
            "service_exec serial=4242 ppid=812 pid=4321 auid=4294967295 uid=33 \
             auid_name=unset uid_name=www-data"
        ]
    );

    let write = "type=SYSCALL msg=audit(1761400100.456:4300): arch=c000003e syscall=257 success=yes \
                 exit=3 a0=ffffff9c a1=7ffd5a1c2f10 a2=441 a3=1b6 items=2 ppid=1001 pid=2002 \
                 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 \
                 comm=\"bash\" exe=\"/usr/bin/bash\" subj=unconfined key=\"logwizz_sensitive_write\"";
    assert_eq!(
        hits(&cfg, write),
        ["sensitive_write serial=4300 pid=2002 auid=1000 uid=0 exe=/usr/bin/bash"]
    );
    // The same record in the ENRICHED format: the login user stays visible after sudo.
    let enriched =
        format!("{write}\u{1d}ARCH=x86_64 SYSCALL=openat AUID=\"alice\" UID=\"root\" GID=\"root\"");
    assert_eq!(
        hits(&cfg, &enriched),
        [
            "sensitive_write serial=4300 pid=2002 auid=1000 uid=0 exe=/usr/bin/bash \
             auid_name=alice uid_name=root"
        ]
    );
    // Names only come from auditd's part after 0x1d, never from the raw record.
    let raw_lookalike = write.replace(
        "subj=unconfined",
        "subj=unconfined AUID=\"root\" UID=\"root\"",
    );
    assert_eq!(
        hits(&cfg, &raw_lookalike),
        ["sensitive_write serial=4300 pid=2002 auid=1000 uid=0 exe=/usr/bin/bash"]
    );

    for line in [
        "type=CONFIG_CHANGE msg=audit(1761400200.000:4400): auid=1000 ses=3 subj=unconfined \
         op=remove_rule key=\"logwizz_service_exec\" list=4 res=1",
        "type=CONFIG_CHANGE msg=audit(1761400200.000:4400): op=set audit_enabled=0 old=1 \
         auid=1000 ses=3 subj=unconfined res=1",
    ] {
        assert_eq!(hits(&cfg, line), ["audit_disabled serial=4400"], "{line}");
    }

    for line in [
        "Oct 25 10:00:00 web1 kernel: [ 812.123456] audit: audit_lost=1 audit_rate_limit=0 audit_backlog_limit=8192",
        "audit: audit_backlog=8193 > audit_backlog_limit=8192",
    ] {
        assert_eq!(hits(&cfg, line), ["audit_lost "], "{line}");
    }

    // Records of other keys, other record types of the same event, and
    // routine rule changes are not reported.
    for line in [
        exec.replace("logwizz_service_exec", "other_key"),
        "type=PATH msg=audit(1761400100.456:4300): item=1 name=\"/etc/passwd\" inode=1234 \
         dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 \
         cap_fe=0 cap_fver=0 cap_frootid=0"
            .into(),
        "type=PROCTITLE msg=audit(1761400000.123:4242): proctitle=7368002D63006964".into(),
        "type=CONFIG_CHANGE msg=audit(1761400200.000:4401): auid=0 ses=3 subj=unconfined \
         op=add_rule key=\"logwizz_service_exec\" list=4 res=1"
            .into(),
        "type=CONFIG_CHANGE msg=audit(1761400200.000:4402): auid=0 ses=3 subj=unconfined \
         op=remove_rule key=\"other_key\" list=4 res=1"
            .into(),
    ] {
        assert!(hits(&cfg, &line).is_empty(), "{line}");
    }
}

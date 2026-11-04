//! Validates the opt-in Docker egress profile without Docker or root.

use std::fs;
use std::path::Path;
use std::process::Command;

fn profile() -> toml::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/docker-egress.toml");
    let source = fs::read_to_string(path).unwrap();
    toml::from_str(&source).unwrap()
}

#[test]
fn docker_egress_profile_passes_config_validation() {
    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/docker-egress.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_logwizz"))
        .args(["--config", config.to_str().unwrap(), "--check-config"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn docker_egress_rule_captures_denied_connections_only() {
    let doc = profile();
    let rule = &doc["rules"][0];
    assert_eq!(rule["id"].as_str(), Some("docker_egress_denied"));
    let pattern = regex::Regex::new(rule["pattern"].as_str().unwrap()).unwrap();

    let denied = "logwizz-egress-deny: IN=br-logwizz OUT=veth-up SRC=172.28.241.2 DST=198.18.0.2 LEN=60 PROTO=TCP SPT=49152 DPT=8081 WINDOW=64240";
    let found = pattern.captures(denied).unwrap();
    assert_eq!(found.name("src").unwrap().as_str(), "172.28.241.2");
    assert_eq!(found.name("dst").unwrap().as_str(), "198.18.0.2");
    assert_eq!(found.name("proto").unwrap().as_str(), "TCP");
    assert_eq!(found.name("dpt").unwrap().as_str(), "8081");

    let denied_v6 = "logwizz-egress-deny: IN=br-logwizz OUT=eth0 SRC=2001:db8::2 DST=2001:db8::3 LEN=80 PROTO=TCP SPT=49152 DPT=443";
    assert!(pattern.is_match(denied_v6));

    let denied_icmp = "logwizz-egress-deny: IN=br-logwizz OUT=eth0 SRC=172.28.241.2 DST=198.18.0.2 LEN=48 PROTO=ICMP TYPE=8 CODE=0";
    let found = pattern.captures(denied_icmp).unwrap();
    assert_eq!(found.name("proto").unwrap().as_str(), "ICMP");
    assert!(found.name("dpt").is_none());

    let allowed = "IN=br-logwizz OUT=veth-up SRC=172.28.241.2 DST=198.18.0.2 LEN=60 PROTO=TCP SPT=49152 DPT=8080";
    assert!(!pattern.is_match(allowed));
    assert!(!pattern.is_match("logwizz-egress-deny: unstructured noise"));
}

#[test]
fn firewall_template_requires_explicit_destination_and_port() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/docker/logwizz-egress.nft");
    let template = fs::read_to_string(path).unwrap();
    assert!(template.contains("<ALLOW_IPV4>"));
    assert!(template.contains("<ALLOW_TCP_PORT>"));
    assert!(!template.contains("192.0.2.10"));
}

#[test]
fn firewall_template_preserves_same_bridge_traffic() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/docker/logwizz-egress.nft");
    let template = fs::read_to_string(path).unwrap();
    let internal = template
        .find("iifname \"br-logwizz\" oifname \"br-logwizz\" accept")
        .expect("same-bridge exemption is required with br_netfilter");
    let deny = template
        .find("iifname \"br-logwizz\" counter drop")
        .expect("egress deny rule");
    assert!(internal < deny, "same-bridge exception must precede the drop");
}

//! Turns `git describe --tags --long --dirty --always` output into the version
//! a source build reports. Shared by build.rs and tests/version.rs.

/// `v0.12.9-0-g62a126b` → `0.12.9+g62a126b`, `v0.12.9-3-g1a2b3c4-dirty` →
/// `0.12.9+3.g1a2b3c4.dirty`, a bare hash (no tag reachable) →
/// `unknown+g62a126b`. Anything else is not trusted: `None`.
pub fn version_from_describe(describe: &str) -> Option<String> {
    let describe = describe.trim();
    let (describe, dirty) = match describe.strip_suffix("-dirty") {
        Some(rest) => (rest, true),
        None => (describe, false),
    };
    let mut meta = Vec::new();
    let base = if is_hash(describe) {
        meta.push(format!("g{describe}"));
        "unknown"
    } else {
        // Split from the right: the tag itself contains no '-', but be strict anyway.
        let mut parts = describe.rsplitn(3, '-');
        let hash = parts.next()?.strip_prefix('g').filter(|h| is_hash(h))?;
        let ahead = parts.next()?;
        let tag = parts.next()?.strip_prefix('v').filter(|t| is_semver(t))?;
        if ahead.is_empty() || !ahead.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if ahead != "0" {
            meta.push(ahead.to_string());
        }
        meta.push(format!("g{hash}"));
        tag
    };
    if dirty {
        meta.push("dirty".to_string());
    }
    Some(format!("{base}+{}", meta.join(".")))
}

fn is_hash(s: &str) -> bool {
    (4..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_semver(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

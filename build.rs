//! Sets LOGWIZZ_VERSION, the version both binaries report (#102).
//!
//! Release builds (the release workflow sets LOGWIZZ_RELEASE=1) report the
//! version it stamped into Cargo.toml, exactly. Source builds report where
//! they come from, from `git describe`, because Cargo.toml's version is only a
//! placeholder there.

use std::path::Path;
use std::process::Command;

#[path = "build/describe.rs"]
mod describe;

fn main() {
    println!("cargo:rerun-if-env-changed=LOGWIZZ_RELEASE");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build/describe.rs");

    let version = if std::env::var("LOGWIZZ_RELEASE").as_deref() == Ok("1") {
        std::env::var("CARGO_PKG_VERSION").expect("set by cargo")
    } else {
        source_version()
            .unwrap_or_else(|| "unknown (source build without git metadata)".to_string())
    };
    println!("cargo:rustc-env=LOGWIZZ_VERSION={version}");
}

fn source_version() -> Option<String> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    // Only this repository's metadata: not a repository the source happens to sit in.
    let top = git(&manifest, &["rev-parse", "--show-toplevel"])?;
    if Path::new(&top).canonicalize().ok()? != Path::new(&manifest).canonicalize().ok()? {
        return None;
    }
    // Rebuild when the commit, the tags or the working tree change. Only paths
    // that exist: cargo reruns the script on every build for a missing one,
    // and packed-refs or index are often absent. A later `git pack-refs`
    // still changes refs/heads, so the new file is picked up on the next run.
    if let Some(dir) = git(&manifest, &["rev-parse", "--absolute-git-dir"]) {
        for p in ["HEAD", "index", "packed-refs", "refs/heads", "refs/tags"] {
            let path = Path::new(&dir).join(p);
            if path.exists() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    let out = git(
        &manifest,
        &[
            "describe",
            "--tags",
            "--long",
            "--dirty",
            "--always",
            "--abbrev=7",
            "--match",
            "v[0-9]*",
        ],
    )?;
    describe::version_from_describe(&out)
}

fn git(dir: &str, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}

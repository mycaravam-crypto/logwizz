//! The version a source build reports, from `git describe` (#102).

#[path = "../build/describe.rs"]
mod describe;

use describe::version_from_describe as v;

#[test]
fn tagged_commit() {
    assert_eq!(v("v0.12.9-0-g62a126b").as_deref(), Some("0.12.9+g62a126b"));
}

#[test]
fn commits_after_the_tag() {
    assert_eq!(
        v("v0.12.9-3-g1a2b3c4\n").as_deref(),
        Some("0.12.9+3.g1a2b3c4")
    );
}

#[test]
fn uncommitted_changes() {
    assert_eq!(
        v("v0.12.9-0-g62a126b-dirty").as_deref(),
        Some("0.12.9+g62a126b.dirty")
    );
    assert_eq!(
        v("v0.12.9-3-g1a2b3c4-dirty").as_deref(),
        Some("0.12.9+3.g1a2b3c4.dirty")
    );
}

#[test]
fn no_tag_reachable() {
    // A shallow clone without tags: `--always` prints the hash alone.
    assert_eq!(v("62a126b").as_deref(), Some("unknown+g62a126b"));
    assert_eq!(
        v("62a126b-dirty").as_deref(),
        Some("unknown+g62a126b.dirty")
    );
}

#[test]
fn unexpected_output_is_rejected() {
    for bad in [
        "",
        "v0.12-0-g62a126b",
        "v0.12.9-x-g62a126b",
        "v0.12.9-0-62a126b",
        "0.12.9-0-g62a126b",
        "release-0-g62a126b",
        "v0.12.9-0-gzzzzzzz",
    ] {
        assert_eq!(v(bad), None, "{bad:?}");
    }
}

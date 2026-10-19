//! Integration tests for rapt library and CLI.

use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::tempdir;

use rapt::models::{
    BinaryPackage, DependencyClause, DependencyGroup, DependencyItem, DependencyType,
    PackageOrigin, ProvideItem, SeriesCache, SourcePackage,
};
use rapt::types::{Architecture, Component, PackageTarget, Pocket, QueryFilter};
use rapt::{CacheManager, RaptQuery};

fn sample_package(name: &str, ver: &str, deps: Vec<(&str, &str, &str)>) -> BinaryPackage {
    let origin = PackageOrigin::new(
        Pocket::Release,
        Component::Main,
        Architecture::Amd64,
        "http://archive.ubuntu.com/ubuntu",
        "resolute",
    );

    let dep_items: Vec<DependencyItem> = deps
        .into_iter()
        .map(|(d_name, op, d_ver)| {
            DependencyItem::new(
                d_name,
                if op.is_empty() { None } else { Some(op) },
                if d_ver.is_empty() { None } else { Some(d_ver) },
                None::<String>,
            )
        })
        .collect();

    let dep_clauses = dep_items
        .into_iter()
        .map(|item| DependencyClause::new(vec![item]))
        .collect();

    let group = DependencyGroup::new(DependencyType::Depends, dep_clauses);

    BinaryPackage::new(
        name,
        ver,
        "amd64",
        Some("Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"),
        Some("100"),
        vec![group],
        vec![ProvideItem::new(format!("{name}-virtual"), None::<String>)],
        Some("utils"),
        Some("optional"),
        Some("https://ubuntu.com"),
        Some(format!(
            "{name} - A sample package for testing\n This is a long description."
        )),
        Some("c4a4aec43084cfb4a44c959b27e3a6d6"),
        Some(format!(
            "pool/main/{}/{}_{}_amd64.deb",
            &name[0..1],
            name,
            ver
        )),
        Some(12345),
        Some("9c615279194cc93afd85ecc6a97bb958"),
        Some("a2c731ebbc971e457699c4ed46ea905b2d78aa12"),
        Some("b6e9bef3c865aa17757cd9ffa820c05a37833f8a6b58287afc9f32dedb345965"),
        Some(
            "ffd586fe981aec819ebd848f11640c1a9b9740a1b57231509bbef25b28a65a813d4e6a066df91b393d3cb911766084349729588ca247728f997468a931161548",
        ),
        None::<String>,
        origin,
        vec![
            ("Package".to_string(), name.to_string()),
            ("Version".to_string(), ver.to_string()),
            ("Architecture".to_string(), "amd64".to_string()),
            (
                "Description".to_string(),
                format!("{name} - A sample package for testing\n This is a long description."),
            ),
        ],
    )
}

fn create_test_cache() -> SeriesCache {
    let mut cache = SeriesCache::new("resolute");

    let hello = sample_package("hello", "2.10-5build1", vec![("libc6", ">=", "2.38")]);
    let libc6 = sample_package("libc6", "2.38-1ubuntu6", vec![]);
    let curl = sample_package(
        "curl",
        "8.18.0-1ubuntu2",
        vec![("libc6", ">=", "2.34"), ("libcurl4", "=", "8.18.0")],
    );

    cache.packages.insert("hello".to_string(), vec![hello]);
    cache.packages.insert("libc6".to_string(), vec![libc6]);
    cache.packages.insert("curl".to_string(), vec![curl]);

    cache.provides.insert(
        "hello-virtual".to_string(),
        vec![("hello".to_string(), "2.10-5build1".to_string(), None)],
    );

    let src = SourcePackage::new(
        "hello",
        "2.10-5build1",
        vec!["hello".to_string()],
        Some("Santiago Vila <sanvila@debian.org>"),
        Some("pool/main/h/hello"),
        vec![
            ("Package".to_string(), "hello".to_string()),
            ("Version".to_string(), "2.10-5build1".to_string()),
            ("Binary".to_string(), "hello".to_string()),
        ],
    );
    cache.source_packages.insert("hello".to_string(), vec![src]);

    cache
}

#[test]
fn test_query_show() {
    let cache = create_test_cache();
    let filter = QueryFilter::builder("resolute").build().unwrap();
    let query = RaptQuery::new(&cache, &filter);

    let target: PackageTarget = "hello".parse().unwrap();
    let output = query.show(&target).unwrap();
    assert!(output.contains("Package: hello"));
    assert!(output.contains("Version: 2.10-5build1"));

    let target_ver: PackageTarget = "hello=2.10-5build1".parse().unwrap();
    let output_ver = query.show(&target_ver).unwrap();
    assert!(output_ver.contains("Package: hello"));

    let target_nonexistent: PackageTarget = "hello=9.9.9".parse().unwrap();
    assert!(query.show(&target_nonexistent).is_err());
}

#[test]
fn test_query_showpkg() {
    let cache = create_test_cache();
    let filter = QueryFilter::builder("resolute").build().unwrap();
    let query = RaptQuery::new(&cache, &filter);

    let output = query.showpkg("hello");
    assert!(output.contains("Package: hello"));
    assert!(output.contains("Versions:"));
    assert!(output.contains("2.10-5build1"));
    assert!(output.contains("Reverse Depends:"));
    assert!(output.contains("Dependencies:"));
    assert!(output.contains("libc6"));
    assert!(output.contains("Provides:"));
}

#[test]
fn test_query_showsrc() {
    let cache = create_test_cache();
    let filter = QueryFilter::builder("resolute").build().unwrap();
    let query = RaptQuery::new(&cache, &filter);

    let output = query.showsrc("hello").unwrap();
    assert!(output.contains("Package: hello"));
    assert!(output.contains("Binary: hello"));
    assert_eq!(query.showsrc("nonexistent"), None);
}

#[test]
fn test_query_depends_and_rdepends() {
    let cache = create_test_cache();
    let filter = QueryFilter::builder("resolute").build().unwrap();
    let query = RaptQuery::new(&cache, &filter);

    let target_hello: PackageTarget = "hello".parse().unwrap();
    let dep_output = query.depends(&target_hello).unwrap();
    assert!(dep_output.contains("hello"));
    assert!(dep_output.contains("Depends: libc6"));

    let target_libc6: PackageTarget = "libc6".parse().unwrap();
    let rdep_output = query.rdepends(&target_libc6).unwrap();
    assert!(rdep_output.contains("libc6"));
    assert!(rdep_output.contains("hello"));
    assert!(rdep_output.contains("curl"));
}

#[test]
fn test_query_pkgnames() {
    let cache = create_test_cache();
    let filter = QueryFilter::builder("resolute").build().unwrap();
    let query = RaptQuery::new(&cache, &filter);

    let all_names = query.pkgnames(None);
    assert!(all_names.contains(&"hello".to_string()));
    assert!(all_names.contains(&"libc6".to_string()));
    assert!(all_names.contains(&"curl".to_string()));
    assert!(all_names.contains(&"hello-virtual".to_string()));

    let hel_names = query.pkgnames(Some("hel"));
    assert!(hel_names.contains(&"hello".to_string()));
    assert!(hel_names.contains(&"hello-virtual".to_string()));
    assert!(!hel_names.contains(&"libc6".to_string()));
}

#[test]
fn test_query_madison() {
    let cache = create_test_cache();
    let filter = QueryFilter::builder("resolute").build().unwrap();
    let query = RaptQuery::new(&cache, &filter);

    let output = query.madison("hello");
    assert!(output.contains(
        "hello | 2.10-5build1 | http://archive.ubuntu.com/ubuntu resolute/main amd64 Packages"
    ));
    assert!(
        output.contains(
            "hello | 2.10-5build1 | http://archive.ubuntu.com/ubuntu resolute/main Sources"
        )
    );
}

#[test]
fn test_query_stats() {
    let cache = create_test_cache();
    let filter = QueryFilter::builder("resolute").build().unwrap();
    let query = RaptQuery::new(&cache, &filter);

    let stats = query.stats();
    assert_eq!(stats.normal_packages, 3); // hello, libc6, curl
    assert_eq!(stats.single_virtual_packages, 1); // hello-virtual
    assert_eq!(stats.missing, 1); // libcurl4 (referenced by curl, not provided)
    assert!(stats.total_package_names >= 4);
}

#[test]
fn test_query_search() {
    let cache = create_test_cache();
    let filter = QueryFilter::builder("resolute").build().unwrap();
    let query = RaptQuery::new(&cache, &filter);

    let reg = vec![regex::Regex::new("testing").unwrap()];
    let output = query.search(&reg, false, false);
    assert!(output.contains("hello - hello - A sample package for testing"));

    let reg_names = vec![regex::Regex::new("^hel").unwrap()];
    let output_names = query.search(&reg_names, false, true);
    assert!(output_names.contains("hello"));
}

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("rapt").unwrap();
    cmd.arg("version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("rapt version"));
}

#[test]
fn test_cli_missing_series() {
    let mut cmd = Command::cargo_bin("rapt").unwrap();
    cmd.arg("stats");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("target series is required"));
}

#[test]
fn test_cli_mutually_exclusive_filters() {
    let mut cmd = Command::cargo_bin("rapt").unwrap();
    cmd.args([
        "--series",
        "resolute",
        "--pocket",
        "release",
        "--not-pocket",
        "proposed",
        "stats",
    ]);
    cmd.assert().failure().stderr(predicate::str::contains(
        "cannot specify both --pocket and --not-pocket",
    ));
}

#[test]
fn test_cli_with_cached_file() {
    let dir = tempdir().unwrap();
    let cache_manager = CacheManager::new(dir.path());
    let cache = create_test_cache();
    cache_manager.save_cache(&cache).unwrap();

    let mut cmd = Command::cargo_bin("rapt").unwrap();
    cmd.env("RAPT_CACHE_DIR", dir.path());
    cmd.args(["--series", "resolute", "stats"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Total package names:"));

    let mut cmd2 = Command::cargo_bin("rapt").unwrap();
    cmd2.env("RAPT_CACHE_DIR", dir.path());
    cmd2.args(["--series", "resolute", "show", "hello"]);
    cmd2.assert()
        .success()
        .stdout(predicate::str::contains("Package: hello"));

    let mut cmd3 = Command::cargo_bin("rapt").unwrap();
    cmd3.env("RAPT_CACHE_DIR", dir.path());
    cmd3.args(["--series", "resolute", "pkgnames", "hel"]);
    cmd3.assert()
        .success()
        .stdout(predicate::str::contains("hello"));

    // Test short flags: -s, -p, -c, -a, and search -n, -f
    let mut cmd_short = Command::cargo_bin("rapt").unwrap();
    cmd_short.env("RAPT_CACHE_DIR", dir.path());
    cmd_short.args([
        "-s", "resolute", "-p", "release", "-c", "main", "-a", "amd64", "stats",
    ]);
    cmd_short
        .assert()
        .success()
        .stdout(predicate::str::contains("Total package names:"));

    let mut cmd_short_search = Command::cargo_bin("rapt").unwrap();
    cmd_short_search.env("RAPT_CACHE_DIR", dir.path());
    cmd_short_search.args(["-s", "resolute", "search", "-n", "hello"]);
    cmd_short_search
        .assert()
        .success()
        .stdout(predicate::str::contains("hello"));

    let mut cmd_short_search_full = Command::cargo_bin("rapt").unwrap();
    cmd_short_search_full.env("RAPT_CACHE_DIR", dir.path());
    cmd_short_search_full.args(["-s", "resolute", "search", "-f", "hello"]);
    cmd_short_search_full
        .assert()
        .success()
        .stdout(predicate::str::contains("Package: hello"));

    // Test short inverse filter flags: -q, -d, -b
    let mut cmd_short_inverse = Command::cargo_bin("rapt").unwrap();
    cmd_short_inverse.env("RAPT_CACHE_DIR", dir.path());
    cmd_short_inverse.args([
        "-s",
        "resolute",
        "-q",
        "proposed",
        "-d",
        "restricted",
        "-b",
        "armhf",
        "stats",
    ]);
    cmd_short_inverse
        .assert()
        .success()
        .stdout(predicate::str::contains("Total package names:"));

    // Test mutually exclusive short flags: -p and -q
    let mut cmd_short_conflict = Command::cargo_bin("rapt").unwrap();
    cmd_short_conflict.env("RAPT_CACHE_DIR", dir.path());
    cmd_short_conflict.args(["-s", "resolute", "-p", "release", "-q", "proposed", "stats"]);
    cmd_short_conflict
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot specify both --pocket and --not-pocket",
        ));
}

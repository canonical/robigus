//! WP-1.8 process-level CLI contracts. Analysis remains an explicit stub;
//! sandbox-unavailable and incomplete-analysis exits belong to later WPs.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::ErrorKind,
    net::TcpListener,
    path::{Path, PathBuf},
    time::Duration,
};

use assert_cmd::Command;
use predicates::prelude::*;
use robigus::model::{Confidence, Ecosystem, PackageVersion};
use robigus::{
    AnalysisMetadata, AnalysisStatus, AnalysisStrategy, AnalyzerId, Configuration, DependencyKind,
    Edge, Evidence, EvidenceMethod, Node, PackageId, PlanRow, PlanStatus, PlanSubject, Predicate,
    Requirement, RequirementKind, SourceId, SourceKind, Store, path_tree_digest,
};
use serde_json::Value;
use tempfile::TempDir;

const ROOT: &str = "fixture-root";
const NORMAL: &str = "fixture-normal";
const BUILD: &str = "fixture-build";
const DEVELOPMENT: &str = "fixture-development";
const RUNTIME: &str = "fixture-runtime";
const TRANSITIVE: &str = "fixture-transitive";
const NAMES: [&str; 6] = [ROOT, NORMAL, BUILD, DEVELOPMENT, RUNTIME, TRANSITIVE];

fn cli(dir: &TempDir) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("tsp-analyzer"));
    command
        .env_clear()
        .env("HOME", dir.path())
        .env("XDG_CACHE_HOME", dir.path().join("xdg-cache"))
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .current_dir(dir.path())
        .timeout(Duration::from_secs(10));
    command
}

fn with_db(dir: &TempDir, db: &Path) -> Command {
    let mut command = cli(dir);
    command.arg("--db").arg(db);
    command
}

fn source_fixture(dir: &TempDir) -> PathBuf {
    let source = dir.path().join("source with spaces");
    fs::create_dir(&source).expect("create local source");
    fs::write(source.join("README.txt"), "local fetch fixture\n").expect("write source");
    source.canonicalize().expect("canonical source path")
}

fn package(name: &str, source: &Path) -> PackageId {
    PackageId {
        name: name.to_owned(),
        version: PackageVersion::SemVer(semver::Version::new(1, 0, 0)),
        source_id: SourceId {
            kind: SourceKind::Path {
                path: source.to_path_buf(),
            },
            precise: None,
        },
        ecosystem: Ecosystem::Rust,
    }
}

fn edge(from: &PackageId, to: &PackageId, kind: DependencyKind) -> Edge {
    Edge {
        from: from.clone(),
        to: Some(to.clone()),
        requirement: Requirement {
            kind: RequirementKind::Crate,
            name: to.name.clone(),
            version_req: None,
        },
        kinds: BTreeSet::from([kind]),
        predicate: Predicate::TRUE,
        confidence: Confidence::MAX,
        evidence: vec![Evidence {
            method: EvidenceMethod::Manifest,
            confidence: Confidence::MAX,
            location: None,
            detail: None,
        }],
    }
}

async fn set_status(store: &Store, id: &PackageId, status: AnalysisStatus) {
    if status == AnalysisStatus::NotStarted {
        return;
    }
    let mut row = PlanRow::new(
        PlanSubject::Package(id.clone()),
        AnalyzerId::Cargo,
        AnalysisStrategy::Manifest,
        None,
        PlanStatus::Running,
    );
    row.attempts = 1;
    store.upsert_plan_rows(&[row.clone()]).await.expect("plan");
    store
        .update_status(id, AnalysisStatus::Started)
        .await
        .expect("start node");
    match status {
        AnalysisStatus::Complete => row.status = PlanStatus::Complete,
        AnalysisStatus::Error => {
            row.status = PlanStatus::Failed;
            row.error = Some("synthetic analyzer failure".to_owned());
        }
        AnalysisStatus::Started => return,
        AnalysisStatus::NotStarted => unreachable!(),
    }
    store.upsert_plan_rows(&[row]).await.expect("finish plan");
    store.update_status(id, status).await.expect("finish node");
}

// root --normal--> normal --normal--> transitive
//      --build--> build; --development--> development; --runtime--> runtime
// Insert in deliberately unsorted order to exercise deterministic rendering.
async fn graph_fixture(dir: &TempDir, filename: &str, reverse: bool) -> PathBuf {
    let db = dir.path().join(filename);
    let store = Store::open(&db).await.expect("open fixture store");
    let ids: Vec<_> = NAMES.iter().map(|name| package(name, dir.path())).collect();
    store
        .write_metadata(&AnalysisMetadata {
            robigus_version: env!("CARGO_PKG_VERSION").to_owned(),
            project_name: ROOT.to_owned(),
            project_version: "1.0.0".to_owned(),
            source_kind: "path".to_owned(),
            source_uri: dir.path().display().to_string(),
            source_digest: "fixture-digest".to_owned(),
            configuration: Configuration::default(),
            toolchain: BTreeMap::new(),
            network_mode: "offline".to_owned(),
            sandbox_mode: "auto".to_owned(),
            options: serde_json::json!({}),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            updated_at: "2026-01-01T00:00:00Z".to_owned(),
        })
        .await
        .expect("metadata");
    let mut order = vec![3, 0, 5, 2, 4, 1];
    if reverse {
        order.reverse();
    }
    for index in order {
        store
            .upsert_node(&Node::new(ids[index].clone()))
            .await
            .expect("node");
    }
    store.set_root(&ids[0], true).await.expect("root");
    let mut edges = vec![
        edge(&ids[0], &ids[3], DependencyKind::Development),
        edge(&ids[0], &ids[1], DependencyKind::Normal),
        edge(&ids[0], &ids[4], DependencyKind::Runtime),
        edge(&ids[0], &ids[2], DependencyKind::Build),
    ];
    if reverse {
        edges.reverse();
    }
    store
        .upsert_edges(&ids[0], &edges)
        .await
        .expect("root edges");
    store
        .upsert_edges(&ids[1], &[edge(&ids[1], &ids[5], DependencyKind::Normal)])
        .await
        .expect("transitive edge");
    for (id, status) in ids.iter().zip([
        AnalysisStatus::Started,
        AnalysisStatus::NotStarted,
        AnalysisStatus::Started,
        AnalysisStatus::Complete,
        AnalysisStatus::Error,
        AnalysisStatus::NotStarted,
    ]) {
        set_status(&store, id, status).await;
    }
    assert!(store.check().await.expect("fixture integrity").is_ok());
    assert_eq!(
        store.load().await.expect("load fixture").graph.node_count(),
        6
    );
    db
}

fn stdout(command: &mut Command) -> Vec<u8> {
    command.assert().success().get_output().stdout.clone()
}

fn print(dir: &TempDir, db: &Path, format: &str, filters: &[&str]) -> Vec<u8> {
    stdout(
        with_db(dir, db)
            .args(["--format", format, "print"])
            .args(filters),
    )
}

fn assert_names(output: &[u8], included: &[&str], excluded: &[&str]) {
    let text = std::str::from_utf8(output).expect("UTF-8 output");
    for name in included {
        assert!(text.contains(name), "missing {name}: {text}");
    }
    for name in excluded {
        assert!(!text.contains(name), "unexpected {name}: {text}");
    }
}

#[test]
fn database_commands_require_global_db() {
    let dir = tempfile::tempdir().expect("tempdir");
    for args in [
        vec!["check"],
        vec!["print"],
        vec!["analyze", "."],
        vec!["export"],
    ] {
        cli(&dir)
            .args(args)
            .assert()
            .code(2)
            .stderr(predicate::str::contains("--db"));
    }
}

#[test]
fn invalid_arguments_are_usage_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("missing.db");
    for args in [
        vec!["--unknown-option"],
        vec!["unknown-command"],
        vec!["fetch"],
        vec!["analyze"],
        vec!["--format", "xml", "print"],
        vec!["--format", "dot", "print"],
        vec!["--format", "dot", "fetch", "."],
        vec!["--sandbox", "unsafe", "check"],
        vec!["--jobs", "not-a-number", "check"],
        vec!["--jobs", "0", "check"],
        vec!["print", "--kind", "invalid"],
        vec!["print", "--status", "pending"],
        vec!["print", "--depth", "not-a-number"],
    ] {
        with_db(&dir, &db).args(args).assert().code(2);
    }
    assert!(
        !db.exists(),
        "argument validation must precede database opening"
    );
}

#[test]
fn help_and_version_do_not_require_a_database() {
    let dir = tempfile::tempdir().expect("tempdir");
    let help = stdout(cli(&dir).arg("--help"));
    assert_names(
        &help,
        &["fetch", "analyze", "check", "print", "export", "--db"],
        &[],
    );
    for command in ["fetch", "analyze", "check", "print", "export"] {
        cli(&dir).args([command, "--help"]).assert().success();
    }
    for args in [vec!["--version"], vec!["version"]] {
        cli(&dir)
            .args(args)
            .assert()
            .success()
            .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
    }
}

#[test]
fn local_fetch_offline_with_explicit_cache_prints_path_and_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_fixture(&dir);
    let cache = dir.path().join("explicit cache");
    let digest = path_tree_digest(&source).expect("tree digest");
    let mut command = cli(&dir);
    command
        .arg("--offline")
        .arg("--cache")
        .arg(&cache)
        .args([
            "--sandbox",
            "auto",
            "--jobs",
            "1",
            "--verbose",
            "--format",
            "text",
        ])
        .arg("fetch")
        .arg(&source);
    let first = stdout(&mut command);
    let text = std::str::from_utf8(&first).expect("UTF-8 output");
    assert!(
        text.lines()
            .any(|line| line == format!("path: {}", source.display()))
    );
    assert!(text.lines().any(|line| line == format!("digest: {digest}")));
    let second = stdout(&mut command);
    assert_eq!(first, second);
    assert_eq!(
        path_tree_digest(&source).expect("unchanged source digest"),
        digest
    );
    assert!(
        !dir.path().join("xdg-cache").exists(),
        "explicit cache must override XDG"
    );
    // Local paths are analyzed in place; a cache directory need not be created.
}

#[test]
fn local_fetch_json_is_machine_readable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_fixture(&dir);
    let output = stdout(
        cli(&dir)
            .args(["--offline", "--format", "json"])
            .arg("--cache")
            .arg(dir.path().join("cache"))
            .arg("fetch")
            .arg(&source),
    );
    let value: Value = serde_json::from_slice(&output).expect("fetch JSON");
    assert_eq!(
        value["path"],
        serde_json::to_value(&source).expect("path JSON")
    );
    assert_eq!(
        value["digest"],
        path_tree_digest(&source).expect("tree digest")
    );
    assert_eq!(
        value["provenance"],
        serde_json::to_value(robigus::Provenance::Verified).expect("provenance JSON")
    );
}

#[test]
fn missing_local_source_is_a_fetch_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing-source");
    cli(&dir)
        .arg("--offline")
        .arg("fetch")
        .arg(&missing)
        .assert()
        .code(1)
        .stderr(predicate::str::is_empty().not());
    assert!(!missing.exists());
}

#[test]
fn remote_offline_fetch_never_connects() {
    let dir = tempfile::tempdir().expect("tempdir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let url = format!(
        "https://{}/source.tar.gz",
        listener.local_addr().expect("address")
    );
    cli(&dir)
        .arg("--offline")
        .arg("--cache")
        .arg(dir.path().join("empty-cache"))
        .arg("fetch")
        .arg(url)
        .assert()
        .code(1)
        .stderr(predicate::str::is_match("(?i)offline").expect("regex"));
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        result => panic!("offline fetch attempted a network connection: {result:?}"),
    }
}

#[test]
fn remote_offline_fetch_resolves_pinned_cache_hits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = dir.path().join("cache");
    let digest = "a".repeat(64);
    let tarball_tree = cache.join("tarball").join(&digest);
    fs::create_dir_all(&tarball_tree).expect("create cached tarball tree");
    let commit = "b".repeat(40);
    let git_tree = cache.join("git").join(&commit);
    fs::create_dir_all(&git_tree).expect("create cached git tree");

    cli(&dir)
        .args(["--offline", "--cache"])
        .arg(&cache)
        .args([
            "fetch",
            "--sha256",
            &digest,
            "https://example.invalid/src.tar.gz",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("digest: {digest}")));
    cli(&dir)
        .args(["--offline", "--cache"])
        .arg(&cache)
        .args([
            "fetch",
            "--rev",
            &commit,
            "https://example.invalid/repo.git",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("digest: {commit}")));
}

#[tokio::test]
async fn check_reports_integrity_violation_with_exit_code_three() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = graph_fixture(&dir, "invalid-json.db", false).await;
    {
        let conn = rusqlite::Connection::open(&db).expect("open raw db");
        conn.execute("UPDATE metadata SET configuration = 'not-json'", [])
            .expect("corrupt metadata json");
    }
    let output = with_db(&dir, &db)
        .args(["--format", "json", "check"])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).expect("check JSON");
    assert_eq!(value["is_ok"], false);
    assert_eq!(value["invalid_json_columns"], 1);
}

#[tokio::test]
async fn check_healthy_database_in_text_and_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = graph_fixture(&dir, "healthy.db", false).await;
    with_db(&dir, &db).arg("check").assert().success();
    let output = stdout(with_db(&dir, &db).args(["--format", "json", "check"]));
    let value: Value = serde_json::from_slice(&output).expect("check JSON");
    assert!(value.is_object(), "integrity report must be a JSON object");
    let store = Store::open(&db).await.expect("open checked store");
    let report = store.check().await.expect("public integrity report");
    let expected = serde_json::to_value(report).expect("report JSON");
    for (key, expected_value) in expected.as_object().expect("report object") {
        assert_eq!(&value[key], expected_value, "check report field {key}");
    }
    assert_eq!(value["is_ok"], true);
}

#[test]
fn corrupted_and_newer_databases_are_database_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let corrupt = dir.path().join("corrupt.db");
    fs::write(&corrupt, b"not a SQLite database").expect("corrupt fixture");
    let newer = dir.path().join("newer.db");
    {
        let connection = rusqlite::Connection::open(&newer).expect("newer fixture");
        // Deliberately incompatible without assuming the current schema version.
        connection
            .pragma_update(None, "user_version", i32::MAX)
            .expect("schema version");
    }
    for db in [&corrupt, &newer] {
        for command in ["check", "print"] {
            with_db(&dir, db)
                .arg(command)
                .assert()
                .code(3)
                .stderr(predicate::str::is_empty().not());
        }
    }
}

#[test]
fn read_commands_do_not_create_missing_databases_or_parent_directories() {
    let dir = tempfile::tempdir().expect("tempdir");
    let parent = dir.path().join("missing-parent");
    let db = parent.join("missing.db");
    for command in ["check", "print"] {
        with_db(&dir, &db).arg(command).assert().code(3);
        assert!(!db.exists(), "{command} created a database");
        assert!(!parent.exists(), "{command} created the parent directory");
    }
}

#[tokio::test]
async fn print_is_deterministic_in_text_and_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first_db = graph_fixture(&dir, "first.db", false).await;
    let second_db = graph_fixture(&dir, "second.db", true).await;
    for format in ["text", "json"] {
        let first = print(&dir, &first_db, format, &[]);
        assert_names(&first, &NAMES, &[]);
        assert_eq!(first, print(&dir, &first_db, format, &[]));
        let second = print(&dir, &second_db, format, &[]);
        if format == "json" {
            let _: Value = serde_json::from_slice(&first).expect("print JSON");
            let _: Value = serde_json::from_slice(&second).expect("print JSON");
        }
        assert_eq!(first, second, "insertion-order dependence");
    }
}

#[tokio::test]
async fn print_filters_dependency_kinds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = graph_fixture(&dir, "kinds.db", false).await;
    for format in ["text", "json"] {
        for (kind, included, excluded) in [
            (
                "normal",
                vec![NORMAL, TRANSITIVE],
                vec![BUILD, DEVELOPMENT, RUNTIME],
            ),
            (
                "build",
                vec![BUILD],
                vec![NORMAL, DEVELOPMENT, RUNTIME, TRANSITIVE],
            ),
            (
                "development",
                vec![DEVELOPMENT],
                vec![NORMAL, BUILD, RUNTIME, TRANSITIVE],
            ),
            (
                "runtime",
                vec![RUNTIME],
                vec![NORMAL, BUILD, DEVELOPMENT, TRANSITIVE],
            ),
        ] {
            // Kind alone filters edges, while depth limits node reachability.
            let all_nodes = print(&dir, &db, format, &["--kind", kind]);
            assert_names(&all_nodes, &NAMES, &[]);
            let output = print(&dir, &db, format, &["--kind", kind, "--depth", "2"]);
            assert_names(&output, &included, &excluded);
            assert_names(&output, &[ROOT], &[]);
            if format == "json" {
                let value: Value = serde_json::from_slice(&all_nodes).expect("filtered JSON");
                let edges: Vec<Edge> = serde_json::from_value(value["edges"].clone())
                    .expect("public edge representation");
                let expected_kind = match kind {
                    "normal" => DependencyKind::Normal,
                    "build" => DependencyKind::Build,
                    "development" => DependencyKind::Development,
                    "runtime" => DependencyKind::Runtime,
                    _ => unreachable!(),
                };
                assert_eq!(edges.len(), included.len());
                assert!(edges.iter().all(|edge| edge.kinds.contains(&expected_kind)));
            }
        }
    }
}

#[tokio::test]
async fn print_filters_depth_and_combines_filters() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = graph_fixture(&dir, "depth.db", false).await;
    for format in ["text", "json"] {
        assert_names(
            &print(&dir, &db, format, &["--depth", "0"]),
            &[ROOT],
            &NAMES[1..],
        );
        assert_names(
            &print(&dir, &db, format, &["--depth", "1"]),
            &NAMES[..5],
            &[TRANSITIVE],
        );
        assert_names(&print(&dir, &db, format, &["--depth", "2"]), &NAMES, &[]);
        assert_names(
            &print(&dir, &db, format, &["--kind", "normal", "--depth", "1"]),
            &[NORMAL],
            &[BUILD, DEVELOPMENT, RUNTIME, TRANSITIVE],
        );
    }
}

#[tokio::test]
async fn print_filters_all_analysis_statuses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = graph_fixture(&dir, "status.db", false).await;
    for format in ["text", "json"] {
        for (status, included) in [
            ("not-started", vec![NORMAL, TRANSITIVE]),
            ("started", vec![ROOT, BUILD]),
            ("complete", vec![DEVELOPMENT]),
            ("error", vec![RUNTIME]),
        ] {
            let excluded: Vec<_> = NAMES
                .into_iter()
                .filter(|name| !included.contains(name))
                .collect();
            assert_names(
                &print(&dir, &db, format, &["--status", status]),
                &included,
                &excluded,
            );
        }
    }
}

#[test]
fn malformed_config_is_a_usage_error_before_fetch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_fixture(&dir);
    let config = dir.path().join("malformed.toml");
    fs::write(&config, "[limits\n").expect("malformed TOML");
    cli(&dir)
        .arg("--config")
        .arg(&config)
        .arg("--offline")
        .arg("fetch")
        .arg(&source)
        .assert()
        .code(2)
        .stderr(predicate::str::is_empty().not());
}

#[test]
fn config_rejects_unknown_fields_and_invalid_limits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_fixture(&dir);
    let config = dir.path().join("limits.toml");
    for contents in [
        "unknown_setting = true\n",
        "[limits.download]\nmax_bytes = 0\n",
        "[limits.download]\nconnect_timeout = 0\n",
        "[limits.download]\ntimeout = -1\n",
        "[limits.extraction]\nmax_entries = 0\n",
        "[limits.extraction]\nmax_total_size = 0\n",
        "[limits.git]\ntimeout = 0\n",
    ] {
        fs::write(&config, contents).expect("invalid config fixture");
        cli(&dir)
            .arg("--offline")
            .arg("--config")
            .arg(&config)
            .arg("fetch")
            .arg(&source)
            .assert()
            .code(2)
            .stderr(predicate::str::is_empty().not());
    }
    let missing = dir.path().join("missing.toml");
    cli(&dir)
        .arg("--config")
        .arg(&missing)
        .arg("fetch")
        .arg(&source)
        .assert()
        .code(2)
        .stderr(predicate::str::is_empty().not());
    assert!(!missing.exists());
}

#[test]
fn valid_config_and_global_options_after_subcommand_are_accepted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_fixture(&dir);
    let config = dir.path().join("valid.toml");
    fs::write(
        &config,
        "[limits.download]\nmax_bytes = 1\n\
        [limits.extraction]\nmax_entries = 1\nmax_total_size = 1\n\
        [limits.git]\nmax_submodule_depth = 0\nmax_submodules = 0\n",
    )
    .expect("valid limit config");
    // Acquisition limits do not apply to in-place local paths. Zero submodule
    // limits are valid and disable expansion, unlike positive size/count limits.
    let output = stdout(
        cli(&dir)
            .arg("fetch")
            .arg(&source)
            .args([
                "--offline",
                "--format",
                "json",
                "--jobs",
                "2",
                "--sandbox",
                "native",
            ])
            .arg("--config")
            .arg(&config)
            .arg("--cache")
            .arg(dir.path().join("cache")),
    );
    let value: Value = serde_json::from_slice(&output).expect("configured fetch JSON");
    assert_eq!(
        value["digest"],
        path_tree_digest(&source).expect("tree digest")
    );
}

#[tokio::test]
async fn status_filter_does_not_stop_depth_traversal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = graph_fixture(&dir, "combined.db", false).await;
    for format in ["text", "json"] {
        assert_names(
            &print(
                &dir,
                &db,
                format,
                &[
                    "--kind",
                    "normal",
                    "--depth",
                    "2",
                    "--status",
                    "not-started",
                ],
            ),
            &[NORMAL, TRANSITIVE],
            &[ROOT, BUILD, DEVELOPMENT, RUNTIME],
        );
        let mut command = cli(&dir);
        command
            .arg("print")
            .arg("--db")
            .arg(&db)
            .args(["--format", format, "--depth", "0"]);
        assert_names(&stdout(&mut command), &[ROOT], &NAMES[1..]);
    }
}

#[test]
fn placeholder_commands_explicitly_fail_instead_of_claiming_success() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source_fixture(&dir);
    let db = dir.path().join("stub.db");
    let placeholder = predicate::str::is_match("(?i)(not (yet )?implemented|stub|placeholder)")
        .expect("placeholder regex");
    with_db(&dir, &db)
        .arg("analyze")
        .arg(&source)
        .assert()
        .failure()
        .stderr(placeholder.clone());
}

//! WP-1.9 process-level export contracts (`tsp-analyzer --db PATH export`).
//!
//! Assumptions pinned down by this file:
//!
//! * `export` has no implicit format. The global `--format` flag defaults to
//!   `text`, so a bare `export` (or an explicit `--format text`) is a usage
//!   error (exit 2) rather than silently switching to JSON. Callers must say
//!   `--format json` or `--format dot` (spec §14).
//! * `--format json` serializes the persisted analysis snapshot — metadata,
//!   nodes, edges (resolved and unresolved), roots, plans, and tool
//!   invocations — as one JSON object. It is lossless: parsing it back yields
//!   an `AnalysisSnapshot` equal to the one read from the store (§11.3).
//! * `--format dot` is a lossy `petgraph` visualization: every node, every
//!   resolved edge, and one edge per unresolved requirement, with labels
//!   escaped for Graphviz.
//! * Readers never create databases or parent directories. Failures are
//!   database errors (exit 3) and write nothing to stdout.
//!
//! Ordering: assertions never assume a particular element order. Determinism
//! is checked by running the same export twice and comparing bytes.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use assert_cmd::Command;
use predicates::prelude::*;
use robigus::model::{Ecosystem, PackageVersion};
use robigus::{
    AnalysisMetadata, AnalysisSnapshot, AnalysisStatus, AnalysisStrategy, AnalyzerId,
    Configuration, Conflict, DependencyKind, Edge, Evidence, EvidenceMethod, Node, PackageId,
    PlanRow, PlanStatus, PlanSubject, Predicate, Provide, Requirement, RequirementKind, SourceId,
    SourceKind, Store, Target, TargetKind, ToolInvocation, VersionConstraint,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const ROOT: &str = "export-root";
const NORMAL: &str = "export-normal";
const BUILD: &str = "export-build";
/// A disconnected, never-started node: export must not drop it.
const IDLE: &str = "export-idle";
/// Names that must be escaped in DOT labels.
const ODD: &str = "odd \"quoted\" \\ name";
const UNRESOLVED: &str = "libmissing \"core\".h";
const FAILURE: &str = "synthetic analyzer failure";

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

fn package(dir: &TempDir, name: &str) -> PackageId {
    PackageId {
        name: name.to_owned(),
        version: PackageVersion::SemVer(semver::Version::new(1, 0, 0)),
        source_id: SourceId {
            kind: SourceKind::Path {
                path: dir.path().to_path_buf(),
            },
            precise: None,
        },
        ecosystem: Ecosystem::Rust,
    }
}

fn resolved_edge(from: &PackageId, to: &PackageId, kind: DependencyKind) -> Edge {
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
        confidence: robigus::Confidence::MAX,
        evidence: vec![Evidence {
            method: EvidenceMethod::Manifest,
            confidence: robigus::Confidence::MAX,
            location: None,
            detail: Some("fixture manifest".to_owned()),
        }],
    }
}

fn unresolved_edge(from: &PackageId, kind: RequirementKind, name: &str) -> Edge {
    Edge {
        from: from.clone(),
        to: None,
        requirement: Requirement {
            kind,
            name: name.to_owned(),
            version_req: Some(VersionConstraint::SemVer(
                ">=0.1".parse().expect("version requirement"),
            )),
        },
        kinds: BTreeSet::from([DependencyKind::Normal]),
        predicate: Predicate::TRUE,
        confidence: robigus::Confidence::new(60),
        evidence: vec![Evidence {
            method: EvidenceMethod::SourceScan,
            confidence: robigus::Confidence::new(60),
            location: None,
            detail: None,
        }],
    }
}

/// Records the plan-row-gated status transitions required by the store.
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
    store
        .upsert_plan_rows(&[row.clone()])
        .await
        .expect("plan row");
    store
        .update_status(id, AnalysisStatus::Started)
        .await
        .expect("start node");
    match status {
        AnalysisStatus::Complete => {
            row.status = PlanStatus::Complete;
            row.attempts = 2;
            row.detail = Some(format!("{} analyzed", id.name));
        }
        AnalysisStatus::Error => {
            row.status = PlanStatus::Failed;
            row.error = Some(FAILURE.to_owned());
        }
        AnalysisStatus::Started => return,
        AnalysisStatus::NotStarted => unreachable!(),
    }
    store.upsert_plan_rows(&[row]).await.expect("finish plan");
    store.update_status(id, status).await.expect("finish node");
}

struct Fixture {
    db: PathBuf,
    root: PackageId,
    normal: PackageId,
    build: PackageId,
    idle: PackageId,
    odd: PackageId,
}

/// root --normal--> normal --normal--> build
///                 normal --header(unresolved)--> libmissing "core".h
///      --build--> odd "quoted" \ name
///
/// `export-idle` is disconnected. Nodes are inserted in a mixed order; one
/// node carries a full payload (path, features, targets, provides, conflicts).
/// The database records a detection plan, package plans (including a
/// failure), and two invocations.
async fn fixture(dir: &TempDir) -> Fixture {
    let db = dir.path().join("export.db");
    let store = Store::open(&db).await.expect("open export fixture");
    let root = package(dir, ROOT);
    let normal = package(dir, NORMAL);
    let build = package(dir, BUILD);
    let idle = package(dir, IDLE);
    let odd = package(dir, ODD);

    let mut root_node = Node::new(root.clone());
    root_node.path = Some(PathBuf::from("crates/export-root"));
    root_node.active_features = BTreeSet::from(["default".to_owned(), "extra".to_owned()]);
    root_node.targets = vec![Target {
        name: "libexport".to_owned(),
        kind: TargetKind::SharedLibrary {
            soname: Some("libexport.so.1".to_owned()),
        },
        path: Some(PathBuf::from("target/release/libexport.so")),
    }];
    root_node.provides = vec![Provide {
        name: "export-virtual".to_owned(),
        version: Some(PackageVersion::SemVer(semver::Version::new(1, 0, 0))),
    }];
    root_node.conflicts = vec![Conflict {
        name: "export-legacy".to_owned(),
        version_req: Some(VersionConstraint::SemVer(
            ">=2".parse().expect("conflict requirement"),
        )),
    }];

    for node in [
        Node::new(odd.clone()),
        Node::new(normal.clone()),
        Node::new(build.clone()),
        root_node,
        Node::new(idle.clone()),
    ] {
        store.upsert_node(&node).await.expect("node");
    }
    store.set_root(&root, true).await.expect("root flag");

    store
        .write_metadata(&AnalysisMetadata {
            robigus_version: env!("CARGO_PKG_VERSION").to_owned(),
            project_name: "export-fixture".to_owned(),
            project_version: "2.3.4".to_owned(),
            source_kind: "path".to_owned(),
            source_uri: dir.path().display().to_string(),
            source_digest: "sha256:export-fixture".to_owned(),
            configuration: Configuration::default(),
            toolchain: BTreeMap::from([
                ("cargo".to_owned(), "1.93.1".to_owned()),
                ("rustc".to_owned(), "1.93.1".to_owned()),
            ]),
            network_mode: "offline".to_owned(),
            sandbox_mode: "native".to_owned(),
            options: json!({ "analysis_depth": 1 }),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            updated_at: "2026-01-01T00:00:00Z".to_owned(),
        })
        .await
        .expect("metadata");

    store
        .upsert_edges(
            &root,
            &[
                resolved_edge(&root, &normal, DependencyKind::Normal),
                resolved_edge(&root, &odd, DependencyKind::Build),
            ],
        )
        .await
        .expect("root edges");
    store
        .upsert_edges(
            &normal,
            &[
                resolved_edge(&normal, &build, DependencyKind::Normal),
                unresolved_edge(&normal, RequirementKind::Header, UNRESOLVED),
            ],
        )
        .await
        .expect("normal edges");

    let mut detection = PlanRow::new(
        PlanSubject::Root(PathBuf::new()),
        AnalyzerId::Cargo,
        AnalysisStrategy::Manifest,
        None,
        PlanStatus::Complete,
    );
    detection.attempts = 1;
    detection.detail = Some("workspace detected".to_owned());
    store
        .upsert_plan_rows(&[detection])
        .await
        .expect("detection plan");

    set_status(&store, &root, AnalysisStatus::Started).await;
    set_status(&store, &normal, AnalysisStatus::Complete).await;
    set_status(&store, &build, AnalysisStatus::Complete).await;
    set_status(&store, &odd, AnalysisStatus::Error).await;
    // `idle` intentionally stays `Not_Started` and disconnected.

    store
        .record_invocation(&ToolInvocation {
            package_id: None,
            tool: "rustc".to_owned(),
            argv: vec!["rustc".to_owned(), "--version".to_owned()],
            env: BTreeMap::new(),
            tool_version: Some("1.93.1".to_owned()),
            sandbox_mode: "native".to_owned(),
            exit_status: "0".to_owned(),
            started_at: "2026-01-01T00:00:01Z".to_owned(),
            duration_ms: 7,
            log_path: None,
        })
        .await
        .expect("probe invocation");
    store
        .record_invocation(&ToolInvocation {
            package_id: Some(root.clone()),
            tool: "cargo metadata".to_owned(),
            argv: vec![
                "cargo".to_owned(),
                "metadata".to_owned(),
                "--format-version".to_owned(),
                "1".to_owned(),
            ],
            env: BTreeMap::from([("CARGO_NET_OFFLINE".to_owned(), "true".to_owned())]),
            tool_version: Some("1.93.1".to_owned()),
            sandbox_mode: "native".to_owned(),
            exit_status: "0".to_owned(),
            started_at: "2026-01-01T00:00:02Z".to_owned(),
            duration_ms: 42,
            log_path: Some("logs/cargo-metadata.log".to_owned()),
        })
        .await
        .expect("metadata invocation");

    assert!(
        store.check().await.expect("fixture integrity").is_ok(),
        "fixture must be a valid analysis"
    );

    Fixture {
        db,
        root,
        normal,
        build,
        idle,
        odd,
    }
}

fn stdout(command: &mut Command) -> Vec<u8> {
    command.assert().success().get_output().stdout.clone()
}

/// Runs a successful export and returns raw stdout.
fn export_stdout(dir: &TempDir, db: &Path, format: &str) -> Vec<u8> {
    stdout(with_db(dir, db).args(["export", "--format", format]))
}

fn assert_database_error(command: &mut Command) {
    command
        .assert()
        .code(3)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty().not());
}

/// Decodes a Graphviz quoted attribute value from `line`, if it has one.
fn dot_label(line: &str) -> Option<String> {
    let rest = &line[line.find("label")?..];
    let start = rest.find('"')? + 1;
    let bytes = rest.as_bytes();
    let mut end = start;
    let mut escaped = false;
    while end < bytes.len() {
        match bytes[end] {
            b'\\' if !escaped => escaped = true,
            b'"' if !escaped => break,
            _ => escaped = false,
        }
        end += 1;
    }
    Some(unescape_dot(&rest[start..end]))
}

fn unescape_dot(value: &str) -> String {
    let mut output = String::new();
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character == '\\' {
            match chars.next() {
                // `\l` is Graphviz's left-justified line break.
                Some('l') => output.push('\n'),
                Some(other) => output.push(other),
                None => output.push('\\'),
            }
        } else {
            output.push(character);
        }
    }
    output
}

/// `(node id, unescaped label)` for every node declaration.
fn dot_node_labels(dot: &str) -> Vec<(String, String)> {
    dot.lines()
        .filter(|line| !line.contains(" -> "))
        .filter_map(|line| {
            let label = dot_label(line)?;
            let id = line.split(" [").next()?.trim();
            (!id.is_empty() && !id.contains(' ')).then(|| (id.to_owned(), label))
        })
        .collect()
}

/// `(source id, target id)` for every edge line.
fn dot_edges(dot: &str) -> Vec<(String, String)> {
    dot.lines()
        .filter_map(|line| {
            let (from, rest) = line.split_once(" -> ")?;
            let to = rest.split_whitespace().next()?;
            Some((from.trim().to_owned(), to.to_owned()))
        })
        .collect()
}

fn dot_node_id(labels: &[(String, String)], name: &str) -> String {
    labels
        .iter()
        .find(|(_, label)| label.contains(name))
        .unwrap_or_else(|| panic!("DOT has no node labeled with {name}"))
        .0
        .clone()
}

fn array<'a>(document: &'a Value, key: &str) -> &'a [Value] {
    document[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be a JSON array"))
}

fn node_entry<'a>(document: &'a Value, name: &str) -> &'a Value {
    array(document, "nodes")
        .iter()
        .find(|entry| entry["node"]["id"]["name"] == name)
        .unwrap_or_else(|| panic!("export has no node {name}"))
}

// ---------------------------------------------------------------------------
// usage, missing and invalid databases
// ---------------------------------------------------------------------------

#[test]
fn export_requires_the_global_database_option() {
    let dir = tempfile::tempdir().expect("tempdir");
    cli(&dir)
        .args(["export", "--format", "json"])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("--db"));
}

#[tokio::test]
async fn export_accepts_only_explicit_json_or_dot_formats() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = fixture(&dir).await;
    // The global `--format` default is `text`: an unspecified format must be a
    // usage error, never a silent text or JSON export.
    for args in [
        vec!["export"],
        vec!["export", "--format", "text"],
        vec!["export", "--format", "yaml"],
    ] {
        with_db(&dir, &fixture.db)
            .args(args)
            .assert()
            .code(2)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::is_empty().not());
    }
    assert!(!export_stdout(&dir, &fixture.db, "json").is_empty());
    assert!(!export_stdout(&dir, &fixture.db, "dot").is_empty());
}

#[test]
fn export_never_creates_a_missing_database_or_parent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let parent = dir.path().join("missing-parent");
    let db = parent.join("missing.db");
    for format in ["json", "dot"] {
        assert_database_error(with_db(&dir, &db).args(["export", "--format", format]));
        assert!(!db.exists(), "{format} export created a database");
        assert!(
            !parent.exists(),
            "{format} export created the parent directory"
        );
    }
}

#[test]
fn invalid_databases_are_database_errors_for_export() {
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
        for format in ["json", "dot"] {
            assert_database_error(with_db(&dir, db).args(["export", "--format", format]));
        }
    }
}

#[tokio::test]
async fn an_empty_database_is_an_error_not_an_empty_export() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("empty.db");
    Store::open(&db).await.expect("create empty schema");
    for format in ["json", "dot"] {
        assert_database_error(with_db(&dir, &db).args(["export", "--format", format]));
    }
}

// ---------------------------------------------------------------------------
// JSON export
// ---------------------------------------------------------------------------

#[tokio::test]
async fn json_export_is_complete_lossless_and_deterministic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = fixture(&dir).await;
    let store = Store::open(&fixture.db).await.expect("reopen fixture");
    let snapshot = store.export_snapshot().await.expect("store snapshot");

    let first = export_stdout(&dir, &fixture.db, "json");
    assert!(!first.is_empty(), "JSON export must not be empty");
    assert_eq!(
        first,
        export_stdout(&dir, &fixture.db, "json"),
        "repeated JSON export must be byte-identical"
    );

    let document: Value = serde_json::from_slice(&first).expect("JSON document");
    let keys: BTreeSet<&str> = document
        .as_object()
        .expect("JSON export must be an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "edges",
            "invocations",
            "metadata",
            "nodes",
            "plans",
            "roots"
        ]),
        "JSON export must carry exactly the full analysis"
    );

    // Losslessness: the document is the store's snapshot, and it parses back
    // into an equal snapshot.
    let expected = serde_json::to_value(&snapshot).expect("snapshot JSON");
    assert_eq!(
        document, expected,
        "export must serialize the complete snapshot"
    );
    let roundtrip: AnalysisSnapshot =
        serde_json::from_slice(&first).expect("JSON export must round-trip");
    assert_eq!(roundtrip, snapshot, "JSON round-trip equality");

    // Metadata identity and details.
    let metadata = &document["metadata"];
    assert_eq!(metadata["project_name"], "export-fixture");
    assert_eq!(metadata["project_version"], "2.3.4");
    assert_eq!(metadata["source_kind"], "path");
    assert_eq!(metadata["source_digest"], "sha256:export-fixture");
    assert_eq!(metadata["network_mode"], "offline");
    assert_eq!(metadata["sandbox_mode"], "native");
    assert_eq!(metadata["toolchain"]["cargo"], "1.93.1");
    assert_eq!(metadata["options"], json!({ "analysis_depth": 1 }));
    assert_eq!(
        metadata["configuration"],
        serde_json::to_value(Configuration::default()).expect("configuration JSON")
    );

    // Package nodes: full identities and per-node detail.
    assert_eq!(array(&document, "nodes").len(), 5);
    for id in [
        &fixture.root,
        &fixture.normal,
        &fixture.build,
        &fixture.idle,
        &fixture.odd,
    ] {
        assert_eq!(
            node_entry(&document, &id.name)["node"]["id"],
            serde_json::to_value(id).expect("package id JSON"),
            "node {} identity",
            id.name
        );
    }
    let root = node_entry(&document, ROOT);
    assert_eq!(root["node"]["status"], "Started");
    assert_eq!(root["node"]["path"], "crates/export-root");
    assert_eq!(root["node"]["active_features"], json!(["default", "extra"]));
    assert_eq!(root["node"]["targets"][0]["name"], "libexport");
    assert_eq!(
        root["node"]["targets"][0]["kind"]["SharedLibrary"]["soname"],
        "libexport.so.1"
    );
    assert_eq!(root["node"]["provides"][0]["name"], "export-virtual");
    assert_eq!(root["node"]["conflicts"][0]["name"], "export-legacy");
    assert_eq!(node_entry(&document, NORMAL)["node"]["status"], "Complete");
    assert_eq!(node_entry(&document, BUILD)["node"]["status"], "Complete");
    assert_eq!(node_entry(&document, IDLE)["node"]["status"], "Not_Started");
    assert_eq!(node_entry(&document, ODD)["node"]["status"], "Error");

    // Dependency edges, resolved and unresolved.
    let edges = array(&document, "edges");
    assert_eq!(edges.len(), 4);
    let resolved = edges
        .iter()
        .find(|edge| edge["edge"]["from"]["name"] == NORMAL && edge["edge"]["to"]["name"] == BUILD)
        .expect("resolved normal -> build edge");
    assert_eq!(resolved["edge"]["requirement"]["kind"], "crate");
    assert_eq!(resolved["edge"]["kinds"], json!(["normal"]));
    assert_eq!(resolved["edge"]["confidence"], 100);
    assert_eq!(resolved["edge"]["evidence"][0]["method"], "manifest");
    let unresolved = edges
        .iter()
        .find(|edge| edge["edge"]["to"].is_null())
        .expect("unresolved requirement must be exported");
    assert_eq!(unresolved["edge"]["from"]["name"], NORMAL);
    assert_eq!(unresolved["edge"]["requirement"]["kind"], "header");
    assert_eq!(unresolved["edge"]["requirement"]["name"], UNRESOLVED);

    // Roots.
    assert_eq!(
        document["roots"],
        json!([serde_json::to_value(&fixture.root).expect("root JSON")])
    );

    // Plans, including the recorded failure.
    let plans = array(&document, "plans");
    assert_eq!(plans.len(), 5);
    let detection = plans
        .iter()
        .find(|plan| plan["row"]["subject"]["root"].is_string())
        .expect("root detection plan");
    assert_eq!(detection["row"]["subject"]["root"], "");
    assert_eq!(detection["row"]["analyzer"], "cargo");
    assert_eq!(detection["row"]["strategy"], "manifest");
    assert_eq!(detection["row"]["status"], "Complete");
    let failed = plans
        .iter()
        .find(|plan| plan["row"]["error"].is_string())
        .expect("failed plan row");
    assert_eq!(failed["row"]["error"], FAILURE);
    assert_eq!(failed["row"]["status"], "Failed");
    assert_eq!(failed["row"]["subject"]["package"]["name"], ODD);

    // Tool invocations, attributed and unattributed.
    let invocations = array(&document, "invocations");
    assert_eq!(invocations.len(), 2);
    let probe = invocations
        .iter()
        .find(|entry| entry["invocation"]["tool"] == "rustc")
        .expect("toolchain probe invocation");
    assert!(probe["invocation"]["package_id"].is_null());
    let recorded = invocations
        .iter()
        .find(|entry| entry["invocation"]["tool"] == "cargo metadata")
        .expect("package invocation");
    assert_eq!(recorded["invocation"]["package_id"]["name"], ROOT);
    assert_eq!(
        recorded["invocation"]["argv"],
        json!(["cargo", "metadata", "--format-version", "1"])
    );
    assert_eq!(recorded["invocation"]["duration_ms"], 42);
    assert_eq!(
        recorded["invocation"]["log_path"],
        "logs/cargo-metadata.log"
    );
}

#[tokio::test]
async fn control_character_predicates_round_trip_through_export() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = fixture(&dir).await;
    let store = Store::open(&fixture.db).await.expect("open store");
    let mut dependency = unresolved_edge(&fixture.root, RequirementKind::Tool, "controls");
    dependency.predicate = Predicate::env("COLOR", "\u{1b}[31m\u{0}");
    store
        .upsert_edges(&fixture.root, &[dependency.clone()])
        .await
        .expect("write predicate");
    let encoded = export_stdout(&dir, &fixture.db, "json");
    let snapshot: AnalysisSnapshot = serde_json::from_slice(&encoded).expect("decode export");
    let analysis = snapshot.to_analysis().expect("reconstruct analysis");
    let found = analysis
        .graph
        .edges_from(&fixture.root)
        .into_iter()
        .find(|edge| edge.requirement.name == "controls")
        .expect("exported edge");
    assert_eq!(found.predicate, dependency.predicate);
}

#[tokio::test]
async fn export_and_check_reject_semantically_duplicate_edges() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = fixture(&dir).await;
    let connection = rusqlite::Connection::open(&fixture.db).expect("raw database");
    let root_id: i64 = connection
        .query_row("SELECT id FROM package WHERE name = ?1", [ROOT], |row| {
            row.get(0)
        })
        .expect("root id");
    for predicate in [
        "feature(\"a\") && feature(\"b\")",
        "feature(\"b\") && feature(\"a\")",
    ] {
        connection.execute(
            "INSERT INTO dependency_edge (from_package_id, requirement, requirement_kind, kinds, predicate, confidence, evidence) VALUES (?1, 'duplicate', 'crate', '[\"normal\"]', ?2, 50, '[]')",
            rusqlite::params![root_id, predicate],
        ).expect("insert duplicate edge");
    }
    drop(connection);
    for format in ["json", "dot"] {
        assert_database_error(with_db(&dir, &fixture.db).args(["export", "--format", format]));
    }
    let output = with_db(&dir, &fixture.db)
        .args(["check", "--format", "json"])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).expect("integrity report");
    assert_eq!(report["duplicate_edges"], 1);
}

// ---------------------------------------------------------------------------
// DOT export
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dot_export_is_a_valid_lossy_digraph_with_escaped_labels() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = fixture(&dir).await;

    let first = export_stdout(&dir, &fixture.db, "dot");
    assert!(!first.is_empty(), "DOT export must not be empty");
    assert_eq!(
        first,
        export_stdout(&dir, &fixture.db, "dot"),
        "repeated DOT export must be byte-identical"
    );

    let dot = std::str::from_utf8(&first).expect("DOT output is UTF-8");
    assert!(dot.trim_start().starts_with("digraph"), "DOT header: {dot}");
    assert!(dot.trim_end().ends_with('}'), "DOT footer: {dot}");

    let labels = dot_node_labels(dot);
    for name in [ROOT, NORMAL, BUILD, IDLE, ODD] {
        assert!(
            labels.iter().any(|(_, label)| label.contains(name)),
            "DOT is missing node {name}: {dot}"
        );
    }
    assert!(labels.len() >= 5, "every node must be declared: {dot}");

    let edges = dot_edges(dot);
    assert_eq!(
        edges.len(),
        4,
        "three resolved edges plus one unresolved edge: {dot}"
    );
    let root_id = dot_node_id(&labels, ROOT);
    let normal_id = dot_node_id(&labels, NORMAL);
    let build_id = dot_node_id(&labels, BUILD);
    let odd_id = dot_node_id(&labels, ODD);
    let expected = vec![
        (root_id.clone(), normal_id.clone()),
        (root_id, odd_id),
        (normal_id.clone(), build_id),
    ];
    for pair in &expected {
        assert!(
            edges.contains(pair),
            "DOT is missing resolved edge {pair:?}: {dot}"
        );
    }
    let extra = edges
        .iter()
        .find(|pair| !expected.contains(pair))
        .expect("DOT must show the unresolved requirement as an edge");
    assert_eq!(
        extra.0, normal_id,
        "the unresolved edge must originate at its source node: {dot}"
    );

    // Graphviz label escaping: quotes and backslashes in package and
    // requirement names must be escaped, and the requirement must be visible.
    assert!(
        dot.contains(r#"odd \"quoted\" \\ name"#),
        "node label is not escaped: {dot}"
    );
    assert!(
        dot.contains(r#"libmissing \"core\".h"#),
        "unresolved requirement is not escaped or missing: {dot}"
    );
}

// ---------------------------------------------------------------------------
// malformed stored data
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malformed_snapshot_rows_are_database_errors_without_partial_output() {
    for corruption in [
        "UPDATE metadata SET configuration = 'not-json'",
        "UPDATE package SET active_features = 'not-json'",
        "UPDATE tool_invocation SET argv = 'not-json'",
        "UPDATE package_target SET soname = 'inconsistent.so' WHERE soname = 'libexport.so.1'",
    ] {
        // A fresh fixture per corruption, so each row type is the first thing
        // that fails to load.
        let dir = tempfile::tempdir().expect("tempdir");
        let fixture = fixture(&dir).await;
        let connection = rusqlite::Connection::open(&fixture.db).expect("raw database");
        connection
            .execute(corruption, [])
            .expect("corrupt fixture row");
        drop(connection);
        for format in ["json", "dot"] {
            assert_database_error(with_db(&dir, &fixture.db).args(["export", "--format", format]));
        }
    }
}

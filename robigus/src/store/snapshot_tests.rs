use super::*;
use crate::model::{DebianOperator, EvidenceMethod, SourceLocation};
use semver::{Version, VersionReq};
use tempfile::TempDir;

async fn test_store() -> (Store, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("analysis.db")).await.unwrap();
    (store, dir)
}

fn metadata() -> AnalysisMetadata {
    let mut configuration = Configuration::default();
    configuration.features.insert(
        "project".into(),
        BTreeSet::from(["serde".into(), "unicode-λ".into()]),
    );
    configuration.build_profiles.insert("nocheck".into());
    configuration.env.insert("CC".into(), "clang".into());
    configuration.series = Some("noble".into());
    configuration
        .target_cfg
        .insert("target_env".into(), "gnu".into());
    AnalysisMetadata {
        robigus_version: "0.1.0".into(),
        project_name: "project".into(),
        project_version: "1.0.0".into(),
        source_kind: "git".into(),
        source_uri: "https://example.org/project".into(),
        source_digest: "deadbeef".into(),
        configuration,
        toolchain: BTreeMap::from([("cargo".into(), "1.93.1".into())]),
        network_mode: "offline".into(),
        sandbox_mode: "bwrap".into(),
        options: serde_json::json!({"jobs": 3, "nested": [true, null, "λ"]}),
        created_at: "2020-01-01T01:02:03Z".into(),
        updated_at: "2021-02-03T04:05:06Z".into(),
    }
}

fn git_package(name: &str) -> PackageId {
    PackageId {
        name: name.into(),
        version: PackageVersion::SemVer(Version::new(1, 2, 3)),
        ecosystem: Ecosystem::Rust,
        source_id: SourceId {
            kind: SourceKind::Git {
                url: Url::parse("https://example.org/repo").unwrap(),
                reference: GitReference::Branch("release/1.x".into()),
            },
            precise: Some("123456789abcdef".into()),
        },
    }
}

fn path_package(name: &str) -> PackageId {
    PackageId {
        name: name.into(),
        version: PackageVersion::SemVer(Version::new(1, 2, 3)),
        ecosystem: Ecosystem::Rust,
        source_id: SourceId {
            kind: SourceKind::Path {
                path: PathBuf::from("/workspace/dep"),
            },
            precise: None,
        },
    }
}

fn invocation(package_id: Option<PackageId>) -> ToolInvocation {
    ToolInvocation {
        package_id,
        tool: "cargo metadata".into(),
        argv: vec![
            "cargo".into(),
            "metadata".into(),
            "--format-version=1".into(),
        ],
        env: BTreeMap::from([("HOME".into(), "/tmp/space here".into())]),
        tool_version: Some("cargo 1.93.1".into()),
        sandbox_mode: "bwrap".into(),
        exit_status: "running".into(),
        started_at: "2024-10-11T12:13:14.123+00:00".into(),
        duration_ms: 0,
        log_path: Some("logs/metadata.log".into()),
    }
}

fn constraint_edge(from: &PackageId, name: &str, version_req: Option<VersionConstraint>) -> Edge {
    Edge {
        from: from.clone(),
        to: None,
        requirement: Requirement {
            kind: RequirementKind::Generic,
            name: name.into(),
            version_req,
        },
        kinds: BTreeSet::from([DependencyKind::Normal]),
        predicate: Predicate::TRUE,
        confidence: Confidence::new(50),
        evidence: Vec::new(),
    }
}

async fn assert_snapshot_unchanged(store: &Store, before: &AnalysisSnapshot) {
    assert_eq!(
        serde_json::to_value(store.export_snapshot().await.unwrap()).unwrap(),
        serde_json::to_value(before).unwrap()
    );
}

fn debian_package(name: &str, version: &str) -> PackageId {
    let mut id = path_package(name);
    id.ecosystem = Ecosystem::Ubuntu;
    id.version = PackageVersion::Debian(version.parse().unwrap());
    id
}

#[tokio::test]
async fn semantic_version_aliases_reject_api_writes_without_merging_payloads() {
    for (stored, alias) in [("1.02-1", "1.2-1"), ("1.0", "1.0-0")] {
        let (store, _dir) = test_store().await;
        store.write_metadata(&metadata()).await.unwrap();
        let mut original = Node::new(debian_package("libx", stored));
        original.path = Some("original".into());
        original.targets.push(Target {
            name: "original-bin".into(),
            kind: TargetKind::Binary,
            path: None,
        });
        original.provides.push(Provide {
            name: "original-provide".into(),
            version: None,
        });
        store.upsert_node(&original).await.unwrap();
        let before = store.export_snapshot().await.unwrap();
        let mut conflicting = Node::new(debian_package("libx", alias));
        assert_eq!(conflicting.id, original.id);
        conflicting.path = Some("must-not-replace-original".into());
        conflicting.active_features.insert("must-not-merge".into());
        assert!(
            matches!(store.upsert_node(&conflicting).await, Err(StoreError::Unrepresentable(message)) if message.contains(stored) && message.contains(alias))
        );
        assert_snapshot_unchanged(&store, &before).await;

        // Edge-created placeholders cannot bypass the spelling policy; even
        // packages/edges inserted earlier in the batch must be rolled back.
        let from = path_package("new-root");
        let mut first = constraint_edge(&from, "first", None);
        first.to = Some(path_package("new-placeholder"));
        let mut second = constraint_edge(&from, "alias", None);
        second.to = Some(conflicting.id);
        assert!(matches!(
            store.upsert_edges(&from, &[first, second]).await,
            Err(StoreError::Unrepresentable(_))
        ));
        assert_snapshot_unchanged(&store, &before).await;

        original.path = Some("updated-exact-spelling".into());
        store.upsert_node(&original).await.unwrap();
        let snapshot = store.export_snapshot().await.unwrap();
        assert_eq!(snapshot.nodes.len(), 1);
        assert_eq!(snapshot.nodes[0].node, original);
        assert_eq!(snapshot.to_analysis().unwrap().graph.node_count(), 1);
        assert_eq!(store.load().await.unwrap().graph.node_count(), 1);
        assert!(store.check().await.unwrap().is_ok());
    }
}

#[tokio::test]
async fn distinct_debian_versions_and_non_version_identities_are_accepted() {
    let (store, _dir) = test_store().await;
    store.write_metadata(&metadata()).await.unwrap();
    let base = debian_package("libx", "1.02-1");
    let mut ids = vec![
        base,
        debian_package("libx", "1.2-2"),
        debian_package("libx", "2:1.2-1"),
    ];
    let alias = debian_package("libx", "1.2-1");
    let mut other_name = alias.clone();
    other_name.name = "liby".into();
    let mut other_uri = alias.clone();
    other_uri.source_id.kind = SourceKind::Path {
        path: "/other/source".into(),
    };
    let mut other_precise = alias;
    other_precise.source_id.precise = Some("other-digest".into());
    ids.extend([other_name, other_uri, other_precise]);
    for id in &ids {
        store.upsert_node(&Node::new(id.clone())).await.unwrap();
    }
    let snapshot = store.export_snapshot().await.unwrap();
    assert_eq!(snapshot.nodes.len(), ids.len());
    assert_eq!(
        snapshot.to_analysis().unwrap().graph.node_count(),
        ids.len()
    );
    assert_eq!(store.load().await.unwrap().graph.node_count(), ids.len());
    let report = store.check().await.unwrap();
    assert_eq!(report.duplicate_identities, 0);
    assert!(report.is_ok());
}

fn insert_raw_debian(raw: &rusqlite::Connection, version: &str, path: &str) {
    raw.execute(
        "INSERT INTO package (name, version, ecosystem, source_kind, source_uri, path)
         VALUES ('libx', ?1, 'ubuntu', 'path', '/workspace/dep', ?2)",
        params![version, path],
    )
    .unwrap();
}

#[tokio::test]
async fn legacy_semantic_duplicates_fail_reads_and_integrity_without_data_loss() {
    let (store, dir) = test_store().await;
    store.write_metadata(&metadata()).await.unwrap();
    let raw = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
    insert_raw_debian(&raw, "1.02-1", "first-payload");
    insert_raw_debian(&raw, "1.2-2", "distinct-payload");
    assert_eq!(store.export_snapshot().await.unwrap().nodes.len(), 2);
    assert_eq!(store.load().await.unwrap().graph.node_count(), 2);
    assert!(store.check().await.unwrap().is_ok());
    insert_raw_debian(&raw, "1.2-1", "alias-payload");
    for result in [
        store.load().await.map(|_| ()),
        store.export_snapshot().await.map(|_| ()),
    ] {
        assert!(
            matches!(result, Err(StoreError::Corrupt(message)) if message.contains("duplicate package identity") && message.contains("rows"))
        );
    }
    let report = store.check().await.unwrap();
    assert_eq!(report.duplicate_identities, 1);
    assert!(!report.is_ok());
    let rows: Vec<(String, String)> = raw
        .prepare("SELECT version, path FROM package ORDER BY id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![
            ("1.02-1".into(), "first-payload".into()),
            ("1.2-2".into(), "distinct-payload".into()),
            ("1.2-1".into(), "alias-payload".into())
        ]
    );
}

#[tokio::test]
async fn integrity_counts_semantic_and_sql_duplicates_once_per_identity() {
    let (store, dir) = test_store().await;
    store.write_metadata(&metadata()).await.unwrap();
    let raw = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
    raw.execute_batch("DROP INDEX idx_package_identity")
        .unwrap();
    insert_raw_debian(&raw, "1.02-1", "first");
    insert_raw_debian(&raw, "1.02-1", "sql-duplicate");
    assert_eq!(store.check().await.unwrap().duplicate_identities, 1);
    insert_raw_debian(&raw, "1.2-1", "semantic-duplicate");
    insert_raw_debian(&raw, "1.2-1", "both-kinds-of-duplicate");
    assert_eq!(store.check().await.unwrap().duplicate_identities, 1);
    insert_raw_debian(&raw, "1.2-2", "distinct");
    assert_eq!(store.check().await.unwrap().duplicate_identities, 1);
    insert_raw_debian(&raw, "1.2-2", "second-duplicate-group");
    let report = store.check().await.unwrap();
    assert_eq!(report.duplicate_identities, 2);
    assert!(!report.is_ok());
    assert!(matches!(store.load().await, Err(StoreError::Corrupt(_))));
    assert!(matches!(
        store.export_snapshot().await,
        Err(StoreError::Corrupt(_))
    ));
}

#[tokio::test]
async fn concurrent_connections_cannot_insert_semantic_version_aliases() {
    for _ in 0..8 {
        let (first, dir) = test_store().await;
        first.write_metadata(&metadata()).await.unwrap();
        let second = Store::open(&dir.path().join("analysis.db")).await.unwrap();
        let mut a = Node::new(debian_package("libx", "1.02-1"));
        a.path = Some("first-writer".into());
        let mut b = Node::new(debian_package("libx", "1.2-1"));
        b.path = Some("second-writer".into());
        let (left, right) = tokio::join!(first.upsert_node(&a), second.upsert_node(&b));
        let expected = match (left, right) {
            (Ok(()), Err(StoreError::Unrepresentable(_))) => &a,
            (Err(StoreError::Unrepresentable(_)), Ok(())) => &b,
            results => panic!("expected one writer and one alias rejection, got {results:?}"),
        };
        let snapshot = first.export_snapshot().await.unwrap();
        assert_eq!(snapshot.nodes.len(), 1);
        assert_eq!(&snapshot.nodes[0].node, expected);
        assert_eq!(snapshot.to_analysis().unwrap().graph.node_count(), 1);
        assert!(second.check().await.unwrap().is_ok());
    }
}

#[tokio::test]
async fn lossless_constraint_variants_round_trip() {
    let (store, _dir) = test_store().await;
    store.write_metadata(&metadata()).await.unwrap();
    let id = path_package("constraints");
    let mut constraints = vec![
        None,
        Some(VersionConstraint::SemVer(VersionReq::STAR)),
        Some(VersionConstraint::SemVer(
            VersionReq::parse(">=1.2.3-alpha.1, <2.0").unwrap(),
        )),
    ];
    for op in [
        DebianOperator::Eq,
        DebianOperator::Lt,
        DebianOperator::Le,
        DebianOperator::Gt,
        DebianOperator::Ge,
    ] {
        constraints.push(Some(VersionConstraint::Debian {
            op,
            target_version: "2:1.02-1ubuntu1".into(),
        }));
    }
    let mut node = Node::new(id.clone());
    let mut edges = Vec::new();
    for (i, constraint) in constraints.into_iter().enumerate() {
        let name = format!("constraint-{i}");
        node.conflicts.push(Conflict {
            name: name.clone(),
            version_req: constraint.clone(),
        });
        edges.push(constraint_edge(&id, &name, constraint.clone()));
        let mut resolved = constraint_edge(&id, &name, constraint);
        resolved.to = Some(id.clone());
        edges.push(resolved);
    }
    store.upsert_node(&node).await.unwrap();
    store.upsert_edges(&id, &edges).await.unwrap();
    let snapshot = store.export_snapshot().await.unwrap();
    assert_eq!(snapshot.nodes[0].node, node);
    assert_eq!(
        snapshot
            .edges
            .iter()
            .map(|item| &item.edge)
            .collect::<Vec<_>>(),
        edges.iter().collect::<Vec<_>>()
    );
    let decoded: AnalysisSnapshot =
        serde_json::from_str(&crate::export::json(&snapshot).unwrap()).unwrap();
    assert_snapshot_unchanged(&store, &decoded).await;
    let analysis = decoded.to_analysis().unwrap();
    assert_eq!(analysis.graph.node(&id), Some(&node));
    assert_eq!(analysis.graph.edge_count(), edges.len());
}

#[tokio::test]
async fn lossy_constraints_reject_node_and_edge_writes_atomically() {
    let (store, _dir) = test_store().await;
    store.write_metadata(&metadata()).await.unwrap();
    let id = path_package("constraints");
    let node = Node::new(id.clone());
    store.upsert_node(&node).await.unwrap();
    let edge = constraint_edge(&id, "existing", None);
    store
        .upsert_edges(&id, std::slice::from_ref(&edge))
        .await
        .unwrap();
    let before = store.export_snapshot().await.unwrap();
    // This constructible SemVer value displays as 1.2.*, dropping patch 3.
    let mut lossy_semver = VersionReq::parse("1.2.3").unwrap();
    lossy_semver.comparators[0].op = semver::Op::Wildcard;
    for constraint in [
        VersionConstraint::Any,
        VersionConstraint::Debian {
            op: DebianOperator::Ge,
            target_version: String::new(),
        },
        VersionConstraint::SemVer(lossy_semver),
    ] {
        for package in [&id, &path_package("new-node")] {
            let mut bad = Node::new(package.clone());
            bad.active_features.insert("must-not-be-written".into());
            bad.conflicts.push(Conflict {
                name: "bad".into(),
                version_req: Some(constraint.clone()),
            });
            assert!(matches!(
                store.upsert_node(&bad).await,
                Err(StoreError::Unrepresentable(_))
            ));
            assert_snapshot_unchanged(&store, &before).await;
        }
        let mut changed = edge.clone();
        changed.confidence = Confidence::MAX;
        for to in [None, Some(path_package("must-not-create-placeholder"))] {
            let mut bad = constraint_edge(&id, "new-edge", Some(constraint.clone()));
            bad.to = to;
            assert!(matches!(
                store.upsert_edges(&id, &[changed.clone(), bad]).await,
                Err(StoreError::Unrepresentable(_))
            ));
            assert_snapshot_unchanged(&store, &before).await;
        }
    }
}

#[tokio::test]
async fn optional_paths_preserve_utf8_and_reject_empty_atomically() {
    let (store, _dir) = test_store().await;
    store.write_metadata(&metadata()).await.unwrap();
    let mut node = Node::new(path_package("paths"));
    node.path = Some("workspace/λ project".into());
    node.targets = vec![
        Target {
            name: "with-path".into(),
            kind: TargetKind::Binary,
            path: Some("src/λ.rs".into()),
        },
        Target {
            name: "without-path".into(),
            kind: TargetKind::Binary,
            path: None,
        },
    ];
    store.upsert_node(&node).await.unwrap();
    let before = store.export_snapshot().await.unwrap();
    assert_eq!(before.nodes[0].node, node);
    for target_path in [false, true] {
        let mut bad = node.clone();
        bad.active_features.insert("must-not-be-written".into());
        if target_path {
            bad.targets[0].path = Some(PathBuf::new());
        } else {
            bad.path = Some(PathBuf::new());
        }
        assert!(matches!(
            store.upsert_node(&bad).await,
            Err(StoreError::Unrepresentable(_))
        ));
        assert_snapshot_unchanged(&store, &before).await;
        bad.id = path_package("new-empty-path-node");
        assert!(matches!(
            store.upsert_node(&bad).await,
            Err(StoreError::Unrepresentable(_))
        ));
        assert_snapshot_unchanged(&store, &before).await;
    }
    node.path = None;
    store.upsert_node(&node).await.unwrap();
    assert_eq!(store.export_snapshot().await.unwrap().nodes[0].node, node);
}

#[cfg(unix)]
#[tokio::test]
async fn non_utf8_payload_paths_are_rejected_without_byte_replacement() {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let (store, _dir) = test_store().await;
    store.write_metadata(&metadata()).await.unwrap();
    let mut node = Node::new(path_package("paths"));
    node.path = Some("src/λ".into());
    node.targets.push(Target {
        name: "bin".into(),
        kind: TargetKind::Binary,
        path: node.path.clone(),
    });
    store.upsert_node(&node).await.unwrap();
    let before = store.export_snapshot().await.unwrap();
    assert_eq!(
        before.nodes[0]
            .node
            .path
            .as_ref()
            .unwrap()
            .as_os_str()
            .as_bytes(),
        node.path.as_ref().unwrap().as_os_str().as_bytes()
    );
    assert_eq!(
        before.nodes[0].node.targets[0]
            .path
            .as_ref()
            .unwrap()
            .as_os_str()
            .as_bytes(),
        node.targets[0]
            .path
            .as_ref()
            .unwrap()
            .as_os_str()
            .as_bytes()
    );
    let invalid = PathBuf::from(OsString::from_vec(b"src/\xff".to_vec()));
    for target_path in [false, true] {
        let mut bad = node.clone();
        if target_path {
            bad.targets[0].path = Some(invalid.clone());
        } else {
            bad.path = Some(invalid.clone());
        }
        assert!(matches!(
            store.upsert_node(&bad).await,
            Err(StoreError::Unrepresentable(_))
        ));
        assert_snapshot_unchanged(&store, &before).await;
        bad.id = path_package("new-path-node");
        assert!(matches!(
            store.upsert_node(&bad).await,
            Err(StoreError::Unrepresentable(_))
        ));
        assert_snapshot_unchanged(&store, &before).await;
    }
}

#[tokio::test]
async fn provide_versions_round_trip_or_reject_atomically() {
    let (store, _dir) = test_store().await;
    store.write_metadata(&metadata()).await.unwrap();
    for (ecosystem, version) in [
        (
            Ecosystem::Rust,
            PackageVersion::SemVer(Version::new(1, 2, 3)),
        ),
        (
            Ecosystem::Ubuntu,
            PackageVersion::Debian("2:1.02-1".parse().unwrap()),
        ),
        (
            Ecosystem::Generic,
            PackageVersion::Opaque("custom-version".into()),
        ),
    ] {
        let mut node = Node::new(path_package(ecosystem.as_str()));
        node.id.ecosystem = ecosystem;
        node.id.version = version.clone();
        node.provides = vec![
            Provide {
                name: "versioned".into(),
                version: Some(version),
            },
            Provide {
                name: "unversioned".into(),
                version: None,
            },
        ];
        store.upsert_node(&node).await.unwrap();
        let before = store.export_snapshot().await.unwrap();
        assert_eq!(
            before
                .nodes
                .iter()
                .find(|item| item.node.id == node.id)
                .unwrap()
                .node,
            node
        );
        let mismatched = match ecosystem {
            Ecosystem::Rust => PackageVersion::Opaque("1.2.3".into()),
            _ => PackageVersion::SemVer(Version::new(1, 2, 3)),
        };
        for version in [PackageVersion::Opaque(String::new()), mismatched] {
            let mut bad = node.clone();
            bad.provides[0].version = Some(version);
            bad.active_features.insert("must-not-be-written".into());
            assert!(matches!(
                store.upsert_node(&bad).await,
                Err(StoreError::Unrepresentable(_))
            ));
            assert_snapshot_unchanged(&store, &before).await;
            bad.id.name.push_str("-new");
            assert!(matches!(
                store.upsert_node(&bad).await,
                Err(StoreError::Unrepresentable(_))
            ));
            assert_snapshot_unchanged(&store, &before).await;
        }
    }
}

#[tokio::test]
async fn invocation_duration_boundaries_are_checked_before_mutation() {
    let (store, _dir) = test_store().await;
    store.write_metadata(&metadata()).await.unwrap();
    for duration in [0, i64::MAX as u64] {
        let mut value = invocation(None);
        value.duration_ms = duration;
        let id = store.begin_invocation(&value).await.unwrap();
        let snapshot = store.export_snapshot().await.unwrap();
        assert_eq!(
            snapshot
                .invocations
                .iter()
                .find(|item| item.id == id)
                .unwrap()
                .invocation,
            value
        );
        for overflow in [i64::MAX as u64 + 1, u64::MAX] {
            value.duration_ms = overflow;
            assert!(matches!(
                store.begin_invocation(&value).await,
                Err(StoreError::Unrepresentable(_))
            ));
            assert_snapshot_unchanged(&store, &snapshot).await;
            assert!(matches!(
                store.record_invocation(&value).await,
                Err(StoreError::Unrepresentable(_))
            ));
            assert_snapshot_unchanged(&store, &snapshot).await;
            assert!(matches!(
                store
                    .finish_invocation(id, "must-not-be-written", overflow)
                    .await,
                Err(StoreError::Unrepresentable(_))
            ));
            assert_snapshot_unchanged(&store, &snapshot).await;
        }
        for completed in [i64::MAX as u64, 0] {
            store.finish_invocation(id, "0", completed).await.unwrap();
            let snapshot = store.export_snapshot().await.unwrap();
            let item = &snapshot
                .invocations
                .iter()
                .find(|item| item.id == id)
                .unwrap()
                .invocation;
            assert_eq!(item.duration_ms, completed);
            assert_eq!(item.exit_status, "0");
        }
    }
}

fn nested_json_value(depth: usize) -> serde_json::Value {
    (0..depth).fold(serde_json::Value::Bool(true), |value, _| {
        serde_json::Value::Array(vec![value])
    })
}

fn nested_predicate(depth: usize) -> Predicate {
    (0..depth).fold(Predicate::feature("nested"), |predicate, level| {
        Predicate::Not(Box::new(Predicate::and(vec![
            predicate,
            Predicate::feature(format!("leaf-{level}")),
        ])))
    })
}

fn snapshot_with_metadata(metadata: AnalysisMetadata) -> AnalysisSnapshot {
    AnalysisSnapshot {
        metadata,
        nodes: Vec::new(),
        edges: Vec::new(),
        roots: Vec::new(),
        plans: Vec::new(),
        invocations: Vec::new(),
    }
}

fn first_snapshot_json_rejection(snapshot_at_depth: impl Fn(usize) -> AnalysisSnapshot) -> usize {
    (0..=256)
        .find(|&depth| crate::export::json(&snapshot_at_depth(depth)).is_err())
        .expect("default AnalysisSnapshot decoder must impose a nesting limit")
}

#[tokio::test]
async fn metadata_options_match_the_snapshot_json_decoder_boundary() {
    let (store, dir) = test_store().await;
    let first_rejected = first_snapshot_json_rejection(|depth| {
        let mut value = metadata();
        value.options = nested_json_value(depth);
        snapshot_with_metadata(value)
    });
    let deepest_accepted = first_rejected - 1;

    for depth in [0, 1, deepest_accepted] {
        let mut value = metadata();
        value.project_name = format!("options-depth-{depth}");
        value.options = nested_json_value(depth);
        store.write_metadata(&value).await.unwrap();
        let loaded = store.metadata().await.unwrap().unwrap();
        assert_eq!(loaded.project_name, value.project_name);
        assert_eq!(loaded.options, value.options);
    }
    let before = store.export_snapshot().await.unwrap();
    let encoded = crate::export::json(&before).unwrap();
    let decoded: AnalysisSnapshot = serde_json::from_str(&encoded).unwrap();
    assert_eq!(
        decoded.metadata.options,
        nested_json_value(deepest_accepted)
    );

    for depth in [first_rejected, 1024] {
        let mut invalid = metadata();
        invalid.project_name = format!("must-not-be-written-{depth}");
        invalid.options = nested_json_value(depth);
        assert!(
            matches!(store.write_metadata(&invalid).await, Err(StoreError::Unrepresentable(message)) if message.contains("metadata options") && (message.contains("AnalysisSnapshot JSON envelope") || message.contains("nesting preflight")))
        );
        assert_snapshot_unchanged(&store, &before).await;
    }

    // Legacy raw rows can be valid standalone JSON but too deep inside the
    // snapshot envelope. They must fail explicitly rather than export bad JSON.
    let raw = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
    let options = serde_json::to_string(&nested_json_value(first_rejected)).unwrap();
    raw.execute("UPDATE metadata SET options = ?1", [options])
        .unwrap();
    assert!(store.metadata().await.unwrap().is_some());
    assert!(
        matches!(store.export_snapshot().await, Err(StoreError::Corrupt(message)) if message.contains("AnalysisSnapshot JSON envelope"))
    );
}

#[tokio::test]
async fn edge_predicates_match_the_snapshot_json_decoder_boundary() {
    let (store, dir) = test_store().await;
    store.write_metadata(&metadata()).await.unwrap();
    let from = path_package("root");
    let first_rejected = first_snapshot_json_rejection(|depth| {
        let mut edge = constraint_edge(&from, "boundary", None);
        edge.predicate = nested_predicate(depth);
        AnalysisSnapshot {
            metadata: metadata(),
            nodes: Vec::new(),
            edges: vec![SnapshotEdge { id: 1, edge }],
            roots: Vec::new(),
            plans: Vec::new(),
            invocations: Vec::new(),
        }
    });
    let deepest_accepted = first_rejected - 1;

    let mut accepted = constraint_edge(&from, "boundary", None);
    accepted.predicate = nested_predicate(deepest_accepted);
    store
        .upsert_edges(&from, std::slice::from_ref(&accepted))
        .await
        .unwrap();
    let before = store.export_snapshot().await.unwrap();
    let encoded = crate::export::json(&before).unwrap();
    let decoded: AnalysisSnapshot = serde_json::from_str(&encoded).unwrap();
    assert_eq!(
        decoded.edges[0].edge.predicate,
        accepted.predicate.canonicalized()
    );

    for depth in [first_rejected, 1024] {
        let mut earlier = constraint_edge(&from, "must-roll-back", None);
        earlier.to = Some(path_package("must-roll-back-placeholder"));
        let mut invalid = constraint_edge(&from, "too-deep", None);
        invalid.predicate = nested_predicate(depth);
        invalid.to = Some(path_package("must-not-create-placeholder"));
        assert!(
            matches!(store.upsert_edges(&from, &[earlier, invalid]).await, Err(StoreError::Unrepresentable(message)) if message.contains("edge predicate") && (message.contains("AnalysisSnapshot JSON envelope") || message.contains("nesting preflight")))
        );
        assert_snapshot_unchanged(&store, &before).await;
    }

    let raw = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
    let package_row: i64 = raw
        .query_row("SELECT id FROM package WHERE name = 'root'", [], |row| {
            row.get(0)
        })
        .unwrap();
    let predicate = nested_predicate(first_rejected).canonical_text();
    raw.execute("INSERT INTO dependency_edge (from_package_id, requirement, requirement_kind, kinds, predicate, confidence, evidence) VALUES (?1, 'raw-too-deep', 'crate', '[\"normal\"]', ?2, 50, '[]')", params![package_row, predicate]).unwrap();
    assert!(
        matches!(store.export_snapshot().await, Err(StoreError::Corrupt(message)) if message.contains("AnalysisSnapshot JSON envelope"))
    );
}

#[tokio::test]
async fn complete_snapshot_round_trips_through_json() {
    let (store, dir) = test_store().await;
    let expected_metadata = metadata();
    store.write_metadata(&expected_metadata).await.unwrap();

    // Same name and version with different sources are distinct nodes.
    let root_id = git_package("shared-name");
    let dep_id = path_package("shared-name");
    let orphan_id = path_package("orphan");
    let mut root = Node::new(root_id.clone());
    root.path = Some(PathBuf::from("workspace/project"));
    root.active_features = BTreeSet::from(["serde".into(), "zstd".into()]);
    root.targets = vec![
        Target {
            name: "project".into(),
            kind: TargetKind::RustLib { proc_macro: true },
            path: Some(PathBuf::from("workspace/project/src/lib.rs")),
        },
        Target {
            name: "libproject".into(),
            kind: TargetKind::SharedLibrary {
                soname: Some("libproject.so.1".into()),
            },
            path: None,
        },
    ];
    root.provides = vec![Provide {
        name: "virtual-project".into(),
        version: Some(PackageVersion::SemVer(Version::new(1, 1, 0))),
    }];
    root.conflicts = vec![Conflict {
        name: "old-project".into(),
        version_req: Some(VersionConstraint::Debian {
            op: DebianOperator::Lt,
            target_version: "2:3.0-1".into(),
        }),
    }];
    let dep = Node::new(dep_id.clone());
    let orphan = Node::new(orphan_id.clone());
    for node in [&root, &dep, &orphan] {
        store.upsert_node(node).await.unwrap();
    }
    store.set_root(&root_id, true).await.unwrap();
    store.set_root(&dep_id, true).await.unwrap();

    let resolved = Edge {
        from: root_id.clone(),
        to: Some(dep_id.clone()),
        requirement: Requirement {
            kind: RequirementKind::Crate,
            name: "declared-dependency".into(),
            version_req: Some(VersionConstraint::SemVer(
                VersionReq::parse(">=1.0, <2.0").unwrap(),
            )),
        },
        kinds: BTreeSet::from([DependencyKind::Normal, DependencyKind::Build]),
        predicate: Predicate::and(vec![
            Predicate::feature("serde"),
            Predicate::cfg("target_os", "linux"),
        ])
        .canonicalized(),
        confidence: Confidence::new(92),
        evidence: vec![
            Evidence {
                method: EvidenceMethod::Manifest,
                confidence: Confidence::new(92),
                location: Some(SourceLocation {
                    path: PathBuf::from("Cargo.toml"),
                    start_line: Some(12),
                    end_line: Some(15),
                }),
                detail: Some("declared with features".into()),
            },
            Evidence {
                method: EvidenceMethod::ToolOutput,
                confidence: Confidence::new(85),
                location: None,
                detail: Some("observed".into()),
            },
        ],
    };
    let unresolved = Edge {
        from: root_id.clone(),
        to: None,
        requirement: Requirement {
            kind: RequirementKind::PkgConfig,
            name: "libssl".into(),
            version_req: Some(VersionConstraint::Debian {
                op: DebianOperator::Ge,
                target_version: "3.0".into(),
            }),
        },
        kinds: BTreeSet::from([DependencyKind::Runtime]),
        predicate: Predicate::feature("tls"),
        confidence: Confidence::new(75),
        evidence: vec![Evidence {
            method: EvidenceMethod::LlmSubAgent,
            confidence: Confidence::new(75),
            location: None,
            detail: Some("needs verification".into()),
        }],
    };
    store
        .upsert_edges(&root_id, &[resolved.clone(), unresolved.clone()])
        .await
        .unwrap();

    let detection = PlanRow::new(
        PlanSubject::Root(PathBuf::new()),
        AnalyzerId::Cpp,
        AnalysisStrategy::Manifest,
        Some(BuildSystem::Cmake),
        PlanStatus::Complete,
    );
    let mut expansion = PlanRow::new(
        PlanSubject::Package(root_id.clone()),
        AnalyzerId::Cargo,
        AnalysisStrategy::ToolIntrospection,
        Some(BuildSystem::BuildScript),
        PlanStatus::Failed,
    );
    expansion.attempts = 7;
    expansion.error = Some("exit 101".into());
    expansion.detail = Some("log: logs/metadata.log".into());
    store
        .upsert_plan_rows(&[detection.clone(), expansion.clone()])
        .await
        .unwrap();
    store
        .update_status(&root_id, AnalysisStatus::Started)
        .await
        .unwrap();
    root.status = AnalysisStatus::Started;

    let mut package_invocation = invocation(Some(root_id.clone()));
    let first_id = store.begin_invocation(&package_invocation).await.unwrap();
    store
        .finish_invocation(first_id, "exit:101", 2345)
        .await
        .unwrap();
    package_invocation.exit_status = "exit:101".into();
    package_invocation.duration_ms = 2345;
    let mut global_invocation = invocation(None);
    global_invocation.tool = "rustc --version".into();
    global_invocation.tool_version = None;
    global_invocation.log_path = None;
    global_invocation.env.clear();
    let second_id = store.begin_invocation(&global_invocation).await.unwrap();
    let duplicate_id = store.begin_invocation(&global_invocation).await.unwrap();

    // Pin timestamps to known values, and independently retrieve the row IDs.
    let raw = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
    raw.execute(
        "UPDATE metadata SET updated_at = ?1",
        [&expected_metadata.updated_at],
    )
    .unwrap();
    raw.execute("UPDATE analysis_plan SET updated_at = CASE WHEN root_path IS NULL THEN '2025-02-03T04:05:06Z' ELSE '2024-01-02T03:04:05Z' END", []).unwrap();
    let package_ids: Vec<i64> = raw
        .prepare("SELECT id FROM package ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let edge_ids: Vec<i64> = raw
        .prepare("SELECT id FROM dependency_edge ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let plan_ids: Vec<i64> = raw
        .prepare("SELECT id FROM analysis_plan ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(package_ids.len(), 3);
    assert_eq!(edge_ids.len(), 2);
    assert_eq!(plan_ids.len(), 2);

    let expected = AnalysisSnapshot {
        metadata: expected_metadata,
        nodes: vec![
            SnapshotNode {
                id: package_ids[0],
                node: root,
            },
            SnapshotNode {
                id: package_ids[1],
                node: dep,
            },
            SnapshotNode {
                id: package_ids[2],
                node: orphan,
            },
        ],
        edges: vec![
            SnapshotEdge {
                id: edge_ids[0],
                edge: resolved,
            },
            SnapshotEdge {
                id: edge_ids[1],
                edge: unresolved,
            },
        ],
        roots: vec![root_id.clone(), dep_id],
        plans: vec![
            SnapshotPlan {
                id: plan_ids[0],
                updated_at: "2024-01-02T03:04:05Z".into(),
                row: detection,
            },
            SnapshotPlan {
                id: plan_ids[1],
                updated_at: "2025-02-03T04:05:06Z".into(),
                row: expansion,
            },
        ],
        invocations: vec![
            SnapshotInvocation {
                id: first_id,
                invocation: package_invocation,
            },
            SnapshotInvocation {
                id: second_id,
                invocation: global_invocation.clone(),
            },
            SnapshotInvocation {
                id: duplicate_id,
                invocation: global_invocation,
            },
        ],
    };
    let snapshot = store.export_snapshot().await.unwrap();
    assert_eq!(snapshot, expected);
    // SourceId equality intentionally ignores a Git reference. Compare serialized
    // structure as well, so a dropped or changed reference cannot go unnoticed.
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    let json_path = dir.path().join("snapshot.json");
    serde_json::to_writer_pretty(std::fs::File::create(&json_path).unwrap(), &snapshot).unwrap();
    let decoded: AnalysisSnapshot =
        serde_json::from_reader(std::fs::File::open(&json_path).unwrap()).unwrap();
    assert_eq!(decoded, snapshot);
    assert_eq!(
        serde_json::to_value(&decoded).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );

    let loaded = store.load().await.unwrap();
    assert_eq!(loaded.metadata, snapshot.metadata);
    assert_eq!(loaded.graph.node_count(), snapshot.nodes.len());
    assert_eq!(loaded.graph.edge_count(), snapshot.edges.len());
    assert_eq!(loaded.graph.roots().len(), snapshot.roots.len());
    assert_eq!(loaded.graph.unresolved().len(), 1);
    let reconstructed = decoded.to_analysis().unwrap();
    assert_eq!(reconstructed.metadata, loaded.metadata);
    assert_eq!(reconstructed.graph.roots(), loaded.graph.roots());
    assert_eq!(
        serde_json::to_value(reconstructed.graph.roots()).unwrap(),
        serde_json::to_value(loaded.graph.roots()).unwrap()
    );
    for node in &snapshot.nodes {
        let id = &node.node.id;
        assert_eq!(loaded.graph.node(id), Some(&node.node));
        assert_eq!(reconstructed.graph.node(id), loaded.graph.node(id));
        assert_eq!(
            serde_json::to_value(reconstructed.graph.node(id)).unwrap(),
            serde_json::to_value(loaded.graph.node(id)).unwrap()
        );
        assert_eq!(
            serde_json::to_value(reconstructed.graph.edges_from(id)).unwrap(),
            serde_json::to_value(loaded.graph.edges_from(id)).unwrap()
        );
    }
    assert_eq!(reconstructed.graph.edge_count(), loaded.graph.edge_count());

    let mut bad = decoded.clone();
    bad.nodes.push(bad.nodes[0].clone());
    assert!(bad.to_analysis().is_err());
    let mut bad = decoded.clone();
    bad.roots.push(bad.roots[0].clone());
    assert!(bad.to_analysis().is_err());
    let mut bad = decoded.clone();
    bad.roots.push(path_package("missing"));
    assert!(bad.to_analysis().is_err());
    let mut bad = decoded.clone();
    bad.edges[0].edge.from = path_package("missing");
    assert!(bad.to_analysis().is_err());
    let mut bad = decoded.clone();
    bad.edges[0].edge.to = Some(path_package("missing"));
    assert!(bad.to_analysis().is_err());
    let mut bad = decoded.clone();
    bad.plans[1].row.subject = PlanSubject::Package(path_package("missing"));
    assert!(bad.to_analysis().is_err());
    let mut bad = decoded.clone();
    bad.invocations[0].invocation.package_id = Some(path_package("missing"));
    assert!(bad.to_analysis().is_err());
    let mut bad = decoded.clone();
    let mut duplicate = bad.edges[0].clone();
    duplicate.id += 100;
    bad.edges.push(duplicate);
    assert!(bad.to_analysis().is_err());
    let mut bad = decoded.clone();
    let mut duplicate = bad.edges[1].clone();
    duplicate.id += 100;
    bad.edges.push(duplicate);
    assert!(bad.to_analysis().is_err());
    let mut bad = decoded.clone();
    if let SourceKind::Git { reference, .. } = &mut bad.roots[0].source_id.kind {
        *reference = GitReference::Tag("different".into());
    }
    assert!(bad.to_analysis().is_err());
}

#[tokio::test]
async fn empty_snapshot_and_missing_metadata() {
    let (store, _dir) = test_store().await;
    assert!(
        matches!(store.export_snapshot().await, Err(StoreError::Corrupt(message)) if message.contains("metadata row missing"))
    );
    store.write_metadata(&metadata()).await.unwrap();
    let snapshot = store.export_snapshot().await.unwrap();
    assert!(snapshot.nodes.is_empty());
    assert!(snapshot.edges.is_empty());
    assert!(snapshot.roots.is_empty());
    assert!(snapshot.plans.is_empty());
    assert!(snapshot.invocations.is_empty());
    let json = serde_json::to_string(&snapshot).unwrap();
    assert_eq!(
        serde_json::from_str::<AnalysisSnapshot>(&json).unwrap(),
        snapshot
    );
}

#[tokio::test]
async fn export_rejects_invalid_or_dangling_records() {
    let (store, dir) = test_store().await;
    store.write_metadata(&metadata()).await.unwrap();
    store.record_invocation(&invocation(None)).await.unwrap();
    let raw = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
    raw.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
    for (column, invalid, valid) in [
        ("argv", "{}", "[]"),
        ("env", "[]", "{}"),
        ("argv", "not json", "[]"),
    ] {
        raw.execute(
            &format!("UPDATE tool_invocation SET {column} = ?1"),
            [invalid],
        )
        .unwrap();
        assert!(
            matches!(store.export_snapshot().await, Err(StoreError::Corrupt(_))),
            "{column}: {invalid}"
        );
        raw.execute(
            &format!("UPDATE tool_invocation SET {column} = ?1"),
            [valid],
        )
        .unwrap();
    }
    raw.execute("UPDATE tool_invocation SET duration_ms = -1", [])
        .unwrap();
    assert!(
        matches!(store.export_snapshot().await, Err(StoreError::Corrupt(message)) if message.contains("duration_ms"))
    );
    raw.execute(
        "UPDATE tool_invocation SET duration_ms = 0, package_id = 99999",
        [],
    )
    .unwrap();
    assert!(
        matches!(store.export_snapshot().await, Err(StoreError::Corrupt(message)) if message.contains("unknown package"))
    );
    raw.execute("UPDATE tool_invocation SET package_id = NULL", [])
        .unwrap();
    raw.execute("INSERT INTO analysis_plan (package_id, analyzer, strategy, status, updated_at) VALUES (99999, 'cargo', 'manifest', 'Pending', 'now')", []).unwrap();
    assert!(
        matches!(store.export_snapshot().await, Err(StoreError::Corrupt(message)) if message.contains("unknown package"))
    );
    raw.execute("DELETE FROM analysis_plan", []).unwrap();
    raw.execute("INSERT INTO analysis_plan (root_path, analyzer, strategy, status, updated_at) VALUES ('', 'not-an-analyzer', 'manifest', 'Pending', 'now')", []).unwrap();
    assert!(
        matches!(store.export_snapshot().await, Err(StoreError::Corrupt(message)) if message.contains("analyzer"))
    );
    raw.execute("DELETE FROM analysis_plan", []).unwrap();
    raw.execute("UPDATE metadata SET options = 'not json'", [])
        .unwrap();
    assert!(matches!(
        store.export_snapshot().await,
        Err(StoreError::Corrupt(_))
    ));
    raw.execute("UPDATE metadata SET options = '{}'", [])
        .unwrap();
    store
        .upsert_node(&Node::new(path_package("broken")))
        .await
        .unwrap();
    raw.execute("UPDATE package SET active_features = 'not json'", [])
        .unwrap();
    assert!(matches!(
        store.export_snapshot().await,
        Err(StoreError::Corrupt(_))
    ));
}

#[tokio::test]
async fn semantic_duplicate_persisted_edges_fail_load_and_export() {
    let (store, dir) = test_store().await;
    store.write_metadata(&metadata()).await.unwrap();
    let id = path_package("root");
    store.upsert_node(&Node::new(id.clone())).await.unwrap();
    let raw = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
    let package_row: i64 = raw
        .query_row("SELECT id FROM package", [], |row| row.get(0))
        .unwrap();
    // Both rows meet the SQLite unique index but have equivalent predicates.
    for predicate in [
        "feature(\"a\") && feature(\"b\")",
        "feature(\"b\") && feature(\"a\")",
    ] {
        raw.execute("INSERT INTO dependency_edge (from_package_id, requirement, requirement_kind, kinds, predicate, confidence, evidence) VALUES (?1, 'x', 'crate', '[\"normal\"]', ?2, 50, '[]')", params![package_row, predicate]).unwrap();
    }
    for result in [
        store.load().await.map(|_| ()),
        store.export_snapshot().await.map(|_| ()),
    ] {
        assert!(
            matches!(result, Err(StoreError::Corrupt(message)) if message.contains("snapshot edge") && message.contains("would merge"))
        );
    }
    let report = store.check().await.unwrap();
    assert_eq!(report.duplicate_edges, 1);
    assert!(!report.is_ok());
    let persisted: i64 = raw
        .query_row("SELECT COUNT(*) FROM dependency_edge", [], |row| row.get(0))
        .unwrap();
    assert_eq!(persisted, 2);
}

#[tokio::test]
async fn distinct_persisted_edges_reconstruct_through_load_and_json_export() {
    let (store, dir) = test_store().await;
    store.write_metadata(&metadata()).await.unwrap();
    let id = path_package("root");
    store.upsert_node(&Node::new(id.clone())).await.unwrap();
    let raw = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
    let package_row: i64 = raw
        .query_row("SELECT id FROM package", [], |row| row.get(0))
        .unwrap();
    for predicate in [
        "feature(\"a\") && feature(\"b\")",
        "feature(\"a\") && feature(\"c\")",
    ] {
        raw.execute("INSERT INTO dependency_edge (from_package_id, requirement, requirement_kind, kinds, predicate, confidence, evidence) VALUES (?1, 'x', 'crate', '[\"normal\"]', ?2, 50, '[]')", params![package_row, predicate]).unwrap();
    }

    let snapshot = store.export_snapshot().await.unwrap();
    assert_eq!(snapshot.edges.len(), 2);
    assert_ne!(snapshot.edges[0].id, snapshot.edges[1].id);
    assert_eq!(snapshot.to_analysis().unwrap().graph.edge_count(), 2);
    assert_eq!(store.load().await.unwrap().graph.edge_count(), 2);
    let report = store.check().await.unwrap();
    assert_eq!(report.duplicate_edges, 0);
    assert!(report.is_ok());

    let encoded = crate::export::json(&snapshot).unwrap();
    let decoded: AnalysisSnapshot = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, snapshot);
    assert_eq!(decoded.to_analysis().unwrap().graph.edge_count(), 2);
}

fn set_revision(conn: &mut rusqlite::Connection, revision: &str) {
    let tx = conn.transaction().unwrap();
    tx.execute("UPDATE metadata SET project_version = ?1", [revision])
        .unwrap();
    tx.execute("UPDATE package SET path = ?1", [revision])
        .unwrap();
    tx.execute("UPDATE analysis_plan SET detail = ?1", [revision])
        .unwrap();
    tx.execute("UPDATE tool_invocation SET exit_status = ?1", [revision])
        .unwrap();
    tx.commit().unwrap();
}

fn assert_revision(snapshot: &AnalysisSnapshot) {
    let revision = &snapshot.metadata.project_version;
    assert_eq!(snapshot.nodes.len(), 1);
    assert_eq!(
        snapshot.nodes[0].node.path.as_deref(),
        Some(Path::new(revision))
    );
    assert_eq!(snapshot.plans.len(), 1);
    assert_eq!(
        snapshot.plans[0].row.detail.as_deref(),
        Some(revision.as_str())
    );
    assert_eq!(snapshot.invocations.len(), 1);
    assert_eq!(&snapshot.invocations[0].invocation.exit_status, revision);
}

#[tokio::test]
async fn snapshot_reads_one_wal_revision_during_independent_writes() {
    let (store, dir) = test_store().await;
    let mut meta = metadata();
    meta.project_version = "before".into();
    store.write_metadata(&meta).await.unwrap();
    let id = path_package("root");
    let mut node = Node::new(id.clone());
    node.path = Some(PathBuf::from("before"));
    store.upsert_node(&node).await.unwrap();
    let mut plan = PlanRow::new(
        PlanSubject::Package(id.clone()),
        AnalyzerId::Cargo,
        AnalysisStrategy::Manifest,
        None,
        PlanStatus::Pending,
    );
    plan.detail = Some("before".into());
    store.upsert_plan_rows(&[plan]).await.unwrap();
    let mut run = invocation(Some(id));
    run.exit_status = "before".into();
    store.record_invocation(&run).await.unwrap();

    let mut writer = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
    // Pin the read transaction before committing a change on another connection.
    // The same readers used by export must still see the old revision afterwards.
    {
        let mut conn = lock(&store.conn).unwrap();
        let tx = conn.transaction().unwrap();
        assert_eq!(
            read_metadata(&tx).unwrap().unwrap().project_version,
            "before"
        );
        set_revision(&mut writer, "after");
        let (nodes, _, _) = read_graph_snapshot(&tx).unwrap();
        assert_eq!(nodes[0].node.path.as_deref(), Some(Path::new("before")));
        assert_eq!(
            read_snapshot_plans(&tx).unwrap()[0].row.detail.as_deref(),
            Some("before")
        );
        assert_eq!(
            read_snapshot_invocations(&tx).unwrap()[0]
                .invocation
                .exit_status,
            "before"
        );
        tx.commit().unwrap();
    }
    let after = store.export_snapshot().await.unwrap();
    assert_eq!(after.metadata.project_version, "after");
    assert_revision(&after);

    // Exercise the public method while a separate connection commits correlated
    // updates; no snapshot may combine fields from different revisions.
    let task = tokio::task::spawn_blocking(move || {
        for revision in 0..150 {
            set_revision(&mut writer, &revision.to_string());
            std::thread::yield_now();
        }
    });
    for _ in 0..150 {
        assert_revision(&store.export_snapshot().await.unwrap());
        tokio::task::yield_now().await;
    }
    task.await.unwrap();
    let final_snapshot = store.export_snapshot().await.unwrap();
    assert_revision(&final_snapshot);
    assert_eq!(final_snapshot.metadata.project_version, "149");
}

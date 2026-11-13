//! Lossless JSON snapshots and lossy dependency-graph visualizations.
//!
//! Renderers inspect only the supplied snapshot; they perform no filesystem,
//! environment, network, or tool queries.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use petgraph::{Graph, dot::Dot};

use crate::{
    error::StoreError,
    model::{PackageId, PlanSubject},
    store::{AnalysisSnapshot, snapshot_json_for_default_decoder},
};

/// Pretty-serialize the entire snapshot, followed by one newline.
///
/// All snapshot fields and vector ordering are preserved, including plans,
/// invocations, roots, and unresolved edges. This does not redact recorded data.
/// Deserializing the result into [`AnalysisSnapshot`] reconstructs the snapshot.
/// Returns an error when serde cannot represent a field in JSON, or when the
/// result exceeds `serde_json`'s default decoding recursion limit. The limit is
/// deliberately preserved; deeply nested options and predicate ASTs are not
/// supported by the lossless JSON format.
pub fn json(snapshot: &AnalysisSnapshot) -> Result<String, serde_json::Error> {
    let mut output = snapshot_json_for_default_decoder(snapshot, true)?;
    output.push('\n');
    Ok(output)
}

/// Render a **lossy** directed DOT visualization, including disconnected nodes,
/// roots, self-loops, parallel edges, and one synthetic node per unresolved edge.
///
/// Concrete nodes are identified by full [`PackageId`] identity, never by their
/// display labels. Numeric DOT IDs are assigned in package-identity order;
/// edges and synthetic nodes are ordered by persisted edge ID and serialized
/// payload, making output independent of snapshot vector ordering.
/// Labels show package identity/status and requirement/kinds/predicate/confidence,
/// but omit metadata, plans, invocations, targets, and evidence details. DOT is
/// not suitable for reconstructing an analysis. Petgraph escapes weight labels,
/// including quotes, backslashes, and newlines; other control characters are
/// rendered as visible escapes. No raw label attributes are used.
///
/// Returns [`StoreError::Corrupt`] for duplicate concrete identities or missing
/// package references (including roots, plans, and invocations). An empty graph
/// is rendered explicitly, not replaced with an empty string.
pub fn dot(snapshot: &AnalysisSnapshot) -> Result<String, StoreError> {
    let mut nodes = BTreeMap::new();
    for entry in &snapshot.nodes {
        if nodes.insert(&entry.node.id, &entry.node).is_some() {
            return Err(StoreError::Corrupt(format!(
                "duplicate DOT package identity: {}",
                entry.node.id
            )));
        }
    }
    let require = |id: &PackageId| -> Result<(), StoreError> {
        if nodes.contains_key(id) {
            Ok(())
        } else {
            Err(StoreError::Corrupt(format!(
                "DOT reference to missing package: {id}"
            )))
        }
    };
    for root in &snapshot.roots {
        require(root)?;
    }
    for plan in &snapshot.plans {
        if let PlanSubject::Package(id) = &plan.row.subject {
            require(id)?;
        }
    }
    for invocation in &snapshot.invocations {
        if let Some(id) = &invocation.invocation.package_id {
            require(id)?;
        }
    }
    let roots: BTreeSet<_> = snapshot.roots.iter().collect();
    let mut graph = Graph::<String, String>::new();
    let mut indices = BTreeMap::new();
    for (id, node) in nodes {
        let role = if roots.contains(id) {
            "root"
        } else {
            "package"
        };
        // Debug source formatting preserves disambiguating source information,
        // without querying any external state. Dot handles the final escaping.
        let label = format!(
            "{id}\n[{role}; {}]\nsource: {:?}",
            node.status, id.source_id
        );
        indices.insert(id, graph.add_node(dot_label(&label)));
    }
    let mut edges = snapshot
        .edges
        .iter()
        .map(|entry| serde_json::to_string(&entry.edge).map(|key| (entry.id, key, &entry.edge)))
        .collect::<Result<Vec<_>, _>>()?;
    edges.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    for (_, _, edge) in edges {
        let from = indices.get(&edge.from).copied().ok_or_else(|| {
            StoreError::Corrupt(format!("DOT edge references missing source: {}", edge.from))
        })?;
        let requirement = format!(
            "{}: {} ({})",
            edge.requirement.kind.as_str(),
            edge.requirement.name,
            edge.requirement.version_req.as_ref().map_or_else(
                || "unspecified".to_owned(),
                |version| version.requirement_text()
            )
        );
        let to = match &edge.to {
            Some(id) => indices.get(id).copied().ok_or_else(|| {
                StoreError::Corrupt(format!("DOT edge references missing target: {id}"))
            })?,
            None => graph.add_node(dot_label(&format!("unresolved requirement\n{requirement}"))),
        };
        graph.add_edge(
            from,
            to,
            dot_label(&format!(
                "{requirement}\nkinds: {:?}\n{}\nconfidence: {}",
                edge.kinds,
                edge.predicate.canonical_text(),
                edge.confidence
            )),
        );
    }
    Ok(format!("{}", Dot::new(&graph)))
}

// Graphviz label escaping in petgraph handles quotes, backslashes and newlines,
// but not other control characters. Display those visibly instead of emitting
// NULs or terminal controls into the DOT document.
fn dot_label(label: &str) -> String {
    let mut result = String::with_capacity(label.len());
    for c in label.chars() {
        match c {
            '\n' => result.push(c),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(result, "\\u{{{:x}}}", u32::from(c));
            }
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{
            Confidence, DependencyKind, Ecosystem, Edge, Node, PackageVersion, Requirement,
            RequirementKind, SourceId, SourceKind,
        },
        predicate::{Configuration, Predicate},
        store::{AnalysisMetadata, SnapshotEdge, SnapshotNode},
    };

    fn package(name: &str, path: &str) -> PackageId {
        PackageId {
            name: name.into(),
            version: PackageVersion::Opaque("1".into()),
            source_id: SourceId {
                kind: SourceKind::Path { path: path.into() },
                precise: None,
            },
            ecosystem: Ecosystem::Generic,
        }
    }

    fn fixture() -> AnalysisSnapshot {
        let root = package("same", "root");
        let orphan = package("same", "orphan");
        AnalysisSnapshot {
            metadata: AnalysisMetadata {
                robigus_version: "test".into(),
                project_name: "test".into(),
                project_version: "1".into(),
                source_kind: "path".into(),
                source_uri: "root".into(),
                source_digest: "digest".into(),
                configuration: Configuration::default(),
                toolchain: BTreeMap::new(),
                network_mode: "offline".into(),
                sandbox_mode: "native".into(),
                options: serde_json::json!({"nested": [null, "unaltered"]}),
                created_at: "created".into(),
                updated_at: "updated".into(),
            },
            nodes: vec![
                SnapshotNode {
                    id: 2,
                    node: Node::new(orphan),
                },
                SnapshotNode {
                    id: 1,
                    node: Node::new(root.clone()),
                },
            ],
            roots: vec![root],
            edges: vec![],
            plans: vec![],
            invocations: vec![],
        }
    }

    fn edge(snapshot: &AnalysisSnapshot, to: Option<PackageId>, name: &str) -> SnapshotEdge {
        SnapshotEdge {
            id: 1,
            edge: Edge {
                from: snapshot.roots[0].clone(),
                to,
                requirement: Requirement {
                    kind: RequirementKind::Generic,
                    name: name.into(),
                    version_req: None,
                },
                kinds: BTreeSet::from([DependencyKind::Runtime]),
                predicate: Predicate::TRUE,
                confidence: Confidence::MAX,
                evidence: vec![],
            },
        }
    }

    #[test]
    fn json_is_pretty_lossless_and_newline_terminated() {
        let snapshot = fixture();
        let output = json(&snapshot).unwrap();
        assert!(output.starts_with("{\n  \"metadata\""));
        assert!(output.ends_with("}\n"));
        let restored: AnalysisSnapshot = serde_json::from_str(&output).unwrap();
        assert_eq!(restored, snapshot);
        assert_eq!(
            serde_json::to_value(restored).unwrap(),
            serde_json::to_value(snapshot).unwrap()
        );
    }

    fn snapshot_with_predicate_depth(depth: usize) -> AnalysisSnapshot {
        let mut snapshot = fixture();
        let mut nested = edge(&snapshot, None, "nested predicate");
        nested.edge.predicate = (0..depth).fold(Predicate::TRUE, |predicate, _| {
            Predicate::Not(Box::new(predicate))
        });
        snapshot.edges.push(nested);
        snapshot
    }

    #[test]
    fn json_rejects_predicates_beyond_the_default_decoder_limit() {
        let normal = json(&snapshot_with_predicate_depth(2)).unwrap();
        serde_json::from_str::<AnalysisSnapshot>(&normal).unwrap();

        let first_rejected = (0..=256)
            .find(|&depth| json(&snapshot_with_predicate_depth(depth)).is_err())
            .expect("the default decoder must impose a nesting limit");
        assert!(first_rejected > 2);
        let boundary = json(&snapshot_with_predicate_depth(first_rejected - 1)).unwrap();
        serde_json::from_str::<AnalysisSnapshot>(&boundary).unwrap();
        let error = json(&snapshot_with_predicate_depth(first_rejected)).unwrap_err();
        assert!(error.to_string().contains("recursion limit"));

        let error = json(&snapshot_with_predicate_depth(1024)).unwrap_err();
        assert!(error.to_string().contains("nesting preflight"));
    }

    fn snapshot_with_options_depth(depth: usize) -> AnalysisSnapshot {
        let mut snapshot = fixture();
        snapshot.metadata.options = (0..depth).fold(serde_json::Value::Null, |value, _| {
            serde_json::Value::Array(vec![value])
        });
        snapshot
    }

    #[test]
    fn json_rejects_options_beyond_the_default_decoder_limit() {
        let first_rejected = (0..=256)
            .find(|&depth| json(&snapshot_with_options_depth(depth)).is_err())
            .expect("the default decoder must impose a nesting limit");
        assert!(first_rejected > 0);
        let boundary = json(&snapshot_with_options_depth(first_rejected - 1)).unwrap();
        serde_json::from_str::<AnalysisSnapshot>(&boundary).unwrap();
        let error = json(&snapshot_with_options_depth(first_rejected)).unwrap_err();
        assert!(error.to_string().contains("recursion limit"));

        let error = json(&snapshot_with_options_depth(1024)).unwrap_err();
        assert!(error.to_string().contains("nesting preflight"));
    }

    #[test]
    fn roots_orphans_and_duplicate_display_labels_are_distinct() {
        let snapshot = fixture();
        assert_eq!(
            snapshot.nodes[0].node.id.to_string(),
            snapshot.nodes[1].node.id.to_string()
        );
        let output = dot(&snapshot).unwrap();
        assert_eq!(output.matches("[ label =").count(), 2);
        assert!(output.contains("[root; Not_Started]"));
        assert!(output.contains("[package; Not_Started]"));
        assert!(output.contains("orphan"));
        let mut reversed = snapshot.clone();
        reversed.nodes.reverse();
        assert_eq!(output, dot(&reversed).unwrap());
    }

    #[test]
    fn unresolved_labels_are_escaped_once_and_each_gets_a_node() {
        let mut snapshot = fixture();
        let label = "quote\"slash\\line\nnext";
        snapshot.edges.push(edge(&snapshot, None, label));
        let mut second = snapshot.edges[0].clone();
        second.id = 2;
        snapshot.edges.push(second);
        let output = dot(&snapshot).unwrap();
        assert_eq!(output.matches("unresolved requirement").count(), 2);
        assert_eq!(output.matches(" -> ").count(), 2);
        assert!(output.contains("quote\\\"slash\\\\line\\lnext"));
        snapshot.edges.reverse();
        assert_eq!(output, dot(&snapshot).unwrap());
    }

    #[test]
    fn dot_renders_control_characters_without_raw_control_bytes() {
        let mut snapshot = fixture();
        let label = "quote\" literal \\N slash\\ cr\r tab\t nul\0 esc\x1b del\x7f";
        snapshot.nodes[0].node.id.name = label.into();
        snapshot.edges.push(edge(&snapshot, None, label));
        let output = dot(&snapshot).unwrap();
        assert!(!output.chars().any(|c| c.is_control() && c != '\n'));
        for expected in [
            "quote\\\"",
            "\\\\N",
            "\\\\r",
            "\\\\t",
            "\\\\u{0}",
            "\\\\u{1b}",
            "\\\\u{7f}",
        ] {
            assert!(
                output.contains(expected),
                "missing {expected:?} in {output:?}"
            );
        }
    }

    #[test]
    fn self_loops_and_parallel_edges_are_not_merged() {
        let mut snapshot = fixture();
        snapshot
            .edges
            .push(edge(&snapshot, Some(snapshot.roots[0].clone()), "self"));
        snapshot.edges.push(snapshot.edges[0].clone());
        let output = dot(&snapshot).unwrap();
        assert_eq!(output.matches(" -> ").count(), 2);
        assert!(output.contains("1 -> 1"));
    }

    #[test]
    fn broken_references_and_duplicate_identities_are_errors() {
        let mut snapshot = fixture();
        let missing = package("missing", "missing");
        snapshot
            .edges
            .push(edge(&snapshot, Some(missing.clone()), "broken"));
        assert!(matches!(dot(&snapshot), Err(StoreError::Corrupt(_))));
        snapshot.edges[0].edge.to = None;
        snapshot.edges[0].edge.from = missing.clone();
        assert!(matches!(dot(&snapshot), Err(StoreError::Corrupt(_))));
        snapshot.edges.clear();
        snapshot.roots.push(missing);
        assert!(matches!(dot(&snapshot), Err(StoreError::Corrupt(_))));
        snapshot.roots.pop();
        snapshot.nodes.push(snapshot.nodes[0].clone());
        assert!(matches!(dot(&snapshot), Err(StoreError::Corrupt(_))));
    }

    #[test]
    fn empty_snapshot_has_explicit_dot_document() {
        let mut snapshot = fixture();
        snapshot.nodes.clear();
        snapshot.roots.clear();
        assert_eq!(dot(&snapshot).unwrap(), "digraph {\n}\n");
    }
}

//! Filtered, cycle-safe dependency graph rendering.

use std::collections::{BTreeMap, BTreeSet, VecDeque, btree_map::Entry};
use std::fmt::Write;

use robigus::{
    AnalysisStatus, Confidence, DependencyGraph, DependencyKind, Edge, Evidence, PackageId,
    Predicate, Requirement,
};
use serde::Serialize;

/// Options for selecting the graph view.
#[derive(clap::Args, Debug, Default)]
pub struct PrintArgs {
    /// Show only edges of this kind: normal, build, development, or runtime.
    /// Kind alone does not hide nodes; depth is measured over matching edges.
    /// Predicates are shown, not evaluated.
    #[arg(long, value_parser = parse_kind)]
    pub kind: Option<DependencyKind>,

    /// Maximum shortest distance from a root (root = 0), over matching edges.
    /// Unreachable nodes are omitted; without a limit they are shown, including
    /// orphans. An unresolved requirement is one edge beyond its source;
    /// resolved edges between visible nodes are retained.
    #[arg(long)]
    pub depth: Option<usize>,

    /// Show only nodes with this status: not-started, started, complete, or
    /// error. Edges require visible endpoints; depth traversal ignores status.
    #[arg(long, value_parser = parse_status)]
    pub status: Option<AnalysisStatus>,
}

fn parse_kind(value: &str) -> Result<DependencyKind, String> {
    match value {
        "normal" => Ok(DependencyKind::Normal),
        "build" => Ok(DependencyKind::Build),
        "development" => Ok(DependencyKind::Development),
        "runtime" => Ok(DependencyKind::Runtime),
        _ => Err("expected one of: normal, build, development, runtime".into()),
    }
}

fn parse_status(value: &str) -> Result<AnalysisStatus, String> {
    match value {
        "not-started" => Ok(AnalysisStatus::NotStarted),
        "started" => Ok(AnalysisStatus::Started),
        "complete" => Ok(AnalysisStatus::Complete),
        "error" => Ok(AnalysisStatus::Error),
        _ => Err("expected one of: not-started, started, complete, error".into()),
    }
}

#[derive(Serialize)]
struct DisplayNode<'a> {
    id: &'a PackageId,
    status: AnalysisStatus,
    /// Shortest distance over matching kinds; `None` means unreachable.
    depth: Option<usize>,
    is_root: bool,
    /// No incoming resolved edge in the original graph and not a root.
    orphan: bool,
}

#[derive(Serialize)]
struct DisplayEdge<'a> {
    from: &'a PackageId,
    to: Option<&'a PackageId>,
    requirement: &'a Requirement,
    kinds: &'a BTreeSet<DependencyKind>,
    predicate: &'a Predicate,
    confidence: Confidence,
    evidence: Vec<&'a Evidence>,
}

#[derive(Serialize)]
struct GraphView<'a> {
    roots: Vec<&'a PackageId>,
    nodes: Vec<DisplayNode<'a>>,
    edges: Vec<DisplayEdge<'a>>,
}

/// Render a filtered graph as text or a structured JSON document.
///
/// Without a depth limit, all status-matching nodes are shown, including
/// orphans and disconnected components; their depth is `null`/`unreachable`
/// if they cannot be reached from a root over matching edges. With a limit,
/// only nodes within that shortest distance are shown. Status affects display,
/// not traversal. Resolved edges require both endpoints to be displayed;
/// unresolved requirements require a displayed source and, if depth is limited,
/// room for one more edge. Predicates are displayed but not evaluated.
/// Returns an error if JSON serialization fails.
pub fn render(
    graph: &DependencyGraph,
    args: &PrintArgs,
    json: bool,
) -> Result<String, serde_json::Error> {
    // Build adjacency once, including the graph's separate unresolved list.
    let matching_edges: Vec<&Edge> = graph
        .raw_graph()
        .edge_weights()
        .chain(graph.unresolved().iter())
        .filter(|edge| args.kind.is_none_or(|kind| edge.kinds.contains(&kind)))
        .collect();
    let mut outgoing: BTreeMap<&PackageId, Vec<&Edge>> = BTreeMap::new();
    for &edge in &matching_edges {
        outgoing.entry(&edge.from).or_default().push(edge);
    }

    // A multi-source BFS gives shortest distances even with cycles and multiple
    // parents. Traversal is independent of the status display filter.
    let mut depths: BTreeMap<&PackageId, usize> = BTreeMap::new();
    let mut queue = VecDeque::new();
    for root in graph.roots() {
        if graph.node(root).is_some() {
            depths.insert(root, 0);
            queue.push_back(root);
        }
    }
    while let Some(from) = queue.pop_front() {
        let depth = depths[from];
        if args.depth.is_some_and(|limit| depth >= limit) {
            continue;
        }
        if let Some(edges) = outgoing.get(from) {
            for &edge in edges {
                if let Some(to) = edge.to.as_ref()
                    && let Entry::Vacant(entry) = depths.entry(to)
                {
                    entry.insert(depth + 1);
                    queue.push_back(to);
                }
            }
        }
    }

    let nodes: Vec<_> = graph
        .nodes()
        .filter_map(|(id, node)| {
            let depth = depths.get(id).copied();
            if args.status.is_some_and(|status| node.status != status)
                || args
                    .depth
                    .is_some_and(|limit| depth.is_none_or(|d| d > limit))
            {
                return None;
            }
            let is_root = graph.roots().contains(id);
            Some(DisplayNode {
                id,
                status: node.status,
                depth,
                is_root,
                orphan: !is_root && graph.edges_to(id).is_empty(),
            })
        })
        .collect();
    let visible: BTreeSet<&PackageId> = nodes.iter().map(|node| node.id).collect();
    let roots = nodes
        .iter()
        .filter(|node| node.is_root)
        .map(|node| node.id)
        .collect();

    // Petgraph and the unresolved side list use insertion order. Sort by the
    // complete edge identity, including the distinction between no version
    // constraint and an explicit constraint, before producing either format.
    let mut sorted_edges = Vec::new();
    for edge in matching_edges {
        // Use the displayed node's identity in edge endpoints. Equivalent
        // PackageIds can carry different non-identity source metadata.
        let Some(&from) = visible.get(&edge.from) else {
            continue;
        };
        let to = match edge.to.as_ref() {
            Some(id) => {
                let Some(&id) = visible.get(id) else {
                    continue;
                };
                Some(id)
            }
            None => {
                if args
                    .depth
                    .is_some_and(|limit| depths.get(from).is_none_or(|depth| *depth >= limit))
                {
                    continue;
                }
                None
            }
        };
        let key = (
            from,
            to,
            edge.requirement.kind,
            &edge.requirement.name,
            serde_json::to_string(&edge.requirement.version_req)?,
            edge.predicate.canonical_text(),
        );
        // Evidence is merged in discovery order; normalize that order too.
        let mut evidence = edge
            .evidence
            .iter()
            .map(|item| serde_json::to_string(item).map(|key| (key, item)))
            .collect::<Result<Vec<_>, _>>()?;
        evidence.sort_by(|a, b| a.0.cmp(&b.0));
        sorted_edges.push((
            key,
            DisplayEdge {
                from,
                to,
                requirement: &edge.requirement,
                kinds: &edge.kinds,
                predicate: &edge.predicate,
                confidence: edge.confidence,
                evidence: evidence.into_iter().map(|(_, item)| item).collect(),
            },
        ));
    }
    sorted_edges.sort_by(|a, b| a.0.cmp(&b.0));
    let edges = sorted_edges.into_iter().map(|(_, edge)| edge).collect();
    let view = GraphView {
        roots,
        nodes,
        edges,
    };

    if json {
        serde_json::to_string_pretty(&view)
    } else {
        Ok(render_text(&view))
    }
}

fn render_text(view: &GraphView<'_>) -> String {
    let mut output = String::new();
    let numbers: BTreeMap<&PackageId, usize> = view
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.id, index + 1))
        .collect();

    let _ = writeln!(output, "Roots:");
    if view.roots.is_empty() {
        let _ = writeln!(output, "  (none visible)");
    }
    for id in &view.roots {
        let _ = writeln!(output, "  [{}] {id}", numbers[id]);
    }

    let _ = writeln!(output, "Nodes:");
    if view.nodes.is_empty() {
        let _ = writeln!(output, "  (none visible)");
    }
    for node in &view.nodes {
        let depth = node
            .depth
            .map_or_else(|| "unreachable".into(), |d| d.to_string());
        let _ = writeln!(
            output,
            "  [{}] {} status={} depth={}{}{} source={:?} precise={:?}",
            numbers[node.id],
            node.id,
            node.status,
            depth,
            if node.is_root { " root" } else { "" },
            if node.orphan { " orphan" } else { "" },
            node.id.source_id.kind,
            node.id.source_id.effective_precise(),
        );
    }

    let _ = writeln!(output, "Edges:");
    if view.edges.is_empty() {
        let _ = writeln!(output, "  (none visible)");
    }
    for edge in &view.edges {
        let destination = edge.to.as_ref().map_or_else(
            || "unresolved".to_string(),
            |to| format!("[{}]", numbers[to]),
        );
        let kinds = edge
            .kinds
            .iter()
            .map(|kind| match kind {
                DependencyKind::Normal => "normal",
                DependencyKind::Build => "build",
                DependencyKind::Development => "development",
                DependencyKind::Runtime => "runtime",
            })
            .collect::<Vec<_>>()
            .join(",");
        let version = edge.requirement.version_req.as_ref().map(|constraint| {
            let text = constraint.requirement_text();
            if text.is_empty() {
                "*".to_string()
            } else {
                text
            }
        });
        let _ = writeln!(
            output,
            "  [{}] -> {} requirement={}:{:?} version={:?} kinds=[{}] predicate={} confidence={}",
            numbers[edge.from],
            destination,
            edge.requirement.kind.as_str(),
            edge.requirement.name,
            version,
            kinds,
            edge.predicate,
            edge.confidence,
        );
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};
    use robigus::{
        EvidenceMethod, Node, RequirementKind, SourceId, SourceKind,
        model::{Ecosystem, GitReference, PackageVersion},
    };
    use serde_json::Value;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        print: PrintArgs,
    }

    fn id(name: &str) -> PackageId {
        PackageId {
            name: name.into(),
            version: PackageVersion::Opaque("1".into()),
            ecosystem: Ecosystem::Generic,
            source_id: SourceId {
                kind: SourceKind::Path { path: name.into() },
                precise: None,
            },
        }
    }

    fn edge(from: &str, to: Option<&str>, name: &str, kinds: &[DependencyKind]) -> Edge {
        Edge {
            from: id(from),
            to: to.map(id),
            requirement: Requirement {
                kind: RequirementKind::Generic,
                name: name.into(),
                version_req: None,
            },
            kinds: kinds.iter().copied().collect(),
            predicate: Predicate::TRUE,
            confidence: Confidence::MAX,
            evidence: Vec::new(),
        }
    }

    fn fixture(reverse: bool) -> DependencyGraph {
        use DependencyKind::{Build, Normal};
        let mut graph = DependencyGraph::new();
        for (name, status) in [
            ("hidden-root", AnalysisStatus::Started),
            ("hidden-mid", AnalysisStatus::NotStarted),
            ("visible-leaf", AnalysisStatus::Complete),
            ("orphan", AnalysisStatus::Complete),
            ("disconnected-a", AnalysisStatus::Error),
            ("disconnected-b", AnalysisStatus::Error),
        ] {
            let mut node = Node::new(id(name));
            node.status = status;
            graph.add_node(node);
        }
        graph.add_root(id("hidden-root"));
        let mut edges = vec![
            edge("hidden-root", Some("hidden-mid"), "middle", &[Normal]),
            edge("hidden-mid", Some("visible-leaf"), "via-middle", &[Normal]),
            edge("hidden-root", Some("visible-leaf"), "via-build", &[Build]),
            edge("visible-leaf", Some("hidden-mid"), "back", &[Normal]),
            edge(
                "visible-leaf",
                Some("visible-leaf"),
                "self",
                &[Normal, Build],
            ),
            edge("hidden-root", None, "missing-root", &[Normal]),
            edge("hidden-mid", None, "missing-middle", &[Normal]),
            edge("visible-leaf", None, "missing-leaf", &[Normal]),
            edge(
                "disconnected-a",
                Some("disconnected-b"),
                "disc-b",
                &[Normal],
            ),
            edge(
                "disconnected-b",
                Some("disconnected-a"),
                "disc-a",
                &[Normal],
            ),
        ];
        // Merging the same edge in opposite discovery orders changes the
        // underlying evidence order, but must not change the rendered view.
        for detail in ["first", "second"] {
            let mut discovered = edge("hidden-root", Some("hidden-mid"), "middle", &[Normal]);
            discovered.evidence.push(Evidence {
                method: EvidenceMethod::Manifest,
                confidence: Confidence::new(80),
                location: None,
                detail: Some(detail.into()),
            });
            edges.push(discovered);
        }
        if reverse {
            edges.reverse();
        }
        for edge in edges {
            graph.add_edge(edge);
        }
        graph
    }

    fn document(graph: &DependencyGraph, args: &PrintArgs) -> Value {
        serde_json::from_str(&render(graph, args, true).unwrap()).unwrap()
    }

    fn nodes(document: &Value) -> Vec<&str> {
        document["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|node| node["id"]["name"].as_str().unwrap())
            .collect()
    }

    fn requirements(document: &Value) -> Vec<&str> {
        document["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge["requirement"]["name"].as_str().unwrap())
            .collect()
    }

    fn node<'a>(document: &'a Value, name: &str) -> &'a Value {
        document["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["id"]["name"] == name)
            .unwrap()
    }

    #[test]
    fn depth_uses_shortest_paths_over_matching_edges() {
        let graph = fixture(false);
        let args = PrintArgs {
            kind: Some(DependencyKind::Normal),
            depth: Some(1),
            ..Default::default()
        };
        let doc = document(&graph, &args);
        assert_eq!(nodes(&doc), vec!["hidden-mid", "hidden-root"]);
        assert_eq!(node(&doc, "hidden-root")["depth"], 0);
        assert_eq!(node(&doc, "hidden-mid")["depth"], 1);
        assert_eq!(requirements(&doc), vec!["missing-root", "middle"]);
        assert!(
            doc["edges"]
                .as_array()
                .unwrap()
                .iter()
                .any(|edge| edge["to"].is_null())
        );

        let doc = document(
            &graph,
            &PrintArgs {
                depth: Some(1),
                ..Default::default()
            },
        );
        assert_eq!(node(&doc, "visible-leaf")["depth"], 1);
        // All edges between visible nodes survive, including cross edges and
        // the self-loop at the depth boundary, not just BFS tree edges.
        for name in [
            "middle",
            "via-build",
            "via-middle",
            "back",
            "self",
            "missing-root",
        ] {
            assert!(requirements(&doc).contains(&name), "missing {name}");
        }
        assert!(!requirements(&doc).contains(&"missing-middle"));
        assert!(!requirements(&doc).contains(&"missing-leaf"));
    }

    #[test]
    fn status_filters_only_the_view_without_leaking_hidden_endpoints() {
        let graph = fixture(false);
        let args = PrintArgs {
            kind: Some(DependencyKind::Normal),
            depth: Some(2),
            status: Some(AnalysisStatus::Complete),
        };
        let json = render(&graph, &args, true).unwrap();
        let doc: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(nodes(&doc), vec!["visible-leaf"]);
        assert!(doc["roots"].as_array().unwrap().is_empty());
        assert_eq!(node(&doc, "visible-leaf")["depth"], 2);
        assert_eq!(requirements(&doc), vec!["self"]);
        for output in [json, render(&graph, &args, false).unwrap()] {
            assert!(!output.contains("hidden-root"));
            assert!(!output.contains("hidden-mid"));
            assert!(!output.contains("missing-leaf"));
        }
    }

    #[test]
    fn no_depth_shows_orphans_and_disconnected_cycles() {
        let graph = fixture(false);
        let args = PrintArgs {
            kind: Some(DependencyKind::Normal),
            ..Default::default()
        };
        let doc = document(&graph, &args);
        assert_eq!(nodes(&doc).len(), 6);
        assert_eq!(node(&doc, "visible-leaf")["depth"], 2);
        assert!(node(&doc, "orphan")["depth"].is_null());
        assert_eq!(node(&doc, "orphan")["orphan"], true);
        assert!(node(&doc, "disconnected-a")["depth"].is_null());
        assert_eq!(node(&doc, "disconnected-a")["orphan"], false);
        for name in [
            "missing-root",
            "missing-middle",
            "missing-leaf",
            "disc-a",
            "disc-b",
        ] {
            assert!(requirements(&doc).contains(&name), "missing {name}");
        }
        assert!(!requirements(&doc).contains(&"via-build"));
        let text = render(&graph, &args, false).unwrap();
        assert!(text.contains("unreachable orphan"));
        assert!(text.contains("unresolved"));
    }

    #[test]
    fn multiple_roots_zero_depth_and_kind_sets() {
        let mut graph = fixture(false);
        graph.add_root(id("visible-leaf"));
        let doc = document(
            &graph,
            &PrintArgs {
                kind: Some(DependencyKind::Build),
                depth: Some(0),
                ..Default::default()
            },
        );
        assert_eq!(nodes(&doc), vec!["hidden-root", "visible-leaf"]);
        assert_eq!(doc["roots"].as_array().unwrap().len(), 2);
        assert_eq!(node(&doc, "visible-leaf")["depth"], 0);
        assert_eq!(requirements(&doc), vec!["via-build", "self"]);
    }

    #[test]
    fn no_roots_and_missing_root_nodes_are_handled() {
        let mut graph = DependencyGraph::new();
        graph.add_node(Node::new(id("alone")));
        graph.add_root(id("missing"));
        let doc = document(&graph, &PrintArgs::default());
        assert_eq!(nodes(&doc), vec!["alone"]);
        assert!(doc["roots"].as_array().unwrap().is_empty());
        assert_eq!(node(&doc, "alone")["orphan"], true);
        assert!(node(&doc, "alone")["depth"].is_null());
        let doc = document(
            &graph,
            &PrintArgs {
                depth: Some(0),
                ..Default::default()
            },
        );
        assert!(nodes(&doc).is_empty());
    }

    #[test]
    fn edge_endpoints_use_the_displayed_node_identity() {
        let mut canonical = id("git-package");
        canonical.source_id = SourceId {
            kind: SourceKind::Git {
                url: "https://example.com/repository".parse().unwrap(),
                reference: GitReference::Branch("main".into()),
            },
            precise: Some("commit".into()),
        };
        let mut alternate = canonical.clone();
        if let SourceKind::Git { reference, .. } = &mut alternate.source_id.kind {
            *reference = GitReference::Tag("release".into());
        }
        assert_eq!(canonical, alternate);

        let mut graph = DependencyGraph::new();
        graph.add_node(Node::new(canonical.clone()));
        graph.add_root(canonical);
        let mut link = edge("unused", None, "self", &[DependencyKind::Normal]);
        link.from = alternate.clone();
        link.to = Some(alternate);
        graph.add_edge(link);
        let doc = document(&graph, &PrintArgs::default());
        assert_eq!(doc["nodes"][0]["id"], doc["edges"][0]["from"]);
        assert_eq!(doc["nodes"][0]["id"], doc["edges"][0]["to"]);
    }

    #[test]
    fn output_is_independent_of_edge_insertion_order() {
        let first = fixture(false);
        let second = fixture(true);
        for json in [false, true] {
            assert_eq!(
                render(&first, &PrintArgs::default(), json).unwrap(),
                render(&second, &PrintArgs::default(), json).unwrap()
            );
        }
    }

    #[test]
    fn clap_validates_filters_and_describes_their_semantics() {
        for (kind, expected) in [
            ("normal", DependencyKind::Normal),
            ("build", DependencyKind::Build),
            ("development", DependencyKind::Development),
            ("runtime", DependencyKind::Runtime),
        ] {
            let parsed = TestCli::try_parse_from(["print", "--kind", kind]).unwrap();
            assert_eq!(parsed.print.kind, Some(expected));
        }
        for (status, expected) in [
            ("not-started", AnalysisStatus::NotStarted),
            ("started", AnalysisStatus::Started),
            ("complete", AnalysisStatus::Complete),
            ("error", AnalysisStatus::Error),
        ] {
            let parsed =
                TestCli::try_parse_from(["print", "--status", status, "--depth", "0"]).unwrap();
            assert_eq!(parsed.print.status, Some(expected));
            assert_eq!(parsed.print.depth, Some(0));
        }
        assert!(TestCli::try_parse_from(["print", "--kind", "other"]).is_err());
        assert!(TestCli::try_parse_from(["print", "--status", "Not_Started"]).is_err());
        assert!(TestCli::try_parse_from(["print", "--depth", "-1"]).is_err());
        let help = TestCli::command().render_long_help().to_string();
        let help = help.split_whitespace().collect::<Vec<_>>().join(" ");
        for word in [
            "matching edges",
            "unresolved",
            "traversal ignores status",
            "orphans",
        ] {
            assert!(help.contains(word), "missing {word} in {help}");
        }
    }
}

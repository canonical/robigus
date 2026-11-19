//! Ecosystem analyzers (spec §7.5, §8): what an analyzer receives
//! ([`AnalysisContext`]) and what it reports ([`AnalyzerOutput`]).
//!
//! Analyzers report; they do not drive expansion or change node status.
//! [`AnalyzerOutput::persist`] writes a result to the store, and expansion
//! (WP-2.3) decides each node's status from the plan rows: a
//! [`PlanStatus::Failed`] row with a recorded error is the cause recorded
//! for an `Error` node (spec §5.1, §22.19).

pub mod cargo;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

pub use cargo::{BuildScriptFinding, scan_build_script};

use crate::credentials::CredentialSource;
use crate::error::StoreError;
use crate::fetch::{FetchedSource, RegistrySource, SourceInput};
use crate::model::{
    DependencyGraph, Edge, Evidence, GitReference, Node, PackageId, PackageVersion, PlanRow,
    SourceKind,
};
use crate::predicate::Configuration;
use crate::registry::{CRATES_IO_INDEX, RegistrySpec};
use crate::sandbox::{NetworkAccess, Sandbox};
use crate::store::Store;

/// Bounds on one analyzer run. The defaults cover large workspaces while
/// keeping a hostile tree from exhausting memory or time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalyzerLimits {
    /// Wall-clock limit for each sandboxed tool run (default 900 seconds;
    /// `cargo metadata` may download the whole registry index for the
    /// graph).
    pub tool_timeout: Duration,
    /// Largest tool output read back, in bytes (default 128 MiB).
    pub max_tool_output: u64,
    /// Largest manifest, lockfile or build script parsed, in bytes
    /// (default 1 MiB, matching detection).
    pub max_file_bytes: u64,
    /// Most in-tree manifests read for one root (default 10,000).
    pub max_manifests: usize,
}

impl Default for AnalyzerLimits {
    fn default() -> Self {
        Self {
            tool_timeout: Duration::from_secs(900),
            max_tool_output: 128 * 1024 * 1024,
            max_file_bytes: 1024 * 1024,
            max_manifests: 10_000,
        }
    }
}

/// Everything an analyzer needs to analyze one detected root (spec §7.5).
pub struct AnalysisContext<'a> {
    /// The fetched source. Every in-tree package is identified by its
    /// [`FetchedSource::source_id`] plus its name and version.
    pub source: &'a FetchedSource,
    /// The root directory to analyze, relative to [`FetchedSource::tree`]
    /// (empty for the top level), as reported by detection.
    pub root: &'a Path,
    /// The primary configuration. For Cargo, its per-package features are
    /// requested for workspace members, on top of their defaults.
    pub configuration: &'a Configuration,
    /// [`NetworkAccess::Offline`] selects static manifest analysis (spec
    /// §8.1, `--offline`); [`NetworkAccess::Allowlist`] runs tools in the
    /// sandbox behind the allowlisting proxy.
    pub network: &'a NetworkAccess,
    /// The sandbox tools run in. Required for tool introspection; offline
    /// analysis executes nothing and needs none.
    pub sandbox: Option<&'a dyn Sandbox>,
    /// Where tool invocations are recorded (spec §11, `tool_invocation`).
    pub store: &'a Store,
    /// Existing host directory, outside the source tree, for tool logs.
    pub workspace: &'a Path,
    /// Resource bounds.
    pub limits: AnalyzerLimits,
}

impl fmt::Debug for AnalysisContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnalysisContext")
            .field("source", &self.source)
            .field("root", &self.root)
            .field("configuration", &self.configuration)
            .field("network", &self.network)
            .field("sandbox", &self.sandbox.map(|sandbox| sandbox.mode()))
            .field("store", &self.store)
            .field("workspace", &self.workspace)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Whether an analysis used allowlisted network access or none, recorded
/// as `network_mode` in the metadata (spec §8.1, §11.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Tools ran with egress through the allowlisting proxy.
    #[default]
    Allowlist,
    /// No network: static analysis only.
    Offline,
}

impl NetworkMode {
    /// The stored form: `allowlist` or `offline`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowlist => "allowlist",
            Self::Offline => "offline",
        }
    }
}

/// A problem that did not stop the analysis but may make its result
/// incomplete, attached to a tree-relative path (empty for the whole root).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct AnalyzerDiagnostic {
    /// Tree-relative path the problem concerns.
    pub path: PathBuf,
    /// What happened.
    pub message: String,
}

/// A discovered package whose sources are not in the analyzed tree and
/// must be fetched before it can be analyzed further (for example for its
/// build script). See [`ExpansionTask::source_input`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ExpansionTask {
    /// The package to expand.
    pub package: PackageId,
}

impl ExpansionTask {
    /// How to fetch the package, pinned exactly as Cargo locked it: a
    /// registry crate by name, version and `.crate` checksum (yanked
    /// versions allowed, since Cargo uses a locked yanked version), or a git
    /// repository at the locked commit. A git repository may hold several
    /// packages, so the caller still has to locate this one in the checkout.
    ///
    /// Crates from registries other than crates.io get no credential
    /// source; the caller maps the index URL to a configured registry when
    /// one needs authentication. `None` for sources that need no fetch or
    /// are not pinned.
    pub fn source_input(&self) -> Option<SourceInput> {
        let precise = self.package.source_id.precise.clone()?;
        match &self.package.source_id.kind {
            SourceKind::CargoRegistry { index_url } => {
                let PackageVersion::SemVer(version) = &self.package.version else {
                    return None;
                };
                let registry = if index_url.as_str() == CRATES_IO_INDEX {
                    RegistrySpec::crates_io()
                } else {
                    RegistrySpec::new(index_url.clone(), None, CredentialSource::None)
                };
                Some(SourceInput::Registry(RegistrySource {
                    registry,
                    name: self.package.name.clone(),
                    version: version.clone(),
                    digest: Some(precise),
                    allow_yanked: true,
                }))
            }
            SourceKind::Git { url, .. } => Some(SourceInput::Git {
                url: url.clone(),
                reference: GitReference::Rev(precise),
            }),
            _ => None,
        }
    }
}

/// What an analyzer discovered for one root (spec §7.5). Every collection
/// is sorted and deduplicated, so equal inputs give equal outputs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AnalyzerOutput {
    /// The root packages (for Cargo, the workspace members).
    pub roots: BTreeSet<PackageId>,
    /// Every discovered package, with status `Not_Started`.
    pub nodes: Vec<Node>,
    /// Dependency edges, resolved and unresolved, merged by identity
    /// (spec §5.2) with canonical predicates.
    pub edges: Vec<Edge>,
    /// Package-keyed plan rows for the strategies that ran (or were
    /// skipped, or failed) for in-tree packages.
    pub plan: Vec<PlanRow>,
    /// Discovered packages that must be fetched to be analyzed further.
    pub expansions: Vec<ExpansionTask>,
    /// Tool name → reported version (spec §10.2), for the metadata.
    pub toolchain: BTreeMap<String, String>,
    /// Whether the network was used.
    pub network_mode: NetworkMode,
    /// Problems that did not stop the analysis.
    pub diagnostics: Vec<AnalyzerDiagnostic>,
}

impl AnalyzerOutput {
    /// Sorts and deduplicates every collection: nodes by id, edges merged
    /// by identity through [`DependencyGraph::add_edge`] (which also
    /// canonicalizes predicates), evidence within each edge, plan rows and
    /// diagnostics.
    pub(crate) fn normalize(&mut self) {
        let mut graph = DependencyGraph::new();
        for node in std::mem::take(&mut self.nodes) {
            graph.add_node(node);
        }
        for edge in std::mem::take(&mut self.edges) {
            graph.add_edge(edge);
        }
        let mut edges: Vec<Edge> = graph
            .raw_graph()
            .edge_weights()
            .cloned()
            .chain(graph.unresolved().iter().cloned())
            .collect();
        for edge in &mut edges {
            edge.evidence.sort_by_cached_key(evidence_key);
            edge.evidence.dedup();
        }
        edges.sort_by_cached_key(edge_key);
        self.edges = edges;
        // Placeholder nodes for edge targets are already explicit nodes.
        self.nodes = graph.nodes().map(|(_, node)| node.clone()).collect();
        for node in &mut self.nodes {
            node.targets
                .sort_by_cached_key(|target| (target.name.clone(), format!("{:?}", target.kind)));
            node.targets.dedup();
        }
        self.plan.sort();
        self.plan.dedup();
        self.expansions.sort();
        self.expansions.dedup();
        self.diagnostics.sort();
        self.diagnostics.dedup();
    }

    /// The output as an in-memory graph.
    pub fn graph(&self) -> DependencyGraph {
        let mut graph = DependencyGraph::new();
        for root in &self.roots {
            graph.add_root(root.clone());
        }
        for node in &self.nodes {
            graph.add_node(node.clone());
        }
        for edge in &self.edges {
            graph.add_edge(edge.clone());
        }
        graph
    }

    /// Writes the nodes, roots, edges and plan rows to `store`. Nodes keep
    /// any status already stored (spec §22.19), so re-persisting after
    /// progress never resets a node. The metadata row is the caller's.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`]; earlier writes are not rolled back, but every
    /// write is an idempotent upsert, so persisting again is safe.
    pub async fn persist(&self, store: &Store) -> Result<(), StoreError> {
        for node in &self.nodes {
            store.upsert_node(node).await?;
        }
        for root in &self.roots {
            store.set_root(root, true).await?;
        }
        let mut by_source: BTreeMap<&PackageId, Vec<Edge>> = BTreeMap::new();
        for edge in &self.edges {
            by_source.entry(&edge.from).or_default().push(edge.clone());
        }
        for (from, edges) in by_source {
            store.upsert_edges(from, &edges).await?;
        }
        store.upsert_plan_rows(&self.plan).await
    }
}

type EvidenceKey = (
    &'static str,
    u8,
    Option<(PathBuf, Option<u64>, Option<u64>)>,
    Option<String>,
);

fn evidence_key(evidence: &Evidence) -> EvidenceKey {
    (
        evidence.method.as_str(),
        evidence.confidence.value(),
        evidence.location.as_ref().map(|location| {
            (
                location.path.clone(),
                location.start_line,
                location.end_line,
            )
        }),
        evidence.detail.clone(),
    )
}

type EdgeKey = (
    PackageId,
    Option<PackageId>,
    &'static str,
    String,
    Option<String>,
    String,
);

fn edge_key(edge: &Edge) -> EdgeKey {
    (
        edge.from.clone(),
        edge.to.clone(),
        edge.requirement.kind.as_str(),
        edge.requirement.name.clone(),
        edge.requirement
            .version_req
            .as_ref()
            .map(|req| req.requirement_text()),
        edge.predicate.canonical_text(),
    )
}

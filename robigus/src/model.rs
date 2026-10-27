//! Core data model for the dependency graph (spec §5).
//!
//! Identity types (`SourceKind`, `SourceId`, `PackageId`), the version
//! model, dependency declarations, the analysis lifecycle, evidence, and the
//! in-memory [`DependencyGraph`].

use crate::dpkg::DpkgVersion;
use crate::error::{FetchError, RobigusError};
use crate::feature::FeatureExpr;
use crate::predicate::Predicate;
use petgraph::Direction;
use petgraph::stable_graph::{EdgeIndex, NodeIndex, StableDiGraph};
use petgraph::visit::EdgeRef;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use ubuntu_info_rust::{Architecture, Component, Suite};
use url::Url;
use walkdir::WalkDir;

// 1. Source Identification
/// Identifies the repository, transport mechanism, or upstream archive.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SourceKind {
    /// crates.io or alternative Cargo sparse/git registries
    CargoRegistry { index_url: Url },
    /// Direct Git checkout with precise tree reference
    Git { url: Url, reference: GitReference },
    /// Local filesystem path
    Path { path: PathBuf },
    /// Direct download of a source tarball. `digest` is the trusted checksum
    /// when one was supplied; otherwise the computed digest is recorded with
    /// `unverified` provenance (spec §7.2).
    Tarball { url: Url, digest: Option<String> },
    /// Ubuntu APT repository archive
    Apt {
        mirror_url: Url,
        /// Series and pocket, e.g. `noble` or `noble-updates`.
        suite: Suite,
        /// Archive components, e.g. `main` and `universe`.
        components: BTreeSet<Component>,
        /// Machine architecture, e.g. `amd64` or `arm64`.
        arch: Architecture,
    },
}

impl SourceKind {
    /// Short machine-friendly name used in logs, `PackageId` display, and
    /// the store's `source_kind` column.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::CargoRegistry { .. } => "cargo-registry",
            Self::Git { .. } => "git",
            Self::Path { .. } => "path",
            Self::Tarball { .. } => "tarball",
            Self::Apt { .. } => "apt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GitReference {
    Branch(String),
    Tag(String),
    Rev(String),
    DefaultBranch,
}

/// SourceId: Identifies where artifacts come from. In standard Cargo, sources are registries, git URLs, or directory paths. In a generalized model, this expands to include Debian/Ubuntu repositories (apt/deb), alongside custom package archives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceId {
    pub kind: SourceKind,
    /// Exact hash, commit ID, or cryptographic digest locking this source instance
    pub precise: Option<String>,
}

// 2. Package Identity & Ecosystem Abstraction
/// Tracks the packaging ecosystem to govern version parsing and linking semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Rust,
    Ubuntu,
    SystemC,
    Generic,
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rust => write!(f, "rust"),
            Self::Ubuntu => write!(f, "ubuntu"),
            Self::SystemC => write!(f, "system-c"),
            Self::Generic => write!(f, "generic"),
        }
    }
}

/// A generalized version identifier covering SemVer and Debian
/// epoch/upstream/revision versions.
///
/// The derived `Ord` is *identity* ordering for `BTreeMap` keys; semantic
/// version comparison goes through the ecosystem-specific comparators (see
/// `dpkg` and `solver`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PackageVersion {
    SemVer(Version),
    Debian(DpkgVersion),
    Opaque(String),
}

impl fmt::Display for PackageVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SemVer(version) => write!(f, "{version}"),
            // `DpkgVersion`'s Display already omits epoch 0 and an empty
            // revision (spec §5.4).
            Self::Debian(version) => write!(f, "{version}"),
            Self::Opaque(raw) => write!(f, "{raw}"),
        }
    }
}

/// PackageId: A globally unique, immutable identifier for a concrete package instance (Name + Version + SourceId).
/// Gives the concrete, resolved identity of a single package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageId {
    pub name: String,
    pub version: PackageVersion,
    pub source_id: SourceId,
    pub ecosystem: Ecosystem,
}

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} ({}/{})",
            self.name,
            self.version,
            self.ecosystem,
            self.source_id.kind.kind_name()
        )
    }
}

// 3. Architectures
/// A machine architecture as tracked by robigus (spec §4.4).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MachineArch {
    /// An architecture defined by the `ubuntu-info-rust` crate.
    Ubuntu(Architecture),
    /// Expands to every `ubuntu-info-rust` architecture at evaluation time.
    All,
    /// Detected but not supported: recorded as a stub, never expanded. The
    /// `_unsupported` suffix is a display convention only.
    Unsupported(String),
}

impl MachineArch {
    /// The default analysis set: every `ubuntu-info-rust` architecture except
    /// `i386` (spec §4.4).
    pub fn default_analysis_set() -> Vec<Self> {
        Architecture::ALL
            .iter()
            .copied()
            .filter(|arch| *arch != Architecture::I386)
            .map(Self::Ubuntu)
            .collect()
    }

    /// `All` expands to every supported architecture; other variants yield
    /// themselves unchanged.
    pub fn expand(&self) -> Vec<Self> {
        match self {
            Self::All => Architecture::ALL
                .iter()
                .copied()
                .map(Self::Ubuntu)
                .collect(),
            other => vec![other.clone()],
        }
    }

    /// Unsupported architectures are recorded but never expanded.
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported(_))
    }
}

impl fmt::Display for MachineArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ubuntu(arch) => write!(f, "{arch}"),
            Self::All => write!(f, "all"),
            Self::Unsupported(name) => write!(f, "{name}_unsupported"),
        }
    }
}

// 4. Targets and Artifact Delivery
/// Represents what a package exposes or builds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKind {
    /// Rust rlib/proc-macro/dylib
    RustLib { proc_macro: bool },
    /// Executable binary
    Binary,
    /// System shared library (.so, .dylib, .dll) with SONAME
    SharedLibrary { soname: Option<String> },
    /// Static library archive (.a)
    StaticLibrary,
    /// C/C++ Header include directory
    Headers,
    /// Pkg-config `.pc` integration
    PkgConfig(String),
}

/// Target: What artifacts the package produces or provides (libraries, binaries, C/C++ headers, dynamic shared objects, system tools).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub name: String,
    pub kind: TargetKind,
    pub path: Option<PathBuf>,
}

// 5. Dependency Declarations
/// General version constraint solver compatibility layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionConstraint {
    SemVer(VersionReq),
    /// Debian comparison: e.g. ">= 2:1.18.0-1"
    Debian {
        op: DebianOperator,
        target_version: String,
    },
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebianOperator {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// Compiled or linked into the TSP itself; runtime needs are `Runtime`.
    Normal,
    /// Host-system tooling required during build (e.g., clang, protoc, bindgen)
    Build,
    /// Test harness and unit test execution
    Development,
    /// Present in the execution environment when the TSP runs: interpreters,
    /// configuration files, data files, and similar (spec §3).
    Runtime,
}

/// Dependency: A query/requirement specified in a manifest (Name + Version Requirement + Source Specification + Constraints).
/// Expresses a dependency relationship in a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub ecosystem: Ecosystem,
    pub version_req: VersionConstraint,
    pub source_id: Option<SourceId>,
    /// The categories this dependency serves; a dependency may appear in
    /// several (spec §3).
    pub kinds: BTreeSet<DependencyKind>,
    pub optional: bool,
    /// Activation condition (spec §4); `Predicate::TRUE` is always active.
    pub predicate: Predicate,
    /// Cargo feature expressions (`foo`, `foo?`, `dep:foo`, `foo?/bar`).
    pub features: BTreeSet<FeatureExpr>,
    pub default_features: bool,
}

// 6. Analysis Lifecycle
/// Per-node state of the dependency analysis (spec §5.1, §7.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AnalysisStatus {
    #[serde(rename = "Not_Started")]
    NotStarted,
    Started,
    Complete,
    Error,
}

impl AnalysisStatus {
    /// The exact serialized form, also used by the store's `status` column.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotStarted => "Not_Started",
            Self::Started => "Started",
            Self::Complete => "Complete",
            Self::Error => "Error",
        }
    }
}

impl fmt::Display for AnalysisStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// 7. Requirements
/// The kind of requirement a dependency edge expresses (spec §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementKind {
    /// A crate from a registry, git, or path source.
    Crate,
    /// A pkg-config module.
    PkgConfig,
    /// A system header (`#include <...>`).
    Header,
    /// A shared-library soname.
    Soname,
    /// An executable tool required at build time.
    Tool,
    /// Anything else (e.g., CMake packages, Meson dependencies).
    Generic,
}

/// The declared dependency need, independent of any resolved node (spec §5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirement {
    pub kind: RequirementKind,
    /// Crate name, pkg-config module, header path, soname, or tool name.
    pub name: String,
    pub version_req: Option<VersionConstraint>,
}

// 8. Evidence and Confidence
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceMethod {
    Manifest,
    Lockfile,
    BuildScript,
    ToolOutput,
    SourceScan,
    Documentation,
    BuildObservation,
    LlmSubAgent,
    HumanOverride,
}

impl EvidenceMethod {
    /// The highest confidence this method may produce (spec §5.3).
    /// LLM-derived evidence is capped at tier L3 (§7.6).
    pub fn max_confidence(&self) -> u8 {
        match self {
            Self::LlmSubAgent => 79,
            _ => 100,
        }
    }
}

/// Where in the source tree a claim was anchored (spec §5.3, §7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Workspace-relative file path.
    pub path: PathBuf,
    pub start_line: Option<u64>,
    pub end_line: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub method: EvidenceMethod,
    pub confidence: u8,
    pub location: Option<SourceLocation>,
    pub detail: Option<String>,
}

impl Evidence {
    pub fn tier(&self) -> ConfidenceTier {
        ConfidenceTier::from_confidence(self.confidence)
    }

    /// True when the evidence exceeds its method's confidence cap (§5.3).
    pub fn violates_cap(&self) -> bool {
        self.confidence > self.method.max_confidence()
    }
}

/// Qualitative confidence ladder over the 0–100 scale (spec §5.3):
/// L0 0–19, L1 20–39, L2 40–59, L3 60–79, L4 80–100.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfidenceTier {
    L0,
    L1,
    L2,
    L3,
    L4,
}

impl ConfidenceTier {
    pub fn from_confidence(confidence: u8) -> Self {
        match confidence {
            0..=19 => Self::L0,
            20..=39 => Self::L1,
            40..=59 => Self::L2,
            60..=79 => Self::L3,
            _ => Self::L4,
        }
    }
}

// 9. Graph Nodes and Edges
/// A virtual package provided by a node (spec §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provide {
    pub name: String,
    pub version: Option<PackageVersion>,
}

/// A conflict declared by a node (spec §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    pub name: String,
    pub version_req: Option<VersionConstraint>,
}

/// A concrete package instance in the graph (spec §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: PackageId,
    /// Workspace-relative source directory, if the node exists in the
    /// analysis tree.
    pub path: Option<PathBuf>,
    pub status: AnalysisStatus,
    /// Features unified across the graph (Cargo resolver v2 semantics).
    pub active_features: BTreeSet<String>,
    pub targets: Vec<Target>,
    pub provides: Vec<Provide>,
    pub conflicts: Vec<Conflict>,
}

impl Node {
    /// A placeholder node for a discovered-but-not-yet-analyzed package.
    pub fn new(id: PackageId) -> Self {
        Self {
            id,
            path: None,
            status: AnalysisStatus::NotStarted,
            active_features: BTreeSet::new(),
            targets: Vec::new(),
            provides: Vec::new(),
            conflicts: Vec::new(),
        }
    }
}

/// A dependency relationship between nodes (spec §5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edge {
    pub from: PackageId,
    /// `None` = unresolved requirement preserved for Phase 2.
    pub to: Option<PackageId>,
    pub requirement: Requirement,
    /// The categories this dependency serves; a dependency may appear in
    /// several (spec §3).
    pub kinds: BTreeSet<DependencyKind>,
    /// Activation condition; `Predicate::TRUE` is always active.
    pub predicate: Predicate,
    pub confidence: u8,
    pub evidence: Vec<Evidence>,
}

/// The in-memory dependency graph (spec §5.4): a petgraph-backed graph for
/// resolved edges plus a side list for unresolved requirements, which have no
/// target node to attach to. Unresolved requirements map to
/// `dependency_edge` rows with a NULL `to_package_id` in the store (§11.2).
#[derive(Debug, Default, Clone)]
pub struct DependencyGraph {
    graph: StableDiGraph<Node, Edge>,
    index: BTreeMap<PackageId, NodeIndex>,
    roots: BTreeSet<PackageId>,
    unresolved: Vec<Edge>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks `id` as a root of the analysis (the TSP or a workspace member).
    pub fn add_root(&mut self, id: PackageId) {
        self.roots.insert(id);
    }

    pub fn roots(&self) -> &BTreeSet<PackageId> {
        &self.roots
    }

    /// Inserts a node, deduplicating by `PackageId`. An existing node's
    /// payload is replaced; its edges are kept.
    pub fn add_node(&mut self, node: Node) -> NodeIndex {
        if let Some(&ix) = self.index.get(&node.id) {
            self.graph[ix] = node;
            ix
        } else {
            let id = node.id.clone();
            let ix = self.graph.add_node(node);
            self.index.insert(id, ix);
            ix
        }
    }

    fn ensure_node(&mut self, id: &PackageId) -> NodeIndex {
        if let Some(&ix) = self.index.get(id) {
            return ix;
        }
        self.add_node(Node::new(id.clone()))
    }

    pub fn node(&self, id: &PackageId) -> Option<&Node> {
        self.index.get(id).map(|&ix| &self.graph[ix])
    }

    pub fn node_mut(&mut self, id: &PackageId) -> Option<&mut Node> {
        self.index
            .get(id)
            .copied()
            .map(move |ix| &mut self.graph[ix])
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Resolved and unresolved edges together.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count() + self.unresolved.len()
    }

    /// Iterates `(id, node)` in `PackageId` order.
    pub fn nodes(&self) -> impl Iterator<Item = (&PackageId, &Node)> {
        self.index.iter().map(|(id, &ix)| (id, &self.graph[ix]))
    }

    /// Adds an edge, merging with an existing edge of the same identity (same
    /// `from`, `to`, `requirement`, and `predicate`): `kinds` are unioned,
    /// confidence is the maximum, and evidence records are merged (§5.2).
    ///
    /// Endpoints that do not exist yet are inserted as placeholder
    /// `AnalysisStatus::NotStarted` nodes. Edges with `to = None` are
    /// unresolved requirements: they are recorded in the side list and
    /// `EdgeIndex::end()` is returned.
    pub fn add_edge(&mut self, edge: Edge) -> EdgeIndex {
        let from_id = edge.from.clone();
        let from_ix = self.ensure_node(&from_id);
        match edge.to.clone() {
            Some(to_id) => {
                let to_ix = self.ensure_node(&to_id);
                if let Some(ix) = self.find_matching_edge(from_ix, &edge) {
                    if let Some(existing) = self.graph.edge_weight_mut(ix) {
                        merge_edge_weights(existing, &edge);
                    }
                    ix
                } else {
                    self.graph.add_edge(from_ix, to_ix, edge)
                }
            }
            None => {
                if let Some(existing) = self.unresolved.iter_mut().find(|e| {
                    e.from == from_id
                        && e.requirement == edge.requirement
                        && e.predicate == edge.predicate
                }) {
                    merge_edge_weights(existing, &edge);
                } else {
                    self.unresolved.push(edge);
                }
                EdgeIndex::end()
            }
        }
    }

    fn find_matching_edge(&self, from_ix: NodeIndex, edge: &Edge) -> Option<EdgeIndex> {
        self.graph
            .edges_directed(from_ix, Direction::Outgoing)
            .find(|e| {
                let weight = e.weight();
                weight.to == edge.to
                    && weight.requirement == edge.requirement
                    && weight.predicate == edge.predicate
            })
            .map(|e| e.id())
    }

    /// All edges originating at `id`, including unresolved requirements.
    pub fn edges_from(&self, id: &PackageId) -> Vec<&Edge> {
        let mut out = Vec::new();
        if let Some(&ix) = self.index.get(id) {
            out.extend(
                self.graph
                    .edges_directed(ix, Direction::Outgoing)
                    .map(|e| e.weight()),
            );
        }
        out.extend(self.unresolved.iter().filter(|e| &e.from == id));
        out
    }

    /// All edges terminating at `id`.
    pub fn edges_to(&self, id: &PackageId) -> Vec<&Edge> {
        self.index
            .get(id)
            .map(|&ix| {
                self.graph
                    .edges_directed(ix, Direction::Incoming)
                    .map(|e| e.weight())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The unresolved requirements recorded for Phase 2 (spec §5.2).
    pub fn unresolved(&self) -> &[Edge] {
        &self.unresolved
    }

    /// The backing petgraph graph (resolved edges only). Unresolved
    /// requirements live in [`DependencyGraph::unresolved`].
    pub fn raw_graph(&self) -> &StableDiGraph<Node, Edge> {
        &self.graph
    }

    /// Cycles as strongly-connected components with more than one node, plus
    /// single nodes with a self-loop. Cycles are legal (Cargo dev-dependency
    /// cycles) and are recorded, not errors (spec §7.7).
    pub fn cycles(&self) -> Vec<Vec<PackageId>> {
        petgraph::algo::tarjan_scc(&self.graph)
            .into_iter()
            .filter(|scc| scc.len() > 1 || self.graph.find_edge(scc[0], scc[0]).is_some())
            .map(|scc| scc.iter().map(|&ix| self.graph[ix].id.clone()).collect())
            .collect()
    }
}

/// Merge policy for same-identity edges (spec §5.2): union `kinds`, take the
/// maximum confidence, and merge evidence without duplicates.
fn merge_edge_weights(existing: &mut Edge, incoming: &Edge) {
    existing.kinds.extend(incoming.kinds.iter().copied());
    existing.confidence = existing.confidence.max(incoming.confidence);
    for evidence in &incoming.evidence {
        if !existing.evidence.contains(evidence) {
            existing.evidence.push(evidence.clone());
        }
    }
}

// 10. Packages and Workspaces

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub package_id: PackageId,
    pub dependencies: Vec<Dependency>,
    pub targets: Vec<Target>,
    /// Feature declarations (`[features]`): feature name → the feature
    /// expressions it enables.
    pub features: BTreeMap<String, Vec<FeatureExpr>>,
    /// Native system linker flags, include paths, or environment hooks
    pub system_metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub manifest: Manifest,
    pub root_dir: PathBuf,
}

// 11. Source Tree Digest
/// Deterministic digest of a directory tree: SHA-256 over a domain tag, the
/// canonically sorted file list, and each entry's contents (spec §7.2). Used
/// to make local-path analyses reproducible.
///
/// Regular files and symlinks participate; other entry types and empty
/// directories do not. Non-UTF-8 file names are hashed lossily.
pub fn path_tree_digest(root: &Path) -> Result<String, RobigusError> {
    let root = root.canonicalize().map_err(FetchError::from)?;
    let mut entries: Vec<(String, PathBuf, bool)> = Vec::new();
    for entry in WalkDir::new(&root).follow_links(false) {
        let entry = entry.map_err(|e| FetchError::Walk(e.to_string()))?;
        if entry.depth() == 0 || entry.file_type().is_dir() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&root)
            .map_err(|_| FetchError::Walk("entry outside source root".to_string()))?
            .to_string_lossy()
            .into_owned();
        let is_symlink = entry.file_type().is_symlink();
        entries.push((relative, entry.path().to_path_buf(), is_symlink));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"robigus-tree-digest-v1\n");
    for (relative, path, is_symlink) in entries {
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        if is_symlink {
            hasher.update(b"l");
            let target = std::fs::read_link(&path).map_err(FetchError::from)?;
            hasher.update(target.to_string_lossy().as_bytes());
        } else {
            hasher.update(b"f");
            let mut file = std::fs::File::open(&path).map_err(FetchError::from)?;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer).map_err(FetchError::from)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
        }
        hasher.update([0]);
    }
    Ok(to_hex(hasher.finalize().as_slice()))
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ubuntu_info_rust::{Pocket, SeriesInfo};

    fn apt_source(suite: Suite, arch: Architecture) -> SourceKind {
        SourceKind::Apt {
            mirror_url: Url::parse("http://archive.ubuntu.com/ubuntu").unwrap(),
            suite,
            components: [Component::Main, Component::Universe].into_iter().collect(),
            arch,
        }
    }

    #[test]
    fn apt_source_round_trips_through_serde() {
        let suite = Suite::new(
            SeriesInfo::from_short_name("noble").unwrap(),
            Pocket::Updates,
        );
        let source = apt_source(suite, Architecture::Amd64);

        let json = serde_json::to_string(&source).unwrap();
        let decoded: SourceKind = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, source);
    }

    #[test]
    fn apt_source_ordering_is_consistent() {
        let noble = Suite::new(
            SeriesInfo::from_short_name("noble").unwrap(),
            Pocket::Release,
        );
        let jammy = Suite::new(
            SeriesInfo::from_short_name("jammy").unwrap(),
            Pocket::Release,
        );

        let noble_source = apt_source(noble, Architecture::Amd64);
        let jammy_source = apt_source(jammy, Architecture::Amd64);

        assert!(jammy_source < noble_source);
    }

    #[test]
    fn source_kind_names_are_stable() {
        assert_eq!(
            SourceKind::Tarball {
                url: Url::parse("https://example.com/x.tar.gz").unwrap(),
                digest: None,
            }
            .kind_name(),
            "tarball"
        );
        assert_eq!(
            SourceKind::Path {
                path: PathBuf::from("/tmp/x")
            }
            .kind_name(),
            "path"
        );
    }

    #[test]
    fn default_analysis_set_excludes_i386() {
        let set = MachineArch::default_analysis_set();
        assert_eq!(set.len(), 7);
        assert!(set.contains(&MachineArch::Ubuntu(Architecture::Amd64)));
        assert!(set.contains(&MachineArch::Ubuntu(Architecture::Amd64v3)));
        assert!(!set.contains(&MachineArch::Ubuntu(Architecture::I386)));
    }

    #[test]
    fn all_expands_to_every_supported_architecture() {
        assert_eq!(MachineArch::All.expand().len(), Architecture::ALL.len());
        assert_eq!(MachineArch::Ubuntu(Architecture::Arm64).expand().len(), 1);
    }

    #[test]
    fn unsupported_architectures_display_with_suffix() {
        assert_eq!(
            MachineArch::Unsupported("mips".into()).to_string(),
            "mips_unsupported"
        );
        assert_eq!(MachineArch::All.to_string(), "all");
        assert_eq!(
            MachineArch::Ubuntu(Architecture::Amd64).to_string(),
            "amd64"
        );
        assert!(!MachineArch::Unsupported("mips".into()).is_supported());
    }

    #[test]
    fn debian_version_display_omits_defaults() {
        let no_epoch: PackageVersion = PackageVersion::Debian("1.0".parse().unwrap());
        assert_eq!(no_epoch.to_string(), "1.0");
        let with_epoch: PackageVersion = PackageVersion::Debian("2:1.0-1".parse().unwrap());
        assert_eq!(with_epoch.to_string(), "2:1.0-1");
    }

    #[test]
    fn package_id_display_includes_ecosystem_and_source() {
        let id = PackageId {
            name: "serde".into(),
            version: PackageVersion::SemVer(Version::new(1, 0, 219)),
            source_id: SourceId {
                kind: SourceKind::CargoRegistry {
                    index_url: Url::parse("https://index.crates.io/").unwrap(),
                },
                precise: None,
            },
            ecosystem: Ecosystem::Rust,
        };
        assert_eq!(id.to_string(), "serde 1.0.219 (rust/cargo-registry)");
    }

    #[test]
    fn analysis_status_serializes_with_spec_names() {
        assert_eq!(
            serde_json::to_string(&AnalysisStatus::NotStarted).unwrap(),
            "\"Not_Started\""
        );
        assert_eq!(
            serde_json::to_string(&AnalysisStatus::Started).unwrap(),
            "\"Started\""
        );
        assert_eq!(
            serde_json::to_string(&AnalysisStatus::Complete).unwrap(),
            "\"Complete\""
        );
        assert_eq!(
            serde_json::to_string(&AnalysisStatus::Error).unwrap(),
            "\"Error\""
        );
        let back: AnalysisStatus = serde_json::from_str("\"Not_Started\"").unwrap();
        assert_eq!(back, AnalysisStatus::NotStarted);
        assert_eq!(AnalysisStatus::NotStarted.to_string(), "Not_Started");
    }

    #[test]
    fn dependency_kind_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&DependencyKind::Runtime).unwrap(),
            "\"runtime\""
        );
        assert_eq!(
            serde_json::to_string(&DependencyKind::Normal).unwrap(),
            "\"normal\""
        );
        assert_eq!(
            serde_json::to_string(&DependencyKind::Build).unwrap(),
            "\"build\""
        );
        assert_eq!(
            serde_json::to_string(&DependencyKind::Development).unwrap(),
            "\"development\""
        );
    }

    #[test]
    fn requirement_kind_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&RequirementKind::PkgConfig).unwrap(),
            "\"pkg_config\""
        );
    }

    #[test]
    fn llm_evidence_is_capped_at_l3() {
        assert_eq!(EvidenceMethod::LlmSubAgent.max_confidence(), 79);
        assert_eq!(EvidenceMethod::Manifest.max_confidence(), 100);
        let evidence = Evidence {
            method: EvidenceMethod::LlmSubAgent,
            confidence: 90,
            location: None,
            detail: None,
        };
        assert!(evidence.violates_cap());
        assert_eq!(evidence.tier(), ConfidenceTier::L4);
    }

    #[test]
    fn confidence_tier_boundaries() {
        assert_eq!(ConfidenceTier::from_confidence(0), ConfidenceTier::L0);
        assert_eq!(ConfidenceTier::from_confidence(19), ConfidenceTier::L0);
        assert_eq!(ConfidenceTier::from_confidence(20), ConfidenceTier::L1);
        assert_eq!(ConfidenceTier::from_confidence(59), ConfidenceTier::L2);
        assert_eq!(ConfidenceTier::from_confidence(60), ConfidenceTier::L3);
        assert_eq!(ConfidenceTier::from_confidence(79), ConfidenceTier::L3);
        assert_eq!(ConfidenceTier::from_confidence(80), ConfidenceTier::L4);
        assert_eq!(ConfidenceTier::from_confidence(100), ConfidenceTier::L4);
    }

    fn test_id(name: &str, major: u64) -> PackageId {
        PackageId {
            name: name.into(),
            version: PackageVersion::SemVer(Version::new(major, 0, 0)),
            source_id: SourceId {
                kind: SourceKind::Path {
                    path: PathBuf::from("/tmp"),
                },
                precise: None,
            },
            ecosystem: Ecosystem::Rust,
        }
    }

    fn test_edge(
        from: PackageId,
        to: Option<PackageId>,
        kind: DependencyKind,
        confidence: u8,
    ) -> Edge {
        Edge {
            from,
            to,
            requirement: Requirement {
                kind: RequirementKind::Crate,
                name: "dep".into(),
                version_req: None,
            },
            kinds: BTreeSet::from([kind]),
            predicate: Predicate::TRUE,
            confidence,
            evidence: vec![Evidence {
                method: EvidenceMethod::Manifest,
                confidence,
                location: None,
                detail: None,
            }],
        }
    }

    #[test]
    fn add_node_deduplicates_by_package_id() {
        let mut graph = DependencyGraph::new();
        let id = test_id("a", 1);
        let mut node = Node::new(id.clone());
        node.status = AnalysisStatus::Complete;
        graph.add_node(node);
        graph.add_node(Node::new(id.clone()));
        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.node(&id).unwrap().status, AnalysisStatus::NotStarted);
    }

    #[test]
    fn add_edge_merges_same_identity() {
        let mut graph = DependencyGraph::new();
        let a = test_id("a", 1);
        let b = test_id("b", 1);
        graph.add_edge(test_edge(
            a.clone(),
            Some(b.clone()),
            DependencyKind::Normal,
            40,
        ));
        graph.add_edge(test_edge(
            a.clone(),
            Some(b.clone()),
            DependencyKind::Development,
            80,
        ));
        assert_eq!(graph.edge_count(), 1);
        let edges = graph.edges_from(&a);
        assert_eq!(edges.len(), 1);
        let edge = edges[0];
        assert!(edge.kinds.contains(&DependencyKind::Normal));
        assert!(edge.kinds.contains(&DependencyKind::Development));
        assert_eq!(edge.confidence, 80);
        assert_eq!(edge.evidence.len(), 2);
    }

    #[test]
    fn distinct_predicates_are_distinct_edges() {
        let mut graph = DependencyGraph::new();
        let a = test_id("a", 1);
        let b = test_id("b", 1);
        let mut first = test_edge(a.clone(), Some(b.clone()), DependencyKind::Normal, 50);
        first.predicate = Predicate::feature("serde");
        graph.add_edge(first);
        graph.add_edge(test_edge(
            a.clone(),
            Some(b.clone()),
            DependencyKind::Normal,
            50,
        ));
        assert_eq!(graph.edge_count(), 2);
    }

    #[test]
    fn unresolved_requirements_are_recorded_separately() {
        let mut graph = DependencyGraph::new();
        let a = test_id("a", 1);
        graph.add_edge(test_edge(a.clone(), None, DependencyKind::Build, 50));
        graph.add_edge(test_edge(a.clone(), None, DependencyKind::Build, 70));
        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.edge_count(), 1);
        assert_eq!(graph.unresolved().len(), 1);
        assert_eq!(graph.unresolved()[0].confidence, 70);
        assert_eq!(graph.edges_from(&a).len(), 1);
        assert!(graph.edges_to(&a).is_empty());
    }

    #[test]
    fn cycles_are_detected_as_sccs() {
        let mut graph = DependencyGraph::new();
        let a = test_id("a", 1);
        let b = test_id("b", 1);
        graph.add_edge(test_edge(
            a.clone(),
            Some(b.clone()),
            DependencyKind::Development,
            50,
        ));
        graph.add_edge(test_edge(
            b.clone(),
            Some(a.clone()),
            DependencyKind::Development,
            50,
        ));
        let cycles = graph.cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 2);
    }

    #[test]
    fn acyclic_graphs_report_no_cycles() {
        let mut graph = DependencyGraph::new();
        let a = test_id("a", 1);
        let b = test_id("b", 1);
        let c = test_id("c", 1);
        graph.add_edge(test_edge(
            a.clone(),
            Some(b.clone()),
            DependencyKind::Normal,
            50,
        ));
        graph.add_edge(test_edge(
            b.clone(),
            Some(c.clone()),
            DependencyKind::Normal,
            50,
        ));
        assert!(graph.cycles().is_empty());
    }

    #[test]
    fn edges_to_reports_incoming_edges() {
        let mut graph = DependencyGraph::new();
        let a = test_id("a", 1);
        let b = test_id("b", 1);
        graph.add_edge(test_edge(
            a.clone(),
            Some(b.clone()),
            DependencyKind::Normal,
            50,
        ));
        assert_eq!(graph.edges_to(&b).len(), 1);
        assert!(graph.edges_to(&a).is_empty());
    }

    #[test]
    fn tree_digest_is_deterministic_and_content_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        std::fs::write(&a, b"hello").unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("c.txt"), b"world").unwrap();

        let first = path_tree_digest(dir.path()).unwrap();
        let second = path_tree_digest(dir.path()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);

        std::fs::write(&a, b"changed").unwrap();
        let third = path_tree_digest(dir.path()).unwrap();
        assert_ne!(third, first);
    }

    #[test]
    fn tree_digest_covers_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real.txt"), b"data").unwrap();
        std::os::unix::fs::symlink("real.txt", dir.path().join("link.txt")).unwrap();

        let with_link = path_tree_digest(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join("link.txt")).unwrap();
        let without_link = path_tree_digest(dir.path()).unwrap();
        assert_ne!(with_link, without_link);
    }
}

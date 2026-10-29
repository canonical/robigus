//! Project detection and the in-memory [`ProjectTree`] (spec §7.3, §7.5).
//!
//! Detection is pure marker inspection: [`ProjectTree::discover`] performs the
//! single I/O-heavy walk (via the `ignore` crate, honoring its default rules
//! plus the §7.3 skip list), and [`detect`] turns the resulting tree into a
//! deterministic [`DetectionReport`] with no further I/O. [`ProjectAnalyzer`]
//! is the analyzer registry seam; its `detect` method is synchronous by design
//! (§6.2).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use ignore::WalkBuilder;

use crate::error::DetectError;
use crate::model::ConfidenceTier;

/// A 0–100 confidence score (spec §5.3).
///
/// Distinct from the raw `u8` stored on [`crate::model::Evidence`] so analyzer
/// detection can carry a typed, clamped score. Values above 100 are clamped to
/// 100 rather than rejected, so malformed input cannot panic (§15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Confidence(u8);

impl Confidence {
    /// The lowest possible confidence (no signal).
    pub const ZERO: Self = Self(0);
    /// The highest possible confidence.
    pub const MAX: Self = Self(100);

    /// Builds a confidence, clamping values above 100 to 100.
    pub const fn new(value: u8) -> Self {
        Self(if value > 100 { 100 } else { value })
    }

    /// The raw 0–100 score.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// The qualitative tier this score falls into (§5.3).
    pub fn tier(self) -> ConfidenceTier {
        ConfidenceTier::from_confidence(self.0)
    }
}

/// The analyzers robigus knows about (spec §7.3). Only [`AnalyzerId::Cargo`]
/// and [`AnalyzerId::Cpp`] ship in v1; the rest are detected and recorded as
/// `Skipped` plan rows so the record shows what was seen but not analyzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnalyzerId {
    Cargo,
    Cpp,
    Python,
    Go,
    Node,
}

impl AnalyzerId {
    /// The stable analyzer name used in plan rows and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Cpp => "cpp",
            Self::Python => "python",
            Self::Go => "go",
            Self::Node => "node",
        }
    }

    /// True for analyzers shipped in v1 (spec §7.3).
    pub fn is_shipped(self) -> bool {
        matches!(self, Self::Cargo | Self::Cpp)
    }
}

/// The per-analyzer build-system/ecosystem strategy a marker signals (spec
/// §7.3). CMake, Meson, Autotools, and Make are strategies *inside* the `cpp`
/// analyzer, not separate analyzers. This axis is distinct from the §7.6
/// analysis-strategy axis (manifest, tool introspection, build observation, …),
/// which is added during expansion (WP-2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Strategy {
    /// Parse the ecosystem manifest (`Cargo.toml`, `package.json`, …).
    Manifest,
    /// `build.rs` → C/C++/assembly discovery inside the Cargo analyzer.
    NativeBuildScript,
    Cmake,
    Meson,
    Autotools,
    Make,
}

impl Strategy {
    /// The stable strategy name used in plan rows and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::NativeBuildScript => "native_build_script",
            Self::Cmake => "cmake",
            Self::Meson => "meson",
            Self::Autotools => "autotools",
            Self::Make => "make",
        }
    }
}

/// The status of a plan row (spec §7.3). Future-ecosystem markers are recorded
/// as `Skipped`; shipped analyzers are `Pending` until expansion runs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlanStatus {
    Pending,
    Skipped,
}

impl PlanStatus {
    /// The exact serialized form, matching the store's `analysis_plan.status`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Skipped => "Skipped",
        }
    }
}

/// One marker file and the analyzer/strategy it signals (spec §7.3).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DetectionSignal {
    /// Workspace-relative marker path.
    pub marker: PathBuf,
    pub analyzer: AnalyzerId,
    pub strategy: Strategy,
    pub confidence: Confidence,
}

/// A detected analysis entry point: a directory that is analyzed as one unit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProjectRoot {
    /// Workspace-relative directory (empty for the top level).
    pub path: PathBuf,
    /// Analyzers that apply to this root.
    pub analyzers: BTreeSet<AnalyzerId>,
}

/// One row of the dependency mapping plan (spec §2, §7.3).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlanRow {
    pub root: PathBuf,
    pub analyzer: AnalyzerId,
    pub strategy: Strategy,
    pub status: PlanStatus,
}

/// The result of [`detect`]: signals, roots, and plan rows, each sorted for
/// determinism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionReport {
    pub signals: Vec<DetectionSignal>,
    pub roots: Vec<ProjectRoot>,
    /// Cargo packages inside a root that are neither workspace members nor
    /// separate roots (test fixtures, examples, …). Recorded so the report
    /// shows what was seen, but not analyzed as roots (spec §7.3).
    pub non_member_crates: Vec<PathBuf>,
    pub plan: Vec<PlanRow>,
}

/// Limits applied to the [`ProjectTree`] walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DetectionLimits {
    /// Maximum directory depth to descend (`None` = unlimited). The root is
    /// depth 0.
    pub max_depth: Option<usize>,
}

/// The §7.3 marker table: filename → (analyzer, strategy, confidence).
const MARKERS: &[(&str, AnalyzerId, Strategy, u8)] = &[
    ("Cargo.toml", AnalyzerId::Cargo, Strategy::Manifest, 90),
    (
        "build.rs",
        AnalyzerId::Cargo,
        Strategy::NativeBuildScript,
        70,
    ),
    ("CMakeLists.txt", AnalyzerId::Cpp, Strategy::Cmake, 90),
    ("meson.build", AnalyzerId::Cpp, Strategy::Meson, 90),
    ("configure.ac", AnalyzerId::Cpp, Strategy::Autotools, 90),
    ("configure", AnalyzerId::Cpp, Strategy::Autotools, 80),
    ("Makefile", AnalyzerId::Cpp, Strategy::Make, 70),
    ("pyproject.toml", AnalyzerId::Python, Strategy::Manifest, 90),
    ("setup.py", AnalyzerId::Python, Strategy::Manifest, 80),
    ("go.mod", AnalyzerId::Go, Strategy::Manifest, 90),
    ("package.json", AnalyzerId::Node, Strategy::Manifest, 90),
];

fn marker_signal(filename: &str) -> Option<(AnalyzerId, Strategy, u8)> {
    MARKERS
        .iter()
        .find(|(name, ..)| *name == filename)
        .map(|(_, analyzer, strategy, confidence)| (*analyzer, *strategy, *confidence))
}

/// Workspace membership info parsed from a `Cargo.toml` (spec §7.3).
#[derive(Debug, Clone, Default)]
struct CargoManifest {
    is_workspace: bool,
    /// Normalized `[workspace] members` globs, relative to the manifest's
    /// directory.
    members: Vec<String>,
    /// Normalized `[workspace] exclude` entries. Cargo treats these as path
    /// prefixes, not globs.
    exclude: Vec<PathBuf>,
}

/// The in-memory result of walking a project tree (spec §7.3). Built once by
/// [`ProjectTree::discover`]; [`detect`] and [`ProjectAnalyzer::detect`] then
/// inspect it without further I/O.
#[derive(Debug, Clone)]
pub struct ProjectTree {
    root: PathBuf,
    /// Sorted workspace-relative paths of every marker file found.
    markers: Vec<PathBuf>,
    /// Parsed Cargo manifests, keyed by the workspace-relative directory
    /// containing the `Cargo.toml` (empty path = top level).
    cargo_manifests: BTreeMap<PathBuf, CargoManifest>,
}

impl ProjectTree {
    /// Walks `root` with the `ignore` crate, honoring its default rules plus
    /// the §7.3 skip list (`target/`, `vendor/`, `node_modules/`, `.git/`) and
    /// the depth limit. Out-of-tree ignore files (parent `.gitignore`s and the
    /// user's global gitignore) are disabled so detection is reproducible.
    pub fn discover(
        root: impl Into<PathBuf>,
        limits: &DetectionLimits,
    ) -> Result<Self, DetectError> {
        let root = root.into();
        let mut markers = Vec::new();
        let mut cargo_manifests = BTreeMap::new();

        let mut builder = WalkBuilder::new(&root);
        builder
            .standard_filters(true)
            .parents(false)
            .git_global(false)
            // `.gitignore` rules apply even when no `.git` directory exists
            // (a tarball may ship `.gitignore` without a repository).
            .require_git(false)
            .max_depth(limits.max_depth)
            .filter_entry(|entry| {
                let name = entry.file_name().to_string_lossy();
                !matches!(name.as_ref(), "target" | "vendor" | "node_modules" | ".git")
            });

        for result in builder.build() {
            let entry = result.map_err(|e| DetectError::Walk(e.to_string()))?;
            let Some(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_file() {
                continue;
            }
            let rel = entry
                .path()
                .strip_prefix(&root)
                .map_err(|e| DetectError::Walk(e.to_string()))?
                .to_path_buf();
            let Some(filename) = rel.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if marker_signal(filename).is_some() {
                markers.push(rel.clone());
            }
            if filename == "Cargo.toml" {
                let content = std::fs::read_to_string(entry.path())?;
                let dir = rel.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
                cargo_manifests.insert(dir, parse_cargo_manifest(&content));
            }
        }

        markers.sort();
        markers.dedup();

        Ok(Self {
            root,
            markers,
            cargo_manifests,
        })
    }

    /// The absolute root directory that was walked.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Sorted workspace-relative paths of every marker file found.
    pub fn markers(&self) -> &[PathBuf] {
        &self.markers
    }

    /// True when `rel` (workspace-relative) is a detected marker file.
    pub fn has_marker(&self, rel: &Path) -> bool {
        self.markers.iter().any(|m| m == rel)
    }

    /// The number of marker files found.
    pub fn marker_count(&self) -> usize {
        self.markers.len()
    }
}

fn parse_cargo_manifest(content: &str) -> CargoManifest {
    let mut manifest = CargoManifest::default();
    let Ok(doc) = content.parse::<toml_edit::DocumentMut>() else {
        return manifest;
    };
    let Some(workspace) = doc.get("workspace").and_then(|item| item.as_table()) else {
        return manifest;
    };
    manifest.is_workspace = true;
    let entries = |key: &str| -> Vec<String> {
        workspace
            .get(key)
            .and_then(|item| item.as_value())
            .and_then(|value| value.as_array())
            .map(|array| {
                array
                    .iter()
                    .filter_map(|value| value.as_str())
                    .filter_map(normalize_workspace_entry)
                    .collect()
            })
            .unwrap_or_default()
    };
    manifest.members = entries("members");
    manifest.exclude = entries("exclude").into_iter().map(PathBuf::from).collect();
    manifest
}

/// Normalizes a workspace `members`/`exclude` entry relative to the
/// workspace directory, so `./a` and `a/` both become `a`. Entries that are
/// absolute or climb above the workspace directory cannot name anything
/// below it and yield `None`.
fn normalize_workspace_entry(entry: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for component in Path::new(entry).components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// How a Cargo package directory relates to the workspaces above it.
#[derive(Debug, Clone, Copy, Default)]
struct Membership {
    /// Matched by an ancestor workspace's `members` and not excluded.
    member: bool,
    /// Named exactly by an ancestor workspace's `exclude`.
    explicitly_excluded: bool,
}

/// Classifies `dir` against every strictly-ancestor workspace. Membership
/// follows Cargo: `members` are globs whose `*` does not cross `/`, and
/// `exclude` entries are path prefixes that override `members`.
fn membership(tree: &ProjectTree, dir: &Path) -> Membership {
    let mut result = Membership::default();
    for (ancestor, manifest) in &tree.cargo_manifests {
        if !manifest.is_workspace || ancestor.as_path() == dir {
            continue;
        }
        let Ok(rel) = dir.strip_prefix(ancestor) else {
            continue;
        };
        let excluded = manifest.exclude.iter().any(|ex| rel.starts_with(ex));
        result.explicitly_excluded |= manifest.exclude.iter().any(|ex| rel == ex);
        result.member |= !excluded && manifest.members.iter().any(|m| glob_matches(m, rel));
    }
    result
}

/// Cargo's member-glob semantics: `*` and `?` never match `/` (Cargo expands
/// members with a filesystem glob, component by component).
const MEMBER_GLOB: glob::MatchOptions = glob::MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

fn glob_matches(pattern: &str, path: &Path) -> bool {
    glob::Pattern::new(pattern)
        .map(|p| p.matches_path_with(path, MEMBER_GLOB))
        .unwrap_or(false)
}

/// Decides which Cargo package directories are analysis roots (spec §7.3).
/// Returns `(roots, non_member_crates)`.
///
/// Directories are decided shallowest first, so every enclosing root is known
/// before the directories inside it. A Cargo directory is:
///
/// - part of an enclosing root (not a root itself) when an ancestor
///   workspace's `members` include it;
/// - a root when no Cargo root encloses it (the top-level project, or an
///   independent crate in a monorepo whose top level is not Cargo);
/// - a separate root when it is enclosed but has its own `[workspace]`, or
///   is listed explicitly in an ancestor workspace's `exclude`;
/// - otherwise a *non-member crate* (test fixture, example, …): recorded,
///   but not a root.
fn cargo_roots(tree: &ProjectTree) -> (BTreeSet<PathBuf>, Vec<PathBuf>) {
    let mut dirs: Vec<&PathBuf> = tree.cargo_manifests.keys().collect();
    dirs.sort_by_key(|dir| (dir.components().count(), (*dir).clone()));

    let mut roots = BTreeSet::new();
    let mut non_member_crates = Vec::new();
    for dir in dirs {
        let membership = membership(tree, dir);
        if membership.member {
            continue;
        }
        let enclosed = roots.iter().any(|root: &PathBuf| dir.starts_with(root));
        let has_workspace = tree
            .cargo_manifests
            .get(dir)
            .is_some_and(|manifest| manifest.is_workspace);
        if !enclosed || has_workspace || membership.explicitly_excluded {
            roots.insert(dir.clone());
        } else {
            non_member_crates.push(dir.clone());
        }
    }
    non_member_crates.sort();
    (roots, non_member_crates)
}

/// The deepest root that is an ancestor of (or equal to) `dir`.
fn nearest_root(
    root_map: &BTreeMap<PathBuf, BTreeMap<AnalyzerId, BTreeSet<Strategy>>>,
    dir: &Path,
) -> Option<PathBuf> {
    root_map
        .keys()
        .filter(|root| dir.starts_with(root))
        .max_by_key(|root| root.components().count())
        .cloned()
}

/// Detects analyzers, roots, and plan rows from a walked tree (spec §7.3).
///
/// Deterministic: every field of the returned report is sorted, and the
/// result does not depend on marker file names. Cargo roots follow the
/// workspace rules of `cargo_roots`. Every other marker attaches to the
/// deepest root enclosing it; a marker with no enclosing root starts a new
/// root at its directory. Markers are attached shallowest first, so a
/// directory's markers are always considered before those of its
/// subdirectories. `vendor/` is skipped entirely, so vendored crates are
/// never roots.
pub fn detect(tree: &ProjectTree) -> DetectionReport {
    let mut signals: Vec<DetectionSignal> = tree
        .markers
        .iter()
        .filter_map(|marker| {
            let filename = marker.file_name().and_then(|n| n.to_str())?;
            let (analyzer, strategy, confidence) = marker_signal(filename)?;
            Some(DetectionSignal {
                marker: marker.clone(),
                analyzer,
                strategy,
                confidence: Confidence::new(confidence),
            })
        })
        .collect();
    signals.sort();

    // Establish roots: directory -> analyzer -> strategies.
    let mut root_map: BTreeMap<PathBuf, BTreeMap<AnalyzerId, BTreeSet<Strategy>>> = BTreeMap::new();

    let (cargo_root_dirs, non_member_crates) = cargo_roots(tree);
    for dir in cargo_root_dirs {
        root_map
            .entry(dir)
            .or_default()
            .entry(AnalyzerId::Cargo)
            .or_default()
            .insert(Strategy::Manifest);
    }

    // Attach every marker to its owning root, creating a new root when no
    // ancestor root exists yet. Shallowest first: attaching in plain path
    // order made the outcome depend on file names (`lib/b/meson.build` sorts
    // before `lib/configure` but after `lib/Makefile`).
    let mut by_depth: Vec<&DetectionSignal> = signals.iter().collect();
    by_depth
        .sort_by_cached_key(|signal| (signal.marker.components().count(), signal.marker.clone()));
    for signal in by_depth {
        let dir = signal
            .marker
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .to_path_buf();
        match nearest_root(&root_map, &dir) {
            Some(root) => {
                root_map
                    .entry(root)
                    .or_default()
                    .entry(signal.analyzer)
                    .or_default()
                    .insert(signal.strategy);
            }
            None => {
                root_map
                    .entry(dir)
                    .or_default()
                    .entry(signal.analyzer)
                    .or_default()
                    .insert(signal.strategy);
            }
        }
    }

    let mut roots = Vec::new();
    let mut plan = Vec::new();
    for (path, analyzers) in root_map {
        roots.push(ProjectRoot {
            path: path.clone(),
            analyzers: analyzers.keys().copied().collect(),
        });
        for (analyzer, strategies) in analyzers {
            for strategy in strategies {
                let status = if analyzer.is_shipped() {
                    PlanStatus::Pending
                } else {
                    PlanStatus::Skipped
                };
                plan.push(PlanRow {
                    root: path.clone(),
                    analyzer,
                    strategy,
                    status,
                });
            }
        }
    }
    roots.sort();
    plan.sort();

    DetectionReport {
        signals,
        roots,
        non_member_crates,
        plan,
    }
}

/// The analyzer registry seam (spec §7.5). `detect` is synchronous by design:
/// pure marker inspection over an in-memory [`ProjectTree`] with no I/O. The
/// `analyze` method is added when the analyzers land (WP-2.2/WP-3.1).
pub trait ProjectAnalyzer: Send + Sync {
    fn id(&self) -> AnalyzerId;
    fn detect(&self, tree: &ProjectTree) -> Confidence;
}

/// The Rust/Cargo analyzer (spec §8.1).
#[derive(Debug, Clone, Copy, Default)]
pub struct CargoAnalyzer;

impl ProjectAnalyzer for CargoAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::Cargo
    }

    fn detect(&self, tree: &ProjectTree) -> Confidence {
        analyzer_confidence(tree, AnalyzerId::Cargo)
    }
}

/// The C/C++ analyzer (spec §8.2).
#[derive(Debug, Clone, Copy, Default)]
pub struct CppAnalyzer;

impl ProjectAnalyzer for CppAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::Cpp
    }

    fn detect(&self, tree: &ProjectTree) -> Confidence {
        analyzer_confidence(tree, AnalyzerId::Cpp)
    }
}

/// The v1 analyzer registry (spec §7.3).
pub fn analyzers() -> Vec<Box<dyn ProjectAnalyzer>> {
    vec![Box::new(CargoAnalyzer), Box::new(CppAnalyzer)]
}

fn analyzer_confidence(tree: &ProjectTree, analyzer: AnalyzerId) -> Confidence {
    tree.markers
        .iter()
        .filter_map(|m| m.file_name().and_then(|n| n.to_str()))
        .filter_map(marker_signal)
        .filter(|(a, ..)| *a == analyzer)
        .map(|(_, _, confidence)| confidence)
        .max()
        .map(Confidence::new)
        .unwrap_or(Confidence::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn discover(root: &Path) -> ProjectTree {
        ProjectTree::discover(root, &DetectionLimits::default()).unwrap()
    }

    fn root_paths(report: &DetectionReport) -> Vec<&Path> {
        report.roots.iter().map(|r| r.path.as_path()).collect()
    }

    #[test]
    fn confidence_clamps_to_100() {
        assert_eq!(Confidence::new(150).value(), 100);
        assert_eq!(Confidence::new(0).value(), 0);
        assert_eq!(Confidence::new(79).tier(), ConfidenceTier::L3);
        assert_eq!(Confidence::new(80).tier(), ConfidenceTier::L4);
    }

    #[test]
    fn single_crate_is_one_root() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        );
        let report = detect(&discover(tmp.path()));
        assert_eq!(report.roots.len(), 1);
        assert_eq!(report.roots[0].path, Path::new(""));
        assert_eq!(
            report.roots[0].analyzers,
            BTreeSet::from([AnalyzerId::Cargo])
        );
    }

    #[test]
    fn monorepo_yields_multiple_roots() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "app1/Cargo.toml",
            "[package]\nname = \"app1\"\nversion = \"0.1.0\"\n",
        );
        write(
            tmp.path(),
            "app2/Cargo.toml",
            "[package]\nname = \"app2\"\nversion = \"0.1.0\"\n",
        );
        let report = detect(&discover(tmp.path()));
        assert_eq!(
            root_paths(&report),
            vec![Path::new("app1"), Path::new("app2")]
        );
    }

    #[test]
    fn vendored_crate_is_not_a_root() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        );
        write(
            tmp.path(),
            "vendor/foo/Cargo.toml",
            "[package]\nname = \"foo\"\nversion = \"0.1.0\"\n",
        );
        let report = detect(&discover(tmp.path()));
        assert_eq!(report.roots.len(), 1);
        assert_eq!(report.roots[0].path, Path::new(""));
        assert!(
            !report
                .signals
                .iter()
                .any(|s| s.marker == Path::new("vendor/foo/Cargo.toml"))
        );
    }

    #[test]
    fn nested_workspace_members_are_not_roots() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n",
        );
        write(
            tmp.path(),
            "crates/a/Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
        );
        write(
            tmp.path(),
            "crates/b/Cargo.toml",
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\n",
        );
        let report = detect(&discover(tmp.path()));
        assert_eq!(report.roots.len(), 1);
        assert_eq!(report.roots[0].path, Path::new(""));
    }

    const PACKAGE: &str = "[package]\nname = \"p\"\nversion = \"0.1.0\"\n";

    /// A nested directory with its own `[workspace]` that the top-level
    /// workspace does not reach is a separate root (for example a detached
    /// cargo-fuzz workspace).
    #[test]
    fn unreachable_nested_workspace_is_a_root() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n",
        );
        write(tmp.path(), "crates/a/Cargo.toml", PACKAGE);
        write(
            tmp.path(),
            "fuzz/Cargo.toml",
            "[package]\nname = \"fuzz\"\nversion = \"0.0.0\"\n\n[workspace]\nmembers = [\".\"]\n",
        );
        let report = detect(&discover(tmp.path()));
        assert_eq!(root_paths(&report), vec![Path::new(""), Path::new("fuzz")]);
        assert!(report.non_member_crates.is_empty());
    }

    /// A plain package inside a root that is neither a member, a workspace,
    /// nor explicitly excluded (a test fixture or example) is recorded but is
    /// not a root.
    #[test]
    fn plain_non_member_crate_is_recorded_not_rooted() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n",
        );
        write(tmp.path(), "crates/a/Cargo.toml", PACKAGE);
        write(tmp.path(), "tests/fixtures/demo/Cargo.toml", PACKAGE);
        let report = detect(&discover(tmp.path()));
        assert_eq!(root_paths(&report), vec![Path::new("")]);
        assert_eq!(
            report.non_member_crates,
            vec![PathBuf::from("tests/fixtures/demo")]
        );
        assert!(
            report
                .signals
                .iter()
                .any(|s| s.marker == Path::new("tests/fixtures/demo/Cargo.toml")),
            "the crate is still recorded as a detection signal"
        );
    }

    /// Fixture crates nested inside a plain (non-workspace) package are not
    /// roots either.
    #[test]
    fn crates_nested_in_a_package_are_not_roots() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "Cargo.toml", PACKAGE);
        write(tmp.path(), "examples/demo/Cargo.toml", PACKAGE);
        let report = detect(&discover(tmp.path()));
        assert_eq!(root_paths(&report), vec![Path::new("")]);
        assert_eq!(
            report.non_member_crates,
            vec![PathBuf::from("examples/demo")]
        );
    }

    /// `exclude` entries are path prefixes: a crate *below* an excluded
    /// directory is excluded from the workspace, but only a crate named
    /// exactly by `exclude` becomes a separate root.
    #[test]
    fn exclude_prefix_without_explicit_listing_is_not_a_root() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"examples/*\"]\nexclude = [\"examples\"]\n",
        );
        write(tmp.path(), "examples/one/Cargo.toml", PACKAGE);
        let report = detect(&discover(tmp.path()));
        assert_eq!(root_paths(&report), vec![Path::new("")]);
        assert_eq!(
            report.non_member_crates,
            vec![PathBuf::from("examples/one")]
        );
    }

    /// Regression (High 6): a member glob's `*` must not cross `/`, as in
    /// Cargo. `crates/*` matched `crates/a/fixture` and hid it.
    #[test]
    fn member_globs_do_not_cross_directories() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n",
        );
        write(tmp.path(), "crates/a/Cargo.toml", PACKAGE);
        write(tmp.path(), "crates/a/fixture/Cargo.toml", PACKAGE);
        let report = detect(&discover(tmp.path()));
        assert_eq!(root_paths(&report), vec![Path::new("")]);
        assert_eq!(
            report.non_member_crates,
            vec![PathBuf::from("crates/a/fixture")],
            "crates/a/fixture is not a member of crates/*"
        );

        // `**` still spans directories.
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/**\"]\n",
        );
        write(tmp.path(), "crates/a/b/Cargo.toml", PACKAGE);
        let report = detect(&discover(tmp.path()));
        assert!(report.non_member_crates.is_empty());
    }

    /// Regression (High 6): `./a`, `b/`, and `c//d` name the same
    /// directories as `a`, `b`, and `c/d`.
    #[test]
    fn member_and_exclude_spellings_are_normalized() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"./a\", \"b/\", \"c//d\", \"./e\"]\nexclude = [\"./e/\"]\n",
        );
        for dir in ["a", "b", "c/d", "e"] {
            write(tmp.path(), &format!("{dir}/Cargo.toml"), PACKAGE);
        }
        let report = detect(&discover(tmp.path()));
        assert_eq!(root_paths(&report), vec![Path::new(""), Path::new("e")]);
        assert!(report.non_member_crates.is_empty());
    }

    #[test]
    fn normalize_workspace_entry_cases() {
        assert_eq!(normalize_workspace_entry("./a/").as_deref(), Some("a"));
        assert_eq!(normalize_workspace_entry("a/./b").as_deref(), Some("a/b"));
        assert_eq!(normalize_workspace_entry("a/../b").as_deref(), Some("b"));
        assert_eq!(
            normalize_workspace_entry("crates/*").as_deref(),
            Some("crates/*")
        );
        assert_eq!(normalize_workspace_entry("../outside"), None);
        assert_eq!(normalize_workspace_entry("/abs"), None);
        assert_eq!(normalize_workspace_entry("."), None);
    }

    /// Regression (High 7): the same layout must give the same roots no
    /// matter what the marker files are called. Attaching markers in plain
    /// path order produced `["lib", "lib/b"]` for `lib/configure` but
    /// `["lib"]` for `lib/Makefile`.
    #[test]
    fn roots_do_not_depend_on_marker_names() {
        for top in [
            "configure",
            "Makefile",
            "CMakeLists.txt",
            "meson.build",
            "package.json",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write(tmp.path(), &format!("lib/{top}"), "");
            write(tmp.path(), "lib/b/meson.build", "");
            write(tmp.path(), "lib/b/c/configure.ac", "");
            let report = detect(&discover(tmp.path()));
            assert_eq!(
                root_paths(&report),
                vec![Path::new("lib")],
                "top marker {top}"
            );
        }
    }

    #[test]
    fn workspace_exclude_makes_a_separate_root() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"crates/b\"]\n",
        );
        write(
            tmp.path(),
            "crates/a/Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
        );
        write(
            tmp.path(),
            "crates/b/Cargo.toml",
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\n",
        );
        let report = detect(&discover(tmp.path()));
        assert_eq!(
            root_paths(&report),
            vec![Path::new(""), Path::new("crates/b")]
        );
    }

    #[test]
    fn polyglot_project_has_multiple_analyzers() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        );
        write(tmp.path(), "package.json", "{}");
        write(tmp.path(), "pyproject.toml", "[project]\nname = \"x\"\n");
        let report = detect(&discover(tmp.path()));
        assert_eq!(report.roots.len(), 1);
        assert_eq!(
            report.roots[0].analyzers,
            BTreeSet::from([AnalyzerId::Cargo, AnalyzerId::Node, AnalyzerId::Python])
        );
        let skipped: BTreeSet<_> = report
            .plan
            .iter()
            .filter(|p| p.status == PlanStatus::Skipped)
            .map(|p| p.analyzer)
            .collect();
        assert_eq!(
            skipped,
            BTreeSet::from([AnalyzerId::Node, AnalyzerId::Python])
        );
        assert!(
            report
                .plan
                .iter()
                .any(|p| p.analyzer == AnalyzerId::Cargo && p.status == PlanStatus::Pending)
        );
    }

    #[test]
    fn skip_list_directories_are_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        );
        write(
            tmp.path(),
            "target/Cargo.toml",
            "[package]\nname = \"t\"\nversion = \"0.1.0\"\n",
        );
        write(tmp.path(), "node_modules/package.json", "{}");
        write(
            tmp.path(),
            "vendor/foo/Cargo.toml",
            "[package]\nname = \"f\"\nversion = \"0.1.0\"\n",
        );
        write(tmp.path(), ".git/config", "");
        let report = detect(&discover(tmp.path()));
        assert_eq!(report.roots.len(), 1);
        assert_eq!(report.signals.len(), 1);
    }

    #[test]
    fn gitignore_rules_are_honored() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        );
        write(tmp.path(), ".gitignore", "generated/\n");
        write(
            tmp.path(),
            "generated/Cargo.toml",
            "[package]\nname = \"g\"\nversion = \"0.1.0\"\n",
        );
        let report = detect(&discover(tmp.path()));
        assert_eq!(report.signals.len(), 1);
        assert!(
            !report
                .signals
                .iter()
                .any(|s| s.marker == Path::new("generated/Cargo.toml"))
        );
    }

    #[test]
    fn depth_limit_stops_descent() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "a/b/c/Cargo.toml",
            "[package]\nname = \"deep\"\nversion = \"0.1.0\"\n",
        );
        let deep =
            ProjectTree::discover(tmp.path(), &DetectionLimits { max_depth: Some(2) }).unwrap();
        assert!(deep.markers().is_empty());
        let shallow =
            ProjectTree::discover(tmp.path(), &DetectionLimits { max_depth: Some(4) }).unwrap();
        assert_eq!(shallow.markers().len(), 1);
    }

    #[test]
    fn build_rs_signals_native_discovery() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        );
        write(tmp.path(), "build.rs", "fn main() {}\n");
        let report = detect(&discover(tmp.path()));
        let strategies: BTreeSet<_> = report
            .plan
            .iter()
            .filter(|p| p.analyzer == AnalyzerId::Cargo)
            .map(|p| p.strategy)
            .collect();
        assert_eq!(
            strategies,
            BTreeSet::from([Strategy::Manifest, Strategy::NativeBuildScript])
        );
    }

    #[test]
    fn cpp_build_systems_are_strategies() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "CMakeLists.txt", "");
        write(tmp.path(), "meson.build", "");
        write(tmp.path(), "configure.ac", "");
        write(tmp.path(), "Makefile", "");
        let report = detect(&discover(tmp.path()));
        assert_eq!(report.roots.len(), 1);
        assert_eq!(report.roots[0].analyzers, BTreeSet::from([AnalyzerId::Cpp]));
        let strategies: BTreeSet<_> = report.plan.iter().map(|p| p.strategy).collect();
        assert_eq!(
            strategies,
            BTreeSet::from([
                Strategy::Cmake,
                Strategy::Meson,
                Strategy::Autotools,
                Strategy::Make
            ])
        );
    }

    #[test]
    fn marker_confidence_values() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        );
        write(tmp.path(), "build.rs", "");
        let report = detect(&discover(tmp.path()));
        let cargo = report
            .signals
            .iter()
            .find(|s| s.marker == Path::new("Cargo.toml"))
            .unwrap();
        assert_eq!(cargo.confidence.value(), 90);
        let build = report
            .signals
            .iter()
            .find(|s| s.marker == Path::new("build.rs"))
            .unwrap();
        assert_eq!(build.confidence.value(), 70);
    }

    #[test]
    fn detection_is_deterministic() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n",
        );
        write(
            tmp.path(),
            "crates/a/Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
        );
        write(
            tmp.path(),
            "crates/b/Cargo.toml",
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\n",
        );
        write(tmp.path(), "package.json", "{}");
        let first = detect(&discover(tmp.path()));
        let second = detect(&discover(tmp.path()));
        assert_eq!(first, second);
        let markers: Vec<_> = first.signals.iter().map(|s| s.marker.clone()).collect();
        let mut sorted = markers.clone();
        sorted.sort();
        assert_eq!(markers, sorted);
    }

    #[test]
    fn analyzer_registry_detect() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        );
        write(tmp.path(), "CMakeLists.txt", "");
        let tree = discover(tmp.path());
        let cargo = CargoAnalyzer;
        let cpp = CppAnalyzer;
        assert_eq!(cargo.id(), AnalyzerId::Cargo);
        assert_eq!(cpp.id(), AnalyzerId::Cpp);
        assert_eq!(cargo.detect(&tree).value(), 90);
        assert_eq!(cpp.detect(&tree).value(), 90);
        assert_eq!(cargo.detect(&tree).tier(), ConfidenceTier::L4);
        assert_eq!(CppAnalyzer.detect(&discover(tmp.path())).value(), 90);
    }

    #[test]
    fn empty_tree_yields_empty_report() {
        let tmp = tempfile::tempdir().unwrap();
        let report = detect(&discover(tmp.path()));
        assert!(report.signals.is_empty());
        assert!(report.roots.is_empty());
        assert!(report.plan.is_empty());
    }
}

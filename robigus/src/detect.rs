//! Project detection and the in-memory [`ProjectTree`] (spec §7.3, §7.5).
//!
//! Detection is pure marker inspection: [`ProjectTree::discover`] performs the
//! single I/O-heavy walk (via the `ignore` crate, honoring its default rules
//! plus the §7.3 skip list), and [`detect`] turns the resulting tree into a
//! deterministic [`DetectionReport`] with no further I/O. [`ProjectAnalyzer`]
//! is the analyzer registry seam; its `detect` method is synchronous by design
//! (§6.2).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

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
    members: Vec<String>,
    exclude: Vec<String>,
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
    if let Some(members) = workspace
        .get("members")
        .and_then(|item| item.as_value())
        .and_then(|value| value.as_array())
    {
        manifest.members = members
            .iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect();
    }
    if let Some(exclude) = workspace
        .get("exclude")
        .and_then(|item| item.as_value())
        .and_then(|value| value.as_array())
    {
        manifest.exclude = exclude
            .iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect();
    }
    manifest
}

/// True when `dir` is a member of an ancestor workspace (spec §7.3): some
/// strictly-ancestor `Cargo.toml` declares `[workspace]` whose `members` globs
/// match `dir` and whose `exclude` globs do not.
fn is_reachable(tree: &ProjectTree, dir: &Path) -> bool {
    for (ancestor, manifest) in &tree.cargo_manifests {
        if ancestor.as_path() == dir || !manifest.is_workspace {
            continue;
        }
        if !dir.starts_with(ancestor) {
            continue;
        }
        let rel = dir.strip_prefix(ancestor).unwrap_or(dir).to_string_lossy();
        let is_member = manifest.members.iter().any(|m| glob_matches(m, &rel));
        let is_excluded = manifest.exclude.iter().any(|m| glob_matches(m, &rel));
        if is_member && !is_excluded {
            return true;
        }
    }
    false
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    glob::Pattern::new(pattern)
        .map(|p| p.matches_path(Path::new(path)))
        .unwrap_or(false)
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
/// Deterministic: every field of the returned report is sorted. The top level
/// is a root whenever it directly contains a marker; Cargo packages/workspaces
/// in subdirectories are separate roots only when they are not reachable from
/// an ancestor workspace; `vendor/` is skipped entirely so vendored crates are
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

    for dir in tree.cargo_manifests.keys() {
        if dir.as_os_str().is_empty() || !is_reachable(tree, dir) {
            root_map
                .entry(dir.clone())
                .or_default()
                .entry(AnalyzerId::Cargo)
                .or_default()
                .insert(Strategy::Manifest);
        }
    }

    // Attach every marker to its owning root, creating a new root when no
    // ancestor root exists yet.
    for signal in &signals {
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

    #[test]
    fn nested_workspace_non_member_is_a_root() {
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
            "standalone/Cargo.toml",
            "[package]\nname = \"s\"\nversion = \"0.1.0\"\n",
        );
        let report = detect(&discover(tmp.path()));
        assert_eq!(
            root_paths(&report),
            vec![Path::new(""), Path::new("standalone")]
        );
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

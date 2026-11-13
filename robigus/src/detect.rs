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
use serde::{Deserialize, Serialize};

pub use crate::model::Confidence;
use crate::model::{AnalysisStrategy, AnalyzerId, BuildSystem, PlanRow, PlanStatus, PlanSubject};

/// One marker file and the analyzer (and, for C/C++ and `build.rs`, the build
/// system) it signals (spec §7.3).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DetectionSignal {
    /// Workspace-relative marker path.
    pub marker: PathBuf,
    pub analyzer: AnalyzerId,
    pub build_system: Option<BuildSystem>,
    pub confidence: Confidence,
}

/// A detected analysis entry point: a directory that is analyzed as one unit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProjectRoot {
    /// Workspace-relative directory (empty for the top level).
    pub path: PathBuf,
    /// Analyzers that apply to this root.
    pub analyzers: BTreeSet<AnalyzerId>,
}

/// The result of [`detect`]: signals, roots, and plan rows, each sorted for
/// determinism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionReport {
    pub signals: Vec<DetectionSignal>,
    pub roots: Vec<ProjectRoot>,
    /// Cargo packages inside a root that are neither workspace members nor
    /// separate roots (test fixtures, examples, …). Recorded so the report
    /// shows what was seen, but not analyzed as roots (spec §7.3).
    pub non_member_crates: Vec<PathBuf>,
    /// Root-keyed plan rows ([`PlanSubject::Root`]), ready for
    /// `Store::upsert_plan_rows`. Shipped analyzers are `Pending`; future
    /// ecosystems are `Skipped`.
    pub plan: Vec<PlanRow>,
    /// What detection can infer about the project (spec §7.4).
    pub characteristics: ProjectCharacteristics,
    /// Problems that may make this report incomplete, sorted.
    pub diagnostics: Vec<DetectionDiagnostic>,
}

/// Limits applied to the [`ProjectTree`] walk. The defaults bound a hostile
/// or pathological tree while covering large monorepos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectionLimits {
    /// Maximum directory depth to inspect (`None` = unlimited); the root is
    /// depth 0. Reaching the limit is reported as a diagnostic.
    pub max_depth: Option<usize>,
    /// Maximum number of entries walked; exceeding it fails detection with
    /// [`DetectError::LimitExceeded`] rather than silently truncating.
    pub max_entries: u64,
    /// Build descriptions (`Cargo.toml`, `CMakeLists.txt`, `meson.build`)
    /// larger than this are not parsed; a diagnostic is recorded instead.
    pub max_manifest_bytes: u64,
}

impl Default for DetectionLimits {
    fn default() -> Self {
        Self {
            max_depth: Some(64),
            max_entries: 500_000,
            max_manifest_bytes: 1024 * 1024,
        }
    }
}

/// A problem found during detection that did not stop it: a malformed,
/// oversized, or unreadable manifest, an invalid workspace member glob, an
/// unreadable directory, or the depth limit cutting the walk short. Each one
/// means the report may be incomplete for `path`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DetectionDiagnostic {
    /// Workspace-relative path the problem concerns (empty = whole tree).
    pub path: PathBuf,
    pub message: String,
}

/// A programming language seen in the tree, by file extension (spec §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Assembly,
    C,
    Cpp,
    Go,
    /// JavaScript and TypeScript.
    JavaScript,
    Python,
    Rust,
}

fn language_of(filename: &str) -> Option<Language> {
    let (_, extension) = filename.rsplit_once('.')?;
    Some(match extension {
        "rs" => Language::Rust,
        "c" | "h" => Language::C,
        "cc" | "cpp" | "cxx" | "c++" | "hh" | "hpp" | "hxx" => Language::Cpp,
        "s" | "S" | "asm" => Language::Assembly,
        "py" => Language::Python,
        "go" => Language::Go,
        "js" | "mjs" | "cjs" | "ts" | "mts" | "cts" => Language::JavaScript,
        _ => return None,
    })
}

/// A testing system the project uses (spec §7.4), inferred from markers and
/// build descriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestSystem {
    /// Cargo's built-in harness (any Cargo package).
    CargoTest,
    /// CTest: `enable_testing()` or `add_test()` in a `CMakeLists.txt`.
    CTest,
    /// Meson's `test()` in a `meson.build`.
    MesonTest,
    /// pytest: a `conftest.py` or `pytest.ini`.
    Pytest,
    /// Go's `testing` package: a `*_test.go` file.
    GoTest,
}

/// The project characteristics detection can infer from the tree alone
/// (spec §7.4). Target machine architectures and operating systems are not
/// inferable from markers: analyzers record them as predicates on edges
/// (spec §4) during analysis (WP-2.2, WP-3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCharacteristics {
    /// From the top-level Cargo manifest (or the only Cargo root).
    pub name: Option<String>,
    /// From that manifest's `package.version`, or the workspace's
    /// `workspace.package.version` when inherited or virtual.
    pub version: Option<String>,
    pub languages: BTreeSet<Language>,
    /// The ecosystems present; an ecosystem's own build tool (for example
    /// Cargo) is implied by its analyzer.
    pub analyzers: BTreeSet<AnalyzerId>,
    /// The C/C++ build systems and `build.rs` scripts present.
    pub build_systems: BTreeSet<BuildSystem>,
    pub test_systems: BTreeSet<TestSystem>,
}

/// The §7.3 marker table: filename → (analyzer, build system, confidence).
const MARKERS: &[(&str, AnalyzerId, Option<BuildSystem>, u8)] = &[
    ("Cargo.toml", AnalyzerId::Cargo, None, 90),
    (
        "build.rs",
        AnalyzerId::Cargo,
        Some(BuildSystem::BuildScript),
        70,
    ),
    (
        "CMakeLists.txt",
        AnalyzerId::Cpp,
        Some(BuildSystem::Cmake),
        90,
    ),
    ("meson.build", AnalyzerId::Cpp, Some(BuildSystem::Meson), 90),
    (
        "configure.ac",
        AnalyzerId::Cpp,
        Some(BuildSystem::Autotools),
        90,
    ),
    (
        "configure",
        AnalyzerId::Cpp,
        Some(BuildSystem::Autotools),
        80,
    ),
    // Every name GNU make looks for, in its lookup order.
    ("GNUmakefile", AnalyzerId::Cpp, Some(BuildSystem::Make), 70),
    ("makefile", AnalyzerId::Cpp, Some(BuildSystem::Make), 70),
    ("Makefile", AnalyzerId::Cpp, Some(BuildSystem::Make), 70),
    ("pyproject.toml", AnalyzerId::Python, None, 90),
    ("setup.py", AnalyzerId::Python, None, 80),
    ("go.mod", AnalyzerId::Go, None, 90),
    ("package.json", AnalyzerId::Node, None, 90),
];

fn marker_signal(filename: &str) -> Option<(AnalyzerId, Option<BuildSystem>, u8)> {
    MARKERS
        .iter()
        .find(|(name, ..)| *name == filename)
        .map(|(_, analyzer, build_system, confidence)| (*analyzer, *build_system, *confidence))
}

/// Workspace membership and identity info parsed from a `Cargo.toml` (spec
/// §7.3, §7.4).
#[derive(Debug, Clone, Default)]
struct CargoManifest {
    is_workspace: bool,
    /// Normalized `[workspace] members` globs, relative to the manifest's
    /// directory.
    members: Vec<String>,
    /// Normalized `[workspace] exclude` entries. Cargo treats these as path
    /// prefixes, not globs.
    exclude: Vec<PathBuf>,
    package_name: Option<String>,
    /// `package.version` when given literally (not workspace-inherited).
    package_version: Option<String>,
    /// `workspace.package.version`.
    workspace_version: Option<String>,
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
    diagnostics: Vec<DetectionDiagnostic>,
    languages: BTreeSet<Language>,
    test_systems: BTreeSet<TestSystem>,
}

impl ProjectTree {
    /// Walks `root` with the `ignore` crate, honoring its default rules plus
    /// the §7.3 skip list (`target/`, `vendor/`, `node_modules/`, `.git/`) and
    /// `limits`. Out-of-tree ignore files (parent `.gitignore`s and the user's
    /// global gitignore) are disabled so detection is reproducible.
    ///
    /// The walk is blocking I/O and runs in `spawn_blocking` (spec §6.2).
    /// Problems that do not prevent detection are recorded as
    /// [`DetectionDiagnostic`]s rather than failing it.
    pub async fn discover(
        root: impl Into<PathBuf>,
        limits: &DetectionLimits,
    ) -> Result<Self, DetectError> {
        let root = root.into();
        let limits = *limits;
        tokio::task::spawn_blocking(move || Self::discover_blocking(root, &limits))
            .await
            .map_err(|error| DetectError::Walk(format!("detection task failed: {error}")))?
    }

    /// The blocking walk behind [`ProjectTree::discover`].
    pub(crate) fn discover_blocking(
        root: impl Into<PathBuf>,
        limits: &DetectionLimits,
    ) -> Result<Self, DetectError> {
        let root = root.into();
        if !root.is_dir() {
            return Err(DetectError::Walk(format!(
                "'{}' is not a directory",
                root.display()
            )));
        }
        let mut tree = Self {
            root: root.clone(),
            markers: Vec::new(),
            cargo_manifests: BTreeMap::new(),
            diagnostics: Vec::new(),
            languages: BTreeSet::new(),
            test_systems: BTreeSet::new(),
        };
        let relative = |path: &Path| path.strip_prefix(&root).unwrap_or(path).to_path_buf();

        let mut builder = WalkBuilder::new(&root);
        builder
            .standard_filters(true)
            .parents(false)
            .git_global(false)
            // `.gitignore` rules apply even when no `.git` directory exists
            // (a tarball may ship `.gitignore` without a repository).
            .require_git(false)
            // One level past the limit, so reaching it can be reported.
            .max_depth(limits.max_depth.map(|depth| depth + 1))
            .filter_entry(|entry| {
                let name = entry.file_name().to_string_lossy();
                !matches!(name.as_ref(), "target" | "vendor" | "node_modules" | ".git")
            });

        let mut entries: u64 = 0;
        let mut depth_limited = false;
        for result in builder.build() {
            let entry = match result {
                Ok(entry) => entry,
                Err(error) => {
                    let path = match &error {
                        ignore::Error::WithPath { path, .. } => relative(path),
                        _ => PathBuf::new(),
                    };
                    tree.diagnose(path, format!("could not be read: {error}"));
                    continue;
                }
            };
            if entry.depth() == 0 {
                continue;
            }
            entries += 1;
            if entries > limits.max_entries {
                return Err(DetectError::LimitExceeded(format!(
                    "more than {} entries under '{}'",
                    limits.max_entries,
                    root.display()
                )));
            }
            if limits.max_depth.is_some_and(|max| entry.depth() > max) {
                depth_limited = true;
                continue;
            }
            if !entry
                .file_type()
                .is_some_and(|file_type| file_type.is_file())
            {
                continue;
            }
            let rel = relative(entry.path());
            let Some(filename) = rel.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if let Some(language) = language_of(filename) {
                tree.languages.insert(language);
            }
            if filename == "conftest.py" || filename == "pytest.ini" {
                tree.test_systems.insert(TestSystem::Pytest);
            }
            if filename.ends_with("_test.go") {
                tree.test_systems.insert(TestSystem::GoTest);
            }
            if marker_signal(filename).is_none() {
                continue;
            }
            tree.markers.push(rel.clone());
            match filename {
                "Cargo.toml" => {
                    tree.test_systems.insert(TestSystem::CargoTest);
                    let dir = rel.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
                    let manifest = match read_bounded(entry.path(), limits.max_manifest_bytes) {
                        Ok(content) => {
                            let (manifest, problems) = parse_cargo_manifest(&content);
                            for problem in problems {
                                tree.diagnose(rel.clone(), problem);
                            }
                            manifest
                        }
                        Err(problem) => {
                            tree.diagnose(rel.clone(), problem);
                            CargoManifest::default()
                        }
                    };
                    tree.cargo_manifests.insert(dir, manifest);
                }
                "CMakeLists.txt" | "meson.build" => {
                    match read_bounded(entry.path(), limits.max_manifest_bytes) {
                        Ok(content) if filename == "CMakeLists.txt" => {
                            let lower = content.to_ascii_lowercase();
                            if has_call(&lower, "enable_testing") || has_call(&lower, "add_test") {
                                tree.test_systems.insert(TestSystem::CTest);
                            }
                        }
                        Ok(content) => {
                            if has_call(&content, "test") {
                                tree.test_systems.insert(TestSystem::MesonTest);
                            }
                        }
                        Err(problem) => tree.diagnose(rel.clone(), problem),
                    }
                }
                _ => {}
            }
        }
        if depth_limited {
            let max = limits.max_depth.unwrap_or_default();
            tree.diagnose(
                PathBuf::new(),
                format!(
                    "directory depth limit of {max} reached; deeper entries were not inspected"
                ),
            );
        }

        tree.markers.sort();
        tree.markers.dedup();
        tree.diagnostics.sort();
        Ok(tree)
    }

    fn diagnose(&mut self, path: PathBuf, message: String) {
        self.diagnostics.push(DetectionDiagnostic { path, message });
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
        self.markers
            .binary_search_by(|m| m.as_path().cmp(rel))
            .is_ok()
    }

    /// The number of marker files found.
    pub fn marker_count(&self) -> usize {
        self.markers.len()
    }

    /// Problems recorded during the walk, sorted.
    pub fn diagnostics(&self) -> &[DetectionDiagnostic] {
        &self.diagnostics
    }
}

/// Reads a build description no larger than `max_bytes`; the error is a
/// diagnostic message.
fn read_bounded(path: &Path, max_bytes: u64) -> Result<String, String> {
    let size = std::fs::metadata(path)
        .map_err(|error| format!("could not be read: {error}"))?
        .len();
    if size > max_bytes {
        return Err(format!(
            "is {size} bytes, over the {max_bytes}-byte limit; not parsed"
        ));
    }
    std::fs::read_to_string(path).map_err(|error| format!("could not be read: {error}"))
}

/// True when `text` contains a call `name(` (optionally with whitespace
/// before the parenthesis) not preceded by an identifier character, so
/// `test(` matches but `my_test(` does not.
fn has_call(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(start, _)| {
        let before_ok = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        let after = text[start + name.len()..].trim_start_matches([' ', '\t']);
        before_ok && after.starts_with('(')
    })
}

/// Parses the workspace and identity fields of a `Cargo.toml`. Returns the
/// manifest plus diagnostic messages; a malformed manifest yields a plain
/// (non-workspace) package entry, so its directory is still known to be a
/// Cargo package.
fn parse_cargo_manifest(content: &str) -> (CargoManifest, Vec<String>) {
    let mut manifest = CargoManifest::default();
    let mut problems = Vec::new();
    let doc = match content.parse::<toml_edit::DocumentMut>() {
        Ok(doc) => doc,
        Err(error) => {
            problems.push(format!(
                "malformed Cargo.toml; treated as a plain package: {}",
                error.to_string().trim()
            ));
            return (manifest, problems);
        }
    };
    let string_at = |table: Option<&toml_edit::Item>, key: &str| {
        table
            .and_then(|item| item.get(key))
            .and_then(|item| item.as_str())
            .map(str::to_owned)
    };
    manifest.package_name = string_at(doc.get("package"), "name");
    manifest.package_version = string_at(doc.get("package"), "version");
    manifest.workspace_version = string_at(
        doc.get("workspace")
            .and_then(|workspace| workspace.get("package")),
        "version",
    );

    let Some(workspace) = doc.get("workspace").and_then(|item| item.as_table()) else {
        return (manifest, problems);
    };
    manifest.is_workspace = true;
    let mut entries = |key: &str| -> Vec<String> {
        workspace
            .get(key)
            .and_then(|item| item.as_value())
            .and_then(|value| value.as_array())
            .map(|array| {
                array
                    .iter()
                    .filter_map(|value| value.as_str())
                    .filter_map(|entry| {
                        let normalized = normalize_workspace_entry(entry);
                        // `.` names the workspace directory itself.
                        let is_self = Path::new(entry)
                            .components()
                            .all(|component| component == Component::CurDir);
                        if normalized.is_none() && !is_self {
                            problems.push(format!(
                                "workspace {key} entry '{entry}' is absolute or outside the \
                                 workspace; ignored"
                            ));
                        }
                        normalized
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    manifest.members = entries("members");
    manifest.exclude = entries("exclude").into_iter().map(PathBuf::from).collect();
    for member in &manifest.members {
        if let Err(error) = glob::Pattern::new(member) {
            problems.push(format!(
                "workspace member glob '{member}' is invalid and matches nothing: {error}"
            ));
        }
    }
    (manifest, problems)
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

/// Detected roots: directory → analyzer → build systems (`None` = the
/// analyzer's own manifest, with no build system).
type RootMap = BTreeMap<PathBuf, BTreeMap<AnalyzerId, BTreeSet<Option<BuildSystem>>>>;

/// The deepest root that is an ancestor of (or equal to) `dir`.
fn nearest_root(root_map: &RootMap, dir: &Path) -> Option<PathBuf> {
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
            let (analyzer, build_system, confidence) = marker_signal(filename)?;
            Some(DetectionSignal {
                marker: marker.clone(),
                analyzer,
                build_system,
                confidence: Confidence::new(confidence),
            })
        })
        .collect();
    signals.sort();

    let mut root_map = RootMap::new();

    let (cargo_root_dirs, non_member_crates) = cargo_roots(tree);
    let characteristics = project_characteristics(tree, &signals, &cargo_root_dirs);
    for dir in cargo_root_dirs {
        root_map
            .entry(dir)
            .or_default()
            .entry(AnalyzerId::Cargo)
            .or_default()
            .insert(None);
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
        let root = nearest_root(&root_map, &dir).unwrap_or(dir);
        root_map
            .entry(root)
            .or_default()
            .entry(signal.analyzer)
            .or_default()
            .insert(signal.build_system);
    }

    let mut roots = Vec::new();
    let mut plan = Vec::new();
    for (path, analyzers) in root_map {
        roots.push(ProjectRoot {
            path: path.clone(),
            analyzers: analyzers.keys().copied().collect(),
        });
        for (analyzer, build_systems) in analyzers {
            let status = if analyzer.is_shipped() {
                PlanStatus::Pending
            } else {
                PlanStatus::Skipped
            };
            // Detection proposes the §7.6 manifest strategy (static parsing
            // of the manifests and build descriptions it found); expansion
            // (WP-2.3) adds tool-introspection, build-observation, and
            // validation rows per node.
            for build_system in build_systems {
                plan.push(PlanRow::new(
                    PlanSubject::Root(path.clone()),
                    analyzer,
                    AnalysisStrategy::Manifest,
                    build_system,
                    status,
                ));
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
        characteristics,
        diagnostics: tree.diagnostics.clone(),
    }
}

/// Infers the §7.4 characteristics. The name and version come from the
/// top-level Cargo manifest, or from the only Cargo root when the top level
/// is not a Cargo package.
fn project_characteristics(
    tree: &ProjectTree,
    signals: &[DetectionSignal],
    cargo_root_dirs: &BTreeSet<PathBuf>,
) -> ProjectCharacteristics {
    let identity_manifest = tree.cargo_manifests.get(Path::new("")).or_else(|| {
        let mut roots = cargo_root_dirs.iter();
        match (roots.next(), roots.next()) {
            (Some(only), None) => tree.cargo_manifests.get(only),
            _ => None,
        }
    });
    ProjectCharacteristics {
        name: identity_manifest.and_then(|manifest| manifest.package_name.clone()),
        version: identity_manifest.and_then(|manifest| {
            manifest
                .package_version
                .clone()
                .or_else(|| manifest.workspace_version.clone())
        }),
        languages: tree.languages.clone(),
        analyzers: signals.iter().map(|signal| signal.analyzer).collect(),
        build_systems: signals
            .iter()
            .filter_map(|signal| signal.build_system)
            .collect(),
        test_systems: tree.test_systems.clone(),
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
    use crate::model::ConfidenceTier;
    use std::fs;

    fn write(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn discover(root: &Path) -> ProjectTree {
        ProjectTree::discover_blocking(root, &DetectionLimits::default()).unwrap()
    }

    fn with_depth(max_depth: usize) -> DetectionLimits {
        DetectionLimits {
            max_depth: Some(max_depth),
            ..DetectionLimits::default()
        }
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
        let deep = ProjectTree::discover_blocking(tmp.path(), &with_depth(2)).unwrap();
        assert!(deep.markers().is_empty());
        // Reaching the limit is reported, not silent.
        assert!(
            deep.diagnostics()
                .iter()
                .any(|d| d.message.contains("depth limit of 2")),
            "{:?}",
            deep.diagnostics()
        );
        let shallow = ProjectTree::discover_blocking(tmp.path(), &with_depth(4)).unwrap();
        assert_eq!(shallow.markers().len(), 1);
        assert!(shallow.diagnostics().is_empty());
    }

    #[test]
    fn default_limits_are_bounded() {
        let limits = DetectionLimits::default();
        assert_eq!(limits.max_depth, Some(64));
        assert!(limits.max_entries > 0);
        assert!(limits.max_manifest_bytes > 0);
    }

    #[test]
    fn entry_limit_fails_detection() {
        let tmp = tempfile::tempdir().unwrap();
        for index in 0..5 {
            write(tmp.path(), &format!("f{index}.txt"), "");
        }
        let limits = DetectionLimits {
            max_entries: 3,
            ..DetectionLimits::default()
        };
        let error = ProjectTree::discover_blocking(tmp.path(), &limits).unwrap_err();
        assert!(matches!(error, DetectError::LimitExceeded(_)), "{error}");
    }

    #[tokio::test]
    async fn discover_runs_off_the_async_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "Cargo.toml", PACKAGE);
        let tree = ProjectTree::discover(tmp.path(), &DetectionLimits::default())
            .await
            .unwrap();
        assert_eq!(tree.markers(), [PathBuf::from("Cargo.toml")]);
        let error = ProjectTree::discover(tmp.path().join("missing"), &DetectionLimits::default())
            .await
            .unwrap_err();
        assert!(matches!(error, DetectError::Walk(_)));
    }

    /// Regression (Medium): a malformed top-level workspace manifest is
    /// reported instead of silently changing the roots; its members fall back
    /// to non-member crates rather than becoming separate roots.
    #[test]
    fn malformed_manifest_is_a_diagnostic() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "Cargo.toml", "[workspace\nmembers = [\"a\"]\n");
        write(tmp.path(), "a/Cargo.toml", PACKAGE);
        let report = detect(&discover(tmp.path()));
        assert_eq!(root_paths(&report), vec![Path::new("")]);
        assert_eq!(report.non_member_crates, vec![PathBuf::from("a")]);
        assert_eq!(report.diagnostics.len(), 1, "{:?}", report.diagnostics);
        assert_eq!(report.diagnostics[0].path, Path::new("Cargo.toml"));
        assert!(
            report.diagnostics[0]
                .message
                .contains("malformed Cargo.toml")
        );
    }

    #[test]
    fn oversized_and_unreadable_manifests_are_diagnostics() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            &format!("{PACKAGE}# {}\n", "x".repeat(256)),
        );
        fs::write(tmp.path().join("CMakeLists.txt"), [0xff, 0xfe, 0x00]).unwrap();
        let limits = DetectionLimits {
            max_manifest_bytes: 128,
            ..DetectionLimits::default()
        };
        let report = detect(&ProjectTree::discover_blocking(tmp.path(), &limits).unwrap());
        let paths: Vec<_> = report.diagnostics.iter().map(|d| d.path.clone()).collect();
        assert_eq!(
            paths,
            vec![PathBuf::from("CMakeLists.txt"), PathBuf::from("Cargo.toml")]
        );
        assert!(
            report.diagnostics[1]
                .message
                .contains("over the 128-byte limit")
        );
        // The markers are still detected.
        assert_eq!(report.signals.len(), 2);
    }

    #[test]
    fn invalid_and_escaping_workspace_entries_are_diagnostics() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/[\", \"../outside\", \".\"]\n",
        );
        let report = detect(&discover(tmp.path()));
        let messages: Vec<_> = report
            .diagnostics
            .iter()
            .map(|d| d.message.as_str())
            .collect();
        assert_eq!(messages.len(), 2, "{messages:?}");
        assert!(messages.iter().any(|m| m.contains("'../outside'")));
        assert!(messages.iter().any(|m| m.contains("glob 'crates/['")));
    }

    /// Medium (§7.4): name, version, languages, build systems, and test
    /// systems inferred from the tree.
    #[test]
    fn characteristics_are_inferred() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion.workspace = true\n\n\
             [workspace]\nmembers = [\"crates/*\"]\n\n[workspace.package]\nversion = \"2.1.0\"\n",
        );
        write(tmp.path(), "src/lib.rs", "");
        write(tmp.path(), "build.rs", "");
        write(tmp.path(), "native/codec.c", "");
        write(tmp.path(), "native/simd.S", "");
        write(
            tmp.path(),
            "native/CMakeLists.txt",
            "project(c)\nENABLE_TESTING()\n",
        );
        write(
            tmp.path(),
            "tools/meson.build",
            "project('t')\nmy_test('x')\n",
        );
        write(tmp.path(), "bindings/conftest.py", "");
        let report = detect(&discover(tmp.path()));
        let characteristics = &report.characteristics;
        assert_eq!(characteristics.name.as_deref(), Some("demo"));
        assert_eq!(characteristics.version.as_deref(), Some("2.1.0"));
        assert_eq!(
            characteristics.languages,
            BTreeSet::from([
                Language::Assembly,
                Language::C,
                Language::Python,
                Language::Rust
            ])
        );
        assert_eq!(
            characteristics.analyzers,
            BTreeSet::from([AnalyzerId::Cargo, AnalyzerId::Cpp])
        );
        assert_eq!(
            characteristics.build_systems,
            BTreeSet::from([
                BuildSystem::BuildScript,
                BuildSystem::Cmake,
                BuildSystem::Meson
            ])
        );
        // `my_test(` is not Meson's `test(`; CMake commands are case-insensitive.
        assert_eq!(
            characteristics.test_systems,
            BTreeSet::from([TestSystem::CargoTest, TestSystem::CTest, TestSystem::Pytest])
        );
    }

    #[test]
    fn has_call_matches_whole_identifiers() {
        assert!(has_call("test('a')", "test"));
        assert!(has_call("x = test ('a')", "test"));
        assert!(!has_call("my_test('a')", "test"));
        assert!(!has_call("tests = 1", "test"));
        assert!(has_call("if(x)\n  add_test(NAME a)", "add_test"));
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
        let build_systems: BTreeSet<_> = report
            .plan
            .iter()
            .filter(|p| p.analyzer == AnalyzerId::Cargo)
            .map(|p| p.build_system)
            .collect();
        assert_eq!(
            build_systems,
            BTreeSet::from([None, Some(BuildSystem::BuildScript)])
        );
    }

    /// Detection plan rows are root-keyed and use the §7.6 manifest strategy,
    /// with the build system in its own field (High 3).
    #[test]
    fn plan_rows_are_root_keyed_manifest_rows() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "Cargo.toml", PACKAGE);
        write(tmp.path(), "native/CMakeLists.txt", "");
        write(tmp.path(), "py/pyproject.toml", "");
        let report = detect(&discover(tmp.path()));
        assert!(!report.plan.is_empty());
        for row in &report.plan {
            assert_eq!(row.subject, PlanSubject::Root(PathBuf::new()));
            assert_eq!(row.strategy, AnalysisStrategy::Manifest);
            assert_eq!(row.attempts, 0);
        }
        let cmake = report
            .plan
            .iter()
            .find(|row| row.build_system == Some(BuildSystem::Cmake))
            .expect("cmake row");
        assert_eq!(cmake.analyzer, AnalyzerId::Cpp);
        assert_eq!(cmake.status, PlanStatus::Pending);
        let python = report
            .plan
            .iter()
            .find(|row| row.analyzer == AnalyzerId::Python)
            .expect("python row");
        assert_eq!(python.status, PlanStatus::Skipped);
        assert_eq!(python.build_system, None);
    }

    #[test]
    fn every_make_spelling_is_detected() {
        for name in ["GNUmakefile", "makefile", "Makefile"] {
            let tmp = tempfile::tempdir().unwrap();
            write(tmp.path(), name, "all:\n");
            let report = detect(&discover(tmp.path()));
            assert_eq!(report.signals.len(), 1, "{name}");
            assert_eq!(report.signals[0].build_system, Some(BuildSystem::Make));
        }
    }

    /// The report serializes for `print`/`export` and round-trips.
    #[test]
    fn detection_report_round_trips_through_json() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            tmp.path(),
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        );
        write(tmp.path(), "src/lib.rs", "");
        write(tmp.path(), "CMakeLists.txt", "add_test(NAME a)\n");
        write(tmp.path(), "broken/Cargo.toml", "[package\n");
        let report = detect(&discover(tmp.path()));
        assert!(!report.diagnostics.is_empty());
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            json.contains("\"confidence\":90"),
            "confidence is a plain number: {json}"
        );
        assert!(json.contains("\"c_test\""));
        let back: DetectionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
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
        let build_systems: BTreeSet<_> = report.plan.iter().map(|p| p.build_system).collect();
        assert_eq!(
            build_systems,
            BTreeSet::from([
                Some(BuildSystem::Cmake),
                Some(BuildSystem::Meson),
                Some(BuildSystem::Autotools),
                Some(BuildSystem::Make)
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

//! robigus: dependency graph analysis for planning Ubuntu packaging of
//! upstream software (spec §1).
//!
//! Phase 1 discovers and persists the complete transitive dependency graph of
//! a target software project. Ubuntu archive mapping and packaging plans are
//! Phase 2/3.

// Spec §18: the only permitted exception will be a narrowly scoped
// `#[allow(unsafe_code)]` inside `sandbox.rs` for the native backend (M3),
// at which point this becomes `deny`.
#![forbid(unsafe_code)]
// Spec §18: every public API is documented; CI denies warnings, so a new
// undocumented public item fails the build.
#![warn(missing_docs)]

pub mod detect;
pub mod dpkg;
pub mod error;
pub mod export;
pub mod feature;
pub mod fetch;
pub mod model;
pub mod predicate;
pub mod sandbox;
#[cfg(target_os = "linux")]
mod sandbox_seccomp;
pub mod solver;
pub mod store;

pub use detect::{
    CargoAnalyzer, Confidence, CppAnalyzer, DetectionDiagnostic, DetectionLimits, DetectionReport,
    DetectionSignal, Language, ProjectAnalyzer, ProjectCharacteristics, ProjectRoot, ProjectTree,
    TestSystem, analyzers, detect,
};
pub use error::{
    DetectError, DpkgError, FetchError, InvalidHost, PredicateError, RobigusError, SandboxAttempt,
    SandboxUnavailable, StoreError,
};
pub use feature::{FeatureExpr, FeatureExprError};
pub use fetch::{
    Cache, DownloadLimits, ExtractionLimits, FetchOptions, FetchedSource, GitOptions, IndexRecord,
    Provenance, RegistryClient, SourceInput, fetch_offline,
};
pub use model::{
    AnalysisStatus, AnalysisStrategy, AnalyzerId, BuildSystem, ConfidenceTier, Conflict,
    Dependency, DependencyGraph, DependencyKind, Edge, Evidence, EvidenceMethod, MachineArch, Node,
    PackageId, PlanRow, PlanStatus, PlanSubject, Provide, Requirement, RequirementKind, SourceId,
    SourceKind, Target, TargetKind, VersionConstraint, path_tree_digest,
};
pub use predicate::{Atom, Configuration, DEFAULT_DNF_TERM_CAP, DnfError, Evaluator, Predicate};
pub use sandbox::proxy::{Allowlist, DEFAULT_ALLOWLIST, HostName, ProxyPolicy};
pub use sandbox::{
    CommandSpec, NetworkAccess, ProcessOutput, ProcessStatus, Sandbox, SandboxError, SandboxMode,
    SandboxPreference, establish_sandbox,
};
pub use store::{
    Analysis, AnalysisMetadata, AnalysisSnapshot, IntegrityReport, SnapshotEdge,
    SnapshotInvocation, SnapshotNode, SnapshotPlan, Store, ToolInvocation,
};

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

pub mod detect;
pub mod dpkg;
pub mod error;
pub mod feature;
pub mod fetch;
pub mod model;
pub mod predicate;
pub mod solver;
pub mod store;

pub use detect::{
    CargoAnalyzer, Confidence, CppAnalyzer, DetectionDiagnostic, DetectionLimits, DetectionReport,
    DetectionSignal, Language, ProjectAnalyzer, ProjectCharacteristics, ProjectRoot, ProjectTree,
    TestSystem, analyzers, detect,
};
pub use error::{
    DetectError, DpkgError, FetchError, PredicateError, RobigusError, SandboxAttempt,
    SandboxUnavailable, StoreError,
};
pub use feature::{FeatureExpr, FeatureExprError};
pub use fetch::{
    Cache, DownloadLimits, ExtractionLimits, FetchOptions, FetchedSource, GitOptions, IndexRecord,
    Provenance, RegistryClient, SourceInput,
};
pub use model::{
    AnalysisStatus, AnalysisStrategy, AnalyzerId, BuildSystem, ConfidenceTier, Conflict,
    Dependency, DependencyGraph, DependencyKind, Edge, Evidence, EvidenceMethod, MachineArch, Node,
    PackageId, PlanRow, PlanStatus, PlanSubject, Provide, Requirement, RequirementKind, SourceId,
    SourceKind, Target, TargetKind, VersionConstraint, path_tree_digest,
};
pub use predicate::{Atom, Configuration, DEFAULT_DNF_TERM_CAP, DnfError, Evaluator, Predicate};
pub use store::{Analysis, AnalysisMetadata, IntegrityReport, Store, ToolInvocation};

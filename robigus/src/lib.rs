//! robigus: dependency graph analysis for planning Ubuntu packaging of
//! upstream software (spec §1).
//!
//! Phase 1 discovers and persists the complete transitive dependency graph of
//! a target software project. Ubuntu archive mapping and packaging plans are
//! Phase 2/3.

pub mod dpkg;
pub mod error;
pub mod feature;
pub mod model;
pub mod predicate;
pub mod solver;

pub use error::{
    DpkgError, FetchError, PredicateError, RobigusError, SandboxAttempt, SandboxUnavailable,
    StoreError,
};
pub use feature::{FeatureExpr, FeatureExprError};
pub use model::{
    AnalysisStatus, ConfidenceTier, Conflict, Dependency, DependencyGraph, DependencyKind, Edge,
    Evidence, EvidenceMethod, MachineArch, Node, PackageId, Provide, Requirement, RequirementKind,
    SourceId, SourceKind, Target, TargetKind, VersionConstraint, path_tree_digest,
};
pub use predicate::{Atom, Predicate};

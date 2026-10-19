//! The `rapt` library: pure async Rust client and wrappers for querying the Ubuntu archive.

pub mod archive;
pub mod cache;
pub mod cli;
pub mod error;
pub mod models;
pub mod parser;
pub mod query;
pub mod types;

pub use archive::{ArchiveClient, DEFAULT_ARCHIVE_URL, DEFAULT_PORTS_URL};
pub use cache::CacheManager;
pub use cli::{Cli, Commands};
pub use error::{RaptError, Result};
pub use models::{
    BinaryPackage, CacheStats, DependencyClause, DependencyGroup, DependencyItem, DependencyType,
    PackageOrigin, ProvideItem, SeriesCache, SourcePackage,
};
pub use query::RaptQuery;
pub use types::{Architecture, Component, PackageTarget, Pocket, QueryFilter, QueryFilterBuilder};

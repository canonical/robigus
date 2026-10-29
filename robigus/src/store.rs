//! SQLite persistence for one analysis (spec §11, §15).
//!
//! One database is created per analysis; the database is the source of truth
//! and supports resumable expansion (§7.7). All SQLite work runs inside
//! `tokio::task::spawn_blocking` on a shared connection behind a mutex —
//! the §11.1 alternative to `tokio-rusqlite`, which is unused because no
//! released version pairs with an MSRV-compatible `rusqlite_migration`.
//! Reads (`load`, `check`) run inside a deferred transaction so WAL readers
//! see one consistent snapshot while an analysis writes.

use crate::error::StoreError;
use crate::model::{
    AnalysisStatus, Conflict, DependencyGraph, DependencyKind, Ecosystem, Edge, Evidence,
    GitReference, Node, PackageId, PackageVersion, Provide, Requirement, RequirementKind, SourceId,
    SourceKind, Target, TargetKind, VersionConstraint,
};
use crate::predicate::{Configuration, Predicate};
use chrono::Utc;
use rusqlite::params;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use url::Url;

mod migrations;
mod schema;

/// One analysis: the persisted metadata plus the rebuilt dependency graph
/// (spec §15).
#[derive(Debug, Clone)]
pub struct Analysis {
    pub metadata: AnalysisMetadata,
    pub graph: DependencyGraph,
}

/// The single-row `metadata` table (spec §11.2).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AnalysisMetadata {
    pub robigus_version: String,
    pub project_name: String,
    pub project_version: String,
    pub source_kind: String,
    pub source_uri: String,
    pub source_digest: String,
    pub configuration: Configuration,
    /// Tool name → version, recorded for reproducibility (spec §10.2).
    pub toolchain: BTreeMap<String, String>,
    /// `'allowlist'` or `'offline'` (spec §10.2).
    pub network_mode: String,
    /// `'bwrap'` or `'native'` (spec §10.2).
    pub sandbox_mode: String,
    /// The applied analysis options as JSON; typed when the `analyze`
    /// command lands (WP-2.3).
    pub options: serde_json::Value,
    pub created_at: String,
    pub updated_at: String,
}

/// One recorded tool execution (spec §10.2, §11.2). `argv` and `env` are
/// scrubbed by the caller before recording.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ToolInvocation {
    pub package_id: Option<PackageId>,
    pub tool: String,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub tool_version: Option<String>,
    pub sandbox_mode: String,
    pub exit_status: String,
    pub started_at: String,
    pub duration_ms: u64,
    /// Workspace-relative path to the full stdout/stderr capture.
    pub log_path: Option<String>,
}

/// Findings of [`Store::check`] (spec §11.3). Unresolved-requirement counts,
/// cycles, and orphans are informational; the remaining findings are
/// integrity failures.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct IntegrityReport {
    pub schema_version: u32,
    pub foreign_keys_ok: bool,
    pub duplicate_identities: usize,
    pub invalid_json_columns: usize,
    /// Rows whose ecosystem/source-kind cannot be parsed back.
    pub corrupt_identities: usize,
    pub status_violations: Vec<PackageId>,
    pub confidence_violations: Vec<String>,
    pub unresolved_requirements: BTreeMap<RequirementKind, usize>,
    pub cycles: Vec<Vec<PackageId>>,
    pub orphans: Vec<PackageId>,
}

impl IntegrityReport {
    /// True when no integrity failure was found. Informational findings
    /// (cycles, orphans, unresolved requirements) do not affect this.
    pub fn is_ok(&self) -> bool {
        self.foreign_keys_ok
            && self.duplicate_identities == 0
            && self.invalid_json_columns == 0
            && self.corrupt_identities == 0
            && self.status_violations.is_empty()
            && self.confidence_violations.is_empty()
    }
}

/// The SQLite store for one analysis (spec §11, §15). Cheap to clone; clones
/// share one connection behind a mutex, and every operation runs in
/// `spawn_blocking` (spec §6.2, §11.1).
#[derive(Debug, Clone)]
pub struct Store {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

/// The persisted identity columns of a package (spec §11.2).
#[derive(Debug, Clone)]
struct PackageIdentity {
    name: String,
    version: String,
    ecosystem: String,
    source_kind: String,
    source_uri: String,
    source_precise: String,
}

impl PackageIdentity {
    fn of(id: &PackageId) -> Self {
        Self {
            name: id.name.clone(),
            version: id.version.to_string(),
            ecosystem: id.ecosystem.as_str().to_string(),
            source_kind: id.source_id.kind.kind_name().to_string(),
            source_uri: id.source_id.kind.identity_uri(),
            source_precise: id.source_id.precise.clone().unwrap_or_default(),
        }
    }

    fn package_id(&self) -> Result<PackageId, StoreError> {
        let ecosystem = Ecosystem::parse(&self.ecosystem).ok_or_else(|| {
            StoreError::Corrupt(format!("unknown ecosystem '{}'", self.ecosystem))
        })?;
        let source_kind =
            reconstruct_source_kind(&self.source_kind, &self.source_uri, &self.source_precise)?;
        Ok(PackageId {
            name: self.name.clone(),
            version: PackageVersion::from_stored_text(ecosystem, &self.version),
            source_id: SourceId {
                kind: source_kind,
                precise: (!self.source_precise.is_empty()).then(|| self.source_precise.clone()),
            },
            ecosystem,
        })
    }
}

/// Reconstructs a [`SourceKind`] from the persisted identity columns. The
/// git reference is not part of the identity; a pinned revision is restored
/// as the reference. Apt payloads (suite, components, arch) are a Phase 2
/// concern and cannot be reconstructed.
fn reconstruct_source_kind(kind: &str, uri: &str, precise: &str) -> Result<SourceKind, StoreError> {
    let url = |text: &str| {
        Url::parse(text)
            .map_err(|error| StoreError::Corrupt(format!("invalid source URI '{text}': {error}")))
    };
    match kind {
        "cargo-registry" => Ok(SourceKind::CargoRegistry {
            index_url: url(uri)?,
        }),
        "git" => Ok(SourceKind::Git {
            url: url(uri)?,
            reference: if precise.is_empty() {
                GitReference::DefaultBranch
            } else {
                GitReference::Rev(precise.to_string())
            },
        }),
        "path" => Ok(SourceKind::Path {
            path: PathBuf::from(uri),
        }),
        "tarball" => Ok(SourceKind::Tarball {
            url: url(uri)?,
            digest: (!precise.is_empty()).then(|| precise.to_string()),
        }),
        "apt" => Err(StoreError::Corrupt(
            "apt-sourced packages are a Phase 2 concern and cannot be reconstructed".to_string(),
        )),
        other => Err(StoreError::Corrupt(format!(
            "unknown source kind '{other}'"
        ))),
    }
}

/// Locks the shared connection; a poisoned lock is unrecoverable.
fn lock(
    conn: &Mutex<rusqlite::Connection>,
) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, StoreError> {
    conn.lock()
        .map_err(|_| StoreError::Sqlite("database lock poisoned".to_string()))
}

fn join_error(error: tokio::task::JoinError) -> StoreError {
    StoreError::Sqlite(format!("database task failed: {error}"))
}

fn user_version(conn: &rusqlite::Connection) -> u32 {
    conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .unwrap_or(0) as u32
}

fn parse_status(text: &str) -> Result<AnalysisStatus, StoreError> {
    match text {
        "Not_Started" => Ok(AnalysisStatus::NotStarted),
        "Started" => Ok(AnalysisStatus::Started),
        "Complete" => Ok(AnalysisStatus::Complete),
        "Error" => Ok(AnalysisStatus::Error),
        other => Err(StoreError::Corrupt(format!("unknown status '{other}'"))),
    }
}

impl Store {
    /// Opens (creating if needed) the database at `path`, applies pending
    /// migrations, and applies the §11.1 pragmas. Opening a database with a
    /// newer schema version fails with [`StoreError::SchemaTooNew`] (CLI
    /// exit code 3).
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                StoreError::Sqlite(format!("failed to create database directory: {error}"))
            })?;
        }
        let path = path.to_path_buf();
        let conn =
            tokio::task::spawn_blocking(move || -> Result<rusqlite::Connection, StoreError> {
                let mut conn = rusqlite::Connection::open(&path)?;
                let found = user_version(&conn);
                if found > schema::SUPPORTED_SCHEMA_VERSION {
                    return Err(StoreError::SchemaTooNew {
                        found,
                        supported: schema::SUPPORTED_SCHEMA_VERSION,
                    });
                }
                migrations::migrations()
                    .to_latest(&mut conn)
                    .map_err(|error| StoreError::Sqlite(error.to_string()))?;
                conn.execute_batch(schema::PRAGMAS)?;
                Ok(conn)
            })
            .await
            .map_err(join_error)??;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Reads the analysis metadata row, if one has been written.
    pub async fn metadata(&self) -> Result<Option<AnalysisMetadata>, StoreError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = lock(&conn)?;
            let tx = conn.transaction()?;
            let metadata = read_metadata(&tx)?;
            tx.commit()?;
            Ok(metadata)
        })
        .await
        .map_err(join_error)?
    }

    /// Writes the metadata row (upsert). The store stamps `updated_at`;
    /// `created_at` is preserved from an existing row on update.
    pub async fn write_metadata(&self, metadata: &AnalysisMetadata) -> Result<(), StoreError> {
        let metadata = metadata.clone();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = lock(&conn)?;
            let now = Utc::now().to_rfc3339();
            let created_at: Option<String> = conn
                .query_row("SELECT created_at FROM metadata WHERE id = 1", [], |row| {
                    row.get(0)
                })
                .ok();
            let created_at = created_at.unwrap_or(metadata.created_at);
            let configuration = serde_json::to_string(&metadata.configuration)?;
            let toolchain = serde_json::to_string(&metadata.toolchain)?;
            let options = serde_json::to_string(&metadata.options)?;
            conn.execute(
                "INSERT INTO metadata (id, robigus_version, project_name, project_version,
                           source_kind, source_uri, source_digest, configuration, toolchain,
                           network_mode, sandbox_mode, options, created_at, updated_at)
                     VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                     ON CONFLICT (id) DO UPDATE SET
                        robigus_version = excluded.robigus_version,
                        project_name = excluded.project_name,
                        project_version = excluded.project_version,
                        source_kind = excluded.source_kind,
                        source_uri = excluded.source_uri,
                        source_digest = excluded.source_digest,
                        configuration = excluded.configuration,
                        toolchain = excluded.toolchain,
                        network_mode = excluded.network_mode,
                        sandbox_mode = excluded.sandbox_mode,
                        options = excluded.options,
                        updated_at = excluded.updated_at",
                params![
                    metadata.robigus_version,
                    metadata.project_name,
                    metadata.project_version,
                    metadata.source_kind,
                    metadata.source_uri,
                    metadata.source_digest,
                    configuration,
                    toolchain,
                    metadata.network_mode,
                    metadata.sandbox_mode,
                    options,
                    created_at,
                    now,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    /// Inserts a node, or updates `is_root`-independent fields on an
    /// identity conflict: `status`, `active_features`, and `path` are
    /// overwritten; `is_root` is preserved (see [`Store::set_root`]). The
    /// identity is (name, version, ecosystem, source_kind, source_uri,
    /// source_precise).
    pub async fn upsert_node(&self, node: &Node) -> Result<(), StoreError> {
        let identity = PackageIdentity::of(&node.id);
        let status = node.status.as_str().to_string();
        let active_features = serde_json::to_string(&node.active_features)?;
        let path = node
            .path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let targets = node
            .targets
            .iter()
            .map(|target| {
                let soname = match &target.kind {
                    TargetKind::SharedLibrary {
                        soname: Some(soname),
                    } => soname.clone(),
                    _ => String::new(),
                };
                Ok((
                    target.name.clone(),
                    serde_json::to_string(&target.kind)?,
                    soname,
                ))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let provides = node
            .provides
            .iter()
            .map(|provide| {
                Ok((
                    provide.name.clone(),
                    provide
                        .version
                        .as_ref()
                        .map(|version| version.to_string())
                        .unwrap_or_default(),
                ))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let conflicts = node
            .conflicts
            .iter()
            .map(|conflict| {
                Ok((
                    conflict.name.clone(),
                    conflict
                        .version_req
                        .as_ref()
                        .map(|req| req.requirement_text())
                        .unwrap_or_default(),
                ))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = lock(&conn)?;
            let tx = conn.transaction()?;
            // `RETURNING id` yields the affected row on both the insert and
            // the update path. `last_insert_rowid()` must not be used here:
            // SQLite leaves it unchanged when an upsert takes the DO UPDATE
            // branch, so it would name whichever row was inserted last —
            // possibly another package's.
            let package_id: i64 = tx.query_row(
                "INSERT INTO package (name, version, ecosystem, source_kind, source_uri,
                       source_precise, is_root, status, active_features, path)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9)
                 ON CONFLICT (name, version, ecosystem, source_kind, source_uri, source_precise)
                 DO UPDATE SET status = excluded.status,
                               active_features = excluded.active_features,
                               path = excluded.path
                 RETURNING id",
                params![
                    identity.name,
                    identity.version,
                    identity.ecosystem,
                    identity.source_kind,
                    identity.source_uri,
                    identity.source_precise,
                    status,
                    active_features,
                    path,
                ],
                |row| row.get(0),
            )?;
            // The node payload is replaced wholesale, mirroring
            // `DependencyGraph::add_node` (spec §5.1).
            tx.execute(
                "DELETE FROM package_target WHERE package_id = ?1",
                params![package_id],
            )?;
            for (name, kind, soname) in &targets {
                tx.execute(
                    "INSERT INTO package_target (package_id, name, kind, soname)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![package_id, name, kind, soname],
                )?;
            }
            tx.execute(
                "DELETE FROM package_provides WHERE package_id = ?1",
                params![package_id],
            )?;
            for (name, version) in &provides {
                tx.execute(
                    "INSERT INTO package_provides (package_id, name, version)
                     VALUES (?1, ?2, ?3)",
                    params![package_id, name, version],
                )?;
            }
            tx.execute(
                "DELETE FROM package_conflicts WHERE package_id = ?1",
                params![package_id],
            )?;
            for (name, version_req) in &conflicts {
                tx.execute(
                    "INSERT INTO package_conflicts (package_id, name, version_req)
                     VALUES (?1, ?2, ?3)",
                    params![package_id, name, version_req],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    /// Marks or unmarks a package as an analysis root (spec §5.1). Rootness
    /// is graph-level state, so it has its own method.
    pub async fn set_root(&self, package: &PackageId, is_root: bool) -> Result<(), StoreError> {
        let identity = PackageIdentity::of(package);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = lock(&conn)?;
            let updated = conn.execute(
                "UPDATE package SET is_root = ?1
                     WHERE name = ?2 AND version = ?3 AND ecosystem = ?4
                       AND source_kind = ?5 AND source_uri = ?6 AND source_precise = ?7",
                params![
                    is_root,
                    identity.name,
                    identity.version,
                    identity.ecosystem,
                    identity.source_kind,
                    identity.source_uri,
                    identity.source_precise,
                ],
            )?;
            if updated == 0 {
                return Err(StoreError::Corrupt("package not found".to_string()));
            }
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    /// Upserts the edges originating at `from` in one transaction. Edges
    /// with the same identity are merged (union `kinds`, maximum confidence,
    /// merged evidence) rather than duplicated (spec §5.2, §11.2): on a
    /// partial-unique-index violation the existing row is selected, merged
    /// in Rust, and updated — `ON CONFLICT` is not used against partial
    /// indexes.
    pub async fn upsert_edges(&self, from: &PackageId, edges: &[Edge]) -> Result<(), StoreError> {
        for edge in edges {
            if &edge.from != from {
                return Err(StoreError::Corrupt(format!(
                    "edge.from '{}' does not match the from argument '{from}'",
                    edge.from
                )));
            }
        }
        let edges = edges.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = lock(&conn)?;
            let tx = conn.transaction()?;
            for edge in &edges {
                upsert_edge(&tx, edge)?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    /// Updates a node's analysis status, enforcing the §7.7 transitions:
    /// `Not_Started → Started → Complete | Error`, `Error → Started` (retry),
    /// `Complete` terminal. Same-state updates are idempotent no-ops.
    pub async fn update_status(
        &self,
        package: &PackageId,
        status: AnalysisStatus,
    ) -> Result<(), StoreError> {
        let identity = PackageIdentity::of(package);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = lock(&conn)?;
            let current: String = match conn.query_row(
                "SELECT status FROM package
                     WHERE name = ?1 AND version = ?2 AND ecosystem = ?3
                       AND source_kind = ?4 AND source_uri = ?5 AND source_precise = ?6",
                params![
                    identity.name,
                    identity.version,
                    identity.ecosystem,
                    identity.source_kind,
                    identity.source_uri,
                    identity.source_precise,
                ],
                |row| row.get(0),
            ) {
                Ok(status) => status,
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    return Err(StoreError::Corrupt("package not found".to_string()));
                }
                Err(error) => return Err(error.into()),
            };
            if current == status.as_str() {
                return Ok(());
            }
            let allowed = matches!(
                (current.as_str(), status),
                ("Not_Started", AnalysisStatus::Started)
                    | ("Started", AnalysisStatus::Complete | AnalysisStatus::Error)
                    | ("Error", AnalysisStatus::Started)
            );
            if !allowed {
                return Err(StoreError::InvalidTransition {
                    from: current,
                    to: status.as_str().to_string(),
                });
            }
            conn.execute(
                "UPDATE package SET status = ?1
                     WHERE name = ?2 AND version = ?3 AND ecosystem = ?4
                       AND source_kind = ?5 AND source_uri = ?6 AND source_precise = ?7",
                params![
                    status.as_str(),
                    identity.name,
                    identity.version,
                    identity.ecosystem,
                    identity.source_kind,
                    identity.source_uri,
                    identity.source_precise,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    /// Records one tool execution (spec §10.2). The caller scrubs `argv` and
    /// `env` of secrets before recording.
    pub async fn record_invocation(&self, invocation: &ToolInvocation) -> Result<(), StoreError> {
        let identity = invocation.package_id.as_ref().map(PackageIdentity::of);
        let argv = serde_json::to_string(&invocation.argv)?;
        let env = serde_json::to_string(&invocation.env)?;
        let tool = invocation.tool.clone();
        let tool_version = invocation.tool_version.clone();
        let sandbox_mode = invocation.sandbox_mode.clone();
        let exit_status = invocation.exit_status.clone();
        let started_at = invocation.started_at.clone();
        let duration_ms = invocation.duration_ms as i64;
        let log_path = invocation.log_path.clone();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = lock(&conn)?;
            let package_id = match &identity {
                Some(identity) => Some(package_row_id(&conn, identity)?),
                None => None,
            };
            conn.execute(
                "INSERT INTO tool_invocation (package_id, tool, argv, env, tool_version,
                           sandbox_mode, exit_status, started_at, duration_ms, log_path)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    package_id,
                    tool,
                    argv,
                    env,
                    tool_version,
                    sandbox_mode,
                    exit_status,
                    started_at,
                    duration_ms,
                    log_path,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    /// Rebuilds the full [`Analysis`] (metadata + graph). Every JSON column
    /// is validated; parse failures are [`StoreError::Corrupt`].
    pub async fn load(&self) -> Result<Analysis, StoreError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = lock(&conn)?;
            let tx = conn.transaction()?;
            let metadata = read_metadata(&tx)?
                .ok_or_else(|| StoreError::Corrupt("metadata row missing".to_string()))?;
            let graph = read_graph(&tx)?;
            tx.commit()?;
            Ok(Analysis { metadata, graph })
        })
        .await
        .map_err(join_error)?
    }

    /// Validates schema and graph well-formedness (spec §11.3). Informational
    /// findings (unresolved requirements, cycles, orphans) do not affect
    /// [`IntegrityReport::is_ok`].
    pub async fn check(&self) -> Result<IntegrityReport, StoreError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = lock(&conn)?;
            let tx = conn.transaction()?;
            let report = run_checks(&tx)?;
            tx.commit()?;
            Ok(report)
        })
        .await
        .map_err(join_error)?
    }
}

fn package_row_id(
    conn: &rusqlite::Connection,
    identity: &PackageIdentity,
) -> Result<i64, StoreError> {
    match conn.query_row(
        "SELECT id FROM package
         WHERE name = ?1 AND version = ?2 AND ecosystem = ?3
           AND source_kind = ?4 AND source_uri = ?5 AND source_precise = ?6",
        params![
            identity.name,
            identity.version,
            identity.ecosystem,
            identity.source_kind,
            identity.source_uri,
            identity.source_precise,
        ],
        |row| row.get(0),
    ) {
        Ok(id) => Ok(id),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            // Placeholder node for an endpoint that has not been analyzed yet
            // — mirrors `DependencyGraph::add_edge` (spec §5.2).
            conn.execute(
                "INSERT INTO package (name, version, ecosystem, source_kind, source_uri,
                       source_precise, is_root, status, active_features, path)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 'Not_Started', '[]', '')",
                params![
                    identity.name,
                    identity.version,
                    identity.ecosystem,
                    identity.source_kind,
                    identity.source_uri,
                    identity.source_precise,
                ],
            )?;
            Ok(conn.last_insert_rowid())
        }
        Err(error) => Err(error.into()),
    }
}

fn upsert_edge(tx: &rusqlite::Transaction<'_>, edge: &Edge) -> Result<(), StoreError> {
    let from_id = package_row_id(tx, &PackageIdentity::of(&edge.from))?;
    let to_id = match &edge.to {
        Some(id) => Some(package_row_id(tx, &PackageIdentity::of(id))?),
        None => None,
    };
    let requirement = edge.requirement.name.clone();
    let requirement_kind = edge.requirement.kind.as_str().to_string();
    let version_req = edge
        .requirement
        .version_req
        .as_ref()
        .map(|req| req.requirement_text())
        .unwrap_or_default();
    let predicate = edge.predicate.canonical_text();
    let kinds = serde_json::to_string(&edge.kinds)?;
    let evidence = serde_json::to_string(&edge.evidence)?;
    let columns = EdgeColumns {
        from_id,
        to_id,
        requirement: &requirement,
        requirement_kind: &requirement_kind,
        version_req: &version_req,
        predicate: &predicate,
    };

    let inserted = tx.execute(
        "INSERT INTO dependency_edge (from_package_id, to_package_id, requirement,
               requirement_kind, version_req, kinds, predicate, confidence, evidence)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            columns.from_id,
            columns.to_id,
            columns.requirement,
            columns.requirement_kind,
            columns.version_req,
            kinds,
            columns.predicate,
            edge.confidence,
            evidence,
        ],
    );
    match inserted {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(ref failure, _))
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            merge_edge_row(tx, &columns, edge)
        }
        Err(error) => Err(error.into()),
    }
}

/// The persisted identity columns of a dependency edge (spec §11.2).
struct EdgeColumns<'a> {
    from_id: i64,
    to_id: Option<i64>,
    requirement: &'a str,
    requirement_kind: &'a str,
    version_req: &'a str,
    predicate: &'a str,
}

fn merge_edge_row(
    tx: &rusqlite::Transaction<'_>,
    columns: &EdgeColumns<'_>,
    edge: &Edge,
) -> Result<(), StoreError> {
    let existing: (i64, String, i64, String) = match columns.to_id {
        Some(to_id) => tx.query_row(
            "SELECT id, kinds, confidence, evidence FROM dependency_edge
             WHERE from_package_id = ?1 AND to_package_id = ?2 AND requirement = ?3
               AND requirement_kind = ?4 AND version_req = ?5 AND predicate = ?6",
            params![
                columns.from_id,
                to_id,
                columns.requirement,
                columns.requirement_kind,
                columns.version_req,
                columns.predicate
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?,
        None => tx.query_row(
            "SELECT id, kinds, confidence, evidence FROM dependency_edge
             WHERE from_package_id = ?1 AND to_package_id IS NULL AND requirement = ?2
               AND requirement_kind = ?3 AND version_req = ?4 AND predicate = ?5",
            params![
                columns.from_id,
                columns.requirement,
                columns.requirement_kind,
                columns.version_req,
                columns.predicate
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?,
    };
    let (existing_id, existing_kinds, existing_confidence, existing_evidence) = existing;
    let mut kinds: BTreeSet<DependencyKind> = serde_json::from_str(&existing_kinds)?;
    kinds.extend(edge.kinds.iter().copied());
    let confidence = existing_confidence.max(edge.confidence as i64);
    let mut evidence: Vec<Evidence> = serde_json::from_str(&existing_evidence)?;
    for record in &edge.evidence {
        if !evidence.contains(record) {
            evidence.push(record.clone());
        }
    }
    tx.execute(
        "UPDATE dependency_edge SET kinds = ?1, confidence = ?2, evidence = ?3 WHERE id = ?4",
        params![
            serde_json::to_string(&kinds)?,
            confidence,
            serde_json::to_string(&evidence)?,
            existing_id
        ],
    )?;
    Ok(())
}

fn read_metadata(conn: &rusqlite::Connection) -> Result<Option<AnalysisMetadata>, StoreError> {
    let mut statement = conn.prepare(
        "SELECT robigus_version, project_name, project_version, source_kind, source_uri,
                source_digest, configuration, toolchain, network_mode, sandbox_mode,
                options, created_at, updated_at
         FROM metadata WHERE id = 1",
    )?;
    let mut rows = statement.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    Ok(Some(AnalysisMetadata {
        robigus_version: row.get("robigus_version")?,
        project_name: row.get("project_name")?,
        project_version: row.get("project_version")?,
        source_kind: row.get("source_kind")?,
        source_uri: row.get("source_uri")?,
        source_digest: row.get("source_digest")?,
        configuration: serde_json::from_str(&row.get::<_, String>("configuration")?)?,
        toolchain: serde_json::from_str(&row.get::<_, String>("toolchain")?)?,
        network_mode: row.get("network_mode")?,
        sandbox_mode: row.get("sandbox_mode")?,
        options: serde_json::from_str(&row.get::<_, String>("options")?)?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    }))
}

fn read_graph(conn: &rusqlite::Connection) -> Result<DependencyGraph, StoreError> {
    let mut graph = DependencyGraph::new();
    let mut by_row_id: HashMap<i64, PackageId> = HashMap::new();
    let mut ecosystems: HashMap<i64, Ecosystem> = HashMap::new();

    {
        let mut statement = conn.prepare(
            "SELECT id, name, version, ecosystem, source_kind, source_uri, source_precise,
                    is_root, status, active_features, path
             FROM package ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let row_id: i64 = row.get("id")?;
            let identity = PackageIdentity {
                name: row.get("name")?,
                version: row.get("version")?,
                ecosystem: row.get("ecosystem")?,
                source_kind: row.get("source_kind")?,
                source_uri: row.get("source_uri")?,
                source_precise: row.get("source_precise")?,
            };
            let package_id = identity.package_id()?;
            let ecosystem = Ecosystem::parse(&identity.ecosystem).ok_or_else(|| {
                StoreError::Corrupt(format!("unknown ecosystem '{}'", identity.ecosystem))
            })?;
            let status = parse_status(&row.get::<_, String>("status")?)?;
            let active_features: BTreeSet<String> =
                serde_json::from_str(&row.get::<_, String>("active_features")?)?;
            let path_text: String = row.get("path")?;
            let is_root: bool = row.get("is_root")?;
            graph.add_node(Node {
                id: package_id.clone(),
                path: (!path_text.is_empty()).then(|| PathBuf::from(path_text)),
                status,
                active_features,
                targets: Vec::new(),
                provides: Vec::new(),
                conflicts: Vec::new(),
            });
            if is_root {
                graph.add_root(package_id.clone());
            }
            by_row_id.insert(row_id, package_id);
            ecosystems.insert(row_id, ecosystem);
        }
    }

    {
        let mut statement =
            conn.prepare("SELECT package_id, name, kind, soname FROM package_target ORDER BY id")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let package_row: i64 = row.get("package_id")?;
            let kind: TargetKind = serde_json::from_str(&row.get::<_, String>("kind")?)?;
            let target = Target {
                name: row.get("name")?,
                kind,
                // `package_target` has no path column (spec §11.2).
                path: None,
            };
            let Some(package_id) = by_row_id.get(&package_row) else {
                return Err(StoreError::Corrupt(
                    "target references unknown package".to_string(),
                ));
            };
            let Some(node) = graph.node_mut(package_id) else {
                return Err(StoreError::Corrupt(
                    "target references unknown package".to_string(),
                ));
            };
            node.targets.push(target);
        }
    }

    {
        let mut statement =
            conn.prepare("SELECT package_id, name, version FROM package_provides ORDER BY id")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let package_row: i64 = row.get("package_id")?;
            let name: String = row.get("name")?;
            let version_text: String = row.get("version")?;
            let ecosystem = ecosystems.get(&package_row).copied().ok_or_else(|| {
                StoreError::Corrupt("provide references unknown package".to_string())
            })?;
            let provide = Provide {
                name,
                version: (!version_text.is_empty())
                    .then(|| PackageVersion::from_stored_text(ecosystem, &version_text)),
            };
            let Some(package_id) = by_row_id.get(&package_row) else {
                return Err(StoreError::Corrupt(
                    "provide references unknown package".to_string(),
                ));
            };
            let Some(node) = graph.node_mut(package_id) else {
                return Err(StoreError::Corrupt(
                    "provide references unknown package".to_string(),
                ));
            };
            node.provides.push(provide);
        }
    }

    {
        let mut statement = conn
            .prepare("SELECT package_id, name, version_req FROM package_conflicts ORDER BY id")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let package_row: i64 = row.get("package_id")?;
            let name: String = row.get("name")?;
            let version_req_text: String = row.get("version_req")?;
            let conflict = Conflict {
                name,
                version_req: (!version_req_text.is_empty())
                    .then(|| VersionConstraint::from_requirement_text(&version_req_text))
                    .transpose()?,
            };
            let Some(package_id) = by_row_id.get(&package_row) else {
                return Err(StoreError::Corrupt(
                    "conflict references unknown package".to_string(),
                ));
            };
            let Some(node) = graph.node_mut(package_id) else {
                return Err(StoreError::Corrupt(
                    "conflict references unknown package".to_string(),
                ));
            };
            node.conflicts.push(conflict);
        }
    }

    {
        let mut statement = conn.prepare(
            "SELECT from_package_id, to_package_id, requirement, requirement_kind,
                    version_req, kinds, predicate, confidence, evidence
             FROM dependency_edge ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let from_row: i64 = row.get("from_package_id")?;
            let to_row: Option<i64> = row.get("to_package_id")?;
            let from = by_row_id
                .get(&from_row)
                .ok_or_else(|| {
                    StoreError::Corrupt("edge references unknown from package".to_string())
                })?
                .clone();
            let to = match to_row {
                Some(to_row) => Some(
                    by_row_id
                        .get(&to_row)
                        .ok_or_else(|| {
                            StoreError::Corrupt("edge references unknown to package".to_string())
                        })?
                        .clone(),
                ),
                None => None,
            };
            let requirement_kind_text: String = row.get("requirement_kind")?;
            let requirement = Requirement {
                name: row.get("requirement")?,
                kind: RequirementKind::parse(&requirement_kind_text).ok_or_else(|| {
                    StoreError::Corrupt(format!(
                        "unknown requirement kind '{requirement_kind_text}'"
                    ))
                })?,
                version_req: match row.get::<_, String>("version_req")? {
                    text if text.is_empty() => None,
                    text => Some(VersionConstraint::from_requirement_text(&text)?),
                },
            };
            let kinds: BTreeSet<DependencyKind> =
                serde_json::from_str(&row.get::<_, String>("kinds")?)?;
            let predicate = Predicate::parse(&row.get::<_, String>("predicate")?)?;
            let confidence: u8 = row.get("confidence")?;
            let evidence: Vec<Evidence> = serde_json::from_str(&row.get::<_, String>("evidence")?)?;
            graph.add_edge(Edge {
                from,
                to,
                requirement,
                kinds,
                predicate,
                confidence,
                evidence,
            });
        }
    }

    Ok(graph)
}

fn run_checks(conn: &rusqlite::Connection) -> Result<IntegrityReport, StoreError> {
    let mut report = IntegrityReport {
        schema_version: user_version(conn),
        ..IntegrityReport::default()
    };

    {
        let mut statement = conn.prepare("PRAGMA foreign_key_check")?;
        let mut rows = statement.query([])?;
        report.foreign_keys_ok = rows.next()?.is_none();
    }

    report.duplicate_identities = conn.query_row(
        "SELECT COUNT(*) FROM (
            SELECT 1 FROM package
            GROUP BY name, version, ecosystem, source_kind, source_uri, source_precise
            HAVING COUNT(*) > 1
         )",
        [],
        |row| row.get::<_, i64>(0),
    )? as usize;

    // JSON validity, identity corruption, and confidence caps.
    {
        let mut statement = conn.prepare(
            "SELECT name, version, ecosystem, source_kind, source_uri, source_precise,
                    active_features FROM package ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let identity = PackageIdentity {
                name: row.get("name")?,
                version: row.get("version")?,
                ecosystem: row.get("ecosystem")?,
                source_kind: row.get("source_kind")?,
                source_uri: row.get("source_uri")?,
                source_precise: row.get("source_precise")?,
            };
            if identity.package_id().is_err() {
                report.corrupt_identities += 1;
            }
            let active_features: Result<BTreeSet<String>, _> =
                serde_json::from_str(&row.get::<_, String>("active_features")?);
            if active_features.is_err() {
                report.invalid_json_columns += 1;
            }
        }
    }
    {
        let mut statement = conn.prepare(
            "SELECT from_package_id, requirement, requirement_kind, kinds, predicate,
                    confidence, evidence FROM dependency_edge ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let kinds: Result<BTreeSet<DependencyKind>, _> =
                serde_json::from_str(&row.get::<_, String>("kinds")?);
            let predicate = Predicate::parse(&row.get::<_, String>("predicate")?);
            let evidence: Result<Vec<Evidence>, _> =
                serde_json::from_str(&row.get::<_, String>("evidence")?);
            if kinds.is_err() || predicate.is_err() || evidence.is_err() {
                report.invalid_json_columns += 1;
                continue;
            }
            let from_row: i64 = row.get("from_package_id")?;
            let from_name: String = conn
                .query_row(
                    "SELECT name FROM package WHERE id = ?1",
                    params![from_row],
                    |row| row.get(0),
                )
                .unwrap_or_else(|_| "<unknown>".to_string());
            let requirement: String = row.get("requirement")?;
            for record in evidence.unwrap_or_default() {
                if record.violates_cap() {
                    report.confidence_violations.push(format!(
                        "edge from {from_name} requirement '{requirement}': {} confidence {} exceeds cap {}",
                        record.method.as_str(),
                        record.confidence,
                        record.method.max_confidence(),
                    ));
                }
            }
        }
    }
    {
        let mut statement =
            conn.prepare("SELECT configuration, toolchain, options FROM metadata WHERE id = 1")?;
        let mut rows = statement.query([])?;
        if let Some(row) = rows.next()? {
            for column in ["configuration", "toolchain", "options"] {
                let text: String = row.get(column)?;
                if serde_json::from_str::<serde_json::Value>(&text).is_err() {
                    report.invalid_json_columns += 1;
                }
            }
        }
    }

    let out_of_bounds: i64 = conn.query_row(
        "SELECT COUNT(*) FROM dependency_edge WHERE confidence < 0 OR confidence > 100",
        [],
        |row| row.get(0),
    )?;
    if out_of_bounds > 0 {
        report.confidence_violations.push(format!(
            "{out_of_bounds} edge(s) with confidence outside 0..=100"
        ));
    }

    // Status invariants.
    collect_identity_violations(
        conn,
        "SELECT p.name, p.version, p.ecosystem, p.source_kind, p.source_uri, p.source_precise
         FROM package p
         JOIN dependency_edge e ON e.from_package_id = p.id AND e.to_package_id IS NOT NULL
         JOIN package t ON t.id = e.to_package_id
         WHERE p.status = 'Complete' AND t.status != 'Complete'
         GROUP BY p.id",
        &mut report,
    )?;
    collect_identity_violations(
        conn,
        "SELECT p.name, p.version, p.ecosystem, p.source_kind, p.source_uri, p.source_precise
         FROM package p
         WHERE p.status IN ('Started', 'Error')
           AND NOT EXISTS (SELECT 1 FROM analysis_plan ap WHERE ap.package_id = p.id)",
        &mut report,
    )?;
    collect_identity_violations(
        conn,
        "SELECT p.name, p.version, p.ecosystem, p.source_kind, p.source_uri, p.source_precise
         FROM package p
         WHERE p.status = 'Error'
           AND NOT EXISTS (
               SELECT 1 FROM analysis_plan ap WHERE ap.package_id = p.id AND ap.error IS NOT NULL
           )",
        &mut report,
    )?;

    // Informational: unresolved requirements by kind.
    {
        let mut statement = conn.prepare(
            "SELECT requirement_kind, COUNT(*) FROM dependency_edge
             WHERE to_package_id IS NULL GROUP BY requirement_kind",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let kind_text: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            if let Some(kind) = RequirementKind::parse(&kind_text) {
                report.unresolved_requirements.insert(kind, count as usize);
            }
        }
    }

    // Informational: orphans (no incoming edges, not a root).
    {
        let mut statement = conn.prepare(
            "SELECT name, version, ecosystem, source_kind, source_uri, source_precise
             FROM package p
             WHERE p.is_root = 0
               AND NOT EXISTS (
                   SELECT 1 FROM dependency_edge e WHERE e.to_package_id = p.id
               )",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let identity = PackageIdentity {
                name: row.get("name")?,
                version: row.get("version")?,
                ecosystem: row.get("ecosystem")?,
                source_kind: row.get("source_kind")?,
                source_uri: row.get("source_uri")?,
                source_precise: row.get("source_precise")?,
            };
            match identity.package_id() {
                Ok(id) => report.orphans.push(id),
                Err(_) => report.corrupt_identities += 1,
            }
        }
    }

    // Cycles require the graph; only computed when the data is clean.
    if report.foreign_keys_ok
        && report.duplicate_identities == 0
        && report.invalid_json_columns == 0
        && report.corrupt_identities == 0
    {
        let graph = read_graph(conn)?;
        report.cycles = graph.cycles();
    }

    Ok(report)
}

fn collect_identity_violations(
    conn: &rusqlite::Connection,
    query: &str,
    report: &mut IntegrityReport,
) -> Result<(), StoreError> {
    let mut statement = conn.prepare(query)?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let identity = PackageIdentity {
            name: row.get(0)?,
            version: row.get(1)?,
            ecosystem: row.get(2)?,
            source_kind: row.get(3)?,
            source_uri: row.get(4)?,
            source_precise: row.get(5)?,
        };
        match identity.package_id() {
            Ok(id) => report.status_violations.push(id),
            Err(_) => report.corrupt_identities += 1,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EvidenceMethod;
    use semver::Version;
    use tempfile::TempDir;

    async fn open_test_store() -> (Store, TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&dir.path().join("analysis.db"))
            .await
            .expect("open");
        (store, dir)
    }

    fn test_id(name: &str) -> PackageId {
        PackageId {
            name: name.to_string(),
            version: PackageVersion::SemVer(Version::new(1, 0, 0)),
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
                name: "dep".to_string(),
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

    fn test_metadata() -> AnalysisMetadata {
        AnalysisMetadata {
            robigus_version: "0.1.0".to_string(),
            project_name: "rav1e".to_string(),
            project_version: "0.7.0".to_string(),
            source_kind: "git".to_string(),
            source_uri: "https://github.com/x/rav1e".to_string(),
            source_digest: "abc".to_string(),
            configuration: Configuration::default(),
            toolchain: BTreeMap::from([("cargo".to_string(), "1.93.1".to_string())]),
            network_mode: "allowlist".to_string(),
            sandbox_mode: "bwrap".to_string(),
            options: serde_json::json!({ "jobs": 4 }),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[tokio::test]
    async fn open_creates_schema_v1() {
        let (_store, dir) = open_test_store().await;
        let raw = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
        let version: i64 = raw
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
        let tables: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN
                 ('metadata', 'package', 'dependency_edge', 'package_target',
                  'package_provides', 'package_conflicts', 'analysis_plan', 'tool_invocation')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 8);
        let journal: String = raw
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal, "wal");
    }

    #[tokio::test]
    async fn open_rejects_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("analysis.db");
        {
            let raw = rusqlite::Connection::open(&path).unwrap();
            raw.pragma_update(None, "user_version", 2).unwrap();
        }
        let error = Store::open(&path).await.unwrap_err();
        assert!(matches!(
            error,
            StoreError::SchemaTooNew {
                found: 2,
                supported: 1
            }
        ));
    }

    #[tokio::test]
    async fn metadata_round_trip() {
        let (store, _dir) = open_test_store().await;
        assert!(store.metadata().await.unwrap().is_none());

        let metadata = test_metadata();
        store.write_metadata(&metadata).await.unwrap();
        let loaded = store.metadata().await.unwrap().expect("metadata");
        assert_eq!(loaded.project_name, "rav1e");
        assert_eq!(loaded.created_at, metadata.created_at);
        assert!(!loaded.updated_at.is_empty());
        assert_eq!(
            loaded.toolchain.get("cargo").map(String::as_str),
            Some("1.93.1")
        );

        // A second write updates in place and preserves created_at.
        store.write_metadata(&metadata).await.unwrap();
        let loaded = store.metadata().await.unwrap().expect("metadata");
        assert_eq!(loaded.created_at, metadata.created_at);
    }

    #[tokio::test]
    async fn node_round_trip() {
        let (store, _dir) = open_test_store().await;
        store.write_metadata(&test_metadata()).await.unwrap();

        let id = test_id("serde");
        let mut node = Node::new(id.clone());
        node.status = AnalysisStatus::Started;
        node.active_features = BTreeSet::from(["derive".to_string()]);
        node.path = Some(PathBuf::from("vendor/serde"));
        store.upsert_node(&node).await.unwrap();
        store.set_root(&id, true).await.unwrap();

        let analysis = store.load().await.unwrap();
        assert_eq!(analysis.graph.node_count(), 1);
        let loaded = analysis.graph.node(&id).expect("node");
        assert_eq!(loaded.status, AnalysisStatus::Started);
        assert_eq!(
            loaded.active_features,
            BTreeSet::from(["derive".to_string()])
        );
        assert_eq!(loaded.path.as_deref(), Some(Path::new("vendor/serde")));
        assert!(analysis.graph.roots().contains(&id));
    }

    #[tokio::test]
    async fn debian_version_round_trip() {
        let (store, _dir) = open_test_store().await;
        store.write_metadata(&test_metadata()).await.unwrap();

        let id = PackageId {
            name: "libfoo".to_string(),
            version: PackageVersion::Debian("2:1.18.0-1ubuntu1".parse().unwrap()),
            source_id: SourceId {
                kind: SourceKind::Path {
                    path: PathBuf::from("/tmp"),
                },
                precise: None,
            },
            ecosystem: Ecosystem::Ubuntu,
        };
        store.upsert_node(&Node::new(id.clone())).await.unwrap();
        let analysis = store.load().await.unwrap();
        assert_eq!(
            analysis.graph.node(&id).expect("node").id.version,
            PackageVersion::Debian("2:1.18.0-1ubuntu1".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn edge_round_trip_and_merge() {
        let (store, _dir) = open_test_store().await;
        store.write_metadata(&test_metadata()).await.unwrap();

        let a = test_id("a");
        let b = test_id("b");
        store.upsert_node(&Node::new(a.clone())).await.unwrap();
        store.upsert_node(&Node::new(b.clone())).await.unwrap();

        store
            .upsert_edges(
                &a,
                &[test_edge(
                    a.clone(),
                    Some(b.clone()),
                    DependencyKind::Normal,
                    40,
                )],
            )
            .await
            .unwrap();
        store
            .upsert_edges(
                &a,
                &[test_edge(
                    a.clone(),
                    Some(b.clone()),
                    DependencyKind::Development,
                    80,
                )],
            )
            .await
            .unwrap();
        // Unresolved requirement, merged across saves.
        store
            .upsert_edges(&a, &[test_edge(a.clone(), None, DependencyKind::Build, 50)])
            .await
            .unwrap();
        store
            .upsert_edges(&a, &[test_edge(a.clone(), None, DependencyKind::Build, 60)])
            .await
            .unwrap();

        let analysis = store.load().await.unwrap();
        assert_eq!(analysis.graph.node_count(), 2);
        assert_eq!(analysis.graph.edge_count(), 2);
        let edges = analysis.graph.edges_from(&a);
        assert_eq!(edges.len(), 2);
        let resolved = edges
            .iter()
            .find(|edge| edge.to.is_some())
            .expect("resolved edge");
        assert!(resolved.kinds.contains(&DependencyKind::Normal));
        assert!(resolved.kinds.contains(&DependencyKind::Development));
        assert_eq!(resolved.confidence, 80);
        assert_eq!(resolved.evidence.len(), 2);
        let unresolved = analysis.graph.unresolved();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].confidence, 60);
    }

    #[tokio::test]
    async fn double_save_is_idempotent() {
        let (store, _dir) = open_test_store().await;
        store.write_metadata(&test_metadata()).await.unwrap();
        let a = test_id("a");
        let b = test_id("b");
        let node = Node::new(a.clone());
        store.upsert_node(&node).await.unwrap();
        store.upsert_node(&node).await.unwrap();
        store.upsert_node(&Node::new(b.clone())).await.unwrap();
        let edge = test_edge(a.clone(), Some(b.clone()), DependencyKind::Normal, 50);
        store
            .upsert_edges(&a, std::slice::from_ref(&edge))
            .await
            .unwrap();
        store
            .upsert_edges(&a, std::slice::from_ref(&edge))
            .await
            .unwrap();

        let analysis = store.load().await.unwrap();
        assert_eq!(analysis.graph.node_count(), 2);
        assert_eq!(analysis.graph.edge_count(), 1);
        assert_eq!(analysis.graph.edges_from(&a)[0].evidence.len(), 1);
    }

    /// Regression: re-upserting an existing node must rewrite *its own*
    /// targets/provides/conflicts. Taking the row id from
    /// `last_insert_rowid()` after an upsert that took the DO UPDATE branch
    /// attached A's payload to B and deleted B's.
    #[tokio::test]
    async fn reupsert_rewrites_only_its_own_payload() {
        let (store, _dir) = open_test_store().await;
        store.write_metadata(&test_metadata()).await.unwrap();
        let with_payload = |id: &PackageId, tag: &str| {
            let mut node = Node::new(id.clone());
            node.targets = vec![Target {
                name: format!("{tag}-bin"),
                kind: TargetKind::Binary,
                path: None,
            }];
            node.provides = vec![Provide {
                name: format!("{tag}-virtual"),
                version: None,
            }];
            node.conflicts = vec![Conflict {
                name: format!("{tag}-conflict"),
                version_req: None,
            }];
            node
        };
        let a = test_id("a");
        let b = test_id("b");
        store.upsert_node(&with_payload(&a, "a1")).await.unwrap();
        store.upsert_node(&with_payload(&b, "b1")).await.unwrap();
        store.upsert_node(&with_payload(&a, "a2")).await.unwrap();

        let graph = store.load().await.unwrap().graph;
        let node_a = graph.node(&a).expect("a");
        let node_b = graph.node(&b).expect("b");
        assert_eq!(node_a.targets.len(), 1);
        assert_eq!(node_a.targets[0].name, "a2-bin");
        assert_eq!(node_a.provides[0].name, "a2-virtual");
        assert_eq!(node_a.conflicts[0].name, "a2-conflict");
        assert_eq!(node_b.targets.len(), 1);
        assert_eq!(node_b.targets[0].name, "b1-bin");
        assert_eq!(node_b.provides.len(), 1);
        assert_eq!(node_b.provides[0].name, "b1-virtual");
        assert_eq!(node_b.conflicts.len(), 1);
        assert_eq!(node_b.conflicts[0].name, "b1-conflict");
    }

    /// Regression (High 5): an edge built through `DependencyGraph` loads back
    /// identical, including a predicate written in non-canonical order, and
    /// two spellings of one predicate stay one edge on both sides.
    #[tokio::test]
    async fn graph_edges_round_trip_with_equivalent_predicates() {
        let (store, _dir) = open_test_store().await;
        store.write_metadata(&test_metadata()).await.unwrap();
        let a = test_id("a");
        let b = test_id("b");
        let mut graph = DependencyGraph::new();
        for text in [
            r#"cfg("target_os" = "linux") && feature("tls")"#,
            r#"feature("tls") && cfg("target_os" = "linux")"#,
        ] {
            let mut edge = test_edge(a.clone(), Some(b.clone()), DependencyKind::Normal, 60);
            edge.predicate = Predicate::parse(text).unwrap();
            graph.add_edge(edge);
        }
        assert_eq!(graph.edge_count(), 1);

        store.upsert_node(&Node::new(a.clone())).await.unwrap();
        store.upsert_node(&Node::new(b.clone())).await.unwrap();
        let edges: Vec<Edge> = graph.edges_from(&a).into_iter().cloned().collect();
        store.upsert_edges(&a, &edges).await.unwrap();

        let loaded = store.load().await.unwrap().graph;
        assert_eq!(loaded.edge_count(), 1);
        assert_eq!(loaded.edges_from(&a), graph.edges_from(&a));
    }

    #[tokio::test]
    async fn status_transitions_are_enforced() {
        let (store, _dir) = open_test_store().await;
        let id = test_id("a");
        store.upsert_node(&Node::new(id.clone())).await.unwrap();

        let error = store
            .update_status(&id, AnalysisStatus::Complete)
            .await
            .unwrap_err();
        assert!(matches!(error, StoreError::InvalidTransition { .. }));
        assert!(
            store
                .update_status(&id, AnalysisStatus::NotStarted)
                .await
                .is_ok()
        ); // same-state no-op

        store
            .update_status(&id, AnalysisStatus::Started)
            .await
            .unwrap();
        store
            .update_status(&id, AnalysisStatus::Error)
            .await
            .unwrap();
        store
            .update_status(&id, AnalysisStatus::Started)
            .await
            .unwrap();
        store
            .update_status(&id, AnalysisStatus::Complete)
            .await
            .unwrap();
        assert!(
            store
                .update_status(&id, AnalysisStatus::Started)
                .await
                .is_err()
        ); // Complete is terminal
        assert!(
            store
                .update_status(&id, AnalysisStatus::Complete)
                .await
                .is_ok()
        ); // same-state no-op
    }

    #[tokio::test]
    async fn targets_provides_conflicts_round_trip() {
        let (store, _dir) = open_test_store().await;
        store.write_metadata(&test_metadata()).await.unwrap();

        let id = test_id("libfoo");
        let mut node = Node::new(id.clone());
        node.targets = vec![Target {
            name: "libfoo".to_string(),
            kind: TargetKind::SharedLibrary {
                soname: Some("libfoo.so.1".to_string()),
            },
            path: Some(PathBuf::from("usr/lib/libfoo.so.1")),
        }];
        node.provides = vec![Provide {
            name: "libfoo".to_string(),
            version: Some(PackageVersion::SemVer(Version::new(1, 0, 1))),
        }];
        node.conflicts = vec![Conflict {
            name: "libbar".to_string(),
            version_req: Some(VersionConstraint::Debian {
                op: crate::model::DebianOperator::Lt,
                target_version: "2.0".to_string(),
            }),
        }];
        store.upsert_node(&node).await.unwrap();

        let analysis = store.load().await.unwrap();
        let loaded = analysis.graph.node(&id).expect("node");
        assert_eq!(loaded.targets.len(), 1);
        assert_eq!(
            loaded.targets[0].kind,
            TargetKind::SharedLibrary {
                soname: Some("libfoo.so.1".to_string())
            }
        );
        assert_eq!(loaded.provides.len(), 1);
        assert_eq!(
            loaded.provides[0].version,
            Some(PackageVersion::SemVer(Version::new(1, 0, 1)))
        );
        assert_eq!(loaded.conflicts.len(), 1);
    }

    #[tokio::test]
    async fn record_invocation_persists() {
        let (store, dir) = open_test_store().await;
        store.write_metadata(&test_metadata()).await.unwrap();
        let id = test_id("a");
        store.upsert_node(&Node::new(id.clone())).await.unwrap();
        store
            .record_invocation(&ToolInvocation {
                package_id: Some(id.clone()),
                tool: "cargo metadata".to_string(),
                argv: vec!["cargo".to_string(), "metadata".to_string()],
                env: BTreeMap::new(),
                tool_version: Some("1.93.1".to_string()),
                sandbox_mode: "bwrap".to_string(),
                exit_status: "success".to_string(),
                started_at: "2026-01-01T00:00:00Z".to_string(),
                duration_ms: 120,
                log_path: Some("logs/cargo-metadata.log".to_string()),
            })
            .await
            .unwrap();

        let raw = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
        let count: i64 = raw
            .query_row("SELECT COUNT(*) FROM tool_invocation", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        let tool: String = raw
            .query_row("SELECT tool FROM tool_invocation", [], |row| row.get(0))
            .unwrap();
        assert_eq!(tool, "cargo metadata");
    }

    #[tokio::test]
    async fn corrupted_json_is_detected() {
        let (store, dir) = open_test_store().await;
        store.write_metadata(&test_metadata()).await.unwrap();
        let a = test_id("a");
        let b = test_id("b");
        store.upsert_node(&Node::new(a.clone())).await.unwrap();
        store.upsert_node(&Node::new(b.clone())).await.unwrap();
        store
            .upsert_edges(
                &a,
                &[test_edge(
                    a.clone(),
                    Some(b.clone()),
                    DependencyKind::Normal,
                    50,
                )],
            )
            .await
            .unwrap();

        {
            let raw = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
            raw.execute("UPDATE dependency_edge SET kinds = 'not json'", [])
                .unwrap();
        }

        let report = store.check().await.unwrap();
        assert!(report.invalid_json_columns > 0);
        assert!(!report.is_ok());
        assert!(store.load().await.is_err());
    }

    #[tokio::test]
    async fn check_reports_status_invariants() {
        let (store, _dir) = open_test_store().await;
        store.write_metadata(&test_metadata()).await.unwrap();
        let a = test_id("a");
        let b = test_id("b");
        let c = test_id("c");
        store.upsert_node(&Node::new(a.clone())).await.unwrap();
        store.upsert_node(&Node::new(b.clone())).await.unwrap();
        store.upsert_node(&Node::new(c.clone())).await.unwrap();
        store
            .upsert_edges(
                &a,
                &[test_edge(
                    a.clone(),
                    Some(b.clone()),
                    DependencyKind::Normal,
                    50,
                )],
            )
            .await
            .unwrap();

        // A completes while its dependency B is still Not_Started.
        store
            .update_status(&a, AnalysisStatus::Started)
            .await
            .unwrap();
        store
            .update_status(&a, AnalysisStatus::Complete)
            .await
            .unwrap();
        // C is Started without any plan rows.
        store
            .update_status(&c, AnalysisStatus::Started)
            .await
            .unwrap();

        let report = store.check().await.unwrap();
        assert!(report.status_violations.contains(&a));
        assert!(report.status_violations.contains(&c));
        assert!(!report.is_ok());
    }

    #[tokio::test]
    async fn check_reports_informational_findings() {
        let (store, _dir) = open_test_store().await;
        store.write_metadata(&test_metadata()).await.unwrap();
        let a = test_id("a");
        let b = test_id("b");
        store.upsert_node(&Node::new(a.clone())).await.unwrap();
        store.upsert_node(&Node::new(b.clone())).await.unwrap();
        store.set_root(&a, true).await.unwrap();
        let mut unresolved = test_edge(a.clone(), None, DependencyKind::Build, 50);
        unresolved.requirement.kind = RequirementKind::PkgConfig;
        store.upsert_edges(&a, &[unresolved]).await.unwrap();

        let report = store.check().await.unwrap();
        assert!(report.is_ok());
        assert_eq!(
            report
                .unresolved_requirements
                .get(&RequirementKind::PkgConfig),
            Some(&1)
        );
        assert_eq!(report.orphans.len(), 1);
        assert_eq!(report.orphans[0], b);
    }

    #[tokio::test]
    async fn concurrent_reader_during_writer() {
        let (store, _dir) = open_test_store().await;
        store.write_metadata(&test_metadata()).await.unwrap();

        let writer = store.clone();
        let reader = store.clone();
        let write_task = tokio::spawn(async move {
            for index in 0..30 {
                writer
                    .upsert_node(&Node::new(test_id(&format!("p{index}"))))
                    .await
                    .unwrap();
            }
        });
        let read_task = tokio::spawn(async move {
            for _ in 0..10 {
                reader.load().await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        write_task.await.unwrap();
        read_task.await.unwrap();

        let analysis = store.load().await.unwrap();
        assert_eq!(analysis.graph.node_count(), 30);
    }
}

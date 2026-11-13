//! The v1 schema DDL and connection pragmas (spec §11.1, §11.2).

/// The schema version this crate writes (spec §11.3).
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// The full v1 DDL, applied by migration 1 (spec §11.2). JSON columns hold
/// serde-serialized model types; nullable-by-design TEXT columns that
/// participate in unique indexes use `''` for absent values.
///
/// v1 has not shipped, so it is still amended in place (spec §22.19–§22.22:
/// `package.source_reference`, `package_target.path`, and the
/// root-or-package keyed `analysis_plan`). Once released, changes MUST be new
/// migrations.
pub const SCHEMA_V1: &str = r#"
CREATE TABLE metadata (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    robigus_version TEXT NOT NULL,
    project_name    TEXT NOT NULL,
    project_version TEXT NOT NULL,
    source_kind     TEXT NOT NULL,
    source_uri      TEXT NOT NULL,
    source_digest   TEXT NOT NULL DEFAULT '',
    configuration   TEXT NOT NULL,
    toolchain       TEXT NOT NULL,
    network_mode    TEXT NOT NULL,
    sandbox_mode    TEXT NOT NULL,
    options         TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE package (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,
    source_kind     TEXT NOT NULL,
    source_uri      TEXT NOT NULL DEFAULT '',
    source_precise  TEXT NOT NULL DEFAULT '',
    source_reference TEXT NOT NULL DEFAULT '',
    is_root         INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'Not_Started',
    active_features TEXT NOT NULL DEFAULT '[]',
    path            TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_package_identity ON package
    (name, version, ecosystem, source_kind, source_uri, source_precise);
CREATE INDEX idx_package_name   ON package (name);
CREATE INDEX idx_package_status ON package (status);

CREATE TABLE dependency_edge (
    id               INTEGER PRIMARY KEY,
    from_package_id  INTEGER NOT NULL REFERENCES package(id) ON DELETE CASCADE,
    to_package_id    INTEGER REFERENCES package(id) ON DELETE SET NULL,
    requirement      TEXT NOT NULL,
    requirement_kind TEXT NOT NULL,
    version_req      TEXT NOT NULL DEFAULT '',
    kinds            TEXT NOT NULL,
    predicate        TEXT NOT NULL,
    confidence       INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    evidence         TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_edge_resolved ON dependency_edge
    (from_package_id, to_package_id, requirement, requirement_kind, version_req, predicate)
    WHERE to_package_id IS NOT NULL;
CREATE UNIQUE INDEX idx_edge_unresolved ON dependency_edge
    (from_package_id, requirement, requirement_kind, version_req, predicate)
    WHERE to_package_id IS NULL;
CREATE INDEX idx_edge_from           ON dependency_edge (from_package_id);
CREATE INDEX idx_edge_to             ON dependency_edge (to_package_id);
CREATE INDEX idx_edge_requirement_kk ON dependency_edge (requirement_kind);

CREATE TABLE package_target (
    id         INTEGER PRIMARY KEY,
    package_id INTEGER NOT NULL REFERENCES package(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL,
    soname     TEXT NOT NULL DEFAULT '',
    path       TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_target_unique ON package_target (package_id, name, kind, soname);
CREATE INDEX idx_target_name ON package_target (name);

CREATE TABLE package_provides (
    id         INTEGER PRIMARY KEY,
    package_id INTEGER NOT NULL REFERENCES package(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_provides_unique ON package_provides (package_id, name, version);
CREATE INDEX idx_provides_name ON package_provides (name);

CREATE TABLE package_conflicts (
    id          INTEGER PRIMARY KEY,
    package_id  INTEGER NOT NULL REFERENCES package(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    version_req TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_conflicts_unique ON package_conflicts (package_id, name, version_req);

CREATE TABLE analysis_plan (
    id           INTEGER PRIMARY KEY,
    package_id   INTEGER REFERENCES package(id) ON DELETE CASCADE,
    root_path    TEXT,
    analyzer     TEXT NOT NULL,
    strategy     TEXT NOT NULL CHECK (strategy IN
                     ('manifest', 'tool_introspection', 'build_observation',
                      'documentation', 'validation')),
    build_system TEXT NOT NULL DEFAULT '' CHECK (build_system IN
                     ('', 'build_script', 'cmake', 'meson', 'autotools', 'make')),
    status       TEXT NOT NULL CHECK (status IN
                     ('Pending', 'Running', 'Complete', 'Failed', 'Skipped')),
    attempts     INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    error        TEXT,
    detail       TEXT,
    updated_at   TEXT NOT NULL,
    CHECK ((package_id IS NULL) <> (root_path IS NULL))
);
CREATE UNIQUE INDEX idx_plan_package ON analysis_plan
    (package_id, analyzer, strategy, build_system) WHERE package_id IS NOT NULL;
CREATE UNIQUE INDEX idx_plan_root ON analysis_plan
    (root_path, analyzer, strategy, build_system) WHERE package_id IS NULL;
CREATE INDEX idx_plan_status ON analysis_plan (status);

CREATE TABLE tool_invocation (
    id           INTEGER PRIMARY KEY,
    package_id   INTEGER REFERENCES package(id) ON DELETE SET NULL,
    tool         TEXT NOT NULL,
    argv         TEXT NOT NULL,
    env          TEXT NOT NULL,
    tool_version TEXT,
    sandbox_mode TEXT NOT NULL,
    exit_status  TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    duration_ms  INTEGER NOT NULL,
    log_path     TEXT
);
CREATE INDEX idx_invocation_package ON tool_invocation (package_id);
"#;

/// Connection pragmas applied on every open (spec §11.1). WAL also allows
/// `check`, `print`, and `export` to read while an analysis writes.
pub const PRAGMAS: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA mmap_size = 268435456;
PRAGMA foreign_keys = ON;
PRAGMA temp_store = MEMORY;
";

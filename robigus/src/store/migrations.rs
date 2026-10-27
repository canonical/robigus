//! Schema migrations via `rusqlite_migration` on `PRAGMA user_version`
//! (spec §11.3). Migrations are forward-only; opening a database with a
//! newer schema version is rejected before migrating (see `Store::open`).

use rusqlite_migration::{M, Migrations};

use super::schema::SCHEMA_V1;

/// The ordered migration list; index + 1 is the resulting `user_version`.
pub fn migrations() -> Migrations<'static> {
    Migrations::new(vec![
        // v1: the full §11.2 schema.
        M::up(SCHEMA_V1),
    ])
}

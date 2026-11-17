# robigus — Project Specification

## 1. Purpose and Scope

robigus is a modular Rust library and set of command-line tools for tracking, planning, and managing software dependency graphs. Its purpose is to plan Ubuntu packaging for arbitrary upstream software: it analyzes a target software project (TSP), discovers and recursively expands its complete dependency graph, and uses that graph to decide which dependencies can be satisfied from the Ubuntu archive and which must be packaged.

robigus is written in pure async Rust. It accepts a target software project as a Rust library call or through the `tsp-analyzer` command-line tool. The target may be supplied as:

- a URL to a version control repository,
- a URL to a source tarball,
- a local filesystem path, or
- a published crate version in a Cargo registry (crates.io or a compatible private registry).

### 1.1 Delivery phases

| Phase | Goal | Primary dependencies |
|---|---|---|
| 1. Dependency graph analysis (v1) | Discover the TSP's languages, build/test systems, targets, and complete transitive dependency graph; persist it to SQLite. | `cargo_metadata`, `toml_edit`, `gix`, `petgraph`, `rusqlite` |
| 2. Ubuntu archive mapping | Determine which dependencies (or acceptable version adjustments) exist in the Ubuntu archive. | `rapt`, `ubuntu-info-rust`, Contents indices |
| 3. Packaging plan | Classify dependencies as archive-satisfiable or needing packaging, and generate packaging templates for the latter. | `rapt`, `ubucargo` |

**v1 comprises Milestones M1–M3 only** (§21): target software project analysis, dependency graph discovery and expansion, and persistence of the full dependency graph. Ubuntu archive mapping (M4) and the packaging plan (M5) are Phase 2/3 work and are **not** part of the first release. Phases 2 and 3 are specified here so that Phase 1's data model and APIs do not preclude them. `ubucargo` is not yet a workspace member; it will be added when Phase 3 begins.

### 1.2 Non-goals for v1

- robigus does not build, install, upload, or publish packages.
- robigus does not modify the host's apt configuration or package database.
- robigus does not perform global cross-ecosystem version solving in Phase 1. It records the graph produced by ecosystem-native tooling and defers version selection to Phase 2/3.
- Platforms other than Linux are recorded but not expanded (see §4.4).
- Ecosystems other than Rust/Cargo and the C/C++/assembly used by Rust projects are out of scope for v1.
- Ubuntu archive mapping and packaging plans (M4/M5) are out of scope for v1.

## 2. Terminology

- **Target software project (TSP)**: the upstream project being analyzed.
- **Dependency graph**: a directed graph whose roots are the TSP (one or more, for example workspace members) and whose nodes are packages/artifacts; edges are dependency relationships.
- **Dependency mapping plan**: the per-node strategy used to discover and expand a node's dependencies (which analyzer, which inputs, which validation), persisted in the `analysis_plan` table.
- **Configuration**: a concrete combination of architecture, platform, enabled features, build profiles, environment, and Ubuntu series used to evaluate predicates.
- **Predicate**: a Boolean expression over configuration atoms that determines whether a dependency edge is active.
- **Requirement**: the *declared* dependency need (crate name, pkg-config module, header, soname, tool) together with its version constraint, independent of any resolved node.
- **Evidence**: the method, location, and confidence supporting a discovered node or edge.
- **Analysis status**: the per-node state of the analysis (`Not_Started`, `Started`, `Complete`, `Error`; §5.1).

## 3. Dependency Categories

Dependencies are categorized by how they are used. An edge carries a **set** of categories (`kinds`), not a single one, because a dependency may appear in multiple categories. For example, `gcc` may be both a dev-dependency (to compile tests) and a dependency (to compile the TSP).

- **dependencies** — needed to build or compile the TSP.
- **dev-dependencies** — needed only for compiling and running tests, examples, and benchmarks.
- **runtime-dependencies** — needed in the execution environment when the TSP runs, including interpreters, configuration files, data files, and similar components separate from the TSP itself.
- **build-dependencies** — required by build scripts (for example `build.rs`) or code generation (for example `.l`/`.lex`/`.flex` and `.y` files) before compiling the main package.

### 3.1 Mapping to Debian/Ubuntu packaging

| robigus category | Debian/Ubuntu field(s) |
|---|---|
| dependencies | `Build-Depends` (build); additionally `Depends` when the provider node ships an artifact that the built output consumes at runtime |
| dev-dependencies | `Build-Depends` excluded under the `nocheck` build profile (`<!nocheck>`); test-runtime dependencies via `debian/tests/control` |
| build-dependencies | `Build-Depends`, `Build-Depends-Arch`, `Build-Depends-Indep`, with `:native`/`:any` qualifiers for cross builds |
| runtime-dependencies | `Depends`, `Recommends`, `Suggests` |

The `Build-Depends` versus `Depends` decision is made in Phase 2/3 from the edge's kind set together with the **provider node's recorded `Target`s** and the ecosystem's linking conventions: a Rust crate compiled into the TSP is `Build-Depends` only, while a node providing a shared library that is linked dynamically contributes `Depends` as well. No separate per-edge linkage attribute is stored; the provider's targets are the source of truth.

The model MUST represent all four categories as a set per edge. The existing `DependencyKind` enum MUST gain a `Runtime` variant, and its `Normal` doc comment ("Needed for compilation and runtime") MUST be corrected: `Normal` means compiled/linked into the TSP; runtime needs are `Runtime`.

## 4. Dependency Predicates

Dependencies are annotated with predicates describing the conditions under which they are required. A dependency with no predicate is always required.

### 4.1 Predicate atoms

| Atom | Meaning | Example |
|---|---|---|
| `feature("name")` | Feature `name` enabled on the **current package** | `feature("serde")` |
| `feature("pkg/name")` | Feature `name` enabled on package `pkg` (qualified form for cross-package references) | `feature("serde/derive")` |
| `cfg("key" = "value")` | Cargo `cfg` key/value pair: `target_os`, `target_family`, `target_env`, `target_vendor`, `target_pointer_width`, `target_feature`, or custom `--cfg` keys | `cfg("target_env" = "musl")` |
| `arch("name")` | Machine architecture; `all` expands to the Ubuntu-supported set (§4.4) | `arch("amd64")` |
| `platform("name")` | Target OS/environment; only `linux` is expanded | `platform("linux")` |
| `build-profile("name")` | Debian build profile is active | `build-profile("nocheck")` |
| `env("NAME" = "value")` | Environment variable condition | `env("CC" = "clang")` |
| `series("name")` | Ubuntu series | `series("noble")` |
| `true` / `false` | Constants | `true` |

Cargo `cfg(...)` predicates (for example from `[target.'cfg(...)'.dependencies]`) are stored **verbatim** as `cfg` atoms — `cfg(unix)` becomes `cfg("target_family" = "unix")`, `cfg(target_arch = "x86_64")` becomes `cfg("target_arch" = "x86_64")` — so that no information is lost. Debian architecture qualifiers are stored as `arch` atoms. `arch("amd64")` and `cfg("target_arch" = "x86_64")` evaluate identically against a `Configuration`, and the store MUST NOT rewrite between the two forms.

### 4.2 Grammar

Predicates form a complete Boolean expression language with `!`, `&&`, and `||`:

```ebnf
predicate   = disjunction ;
disjunction = conjunction { "||" conjunction } ;
conjunction = unary { "&&" unary } ;
unary       = "!" unary | "(" predicate ")" | atom ;
atom        = "feature" "(" string ")"
            | "cfg" "(" string "=" string ")"
            | "arch" "(" string ")"
            | "platform" "(" string ")"
            | "build-profile" "(" string ")"
            | "env" "(" string "=" string ")"
            | "series" "(" string ")"
            | "true" | "false" ;
```

Precedence: `!` binds tighter than `&&`, which binds tighter than `||`. An empty predicate is equivalent to `true`. Package-qualified features (`feature("pkg/name")`) are ordinary string atoms; the `/` carries no grammar meaning.

### 4.3 Representation and evaluation

- The in-memory representation MUST be a typed AST (`Predicate` enum), not a string.
- Predicates MUST be serialized with `serde` for persistence and interchange.
- The store MUST persist the AST (in a deterministic **canonical serialization**: constant folding, de-duplication of identical operands, and sorted operands under `&&`/`||`) used for equality, deduplication, and display. Canonicalization is a pure syntax transformation and MUST NOT alter semantics.
- No CNF or DNF is persisted. Equivalence and matching are done by AST equality and query-time evaluation. DNF MAY be computed on demand for enumeration and reporting, with a size guard (node or term cap) so pathological inputs cannot blow up.
- Evaluation MUST be lazy and memoized per `Configuration`; robigus MUST NOT enumerate the full cross-product of architectures, platforms, features, and profiles.
- The predicate parser MUST be fuzz-tested and property-tested (see §16).

### 4.4 Architecture and platform enumeration

- The internal representation is `MachineArch`: `Ubuntu(Architecture)` (from the `ubuntu-info-rust` crate), `All`, or `Unsupported(String)`.
- `All` is stored as-is and expands, at evaluation time, to every machine architecture defined by `ubuntu-info-rust`.
- The default analysis set is every `ubuntu-info-rust` architecture **except** `i386`: `amd64`, `amd64v3`, `arm64`, `armhf`, `ppc64el`, `riscv64`, `s390x`. `i386` is supported and can be enabled through configuration, but is not analyzed by default. This default is robigus's own; `rapt`'s query defaults are independent.
- Architectures outside the `ubuntu-info-rust` set are recorded as `Unsupported(name)` stubs — evidence that they were detected — and are never expanded. They display with an `_unsupported` suffix (for example `mips_unsupported`); the suffix is a display convention only and MUST NOT be the internal representation.
- robigus tracks only the `linux` platform. Other platforms are recorded as `Unsupported` stubs (for example `windows_unsupported`) and are not expanded.

### 4.5 Examples

- `rav1e`'s `asm` feature is available only on `amd64` and `arm64`:
  `feature("asm") && (arch("amd64") || arch("arm64"))`
- On `amd64`, `nasm` is required:
  `feature("asm") && arch("amd64")`
- On `arm64`, `gas` is required unless `CC=clang` is set:
  `feature("asm") && arch("arm64") && !env("CC" = "clang")`
- On `arm64` with `CC=clang`, `clang` is required:
  `feature("asm") && arch("arm64") && env("CC" = "clang")`
- Debian build-profile mapping: a test-only dependency is needed when `nocheck` is not active, i.e. `!build-profile("nocheck")`.
- Debian architecture qualifiers map directly: `foo [amd64 !arm64]` becomes `arch("amd64") && !arch("arm64")`.
- Cargo target-specific dependency: `[target.'cfg(any(target_os = "linux", target_family = "unix"))'.dependencies]` becomes `cfg("target_os" = "linux") || cfg("target_family" = "unix")`.

## 5. Dependency Graph Model

### 5.1 Nodes

A node is a concrete package instance identified by `PackageId` (name + version + source + ecosystem). The TSP is the root node; a project may have multiple roots (for example workspace members).

Source identity matches the persisted identity columns exactly (§11.2, §22.21): a git source is identified by its URL plus the exact commit (`SourceId.precise`) — the requested branch/tag/rev is stored (`source_reference`) but is not part of the identity, so the same commit requested by branch or by tag is one package; a tarball is identified by its URL plus its digest (`precise`, or the kind's `digest` when `precise` is unset); a Cargo registry package is identified by its normalized sparse index URL plus the `.crate` checksum (`precise`), whether it was fetched as the root or discovered as a dependency (§7.2, §8.1, §22.31); other sources compare structurally. The store rejects (`StoreError::Unrepresentable`) any `PackageId` that would not load back equal — in particular a version variant other than the one its ecosystem parses back to (SemVer for `rust`, dpkg for `ubuntu`, opaque otherwise).

```rust
pub struct Node {
    pub id: PackageId,
    /// Workspace-relative source directory, if the node exists in the analysis tree.
    pub path: Option<PathBuf>,
    pub status: AnalysisStatus,
    /// Features unified across the graph (Cargo resolver v2 semantics, §9).
    pub active_features: BTreeSet<String>,
    pub targets: Vec<Target>,
    pub provides: Vec<Provide>,   // virtual packages: name + optional version
    pub conflicts: Vec<Conflict>, // name + optional version constraint
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisStatus { NotStarted, Started, Complete, Error }
// Serialized exactly as "Not_Started", "Started", "Complete", "Error".
```

Analysis-status semantics:

- `Not_Started` — initial state; no analysis has been performed for this node.
- `Started` — analysis work has started but is not complete. The status MUST be persisted **before** work begins so an interrupted run can resume (§7.7).
- `Complete` — the node's analysis is complete. A node MAY be marked `Complete` only when every dependency edge it discovered resolves to a node that is also `Complete`. Edges with no target (unresolved requirements, §5.2) are exempt: they have no node to complete in Phase 1.
- `Error` — an error occurred that must be resolved before the analysis can complete; the failure is recorded in the node's `analysis_plan` rows.

### 5.2 Edges

An edge is a dependency relationship from a dependent node to a dependency node.

```rust
pub struct Edge {
    pub from: PackageId,
    /// `None` = unresolved requirement preserved for Phase 2.
    pub to: Option<PackageId>,
    pub requirement: Requirement,
    /// Set of categories; a dependency may serve several (§3).
    pub kinds: BTreeSet<DependencyKind>,
    /// Activation condition; default `true`.
    pub predicate: Predicate,
    pub confidence: u8,          // 0..=100
    pub evidence: Vec<Evidence>,
}

pub struct Requirement {
    pub kind: RequirementKind,   // Crate | PkgConfig | Header | Soname | Tool | Generic
    pub name: String,            // crate name, pkg-config module, header path, soname, tool name
    pub version_req: Option<VersionConstraint>,
}
```

An edge whose dependency cannot be resolved to a concrete node (for example a system library not yet mapped) has `to = None` and retains its requirement. This is how Phase 1 preserves information for Phase 2.

Merge policy: when two discoveries produce the same edge identity (same `from`, `to`, `requirement`, and `predicate`), their `kinds` sets are unioned, their evidence is merged, and the confidence is the maximum of the two. Conflicting discoveries are retained and reported rather than silently discarded.

### 5.3 Evidence and confidence

```rust
pub enum EvidenceMethod {
    Manifest,
    Lockfile,
    BuildScript,
    ToolOutput,
    SourceScan,
    Documentation,
    BuildObservation,
    LlmSubAgent,
    HumanOverride,
}

pub struct Evidence {
    pub method: EvidenceMethod,
    pub confidence: u8,          // 0..=100
    pub location: Option<SourceLocation>,
    pub detail: Option<String>,
}

pub struct SourceLocation {
    /// Workspace-relative file path.
    pub path: PathBuf,
    pub start_line: Option<u64>,
    pub end_line: Option<u64>,
}
```

Confidence is tiered on an L0–L4 ladder so that caps (for example for LLM evidence, §7.6) are enforceable:

| Tier | Confidence range | Meaning |
|---|---|---|
| L0 | 0–19 | Unsupported guess; MUST NOT be persisted as sole evidence |
| L1 | 20–39 | Documentation or naming heuristic only |
| L2 | 40–59 | Source scan with unverified anchors |
| L3 | 60–79 | Verified anchor or sandboxed tool output, not independently cross-checked |
| L4 | 80–100 | Cross-validated: two independent methods agree |

Merge policy: retain all evidence; an edge's confidence is the maximum of its evidence. `check` MUST validate that persisted evidence respects tier caps (in particular `LlmSubAgent` evidence MUST NOT exceed L3).

### 5.4 Required model changes

The existing `model.rs` MUST be extended as follows before M1 closes:

- Add `DependencyKind::Runtime`; convert `Dependency.kind` (and edges) to a kind **set** (`BTreeSet<DependencyKind>`).
- Replace `Dependency.platform: Option<String>` with a `Predicate`.
- Model Cargo feature syntax with a `FeatureExpr` type (`Simple("foo")`, optional-dependency `foo?`, dependency-feature `foo/bar`, `foo?/bar`, `dep:foo`); `Dependency.features` becomes `BTreeSet<FeatureExpr>`.
- Replace `Resolve`/`ResolvedNode` with a `DependencyGraph` backed by `petgraph` (node weight = `Node`, edge weight = `Edge`) plus a `PackageId → NodeIndex` index. The current `ResolvedNode.dependencies: BTreeSet<PackageId>` cannot carry `kind`, `requirement`, `predicate`, or `evidence`. `Resolve.root` becomes `BTreeSet<PackageId>` (multiple roots).
- Unify `PackageVersion::Debian` with `dpkg::DpkgVersion` — one parser, one ordering. First fix `DpkgVersion`: it derives `Eq` structurally while `Ord` compares semantically, so `1.02 != 1.2` under `==` while comparing `Equal` under `Ord` — a broken `Ord`/`Eq` contract that corrupts sorted containers. `PartialEq` MUST agree with `Ord`. Identity ordering (as used by `Ord` on `PackageId`) and semantic version ordering MUST remain separate concerns.
- Delete or replace `solver.rs`'s `debian_compare_versions` stub (currently always `Equal`); it must not survive the solver rework (§9).
- Add `SourceKind::Tarball { url, digest }` so tarball inputs (§7.1) are representable; `SourceKind::Path` MUST record a deterministic tree digest so local-path analyses are reproducible.
- Give `DpkgVersion::parse` a typed `thiserror` error instead of `String`.
- Make `PackageId`'s `Display` include ecosystem and source so logs and reports are unambiguous.

## 6. Architecture

```mermaid
flowchart TD
    A[Source input: git URL, tarball, path, registry crate] --> B[Fetch and verify]
    B --> C[Safe extraction]
    C --> D[Project detection]
    D --> E[Analyzer registry]
    E --> F[Per-node analysis in sandbox]
    F --> G[Evidence and confidence merge]
    G --> H[Transitive expansion queue]
    H --> F
    G --> I[SQLite graph store]
    I --> J[Phase 2: Ubuntu archive mapping via rapt]
    J --> K[Phase 3: packaging plan via ubucargo]
```

### 6.1 Components

- **Acquisition** (`fetch`): fetch repositories, tarballs, and registry crates (with registry authentication, §7.2.2); verify digests; cache by content hash.
- **Detection** (`detect`): identify languages, build systems, test systems, and analyzers with a confidence score.
- **Analyzers** (`analyzers`): per-ecosystem discovery of direct dependencies and artifacts.
- **Expansion** (`expand`): recursive work queue over nodes, deduplication, cycle detection (SCC), analysis-plan selection, per-node status tracking, and resumability.
- **Store** (`store`): SQLite persistence, schema migration, integrity checking, export.
- **Mapping** (`mapping`, Phase 2): Ubuntu archive lookup and dependency-to-package mapping.
- **Plan** (`plan`, Phase 3): packaging classification and template generation.

### 6.2 Async model

- All public APIs that perform I/O are `async` and run on `tokio` (for example `ProjectTree::discover`, whose blocking walk runs in `spawn_blocking`). The deliberate exceptions are `ProjectAnalyzer::detect` and the free function `detect::detect`, which are synchronous by design: pure inspection of an in-memory `ProjectTree` with no I/O (§7.5).
- Network I/O uses `reqwest`; git uses `gix`. `gix` operations are blocking and MUST run inside `spawn_blocking`.
- Blocking work (SQLite, archive extraction, CPU-bound parsing) MUST run in `tokio::task::spawn_blocking`.
- CPU-bound analysis MAY use `rayon` inside a blocking task.
- Analyzers are `Send + Sync` and may run concurrently, subject to a configurable concurrency limit.

### 6.3 Recommended crates and tools

| Concern | Crate/tool | Phase |
|---|---|---|
| Async runtime | `tokio` | 1 |
| HTTP | `reqwest` | 1 |
| Git | `gix` | 1 |
| Archive extraction | `tar`, `flate2`, `xz2`, `zstd` | 1 |
| Checksums | `sha2` | 1 |
| Rust metadata | `cargo_metadata`, `toml_edit` | 1 |
| Graph algorithms | `petgraph` | 1 |
| Core types | `serde`, `thiserror`, `semver`, `url`, `async-trait`, `ubuntu-info-rust` | 1 |
| SQLite | `rusqlite` (bundled), `rusqlite_migration` | 1 |
| CLI | `clap` | 1 |
| Logging | `tracing`, `tracing-subscriber` | 1 |
| Diagnostics | `miette` | 1 |
| File traversal | `walkdir`, `ignore` | 1 |
| pkg-config | `pkg-config` | 1 |
| Sandbox | `landlock`, `nix`, `bubblewrap` (external) | 1 |
| Build-file parsing | `regex`, `tree-sitter` (later) | 1–2 |
| Ubuntu archive | `rapt`, `ubuntu-info-rust` | 2 |
| Constraint solving | `pubgrub` or `resolvo` | 2–3 |
| Packaging templates | `ubucargo` | 3 |
| Testing | `insta`, `proptest`, `cargo-fuzz`, `wiremock`, `assert_cmd`, `predicates`, `tempfile` | 1 |

## 7. Target Software Project Analyzer (`tsp-analyzer`)

`tsp-analyzer` is the entry point. It is available as a Rust library and as a CLI.

### 7.1 Inputs

- Git URL (with optional branch, tag, or revision),
- tarball URL,
- local path,
- registry crate: a crate name and exact version in a Cargo sparse registry — crates.io by default, or a private registry that serves the same index and `.crate` formats, with or without authentication (§7.2, §22.30–33).

### 7.2 Acquisition and extraction

- Fetch into a content-addressed cache keyed by URL and digest (`--cache <PATH>`, default under the XDG cache directory). The cache is trusted local state owned by the invoking user: digests are verified when an entry is created, and a later hit is not re-verified. Anyone able to write the cache can alter analysis inputs, so it must not be shared with less-trusted users.
- **Checksum provenance**: registry `.crate` artifacts MUST be verified against the checksum recorded in the registry index (mandatory, never optional). Git sources MUST record the exact resolved commit; when a lockfile pins it, that revision is used. A bare tarball URL has no trusted digest unless one is supplied via configuration or CLI; robigus records the computed SHA-256 and marks the provenance `unverified` in metadata.
- Path inputs: a deterministic tree digest (hash over the canonical, sorted file list and contents) MUST be computed so local-path analyses are reproducible.
- Extract with `tar` plus `flate2`/`xz2`/`zstd`.
- Extraction MUST reject absolute paths, `..` traversal, symlinks escaping the destination, device nodes, and setuid/setgid entries; it MUST enforce entry-count and total-size limits (decompression-bomb protection).
- Never execute anything during extraction.
- **Download limits**: every HTTP download (tarballs, registry index entries and `.crate` files) has a connect timeout, a whole-request timeout, and a size cap; bodies are streamed and abandoned once over the cap, never buffered unbounded (`DownloadLimits`).
- **Git**: the whole clone, checkout, and submodule fetch is bounded by a wall-clock timeout, and the checked-out tree is held to the same entry-count and total-size limits as an extracted tarball (checked after checkout). Submodules are checked out recursively at the commit the superproject pins (`update = none` submodules are skipped), within depth and count limits. `.gitmodules` is untrusted: submodule names and paths are validated (no traversal, no symlink crossing) and only allowlisted URL schemes are fetched — `https` by default — so a hostile `file://` or `ssh://` URL cannot pull local repositories or use host credentials (`GitOptions`, §22.24).
- **HTTP redirects** (every download: tarballs, registry index files and `.crate` files): at most 5 hops, and never from `https` to `http`. Redirects to other hosts are followed, because registries and release hosts use CDNs, but registry credentials are never forwarded to another host (§17).
- `FetchedSource::source_id()` pins the root's `SourceId.precise` to the recorded digest (resolved commit, archive digest, `.crate` checksum, or tree digest).

#### 7.2.1 Registry sources

A registry source names a crate and an exact version in a Cargo-compatible **sparse** registry (Cargo's [index format](https://doc.rust-lang.org/cargo/reference/registry-index.html)).

- **Index URL:** must be `sparse+https://…`. It is normalized by removing `sparse+`, lowercasing the scheme and host, dropping a default port, and adding a trailing slash; userinfo, a query or a fragment are rejected. A URL without the `sparse+` prefix is a **git** index in Cargo and is rejected with a hint to use the registry's sparse URL; git-protocol indexes are not supported. Plain `http` is accepted only through a library option for tests, never from the CLI or configuration. With no registry given, the index is crates.io.
- **crates.io identity:** crates.io is always `https://index.crates.io/`. Its legacy git URL, `https://github.com/rust-lang/crates.io-index` (with or without `registry+`), is mapped to that identity wherever it appears: source inputs, `Cargo.lock`, and `cargo metadata` output (§8.1).
- **Names and versions:** the version is exact (`semver::Version`); requirement operators and "latest" are rejected, so analyses are reproducible. Versions match ignoring build metadata, because an index may list each version only once ignoring build metadata; two records that differ only in build metadata make that crate's index malformed. The index file path uses the lowercased name; record names match case-insensitively and are reported as the index spells them. `-` and `_` are distinct (they name different index files); when a name is not found, the error suggests the other spelling. Names must be ASCII alphanumerics, `-` or `_`, start with a letter, and be at most 64 characters.
- **Index lookups:** `config.json` is requested first, then the crate's index file. A 404, 410 or 451 for the index file means the crate does not exist. Unknown `config.json` fields are ignored. Malformed lines for *other* versions, and records whose schema version `v` is above 2, are skipped; a malformed or duplicate record for the requested version is an error.
- **Download URL:** derived only from `config.json`'s `dl`, with the markers `{crate}`, `{version}`, `{prefix}`, `{lowerprefix}` and `{sha256-checksum}`; when `dl` contains none, `/{crate}/{version}/download` is appended. Substituted values are percent-encoded. Index records cannot override the download location.
- **Verification:** the record's `cksum` must be 64 hexadecimal characters, and the downloaded `.crate` MUST match it; the result has `Provenance::Verified`. A caller may also supply an expected SHA-256, which must equal `cksum`. The index itself is trusted over TLS, as in Cargo.
- **Yanked versions** are refused unless the caller explicitly allows them (`--allow-yanked`); an allowed yanked fetch is reported as yanked and, for `analyze`, recorded in the metadata options.
- **Cache and contents:** the cache entry is `crate/<cksum>`, separate from `tarball/`, so identical bytes from different registries share one entry. The `.crate` is a gzip tarball extracted with the same hardening and limits as any tarball; it MUST contain exactly one top-level entry, a directory named `<name>-<version>`, which becomes the source tree. Nothing in it is executed.
- **Offline:** a registry source can be served offline only when its checksum is supplied and that cache entry exists. The yanked state cannot be checked offline and is reported as unknown.
- **Network:** registry fetches run on the host, like git and tarball fetches, bounded by `DownloadLimits`. They do not use the sandbox proxy, and the analysis allowlist (§10.2) does not apply to them.

#### 7.2.2 Registry authentication

Private registries may require a token, as described by Cargo's [registry authentication](https://doc.rust-lang.org/cargo/reference/registry-authentication.html) and [credential provider protocol](https://doc.rust-lang.org/cargo/reference/credential-provider-protocol.html). A token grants access to private source code: it MUST NOT reach any host other than its registry, the database, exports, logs, error messages, the process list, the sandbox, or core dumps, and robigus MUST NOT store it.

- **When a token is used:** only for a registry whose `config.json` declares `"auth-required": true`, or that answers the unauthenticated `config.json` request with 401, in which case robigus obtains a token and retries `config.json` with it. A token is never obtained, read or sent for a registry that does not require one, including crates.io.
- **Sources:** each named registry in robigus's configuration (`[registries.<name>]`, §14) uses exactly one credential source:
  - an environment variable, `ROBIGUS_REGISTRY_<NAME>_TOKEN`, where `<NAME>` is the registry name uppercased with `-` replaced by `_` (the default);
  - a credential process implementing Cargo's credential provider protocol (a `get` request with operation `read`), given as an absolute path and argument vector and run without a shell, with a cleared environment except `PATH` and `HOME`, no inherited descriptors other than stdio, a timeout and a bounded response. Its stdout is parsed as protocol messages and never logged. Tokens it marks `cache: "never"` are not reused; `session` and `expires` tokens are cached in memory for the current process only, until expiry;
  - a token file at an absolute path, which MUST be a regular file owned by the invoking user, not reached through a symlink, and inaccessible to group and others (mode `0600` or stricter); the token is its first line.
- **Never used:** Cargo's credentials file and configuration, `CARGO_REGISTRY_TOKEN`, `CARGO_REGISTRIES_*` variables, `.netrc`, or tokens on the command line. An index given directly with `--index` never uses credentials, so an ad-hoc URL cannot receive a token configured for a named registry.
- **Scoping:** a token is bound to its registry's normalized index URL. It is sent as the `Authorization` header only over `https`, and only to the index host and to the `dl` host from that registry's `config.json`. It is never sent on a redirect to another host, over `http`, or to any other host.
- **Handling:** tokens are held in a type that cannot be displayed, serialized or cloned, whose debug form is redacted, and which is zeroed when dropped. The header value is marked sensitive so HTTP tracing omits it. Core dumps are disabled for the process while a token is held. Registry and credential-process error text is bounded, and any echo of the active token is redacted.
- **Never recorded:** tokens and `Authorization` headers never appear in `FetchedSource`, the store, `tool_invocation`, exports, proxy logs, `tracing` output or error messages, and never enter the sandbox (§10.2).
- **Diagnostics:** 401 and 403 are reported distinctly (authentication required; token rejected or lacking access), naming the registry and the configured credential source but never the token. A `WWW-Authenticate: Cargo login_url="…"` challenge is shown so the user knows where to obtain a token. Requests are not retried in a loop.
- **Maintenance:** robigus has no `login` or `logout` commands; tokens are issued, rotated and revoked at the registry and its credential provider. Read-only, least-privilege tokens are recommended (`robigus/SECURITY.md`).

### 7.3 Detection

Detection uses marker files and produces a confidence score per signal:

| Marker | Signal |
|---|---|
| `Cargo.toml` | Rust/Cargo analyzer |
| `build.rs` | C/C++/assembly discovery inside the Rust analyzer |
| `CMakeLists.txt` | C/C++ strategy: CMake |
| `meson.build` | C/C++ strategy: Meson |
| `configure.ac` / `configure` | C/C++ strategy: Autotools |
| `Makefile` | C/C++ strategy: Make |
| `pyproject.toml` / `setup.py` | Python (future analyzer; recorded, not analyzed in v1) |
| `go.mod` | Go (future) |
| `package.json` | Node (future) |

v1 ships two analyzers: `cargo` and `cpp`. CMake, Meson, Autotools, and Make are **strategies inside the `cpp` analyzer**, not separate analyzers. Markers for future ecosystems are recorded in the analysis plan with status `Skipped` so the record shows what was seen but not analyzed.

Polyglot and monorepo projects MUST be supported: detection runs per subdirectory, and multiple analyzers may contribute to one project. Detection MUST skip `target/`, `vendor/`, `node_modules/`, `.git/`, and anything matched by the `ignore` crate's default rules. Crates under `vendor/` are analyzed only when referenced by an in-tree manifest; unreferenced vendored crates are not expanded. Workspace membership follows Cargo: `members` entries are globs whose `*` does not cross `/`, `exclude` entries are path prefixes that override `members`, and both are normalized (`./a` and `a/` name `a`). A Cargo package directory not reached by an ancestor workspace's `members` becomes a separate root only when it has its own `[workspace]` or is listed explicitly in an ancestor workspace's `exclude`; any other such package (test fixtures, examples) is recorded as a detection signal and a non-member crate, but is not a root. A package with no enclosing Cargo root (the top level, or an independent crate in a monorepo whose top level is not Cargo) is always a root. Root assignment MUST NOT depend on marker file names: markers attach to roots shallowest first.

The walk is bounded (`DetectionLimits`: a depth limit, default 64; an entry-count limit, default 500,000, whose violation fails detection; and a size cap on parsed build descriptions, default 1 MiB). Problems that do not stop detection — malformed, oversized, or unreadable manifests, invalid or escaping workspace entries, unreadable directories, reaching the depth limit — are recorded as `DetectionDiagnostic`s in the report and never silently change its meaning; a malformed manifest is treated as a plain (non-workspace) package.

### 7.4 Characteristics

The analyzer determines and records:

- project name and version;
- programming languages;
- build systems;
- testing systems;
- target machine architectures;
- target operating systems and platforms;
- the dependency mapping plan.

Detection infers what the tree alone shows (`ProjectCharacteristics`): name and version from the top-level Cargo manifest (or the only Cargo root; `workspace.package.version` when inherited), languages by file extension, analyzers and build systems from markers, and test systems from markers and build descriptions (Cargo's harness, CTest's `enable_testing()`/`add_test()`, Meson's `test()`, pytest's `conftest.py`/`pytest.ini`, Go's `*_test.go`). Target architectures and platforms are not inferable from markers; analyzers record them as predicates during analysis (§4, §8).

### 7.5 Analyzer registry

```rust
#[async_trait]
pub trait ProjectAnalyzer: Send + Sync {
    fn id(&self) -> AnalyzerId;
    /// Synchronous by design: pure marker inspection, no I/O.
    fn detect(&self, tree: &ProjectTree) -> Confidence;
    async fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<AnalyzerOutput, AnalyzerError>;
}
```

`AnalyzerOutput` contains discovered nodes (with status `Not_Started`), dependency edges, targets, provides/conflicts, evidence, analysis-plan rows, and follow-up expansion tasks. Analyzers MUST be deterministic given the same inputs and sandbox configuration.

### 7.6 Analysis strategies

The analysis plan selects one or more strategies per node:

- **Manifest** — parse declarative manifests (`Cargo.toml`, `pyproject.toml`, `package.json`).
- **Tool introspection** — run ecosystem tooling in the sandbox (for example `cargo metadata`).
- **Build observation** — execute a build or configure step in the sandbox and observe outputs (ELF `NEEDED` entries, `pkg-config` calls, generated files).
- **Documentation** — parse README and build instructions; optionally dispatch an LLM-assisted sub-agent for ambiguous projects.
- **Validation** — independently re-analyze a node, cross-check two analyzers, or dispatch a reviewer sub-agent.

In-process analyzers MUST be the default; sub-agents (out-of-process or LLM-assisted) are opt-in via configuration, run inside the same sandbox as any other analysis, and MUST record their evidence with method `LlmSubAgent`. The following rules apply to LLM sub-agents:

- **Line-level and AST anchor rule**: the sub-agent MUST return precise, continuous file paths with starting and ending lines for every claim. The orchestrator MUST parse these locations and verify that the referenced strings and constructs actually exist in the codebase before accepting the evidence. Claims that cannot be verified are discarded.
- **No-code-reproduction constraint**: to prevent token bloat and superficial pattern matching, sub-agents MUST NOT copy large chunks of source code into their reports. They MUST summarize the logic and map identifiers (variables, function signatures) rather than quoting exact text.
- **Confidence cap**: LLM-derived evidence MUST NOT exceed tier L3 (§5.3). It MUST NOT be the sole evidence for an edge when a deterministic method is available; when it is the only evidence, the edge is flagged in reports.
- Prompt-injection stance: TSP content is untrusted input to the sub-agent (§17). Sub-agents receive no host secrets or credentials, and no network access beyond the analysis allowlist (their LLM API endpoint must be added to the allowlist explicitly when enabled).

### 7.7 Recursive expansion

1. Start with the TSP root node or nodes.
2. For each node: create/refresh its `analysis_plan` rows, set status `Started` and **persist before work begins**, then run the chosen strategies in the sandbox.
3. Merge discovered edges and evidence (union `kinds`, max confidence, §5.2); upsert nodes and edges incrementally so the database always reflects progress.
4. Enqueue unresolved dependencies for expansion.
5. Deduplicate by `PackageId`; detect cycles with SCC analysis (cycles are legal — Cargo dev-dependency cycles — and are recorded, not errors); enforce configurable depth and node limits.
6. Mark a node `Complete` only when all of its targeted dependencies are `Complete` (unresolved requirements exempt, §5.1); failures mark the node `Error` with the cause recorded in its plan rows.
7. **Resume**: because one database is per analysis (§11), re-running `tsp-analyzer analyze` against an existing `--db` resumes the run: `Complete` nodes are skipped, `Started` nodes are re-analyzed, and `Error` nodes are retried after their cause is addressed. The recorded source identity (URI + digest) and configuration MUST match the request or the tool exits with code 3.
8. If limits stop expansion, the run finishes with an incomplete graph: exit code 5 is returned, and every non-`Complete` node remains queryable (§14).

## 8. Ecosystem Analyzers

### 8.1 Rust/Cargo (primary)

- Use `cargo_metadata` (`cargo metadata --format-version 1`) as the primary source; it handles workspace inheritance, target-specific dependencies, features, and resolved versions. It runs **in the sandbox with network access to the crates.io allowlist enabled by default** (§10), so the registry index can be fetched and updated. `toml_edit` is a fallback for offline runs (`--offline`); offline analyses produce declared-but-unresolved edges, record `network_mode = "offline"` in metadata, and carry reduced-confidence evidence.
- Use unfiltered `cargo metadata` (no `--filter-platform`) as the primary source so predicates for all targets are recorded. `cargo metadata --filter-platform <triple>` MAY be used in the Validation strategy to cross-check target-specific evaluation.
- Parse `[target.'cfg(...)'.dependencies]` (stored as `cfg` atoms, §4.1), optional dependencies, and feature syntax (`dep:foo`, `foo?/bar`) via `FeatureExpr`.
- Analyze `build.rs` for `cc`, `cxx`, `bindgen`, `pkg-config`, `cmake`, and `meson` usage, and for `cargo:` directives and the `links` key.
- Fetch registry crates as `.crate` tarballs (checksum-verified, §7.2.1); fetch git dependencies with `gix` (in `spawn_blocking`); read path dependencies from disk.
- **Registry identity:** map Cargo's `source` strings to `SourceKind::CargoRegistry` with the §7.2.1 index-URL normalization, including crates.io's legacy git URL, which becomes `https://index.crates.io/`. Set each registry package's `SourceId.precise` to the `checksum` recorded in `Cargo.lock`, so a crate that is both the root and a dependency is one node (§5.1). A registry dependency without a lockfile checksum, or from another git-protocol index, is declared-but-unresolved with a recorded reason.
- **Authenticated registries:** registry tokens never enter the sandbox (§7.2.2, §10.2), so `cargo metadata` cannot read authenticated registries in Phase 1. Dependencies hosted in one are declared-but-unresolved, with a reason naming the registry.
- **Path containment**: path dependencies MUST resolve only within the fetched source tree. A path dependency that escapes the analysis root (for example `path = "../../outside"`) MUST be rejected and recorded as an error on that node; the sandbox's read-only source mount enforces the same rule at execution time.
- Record both the declared requirement and the resolved version.

### 8.2 C/C++/assembly within Rust projects

- Parse `build.rs`, `CMakeLists.txt`, `meson.build`, `configure.ac`, and `Makefile` for `find_package`, `pkg_check_modules`, `PKG_CHECK_MODULES`, `AC_CHECK_LIB`, `dependency()`, `target_link_libraries`, and `-l` flags. These build systems are strategies inside the `cpp` analyzer (§7.3).
- Scan `#include <...>` directives for system headers.
- Use `pkg-config` (the crate or the tool in the sandbox) to resolve module names.
- Record system dependencies as unresolved requirements (pkg-config module, header, soname) for Phase 2 mapping.

### 8.3 Future ecosystems

Python, Go, and Node analyzers are out of scope for v1 but MUST fit the same `ProjectAnalyzer` trait and evidence model.

## 9. Dependency Resolution Policy

Phase 1 is a **graph expansion** problem, not a global version-solving problem.

- Concrete versions come from ecosystem-native resolution: `cargo metadata` and `Cargo.lock` for Rust; declared requirements for system dependencies.
- For Cargo nodes, robigus MUST delegate resolution and **feature unification** to cargo itself (resolver v2, via `cargo metadata`) and record the unified result. robigus MUST NOT re-implement Cargo's resolver or feature-unification semantics. Offline fallback edges are declared-but-unresolved.
- **Feature provenance**: because edges carry predicates with package-qualified feature atoms (§4.1), robigus MUST be able to answer "which root feature activations cause this node/requirement to be present" by walking reverse edges and evaluating predicates. The CLI exposes this as `print --why` (§14).
- The existing `solver.rs` traits (`DependencyProvider`, `ConflictPolicy`) remain the Phase 2 provider seam, but `ModularSolver` MUST be reframed as a graph expander or deleted. The current greedy work-queue sketch is not a resolver: it never populates `ResolvedNode.dependencies`, performs no backtracking, and does not unify features. It MUST NOT ship in v1 in its current form. If `ConflictPolicy` is retained for Phase 2, fix its pre-1.0 handling: keying Rust side-by-side domains by major version alone wrongly merges `0.1` and `0.2`, which Cargo treats as incompatible; key pre-1.0 by `major.minor`.
- Phase 2/3 MAY use a CDCL solver (`pubgrub` or `resolvo`) to select Ubuntu packages and acceptable version adjustments, with human-readable conflict explanations.

## 10. Sandboxed Analysis

Fetched sources are untrusted. All analysis that executes project code MUST run in a sandbox.

### 10.1 Threat model

- Malicious or compromised upstream source code, build scripts, `configure` scripts, and tests.
- Network exfiltration or fetching of unexpected content.
- Prompt injection through untrusted content fed to LLM sub-agents (§7.6, §17).
- Resource exhaustion (CPU, memory, disk, process count).
- Writes to the host filesystem or access to host secrets.

### 10.2 Requirements

- Run as an unprivileged user in isolated namespaces (mount, PID, network, user).
- Prefer `bubblewrap` (`bwrap`) when available; otherwise use Landlock plus seccomp and namespaces via the `landlock` and `nix` crates. The bubblewrap backend requires bubblewrap ≥ 0.11 (read-only overlay support; Ubuntu 26.04+); an older `bwrap` counts as unavailable.
- `--sandbox <mode>` accepts `auto` (default: `bwrap` if available, else native), `bwrap`, or `native`. There is **no** `none` mode.
- **Fail closed**: if no sandbox can be established — for example unprivileged user namespaces blocked by AppArmor on stock Ubuntu, `bwrap` missing, or seccomp/namespace setup failure — the tool MUST exit with code 4, print `no sandbox available`, and include a detailed diagnostic listing every mechanism attempted and why each failed. (Operator guidance, not a tool mode: run robigus where namespaces are permitted, such as a configured CI runner.)
- Mount the source tree read-only; provide writable tmpfs for build output and a writable `CARGO_HOME` inside the sandbox (required by `cargo metadata`).
- Do not expose the host home directory, SSH agent, environment secrets, or package manager credentials. Registry tokens (§7.2.2) are used only by host-side fetches and never enter the sandbox's environment, files or arguments.
- Network egress is restricted to the allowlist by default; `--offline` disables all egress, and configuration may narrow the allowlist further. Unrestricted, unproxied egress is never available.
- When egress is enabled, it MUST be mediated by an allowlisting forward proxy started by robigus and exposed to the sandbox (proxy environment variables), with direct egress blocked by the network namespace. The proxy validates CONNECT/SNI host names against the allowlist and logs every request.
  - Transport: the sandbox keeps its own network namespace. A fixed bootstrap (`/usr/bin/python3 -I -S` from the read-only runtime) binds `127.0.0.1:3128` inside it and passes the listening socket to robigus over a private socketpair before the workload starts; the workload holds neither. robigus serves that listener and connects upstream from the host.
  - Policy: HTTP/1.x `CONNECT` and absolute-form `GET`/`HEAD` `http://` requests only; literal DNS host names only (no IP literals); allowed ports (default 80, 443); the `Host` header must agree with the target; for `CONNECT`, the TLS ClientHello SNI must equal the `CONNECT` host, or the tunnel closes before any client byte is forwarded. Names resolving to any non-public address are refused. TLS is relayed unchanged (no MITM).
  - Logging: one JSON line per decision and per closed connection in `proxy.jsonl` in the invocation's log directory, mirrored as `tracing` events (target `robigus::proxy`).
- Default allowlist: `crates.io` subdomains (registry index and static/CDN hosts), `ubuntu.com` subdomains (archive, security, ports, changelogs), `github.com` subdomains (including codeload and release assets), `gitlab.com` subdomains, and `codeberg.org` subdomains. A configuration file or CLI parameter may add other hosts or remove defaults. Configuration: `[network] allowlist` replaces the defaults, `allow` adds hosts, and `deny` removes hosts; each entry covers its subdomains and denial always wins.
- Enforce wall-clock timeouts and cgroup v2 limits (memory, pids, CPU) when cgroup delegation is available; when it is not, fall back to timeouts and process limits and record that fact in metadata.
- Capture stdout and stderr and record the exact commands, environment (scrubbed), and tool versions for reproducibility (§11 `tool_invocation`).
- If a sandbox cannot be established, analysis MUST fail closed rather than run unsandboxed.

## 11. Dependency Graph Persistence

The SQLite file is the **source of truth** for one analysis of one target project and version. **One database is created per analysis**; re-running `analyze` against an existing database resumes that analysis (§7.7). Because there is exactly one analysis per database, the schema carries no `analysis_id` foreign keys.

### 11.1 Configuration

Use `rusqlite` with the `bundled` feature. All SQLite work runs inside `tokio::task::spawn_blocking` on a shared `Arc<Mutex<rusqlite::Connection>>`; `tokio-rusqlite` is unused. The mutex serializes access; reads (`load`, `check`) run inside deferred transactions so WAL readers see one consistent snapshot while an analysis writes. Schema migrations use the **`rusqlite_migration`** crate with `PRAGMA user_version`; there is no `schema_version` table. Apply:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA mmap_size = 268435456;
PRAGMA foreign_keys = ON;
PRAGMA temp_store = MEMORY;
```

WAL mode also allows `check`, `print`, and `export` to read a database while an analysis is writing it.

### 11.2 Schema (v1, `user_version = 1`)

```sql
CREATE TABLE metadata (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    robigus_version TEXT NOT NULL,
    project_name    TEXT NOT NULL,
    project_version TEXT NOT NULL,
    source_kind     TEXT NOT NULL,
    source_uri      TEXT NOT NULL,
    source_digest   TEXT NOT NULL DEFAULT '',
    configuration   TEXT NOT NULL,  -- JSON: primary Configuration used for analysis
    toolchain       TEXT NOT NULL,  -- JSON: tool name -> version (cargo, rustc, pkg-config, cc, ...)
    network_mode    TEXT NOT NULL,  -- 'allowlist' | 'offline'
    sandbox_mode    TEXT NOT NULL,  -- 'bwrap' | 'native'
    options         TEXT NOT NULL,  -- JSON: AnalysisOptions as applied
    created_at      TEXT NOT NULL,  -- RFC 3339, UTC
    updated_at      TEXT NOT NULL   -- RFC 3339, UTC
);

CREATE TABLE package (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,
    source_kind     TEXT NOT NULL,
    source_uri      TEXT NOT NULL DEFAULT '',
    source_precise  TEXT NOT NULL DEFAULT '',  -- git commit / tarball digest / .crate checksum; part of identity
    source_reference TEXT NOT NULL DEFAULT '', -- git only: 'default' | 'branch:<n>' | 'tag:<n>' | 'rev:<r>'; NOT identity
    is_root         INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'Not_Started',
    active_features TEXT NOT NULL DEFAULT '[]', -- JSON array of unified feature names
    path            TEXT NOT NULL DEFAULT ''    -- workspace-relative source dir; '' if none
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
    requirement_kind TEXT NOT NULL,   -- 'crate' | 'pkg_config' | 'header' | 'soname' | 'tool' | 'generic'
    version_req      TEXT NOT NULL DEFAULT '',
    kinds            TEXT NOT NULL,   -- JSON array of DependencyKind (a set)
    predicate        TEXT NOT NULL,   -- canonical serialization of the Predicate AST
    confidence       INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    evidence         TEXT NOT NULL    -- JSON array of Evidence
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
    kind       TEXT NOT NULL,              -- full serialized TargetKind (includes soname for shared libraries)
    soname     TEXT NOT NULL DEFAULT '',   -- denormalized for soname lookups (Phase 2)
    path       TEXT NOT NULL DEFAULT ''    -- Target.path; '' if none; NOT part of the unique index
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
    package_id   INTEGER REFERENCES package(id) ON DELETE CASCADE, -- node rows
    root_path    TEXT,              -- detection rows: workspace-relative root dir ('' = top level)
    analyzer     TEXT NOT NULL,     -- 'cargo' | 'cpp' | 'python' | 'go' | 'node'
    strategy     TEXT NOT NULL CHECK (strategy IN       -- §7.6 strategies
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
    CHECK ((package_id IS NULL) <> (root_path IS NULL))  -- exactly one subject
);
CREATE UNIQUE INDEX idx_plan_package ON analysis_plan
    (package_id, analyzer, strategy, build_system) WHERE package_id IS NOT NULL;
CREATE UNIQUE INDEX idx_plan_root ON analysis_plan
    (root_path, analyzer, strategy, build_system) WHERE package_id IS NULL;
CREATE INDEX idx_plan_status ON analysis_plan (status);

CREATE TABLE tool_invocation (
    id           INTEGER PRIMARY KEY,
    package_id   INTEGER REFERENCES package(id) ON DELETE SET NULL,
    tool         TEXT NOT NULL,     -- e.g. 'cargo metadata'; LLM sub-agent calls use 'llm-sub-agent'
    argv         TEXT NOT NULL,     -- JSON array; secrets scrubbed
    env          TEXT NOT NULL,     -- JSON object; secrets scrubbed
    tool_version TEXT,
    sandbox_mode TEXT NOT NULL,
    exit_status  TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    duration_ms  INTEGER NOT NULL,
    log_path     TEXT               -- workspace-relative path to full stdout/stderr
);
CREATE INDEX idx_invocation_package ON tool_invocation (package_id);
```

Schema conventions:

- JSON columns (`configuration`, `toolchain`, `options`, `kinds`, `predicate`, `evidence`, `active_features`) are serde-serialized model types; the store MUST validate them on load, and a parse error is an integrity failure.
- Nullable TEXT columns that participate in unique indexes (`path`, `soname`, `version`, `version_req`) are stored as `''` when absent so uniqueness holds (SQLite treats NULLs as distinct in unique indexes).
- The two partial unique indexes on `dependency_edge` make re-runs idempotent upserts and prevent duplicate edges on resume.

### 11.3 Migrations and integrity

- Schema changes MUST be versioned and applied through `rusqlite_migration` using `PRAGMA user_version`; migrations are forward-only. Opening a database with a **newer** schema version MUST fail with exit code 3.
- `tsp-analyzer check` MUST verify:
  - the schema version;
  - `PRAGMA foreign_key_check`;
  - no duplicate package identities (enforced by unique index, re-verified);
  - every `predicate`, `kinds`, `evidence`, `active_features` JSON value parses into its model type;
  - confidence values are within `0..=100` and within tier caps (in particular `LlmSubAgent` ≤ L3);
  - status invariants: a `Complete` node's targeted dependencies are `Complete`; `Started`/`Error` nodes have at least one plan row and `Error` nodes have a recorded error;
  - informational findings: unresolved requirements grouped by `requirement_kind`, cycles (SCCs with more than one node, plus any node with an edge to itself), and orphan nodes (no incoming edges and not a root).
- JSON export MUST be lossless with respect to the graph model (everything needed to reconstruct the `Analysis`); DOT export is a lossy visualization. A lossless `import` is future work.
- Losslessness applies to the model values the schema can represent. The store rejects (`StoreError::Unrepresentable`) — rather than silently altering — non-UTF-8 or empty optional paths, empty provide versions, version constraints whose stored text would not parse back identically, and JSON values (metadata options, predicates) nested beyond the default `serde_json` decoder limit. `Some(VersionConstraint::Any)` is stored as the sentinel `@any`, distinct from `''` (absent). Everything the store accepts round-trips exactly through JSON export and `AnalysisSnapshot::to_analysis`.

## 12. Ubuntu Archive Mapping (Phase 2)

Phase 2 uses `rapt` to determine which dependencies can be satisfied from the Ubuntu archive.

- Query package existence, versions, provides, and dependencies through `rapt`'s `ArchiveClient` and `RaptQuery`.
- `rapt` will be extended — in the `rapt` crate — with structured query APIs (its current `showpkg`/`depends` return human-readable strings) and with `Contents-<arch>.gz` index support for file-path-to-package mapping. These `rapt` features are not needed for Phase 1.
- Mapping rules (per the Debian Rust packaging policy, https://wiki.debian.org/Teams/RustPackaging/Policy):
  - Rust crates map to source package `rust-<crate>` with binary packages `librust-<crate>-dev` and feature variants `librust-<crate>+<feature>-dev`. The crate version is carried in the package **version**, not the package name.
  - pkg-config modules to `-dev` packages via `.pc` paths.
  - Headers to `-dev` packages via Contents.
  - Sonames to runtime library packages via Contents.
  - Python distributions to `python3-*` (future).
- Classify each requirement as `Satisfied`, `SatisfiedWithVersionAdjustment`, `Missing`, or `Unmapped`.
- Use a CDCL solver (`pubgrub` or `resolvo`) when version adjustments or alternatives must be chosen.

## 13. Packaging Plan (Phase 3)

For each dependency classified as `Missing`, generate a packaging template with `ubucargo`. `ubucargo` is published on crates.io (`canonical/ubucargo`) under GPL-3.0-or-later, which is compatible with robigus's GPL-3.0-only. It currently ships as a binary crate with no library target; Phase 3 integration MUST either invoke it as a subprocess or add/require a library target.

The plan:

1. orders packages so dependencies are packaged first, computed over the **SCC condensation** of the graph (dev/build dependency cycles are legal and must not break the sort);
2. records the classification and rationale for each dependency;
3. records the generated template location;
4. is persisted in SQLite and exportable as JSON.

## 14. Command-Line Tools

`tsp-analyzer` provides:

| Command | Purpose |
|---|---|
| `fetch <SOURCE>` | Acquire and verify a source; print the local path and digest. |

`SOURCE` is a local path, a git repository URL, a tarball URL, or `crate:<name>@<version>` for a registry crate (§7.2.1). The `crate:` form is recognized only when followed by a valid crate name, `@`, and an exact version; write `./crate:…` to name a local directory instead. Source options for `fetch` and `analyze`:

| Option | Applies to | Meaning |
|---|---|---|
| `--branch`, `--tag`, `--rev` | git | Reference to check out (mutually exclusive). |
| `--sha256 <DIGEST>` | tarball, registry | Expected SHA-256; required for offline cache hits. For a registry crate it must equal the index checksum. |
| `--registry <NAME>` | registry | Use a registry defined in `[registries.<name>]`; unknown names are usage errors. |
| `--index <URL>` | registry | Use a sparse index URL directly (`sparse+https://…`); never uses credentials. Conflicts with `--registry`. |
| `--allow-yanked` | registry | Allow an explicitly requested yanked version. |

Without `--registry` or `--index`, a registry crate comes from crates.io. Git options are usage errors for a registry source, and registry options for any other source. With `--format json`, `fetch` output for a registry crate adds `name`, `version` and `yanked` (`true`, `false`, or `null` when unknown offline).

Registry configuration in the `--config` file (Cargo's `[registries]` syntax; robigus never reads Cargo's own configuration):

```toml
[registries.internal]
index = "sparse+https://registry.example.com/index/"   # required; sparse+https only
credential-provider = { env = true }                    # default: ROBIGUS_REGISTRY_INTERNAL_TOKEN
# credential-provider = { process = ["/usr/bin/cargo-credential-libsecret"] }
# credential-provider = { file = "/home/user/.config/robigus/internal.token" }
```

Entries are validated when the configuration is loaded: index URLs must be `sparse+https`, and process and file paths must be absolute. The credential sources are specified in §7.2.2.
| `analyze <SOURCE>` | Fetch (if needed), analyze, and persist. Requires the global `--db`. If the database already exists, the analysis is **resumed**; the recorded source identity and configuration MUST match (§7.7). |
| `check <DB>` | Validate schema and graph well-formedness (§11.3). |
| `print <DB>` | Pretty-print the graph. Filters: `--kind`, `--arch`, `--platform`, `--feature`, `--build-profile`, `--series`, `--env`, `--depth`, `--status`, and `--why <PKG\|REQUIREMENT>` (feature/requirement provenance, §9). Filters evaluate predicates against the recorded configuration unless `--config` overrides it. |
| `export <DB> --format json\|dot` | Export the graph. JSON is lossless; DOT is a lossy visualization. |
| `version` | Print the tool version. |

Global options: `--db <PATH>` (required for commands that read or write a database; the per-command `--db` form is retired), `--format`, `--offline`, `--sandbox <auto|bwrap|native>`, `--jobs`, `--verbose`, `--config <PATH>`, `--cache <PATH>`.

Exit codes: `0` success, `1` analysis failure, `2` usage error, `3` database or schema error (including resume identity mismatch and newer schema version), `4` sandbox unavailable, `5` analysis finished with an incomplete graph (limits or node errors).

## 15. Library API

```rust
pub async fn analyze(input: SourceInput, options: AnalysisOptions) -> Result<Analysis>;

pub struct Analysis {
    pub metadata: AnalysisMetadata,
    pub graph: DependencyGraph,
}

pub enum SourceInput {
    Git { url: Url, reference: GitReference },
    Tarball { url: Url, digest: Option<String> },
    Path { path: PathBuf },
    Registry {
        registry: RegistrySpec,         // normalized sparse index URL (+ configured name)
        name: String,
        version: semver::Version,       // exact; no requirement operators
        digest: Option<String>,         // expected SHA-256; must equal the index cksum
    },
}

pub struct RegistrySpec {
    pub index_url: Url,                 // normalized; `SourceKind::CargoRegistry` identity
    pub name: Option<String>,           // configured name: credential lookup and diagnostics only
    pub credentials: CredentialSource,  // None | Env | Process | File (§7.2.2)
}

pub struct AnalysisOptions {
    pub configuration: Configuration,   // primary arch/platform/features/profiles/env/series
    pub network: NetworkPolicy,         // Allowlist(default) | Custom(Vec<Host>) | Offline
    pub sandbox: SandboxPreference,     // Auto | Bwrap | Native
    pub limits: Limits,                 // depth, node count, wall clock
}

pub struct Store { /* rusqlite connection behind a mutex, driven via spawn_blocking */ }
impl Store {
    pub async fn open(path: &Path) -> Result<Self>;               // create/open + migrate
    pub async fn metadata(&self) -> Result<AnalysisMetadata>;
    pub async fn upsert_node(&self, node: &Node) -> Result<()>;   // status written on first insert only
    pub async fn upsert_edges(&self, from: &PackageId, edges: &[Edge]) -> Result<()>;
    pub async fn upsert_plan_rows(&self, rows: &[PlanRow]) -> Result<()>; // root- or package-keyed
    pub async fn plan_rows(&self) -> Result<Vec<PlanRow>>;
    pub async fn update_status(&self, package: &PackageId, status: AnalysisStatus) -> Result<()>;
    pub async fn record_invocation(&self, invocation: &ToolInvocation) -> Result<()>;
    pub async fn load(&self) -> Result<Analysis>;
    pub async fn check(&self) -> Result<IntegrityReport>;
}

pub trait ProjectAnalyzer: Send + Sync { /* id, detect (sync), analyze (async) */ }
pub trait DependencyProvider: Send + Sync { /* Phase 2 seam */ }

#[async_trait]
pub trait Sandbox: Send + Sync {
    fn mode(&self) -> SandboxMode;   // Bwrap | Native
    async fn run(&self, command: &CommandSpec) -> Result<ProcessOutput, SandboxError>;
}
pub fn establish_sandbox(preference: SandboxPreference)
    -> Result<Box<dyn Sandbox>, SandboxUnavailable>;
```

- All public APIs that perform I/O are `async`; `ProjectAnalyzer::detect` and `detect::detect` are synchronous by design (pure in-memory inspection, §6.2, §7.5).
- `Store` methods are asynchronous: each operation clones the `Arc<Mutex<rusqlite::Connection>>` handle and runs in `tokio::task::spawn_blocking`; callers never touch `rusqlite` directly on an async thread.
- `SandboxUnavailable` implements `std::error::Error` and a `miette` diagnostic, and carries every attempted mechanism with its OS-level cause (drives exit code 4).
- `IntegrityReport` exposes the §11.3 findings as typed fields (schema version, foreign-key result, duplicate identities, invalid JSON columns, status violations, confidence-cap violations, unresolved-requirement counts, cycles, orphans).
- Public types MUST implement `Debug`; errors MUST implement `std::error::Error` via `thiserror`.
- Library code MUST NOT panic on malformed input.
- The CLI MUST use `miette` for user-facing diagnostics.
- `RegistrySpec` for an index given directly (`--index`) always has `CredentialSource::None`. Registry tokens are an opaque type with a redacted `Debug` and no `Display`, `Serialize` or `Clone` (§7.2.2); no public API returns a token.
- Plain `http` registry indexes are accepted only through a library option intended for tests; the CLI and configuration cannot enable them.

## 16. Testing Strategy

- **Unit tests** alongside modules (`#[cfg(test)]`).
- **Fixtures**: small synthetic projects under `tests/fixtures/` for each analyzer and build system (Cargo features, target-specific dependencies, `build.rs` with `cc`, workspaces, git and path dependencies, mixed C), plus fixtures for path-dependency escape attempts and vendored crates.
- **Snapshot tests** with `insta` for analyzer output and CLI output; snapshots MUST redact absolute paths, timestamps, and environment-dependent versions.
- **Property tests** with `proptest` for predicate canonicalization (idempotence, De Morgan, commutativity/associativity) and `dpkg` version comparison.
- **Fuzzing** with `cargo-fuzz` for the predicate parser and `dpkg` comparator; fuzz jobs run on nightly CI, separate from the stable gate.
- **Differential testing** of `dpkg.rs` against `dpkg --compare-versions` on an Ubuntu CI runner.
- **Store tests**: migration tests (open an older-version database → migrate; open a newer-version database → exit 3), round-trip save/load tests, and idempotent re-run (upsert) tests.
- **Resume tests**: interrupt an analysis mid-run, resume against the same database, and assert per-node status transitions including the `Complete` precondition.
- **Limit tests**: depth and node limits leave an incomplete graph, exit code 5, and queryable non-`Complete` nodes.
- **Extraction-hardening tests**: absolute paths, `..` traversal, escaping symlinks, device nodes, setuid/setgid entries, and decompression bombs are all rejected.
- **Containment tests**: a path dependency escaping the analysis root is rejected.
- **Integration tests** with `assert_cmd`, `predicates`, and `tempfile`.
- **Test isolation from the developer's environment**: tests that run external tools (for example `git` to build fixture repositories) MUST clear the inherited environment and run only inside temporary directories. The repository's pre-commit hook runs `cargo test`, and git exports `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, and similar variables to hooks; inherited, they redirect fixture commands to the enclosing repository.
- **HTTP mocking** with `wiremock` for registry and archive interactions, including sparse registries with each `dl` form, authenticated registries, and redirects.
- **Credential tests:** a canary token MUST NOT appear in debug output, errors (including a server that echoes it), `tracing` output, the store, `tool_invocation`, exports, or any request other than an in-scope HTTPS request; Cargo credential files and `CARGO_REGISTRIES_*` variables are ignored even when present.
- **Sandbox tests** verifying that analysis cannot reach non-allowlisted hosts or write outside its workspace.
- **CI** MUST run `cargo fmt -- --check`, `cargo clippy --locked --all-targets --all-features -- -D warnings`, `cargo doc --locked --no-deps --all-features`, `cargo test --locked --all-targets --all-features`, `cargo audit`, `cargo deny` (licenses and advisories), and an MSRV job pinned to 1.93.1; CI MUST trigger on pushes as well as pull requests.

## 17. Security

- Treat all fetched sources as untrusted; sandbox all execution (§10).
- Never execute build scripts outside the sandbox.
- Validate archive extraction (§7.2).
- Do not log secrets; scrub environment variables from sandbox logs and `tool_invocation` records.
- Registry credentials follow §7.2.2: tokens are read only from robigus's own configured sources, never stored, sent only to their registry's hosts over HTTPS, kept out of every record and of the sandbox, zeroed when dropped, and excluded from core dumps.
- LLM sub-agents: run sandboxed; never include host secrets or credentials in prompt context; treat their output as untrusted and require anchor verification (§7.6) before it becomes evidence; record their interactions in `tool_invocation` for audit.
- Record provenance for every discovered edge so results can be audited.
- Provide a robigus-specific `SECURITY.md` (`robigus/SECURITY.md`) with its own reporting path and sandbox scope; the workspace `SECURITY.md` covers the repository's other crates.
- Report vulnerabilities per `SECURITY.md`.

## 18. Coding Standards

- Follow idiomatic Rust as defined in `../rust-instructions.md`.
- Edition 2024; MSRV 1.93.1 (the default Rust toolchain on Ubuntu 26.04 LTS).
- License: GPL-3.0-only (matching `rapt`; `ubucargo` is GPL-3.0-or-later and compatible).
- Include `description`, `license`, `repository`, `keywords`, `categories`, and `rust-version = "1.93.1"` in `robigus/Cargo.toml`.
- Use `thiserror` for library errors and `miette` for CLI diagnostics; `DpkgVersion::parse` and every parser MUST return typed errors, never `String`.
- Use `tracing` for structured logging; never use `println!` for diagnostics in library code.
- Avoid `unwrap` and `expect` in library code; return `Result`.
- Use `spawn_blocking` for blocking I/O and CPU-bound work.
- `#![forbid(unsafe_code)]` at the crate root, with narrowly scoped `#[allow(unsafe_code)]` only inside `sandbox.rs` where `nix`/`landlock` require it.
- Document all public APIs with rustdoc and examples.

## 19. Folder Structure

```
/src
  lib.rs
  main.rs           # `tsp-analyzer` binary ([[bin]] name = "tsp-analyzer")
  model.rs          # core types (Node, Edge, Requirement, AnalysisStatus, …)
  predicate.rs      # predicate AST, parser, canonicalization, evaluation
  feature.rs        # FeatureExpr: Cargo feature syntax (dep:foo, foo?/bar)
  fetch.rs          # acquisition, verification, safe extraction
  detect.rs         # project detection and ProjectTree
  sandbox.rs        # sandbox abstraction and implementations
  analyzers/
    mod.rs
    cargo.rs        # Rust/Cargo
    cpp.rs          # C/C++/assembly; CMake/Meson/Autotools/Make strategies
  expand.rs         # graph expansion, dedup, SCC, resume, limits
  store.rs          # SQLite persistence, migrations, integrity
  mapping/          # Phase 2 (stub in v1)
  plan/             # Phase 3 (stub in v1)
/tests
  fixtures/
  integration tests
```

## 20. Persona

You are a Rust expert with deep knowledge of the Rust programming language, Cargo, `Cargo.toml`, and idiomatic Rust packaging.

You are an Ubuntu expert with deep knowledge of Ubuntu releases, packages, and the Ubuntu archive.

You are a Debian packaging expert with deep knowledge of `debian/control`, build profiles, architecture qualifiers, and dependency relationships.

## 21. Milestones

1. **M1 — Foundations**: predicate AST and parser (including `cfg` atoms), model extensions (§5.4: kind sets, `Runtime`, `Evidence`, `FeatureExpr`, `DependencyGraph`, `AnalysisStatus`, `SourceKind::Tarball`, dpkg unification with the `Eq`/`Ord` fix), SQLite store with `rusqlite_migration`, sandbox abstraction with fail-closed establishment, CLI skeleton, `check`, `print`, `export`; `robigus/Cargo.toml` metadata and a robigus `SECURITY.md`.
2. **M2 — Rust analysis**: Cargo analyzer (sandboxed `cargo metadata` with allowlisted network, unfiltered so predicates are recorded for all targets), transitive expansion with per-node status and resume, evidence and confidence merge, fixtures and snapshots.
3. **M3 — C/C++ and assisted analysis**: `cpp` analyzer (CMake/Meson/Autotools/Make strategies), sandboxed build-observation strategy, LLM sub-agent integration with anchor verification and the L3 confidence cap.
4. **M4 — Ubuntu mapping** (Phase 2, **not in v1**): `rapt` integration, structured `rapt` query APIs, Contents indices, classification.
5. **M5 — Packaging plan** (Phase 3, **not in v1**): `ubucargo` integration (subprocess or library target), SCC-condensed plan generation.

## 22. Recorded Decisions

Decisions binding on this specification:

1. v1 = M1–M3 only: TSP analysis, dependency graph discovery and expansion, persistence. M4/M5 are Phase 2/3.
2. Default network posture: crates.io access is allowed by default so `cargo metadata` can pull and update registry data; `--offline` disables egress. `toml_edit` remains the offline fallback.
3. Features follow Cargo's model; feature dependencies are mapped throughout the full graph, and the source of a feature-driven requirement is traceable via qualified feature predicates and `print --why`.
4. Cargo `cfg()` conditions are represented by a general `cfg("key" = "value")` atom, stored verbatim (no lossy mapping).
5. `kind` is a set per edge; no separate linkage attribute — `Depends` vs `Build-Depends` is decided in Phase 2/3 from the kind set plus the provider node's targets.
6. One SQLite database per analysis.
7. Predicates are persisted AST-only with query-time evaluation; no persisted CNF/DNF.
8. Sandboxing is mandatory and fails closed; there is no "none" mode. Failures exit 4 with detailed diagnostics of what was attempted.
9. Default network allowlist: crates.io, ubuntu.com, github.com, gitlab.com, codeberg.org (with subdomains); extendable/restrictable via configuration file or CLI.
10. LLM sub-agents are in v1: sandboxed, opt-in, anchor-verified (line-level and AST anchors verified by the orchestrator), subject to the no-code-reproduction constraint, and capped at confidence tier L3.
11. Per-node `AnalysisStatus` (`Not_Started`, `Started`, `Complete`, `Error`) drives resume; a node is `Complete` only when all of its targeted dependencies are `Complete`.
12. Ubuntu Rust package naming follows the Debian Rust packaging policy: `rust-<crate>` sources; `librust-<crate>-dev` and `librust-<crate>+<feature>-dev` binaries; version in the package version, not the name.
13. `rapt` will grow structured query APIs and Contents support in the future; Phase 1 does not depend on them.
14. `ubucargo` is published (crates.io, `canonical/ubucargo`, GPL-3.0-or-later); it is currently a binary crate, so Phase 3 integrates via subprocess or a future library target.
15. Persistence uses `rusqlite` (bundled) with `rusqlite_migration` on `PRAGMA user_version`; all SQLite work runs in `tokio::task::spawn_blocking` on a shared `Arc<Mutex<rusqlite::Connection>>` (§11.1), so `tokio-rusqlite` is unused. Turso was evaluated and rejected for v1: `turso-migrate` pins turso 0.4.x, which lacks CHECK-constraint and foreign-key enforcement, and turso 0.8.x does not enforce partial unique indexes — a swap would lose functionality (§11.2, §11.3).
16. `MachineArch` = `Ubuntu(Architecture)` | `All` | `Unsupported(String)`; `All` expands to the `ubuntu-info-rust` set; unsupported architectures are stubbed (`supported = false`, not expanded); the default analysis set excludes `i386` and includes `amd64v3`.
17. Separate analysis roots inside a Cargo root are limited to directories with their own `[workspace]` and crates listed explicitly in an ancestor workspace's `exclude`; other non-member crates are recorded, not rooted (§7.3).
18. Dependency-edge identity uses the canonical predicate in memory as well as in the store: `DependencyGraph::add_edge` canonicalizes the predicate, so equivalent spellings merge into one edge and a graph round-trips through the store unchanged (§4.3, §5.2).
19. A node's status is written only when it is first inserted (`Store::upsert_node`, and likewise `DependencyGraph::add_node`); every later change goes through `Store::update_status`, which enforces the §7.7 transitions. `update_status` also enforces the §11.3 plan invariants at write time, in the §7.7 order (plan rows first): `Started` requires at least one plan row, and `Error` requires a plan row with a recorded `error`.
20. `analysis_plan` rows are keyed by subject: detection rows by `root_path` (no package exists yet; future-ecosystem roots never get one), node rows by `package_id` — exactly one of the two is set. `strategy` holds the §7.6 strategies; the build system (`build_script`, `cmake`, `meson`, `autotools`, `make`) is a separate `build_system` column, part of the row key. Detection proposes `manifest` rows; expansion adds the other strategies per node.
21. A git package's identity is its URL plus the exact commit; the requested reference is stored in `package.source_reference` (kept from the first insert) and is not part of the identity. `SourceId`'s `Eq`/`Ord`/`Hash` follow the same identity.
22. `package_target.path` stores `Target.path` (`''` when absent; not part of the unique index). Schema v1 is unreleased and was amended in place for decisions 19–22; after release, schema changes MUST be new migrations.
23. `Store::record_invocation` requires an attributed package to be stored already (`StoreError::PackageNotFound` otherwise) and never creates a placeholder; `package_id: None` records invocations not tied to a node. Only edge-identity unique-constraint collisions take the merge path; any other constraint failure is a real error.
24. Git submodules are fetched by robigus itself (gix reads but does not clone them): recursively, at the superproject's pinned commits, within depth/count limits, from allowlisted schemes only (`https` by default). Download and git timeouts and size caps are configurable through `FetchOptions`.
25. Detection reports problems as diagnostics rather than failing or silently changing results, except exceeding the entry-count limit, which fails; its defaults are depth 64, 500,000 entries, and 1 MiB build descriptions.
26. Confidence is one bounded type, `model::Confidence` (0–100), shared by `Evidence`, `Edge`, and detection signals. `Confidence::new` clamps; `TryFrom<u8>` and deserialization reject values above 100, so an out-of-range confidence cannot be constructed in Rust or loaded from JSON; the database column has a CHECK. It serializes as a plain number.
27. The source cache is lock-free: work is staged in unique per-process scratch paths and published with an atomic `rename`; losing the race to an identical content-addressed entry is success.
28. Git acquisition is isolated from the caller's git setup: repositories are opened with `gix::open::Options::isolated()`, so `GIT_*` environment variables and global/system git configuration (for example `url.<base>.insteadOf` rewrites) cannot change what is fetched.
29. The sandbox-to-proxy transport is a listening socket created inside the sandbox's network namespace and passed to robigus (§10.2), rather than sharing the host network namespace or adding a forwarder process. The workload therefore never gains a route off the host, the seccomp socket policy is unchanged, and no extra binary is needed beyond the runtime's `/usr/bin/python3`. Upstream addresses are resolved on the host and must be public unicast; `ProxyPolicy::resolve` pins trusted addresses (mirrors, tests).
30. Registry sources (§7.2.1) support only the sparse protocol, given as `sparse+https://…`. Git-protocol indexes would require cloning a whole index repository, and a URL without `sparse+` is a git index in Cargo, so both are rejected with a hint. Versions are exact, so analyses are reproducible; resolving "latest" or a range is out of scope.
31. A registry package's identity is its normalized sparse index URL plus its `.crate` checksum, for fetched roots and for dependencies alike (dependencies take the checksum from `Cargo.lock`). crates.io is always `https://index.crates.io/`, and its legacy git URL maps to it everywhere, as Cargo does internally. The cache key is `crate/<cksum>`, separate from tarballs because the cached tree is the `.crate`'s single `<name>-<version>` directory.
32. Yanked registry versions are refused unless explicitly allowed, matching Cargo, which never resolves to a yanked version but allows one that is explicitly pinned.
33. Registry authentication is in v1 and designed in from the start (§7.2.2). robigus stores no tokens and reads them only from its own per-registry source (environment variable, Cargo-protocol credential process, or a `0600` token file), never from Cargo's credentials or configuration. Tokens are scoped to their registry's hosts over HTTPS, never follow cross-host redirects, never enter the sandbox or any record, are zeroed when dropped, and are excluded from core dumps. Authentication for registry dependencies resolved inside the sandbox is deferred: such dependencies are declared-but-unresolved in Phase 1.
34. Downloads follow at most 5 redirects and never downgrade from `https` to `http` (§7.2).

//! Source acquisition, verification, and safe extraction (spec §7.1, §7.2).
//!
//! All fetched content is untrusted: tarball extraction enforces the §7.2
//! hardening rules (path traversal, escaping links, device nodes, setuid/
//! setgid, entry-count and total-size limits), and every source records a
//! SHA-256 digest with explicit provenance. Git sources record the exact
//! resolved commit; registry `.crate` artifacts are checksum-verified against
//! the registry index (mandatory, never optional).

use crate::error::{FetchError, RobigusError};
use crate::model::{GitReference, SourceId, SourceKind, path_tree_digest};
use flate2::read::GzDecoder;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use tokio::task::spawn_blocking;
use url::Url;

// 1. Inputs and outcomes
/// A target software project as supplied by the caller (spec §7.1).
#[derive(Debug, Clone)]
pub enum SourceInput {
    Git { url: Url, reference: GitReference },
    Tarball { url: Url, digest: Option<String> },
    Path { path: PathBuf },
}

/// How strongly the recorded digest is vouched for (spec §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Provenance {
    /// The digest was supplied by a trusted party or computed from the exact
    /// content that will be analyzed.
    Verified,
    /// The digest was computed from downloaded content that nobody vouched
    /// for; recorded for reproducibility, not trust.
    Unverified,
}

/// A source acquired into the cache and ready for analysis.
#[derive(Debug, Clone)]
pub struct FetchedSource {
    /// Directory containing the source tree.
    pub tree: PathBuf,
    /// SHA-256 of the content (tree digest for paths, archive digest for
    /// tarballs, resolved commit for git).
    pub digest: String,
    pub provenance: Provenance,
    pub kind: SourceKind,
}

impl FetchedSource {
    /// The [`SourceId`] for the root package(s) of this source: the kind,
    /// pinned by the recorded digest as `precise` (spec §5.1, §22.21) — the
    /// resolved commit for git, the archive digest for a tarball, the tree
    /// digest for a path.
    pub fn source_id(&self) -> SourceId {
        SourceId {
            kind: self.kind.clone(),
            precise: Some(self.digest.clone()),
        }
    }
}

// 2. Content-addressed cache
/// The content-addressed source cache: `<root>/<kind>/<digest>` (spec §7.2).
#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// `XDG_CACHE_HOME/robigus`, falling back to `~/.cache/robigus`.
    pub fn default_dir() -> PathBuf {
        if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
            return PathBuf::from(xdg).join("robigus");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".cache").join("robigus");
        }
        std::env::temp_dir().join("robigus-cache")
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The cache location `<root>/<kind>/<key>`. Both parts MUST be a single
    /// safe path component: keys can originate from untrusted input (for
    /// example a revision in a TSP's `Cargo.lock`), and a key such as
    /// `../../x` would otherwise address a directory outside the cache.
    pub fn path_for(&self, kind: &str, key: &str) -> Result<PathBuf, FetchError> {
        validate_cache_component(kind)?;
        validate_cache_component(key)?;
        Ok(self.root.join(kind).join(key))
    }

    /// A fresh, unique scratch path under `<root>/tmp` for staging work that
    /// is moved into the cache only once it is complete.
    fn scratch_path(&self, label: &str) -> PathBuf {
        static SCRATCH: AtomicU64 = AtomicU64::new(0);
        self.root.join("tmp").join(format!(
            "{label}-{}-{}",
            std::process::id(),
            SCRATCH.fetch_add(1, Ordering::Relaxed)
        ))
    }
}

fn validate_cache_component(component: &str) -> Result<(), FetchError> {
    let safe = !component.is_empty()
        && !component.starts_with('.')
        && component
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if safe {
        Ok(())
    } else {
        Err(FetchError::InvalidCacheKey(component.to_string()))
    }
}

/// Normalizes a caller-supplied SHA-256 digest (trimmed, lowercase) and
/// rejects anything that is not exactly 64 hexadecimal characters.
fn normalize_sha256(digest: &str) -> Result<String, FetchError> {
    let normalized = digest.trim().to_ascii_lowercase();
    if normalized.len() == 64 && normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(normalized)
    } else {
        Err(FetchError::InvalidDigest(digest.to_string()))
    }
}

/// A full git object id: 40 (SHA-1) or 64 (SHA-256) hex characters,
/// normalized to lowercase. Abbreviated hashes, branch names, and anything
/// else return `None` and must be resolved by a fetch.
fn full_commit_hash(rev: &str) -> Option<String> {
    let normalized = rev.trim().to_ascii_lowercase();
    let is_hash =
        matches!(normalized.len(), 40 | 64) && normalized.chars().all(|c| c.is_ascii_hexdigit());
    is_hash.then_some(normalized)
}

// 3. Extraction limits
/// Decompression-bomb and resource-exhaustion guards (spec §7.2).
#[derive(Debug, Clone, Copy)]
pub struct ExtractionLimits {
    pub max_entries: u64,
    pub max_total_size: u64,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_total_size: 1024 * 1024 * 1024, // 1 GiB uncompressed
        }
    }
}

/// Bounds on every HTTP download (tarballs, registry index and `.crate`
/// files). Bodies are streamed and abandoned as soon as they exceed
/// `max_bytes`, so an oversized or endless response cannot exhaust memory.
#[derive(Debug, Clone, Copy)]
pub struct DownloadLimits {
    pub max_bytes: u64,
    pub connect_timeout: Duration,
    /// Wall-clock limit for one request, including reading the body.
    pub timeout: Duration,
}

impl Default for DownloadLimits {
    fn default() -> Self {
        Self {
            max_bytes: 512 * 1024 * 1024, // 512 MiB compressed
            connect_timeout: Duration::from_secs(30),
            timeout: Duration::from_secs(600),
        }
    }
}

/// Git acquisition policy.
#[derive(Debug, Clone)]
pub struct GitOptions {
    /// Wall-clock limit for the whole clone, checkout, and submodule fetch.
    pub timeout: Duration,
    /// Maximum submodule nesting depth (a superproject's own submodules are
    /// depth 1).
    pub max_submodule_depth: usize,
    /// Maximum number of submodules fetched in total.
    pub max_submodules: usize,
    /// URL schemes a submodule may be fetched from. `.gitmodules` is
    /// untrusted project content: the default allows only `https`, so a
    /// hostile `file://` or `ssh://` URL cannot pull a local repository or
    /// use host credentials.
    pub submodule_schemes: BTreeSet<String>,
}

impl Default for GitOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(600),
            max_submodule_depth: 4,
            max_submodules: 64,
            submodule_schemes: BTreeSet::from(["https".to_string()]),
        }
    }
}

/// Resource limits and policy for [`fetch`].
#[derive(Debug, Clone, Default)]
pub struct FetchOptions {
    pub download: DownloadLimits,
    /// Applied to extracted tarballs and to git checkouts (whose size can
    /// only be checked after checkout).
    pub extraction: ExtractionLimits,
    pub git: GitOptions,
}

// 4. Dispatch
/// Fetches a source into the cache (spec §7.2).
pub async fn fetch(
    input: SourceInput,
    cache: &Cache,
    options: &FetchOptions,
) -> Result<FetchedSource, RobigusError> {
    match input {
        SourceInput::Git { url, reference } => fetch_git(&url, &reference, cache, options).await,
        SourceInput::Tarball { url, digest } => {
            fetch_tarball(&url, digest.as_deref(), cache, options).await
        }
        SourceInput::Path { path } => fetch_path(&path).await,
    }
}

/// Fetches a git repository: clone into a scratch directory, resolve the
/// requested revision to a commit, check that commit out together with its
/// submodules (each at the commit the superproject pins), and move the tree
/// into the content-addressed cache. When the reference pins a revision that
/// is already cached, no network access happens.
///
/// The whole operation is bounded by [`GitOptions::timeout`]; the checked-out
/// tree is held to [`FetchOptions::extraction`] (checked after checkout, so
/// it bounds what analysis sees rather than transient disk use).
pub async fn fetch_git(
    url: &Url,
    reference: &GitReference,
    cache: &Cache,
    options: &FetchOptions,
) -> Result<FetchedSource, RobigusError> {
    let url = url.clone();
    let reference = reference.clone();
    let cache = cache.clone();
    let options = options.clone();
    spawn_blocking(move || {
        fetch_git_sync(&url, &reference, &cache, &options).map_err(RobigusError::from)
    })
    .await
    .map_err(|error| RobigusError::Fetch(FetchError::Git(format!("git task failed: {error}"))))?
}

/// Downloads a tarball, verifies its digest (when one was supplied), and
/// extracts it into the content-addressed cache. When the digest is pinned
/// and the tree is already cached, no network access happens.
pub async fn fetch_tarball(
    url: &Url,
    expected_digest: Option<&str>,
    cache: &Cache,
    options: &FetchOptions,
) -> Result<FetchedSource, RobigusError> {
    // Validated before any cache lookup or network access: the digest is
    // used as a cache key.
    let expected = expected_digest.map(normalize_sha256).transpose()?;
    if let Some(digest) = &expected {
        let cached = cache.path_for("tarball", digest)?;
        if cached.is_dir() {
            return Ok(FetchedSource {
                tree: cached,
                digest: digest.clone(),
                provenance: Provenance::Verified,
                kind: SourceKind::Tarball {
                    url: url.clone(),
                    digest: Some(digest.clone()),
                },
            });
        }
    }

    let bytes = download(url, &options.download).await?;
    let url = url.clone();
    let cache = cache.clone();
    let limits = options.extraction;
    spawn_blocking(move || {
        install_tarball(&bytes, expected.as_deref(), &url, &cache, &limits)
            .map_err(RobigusError::from)
    })
    .await
    .map_err(|error| {
        RobigusError::Fetch(FetchError::Download(format!(
            "extract task failed: {error}"
        )))
    })?
}

/// Computes the deterministic tree digest of a local path and analyzes it in
/// place (spec §7.2).
///
/// The tree and the recorded [`SourceKind::Path`] are both the canonical
/// absolute path.
pub async fn fetch_path(path: &Path) -> Result<FetchedSource, RobigusError> {
    let path = path.to_path_buf();
    spawn_blocking(move || -> Result<FetchedSource, RobigusError> {
        let tree = path.canonicalize().map_err(FetchError::from)?;
        let digest = path_tree_digest(&tree)?;
        Ok(FetchedSource {
            kind: SourceKind::Path { path: tree.clone() },
            tree,
            digest,
            provenance: Provenance::Verified,
        })
    })
    .await
    .map_err(|error| {
        RobigusError::Fetch(FetchError::Walk(format!("digest task failed: {error}")))
    })?
}

// 5. Git acquisition
fn fetch_git_sync(
    url: &Url,
    reference: &GitReference,
    cache: &Cache,
    options: &FetchOptions,
) -> Result<FetchedSource, FetchError> {
    if let Some((tree, commit)) = git_cache_hit(cache, reference)? {
        return Ok(FetchedSource {
            tree,
            digest: commit,
            provenance: Provenance::Verified,
            kind: SourceKind::Git {
                url: url.clone(),
                reference: reference.clone(),
            },
        });
    }

    let scratch = cache.scratch_path("clone");
    fs::create_dir_all(&scratch)?;
    let interrupt = Arc::new(AtomicBool::new(false));
    let cloned = {
        let _watchdog = Watchdog::start(options.git.timeout, interrupt.clone());
        checkout_tree(url, reference, &scratch, options, &interrupt)
    };
    if cloned.is_err() {
        let _ = fs::remove_dir_all(&scratch);
    }
    let commit = cloned.map_err(|error| {
        if interrupt.load(Ordering::SeqCst) {
            FetchError::Git(format!(
                "git fetch of {url} exceeded the {:?} time limit",
                options.git.timeout
            ))
        } else {
            error
        }
    })?;

    let tree = match cache.path_for("git", &commit) {
        Ok(tree) => tree,
        Err(error) => {
            let _ = fs::remove_dir_all(&scratch);
            return Err(error);
        }
    };
    install_into_cache(&scratch, &tree, &cache.root.join("git"))?;

    Ok(FetchedSource {
        tree,
        digest: commit,
        provenance: Provenance::Verified,
        kind: SourceKind::Git {
            url: url.clone(),
            reference: reference.clone(),
        },
    })
}

/// Clones `url` at `reference` into `dest`, checks out its submodules, and
/// holds the result to the extraction limits. Returns the resolved commit.
fn checkout_tree(
    url: &Url,
    reference: &GitReference,
    dest: &Path,
    options: &FetchOptions,
    interrupt: &AtomicBool,
) -> Result<String, FetchError> {
    let commit = clone_and_checkout(url, reference, dest, interrupt)?;
    let mut fetched = 0;
    checkout_submodules(dest, &options.git, interrupt, 1, &mut fetched)?;
    check_worktree_limits(dest, &options.extraction)?;
    Ok(commit)
}

/// Sets a flag once a timeout elapses, unless dropped first. gix polls the
/// flag (its `should_interrupt`) and aborts the running fetch or checkout.
struct Watchdog {
    done: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    fn start(timeout: Duration, flag: Arc<AtomicBool>) -> Self {
        let (done, finished) = mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            if let Err(mpsc::RecvTimeoutError::Timeout) = finished.recv_timeout(timeout) {
                flag.store(true, Ordering::SeqCst);
            }
        });
        Self {
            done: Some(done),
            thread: Some(thread),
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        // Disconnecting the channel wakes the thread without setting the flag.
        drop(self.done.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// One submodule to check out, read from the superproject before cloning.
struct PendingSubmodule {
    name: String,
    path: String,
    commit: String,
    url: String,
}

/// Checks out every submodule of the repository at `worktree` at the commit
/// its superproject pins, recursively (gix reads submodule metadata but does
/// not clone submodules). `.gitmodules` is untrusted: names must validate,
/// paths must stay inside the worktree without crossing a symlink, and URLs
/// must use an allowed scheme. Submodules configured `update = none` and
/// entries without a gitlink in `HEAD` are skipped, as `git submodule update
/// --init --recursive` would.
fn checkout_submodules(
    worktree: &Path,
    options: &GitOptions,
    interrupt: &AtomicBool,
    depth: usize,
    fetched: &mut usize,
) -> Result<(), FetchError> {
    let git = |what: &str, error: &dyn std::fmt::Display| {
        FetchError::Git(format!(
            "submodule {what} in {}: {error}",
            worktree.display()
        ))
    };
    let pending = {
        let repo = gix::open_opts(worktree, gix::open::Options::isolated())
            .map_err(|error| git("discovery", &error))?;
        let Some(submodules) = repo
            .submodules()
            .map_err(|error| git("discovery", &error))?
        else {
            return Ok(());
        };
        let mut pending = Vec::new();
        for submodule in submodules {
            let name = submodule
                .validated_name()
                .map_err(|error| git("name", &error))?
                .to_string();
            let update = submodule.update().map_err(|error| git(&name, &error))?;
            if matches!(update, Some(gix::submodule::config::Update::None)) {
                continue;
            }
            let Some(commit) = submodule.head_id().map_err(|error| git(&name, &error))? else {
                continue;
            };
            let path = submodule.path().map_err(|error| git(&name, &error))?;
            let url = submodule
                .resolved_url()
                .map_err(|error| git(&name, &error))?;
            pending.push(PendingSubmodule {
                path: path.to_string(),
                commit: commit.to_string(),
                url: url.to_bstring().to_string(),
                name,
            });
        }
        pending
    };

    for submodule in pending {
        if depth > options.max_submodule_depth {
            return Err(FetchError::Git(format!(
                "submodule '{}' exceeds the nesting limit of {}",
                submodule.name, options.max_submodule_depth
            )));
        }
        *fetched += 1;
        if *fetched > options.max_submodules {
            return Err(FetchError::Git(format!(
                "more than {} submodules",
                options.max_submodules
            )));
        }
        let rel = Path::new(&submodule.path);
        if rel.as_os_str().is_empty()
            || !rel
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            return Err(FetchError::Git(format!(
                "submodule '{}' path '{}' escapes the worktree",
                submodule.name, submodule.path
            )));
        }
        ensure_no_symlink_components(worktree, rel)?;
        let url = Url::parse(&submodule.url)
            .ok()
            .filter(|url| options.submodule_schemes.contains(url.scheme()))
            .ok_or_else(|| {
                FetchError::Git(format!(
                    "submodule '{}' URL '{}' is not allowed: only {:?} URLs may be fetched",
                    submodule.name, submodule.url, options.submodule_schemes
                ))
            })?;
        let dest = worktree.join(rel);
        // The superproject checkout leaves the gitlink as an empty directory
        // (or nothing); anything else means the path is already in use.
        match fs::read_dir(&dest) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    return Err(FetchError::Git(format!(
                        "submodule '{}' path '{}' is not empty",
                        submodule.name, submodule.path
                    )));
                }
                fs::remove_dir(&dest)?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        create_parent_dirs(&dest)?;
        let checked_out = clone_and_checkout(
            &url,
            &GitReference::Rev(submodule.commit.clone()),
            &dest,
            interrupt,
        )?;
        if checked_out != submodule.commit {
            return Err(FetchError::Git(format!(
                "submodule '{}' resolved to {checked_out}, expected {}",
                submodule.name, submodule.commit
            )));
        }
        checkout_submodules(&dest, options, interrupt, depth + 1, fetched)?;
    }
    Ok(())
}

/// Holds a checked-out tree (excluding `.git` directories) to the extraction
/// limits, so git sources face the same bounds as tarballs before analysis.
fn check_worktree_limits(root: &Path, limits: &ExtractionLimits) -> Result<(), FetchError> {
    let mut entries: u64 = 0;
    let mut total: u64 = 0;
    let walker = walkdir::WalkDir::new(root)
        .min_depth(1)
        .into_iter()
        .filter_entry(|entry| entry.file_name() != ".git");
    for entry in walker {
        let entry = entry.map_err(|error| FetchError::Walk(error.to_string()))?;
        entries += 1;
        if entries > limits.max_entries {
            return Err(FetchError::Git(format!(
                "checkout exceeds the entry-count limit of {}",
                limits.max_entries
            )));
        }
        if entry.file_type().is_file() {
            let size = entry
                .metadata()
                .map_err(|error| FetchError::Walk(error.to_string()))?
                .len();
            total = total.saturating_add(size);
            if total > limits.max_total_size {
                return Err(FetchError::Git(format!(
                    "checkout exceeds the total-size limit of {}",
                    limits.max_total_size
                )));
            }
        }
    }
    Ok(())
}

/// Moves a completed staging tree to its content-addressed cache location.
///
/// The cache needs no lock: staging paths are unique per process and call,
/// and an entry appears atomically via `rename`. When another process or
/// task installs the same content first, our rename fails because the
/// target already exists; since both trees have the same content address,
/// the existing entry is used and the staging copy discarded.
fn install_into_cache(staging: &Path, tree: &Path, kind_dir: &Path) -> Result<(), FetchError> {
    fs::create_dir_all(kind_dir)?;
    if let Err(error) = fs::rename(staging, tree) {
        let _ = fs::remove_dir_all(staging);
        if !tree.is_dir() {
            return Err(error.into());
        }
    }
    Ok(())
}

/// A pinned revision that is already cached needs no network access. Only a
/// full commit hash may address the cache: it is the content address the
/// cache is keyed by, and any other string (a branch, a short hash, or a
/// hostile `../..` value from an untrusted lockfile) must be resolved by a
/// fetch instead.
fn git_cache_hit(
    cache: &Cache,
    reference: &GitReference,
) -> Result<Option<(PathBuf, String)>, FetchError> {
    let GitReference::Rev(rev) = reference else {
        return Ok(None);
    };
    let Some(commit) = full_commit_hash(rev) else {
        return Ok(None);
    };
    let cached = cache.path_for("git", &commit)?;
    Ok(cached.is_dir().then_some((cached, commit)))
}

/// Clones `url` into `dest` and checks out `reference`. The repository is
/// opened *isolated*: no environment variables (`GIT_DIR`,
/// `GIT_INDEX_FILE`, `GIT_CONFIG_*`, …) and no global or system git
/// configuration are consulted. The result therefore cannot depend on the
/// caller's git setup (for example a URL `insteadOf` rewrite) or on the
/// repository variables git exports to hooks.
fn clone_and_checkout(
    url: &Url,
    reference: &GitReference,
    dest: &Path,
    interrupt: &AtomicBool,
) -> Result<String, FetchError> {
    let mut prepare = gix::clone::PrepareFetch::new(
        url.as_str(),
        dest,
        gix::create::Kind::WithWorktree,
        gix::create::Options::default(),
        gix::open::Options::isolated(),
    )
    .map_err(|error| FetchError::Git(format!("clone preparation failed: {error}")))?;
    let (mut prepare_checkout, _) = prepare
        .fetch_then_checkout(gix::progress::Discard, interrupt)
        .map_err(|error| FetchError::Git(format!("fetch failed: {error}")))?;

    let commit = resolve_commit(prepare_checkout.repo(), reference)?;
    point_head_at(prepare_checkout.repo(), &commit)?;

    prepare_checkout
        .main_worktree(gix::progress::Discard, interrupt)
        .map_err(|error| FetchError::Git(format!("checkout of {commit} failed: {error}")))?;
    Ok(commit.to_string())
}

fn resolve_commit(
    repo: &gix::Repository,
    reference: &GitReference,
) -> Result<gix::hash::ObjectId, FetchError> {
    let peeled = |spec: String| -> Result<gix::hash::ObjectId, FetchError> {
        let id = repo
            .rev_parse_single(spec.as_str())
            .map_err(|error| FetchError::Git(format!("revision '{spec}' not found: {error}")))?;
        let commit = id
            .object()
            .map_err(|error| FetchError::Git(format!("revision '{spec}' is unreadable: {error}")))?
            .peel_to_kind(gix::object::Kind::Commit)
            .map_err(|error| {
                FetchError::Git(format!(
                    "revision '{spec}' does not peel to a commit: {error}"
                ))
            })?;
        Ok(commit.id().detach())
    };
    match reference {
        GitReference::DefaultBranch => repo
            .head_id()
            .map(|id| id.detach())
            .map_err(|error| FetchError::Git(format!("no default branch: {error}"))),
        // A clone creates a local branch only for the remote's default
        // branch; every other branch exists as a remote-tracking ref.
        GitReference::Branch(name) => peeled(format!("refs/heads/{name}"))
            .or_else(|_| peeled(format!("refs/remotes/origin/{name}"))),
        GitReference::Tag(name) => peeled(format!("refs/tags/{name}")),
        GitReference::Rev(rev) => peeled(rev.clone()),
    }
}

/// Points HEAD (detached) at `commit` so the clone's worktree checkout
/// materializes exactly the revision under analysis.
fn point_head_at(repo: &gix::Repository, commit: &gix::hash::ObjectId) -> Result<(), FetchError> {
    let edit = gix::refs::transaction::RefEdit {
        change: gix::refs::transaction::Change::Update {
            log: gix::refs::transaction::LogChange {
                mode: gix::refs::transaction::RefLog::AndReference,
                force_create_reflog: false,
                message: gix::bstr::BString::from("robigus: checkout analysis revision"),
            },
            expected: gix::refs::transaction::PreviousValue::Any,
            new: gix::refs::Target::Object(*commit),
        },
        name: gix::refs::FullName::try_from("HEAD")
            .map_err(|error| FetchError::Git(format!("HEAD is not a valid ref name: {error}")))?,
        deref: false,
    };
    repo.edit_reference(edit)
        .map_err(|error| FetchError::Git(format!("failed to point HEAD at {commit}: {error}")))?;
    Ok(())
}

// 6. Tarball acquisition
async fn download(url: &Url, limits: &DownloadLimits) -> Result<Vec<u8>, FetchError> {
    let failed = |error: &dyn std::fmt::Display| {
        FetchError::Download(format!("download of {url} failed: {error}"))
    };
    let response = http_client(limits)
        .map_err(|error| failed(&error))?
        .get(url.as_str())
        .send()
        .await
        .map_err(|error| failed(&error))?
        .error_for_status()
        .map_err(|error| failed(&error))?;
    read_capped(response, limits.max_bytes)
        .await
        .map_err(|error| failed(&error))
}

/// The HTTP client for every download: robigus user agent plus the connect
/// and whole-request timeouts.
fn http_client(limits: &DownloadLimits) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(http_user_agent())
        .connect_timeout(limits.connect_timeout)
        .timeout(limits.timeout)
        .build()
}

/// Reads a response body, failing as soon as it exceeds `max_bytes`: a
/// declared `Content-Length` over the limit is rejected before reading, and
/// an undeclared or lying body is cut off while streaming.
async fn read_capped(mut response: reqwest::Response, max_bytes: u64) -> Result<Vec<u8>, String> {
    let too_large = || format!("response exceeds the {max_bytes}-byte download limit");
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        if (body.len() + chunk.len()) as u64 > max_bytes {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Verifies and installs a downloaded tarball: digest check, extraction into
/// the content-addressed cache. Sync so tests can drive it without network.
///
/// Extraction is staged in a scratch directory and renamed into place only on
/// success, so an interrupted or rejected extraction never leaves a partial
/// tree that a later run would treat as a cache hit.
fn install_tarball(
    bytes: &[u8],
    expected: Option<&str>,
    url: &Url,
    cache: &Cache,
    limits: &ExtractionLimits,
) -> Result<FetchedSource, FetchError> {
    let (digest, provenance) = verify_digest(expected, bytes)?;
    let tree = cache.path_for("tarball", &digest)?;
    if tree.is_dir() {
        return Ok(FetchedSource {
            tree,
            digest: digest.clone(),
            provenance,
            kind: SourceKind::Tarball {
                url: url.clone(),
                digest: Some(digest),
            },
        });
    }

    let staging = cache.scratch_path("extract");
    let archive = staging.with_extension("archive");
    fs::create_dir_all(cache.root.join("tmp"))?;
    fs::write(&archive, bytes)?;
    // `extract_tarball` removes `staging` itself on failure.
    let extracted = extract_tarball(&archive, &staging, limits);
    let _ = fs::remove_file(&archive);
    extracted?;

    install_into_cache(&staging, &tree, &cache.root.join("tarball"))?;

    Ok(FetchedSource {
        tree,
        digest: digest.clone(),
        provenance,
        kind: SourceKind::Tarball {
            url: url.clone(),
            digest: Some(digest),
        },
    })
}

/// `expected` is a caller- or config-supplied digest (spec §7.2): a mismatch
/// is a hard error; no expectation records the computed digest with
/// provenance `Unverified`.
fn verify_digest(expected: Option<&str>, bytes: &[u8]) -> Result<(String, Provenance), FetchError> {
    let digest = crate::model::to_hex(Sha256::digest(bytes).as_slice());
    match expected {
        Some(expected) => {
            let expected = normalize_sha256(expected)?;
            if expected != digest {
                return Err(FetchError::Checksum {
                    expected,
                    actual: digest,
                });
            }
            Ok((digest, Provenance::Verified))
        }
        None => Ok((digest, Provenance::Unverified)),
    }
}

// 7. Safe extraction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compression {
    Gzip,
    Xz,
    Zstd,
    None,
}

fn detect_compression(archive: &Path) -> Result<Compression, FetchError> {
    let mut magic = [0u8; 6];
    let mut file = fs::File::open(archive)?;
    let read = file.read(&mut magic)?;
    match &magic[..read] {
        [0x1f, 0x8b, ..] => Ok(Compression::Gzip),
        [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] => Ok(Compression::Xz),
        [0x28, 0xb5, 0x2f, 0xfd, ..] => Ok(Compression::Zstd),
        _ => Ok(Compression::None),
    }
}

/// Extracts a (possibly compressed) tar archive into `dest`, enforcing every
/// §7.2 hardening rule. Nothing is ever executed.
///
/// `dest` must not exist or must be an empty directory. On any failure the
/// partially extracted tree is removed, so a rejected archive never leaves
/// content behind — in particular never an escaping symlink.
///
/// Links are the subtle case: a lexical check alone is not enough, because an
/// entry path or a link target can traverse a symlink extracted earlier and
/// land outside `dest` while looking contained. Extraction therefore
///
/// 1. never writes through a symlink: every existing component of an entry's
///    parent path is checked with `symlink_metadata`, and an existing file or
///    link at the entry's own path is unlinked rather than followed;
/// 2. defers symlink creation until every file, directory, and hardlink
///    exists, so no entry is ever written while a symlink is on disk; and
/// 3. re-resolves every created symlink against the final tree, following
///    on-disk links, and rejects any that resolve outside `dest`. Checking the
///    final tree makes the result independent of archive entry order.
pub fn extract_tarball(
    archive: &Path,
    dest: &Path,
    limits: &ExtractionLimits,
) -> Result<(), FetchError> {
    match fs::symlink_metadata(dest) {
        Ok(metadata) if metadata.is_dir() => {
            if fs::read_dir(dest)?.next().is_some() {
                return Err(FetchError::Extraction(format!(
                    "destination '{}' is not empty",
                    dest.display()
                )));
            }
        }
        Ok(_) => {
            return Err(FetchError::Extraction(format!(
                "destination '{}' is not a directory",
                dest.display()
            )));
        }
        Err(error) if error.kind() == ErrorKind::NotFound => fs::create_dir_all(dest)?,
        Err(error) => return Err(error.into()),
    }
    let result = dest
        .canonicalize()
        .map_err(FetchError::from)
        .and_then(|root| extract_into(archive, &root, limits));
    if result.is_err() {
        // `remove_dir_all` removes symlinks without following them.
        let _ = fs::remove_dir_all(dest);
    }
    result
}

/// The extraction passes behind [`extract_tarball`]; `root` is the canonical,
/// empty destination directory.
fn extract_into(archive: &Path, root: &Path, limits: &ExtractionLimits) -> Result<(), FetchError> {
    let file = fs::File::open(archive)?;
    let decompressed: Box<dyn Read> = match detect_compression(archive)? {
        Compression::Gzip => Box::new(GzDecoder::new(file)),
        Compression::Xz => Box::new(xz2::read::XzDecoder::new(file)),
        Compression::Zstd => Box::new(zstd::Decoder::new(file)?),
        Compression::None => Box::new(file),
    };
    let mut archive = tar::Archive::new(decompressed);
    // Archive modes are never applied: files are created with default
    // permissions, so setuid/setgid bits cannot land on disk.
    archive.set_preserve_permissions(false);

    let mut entries = archive
        .entries()
        .map_err(|error| FetchError::Extraction(format!("unreadable archive: {error}")))?;
    let mut count: u64 = 0;
    let mut total: u64 = 0;
    // Pending symlinks, created only after every other entry. Keyed by the
    // normalized relative path so a later entry for the same path supersedes
    // an earlier one (tar's last-entry-wins semantics).
    let mut symlinks: BTreeMap<PathBuf, PathBuf> = BTreeMap::new();

    while let Some(entry) = entries
        .next()
        .transpose()
        .map_err(|error| FetchError::Extraction(format!("corrupt archive entry: {error}")))?
    {
        count += 1;
        if count > limits.max_entries {
            return Err(FetchError::Extraction(format!(
                "entry-count limit of {} exceeded",
                limits.max_entries
            )));
        }

        let path: PathBuf = entry
            .path()
            .map_err(|error| FetchError::Extraction(format!("corrupt entry path: {error}")))?
            .into_owned();
        if path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
            return Err(FetchError::Extraction(format!(
                "entry path '{path:?}' escapes the destination"
            )));
        }
        let header = entry.header();
        let entry_type = header.entry_type();

        // Archive-wide pax metadata (for example the commit id `git archive`
        // records in every GitHub tarball) is never materialized.
        if entry_type.is_pax_global_extensions() {
            continue;
        }

        if let Ok(mode) = header.mode()
            && (mode & 0o4000 != 0 || mode & 0o2000 != 0)
        {
            return Err(FetchError::Extraction(format!(
                "entry '{path:?}' has setuid/setgid bits set"
            )));
        }

        let rel = normalize_lexical(&path);
        if rel.as_os_str().is_empty() {
            // A `./` entry names the destination itself.
            if entry_type.is_dir() {
                continue;
            }
            return Err(FetchError::Extraction(format!(
                "entry '{path:?}' names the destination itself"
            )));
        }
        if let Some(parent) = rel.parent() {
            ensure_no_symlink_components(root, parent)?;
        }
        symlinks.remove(&rel);
        let dest_path = root.join(&rel);

        match entry_type {
            tar::EntryType::Directory => match fs::symlink_metadata(&dest_path) {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => {
                    return Err(FetchError::Extraction(format!(
                        "directory entry '{path:?}' conflicts with an existing file"
                    )));
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    fs::create_dir_all(&dest_path)?;
                }
                Err(error) => return Err(error.into()),
            },
            tar::EntryType::Regular => {
                let size = header.size().map_err(|error| {
                    FetchError::Extraction(format!("corrupt entry size: {error}"))
                })?;
                total = total.saturating_add(size);
                if total > limits.max_total_size {
                    return Err(FetchError::Extraction(format!(
                        "total-size limit of {} exceeded",
                        limits.max_total_size
                    )));
                }
                create_parent_dirs(&dest_path)?;
                clear_slot(&dest_path, &path)?;
                let mut out = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&dest_path)?;
                let mut entry = entry;
                std::io::copy(&mut entry, &mut out)?;
            }
            tar::EntryType::Symlink => {
                let target = link_target(&entry, &path, "symlink")?;
                if target.has_root() {
                    return Err(FetchError::Extraction(format!(
                        "symlink '{path:?}' has an absolute target '{target:?}'"
                    )));
                }
                // Early, friendly rejection of the obvious case; the final
                // on-disk resolution below is the authoritative check.
                let link_dir = dest_path.parent().unwrap_or(root);
                if !normalize_lexical(&link_dir.join(&target)).starts_with(root) {
                    return Err(FetchError::Extraction(format!(
                        "symlink '{path:?}' target '{target:?}' escapes the destination"
                    )));
                }
                symlinks.insert(rel, target);
            }
            tar::EntryType::Link => {
                // Hardlink targets are relative to the archive root and must
                // name a regular file extracted earlier in this archive.
                let target = link_target(&entry, &path, "hardlink")?;
                if target.has_root() || target.components().any(|c| c == Component::ParentDir) {
                    return Err(FetchError::Extraction(format!(
                        "hardlink '{path:?}' target '{target:?}' escapes the destination"
                    )));
                }
                let target_rel = normalize_lexical(&target);
                ensure_no_symlink_components(root, &target_rel)?;
                let source = root.join(&target_rel);
                let is_regular_file = fs::symlink_metadata(&source)
                    .map(|metadata| metadata.is_file())
                    .unwrap_or(false);
                if target_rel.as_os_str().is_empty() || !is_regular_file {
                    return Err(FetchError::Extraction(format!(
                        "hardlink '{path:?}' target '{target:?}' is not a previously \
                         extracted regular file"
                    )));
                }
                create_parent_dirs(&dest_path)?;
                clear_slot(&dest_path, &path)?;
                fs::hard_link(&source, &dest_path)?;
            }
            other => {
                return Err(FetchError::Extraction(format!(
                    "entry '{path:?}' has an unsupported type ({other:?})"
                )));
            }
        }
    }

    for (rel, target) in &symlinks {
        if let Some(parent) = rel.parent() {
            ensure_no_symlink_components(root, parent)?;
        }
        let dest_path = root.join(rel);
        create_parent_dirs(&dest_path)?;
        clear_slot(&dest_path, rel)?;
        create_symlink(target, &dest_path)?;
    }
    for rel in symlinks.keys() {
        verify_symlink_confined(root, rel)?;
    }
    Ok(())
}

fn link_target<R: Read>(
    entry: &tar::Entry<'_, R>,
    path: &Path,
    what: &str,
) -> Result<PathBuf, FetchError> {
    entry
        .link_name()
        .map_err(|error| FetchError::Extraction(format!("corrupt link target: {error}")))?
        .map(|target| target.into_owned())
        .ok_or_else(|| {
            FetchError::Extraction(format!("entry '{path:?}' is a {what} without a target"))
        })
}

/// Rejects `rel` (relative to `root`) if any existing component is a
/// symlink, so nothing is ever created or written through a link. Components
/// that do not exist yet are fine: they are created as real directories.
fn ensure_no_symlink_components(root: &Path, rel: &Path) -> Result<(), FetchError> {
    let mut current = root.to_path_buf();
    for component in rel.components() {
        match component {
            Component::Normal(name) => current.push(name),
            Component::CurDir => continue,
            _ => {
                return Err(FetchError::Extraction(format!(
                    "entry path '{}' escapes the destination",
                    rel.display()
                )));
            }
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(FetchError::Extraction(format!(
                    "entry path '{}' traverses the symlink '{}'",
                    rel.display(),
                    current.strip_prefix(root).unwrap_or(&current).display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn create_parent_dirs(path: &Path) -> Result<(), FetchError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Makes room for a new entry at `path` without following a link: an
/// existing file or symlink is unlinked (a later archive entry wins), and an
/// existing directory is a conflict.
fn clear_slot(path: &Path, entry: &Path) -> Result<(), FetchError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Err(FetchError::Extraction(format!(
            "entry '{}' conflicts with an existing directory",
            entry.display()
        ))),
        Ok(_) => Ok(fs::remove_file(path)?),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, _link: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        ErrorKind::Unsupported,
        "symlink entries require a unix host",
    ))
}

/// Bound on symlink hops while resolving one link, mirroring the kernel's
/// `ELOOP` limit.
const MAX_SYMLINK_HOPS: usize = 40;

/// Resolves the symlink at `link_rel` (relative to `root`) against the
/// on-disk tree, following every symlink it traverses, and fails if the
/// resolution ever leaves `root`. Missing components are resolved lexically
/// (dangling links are allowed as long as they stay inside the tree).
fn verify_symlink_confined(root: &Path, link_rel: &Path) -> Result<(), FetchError> {
    enum Step {
        Parent,
        Name(OsString),
    }
    let escapes = || {
        FetchError::Extraction(format!(
            "symlink '{}' resolves outside the destination",
            link_rel.display()
        ))
    };
    let steps_of = |path: &Path| -> Result<Vec<Step>, FetchError> {
        let mut steps = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(name) => steps.push(Step::Name(name.to_os_string())),
                Component::ParentDir => steps.push(Step::Parent),
                Component::CurDir => {}
                Component::RootDir | Component::Prefix(_) => return Err(escapes()),
            }
        }
        Ok(steps)
    };

    let mut pending: VecDeque<Step> = steps_of(link_rel)?.into();
    // Resolved components below `root`; each is a real, non-symlink entry
    // (or does not exist), so `root` + `resolved` is a physical path.
    let mut resolved = PathBuf::new();
    let mut hops = 0;
    while let Some(step) = pending.pop_front() {
        let name = match step {
            Step::Parent => {
                if !resolved.pop() {
                    return Err(escapes());
                }
                continue;
            }
            Step::Name(name) => name,
        };
        let candidate = root.join(&resolved).join(&name);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return Err(FetchError::Extraction(format!(
                        "symlink '{}' has too many levels of indirection",
                        link_rel.display()
                    )));
                }
                let target = fs::read_link(&candidate)?;
                for step in steps_of(&target)?.into_iter().rev() {
                    pending.push_front(step);
                }
            }
            Ok(_) => resolved.push(&name),
            Err(error) if error.kind() == ErrorKind::NotFound => resolved.push(&name),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Lexically resolves `.` and `..` components without touching the filesystem.
fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

// 8. Registry helper (used by the Cargo analyzer, WP-2.2)
/// A client for a Cargo sparse registry index: index lookups and
/// checksum-verified `.crate` downloads (spec §7.2, §8.1).
pub struct RegistryClient {
    index: Url,
    http: reqwest::Client,
    limits: DownloadLimits,
    /// The index `config.json`, fetched at most once per client.
    config: tokio::sync::OnceCell<IndexConfig>,
}

/// One record of a sparse-index entry.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct IndexRecord {
    pub name: String,
    pub vers: String,
    pub cksum: String,
    #[serde(default)]
    pub yanked: bool,
    /// Per-record download override, if the registry defines one.
    pub dl: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct IndexConfig {
    dl: String,
}

impl RegistryClient {
    /// A client with the default [`DownloadLimits`].
    pub fn new(index_url: Url) -> Result<Self, FetchError> {
        Self::with_limits(index_url, DownloadLimits::default())
    }

    /// A client whose index lookups and `.crate` downloads are bounded by
    /// `limits` (size cap and timeouts).
    pub fn with_limits(index_url: Url, limits: DownloadLimits) -> Result<Self, FetchError> {
        Ok(Self {
            index: index_url,
            http: http_client(&limits)
                .map_err(|error| FetchError::Registry(format!("http client failed: {error}")))?,
            limits,
            config: tokio::sync::OnceCell::new(),
        })
    }

    /// GETs `url` and reads the body within the download limits.
    async fn get_capped(&self, url: Url, what: &str) -> Result<Vec<u8>, FetchError> {
        let failed =
            |error: &dyn std::fmt::Display| FetchError::Registry(format!("{what} failed: {error}"));
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| failed(&error))?
            .error_for_status()
            .map_err(|error| failed(&error))?;
        read_capped(response, self.limits.max_bytes)
            .await
            .map_err(|error| failed(&error))
    }

    /// The sparse-index path for a crate name (crates.io layout).
    fn index_path(name: &str) -> Result<String, FetchError> {
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(FetchError::Registry(format!("invalid crate name '{name}'")));
        }
        let chars: Vec<char> = name.chars().collect();
        Ok(match chars.len() {
            1 | 2 => format!("1/{name}"),
            3 => format!("3/{}/{}", chars[0], name),
            _ => format!(
                "{}/{}/{name}",
                chars[..2].iter().collect::<String>(),
                chars[2..4].iter().collect::<String>()
            ),
        })
    }

    /// Looks up the index record for one crate version.
    pub async fn index_record(&self, name: &str, version: &str) -> Result<IndexRecord, FetchError> {
        let path = Self::index_path(name)?;
        let url = self
            .index
            .join(&path)
            .map_err(|error| FetchError::Registry(format!("invalid index URL: {error}")))?;
        let body = self.get_capped(url, "index lookup").await?;
        let text = String::from_utf8(body).map_err(|error| {
            FetchError::Registry(format!("index lookup failed: not UTF-8: {error}"))
        })?;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let record: IndexRecord = serde_json::from_str(line)
                .map_err(|error| FetchError::Registry(format!("invalid index record: {error}")))?;
            if record.name == name && record.vers == version {
                return Ok(record);
            }
        }
        Err(FetchError::Registry(format!(
            "crate {name} {version} not found in the registry index"
        )))
    }

    /// Downloads the `.crate` artifact and verifies its SHA-256 against the
    /// index checksum. Verification is mandatory, never optional (spec §7.2).
    pub async fn download_crate(
        &self,
        name: &str,
        version: &str,
    ) -> Result<(Vec<u8>, IndexRecord), FetchError> {
        let record = self.index_record(name, version).await?;
        if record.yanked {
            return Err(FetchError::Registry(format!(
                "crate {name} {version} is yanked"
            )));
        }
        let download_url = self.download_url(name, version, &record).await?;
        let bytes = self.get_capped(download_url, "crate download").await?;
        let digest = crate::model::to_hex(Sha256::digest(bytes.as_slice()).as_slice());
        if digest != record.cksum.to_ascii_lowercase() {
            return Err(FetchError::Checksum {
                expected: record.cksum,
                actual: digest,
            });
        }
        Ok((bytes, record))
    }

    /// Resolves the `.crate` download URL: a per-record `dl` override (full
    /// URL or path template) or the index `config.json` endpoint.
    async fn download_url(
        &self,
        name: &str,
        version: &str,
        record: &IndexRecord,
    ) -> Result<Url, FetchError> {
        let default_template = format!("{name}/{name}-{version}.crate");
        let template = record.dl.clone().unwrap_or(default_template);
        if let Ok(url) = Url::parse(&template) {
            return Ok(url);
        }
        let config = self
            .config
            .get_or_try_init(|| async {
                let config_url = self
                    .index
                    .join("config.json")
                    .map_err(|error| FetchError::Registry(format!("invalid index URL: {error}")))?;
                let body = self.get_capped(config_url, "index config lookup").await?;
                serde_json::from_slice::<IndexConfig>(&body)
                    .map_err(|error| FetchError::Registry(format!("invalid index config: {error}")))
            })
            .await?;
        let template = template
            .replace("{crate}", name)
            .replace("{version}", version);
        Url::parse(&format!("{}/{template}", config.dl.trim_end_matches('/')))
            .map_err(|error| FetchError::Registry(format!("invalid download URL: {error}")))
    }
}

fn http_user_agent() -> String {
    format!("robigus/{}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn temp_cache() -> (Cache, TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (Cache::new(dir.path().join("cache")), dir)
    }

    fn tar_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, *contents)
                .expect("append entry");
        }
        builder.into_inner().expect("finish tar")
    }

    /// Builds a raw ustar header by hand: the tar crate refuses to *create*
    /// malicious archives (traversal names, device nodes, setuid modes), so
    /// the hostile fixtures are crafted byte-for-byte.
    fn raw_header(
        name: &str,
        typeflag: u8,
        mode: u32,
        size: u64,
        linkname: Option<&str>,
    ) -> [u8; 512] {
        let mut header = [0u8; 512];
        let name_bytes = name.as_bytes();
        assert!(name_bytes.len() <= 100, "fixture name too long");
        header[..name_bytes.len()].copy_from_slice(name_bytes);
        header[100..108].copy_from_slice(format!("{:06o}\0 ", mode).as_bytes());
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", size).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = typeflag;
        if let Some(link) = linkname {
            let link_bytes = link.as_bytes();
            assert!(link_bytes.len() <= 100, "fixture linkname too long");
            header[157..157 + link_bytes.len()].copy_from_slice(link_bytes);
        }
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        // The ustar checksum is the byte sum with the chksum field treated as
        // spaces.
        header[148..156].copy_from_slice(b"        ");
        let sum: u32 = header.iter().map(|byte| *byte as u32).sum();
        header[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
        header
    }

    fn raw_tar(entries: &[([u8; 512], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (header, data) in entries {
            out.extend_from_slice(header);
            out.extend_from_slice(data);
            let remainder = data.len() % 512;
            if remainder != 0 {
                out.extend(std::iter::repeat_n(0u8, 512 - remainder));
            }
        }
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    fn symlink_header(name: &str, target: &str) -> [u8; 512] {
        raw_header(name, b'2', 0o777, 0, Some(target))
    }

    fn extract_raw(entries: &[([u8; 512], &[u8])]) -> (TempDir, PathBuf, Result<(), FetchError>) {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.tar");
        fs::write(&archive, raw_tar(entries)).unwrap();
        let dest = dir.path().join("dest");
        let result = extract_tarball(&archive, &dest, &ExtractionLimits::default());
        (dir, dest, result)
    }

    /// Regression (C1): `a -> .` then `a/b -> ..` look contained lexically,
    /// but `a/b` physically names the destination's parent, so writing
    /// `b/pwned.txt` used to escape.
    #[test]
    fn symlink_chain_through_parent_is_rejected() {
        let (dir, dest, result) = extract_raw(&[
            (symlink_header("a", "."), &b""[..]),
            (symlink_header("a/b", ".."), &b""[..]),
            (
                raw_header("b/pwned.txt", b'0', 0o644, 5, None),
                &b"pwned"[..],
            ),
        ]);
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("traverses the symlink"),
            "{error}"
        );
        assert!(!dir.path().join("pwned.txt").exists());
        assert!(!dest.exists(), "a rejected archive leaves no tree behind");
    }

    /// A symlink whose *target* traverses other symlinks: `s1 -> d` and
    /// `d/s2 -> ..` are each contained, but `s3 -> s1/s2/..` resolves to the
    /// destination's parent. Listing `s3` first must not change the outcome.
    #[test]
    fn symlink_target_through_symlinks_is_rejected() {
        for s3_first in [false, true] {
            let s3 = (symlink_header("s3", "s1/s2/.."), &b""[..]);
            let mut entries = vec![
                (raw_header("d/", b'5', 0o755, 0, None), &b""[..]),
                (symlink_header("s1", "d"), &b""[..]),
                (symlink_header("d/s2", ".."), &b""[..]),
            ];
            if s3_first {
                entries.insert(0, s3);
            } else {
                entries.push(s3);
            }
            let (_dir, dest, result) = extract_raw(&entries);
            let error = result.unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("resolves outside the destination"),
                "{error}"
            );
            assert!(!dest.exists());
        }
    }

    #[test]
    fn contained_symlink_chains_are_allowed() {
        let (_dir, dest, result) = extract_raw(&[
            (raw_header("d/f.txt", b'0', 0o644, 2, None), &b"hi"[..]),
            (symlink_header("s1", "d"), &b""[..]),
            (symlink_header("s2", "s1/f.txt"), &b""[..]),
            (symlink_header("dangling", "missing/file"), &b""[..]),
        ]);
        result.unwrap();
        assert_eq!(fs::read_to_string(dest.join("s2")).unwrap(), "hi");
        assert!(fs::symlink_metadata(dest.join("dangling")).is_ok());
    }

    /// A regular file that follows a symlink of the same name replaces the
    /// link; it is never written through it.
    #[test]
    fn regular_file_never_writes_through_a_symlink() {
        let (_dir, dest, result) = extract_raw(&[
            (raw_header("real.txt", b'0', 0o644, 4, None), &b"orig"[..]),
            (symlink_header("link", "real.txt"), &b""[..]),
            (raw_header("link", b'0', 0o644, 3, None), &b"new"[..]),
        ]);
        result.unwrap();
        assert_eq!(fs::read_to_string(dest.join("real.txt")).unwrap(), "orig");
        let link = fs::symlink_metadata(dest.join("link")).unwrap();
        assert!(link.is_file());
        assert_eq!(fs::read_to_string(dest.join("link")).unwrap(), "new");
    }

    #[test]
    fn escaping_hardlink_is_rejected() {
        let (dir, dest, result) = extract_raw(&[(
            raw_header("h", b'1', 0o644, 0, Some("../outside")),
            &b""[..],
        )]);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("escapes the destination")
        );
        assert!(!dir.path().join("outside").exists());
        assert!(!dest.exists());
    }

    /// Hardlinks may only point at regular files already extracted; in
    /// particular not at a symlink (deferred) or a missing path.
    #[test]
    fn hardlink_to_non_regular_file_is_rejected() {
        let (_dir, _dest, result) = extract_raw(&[
            (symlink_header("s", "d"), &b""[..]),
            (raw_header("h", b'1', 0o644, 0, Some("s")), &b""[..]),
        ]);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not a previously extracted regular file")
        );
    }

    #[test]
    fn contained_hardlink_is_allowed() {
        let (_dir, dest, result) = extract_raw(&[
            (raw_header("a.txt", b'0', 0o644, 5, None), &b"hello"[..]),
            (
                raw_header("sub/b.txt", b'1', 0o644, 0, Some("a.txt")),
                &b""[..],
            ),
        ]);
        result.unwrap();
        assert_eq!(fs::read_to_string(dest.join("sub/b.txt")).unwrap(), "hello");
    }

    /// `git archive` (every GitHub release tarball) starts with a pax global
    /// header; it is metadata and must be skipped, not rejected.
    #[test]
    fn pax_global_header_is_skipped() {
        let pax = b"15 comment=abc\n";
        let (_dir, dest, result) = extract_raw(&[
            (
                raw_header("pax_global_header", b'g', 0o666, pax.len() as u64, None),
                &pax[..],
            ),
            (raw_header("src/lib.rs", b'0', 0o644, 2, None), &b"//"[..]),
        ]);
        result.unwrap();
        assert!(dest.join("src/lib.rs").exists());
        assert!(!dest.join("pax_global_header").exists());
    }

    #[test]
    fn non_empty_destination_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.tar");
        fs::write(&archive, raw_tar(&[])).unwrap();
        let dest = dir.path().join("dest");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("keep.txt"), b"user data").unwrap();
        let error = extract_tarball(&archive, &dest, &ExtractionLimits::default()).unwrap_err();
        assert!(error.to_string().contains("not empty"));
        assert!(
            dest.join("keep.txt").exists(),
            "existing content is untouched"
        );
    }

    /// A rejected archive must not leave a partial tree in the cache that a
    /// later run would treat as a verified cache hit.
    #[test]
    fn rejected_install_leaves_no_cache_entry() {
        let (cache, _dir) = temp_cache();
        let url = Url::parse("https://example.com/evil.tar").unwrap();
        let bytes = raw_tar(&[
            (raw_header("ok.txt", b'0', 0o644, 2, None), &b"ok"[..]),
            (symlink_header("a", "."), &b""[..]),
            (symlink_header("a/b", ".."), &b""[..]),
        ]);
        install_tarball(&bytes, None, &url, &cache, &ExtractionLimits::default()).unwrap_err();
        let digest = crate::model::to_hex(Sha256::digest(&bytes).as_slice());
        assert!(!cache.path_for("tarball", &digest).unwrap().exists());
        let leftovers = fs::read_dir(cache.root().join("tmp"))
            .map(|entries| entries.count())
            .unwrap_or(0);
        assert_eq!(leftovers, 0, "staging files are cleaned up");
    }

    /// Regression (High 1): cache keys come from untrusted input and must
    /// not address paths outside the cache.
    #[test]
    fn cache_keys_must_be_single_safe_components() {
        let (cache, _dir) = temp_cache();
        for bad in [
            "../../secret",
            "..",
            ".",
            "",
            "a/b",
            "/etc",
            ".hidden",
            "a\0b",
        ] {
            assert!(
                matches!(
                    cache.path_for("git", bad),
                    Err(FetchError::InvalidCacheKey(_))
                ),
                "{bad:?} must be rejected"
            );
            assert!(cache.path_for(bad, "abc").is_err(), "kind {bad:?}");
        }
        assert!(cache.path_for("git", &"a".repeat(40)).is_ok());
    }

    #[test]
    fn git_cache_hits_require_a_full_commit_hash() {
        let (cache, dir) = temp_cache();
        // A directory reachable by traversal from `<cache>/git`.
        fs::create_dir_all(cache.root().join("git")).unwrap();
        fs::create_dir_all(dir.path().join("secret")).unwrap();
        let rev = |text: &str| GitReference::Rev(text.to_string());
        assert!(
            git_cache_hit(&cache, &rev("../../secret"))
                .unwrap()
                .is_none()
        );
        assert!(git_cache_hit(&cache, &rev("main")).unwrap().is_none());

        // Abbreviated hashes are resolved by a fetch, never by the cache.
        let commit = "ab".repeat(20);
        fs::create_dir_all(cache.path_for("git", &commit).unwrap()).unwrap();
        assert!(
            git_cache_hit(&cache, &rev(&commit[..12]))
                .unwrap()
                .is_none()
        );
        assert!(
            git_cache_hit(&cache, &GitReference::Branch(commit.clone()))
                .unwrap()
                .is_none()
        );

        // A full hash hits, normalized to lowercase.
        let (tree, digest) = git_cache_hit(&cache, &rev(&commit.to_ascii_uppercase()))
            .unwrap()
            .expect("cache hit");
        assert_eq!(digest, commit);
        assert_eq!(tree, cache.path_for("git", &commit).unwrap());
    }

    #[tokio::test]
    async fn malformed_tarball_digest_is_rejected_before_any_io() {
        let (cache, dir) = temp_cache();
        fs::create_dir_all(cache.root().join("tarball")).unwrap();
        fs::create_dir_all(dir.path().join("secret")).unwrap();
        // `.invalid` never resolves, so reaching the network would fail
        // differently.
        let url = Url::parse("https://robigus.invalid/src.tar").unwrap();
        let non_hex = "g".repeat(64);
        for bad in ["../../secret", "abc", non_hex.as_str()] {
            let error = fetch_tarball(&url, Some(bad), &cache, &FetchOptions::default())
                .await
                .unwrap_err();
            assert!(
                matches!(error, RobigusError::Fetch(FetchError::InvalidDigest(_))),
                "{bad:?}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn tarball_cache_hit_normalizes_the_digest() {
        let (cache, _dir) = temp_cache();
        let url = Url::parse("https://robigus.invalid/src.tar").unwrap();
        let digest = crate::model::to_hex(Sha256::digest(b"x").as_slice());
        fs::create_dir_all(cache.path_for("tarball", &digest).unwrap()).unwrap();
        let supplied = format!("  {}  ", digest.to_ascii_uppercase());
        let fetched = fetch_tarball(&url, Some(&supplied), &cache, &FetchOptions::default())
            .await
            .unwrap();
        assert_eq!(fetched.digest, digest);
        assert_eq!(fetched.provenance, Provenance::Verified);
    }

    #[test]
    fn traversal_entry_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("evil.tar");
        let header = raw_header("../evil.txt", b'0', 0o644, 5, None);
        let bytes = raw_tar(&[(header, b"pwned")]);
        fs::write(&archive, bytes).unwrap();
        let dest = dir.path().join("dest");
        let error = extract_tarball(&archive, &dest, &ExtractionLimits::default()).unwrap_err();
        assert!(error.to_string().contains("escapes the destination"));
        assert!(!dir.path().join("evil.txt").exists());
    }

    #[test]
    fn absolute_path_entry_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("evil.tar");
        let header = raw_header("/etc/evil.txt", b'0', 0o644, 5, None);
        let bytes = raw_tar(&[(header, b"pwned")]);
        fs::write(&archive, bytes).unwrap();
        let dest = dir.path().join("dest");
        let error = extract_tarball(&archive, &dest, &ExtractionLimits::default()).unwrap_err();
        assert!(error.to_string().contains("escapes the destination"));
    }

    #[test]
    fn escaping_symlink_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("evil.tar");
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        builder
            .append_link(&mut header, "link", "../../outside")
            .unwrap();
        let bytes = builder.into_inner().unwrap();
        fs::write(&archive, bytes).unwrap();
        let dest = dir.path().join("dest");
        let error = extract_tarball(&archive, &dest, &ExtractionLimits::default()).unwrap_err();
        assert!(error.to_string().contains("escapes the destination"));
        assert!(!dir.path().join("outside").exists());
    }

    #[test]
    fn inside_symlink_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("ok.tar");
        let mut builder = tar::Builder::new(Vec::new());
        let mut file_header = tar::Header::new_gnu();
        file_header.set_size(5);
        file_header.set_mode(0o644);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, "a.txt", &b"hello"[..])
            .unwrap();
        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Symlink);
        link_header.set_size(0);
        link_header.set_mode(0o777);
        link_header.set_cksum();
        builder
            .append_link(&mut link_header, "sub/link", "../a.txt")
            .unwrap();
        let bytes = builder.into_inner().unwrap();
        fs::write(&archive, bytes).unwrap();
        let dest = dir.path().join("dest");
        extract_tarball(&archive, &dest, &ExtractionLimits::default()).unwrap();
        assert!(dest.join("sub").join("link").exists());
    }

    #[test]
    fn device_node_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("evil.tar");
        let header = raw_header("dev", b'4', 0o644, 0, None); // block device
        let bytes = raw_tar(&[(header, &b""[..])]);
        fs::write(&archive, bytes).unwrap();
        let dest = dir.path().join("dest");
        let error = extract_tarball(&archive, &dest, &ExtractionLimits::default()).unwrap_err();
        assert!(error.to_string().contains("unsupported type"));
    }

    #[test]
    fn setuid_entry_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("evil.tar");
        let header = raw_header("rootkit", b'0', 0o4755, 2, None);
        let bytes = raw_tar(&[(header, b"hi")]);
        fs::write(&archive, bytes).unwrap();
        let dest = dir.path().join("dest");
        let error = extract_tarball(&archive, &dest, &ExtractionLimits::default()).unwrap_err();
        assert!(error.to_string().contains("setuid/setgid"));
    }

    #[test]
    fn gzip_bomb_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("bomb.tar.gz");
        let mut builder = tar::Builder::new(Vec::new());
        let zeros = vec![0u8; 1024 * 1024];
        let mut header = tar::Header::new_gnu();
        header.set_size(zeros.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "zeros", zeros.as_slice())
            .unwrap();
        let tar_bytes = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&tar_bytes).unwrap();
        let gzipped = encoder.finish().unwrap();
        assert!(gzipped.len() < 64 * 1024, "fixture must compress well");
        fs::write(&archive, gzipped).unwrap();
        let dest = dir.path().join("dest");
        let limits = ExtractionLimits {
            max_entries: 100_000,
            max_total_size: 64 * 1024,
        };
        let error = extract_tarball(&archive, &dest, &limits).unwrap_err();
        assert!(error.to_string().contains("total-size limit"));
    }

    #[test]
    fn entry_count_overflow_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("many.tar");
        let entries: Vec<([u8; 512], &[u8])> = (0..5)
            .map(|index| {
                (
                    raw_header(&format!("f{index}"), b'0', 0o644, 0, None),
                    &b""[..],
                )
            })
            .collect();
        let bytes = raw_tar(&entries);
        fs::write(&archive, bytes).unwrap();
        let dest = dir.path().join("dest");
        let limits = ExtractionLimits {
            max_entries: 3,
            max_total_size: 1024 * 1024,
        };
        let error = extract_tarball(&archive, &dest, &limits).unwrap_err();
        assert!(error.to_string().contains("entry-count limit"));
    }

    #[test]
    fn digest_verification_modes() {
        let bytes = b"content";
        let computed = crate::model::to_hex(Sha256::digest(bytes).as_slice());

        let (digest, provenance) = verify_digest(None, bytes).unwrap();
        assert_eq!(digest, computed);
        assert_eq!(provenance, Provenance::Unverified);

        let (digest, provenance) = verify_digest(Some(&computed), bytes).unwrap();
        assert_eq!(digest, computed);
        assert_eq!(provenance, Provenance::Verified);

        let error = verify_digest(Some(&"0".repeat(64)), bytes).unwrap_err();
        assert!(matches!(error, FetchError::Checksum { .. }));
    }

    #[tokio::test]
    async fn tarball_cache_hit_skips_install() {
        let (cache, _dir) = temp_cache();
        let url = Url::parse("https://example.com/src.tar.gz").unwrap();
        let bytes = b"archive-bytes";
        let digest = crate::model::to_hex(Sha256::digest(bytes).as_slice());

        // Pre-populate the cached tree with a marker.
        let cached_tree = cache.path_for("tarball", &digest).unwrap();
        fs::create_dir_all(&cached_tree).unwrap();
        fs::write(cached_tree.join("marker"), b"cached").unwrap();

        let fetched = fetch_tarball(&url, Some(&digest), &cache, &FetchOptions::default())
            .await
            .unwrap();
        assert_eq!(fetched.tree, cached_tree);
        assert_eq!(fetched.provenance, Provenance::Verified);
        assert_eq!(
            fs::read_to_string(fetched.tree.join("marker")).unwrap(),
            "cached"
        );
    }

    /// The cache is lock-free: losing the install race to an identical
    /// entry is success, and the losing staging copy is discarded.
    #[test]
    fn losing_the_install_race_uses_the_existing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let kind_dir = dir.path().join("git");
        let tree = kind_dir.join("abc");
        fs::create_dir_all(&tree).unwrap();
        fs::write(tree.join("winner"), b"").unwrap();
        let staging = dir.path().join("staging");
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("loser"), b"").unwrap();

        install_into_cache(&staging, &tree, &kind_dir).unwrap();
        assert!(tree.join("winner").exists());
        assert!(!staging.exists(), "the staging copy is removed");
    }

    #[tokio::test]
    async fn concurrent_installs_of_the_same_tarball_succeed() {
        let (cache, _dir) = temp_cache();
        let url = Url::parse("https://example.com/src.tar").unwrap();
        let bytes = tar_bytes(&[("src/lib.rs", b"fn main() {}")]);
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let (cache, url, bytes) = (cache.clone(), url.clone(), bytes.clone());
                tokio::task::spawn_blocking(move || {
                    install_tarball(&bytes, None, &url, &cache, &ExtractionLimits::default())
                })
            })
            .collect();
        let mut trees = BTreeSet::new();
        for task in tasks {
            trees.insert(task.await.unwrap().unwrap().tree);
        }
        assert_eq!(trees.len(), 1);
        let tree = trees.into_iter().next().unwrap();
        assert!(tree.join("src/lib.rs").exists());
        let leftovers = fs::read_dir(cache.root().join("tmp")).unwrap().count();
        assert_eq!(leftovers, 0, "every staging copy is cleaned up");
    }

    #[tokio::test]
    async fn tarball_install_extracts_into_cache() {
        let (cache, _dir) = temp_cache();
        let url = Url::parse("https://example.com/src.tar").unwrap();
        let bytes = tar_bytes(&[("src/lib.rs", b"fn main() {}")]);

        let fetched =
            install_tarball(&bytes, None, &url, &cache, &ExtractionLimits::default()).unwrap();
        assert_eq!(fetched.provenance, Provenance::Unverified);
        assert!(fetched.tree.join("src").join("lib.rs").exists());

        // A second install with the same bytes hits the same tree.
        let again =
            install_tarball(&bytes, None, &url, &cache, &ExtractionLimits::default()).unwrap();
        assert_eq!(again.tree, fetched.tree);
        assert_eq!(again.digest, fetched.digest);
    }

    #[tokio::test]
    async fn tarball_digest_mismatch_is_rejected() {
        let (cache, _dir) = temp_cache();
        let url = Url::parse("https://example.com/src.tar").unwrap();
        let bytes = tar_bytes(&[("src/lib.rs", b"fn main() {}")]);
        let error = install_tarball(
            &bytes,
            Some(&"0".repeat(64)),
            &url,
            &cache,
            &ExtractionLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error, FetchError::Checksum { .. }));
    }

    #[tokio::test]
    async fn git_pinned_revision_cache_hit() {
        let (cache, _dir) = temp_cache();
        let url = Url::parse("https://example.com/repo.git").unwrap();
        let commit = "0".repeat(40);
        let cached_tree = cache.path_for("git", &commit).unwrap();
        fs::create_dir_all(&cached_tree).unwrap();
        fs::write(cached_tree.join("marker"), b"cached").unwrap();

        let fetched = fetch_git(
            &url,
            &GitReference::Rev(commit.clone()),
            &cache,
            &FetchOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(fetched.tree, cached_tree);
        assert_eq!(fetched.digest, commit);
        assert_eq!(fetched.provenance, Provenance::Verified);
        assert_eq!(
            fs::read_to_string(fetched.tree.join("marker")).unwrap(),
            "cached"
        );
    }

    #[tokio::test]
    async fn path_input_records_tree_digest() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        let fetched = fetch_path(dir.path()).await.unwrap();
        let expected = path_tree_digest(&fetched.tree).unwrap();
        assert_eq!(fetched.digest, expected);
        assert_eq!(fetched.provenance, Provenance::Verified);
        assert!(fetched.tree.join("a.txt").exists());
    }

    #[tokio::test]
    async fn registry_client_verifies_checksums() {
        let server = wiremock::MockServer::start().await;
        let index_url = Url::parse(&server.uri()).unwrap();

        let cksum = crate::model::to_hex(Sha256::digest(b"crate-bytes").as_slice());
        let record = format!(
            "{{\"name\":\"foo\",\"vers\":\"1.0.0\",\"cksum\":\"{cksum}\",\"yanked\":false}}"
        );
        async fn mount_registry(
            server: &wiremock::MockServer,
            record: &str,
            crate_body: &'static [u8],
        ) {
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/3/f/foo"))
                .respond_with(
                    wiremock::ResponseTemplate::new(200).set_body_string(record.to_string()),
                )
                .mount(server)
                .await;
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/config.json"))
                .respond_with(
                    wiremock::ResponseTemplate::new(200)
                        .set_body_string(format!("{{\"dl\":\"{}/crates\"}}", server.uri())),
                )
                .mount(server)
                .await;
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/crates/foo/foo-1.0.0.crate"))
                .respond_with(
                    wiremock::ResponseTemplate::new(200).set_body_bytes(crate_body.to_vec()),
                )
                .mount(server)
                .await;
        }

        mount_registry(&server, &record, b"crate-bytes").await;
        let client = RegistryClient::new(index_url).unwrap();
        let (bytes, downloaded) = client.download_crate("foo", "1.0.0").await.unwrap();
        assert_eq!(bytes, b"crate-bytes");
        assert_eq!(downloaded.cksum, cksum);

        // A corrupted artifact must be rejected against the index checksum.
        server.reset().await;
        mount_registry(&server, &record, b"corrupted").await;
        let error = client.download_crate("foo", "1.0.0").await.unwrap_err();
        assert!(matches!(error, FetchError::Checksum { .. }));
    }

    #[test]
    fn index_paths_follow_the_sparse_layout() {
        assert_eq!(RegistryClient::index_path("a").unwrap(), "1/a");
        assert_eq!(RegistryClient::index_path("ab").unwrap(), "1/ab");
        assert_eq!(RegistryClient::index_path("abc").unwrap(), "3/a/abc");
        assert_eq!(RegistryClient::index_path("serde").unwrap(), "se/rd/serde");
        assert!(RegistryClient::index_path("../evil").is_err());
    }

    #[tokio::test]
    async fn fetched_source_id_is_pinned_by_the_digest() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        let fetched = fetch_path(dir.path()).await.unwrap();
        let source_id = fetched.source_id();
        assert_eq!(source_id.precise.as_deref(), Some(fetched.digest.as_str()));
        assert_eq!(
            source_id.kind,
            SourceKind::Path {
                path: dir.path().canonicalize().unwrap()
            }
        );
    }

    // Download limits

    async fn serve(body: Vec<u8>, delay: Duration) -> (wiremock::MockServer, Url) {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_bytes(body)
                    .set_delay(delay),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&format!("{}/src.tar", server.uri())).unwrap();
        (server, url)
    }

    #[tokio::test]
    async fn downloads_over_the_size_limit_are_rejected() {
        let (_server, url) = serve(vec![0u8; 4096], Duration::ZERO).await;
        let limits = DownloadLimits {
            max_bytes: 1024,
            ..DownloadLimits::default()
        };
        let error = download(&url, &limits).await.unwrap_err();
        assert!(error.to_string().contains("download limit"), "{error}");
        assert_eq!(
            download(&url, &DownloadLimits::default())
                .await
                .unwrap()
                .len(),
            4096
        );
    }

    #[tokio::test]
    async fn downloads_time_out() {
        let (_server, url) = serve(b"late".to_vec(), Duration::from_millis(500)).await;
        let limits = DownloadLimits {
            timeout: Duration::from_millis(100),
            ..DownloadLimits::default()
        };
        let error = download(&url, &limits).await.unwrap_err();
        assert!(matches!(error, FetchError::Download(_)), "{error}");
    }

    #[tokio::test]
    async fn fetch_tarball_applies_the_download_limit() {
        let (_server, url) = serve(tar_bytes(&[("a.txt", b"0123456789")]), Duration::ZERO).await;
        let (cache, _dir) = temp_cache();
        let options = FetchOptions {
            download: DownloadLimits {
                max_bytes: 64,
                ..DownloadLimits::default()
            },
            ..FetchOptions::default()
        };
        let error = fetch_tarball(&url, None, &cache, &options)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("download limit"), "{error}");
    }

    /// The registry client caps index and `.crate` bodies and fetches the
    /// index `config.json` once per client.
    #[tokio::test]
    async fn registry_client_limits_and_caches_config() {
        /// A registry serving `foo` 1.0.0 and 1.1.0 as 2 KiB `.crate` files;
        /// `config.json` must be requested exactly once.
        async fn registry() -> (wiremock::MockServer, Url) {
            let server = wiremock::MockServer::start().await;
            let big = vec![7u8; 2048];
            let cksum = crate::model::to_hex(Sha256::digest(&big).as_slice());
            let records: String = ["1.0.0", "1.1.0"]
                .iter()
                .map(|vers| {
                    format!("{{\"name\":\"foo\",\"vers\":\"{vers}\",\"cksum\":\"{cksum}\"}}\n")
                })
                .collect();
            wiremock::Mock::given(wiremock::matchers::path("/3/f/foo"))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(records))
                .mount(&server)
                .await;
            wiremock::Mock::given(wiremock::matchers::path("/config.json"))
                .respond_with(
                    wiremock::ResponseTemplate::new(200)
                        .set_body_string(format!("{{\"dl\":\"{}/crates\"}}", server.uri())),
                )
                .expect(1)
                .mount(&server)
                .await;
            wiremock::Mock::given(wiremock::matchers::path_regex("^/crates/foo/"))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(big))
                .mount(&server)
                .await;
            let url = Url::parse(&server.uri()).unwrap();
            (server, url)
        }

        let (server, index_url) = registry().await;
        let client = RegistryClient::new(index_url).unwrap();
        client.download_crate("foo", "1.0.0").await.unwrap();
        client.download_crate("foo", "1.1.0").await.unwrap();
        // `expect(1)` on config.json: two downloads, one config fetch.
        server.verify().await;

        // The index (~200 bytes) fits under a 1 KiB cap; the 2 KiB `.crate`
        // does not.
        let (_capped_server, capped_url) = registry().await;
        let capped = RegistryClient::with_limits(
            capped_url,
            DownloadLimits {
                max_bytes: 1024,
                ..DownloadLimits::default()
            },
        )
        .unwrap();
        capped.index_record("foo", "1.0.0").await.unwrap();
        let error = capped.download_crate("foo", "1.0.0").await.unwrap_err();
        assert!(error.to_string().contains("download limit"), "{error}");
    }

    // Git acquisition (local fixture repositories; skipped without `git`)

    /// Runs `git` for fixture setup with an isolated, deterministic config.
    ///
    /// The environment is cleared first. Git exports repository variables
    /// (`GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, …) to hooks, and this
    /// repository's pre-commit hook runs `cargo test`: inheriting them made
    /// these fixture commands operate on the *enclosing* repository —
    /// `git init` failed on its locked config, and `git commit` committed its
    /// working tree. `XDG_CONFIG_HOME` and friends are dropped for the same
    /// reason, so no user configuration leaks in either.
    fn git(dir: &Path, args: &[&str]) -> String {
        let temp = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        let target = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        assert!(
            target.starts_with(&temp),
            "fixture git commands must run inside {}, not {}",
            temp.display(),
            target.display()
        );
        let output = std::process::Command::new("git")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("LC_ALL", "C")
            // Stops repository discovery from climbing out of the fixture.
            .env("GIT_CEILING_DIRECTORIES", &temp)
            .args([
                "-c",
                "user.name=robigus",
                "-c",
                "user.email=robigus@example.invalid",
                "-c",
                "init.defaultBranch=main",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "protocol.file.allow=always",
            ])
            .args(args)
            .current_dir(dir)
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn git_available() -> bool {
        let available = std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success());
        if !available {
            eprintln!("skipping: git is not installed");
        }
        available
    }

    /// Creates a repository at `dir` with one commit of `files`; returns the
    /// commit id.
    fn make_repo(dir: &Path, files: &[(&str, &str)]) -> String {
        fs::create_dir_all(dir).unwrap();
        git(dir, &["init", "-q"]);
        commit_files(dir, files, "initial")
    }

    fn commit_files(dir: &Path, files: &[(&str, &str)], message: &str) -> String {
        for (path, contents) in files {
            let path = dir.join(path);
            create_parent_dirs(&path).unwrap();
            fs::write(path, contents).unwrap();
        }
        git(dir, &["add", "-A"]);
        git(dir, &["commit", "-q", "-m", message]);
        git(dir, &["rev-parse", "HEAD"])
    }

    fn file_url(path: &Path) -> Url {
        Url::from_file_path(path).unwrap()
    }

    fn with_file_submodules() -> FetchOptions {
        let mut options = FetchOptions::default();
        options.git.submodule_schemes.insert("file".to_string());
        options
    }

    #[tokio::test]
    async fn git_clone_resolves_default_and_non_default_branches() {
        if !git_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let main = make_repo(&repo, &[("README", "main")]);
        git(&repo, &["checkout", "-q", "-b", "feature"]);
        let feature = commit_files(&repo, &[("README", "feature")], "feature");
        git(&repo, &["checkout", "-q", "main"]);

        let (cache, _cache_dir) = temp_cache();
        let options = FetchOptions::default();
        let url = file_url(&repo);
        let fetched = fetch_git(&url, &GitReference::DefaultBranch, &cache, &options)
            .await
            .unwrap();
        assert_eq!(fetched.digest, main);
        assert_eq!(
            fs::read_to_string(fetched.tree.join("README")).unwrap(),
            "main"
        );
        assert_eq!(fetched.source_id().precise.as_deref(), Some(main.as_str()));

        // Regression (Medium): a non-default branch exists only as a
        // remote-tracking ref after the clone.
        let fetched = fetch_git(
            &url,
            &GitReference::Branch("feature".to_string()),
            &cache,
            &options,
        )
        .await
        .unwrap();
        assert_eq!(fetched.digest, feature);
        assert_eq!(
            fs::read_to_string(fetched.tree.join("README")).unwrap(),
            "feature"
        );
    }

    /// Builds a superproject whose submodule `vendor/sub` is pinned to the
    /// submodule's *first* commit, although the submodule has a newer one.
    /// Returns `(superproject, pinned commit)`.
    fn superproject_with_submodule(root: &Path) -> (PathBuf, String) {
        let sub = root.join("sub");
        let pinned = make_repo(&sub, &[("lib.c", "int v1;")]);
        commit_files(&sub, &[("lib.c", "int v2;")], "v2");

        let superproject = root.join("super");
        make_repo(&superproject, &[("Cargo.toml", "[package]")]);
        git(
            &superproject,
            &[
                "submodule",
                "add",
                "-q",
                file_url(&sub).as_str(),
                "vendor/sub",
            ],
        );
        git(
            &superproject.join("vendor/sub"),
            &["checkout", "-q", &pinned],
        );
        git(&superproject, &["add", "-A"]);
        git(&superproject, &["commit", "-q", "-m", "add submodule"]);
        (superproject, pinned)
    }

    #[tokio::test]
    async fn git_submodules_are_checked_out_at_the_pinned_commit() {
        if !git_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (superproject, _pinned) = superproject_with_submodule(dir.path());
        let (cache, _cache_dir) = temp_cache();
        let fetched = fetch_git(
            &file_url(&superproject),
            &GitReference::DefaultBranch,
            &cache,
            &with_file_submodules(),
        )
        .await
        .unwrap();
        assert_eq!(
            fs::read_to_string(fetched.tree.join("vendor/sub/lib.c")).unwrap(),
            "int v1;",
            "the pinned commit, not the submodule's newest"
        );
    }

    /// `.gitmodules` is untrusted: by default only `https` submodules are
    /// fetched, so a `file://` URL is refused and nothing is cached.
    #[tokio::test]
    async fn git_submodule_url_schemes_are_restricted() {
        if !git_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (superproject, _) = superproject_with_submodule(dir.path());
        let (cache, _cache_dir) = temp_cache();
        let error = fetch_git(
            &file_url(&superproject),
            &GitReference::DefaultBranch,
            &cache,
            &FetchOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("is not allowed"), "{error}");
        assert!(
            !cache.root().join("git").exists()
                || fs::read_dir(cache.root().join("git")).unwrap().count() == 0,
            "a rejected fetch caches nothing"
        );
    }

    #[tokio::test]
    async fn git_submodules_with_update_none_are_skipped() {
        if !git_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (superproject, _) = superproject_with_submodule(dir.path());
        git(
            &superproject,
            &[
                "config",
                "-f",
                ".gitmodules",
                "submodule.vendor/sub.update",
                "none",
            ],
        );
        git(&superproject, &["commit", "-q", "-am", "skip submodule"]);
        let (cache, _cache_dir) = temp_cache();
        // Default options would reject the file:// URL if it were fetched.
        let fetched = fetch_git(
            &file_url(&superproject),
            &GitReference::DefaultBranch,
            &cache,
            &FetchOptions::default(),
        )
        .await
        .unwrap();
        assert!(!fetched.tree.join("vendor/sub/lib.c").exists());
    }

    #[tokio::test]
    async fn git_checkouts_are_held_to_the_extraction_limits() {
        if !git_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        make_repo(&repo, &[("a", "1"), ("b", "2"), ("c", "3")]);
        let (cache, _cache_dir) = temp_cache();
        let options = FetchOptions {
            extraction: ExtractionLimits {
                max_entries: 2,
                ..ExtractionLimits::default()
            },
            ..FetchOptions::default()
        };
        let error = fetch_git(
            &file_url(&repo),
            &GitReference::DefaultBranch,
            &cache,
            &options,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("entry-count limit"), "{error}");
    }

    #[test]
    fn watchdog_fires_only_after_its_timeout() {
        let flag = Arc::new(AtomicBool::new(false));
        {
            let _watchdog = Watchdog::start(Duration::from_millis(10), flag.clone());
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(flag.load(Ordering::SeqCst), "fired after the timeout");

        let flag = Arc::new(AtomicBool::new(false));
        drop(Watchdog::start(Duration::from_secs(60), flag.clone()));
        assert!(!flag.load(Ordering::SeqCst), "dropping it first disarms it");
    }
}

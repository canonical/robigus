//! Source acquisition, verification, and safe extraction (spec §7.1, §7.2).
//!
//! All fetched content is untrusted: tarball extraction enforces the §7.2
//! hardening rules (path traversal, escaping links, device nodes, setuid/
//! setgid, entry-count and total-size limits), and every source records a
//! SHA-256 digest with explicit provenance. Git sources record the exact
//! resolved commit; registry `.crate` artifacts are checksum-verified against
//! the registry index (mandatory, never optional).

use crate::error::{FetchError, RobigusError};
use crate::model::{GitReference, SourceKind, path_tree_digest};
use flate2::read::GzDecoder;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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

// 4. Dispatch
/// Fetches a source into the cache (spec §7.2).
pub async fn fetch(input: SourceInput, cache: &Cache) -> Result<FetchedSource, RobigusError> {
    match input {
        SourceInput::Git { url, reference } => fetch_git(&url, &reference, cache).await,
        SourceInput::Tarball { url, digest } => fetch_tarball(&url, digest.as_deref(), cache).await,
        SourceInput::Path { path } => fetch_path(&path).await,
    }
}

/// Fetches a git repository: clone into a scratch directory, resolve the
/// requested revision to a commit, check that commit out, and move the tree
/// into the content-addressed cache. When the reference pins a revision that
/// is already cached, no network access happens.
pub async fn fetch_git(
    url: &Url,
    reference: &GitReference,
    cache: &Cache,
) -> Result<FetchedSource, RobigusError> {
    let url = url.clone();
    let reference = reference.clone();
    let cache = cache.clone();
    spawn_blocking(move || fetch_git_sync(&url, &reference, &cache).map_err(RobigusError::from))
        .await
        .map_err(|error| {
            RobigusError::Fetch(FetchError::Git(format!("git task failed: {error}")))
        })?
}

/// Downloads a tarball, verifies its digest (when one was supplied), and
/// extracts it into the content-addressed cache. When the digest is pinned
/// and the tree is already cached, no network access happens.
pub async fn fetch_tarball(
    url: &Url,
    expected_digest: Option<&str>,
    cache: &Cache,
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

    let bytes = download(url).await?;
    let url = url.clone();
    let cache = cache.clone();
    spawn_blocking(move || {
        install_tarball(&bytes, expected.as_deref(), &url, &cache).map_err(RobigusError::from)
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
pub async fn fetch_path(path: &Path) -> Result<FetchedSource, RobigusError> {
    let path = path.to_path_buf();
    spawn_blocking(move || {
        let tree = path
            .canonicalize()
            .map_err(FetchError::from)
            .map_err(RobigusError::from)?;
        let digest = path_tree_digest(&tree)?;
        Ok(FetchedSource {
            tree,
            digest,
            provenance: Provenance::Verified,
            kind: SourceKind::Path {
                path: PathBuf::new(),
            },
        })
    })
    .await
    .map(|result| {
        result.map(|mut fetched| {
            // The kind carries the caller-supplied path; the tree is the
            // canonicalized form.
            fetched.kind = SourceKind::Path {
                path: fetched.tree.clone(),
            };
            fetched
        })
    })
    .map_err(|error| {
        RobigusError::Fetch(FetchError::Walk(format!("digest task failed: {error}")))
    })?
}

// 5. Git acquisition
fn fetch_git_sync(
    url: &Url,
    reference: &GitReference,
    cache: &Cache,
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
    let cloned = clone_and_checkout(url, reference, &scratch);
    if cloned.is_err() {
        let _ = fs::remove_dir_all(&scratch);
    }
    let commit = cloned?;

    let tree = match cache.path_for("git", &commit) {
        Ok(tree) => tree,
        Err(error) => {
            let _ = fs::remove_dir_all(&scratch);
            return Err(error);
        }
    };
    if tree.exists() {
        fs::remove_dir_all(&scratch)?;
    } else {
        fs::create_dir_all(cache.root.join("git"))?;
        fs::rename(&scratch, &tree)?;
    }

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

fn clone_and_checkout(
    url: &Url,
    reference: &GitReference,
    dest: &Path,
) -> Result<String, FetchError> {
    let mut prepare = gix::clone::PrepareFetch::new(
        url.as_str(),
        dest,
        gix::create::Kind::WithWorktree,
        gix::create::Options::default(),
        gix::open::Options::default(),
    )
    .map_err(|error| FetchError::Git(format!("clone preparation failed: {error}")))?;
    let (mut prepare_checkout, _) = prepare
        .fetch_then_checkout(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
        .map_err(|error| FetchError::Git(format!("fetch failed: {error}")))?;

    let commit = resolve_commit(prepare_checkout.repo(), reference)?;
    point_head_at(prepare_checkout.repo(), &commit)?;

    prepare_checkout
        .main_worktree(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
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
        GitReference::Branch(name) => peeled(format!("refs/heads/{name}")),
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
async fn download(url: &Url) -> Result<Vec<u8>, FetchError> {
    let response = reqwest::get(url.as_str())
        .await
        .map_err(|error| FetchError::Download(format!("download of {url} failed: {error}")))?;
    let response = response
        .error_for_status()
        .map_err(|error| FetchError::Download(format!("download of {url} failed: {error}")))?;
    let bytes = response
        .bytes()
        .await
        .map_err(|error| FetchError::Download(format!("download of {url} failed: {error}")))?;
    Ok(bytes.to_vec())
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
    let extracted = extract_tarball(&archive, &staging, &ExtractionLimits::default());
    let _ = fs::remove_file(&archive);
    extracted?;

    fs::create_dir_all(cache.root.join("tarball"))?;
    if let Err(error) = fs::rename(&staging, &tree) {
        let _ = fs::remove_dir_all(&staging);
        // A concurrent install of the same content may have won the race.
        if !tree.is_dir() {
            return Err(error.into());
        }
    }

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
pub(crate) fn normalize_lexical(path: &Path) -> PathBuf {
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
    pub fn new(index_url: Url) -> Result<Self, FetchError> {
        Ok(Self {
            index: index_url,
            http: reqwest::Client::builder()
                .user_agent(http_user_agent())
                .build()
                .map_err(|error| FetchError::Registry(format!("http client failed: {error}")))?,
        })
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
        let text = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| FetchError::Registry(format!("index lookup failed: {error}")))?
            .error_for_status()
            .map_err(|error| FetchError::Registry(format!("index lookup failed: {error}")))?
            .text()
            .await
            .map_err(|error| FetchError::Registry(format!("index lookup failed: {error}")))?;
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
        let response = self
            .http
            .get(download_url)
            .send()
            .await
            .map_err(|error| FetchError::Registry(format!("crate download failed: {error}")))?
            .error_for_status()
            .map_err(|error| FetchError::Registry(format!("crate download failed: {error}")))?;
        let bytes = response
            .bytes()
            .await
            .map_err(|error| FetchError::Registry(format!("crate download failed: {error}")))?
            .to_vec();
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
        let config_url = self
            .index
            .join("config.json")
            .map_err(|error| FetchError::Registry(format!("invalid index URL: {error}")))?;
        let config: IndexConfig = self
            .http
            .get(config_url)
            .send()
            .await
            .map_err(|error| FetchError::Registry(format!("index config lookup failed: {error}")))?
            .error_for_status()
            .map_err(|error| FetchError::Registry(format!("index config lookup failed: {error}")))?
            .json::<IndexConfig>()
            .await
            .map_err(|error| FetchError::Registry(format!("invalid index config: {error}")))?;
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
        install_tarball(&bytes, None, &url, &cache).unwrap_err();
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
            let error = fetch_tarball(&url, Some(bad), &cache).await.unwrap_err();
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
        let fetched = fetch_tarball(&url, Some(&supplied), &cache).await.unwrap();
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

        let fetched = fetch_tarball(&url, Some(&digest), &cache).await.unwrap();
        assert_eq!(fetched.tree, cached_tree);
        assert_eq!(fetched.provenance, Provenance::Verified);
        assert_eq!(
            fs::read_to_string(fetched.tree.join("marker")).unwrap(),
            "cached"
        );
    }

    #[tokio::test]
    async fn tarball_install_extracts_into_cache() {
        let (cache, _dir) = temp_cache();
        let url = Url::parse("https://example.com/src.tar").unwrap();
        let bytes = tar_bytes(&[("src/lib.rs", b"fn main() {}")]);

        let fetched = install_tarball(&bytes, None, &url, &cache).unwrap();
        assert_eq!(fetched.provenance, Provenance::Unverified);
        assert!(fetched.tree.join("src").join("lib.rs").exists());

        // A second install with the same bytes hits the same tree.
        let again = install_tarball(&bytes, None, &url, &cache).unwrap();
        assert_eq!(again.tree, fetched.tree);
        assert_eq!(again.digest, fetched.digest);
    }

    #[tokio::test]
    async fn tarball_digest_mismatch_is_rejected() {
        let (cache, _dir) = temp_cache();
        let url = Url::parse("https://example.com/src.tar").unwrap();
        let bytes = tar_bytes(&[("src/lib.rs", b"fn main() {}")]);
        let error = install_tarball(&bytes, Some(&"0".repeat(64)), &url, &cache).unwrap_err();
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

        let fetched = fetch_git(&url, &GitReference::Rev(commit.clone()), &cache)
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
}

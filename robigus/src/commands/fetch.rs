//! Source acquisition command (`tsp-analyzer fetch`).

use std::path::PathBuf;

use crate::cli::CliError;
use robigus::fetch::{Cache, FetchOptions, FetchedSource, SourceInput, fetch, fetch_offline};
use robigus::model::GitReference;
use url::Url;

#[derive(clap::Args, Debug, Clone)]
pub struct FetchArgs {
    /// Local path, tarball URL, or git repository URL.
    #[arg(value_name = "SOURCE")]
    pub source: String,

    /// Git branch to resolve (mutually exclusive with --tag, --rev, and --sha256).
    #[arg(long, conflicts_with_all = ["tag", "rev", "sha256"])]
    pub branch: Option<String>,

    /// Git tag to resolve (mutually exclusive with --branch, --rev, and --sha256).
    #[arg(long, conflicts_with_all = ["branch", "rev", "sha256"])]
    pub tag: Option<String>,

    /// Git revision or commit hash (required for offline git cache hits).
    #[arg(long, conflicts_with_all = ["branch", "tag", "sha256"])]
    pub rev: Option<String>,

    /// Expected tarball SHA-256 digest (required for offline tarball cache hits).
    #[arg(long, conflicts_with_all = ["branch", "tag", "rev"])]
    pub sha256: Option<String>,
}

pub async fn run(
    args: &FetchArgs,
    offline: bool,
    cache: &Cache,
    options: &FetchOptions,
) -> Result<FetchedSource, CliError> {
    let input = parse_source(args)?;
    let fetched = if offline {
        fetch_offline(input, cache).await?
    } else {
        fetch(input, cache, options).await?
    };
    Ok(fetched)
}

fn parse_source(args: &FetchArgs) -> Result<SourceInput, CliError> {
    let git_ref = match (&args.branch, &args.tag, &args.rev) {
        (Some(branch), None, None) => Some(GitReference::Branch(branch.clone())),
        (None, Some(tag), None) => Some(GitReference::Tag(tag.clone())),
        (None, None, Some(rev)) => Some(GitReference::Rev(rev.clone())),
        (None, None, None) => None,
        _ => {
            return Err(CliError::Usage(
                "at most one of --branch, --tag, or --rev may be supplied".into(),
            ));
        }
    };

    if let Some(url) = parse_remote_url(&args.source)? {
        if args.sha256.is_some() {
            return Ok(SourceInput::Tarball {
                url,
                digest: args.sha256.clone(),
            });
        }
        if let Some(reference) = git_ref {
            return Ok(SourceInput::Git { url, reference });
        }
        if looks_like_tarball(&url) {
            return Ok(SourceInput::Tarball { url, digest: None });
        }
        return Ok(SourceInput::Git {
            url,
            reference: GitReference::DefaultBranch,
        });
    }

    if git_ref.is_some() || args.sha256.is_some() {
        return Err(CliError::Usage(
            "--branch, --tag, --rev, and --sha256 apply only to remote git or tarball URLs".into(),
        ));
    }
    Ok(SourceInput::Path {
        path: PathBuf::from(&args.source),
    })
}

fn parse_remote_url(source: &str) -> Result<Option<Url>, CliError> {
    let Some((scheme, _)) = source.split_once("://") else {
        return Ok(None);
    };
    if !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return Ok(None);
    }
    let url = Url::parse(source)
        .map_err(|error| CliError::Usage(format!("invalid source URL '{source}': {error}")))?;
    Ok(Some(url))
}

fn looks_like_tarball(url: &Url) -> bool {
    let path = url.path().to_ascii_lowercase();
    [
        ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.zst", ".tzst", ".crate",
    ]
    .iter()
    .any(|ext| path.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_paths_tarballs_and_git_urls() {
        let local = parse_source(&FetchArgs {
            source: "relative/path".into(),
            branch: None,
            tag: None,
            rev: None,
            sha256: None,
        })
        .unwrap();
        assert!(matches!(local, SourceInput::Path { .. }));

        let tarball = parse_source(&FetchArgs {
            source: "https://example.com/archive.tar.gz".into(),
            branch: None,
            tag: None,
            rev: None,
            sha256: None,
        })
        .unwrap();
        assert!(matches!(tarball, SourceInput::Tarball { digest: None, .. }));

        let git = parse_source(&FetchArgs {
            source: "https://example.com/repo.git".into(),
            branch: None,
            tag: Some("v1.0.0".into()),
            rev: None,
            sha256: None,
        })
        .unwrap();
        assert!(matches!(
            git,
            SourceInput::Git {
                reference: GitReference::Tag(_),
                ..
            }
        ));
    }

    #[test]
    fn rejects_remote_flags_on_local_paths() {
        let error = parse_source(&FetchArgs {
            source: "./local".into(),
            branch: None,
            tag: None,
            rev: Some("deadbeef".into()),
            sha256: None,
        })
        .unwrap_err();
        assert_eq!(error.exit_code(), 2);
    }
}

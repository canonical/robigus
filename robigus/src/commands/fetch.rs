//! Source acquisition command (`tsp-analyzer fetch`).

use std::path::PathBuf;

use crate::cli::{CliError, Config};
use robigus::fetch::{
    Cache, FetchOptions, FetchedSource, RegistrySource, SourceInput, fetch, fetch_offline,
};
use robigus::model::GitReference;
use robigus::registry::{RegistrySpec, parse_exact_version, validate_crate_name};
use url::Url;

#[derive(clap::Args, Debug, Clone, Default)]
pub struct FetchArgs {
    /// Local path, git repository URL, tarball URL, or `crate:<name>@<version>`
    /// for a registry crate (crates.io unless --registry or --index is given).
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

    /// Expected SHA-256 of a tarball or `.crate` (required for offline cache
    /// hits; for a registry crate it must equal the index checksum).
    #[arg(long, conflicts_with_all = ["branch", "tag", "rev"])]
    pub sha256: Option<String>,

    /// Registry crate: use a registry defined in the config's `[registries.NAME]`.
    #[arg(long, value_name = "NAME", conflicts_with = "index")]
    pub registry: Option<String>,

    /// Registry crate: use this sparse index (`sparse+https://…`). Never sends credentials.
    #[arg(long, value_name = "URL")]
    pub index: Option<String>,

    /// Registry crate: fetch the version even if it is yanked.
    #[arg(long)]
    pub allow_yanked: bool,
}

pub async fn run(
    args: &FetchArgs,
    offline: bool,
    cache: &Cache,
    config: &Config,
    options: &FetchOptions,
) -> Result<FetchedSource, CliError> {
    let input = parse_source(args, config)?;
    let fetched = if offline {
        fetch_offline(input, cache).await?
    } else {
        fetch(input, cache, options).await?
    };
    Ok(fetched)
}

fn parse_source(args: &FetchArgs, config: &Config) -> Result<SourceInput, CliError> {
    if let Some(spec) = args.source.strip_prefix("crate:") {
        return parse_registry_source(spec, args, config);
    }
    if args.registry.is_some() || args.index.is_some() || args.allow_yanked {
        return Err(CliError::Usage(
            "--registry, --index, and --allow-yanked apply only to `crate:<name>@<version>` sources"
                .into(),
        ));
    }
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
            "--branch, --tag, --rev, and --sha256 apply only to remote git, tarball, or crate sources"
                .into(),
        ));
    }
    Ok(SourceInput::Path {
        path: PathBuf::from(&args.source),
    })
}

/// `crate:<name>@<version>` (spec §14). The name and an exact version are
/// both required; write `./crate:…` for a local directory of that name.
fn parse_registry_source(
    spec: &str,
    args: &FetchArgs,
    config: &Config,
) -> Result<SourceInput, CliError> {
    let usage = |reason: String| {
        CliError::Usage(format!(
            "{reason}; registry sources are `crate:<name>@<version>` (write `./crate:…` for a local directory)"
        ))
    };
    if args.branch.is_some() || args.tag.is_some() || args.rev.is_some() {
        return Err(CliError::Usage(
            "--branch, --tag, and --rev do not apply to registry crates".into(),
        ));
    }
    let (name, version) = spec
        .split_once('@')
        .ok_or_else(|| usage(format!("'crate:{spec}' has no version")))?;
    validate_crate_name(name).map_err(|error| usage(error.to_string()))?;
    let version = parse_exact_version(version).map_err(|error| usage(error.to_string()))?;
    let registry = match (&args.registry, &args.index) {
        (Some(name), _) => config.registry(name)?,
        (None, Some(index)) => {
            RegistrySpec::direct(index).map_err(|error| CliError::Usage(error.to_string()))?
        }
        (None, None) => RegistrySpec::crates_io(),
    };
    Ok(SourceInput::Registry(RegistrySource {
        registry,
        name: name.to_owned(),
        version,
        digest: args.sha256.clone(),
        allow_yanked: args.allow_yanked,
    }))
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
    use robigus::CredentialSource;

    fn args(source: &str) -> FetchArgs {
        FetchArgs {
            source: source.into(),
            ..FetchArgs::default()
        }
    }

    fn parse(args: &FetchArgs) -> Result<SourceInput, CliError> {
        parse_source(args, &Config::default())
    }

    #[test]
    fn classifies_paths_tarballs_and_git_urls() {
        assert!(matches!(
            parse(&args("relative/path")).unwrap(),
            SourceInput::Path { .. }
        ));
        assert!(matches!(
            parse(&args("https://example.com/archive.tar.gz")).unwrap(),
            SourceInput::Tarball { digest: None, .. }
        ));
        let git = parse(&FetchArgs {
            tag: Some("v1.0.0".into()),
            ..args("https://example.com/repo.git")
        })
        .unwrap();
        assert!(matches!(
            git,
            SourceInput::Git {
                reference: GitReference::Tag(_),
                ..
            }
        ));
        // A local directory whose name starts with `crate:`.
        assert!(matches!(
            parse(&args("./crate:odd")).unwrap(),
            SourceInput::Path { .. }
        ));
    }

    #[test]
    fn rejects_remote_flags_on_local_paths() {
        for flags in [
            FetchArgs {
                rev: Some("deadbeef".into()),
                ..args("./local")
            },
            FetchArgs {
                index: Some("sparse+https://registry.example/".into()),
                ..args("./local")
            },
            FetchArgs {
                allow_yanked: true,
                ..args("https://example.com/archive.tar.gz")
            },
        ] {
            assert_eq!(parse(&flags).unwrap_err().exit_code(), 2);
        }
    }

    #[test]
    fn parses_registry_sources() {
        let SourceInput::Registry(source) = parse(&FetchArgs {
            sha256: Some("a".repeat(64)),
            allow_yanked: true,
            ..args("crate:itoa@1.0.11")
        })
        .unwrap() else {
            panic!("expected a registry source");
        };
        assert_eq!(source.registry, RegistrySpec::crates_io());
        assert_eq!(source.name, "itoa");
        assert_eq!(source.version.to_string(), "1.0.11");
        assert_eq!(source.digest.as_deref(), Some("a".repeat(64).as_str()));
        assert!(source.allow_yanked);

        let SourceInput::Registry(direct) = parse(&FetchArgs {
            index: Some("sparse+https://Registry.Example/index".into()),
            ..args("crate:My_Crate@0.1.0-rc.1")
        })
        .unwrap() else {
            panic!("expected a registry source");
        };
        assert_eq!(
            direct.registry.index_url.as_str(),
            "https://registry.example/index/"
        );
        assert_eq!(direct.registry.credentials, CredentialSource::None);

        for (source, flags, expected) in [
            ("crate:itoa", FetchArgs::default(), "no version"),
            (
                "crate:itoa@^1",
                FetchArgs::default(),
                "not an exact version",
            ),
            ("crate:itoa@1", FetchArgs::default(), "not an exact version"),
            (
                "crate:1bad@1.0.0",
                FetchArgs::default(),
                "invalid crate name",
            ),
            ("crate:@1.0.0", FetchArgs::default(), "invalid crate name"),
            (
                "crate:itoa@1.0.0",
                FetchArgs {
                    tag: Some("v1".into()),
                    ..FetchArgs::default()
                },
                "do not apply",
            ),
            (
                "crate:itoa@1.0.0",
                FetchArgs {
                    index: Some("https://registry.example/".into()),
                    ..FetchArgs::default()
                },
                "git index",
            ),
            (
                "crate:itoa@1.0.0",
                FetchArgs {
                    registry: Some("missing".into()),
                    ..FetchArgs::default()
                },
                "unknown registry",
            ),
        ] {
            let error = parse(&FetchArgs {
                source: source.into(),
                ..flags
            })
            .unwrap_err();
            assert_eq!(error.exit_code(), 2, "{source}: {error}");
            assert!(error.to_string().contains(expected), "{source}: {error}");
        }
    }

    #[test]
    fn named_registries_come_from_the_config() {
        let config: Config = toml::from_str(
            r#"
[registries.internal]
index = "sparse+https://registry.example/index/"
[registries.vault]
index = "sparse+https://vault.example/"
credential-provider = { process = ["/usr/bin/provider", "--account", "work"] }
[registries.file]
index = "sparse+https://file.example/"
credential-provider = { file = "/home/me/token" }
[registries.public]
index = "sparse+https://public.example/"
credential-provider = { env = false }
"#,
        )
        .unwrap();
        config.validate().unwrap();
        let resolve = |name: &str| {
            let SourceInput::Registry(source) = parse_source(
                &FetchArgs {
                    registry: Some(name.into()),
                    ..args("crate:demo@1.0.0")
                },
                &config,
            )
            .unwrap() else {
                panic!("expected a registry source");
            };
            source.registry
        };
        let internal = resolve("internal");
        assert_eq!(internal.name.as_deref(), Some("internal"));
        assert_eq!(
            internal.credentials,
            CredentialSource::Env {
                registry: "internal".into()
            }
        );
        assert_eq!(
            resolve("vault").credentials,
            CredentialSource::Process {
                program: "/usr/bin/provider".into(),
                args: vec!["--account".into(), "work".into()],
            }
        );
        assert_eq!(
            resolve("file").credentials,
            CredentialSource::File {
                path: "/home/me/token".into()
            }
        );
        assert_eq!(resolve("public").credentials, CredentialSource::None);
    }

    #[test]
    fn invalid_registry_config_is_rejected_at_load() {
        for text in [
            "[registries.bad]\nindex = \"https://registry.example/\"",
            "[registries.bad]\nindex = \"sparse+http://registry.example/\"",
            "[registries.bad]\nindex = \"sparse+https://registry.example/\"\ncredential-provider = { file = \"relative/token\" }",
            "[registries.bad]\nindex = \"sparse+https://registry.example/\"\ncredential-provider = { process = [\"provider\"] }",
            "[registries.bad]\nindex = \"sparse+https://registry.example/\"\ncredential-provider = { process = [] }",
            "[registries.\"1bad\"]\nindex = \"sparse+https://registry.example/\"",
        ] {
            let config: Config = toml::from_str(text).unwrap();
            assert_eq!(config.validate().unwrap_err().exit_code(), 2, "{text}");
        }
        for text in [
            "[registries.bad]\nindex = \"sparse+https://r.example/\"\ntoken = \"secret\"",
            "[registries.bad]\nindex = \"sparse+https://r.example/\"\ncredential-provider = { env = true, file = \"/t\" }",
            "[registries.bad]\ncredential-provider = { env = true }",
        ] {
            assert!(toml::from_str::<Config>(text).is_err(), "accepted {text}");
        }
    }
}

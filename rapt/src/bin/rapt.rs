//! The `rapt` command-line application.

use std::process::ExitCode;

use clap::Parser;
use regex::Regex;

use rapt::cli::{Cli, Commands};
use rapt::error::{RaptError, Result};
use rapt::{ArchiveClient, CacheManager, RaptQuery, SeriesCache};

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(err) = run().await {
        eprintln!("rapt: error: {err}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Check version subcommand first (doesn't require series or cache)
    if matches!(cli.command, Commands::Version) {
        println!("rapt version {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let filter = cli.build_filter()?;
    let cache_manager = CacheManager::default();
    let archive_client = ArchiveClient::default();

    // Determine if we need to load or refresh cache
    let mut cache: Option<SeriesCache> = cache_manager.load_cache(filter.series())?;

    let need_update =
        matches!(cli.command, Commands::Update) || cache.as_ref().is_none_or(|c| !c.is_fresh());

    if need_update {
        eprintln!("Updating package cache for series '{}'...", filter.series());
        let new_cache = archive_client.populate_cache(&filter).await?;
        cache_manager.save_cache(&new_cache)?;
        cache = Some(new_cache);
    }

    let cache = cache.ok_or_else(|| {
        RaptError::Other(format!(
            "failed to obtain package cache for series '{}'",
            filter.series()
        ))
    })?;

    let query_runner = RaptQuery::new(&cache, &filter);

    match cli.command {
        Commands::Update => {
            println!("Cache successfully updated for '{}'.", filter.series());
        }
        Commands::Showpkg(args) => {
            for pkg in &args.packages {
                print!("{}", query_runner.showpkg(pkg));
            }
        }
        Commands::Showsrc(args) => {
            for pkg in &args.packages {
                if let Some(output) = query_runner.showsrc(pkg) {
                    print!("{output}");
                } else {
                    eprintln!("rapt: source package '{pkg}' not found");
                }
            }
        }
        Commands::Stats => {
            let stats = query_runner.stats();
            println!("{}", stats.format_stats());
        }
        Commands::Dump => {
            print!("{}", query_runner.dump());
        }
        Commands::Unmet => {
            print!("{}", query_runner.unmet());
        }
        Commands::Show(args) => {
            for target in &args.packages {
                let output = query_runner.show(target)?;
                print!("{output}");
            }
        }
        Commands::Search(args) => {
            let mut regexes = Vec::new();
            for pat in &args.regex {
                let r = Regex::new(pat).map_err(|source| RaptError::InvalidRegex {
                    pattern: pat.clone(),
                    source,
                })?;
                regexes.push(r);
            }
            let output = query_runner.search(&regexes, args.full, args.names_only);
            print!("{output}");
        }
        Commands::Depends(args) => {
            for target in &args.packages {
                let output = query_runner.depends(target)?;
                print!("{output}");
            }
        }
        Commands::Rdepends(args) => {
            for target in &args.packages {
                let output = query_runner.rdepends(target)?;
                print!("{output}");
            }
        }
        Commands::Pkgnames(args) => {
            let names = query_runner.pkgnames(args.prefix.as_deref());
            for name in names {
                println!("{name}");
            }
        }
        Commands::Madison(args) => {
            for pkg in &args.packages {
                print!("{}", query_runner.madison(pkg));
            }
        }
        Commands::Version => unreachable!(),
    }

    Ok(())
}

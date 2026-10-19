//! The rapt command-line client arguments and subcommands definitions.

use clap::{Args, Parser, Subcommand};

use crate::types::{
    Architecture, Component, PackageTarget, Pocket, QueryFilter, QueryFilterBuilder,
};

/// rapt: Ubuntu archive command-line client and query tool.
#[derive(Debug, Parser)]
#[command(name = "rapt", version, about = "Ubuntu archive command-line client")]
pub struct Cli {
    /// Target Ubuntu series (e.g. resolute, noble, jammy).
    #[arg(short, long, global = true)]
    pub series: Option<String>,

    /// Target archive pockets (release, proposed, updates, security, backports).
    #[arg(
        short,
        long,
        value_name = "POCKET",
        value_delimiter = ',',
        global = true
    )]
    pub pocket: Option<Vec<Pocket>>,

    /// Inverse filter for pockets: all pockets except those specified.
    #[arg(
        short = 'q',
        long,
        value_name = "POCKET",
        value_delimiter = ',',
        global = true
    )]
    pub not_pocket: Option<Vec<Pocket>>,

    /// Target archive components (main, universe, restricted, multiverse).
    #[arg(
        short,
        long,
        value_name = "COMPONENT",
        value_delimiter = ',',
        global = true
    )]
    pub component: Option<Vec<Component>>,

    /// Inverse filter for components: all components except those specified.
    #[arg(
        short = 'd',
        long,
        value_name = "COMPONENT",
        value_delimiter = ',',
        global = true
    )]
    pub not_component: Option<Vec<Component>>,

    /// Target CPU architectures (amd64, arm64, armhf, ppc64el, s390x, riscv64).
    #[arg(short, long, value_name = "ARCH", value_delimiter = ',', global = true)]
    pub arch: Option<Vec<Architecture>>,

    /// Inverse filter for architectures: all architectures except those specified.
    #[arg(
        short = 'b',
        long,
        value_name = "ARCH",
        value_delimiter = ',',
        global = true
    )]
    pub not_arch: Option<Vec<Architecture>>,

    /// Command to execute.
    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    /// Constructs a `QueryFilter` from the parsed CLI flags.
    pub fn build_filter(&self) -> crate::error::Result<QueryFilter> {
        let series = self
            .series
            .as_deref()
            .ok_or(crate::error::RaptError::MissingSeries)?;

        let mut builder = QueryFilterBuilder::new(series);
        if let Some(p) = &self.pocket {
            builder = builder.pockets(p.clone());
        }
        if let Some(np) = &self.not_pocket {
            builder = builder.not_pockets(np.clone());
        }
        if let Some(c) = &self.component {
            builder = builder.components(c.clone());
        }
        if let Some(nc) = &self.not_component {
            builder = builder.not_components(nc.clone());
        }
        if let Some(a) = &self.arch {
            builder = builder.architectures(a.clone());
        }
        if let Some(na) = &self.not_arch {
            builder = builder.not_architectures(na.clone());
        }

        builder.build()
    }
}

/// Available subcommands for rapt.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Update the local rapt package cache.
    Update,

    /// Display information about the package(s) including forward and reverse dependencies.
    Showpkg(PkgArgs),

    /// Display information about the source package(s).
    Showsrc(PkgArgs),

    /// Display statistics about the local rapt package cache.
    Stats,

    /// Short listing of every package in the cache (primarily for debugging).
    Dump,

    /// Display a summary of all unmet dependencies in the local rapt package cache.
    Unmet,

    /// Show the full package record(s) for the named package(s).
    Show(VersionedPkgArgs),

    /// Search package names and descriptions using regular expressions.
    Search(SearchArgs),

    /// Show a listing of each dependency a package has.
    Depends(VersionedPkgArgs),

    /// Show a listing of each reverse dependency a package has.
    Rdepends(VersionedPkgArgs),

    /// Print the name of each package in the local rapt package cache.
    Pkgnames(PkgnamesArgs),

    /// Mimic the output format and functionality of the madison archive management tool.
    Madison(PkgArgs),

    /// Prints the rapt tool version and exits.
    Version,
}

/// Arguments for sub-commands taking one or more package names.
#[derive(Debug, Args)]
pub struct PkgArgs {
    /// One or more package names.
    #[arg(required = true, num_args = 1..)]
    pub packages: Vec<String>,
}

/// Arguments for sub-commands taking one or more package names with optional version (`PKG[=PKG_VERSION_NUMBER]...`).
#[derive(Debug, Args)]
pub struct VersionedPkgArgs {
    /// One or more package names with optional version number.
    #[arg(required = true, num_args = 1.., value_parser = clap::value_parser!(PackageTarget))]
    pub packages: Vec<PackageTarget>,
}

/// Arguments for `search` sub-command.
#[derive(Debug, Args)]
pub struct SearchArgs {
    /// One or more regular expressions to match against packages.
    #[arg(required = true, num_args = 1..)]
    pub regex: Vec<String>,

    /// Produce output identical to the 'show' sub-command for each matching package.
    #[arg(short, long)]
    pub full: bool,

    /// Only search package names and provided packages, not descriptions.
    #[arg(short, long)]
    pub names_only: bool,
}

/// Arguments for `pkgnames` sub-command.
#[derive(Debug, Args)]
pub struct PkgNamesArgs {
    /// Optional prefix to filter package names.
    pub prefix: Option<String>,
}

pub type PkgnamesArgs = PkgNamesArgs;

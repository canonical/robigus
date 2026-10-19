# rapt

`rapt` is an Ubuntu Linux command-line client and Rust library for querying the Ubuntu archive.

Written in pure async Rust, `rapt` performs network requests directly against the Ubuntu archive to retrieve package and index metadata. It only queries the Ubuntu archive and downloads index data for local caching; it never installs or removes packages, nor does it modify system `apt` configurations or host package caches.

## Overview

- **Library crate (`rapt`)**: Provides ergonomic Rust abstractions around Ubuntu package and archive queries, including parsers for RFC 822 / Deb822 index files (`Packages` and `Sources`), query filtering, and cache management.
- **CLI binary (`rapt`)**: Command-line interface with sub-commands inspired by `apt-cache` and `madison`, formatted for terminal display and scripted workflows.
- **Local Caching**: Index data is cached locally per Ubuntu series (e.g. `resolute.json`) and kept fresh (re-queried if older than 1 hour or when explicitly running `update`).
- **Archive Mirrors**: Queries `http://archive.ubuntu.com/ubuntu` for `amd64` and `http://ports.ubuntu.com/ubuntu-ports` for other architectures (`arm64`, `armhf`, `ppc64el`, `s390x`, `riscv64`).

## Installation & Build

Build the project using Cargo:

```bash
cargo build --release
```

Run tests:

```bash
cargo test
```

## Command-Line Usage

All queries require a target Ubuntu series specified via `-s` / `--series`:

```bash
rapt -s noble <COMMAND> [OPTIONS]
```

### Global Query Filter Options

Filter which pockets, components, and architectures are queried:

| Flag | Long Flag | Description | Values / Examples |
|------|-----------|-------------|-------------------|
| `-s` | `--series` | Target Ubuntu series (required) | `noble`, `resolute`, `jammy` |
| `-p` | `--pocket` | Include specific pockets | `release`, `proposed`, `updates`, `security`, `backports` |
| `-q` | `--not-pocket` | Exclude specific pockets (inverse filter) | Accepts 1 to 4 pockets |
| `-c` | `--component` | Include specific components | `main`, `universe`, `restricted`, `multiverse` |
| `-d` | `--not-component` | Exclude specific components (inverse filter) | Accepts 1 to 3 components |
| `-a` | `--arch` | Include specific CPU architectures | `amd64`, `arm64`, `armhf`, `ppc64el`, `s390x`, `riscv64` |
| `-b` | `--not-arch` | Exclude specific architectures (inverse filter) | Accepts 1 to 5 architectures |

*Note: Positive and inverse filter flags (e.g. `--pocket` and `--not-pocket` / `-q`) are mutually exclusive.*

### Sub-Commands

- `update`: Update the local rapt package cache for the target series.
- `showpkg <PKG...>`: Display package details, versions, forward dependencies, and reverse dependencies.
- `showsrc <PKG...>`: Display source package records.
- `stats`: Display statistical totals for the series cache (total packages, normal, virtual, missing, dependencies).
- `dump`: Short listing of every package in the cache (for debugging).
- `unmet`: Display a summary of all unmet dependencies in the local cache.
- `show <PKG[=VERSION]...>`: Show full package record(s).
- `search [OPTIONS] <REGEX...>`: Regular expression search over package names and descriptions.
  - `-f`, `--full`: Output full package records identical to `show`.
  - `-n`, `--names-only`: Search package names and provided packages only.
- `depends <PKG[=VERSION]...>`: List dependencies and fulfilling packages.
- `rdepends <PKG[=VERSION]...>`: List reverse dependencies of a package.
- `pkgnames [PREFIX]`: Print names of packages in the cache, optionally filtered by prefix.
- `madison <PKG...>`: Mimic the Debian/Ubuntu `madison` archive management tool output.
- `version`: Print `rapt` version and exit.

## Examples

```bash
# Print package statistics for Ubuntu 26.04 (resolute)
rapt -s resolute stats

# Show package record for curl
rapt -s resolute show curl

# Search for packages matching regexes with names-only
rapt -s resolute search -n "curl"

# Exclude proposed pocket using -q and restricted component using -d
rapt -s resolute -q proposed -d restricted stats

# Madison table output for hello
rapt -s resolute madison hello
```


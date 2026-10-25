# Project Overview
robigus is a modular Rust library and set of command-line tools for tracking, planning, and managing software dependency graphs.  robigus is written in pure async Rust and accepts a target software project to be packaged.  It examines the target software project's configuration, build scripts and directives, and documentation to discover the target software project's dependencies.  

## Dependency Categories
Dependencies are categorized based on how they are used in the target software project:
* "dependencies" - dependencies needed to build or compile the target software project
* "dev-dependencies" - dependencies needed only for compiling and running tests, examples, and benchmarks.
* "runtime-dependencies" - dependencies needed in the execution environment when the target software project runs.  This includes interpreters, configuration files, data files, or similar components that are separate from the target software project itself, but required by the target software project for it to work.
* "build-dependencies" - dependencies required by build scripts (for example, 'build.rs' files for Rust) or code generation (for example, '.l', '.lex', or '.flex' files for lexical analyzer generators, or '.y' files for parser generators) before compiling the main package.
A dependency may appear in multiple categories depending on how it is used.  For example, the "gcc" compiler might appear in both "dev-dependencies" to compile tests and "dependencies" to compile the target software project.

## Dependency Annotations
Dependencies are also annotated based on certain predicates that describe what conditions must be true for the dependency to be required.  Dependencies with zero predicate annotations are always needed under all conditions.  Some example predicate annotation types include:
* "feature" - indicates the dependency is needed to enable an optional feature in the target software project.  For example, many Rust crates will offer an optional 'serde' feature to enable serde-compatible 'Serialize' and 'Deserialize' traits.  Another example is the "ffmpeg" project that has many different optional features to enable media formats and codecs. 
* "architecture" - indicates the dependency is needed for the target software project to work on a given machine architecture.  For example, a dependency might be needed for the "arm64" machine architecture, but not the "amd64" machine architecture.  Because there are a very large number of machine architectures, robigus will only track and use the machine architectures defined in the "ubuntu-info-rust" crate.  Other machine architectures outside of the machine architectures in the "ubuntu-info-rust" crate will be listed with the machine architecture name and "_unsupported" to indicate that the dependency is known, but will not be enumerated or expanded for the unsupported machine architecture; for example: "mips_unsupported".
* "platform" - indicates the dependency is needed for the target software project to work on a given operating system or target environment.  For example, a dependency might be needed for "linux" platforms, but not needed for "windows" platforms.  Because there are a large number of platforms, robigus will only track and use the "linux" platform.  Other platforms such as "windows", "macos", and others will be listed with the platform name and "_unsupported"; for example: "windows_unsupported".
A dependency may annotated with multiple predicates to describe precise conditions where it is needed.  For example, the "rav1e" crate (https://github.com/xiph/rav1e) has a 'asm' feature that is only available on the 'amd64' and 'arm64' machine architectures.  On the 'amd64' machine architecture, the "nasm" assembler is required to build the optimized 'amd64' assembly code.  On the 'arm64' machine architecture, the "gas" assembler is required OR the "clang" compiler can be used via the "CC=clang" environment variable setting.

## Folder Structure
- `/src`: top-level Rust source code folder
- `/src/bin`: robigus command-line tools
- `/src/lib.rs`: top-level library for shared modules and functionality
- `/test`: top-level folder for integration tests

## Coding Standards
- Follow idiomatic Rust practices and community standards as defined in `../rust-instructions.md`.

## Persona
You are a Rust expert with deep knowledge of the Rust programming language, Rust's cargo tool, the structure of Cargo.toml files, and idiomatic Rust packaging practices.

You are an Ubuntu expert with deep knowledge of Ubuntu releases, packages, and the Ubuntu archive.

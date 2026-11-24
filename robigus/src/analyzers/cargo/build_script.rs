//! Static `build.rs` scan (spec §8.1; WP-2.2).
//!
//! A regex scan cannot evaluate control flow, computed names or helper
//! modules, so every finding is tier L2 evidence ([`EvidenceMethod::BuildScript`]
//! for `cargo:` directives and `links`, [`EvidenceMethod::SourceScan`] for
//! build-helper calls; spec §5.3). Discovered native needs become unresolved
//! [`Edge`]s (`to = None`) for Phase 2 mapping.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use crate::model::{
    Confidence, DependencyKind, Edge, Evidence, EvidenceMethod, PackageId, Requirement,
    RequirementKind, SourceLocation,
};
use crate::predicate::Predicate;

/// Cap on findings emitted from one build script so a generated or hostile
/// file cannot flood the graph.
const MAX_FINDINGS: usize = 1_000;

/// Tier L2 confidence for explicit `cargo:` directives and `links` keys.
pub(super) const BUILD_SCRIPT_CONFIDENCE: Confidence = Confidence::new(50);

/// Tier L2 confidence for heuristic build-helper API matches in `build.rs`.
pub(super) const SOURCE_SCAN_CONFIDENCE: Confidence = Confidence::new(45);

/// One native requirement statically discovered in a `build.rs` file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct BuildScriptFinding {
    /// 1-based line number of the first occurrence in the file.
    pub line: u64,
    /// Kind of native requirement (`PkgConfig`, `Soname`, `Tool`, `Generic`).
    pub kind: RequirementKind,
    /// Module, library, or tool name.
    pub name: String,
    /// Evidence method (`BuildScript` for `cargo:` directives, `SourceScan`
    /// for API call patterns).
    pub method: EvidenceMethod,
    /// Dependency categories the requirement contributes to.
    pub dep_kinds: BTreeSet<DependencyKind>,
    /// Short explanation recorded in [`Evidence::detail`].
    pub detail: String,
}

struct Patterns {
    rustc_link_lib: Regex,
    pkg_config_fn: Regex,
    pkg_config_method: Regex,
    cc_build: Regex,
    cc_cpp_mode: Regex,
    cxx_build: Regex,
    bindgen_builder: Regex,
    cmake_call: Regex,
    meson_call: Regex,
    command_tool: Regex,
}

static PATTERNS: LazyLock<Patterns> = LazyLock::new(|| {
    let compile = |pattern: &str| Regex::new(pattern).expect("static regex is valid");
    Patterns {
        // Matches both `cargo:rustc-link-lib=[KIND[:MODIFIERS]=]NAME` and Cargo
        // 1.77+ `cargo::rustc-link-lib=…`. Rejects format placeholders (`{}` /
        // `{name}`) and requires a closing delimiter so an unknown `foo=bar`
        // kind is not partially matched as library `foo`.
        rustc_link_lib: compile(
            r#"cargo::?rustc-link-lib=(?:(static|dylib|framework|raw-dylib)(?::[^="'\s{}]*)?=)?([A-Za-z0-9_+.-]+)(?:["'\s\\]|$)"#,
        ),
        pkg_config_fn: compile(r#"\bpkg_config\s*::\s*probe_library\s*\(\s*"([A-Za-z0-9_+.-]+)""#),
        pkg_config_method: compile(r#"\.\s*probe\s*\(\s*"([A-Za-z0-9_+.-]+)""#),
        cc_build: compile(r"\bcc\s*::\s*Build\s*::\s*new\s*\("),
        cc_cpp_mode: compile(r"\.\s*cpp\s*\(\s*true\s*\)"),
        cxx_build: compile(r"\bcxx_build\s*::\s*bridges?\s*\("),
        bindgen_builder: compile(r"\bbindgen\s*::\s*(?:Builder\s*::\s*default|builder)\s*\("),
        cmake_call: compile(r"\bcmake\s*::\s*(?:Config\s*::\s*new|build)\s*\("),
        meson_call: compile(r"\bmeson(?:_next)?\s*::\s*build\s*\("),
        command_tool: compile(
            r#"\bCommand\s*::\s*new\s*\(\s*"(cmake|meson|ninja|pkg-config|bindgen)"\s*\)"#,
        ),
    }
});

/// Scans Rust `source` text from a `build.rs` file and returns deterministic,
/// deduplicated native requirements with 1-based line numbers.
///
/// Comments (`//` and nested `/* ... */`) are blanked out while preserving
/// newlines and string literals so commented-out code does not produce false
/// positives.
///
/// # Examples
///
/// ```
/// use robigus::RequirementKind;
/// use robigus::analyzers::scan_build_script;
///
/// let script = r#"
/// fn main() {
///     // println!("cargo:rustc-link-lib=ignored");
///     pkg_config::probe_library("zlib").unwrap();
///     cc::Build::new().file("native/shim.c").compile("shim");
///     println!("cargo::rustc-link-lib=z");
/// }
/// "#;
/// let findings = scan_build_script(script);
/// assert!(findings.iter().any(|f| f.kind == RequirementKind::PkgConfig && f.name == "zlib"));
/// assert!(findings.iter().any(|f| f.kind == RequirementKind::Tool && f.name == "cc"));
/// assert!(findings.iter().any(|f| f.kind == RequirementKind::Soname && f.name == "z"));
/// assert!(!findings.iter().any(|f| f.name == "ignored"));
/// ```
pub fn scan_build_script(source: &str) -> Vec<BuildScriptFinding> {
    let stripped = strip_rust_comments(source);
    let line_starts = line_offsets(&stripped);
    let line_at =
        |offset: usize| -> u64 { line_starts.partition_point(|&start| start <= offset) as u64 };

    // Keyed by `(kind, name, method)` so repeated mentions in one script
    // collapse to the earliest line while merging `dep_kinds`.
    let mut map: BTreeMap<(RequirementKind, String, EvidenceMethod), BuildScriptFinding> =
        BTreeMap::new();
    let mut record = |finding: BuildScriptFinding| {
        if map.len() >= MAX_FINDINGS
            && !map.contains_key(&(finding.kind, finding.name.clone(), finding.method))
        {
            return;
        }
        let key = (finding.kind, finding.name.clone(), finding.method);
        map.entry(key)
            .and_modify(|existing| {
                if finding.line < existing.line {
                    existing.line = finding.line;
                    existing.detail = finding.detail.clone();
                }
                existing.dep_kinds.extend(finding.dep_kinds.iter().copied());
            })
            .or_insert(finding);
    };

    let patterns = &*PATTERNS;

    for captures in patterns.rustc_link_lib.captures_iter(&stripped) {
        let Some(whole) = captures.get(0) else {
            continue;
        };
        let modifier = captures.get(1).map(|m| m.as_str());
        // macOS frameworks and Windows raw-dylibs are never active on Linux (§1.2, §4.4).
        if matches!(modifier, Some("framework" | "raw-dylib")) {
            continue;
        }
        let Some(name_match) = captures.get(2) else {
            continue;
        };
        let name = name_match.as_str();
        let (kind, dep_kinds, label) = match modifier {
            Some("static") => (
                RequirementKind::Generic,
                BTreeSet::from([DependencyKind::Build, DependencyKind::Normal]),
                "static library",
            ),
            _ => (
                RequirementKind::Soname,
                BTreeSet::from([DependencyKind::Normal]),
                "shared library",
            ),
        };
        record(BuildScriptFinding {
            line: line_at(whole.start()),
            kind,
            name: name.to_string(),
            method: EvidenceMethod::BuildScript,
            dep_kinds,
            detail: format!("cargo:rustc-link-lib directive ({label} '{name}')"),
        });
    }

    for captures in patterns.pkg_config_fn.captures_iter(&stripped) {
        if let (Some(whole), Some(module)) = (captures.get(0), captures.get(1)) {
            let name = module.as_str();
            record(BuildScriptFinding {
                line: line_at(whole.start()),
                kind: RequirementKind::PkgConfig,
                name: name.to_string(),
                method: EvidenceMethod::SourceScan,
                dep_kinds: BTreeSet::from([DependencyKind::Build, DependencyKind::Normal]),
                detail: format!("pkg_config::probe_library(\"{name}\") in build.rs"),
            });
        }
    }

    // `.probe("...")` is anchored to files that reference `pkg_config` so an
    // unrelated `.probe("...")` method in another domain does not misfire.
    if stripped.contains("pkg_config") {
        for captures in patterns.pkg_config_method.captures_iter(&stripped) {
            if let (Some(whole), Some(module)) = (captures.get(0), captures.get(1)) {
                let name = module.as_str();
                record(BuildScriptFinding {
                    line: line_at(whole.start()),
                    kind: RequirementKind::PkgConfig,
                    name: name.to_string(),
                    method: EvidenceMethod::SourceScan,
                    dep_kinds: BTreeSet::from([DependencyKind::Build, DependencyKind::Normal]),
                    detail: format!("pkg_config Config::probe(\"{name}\") in build.rs"),
                });
            }
        }
    }

    let uses_cpp = patterns.cc_cpp_mode.is_match(&stripped);
    if let Some(found) = patterns.cc_build.find(&stripped) {
        let compiler = if uses_cpp { "c++" } else { "cc" };
        record(BuildScriptFinding {
            line: line_at(found.start()),
            kind: RequirementKind::Tool,
            name: compiler.to_string(),
            method: EvidenceMethod::SourceScan,
            dep_kinds: BTreeSet::from([DependencyKind::Build]),
            detail: format!("cc::Build::new() ({compiler}) in build.rs"),
        });
    }

    if let Some(found) = patterns.cxx_build.find(&stripped) {
        record(BuildScriptFinding {
            line: line_at(found.start()),
            kind: RequirementKind::Tool,
            name: "c++".to_string(),
            method: EvidenceMethod::SourceScan,
            dep_kinds: BTreeSet::from([DependencyKind::Build]),
            detail: "cxx_build bridge compilation in build.rs".to_string(),
        });
    }

    if let Some(found) = patterns.bindgen_builder.find(&stripped) {
        record(BuildScriptFinding {
            line: line_at(found.start()),
            kind: RequirementKind::Tool,
            name: "libclang".to_string(),
            method: EvidenceMethod::SourceScan,
            dep_kinds: BTreeSet::from([DependencyKind::Build]),
            detail: "bindgen builder in build.rs (requires libclang)".to_string(),
        });
    }

    if let Some(found) = patterns.cmake_call.find(&stripped) {
        record(BuildScriptFinding {
            line: line_at(found.start()),
            kind: RequirementKind::Tool,
            name: "cmake".to_string(),
            method: EvidenceMethod::SourceScan,
            dep_kinds: BTreeSet::from([DependencyKind::Build]),
            detail: "cmake crate invocation in build.rs".to_string(),
        });
    }

    if let Some(found) = patterns.meson_call.find(&stripped) {
        record(BuildScriptFinding {
            line: line_at(found.start()),
            kind: RequirementKind::Tool,
            name: "meson".to_string(),
            method: EvidenceMethod::SourceScan,
            dep_kinds: BTreeSet::from([DependencyKind::Build]),
            detail: "meson crate invocation in build.rs".to_string(),
        });
    }

    for captures in patterns.command_tool.captures_iter(&stripped) {
        if let (Some(whole), Some(tool)) = (captures.get(0), captures.get(1)) {
            let name = tool.as_str();
            record(BuildScriptFinding {
                line: line_at(whole.start()),
                kind: RequirementKind::Tool,
                name: name.to_string(),
                method: EvidenceMethod::SourceScan,
                dep_kinds: BTreeSet::from([DependencyKind::Build]),
                detail: format!("Command::new(\"{name}\") in build.rs"),
            });
        }
    }

    let mut findings: Vec<BuildScriptFinding> = map.into_values().collect();
    findings.sort();
    findings
}

/// Converts [`scan_build_script`] findings into unresolved [`Edge`]s anchored
/// at `relative_script_path` (workspace-relative).
pub(super) fn findings_to_edges(
    from: &PackageId,
    relative_script_path: &Path,
    findings: &[BuildScriptFinding],
) -> Vec<Edge> {
    findings
        .iter()
        .map(|finding| {
            let confidence = match finding.method {
                EvidenceMethod::BuildScript => BUILD_SCRIPT_CONFIDENCE,
                _ => SOURCE_SCAN_CONFIDENCE,
            };
            Edge {
                from: from.clone(),
                to: None,
                requirement: Requirement {
                    kind: finding.kind,
                    name: finding.name.clone(),
                    version_req: None,
                },
                kinds: finding.dep_kinds.clone(),
                predicate: Predicate::TRUE,
                confidence,
                evidence: vec![Evidence {
                    method: finding.method,
                    confidence,
                    location: Some(SourceLocation {
                        path: relative_script_path.to_path_buf(),
                        start_line: Some(finding.line),
                        end_line: Some(finding.line),
                    }),
                    detail: Some(finding.detail.clone()),
                }],
            }
        })
        .collect()
}

/// Creates the tier-L2 unresolved native-library edge for a `Cargo.toml`
/// `package.links` declaration (spec §8.1).
pub(super) fn links_edge(
    from: &PackageId,
    links: &str,
    manifest_rel_path: &Path,
    line: Option<u64>,
) -> Edge {
    Edge {
        from: from.clone(),
        to: None,
        requirement: Requirement {
            kind: RequirementKind::Generic,
            name: links.to_string(),
            version_req: None,
        },
        kinds: BTreeSet::from([DependencyKind::Build, DependencyKind::Normal]),
        predicate: Predicate::TRUE,
        confidence: BUILD_SCRIPT_CONFIDENCE,
        evidence: vec![Evidence {
            method: EvidenceMethod::BuildScript,
            confidence: BUILD_SCRIPT_CONFIDENCE,
            location: Some(SourceLocation {
                path: manifest_rel_path.to_path_buf(),
                start_line: line,
                end_line: line,
            }),
            detail: Some(format!("Cargo.toml package.links = \"{links}\"")),
        }],
    }
}

fn line_offsets(text: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (idx, byte) in text.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(idx + 1);
        }
    }
    starts
}

/// Replaces `//` and nested `/* ... */` comments with spaces while keeping
/// newlines and string/raw-string literals intact so line numbers stay exact.
fn strip_rust_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // Raw string literal: `r###"..."###` or `br###"..."###`.
        if let Some((prefix_len, hashes)) = raw_string_open(&bytes[i..]) {
            out.extend_from_slice(&bytes[i..i + prefix_len]);
            i += prefix_len;
            while i < bytes.len() {
                let b = bytes[i];
                out.push(b);
                i += 1;
                if b == b'"' && bytes[i..].starts_with(&vec![b'#'; hashes]) {
                    out.extend_from_slice(&bytes[i..i + hashes]);
                    i += hashes;
                    break;
                }
            }
            continue;
        }
        // Ordinary string literal `"..."`.
        if bytes[i] == b'"' {
            out.push(b'"');
            i += 1;
            while i < bytes.len() {
                let b = bytes[i];
                out.push(b);
                i += 1;
                if b == b'\\' && i < bytes.len() {
                    out.push(bytes[i]);
                    i += 1;
                } else if b == b'"' {
                    break;
                }
            }
            continue;
        }
        // Character literal `'x'` / `'\''` so `'"'` does not start a string
        // (lifetimes like `'a` are not followed by a closing `'`).
        if bytes[i] == b'\''
            && let Some(len) = char_literal_len(&bytes[i..])
        {
            out.extend_from_slice(&bytes[i..i + len]);
            i += len;
            continue;
        }
        // Line comment `//...`.
        if bytes[i..].starts_with(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        // Nested block comment `/* ... */`.
        if bytes[i..].starts_with(b"/*") {
            let mut depth = 1usize;
            out.extend_from_slice(b"  ");
            i += 2;
            while i < bytes.len() && depth > 0 {
                if bytes[i..].starts_with(b"/*") {
                    depth += 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    depth -= 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                } else {
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
            }
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    // Every replacement wrote ASCII spaces over comment bytes while copying
    // multi-byte UTF-8 sequences inside strings and identifiers verbatim.
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

fn raw_string_open(slice: &[u8]) -> Option<(usize, usize)> {
    let mut pos = match slice {
        [b'b', b'r', ..] | [b'c', b'r', ..] => 2,
        [b'r', ..] => 1,
        _ => return None,
    };
    let mut hashes = 0;
    while slice.get(pos) == Some(&b'#') {
        hashes += 1;
        pos += 1;
    }
    (slice.get(pos) == Some(&b'"')).then_some((pos + 1, hashes))
}

fn char_literal_len(slice: &[u8]) -> Option<usize> {
    match slice {
        [b'\'', b'\\', _, b'\'', ..] => Some(4),
        [b'\'', b, b'\'', ..] if *b != b'\'' && *b != b'\n' => Some(3),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ConfidenceTier;

    #[test]
    fn discovers_directives_helpers_and_ignores_comments() {
        let script = r#"
// pkg_config::probe_library("commented");
/*
    println!("cargo:rustc-link-lib=also_commented");
    /* nested println!("cargo:rustc-link-lib=nested_commented"); */
*/
fn main() {
    pkg_config::Config::new().atleast_version("1.2").probe("libssl").unwrap();
    pkg_config::probe_library("zlib").unwrap();
    cc::Build::new().cpp(true).file("shim.cc").compile("shim");
    bindgen::Builder::default().header("wrapper.h").generate().unwrap();
    cmake::Config::new("vendor/foo").build();
    meson::build("vendor/bar", "build");
    std::process::Command::new("ninja").status().unwrap();
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo::rustc-link-lib=static=bundled");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
    println!("cargo:rustc-link-lib={}", dynamic_var);
}
"#;
        let findings = scan_build_script(script);
        let summary: Vec<(RequirementKind, &str, u64)> = findings
            .iter()
            .map(|f| (f.kind, f.name.as_str(), f.line))
            .collect();
        // `BuildScriptFinding` sorts by `line` first, so findings follow source order.
        assert_eq!(
            summary,
            vec![
                (RequirementKind::PkgConfig, "libssl", 8),
                (RequirementKind::PkgConfig, "zlib", 9),
                (RequirementKind::Tool, "c++", 10),
                (RequirementKind::Tool, "libclang", 11),
                (RequirementKind::Tool, "cmake", 12),
                (RequirementKind::Tool, "meson", 13),
                (RequirementKind::Tool, "ninja", 14),
                (RequirementKind::Soname, "crypto", 15),
                (RequirementKind::Generic, "bundled", 16),
            ]
        );
        assert_eq!(BUILD_SCRIPT_CONFIDENCE.tier(), ConfidenceTier::L2);
        assert_eq!(SOURCE_SCAN_CONFIDENCE.tier(), ConfidenceTier::L2);
    }

    #[test]
    fn string_literals_with_comment_markers_do_not_hide_later_code() {
        let script = r##"
fn main() {
    let _url = "https://example.invalid/*not-a-comment";
    let _raw = r#"still // not /* a comment"#;
    let _ch = '"';
    cxx_build::bridge("src/lib.rs").compile("demo");
}
"##;
        let findings = scan_build_script(script);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].name, "c++");
        assert_eq!(findings[0].line, 6);
    }
}

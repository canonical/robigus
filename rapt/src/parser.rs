//! Parser for Debian 822 control format, Packages, and Sources index files.

use crate::error::{RaptError, Result};
use crate::models::{
    BinaryPackage, DependencyClause, DependencyGroup, DependencyItem, DependencyType,
    PackageOrigin, ProvideItem, SourcePackage,
};

/// Parses a dependency line such as `libc6 (>= 2.38), debhelper-compat (= 13) | debhelper (>= 12)`.
pub fn parse_dependency_line(dep_type: DependencyType, input: &str) -> DependencyGroup {
    let mut clauses = Vec::new();

    // Clauses separated by comma
    for raw_clause in input.split(',') {
        let trimmed_clause = raw_clause.trim();
        if trimmed_clause.is_empty() {
            continue;
        }

        // Alternatives separated by '|'
        let mut alternatives = Vec::new();
        for raw_alt in trimmed_clause.split('|') {
            let alt = raw_alt.trim();
            if alt.is_empty() {
                continue;
            }

            // e.g. "libc6 (>= 2.38) [!arm64] <stage1>"
            // Split by whitespace or parentheses
            alternatives.push(parse_dependency_item(alt));
        }

        if !alternatives.is_empty() {
            clauses.push(DependencyClause::new(alternatives));
        }
    }

    DependencyGroup::new(dep_type, clauses)
}

/// Parses a single dependency alternative item, e.g. `libc6 (>= 2.38)` or `debconf [!armhf]`.
fn parse_dependency_item(input: &str) -> DependencyItem {
    let parts = input.trim();

    // Architecture filter e.g. `[i386 amd64]`
    if let Some(start_bracket) = parts.find('[')
        && let Some(end_bracket) = parts[start_bracket..].find(']')
    {
        let arch_slice = &parts[start_bracket + 1..start_bracket + end_bracket];
        let architecture = Some(arch_slice.trim().to_string());
        // Cut bracket portion out of parts
        let before = &parts[..start_bracket];
        let after = &parts[start_bracket + end_bracket + 1..];
        let recombined = format!("{before} {after}");
        return parse_dependency_item_no_arch(recombined.trim(), architecture);
    }

    parse_dependency_item_no_arch(parts, None)
}

fn parse_dependency_item_no_arch(input: &str, architecture: Option<String>) -> DependencyItem {
    let input = input.trim();
    if let Some(open_paren) = input.find('(') {
        let name = input[..open_paren].trim();
        let rest = &input[open_paren + 1..];
        let ver_str = rest.trim_end_matches(')').trim();

        let mut parts = ver_str.split_whitespace();
        let operator = parts.next().map(str::to_string);
        let version = parts.next().map(str::to_string);

        DependencyItem::new(name, operator, version, architecture)
    } else {
        // No version constraint
        DependencyItem::new(input, None::<String>, None::<String>, architecture)
    }
}

/// Parses a `Provides` field into `ProvideItem`s.
/// E.g. `debconf-2.0, mail-transport-agent (= 1.0)`.
pub fn parse_provides_line(input: &str) -> Vec<ProvideItem> {
    let mut items = Vec::new();
    for raw in input.split(',') {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(open_paren) = trimmed.find('(') {
            let name = trimmed[..open_paren].trim();
            let rest = &trimmed[open_paren + 1..];
            let ver_str = rest.trim_end_matches(')').trim();
            let mut parts = ver_str.split_whitespace();
            // Could be "= 1.0" or "1.0"
            let first = parts.next();
            let second = parts.next();
            let version = if second.is_some() { second } else { first };
            items.push(ProvideItem::new(name, version));
        } else {
            items.push(ProvideItem::new(trimmed, None::<String>));
        }
    }
    items
}

/// Parses Debian RFC822 paragraphs from raw uncompressed string.
/// Each paragraph is separated by empty lines.
pub fn parse_rfc822_paragraphs(input: &str) -> Vec<Vec<(String, String)>> {
    let mut paragraphs = Vec::new();
    let mut current_fields = Vec::new();
    let mut current_key: Option<String> = None;
    let mut current_val = String::new();

    for line in input.lines() {
        if line.trim().is_empty() {
            if let Some(key) = current_key.take() {
                current_fields.push((key, std::mem::take(&mut current_val)));
            }
            if !current_fields.is_empty() {
                paragraphs.push(std::mem::take(&mut current_fields));
            }
            continue;
        }

        if line.starts_with(' ') || line.starts_with('\t') {
            // Folded or continuation line
            if current_key.is_some() {
                current_val.push('\n');
                current_val.push_str(line);
            }
        } else if let Some((key, val)) = line.split_once(':') {
            if let Some(prev_key) = current_key.take() {
                current_fields.push((prev_key, std::mem::take(&mut current_val)));
            }
            current_key = Some(key.trim().to_string());
            current_val = val.trim_start().to_string();
        }
    }

    if let Some(key) = current_key.take() {
        current_fields.push((key, current_val));
    }
    if !current_fields.is_empty() {
        paragraphs.push(current_fields);
    }

    paragraphs
}

/// Parses a `Packages` index paragraph into a `BinaryPackage`.
pub fn parse_binary_package(
    fields: Vec<(String, String)>,
    origin: PackageOrigin,
) -> Result<BinaryPackage> {
    let mut package = None;
    let mut version = None;
    let mut architecture = None;
    let mut maintainer = None;
    let mut installed_size = None;
    let mut section = None;
    let mut priority = None;
    let mut homepage = None;
    let mut description = None;
    let mut description_md5 = None;
    let mut filename = None;
    let mut size = None;
    let mut md5sum = None;
    let mut sha1 = None;
    let mut sha256 = None;
    let mut sha512 = None;
    let mut source = None;
    let mut depends = Vec::new();
    let mut provides = Vec::new();

    for (key, val) in &fields {
        match key.to_ascii_lowercase().as_str() {
            "package" => package = Some(val.trim().to_string()),
            "version" => version = Some(val.trim().to_string()),
            "architecture" => architecture = Some(val.trim().to_string()),
            "maintainer" => maintainer = Some(val.trim().to_string()),
            "installed-size" => installed_size = Some(val.trim().to_string()),
            "section" => section = Some(val.trim().to_string()),
            "priority" => priority = Some(val.trim().to_string()),
            "homepage" => homepage = Some(val.trim().to_string()),
            "description" => description = Some(val.clone()),
            "description-md5" => description_md5 = Some(val.trim().to_string()),
            "filename" => filename = Some(val.trim().to_string()),
            "size" => size = val.trim().parse::<u64>().ok(),
            "md5sum" => md5sum = Some(val.trim().to_string()),
            "sha1" => sha1 = Some(val.trim().to_string()),
            "sha256" => sha256 = Some(val.trim().to_string()),
            "sha512" => sha512 = Some(val.trim().to_string()),
            "source" => source = Some(val.trim().to_string()),
            "depends" => depends.push(parse_dependency_line(DependencyType::Depends, val)),
            "pre-depends" => depends.push(parse_dependency_line(DependencyType::PreDepends, val)),
            "recommends" => depends.push(parse_dependency_line(DependencyType::Recommends, val)),
            "suggests" => depends.push(parse_dependency_line(DependencyType::Suggests, val)),
            "conflicts" => depends.push(parse_dependency_line(DependencyType::Conflicts, val)),
            "breaks" => depends.push(parse_dependency_line(DependencyType::Breaks, val)),
            "replaces" => depends.push(parse_dependency_line(DependencyType::Replaces, val)),
            "enhances" => depends.push(parse_dependency_line(DependencyType::Enhances, val)),
            "provides" => provides.extend(parse_provides_line(val)),
            _ => {}
        }
    }

    let package = package.ok_or_else(|| {
        RaptError::Other("missing 'Package' field in Packages record".to_string())
    })?;
    let version = version.unwrap_or_else(|| "unknown".to_string());
    let architecture = architecture.unwrap_or_else(|| "all".to_string());

    Ok(BinaryPackage::new(
        package,
        version,
        architecture,
        maintainer,
        installed_size,
        depends,
        provides,
        section,
        priority,
        homepage,
        description,
        description_md5,
        filename,
        size,
        md5sum,
        sha1,
        sha256,
        sha512,
        source,
        origin,
        fields,
    ))
}

/// Parses a `Sources` index paragraph into a `SourcePackage`.
pub fn parse_source_package(fields: Vec<(String, String)>) -> Result<SourcePackage> {
    let mut package = None;
    let mut version = None;
    let mut binary = Vec::new();
    let mut maintainer = None;
    let mut directory = None;

    for (key, val) in &fields {
        match key.to_ascii_lowercase().as_str() {
            "package" => package = Some(val.trim().to_string()),
            "version" => version = Some(val.trim().to_string()),
            "maintainer" => maintainer = Some(val.trim().to_string()),
            "directory" => directory = Some(val.trim().to_string()),
            "binary" => {
                for b in val.split(',') {
                    let b = b.trim();
                    if !b.is_empty() {
                        binary.push(b.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    let package = package
        .ok_or_else(|| RaptError::Other("missing 'Package' field in Sources record".to_string()))?;
    let version = version.unwrap_or_else(|| "unknown".to_string());

    Ok(SourcePackage::new(
        package, version, binary, maintainer, directory, fields,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Architecture, Component, Pocket};

    #[test]
    fn test_parse_dependencies() {
        let line = "libc6 (>= 2.38), debhelper-compat (= 13) | debhelper (>= 12)";
        let group = parse_dependency_line(DependencyType::Depends, line);
        assert_eq!(group.dep_type(), DependencyType::Depends);
        assert_eq!(group.clauses().len(), 2);

        let first = &group.clauses()[0];
        assert_eq!(first.alternatives().len(), 1);
        assert_eq!(first.alternatives()[0].name(), "libc6");
        assert_eq!(first.alternatives()[0].operator(), Some(">="));
        assert_eq!(first.alternatives()[0].version(), Some("2.38"));

        let second = &group.clauses()[1];
        assert_eq!(second.alternatives().len(), 2);
        assert_eq!(second.alternatives()[0].name(), "debhelper-compat");
        assert_eq!(second.alternatives()[0].operator(), Some("="));
        assert_eq!(second.alternatives()[0].version(), Some("13"));
        assert_eq!(second.alternatives()[1].name(), "debhelper");
        assert_eq!(second.alternatives()[1].operator(), Some(">="));
        assert_eq!(second.alternatives()[1].version(), Some("12"));
    }

    #[test]
    fn test_parse_provides() {
        let line = "mail-transport-agent, debconf-2.0 (= 1.0)";
        let items = parse_provides_line(line);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name(), "mail-transport-agent");
        assert_eq!(items[0].version(), None);
        assert_eq!(items[1].name(), "debconf-2.0");
        assert_eq!(items[1].version(), Some("1.0"));
    }

    #[test]
    fn test_parse_binary_package() {
        let text = "Package: hello\nVersion: 2.10-5\nArchitecture: amd64\nDepends: libc6 (>= 2.38)\nDescription: GNU hello\n An example package\n";
        let paragraphs = parse_rfc822_paragraphs(text);
        assert_eq!(paragraphs.len(), 1);

        let origin = PackageOrigin::new(
            Pocket::Release,
            Component::Main,
            Architecture::Amd64,
            "http://archive.ubuntu.com/ubuntu",
            "resolute",
        );
        let pkg = parse_binary_package(paragraphs[0].clone(), origin).unwrap();
        assert_eq!(pkg.package(), "hello");
        assert_eq!(pkg.version(), "2.10-5");
        assert_eq!(pkg.short_description(), Some("GNU hello"));
        assert_eq!(pkg.depends().len(), 1);
    }
}

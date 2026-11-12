//! Rendering for the database integrity report.

use std::fmt::Write;

use robigus::{PackageId, store::IntegrityReport};
use serde::Serialize;

#[derive(Serialize)]
struct JsonReport<'a> {
    is_ok: bool,
    #[serde(flatten)]
    report: &'a IntegrityReport,
}

fn package_label(id: &PackageId) -> String {
    format!(
        "{id} [source={:?}, precise={:?}]",
        id.source_id.kind,
        id.source_id.effective_precise()
    )
}

/// Render every integrity finding as text or a structured JSON document.
///
/// `is_ok` reflects only integrity failures; cycles, orphans, and unresolved
/// requirements are informational. Returns an error if JSON serialization
/// fails.
pub fn render(report: &IntegrityReport, json: bool) -> Result<String, serde_json::Error> {
    // Store queries and SCC traversal need not return findings in a stable order.
    let mut report = report.clone();
    report.status_violations.sort();
    report.confidence_violations.sort();
    report.orphans.sort();
    for cycle in &mut report.cycles {
        cycle.sort();
    }
    report.cycles.sort();

    if json {
        return serde_json::to_string_pretty(&JsonReport {
            is_ok: report.is_ok(),
            report: &report,
        });
    }

    let mut output = String::new();
    let _ = writeln!(
        output,
        "Integrity: {} (cycles, orphans, and unresolved requirements are informational)",
        if report.is_ok() { "OK" } else { "FAILED" }
    );
    let _ = writeln!(output, "Schema version: {}", report.schema_version);
    let _ = writeln!(
        output,
        "Foreign keys: {}",
        if report.foreign_keys_ok {
            "OK"
        } else {
            "FAILED"
        }
    );
    let _ = writeln!(
        output,
        "Duplicate identities: {}",
        report.duplicate_identities
    );
    let _ = writeln!(
        output,
        "Invalid JSON columns: {}",
        report.invalid_json_columns
    );
    let _ = writeln!(output, "Corrupt identities: {}", report.corrupt_identities);

    let _ = writeln!(
        output,
        "Status violations ({}):",
        report.status_violations.len()
    );
    for id in &report.status_violations {
        let _ = writeln!(output, "  - {}", package_label(id));
    }
    let _ = writeln!(
        output,
        "Confidence violations ({}):",
        report.confidence_violations.len()
    );
    for violation in &report.confidence_violations {
        let _ = writeln!(output, "  - {violation}");
    }

    let _ = writeln!(output, "Unresolved requirements by kind (informational):");
    if report.unresolved_requirements.is_empty() {
        let _ = writeln!(output, "  (none)");
    }
    for (kind, count) in &report.unresolved_requirements {
        let _ = writeln!(output, "  {}: {count}", kind.as_str());
    }
    let _ = writeln!(
        output,
        "Cycles (informational; {} components):",
        report.cycles.len()
    );
    for (index, cycle) in report.cycles.iter().enumerate() {
        let _ = writeln!(output, "  Component {}:", index + 1);
        for id in cycle {
            let _ = writeln!(output, "    - {}", package_label(id));
        }
    }
    let _ = writeln!(output, "Orphans (informational; {}):", report.orphans.len());
    for id in &report.orphans {
        let _ = writeln!(output, "  - {}", package_label(id));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use robigus::{
        RequirementKind,
        model::{Ecosystem, PackageVersion, SourceId, SourceKind},
    };

    fn package(name: &str) -> PackageId {
        PackageId {
            name: name.into(),
            version: PackageVersion::Opaque("1".into()),
            ecosystem: Ecosystem::Generic,
            source_id: SourceId {
                kind: SourceKind::Path { path: name.into() },
                precise: None,
            },
        }
    }

    #[test]
    fn informational_findings_do_not_fail_check() {
        let report = IntegrityReport {
            schema_version: 1,
            foreign_keys_ok: true,
            unresolved_requirements: [(RequirementKind::Tool, 2)].into_iter().collect(),
            cycles: vec![vec![package("b"), package("a")]],
            orphans: vec![package("orphan")],
            ..IntegrityReport::default()
        };
        let json: serde_json::Value =
            serde_json::from_str(&render(&report, true).unwrap()).unwrap();
        assert_eq!(json["is_ok"], true);
        assert_eq!(json["unresolved_requirements"]["tool"], 2);
        assert_eq!(json["cycles"][0][0]["name"], "a");
        assert_eq!(json["orphans"][0]["name"], "orphan");
        let text = render(&report, false).unwrap();
        assert!(text.contains("Integrity: OK"));
        assert!(text.contains("tool: 2"));
        assert!(text.contains("Cycles (informational; 1 components)"));
        assert!(text.contains("orphan"));
    }

    #[test]
    fn all_failure_fields_are_reported() {
        let report = IntegrityReport {
            schema_version: 2,
            foreign_keys_ok: false,
            duplicate_identities: 3,
            invalid_json_columns: 4,
            corrupt_identities: 5,
            status_violations: vec![package("bad-status")],
            confidence_violations: vec!["bad confidence".into()],
            ..IntegrityReport::default()
        };
        let json: serde_json::Value =
            serde_json::from_str(&render(&report, true).unwrap()).unwrap();
        assert_eq!(json["is_ok"], false);
        assert_eq!(json["foreign_keys_ok"], false);
        assert_eq!(json["duplicate_identities"], 3);
        assert_eq!(json["invalid_json_columns"], 4);
        assert_eq!(json["corrupt_identities"], 5);
        assert_eq!(json["status_violations"][0]["name"], "bad-status");
        assert_eq!(json["confidence_violations"][0], "bad confidence");
        let text = render(&report, false).unwrap();
        for finding in [
            "Integrity: FAILED",
            "Schema version: 2",
            "Foreign keys: FAILED",
            "Duplicate identities: 3",
            "Invalid JSON columns: 4",
            "Corrupt identities: 5",
            "bad-status",
            "bad confidence",
        ] {
            assert!(text.contains(finding), "missing {finding}");
        }
    }
}

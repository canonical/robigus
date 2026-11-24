//! Cargo `cfg(...)` target platforms and `[features]` expressions mapped to
//! [`Predicate`]s (spec §4.1, §8.1).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use cargo_metadata::cargo_platform::{Cfg, CfgExpr, Platform};

use crate::feature::{FeatureExpr, FeatureExprError};
use crate::predicate::Predicate;

/// Maximum `cfg(...)` AST nesting accepted before rejecting the expression,
/// staying comfortably below [`crate::store`]'s JSON recursion preflight cap.
const MAX_CFG_DEPTH: usize = 48;

/// Parses a `[target.<spec>.*]` key and maps it to a [`Predicate`].
pub(super) fn target_spec_to_predicate(spec: &str) -> Result<Predicate, String> {
    let platform: Platform = spec
        .parse()
        .map_err(|error| format!("invalid Cargo target '{spec}': {error}"))?;
    platform_to_predicate(&platform)
}

/// Maps a parsed [`cargo_metadata::cargo_platform::Platform`] to a
/// [`Predicate`] verbatim (spec §4.1).
///
/// Named targets (`x86_64-unknown-linux-gnu`) become `cfg("target" = "<triple>")`,
/// matching [`crate::Configuration::for_arch`]. Bare `target_family` shorthands
/// (`unix`, `windows`, `wasm`) become `cfg("target_family" = "<family>")`.
pub(super) fn platform_to_predicate(platform: &Platform) -> Result<Predicate, String> {
    match platform {
        Platform::Name(triple) => Ok(Predicate::cfg("target", triple.clone())),
        Platform::Cfg(expr) => cfg_expr_to_predicate(expr, 0),
    }
}

fn cfg_expr_to_predicate(expr: &CfgExpr, depth: usize) -> Result<Predicate, String> {
    if depth > MAX_CFG_DEPTH {
        return Err(format!(
            "cfg(...) expression exceeds maximum nesting depth of {MAX_CFG_DEPTH}"
        ));
    }
    match expr {
        CfgExpr::True => Ok(Predicate::TRUE),
        CfgExpr::False => Ok(Predicate::FALSE),
        CfgExpr::Not(inner) => Ok(Predicate::Not(Box::new(cfg_expr_to_predicate(
            inner,
            depth + 1,
        )?))),
        CfgExpr::All(items) => {
            let mut operands = Vec::with_capacity(items.len());
            for item in items {
                operands.push(cfg_expr_to_predicate(item, depth + 1)?);
            }
            Ok(Predicate::and(operands).canonicalized())
        }
        CfgExpr::Any(items) => {
            let mut operands = Vec::with_capacity(items.len());
            for item in items {
                operands.push(cfg_expr_to_predicate(item, depth + 1)?);
            }
            Ok(Predicate::or(operands).canonicalized())
        }
        CfgExpr::Value(Cfg::KeyPair(key, value)) => Ok(Predicate::cfg(key.as_str(), value.clone())),
        CfgExpr::Value(Cfg::Name(ident)) => {
            let name = ident.as_str();
            if matches!(name, "unix" | "windows" | "wasm") {
                Ok(Predicate::cfg("target_family", name))
            } else {
                Ok(Predicate::cfg(name, ""))
            }
        }
    }
}

/// Parsed `[features]` table for one Cargo package, using [`FeatureExpr`].
#[derive(Debug, Clone, Default)]
pub(super) struct PackageFeatures {
    /// Feature name → parsed activation expressions.
    parsed: BTreeMap<String, Vec<FeatureExpr>>,
}

impl PackageFeatures {
    /// Parses `raw_features` with [`FeatureExpr::parse`] and synthesizes
    /// Cargo's implicit features (`foo = ["dep:foo"]`) for any optional
    /// dependency alias in `optional_dep_aliases` that is neither already a
    /// feature key nor referenced via `dep:<alias>` (Cargo 1.60+ rule).
    pub(super) fn from_raw(
        raw_features: &BTreeMap<String, Vec<String>>,
        optional_dep_aliases: &BTreeSet<String>,
    ) -> (Self, Vec<FeatureExprError>) {
        let mut parsed: BTreeMap<String, Vec<FeatureExpr>> = BTreeMap::new();
        let mut errors = Vec::new();
        let mut explicit_dep_refs = BTreeSet::new();

        for (feature_name, items) in raw_features {
            let mut exprs = Vec::with_capacity(items.len());
            for item in items {
                match FeatureExpr::parse(item) {
                    Ok(expr) => {
                        if let FeatureExpr::Dep(dep) = &expr {
                            explicit_dep_refs.insert(dep.clone());
                        }
                        exprs.push(expr);
                    }
                    Err(error) => errors.push(error),
                }
            }
            parsed.insert(feature_name.clone(), exprs);
        }

        for alias in optional_dep_aliases {
            if !explicit_dep_refs.contains(alias) && !parsed.contains_key(alias) {
                parsed.insert(alias.clone(), vec![FeatureExpr::Dep(alias.clone())]);
            }
        }

        (Self { parsed }, errors)
    }

    /// True when `feature` is a defined (explicit or implicit) feature on this
    /// package.
    pub(super) fn contains(&self, feature: &str) -> bool {
        self.parsed.contains_key(feature)
    }

    /// Disjunction of package features whose activation enables the optional
    /// dependency `dep_alias` (via `dep:<alias>` or non-weak `<alias>/<feat>`,
    /// closed under intra-package `Simple` feature forwarding).
    ///
    /// Weak expressions (`<alias>?` and `<alias>?/<feat>`) do **not** activate
    /// an optional dependency on their own.
    pub(super) fn activation_predicate(&self, dep_alias: &str) -> Predicate {
        let mut direct: BTreeSet<String> = BTreeSet::new();
        // `inner -> {outer features that include Simple(inner)}`.
        let mut reverse_simple: BTreeMap<&str, Vec<&str>> = BTreeMap::new();

        for (feature, exprs) in &self.parsed {
            for expr in exprs {
                match expr {
                    FeatureExpr::Dep(dep) if dep == dep_alias => {
                        direct.insert(feature.clone());
                    }
                    FeatureExpr::DepFeature {
                        dep, weak: false, ..
                    } if dep == dep_alias => {
                        direct.insert(feature.clone());
                    }
                    FeatureExpr::Simple(inner) => {
                        reverse_simple
                            .entry(inner.as_str())
                            .or_default()
                            .push(feature.as_str());
                    }
                    FeatureExpr::Optional(_)
                    | FeatureExpr::Dep(_)
                    | FeatureExpr::DepFeature { .. } => {}
                }
            }
        }

        let mut all_activating = direct.clone();
        let mut queue: VecDeque<String> = direct.into_iter().collect();
        while let Some(current) = queue.pop_front() {
            if let Some(parents) = reverse_simple.get(current.as_str()) {
                for &parent in parents {
                    if all_activating.insert(parent.to_string()) {
                        queue.push_back(parent.to_string());
                    }
                }
            }
        }

        if all_activating.is_empty() {
            Predicate::FALSE
        } else {
            Predicate::or(all_activating.into_iter().map(Predicate::feature).collect())
                .canonicalized()
        }
    }

    /// Cross-package feature expressions (`dep/feat` or `dep?/feat`) targeting
    /// `dep_alias`, formatted as `feature -> expr` for diagnostic/evidence
    /// detail.
    pub(super) fn forwarded_subfeatures(&self, dep_alias: &str) -> Vec<String> {
        let mut forwarded = Vec::new();
        for (feature, exprs) in &self.parsed {
            for expr in exprs {
                if let FeatureExpr::DepFeature { dep, .. } = expr
                    && dep == dep_alias
                {
                    forwarded.push(format!("{feature} -> {expr}"));
                }
            }
        }
        forwarded
    }
}

/// Conjoins an optional target-platform predicate with an optional-dependency
/// feature predicate, returning a canonicalized [`Predicate`].
pub(super) fn combine_predicates(
    platform: Option<Predicate>,
    optional_feature: Option<Predicate>,
) -> Predicate {
    match (platform, optional_feature) {
        (None, None) => Predicate::TRUE,
        (Some(pred), None) | (None, Some(pred)) => pred.canonicalized(),
        (Some(left), Some(right)) => Predicate::and(vec![left, right]).canonicalized(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MachineArch;
    use crate::predicate::{Configuration, Evaluator};
    use ubuntu_info_rust::Architecture;

    #[test]
    fn maps_cfg_expressions_and_named_triples_verbatim() {
        let unix = target_spec_to_predicate("cfg(unix)").unwrap();
        assert_eq!(unix.canonical_text(), r#"cfg("target_family" = "unix")"#);

        let compound = target_spec_to_predicate(
            r#"cfg(all(any(target_os = "linux", target_family = "unix"), not(target_arch = "x86")))"#,
        )
        .unwrap();
        assert_eq!(
            compound.canonical_text(),
            r#"!cfg("target_arch" = "x86") && (cfg("target_family" = "unix") || cfg("target_os" = "linux"))"#
        );

        let amd64 = Evaluator::new(Configuration::for_arch(MachineArch::Ubuntu(
            Architecture::Amd64,
        )));
        let i386 = Evaluator::new(Configuration::for_arch(MachineArch::Ubuntu(
            Architecture::I386,
        )));
        assert!(amd64.evaluate(&compound, None));
        assert!(!i386.evaluate(&compound, None));

        let triple = target_spec_to_predicate("x86_64-unknown-linux-gnu").unwrap();
        assert_eq!(
            triple.canonical_text(),
            r#"cfg("target" = "x86_64-unknown-linux-gnu")"#
        );
        assert!(amd64.evaluate(&triple, None));
        assert!(!i386.evaluate(&triple, None));
    }

    #[test]
    fn rejects_excessively_nested_cfg() {
        let open = "all(".repeat(MAX_CFG_DEPTH + 5);
        let close = ")".repeat(MAX_CFG_DEPTH + 5);
        let spec = format!("cfg({open}unix{close})");
        assert!(target_spec_to_predicate(&spec).is_err());
    }

    #[test]
    fn feature_predicates_distinguish_strong_weak_and_implicit_activations() {
        let raw = BTreeMap::from([
            ("default".into(), vec!["std".into()]),
            ("std".into(), vec!["dep:itoa".into(), "serde?/std".into()]),
            ("json".into(), vec!["serde/derive".into()]),
            ("full".into(), vec!["json".into(), "default".into()]),
        ]);
        let optional = BTreeSet::from(["itoa".into(), "serde".into(), "ryu".into()]);
        let (features, errors) = PackageFeatures::from_raw(&raw, &optional);
        assert!(errors.is_empty());

        // `dep:itoa` suppresses the implicit `itoa` feature; `std`, `default`,
        // and `full` transitively enable it.
        assert_eq!(
            features.activation_predicate("itoa").canonical_text(),
            r#"feature("default") || feature("full") || feature("std")"#
        );
        // `serde?/std` is weak and does NOT activate `serde`; `serde/derive`
        // (via `json` and `full`) plus the implicit `serde` feature do.
        assert_eq!(
            features.activation_predicate("serde").canonical_text(),
            r#"feature("full") || feature("json") || feature("serde")"#
        );
        // `ryu` has no `dep:ryu` reference, so Cargo's implicit `ryu` feature
        // activates it.
        assert_eq!(
            features.activation_predicate("ryu").canonical_text(),
            r#"feature("ryu")"#
        );
    }
}

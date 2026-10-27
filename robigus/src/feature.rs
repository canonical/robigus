//! Cargo feature-activation expressions (spec §5.4).
//!
//! Cargo's feature syntax is modeled explicitly rather than as raw strings:
//! `foo`, `foo?` (optional-dependency activation), `dep:foo`, and
//! `foo/bar` / `foo?/bar` (dependency features).

use std::fmt;

/// A failure to parse a feature expression.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid feature expression '{input}': {reason}")]
pub struct FeatureExprError {
    pub input: String,
    pub reason: String,
}

/// A Cargo feature-activation expression.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum FeatureExpr {
    /// `foo` — the package's own feature.
    Simple(String),
    /// `foo?` — activation of the optional dependency `foo`.
    Optional(String),
    /// `dep:foo` — explicit optional-dependency reference.
    Dep(String),
    /// `foo/bar` (`weak = false`) or `foo?/bar` (`weak = true`): enables
    /// `feature` on the dependency `dep`, weakly only when `dep` is itself
    /// enabled.
    DepFeature {
        dep: String,
        feature: String,
        weak: bool,
    },
}

impl FeatureExpr {
    /// Parses a Cargo feature expression.
    pub fn parse(input: &str) -> Result<Self, FeatureExprError> {
        let err = |reason: &str| FeatureExprError {
            input: input.to_string(),
            reason: reason.to_string(),
        };

        if input.is_empty() {
            return Err(err("empty expression"));
        }

        if let Some(rest) = input.strip_prefix("dep:") {
            if rest.is_empty() {
                return Err(err("missing dependency name after 'dep:'"));
            }
            if rest.contains('/') || rest.contains('?') {
                return Err(err("'dep:' names must not contain '/' or '?'"));
            }
            return Ok(Self::Dep(rest.to_string()));
        }

        if let Some((dep, feature)) = input.split_once('/') {
            if feature.is_empty() {
                return Err(err("missing feature name after '/'"));
            }
            if feature.contains('?') || feature.contains('/') {
                return Err(err("feature names must not contain '?' or '/'"));
            }
            let (dep, weak) = match dep.strip_suffix('?') {
                Some(dep) => (dep, true),
                None => (dep, false),
            };
            if dep.is_empty() {
                return Err(err("missing dependency name before '/'"));
            }
            if dep.contains('?') {
                return Err(err("'?' is only allowed directly before '/'"));
            }
            return Ok(Self::DepFeature {
                dep: dep.to_string(),
                feature: feature.to_string(),
                weak,
            });
        }

        if let Some(name) = input.strip_suffix('?') {
            if name.is_empty() {
                return Err(err("missing feature name before '?'"));
            }
            if name.contains('?') {
                return Err(err(
                    "'?' is only allowed as a suffix or directly before '/'",
                ));
            }
            return Ok(Self::Optional(name.to_string()));
        }

        if input.contains('?') {
            return Err(err(
                "'?' is only allowed as a suffix or directly before '/'",
            ));
        }

        Ok(Self::Simple(input.to_string()))
    }

    /// A plain feature activation.
    pub fn simple(name: impl Into<String>) -> Self {
        Self::Simple(name.into())
    }
}

impl fmt::Display for FeatureExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Simple(name) => write!(f, "{name}"),
            Self::Optional(name) => write!(f, "{name}?"),
            Self::Dep(name) => write!(f, "dep:{name}"),
            Self::DepFeature { dep, feature, weak } => {
                if *weak {
                    write!(f, "{dep}?/{feature}")
                } else {
                    write!(f, "{dep}/{feature}")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_displays_cargo_forms() {
        let cases = [
            ("serde", FeatureExpr::Simple("serde".into())),
            ("serde?", FeatureExpr::Optional("serde".into())),
            ("dep:serde", FeatureExpr::Dep("serde".into())),
            (
                "serde/derive",
                FeatureExpr::DepFeature {
                    dep: "serde".into(),
                    feature: "derive".into(),
                    weak: false,
                },
            ),
            (
                "serde?/derive",
                FeatureExpr::DepFeature {
                    dep: "serde".into(),
                    feature: "derive".into(),
                    weak: true,
                },
            ),
        ];
        for (text, expected) in cases {
            let parsed = FeatureExpr::parse(text).expect("must parse");
            assert_eq!(parsed, expected, "parsing {text}");
            assert_eq!(parsed.to_string(), text, "displaying {text:?}");
        }
    }

    #[test]
    fn rejects_invalid_expressions() {
        for bad in [
            "",
            "dep:",
            "/bar",
            "foo/",
            "foo//bar",
            "fo?o",
            "?",
            "dep:foo/bar",
            "foo??",
            "foo?/bar/baz",
        ] {
            assert!(
                FeatureExpr::parse(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }
}

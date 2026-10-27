//! Predicate AST (spec §4).
//!
//! This module currently provides the typed AST, its atom constructors, and
//! a precedence-aware `Display`. The parser, canonical serialization, and
//! per-`Configuration` evaluator land in WP-1.3.

use crate::model::MachineArch;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A Boolean activation condition over configuration atoms (spec §4.2).
///
/// The in-memory representation is this typed AST, never a string. Operands
/// of `And`/`Or` keep their discovery order; canonical (sorted, folded)
/// equality is a WP-1.3 concern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Predicate {
    And(Vec<Predicate>),
    Or(Vec<Predicate>),
    Not(Box<Predicate>),
    Atom(Atom),
}

/// The predicate atoms (spec §4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Atom {
    /// `feature("name")` (`package = None`) or `feature("pkg/name")`
    /// (`package = Some`).
    Feature {
        package: Option<String>,
        name: String,
    },
    /// `cfg("key" = "value")` — a Cargo `cfg` key/value pair, stored verbatim.
    Cfg {
        key: String,
        value: String,
    },
    /// `arch("amd64")` — `MachineArch` covers `all` and unsupported stubs.
    Arch(MachineArch),
    /// `platform("linux")`.
    Platform(String),
    /// `build-profile("nocheck")`.
    BuildProfile(String),
    /// `env("CC" = "clang")`.
    Env {
        name: String,
        value: String,
    },
    /// `series("noble")`.
    Series(String),
    True,
    False,
}

impl Predicate {
    /// The always-active predicate (an edge with no predicate).
    pub const TRUE: Self = Self::Atom(Atom::True);
    /// The never-active predicate.
    pub const FALSE: Self = Self::Atom(Atom::False);

    pub fn and(operands: Vec<Self>) -> Self {
        Self::And(operands)
    }

    pub fn or(operands: Vec<Self>) -> Self {
        Self::Or(operands)
    }

    /// `feature("name")` on the current package.
    pub fn feature(name: impl Into<String>) -> Self {
        Self::Atom(Atom::Feature {
            package: None,
            name: name.into(),
        })
    }

    /// `feature("pkg/name")` on another package.
    pub fn qualified_feature(package: impl Into<String>, name: impl Into<String>) -> Self {
        Self::Atom(Atom::Feature {
            package: Some(package.into()),
            name: name.into(),
        })
    }

    pub fn cfg(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Atom(Atom::Cfg {
            key: key.into(),
            value: value.into(),
        })
    }

    pub fn arch(arch: MachineArch) -> Self {
        Self::Atom(Atom::Arch(arch))
    }

    pub fn platform(name: impl Into<String>) -> Self {
        Self::Atom(Atom::Platform(name.into()))
    }

    pub fn build_profile(name: impl Into<String>) -> Self {
        Self::Atom(Atom::BuildProfile(name.into()))
    }

    pub fn env(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Atom(Atom::Env {
            name: name.into(),
            value: value.into(),
        })
    }

    pub fn series(name: impl Into<String>) -> Self {
        Self::Atom(Atom::Series(name.into()))
    }
}

impl std::ops::Not for Predicate {
    type Output = Self;

    fn not(self) -> Self {
        Self::Not(Box::new(self))
    }
}

impl fmt::Display for Predicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_predicate(self, Precedence::Top, f)
    }
}

impl fmt::Display for Atom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Feature {
                package: None,
                name,
            } => write!(f, "feature(\"{name}\")"),
            Self::Feature {
                package: Some(package),
                name,
            } => write!(f, "feature(\"{package}/{name}\")"),
            Self::Cfg { key, value } => write!(f, "cfg(\"{key}\" = \"{value}\")"),
            Self::Arch(arch) => write!(f, "arch(\"{arch}\")"),
            Self::Platform(name) => write!(f, "platform(\"{name}\")"),
            Self::BuildProfile(name) => write!(f, "build-profile(\"{name}\")"),
            Self::Env { name, value } => write!(f, "env(\"{name}\" = \"{value}\")"),
            Self::Series(name) => write!(f, "series(\"{name}\")"),
            Self::True => write!(f, "true"),
            Self::False => write!(f, "false"),
        }
    }
}

/// Operator precedence for parenthesization (spec §4.2: `!` binds tighter
/// than `&&`, which binds tighter than `||`). A child is parenthesized when
/// its precedence is lower than its parent's; `Not` and `Atom` children
/// never need parens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Precedence {
    Top = 0,
    Or = 1,
    And = 2,
    Not = 3,
}

fn write_predicate(
    predicate: &Predicate,
    parent: Precedence,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    match predicate {
        Predicate::And(operands) if operands.is_empty() => write!(f, "true"),
        Predicate::Or(operands) if operands.is_empty() => write!(f, "false"),
        Predicate::And(operands) => write_joined(operands, " && ", Precedence::And, parent, f),
        Predicate::Or(operands) => write_joined(operands, " || ", Precedence::Or, parent, f),
        Predicate::Not(inner) => {
            // The inner expression parenthesizes itself relative to `Not`
            // precedence, so no outer parens are needed here.
            write!(f, "!")?;
            write_predicate(inner, Precedence::Not, f)
        }
        Predicate::Atom(atom) => write!(f, "{atom}"),
    }
}

fn write_joined(
    operands: &[Predicate],
    separator: &str,
    self_precedence: Precedence,
    parent: Precedence,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    let parens = self_precedence < parent;
    if parens {
        write!(f, "(")?;
    }
    for (index, operand) in operands.iter().enumerate() {
        if index > 0 {
            write!(f, "{separator}")?;
        }
        write_predicate(operand, self_precedence, f)?;
    }
    if parens {
        write!(f, ")")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ubuntu_info_rust::Architecture;

    #[test]
    fn displays_rav1e_asm_example() {
        let predicate = Predicate::and(vec![
            Predicate::feature("asm"),
            Predicate::or(vec![
                Predicate::arch(MachineArch::Ubuntu(Architecture::Amd64)),
                Predicate::arch(MachineArch::Ubuntu(Architecture::Arm64)),
            ]),
        ]);
        assert_eq!(
            predicate.to_string(),
            "feature(\"asm\") && (arch(\"amd64\") || arch(\"arm64\"))"
        );
    }

    #[test]
    fn displays_nocheck_example() {
        let predicate = !Predicate::build_profile("nocheck");
        assert_eq!(predicate.to_string(), "!build-profile(\"nocheck\")");
    }

    #[test]
    fn parenthesizes_by_precedence() {
        let or_in_and = Predicate::and(vec![
            Predicate::feature("a"),
            Predicate::or(vec![Predicate::feature("b"), Predicate::feature("c")]),
        ]);
        assert_eq!(
            or_in_and.to_string(),
            "feature(\"a\") && (feature(\"b\") || feature(\"c\"))"
        );

        let and_in_or = Predicate::or(vec![
            Predicate::and(vec![Predicate::feature("a"), Predicate::feature("b")]),
            Predicate::feature("c"),
        ]);
        // `&&` binds tighter than `||`, so the parentheses are redundant.
        assert_eq!(
            and_in_or.to_string(),
            "feature(\"a\") && feature(\"b\") || feature(\"c\")"
        );

        let not_and = !Predicate::and(vec![Predicate::feature("a"), Predicate::feature("b")]);
        assert_eq!(not_and.to_string(), "!(feature(\"a\") && feature(\"b\"))");

        let not_atom = !Predicate::feature("a");
        assert_eq!(not_atom.to_string(), "!feature(\"a\")");
    }

    #[test]
    fn displays_qualified_feature_and_cfg() {
        let predicate = Predicate::and(vec![
            Predicate::qualified_feature("serde", "derive"),
            Predicate::cfg("target_env", "musl"),
            Predicate::env("CC", "clang"),
            Predicate::series("noble"),
        ]);
        assert_eq!(
            predicate.to_string(),
            "feature(\"serde/derive\") && cfg(\"target_env\" = \"musl\") && env(\"CC\" = \"clang\") && series(\"noble\")"
        );
    }

    #[test]
    fn displays_constants_and_empty_operands() {
        assert_eq!(Predicate::TRUE.to_string(), "true");
        assert_eq!(Predicate::FALSE.to_string(), "false");
        assert_eq!(Predicate::and(vec![]).to_string(), "true");
        assert_eq!(Predicate::or(vec![]).to_string(), "false");
    }

    #[test]
    fn serde_round_trips() {
        let predicate = Predicate::and(vec![
            Predicate::feature("asm"),
            !Predicate::env("CC", "clang"),
        ]);
        let json = serde_json::to_string(&predicate).expect("serialize");
        let back: Predicate = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, predicate);
    }
}

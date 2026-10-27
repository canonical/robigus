//! Predicate AST, parser, canonicalization, and evaluation (spec §4).
//!
//! The in-memory representation is the typed [`Predicate`] AST, never a
//! string. [`Predicate::parse`] implements the §4.2 grammar;
//! [`Predicate::canonical_text`] produces the canonical serialization used
//! for storage and equality; [`Evaluator`] evaluates lazily and memoized per
//! [`Configuration`]; [`Predicate::dnf`] computes disjunctive normal form on
//! demand behind a term cap.

use crate::error::PredicateError;
use crate::model::MachineArch;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use ubuntu_info_rust::Architecture;

// 1. AST
/// A Boolean activation condition over configuration atoms (spec §4.2).
///
/// The in-memory representation is this typed AST, never a string. Operands
/// of `And`/`Or` keep their discovery order; use [`Predicate::canonicalized`]
/// for the canonical (sorted, folded) form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Predicate {
    And(Vec<Predicate>),
    Or(Vec<Predicate>),
    Not(Box<Predicate>),
    Atom(Atom),
}

/// The predicate atoms (spec §4.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

// 2. Display
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
            } => {
                f.write_str("feature(\"")?;
                write_escaped(f, name)?;
                f.write_str("\")")
            }
            Self::Feature {
                package: Some(package),
                name,
            } => {
                f.write_str("feature(\"")?;
                write_escaped(f, package)?;
                f.write_str("/")?;
                write_escaped(f, name)?;
                f.write_str("\")")
            }
            Self::Cfg { key, value } => {
                f.write_str("cfg(\"")?;
                write_escaped(f, key)?;
                f.write_str("\" = \"")?;
                write_escaped(f, value)?;
                f.write_str("\")")
            }
            Self::Arch(arch) => {
                f.write_str("arch(\"")?;
                write_escaped(f, &arch.to_string())?;
                f.write_str("\")")
            }
            Self::Platform(name) => {
                f.write_str("platform(\"")?;
                write_escaped(f, name)?;
                f.write_str("\")")
            }
            Self::BuildProfile(name) => {
                f.write_str("build-profile(\"")?;
                write_escaped(f, name)?;
                f.write_str("\")")
            }
            Self::Env { name, value } => {
                f.write_str("env(\"")?;
                write_escaped(f, name)?;
                f.write_str("\" = \"")?;
                write_escaped(f, value)?;
                f.write_str("\")")
            }
            Self::Series(name) => {
                f.write_str("series(\"")?;
                write_escaped(f, name)?;
                f.write_str("\")")
            }
            Self::True => f.write_str("true"),
            Self::False => f.write_str("false"),
        }
    }
}

/// Writes a string literal body with the escapes the lexer understands
/// (`\"`, `\\`, `\n`, `\r`, `\t`, `\u{…}`), so that `Display` output is
/// always faithful and parseable.
fn write_escaped(f: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    for c in value.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            c if (c as u32) < 0x20 => write!(f, "\\u{:x}", c as u32)?,
            c => write!(f, "{c}")?,
        }
    }
    Ok(())
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
        Predicate::And(operands) if operands.is_empty() => f.write_str("true"),
        Predicate::Or(operands) if operands.is_empty() => f.write_str("false"),
        Predicate::And(operands) => write_joined(operands, " && ", Precedence::And, parent, f),
        Predicate::Or(operands) => write_joined(operands, " || ", Precedence::Or, parent, f),
        Predicate::Not(inner) => {
            // The inner expression parenthesizes itself relative to `Not`
            // precedence, so no outer parens are needed here.
            f.write_str("!")?;
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
        f.write_str("(")?;
    }
    for (index, operand) in operands.iter().enumerate() {
        if index > 0 {
            f.write_str(separator)?;
        }
        write_predicate(operand, self_precedence, f)?;
    }
    if parens {
        f.write_str(")")?;
    }
    Ok(())
}

// 3. Parsing
impl Predicate {
    /// Parses a predicate from its textual form (spec §4.2). An empty or
    /// whitespace-only input is equivalent to `true`.
    pub fn parse(input: &str) -> Result<Self, PredicateError> {
        let tokens = lex(input)?;
        let mut parser = Parser {
            tokens: &tokens,
            position: 0,
            input_len: input.len(),
        };
        if parser.peek().is_none() {
            return Ok(Self::TRUE);
        }
        let predicate = parser.parse_disjunction()?;
        if let Some(trailing) = parser.peek() {
            return Err(parser.error(Some(trailing), "unexpected trailing input"));
        }
        Ok(predicate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    Str(String),
    Not,
    And,
    Or,
    LParen,
    RParen,
    Equals,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenSpanned {
    token: Token,
    start: usize,
    end: usize,
}

fn lex(input: &str) -> Result<Vec<TokenSpanned>, PredicateError> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut position = 0;
    while position < bytes.len() {
        let byte = bytes[position];
        match byte {
            b' ' | b'\t' | b'\n' | b'\r' => position += 1,
            b'!' => {
                tokens.push(TokenSpanned {
                    token: Token::Not,
                    start: position,
                    end: position + 1,
                });
                position += 1;
            }
            b'(' => {
                tokens.push(TokenSpanned {
                    token: Token::LParen,
                    start: position,
                    end: position + 1,
                });
                position += 1;
            }
            b')' => {
                tokens.push(TokenSpanned {
                    token: Token::RParen,
                    start: position,
                    end: position + 1,
                });
                position += 1;
            }
            b'=' => {
                tokens.push(TokenSpanned {
                    token: Token::Equals,
                    start: position,
                    end: position + 1,
                });
                position += 1;
            }
            b'&' => {
                if bytes.get(position + 1) == Some(&b'&') {
                    tokens.push(TokenSpanned {
                        token: Token::And,
                        start: position,
                        end: position + 2,
                    });
                    position += 2;
                } else {
                    return Err(PredicateError {
                        span_start: position,
                        span_end: position + 1,
                        message: "expected '&&'".to_string(),
                    });
                }
            }
            b'|' => {
                if bytes.get(position + 1) == Some(&b'|') {
                    tokens.push(TokenSpanned {
                        token: Token::Or,
                        start: position,
                        end: position + 2,
                    });
                    position += 2;
                } else {
                    return Err(PredicateError {
                        span_start: position,
                        span_end: position + 1,
                        message: "expected '||'".to_string(),
                    });
                }
            }
            b'"' => {
                let (token, end) = lex_string(input, bytes, position)?;
                tokens.push(TokenSpanned {
                    token,
                    start: position,
                    end,
                });
                position = end;
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let mut end = position + 1;
                while bytes
                    .get(end)
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
                {
                    end += 1;
                }
                tokens.push(TokenSpanned {
                    token: Token::Ident(input[position..end].to_string()),
                    start: position,
                    end,
                });
                position = end;
            }
            _ => {
                return Err(PredicateError {
                    span_start: position,
                    span_end: position + 1,
                    message: format!("unexpected character '{}'", byte as char),
                });
            }
        }
    }
    Ok(tokens)
}

/// Lexes a string literal starting at the opening quote; returns the decoded
/// value and the end offset (past the closing quote).
fn lex_string(input: &str, bytes: &[u8], start: usize) -> Result<(Token, usize), PredicateError> {
    let mut value = String::new();
    let mut cursor = start + 1;
    loop {
        let Some(&byte) = bytes.get(cursor) else {
            return Err(PredicateError {
                span_start: start,
                span_end: bytes.len(),
                message: "unterminated string literal".to_string(),
            });
        };
        match byte {
            b'"' => return Ok((Token::Str(value), cursor + 1)),
            b'\\' => {
                let Some(&escape) = bytes.get(cursor + 1) else {
                    return Err(PredicateError {
                        span_start: cursor,
                        span_end: cursor + 1,
                        message: "unterminated escape sequence".to_string(),
                    });
                };
                match escape {
                    b'"' => {
                        value.push('"');
                        cursor += 2;
                    }
                    b'\\' => {
                        value.push('\\');
                        cursor += 2;
                    }
                    b'n' => {
                        value.push('\n');
                        cursor += 2;
                    }
                    b'r' => {
                        value.push('\r');
                        cursor += 2;
                    }
                    b't' => {
                        value.push('\t');
                        cursor += 2;
                    }
                    b'u' => {
                        cursor = lex_unicode_escape(input, bytes, cursor, &mut value)?;
                    }
                    other => {
                        return Err(PredicateError {
                            span_start: cursor,
                            span_end: cursor + 2,
                            message: format!("unknown escape '\\{}'", other as char),
                        });
                    }
                }
            }
            _ => {
                let ch = input[cursor..]
                    .chars()
                    .next()
                    .ok_or_else(|| PredicateError {
                        span_start: cursor,
                        span_end: cursor + 1,
                        message: "unexpected end of input".to_string(),
                    })?;
                value.push(ch);
                cursor += ch.len_utf8();
            }
        }
    }
}

/// Lexes a `\u{hex}` escape; returns the offset past the closing brace.
fn lex_unicode_escape(
    input: &str,
    bytes: &[u8],
    start: usize,
    value: &mut String,
) -> Result<usize, PredicateError> {
    let brace = start + 2;
    if bytes.get(brace) != Some(&b'{') {
        return Err(PredicateError {
            span_start: start,
            span_end: brace,
            message: "expected '{' after '\\u'".to_string(),
        });
    }
    let mut end = brace + 1;
    while bytes.get(end).is_some_and(u8::is_ascii_hexdigit) {
        end += 1;
    }
    if bytes.get(end) != Some(&b'}') {
        return Err(PredicateError {
            span_start: start,
            span_end: end,
            message: "unterminated '\\u{...}' escape".to_string(),
        });
    }
    let hex = &input[brace + 1..end];
    let code = u32::from_str_radix(hex, 16).map_err(|_| PredicateError {
        span_start: brace + 1,
        span_end: end,
        message: "invalid '\\u' escape".to_string(),
    })?;
    let ch = char::from_u32(code).ok_or_else(|| PredicateError {
        span_start: brace + 1,
        span_end: end,
        message: "invalid unicode scalar value".to_string(),
    })?;
    value.push(ch);
    Ok(end + 1)
}

struct Parser<'input> {
    tokens: &'input [TokenSpanned],
    position: usize,
    input_len: usize,
}

impl<'input> Parser<'input> {
    fn peek(&self) -> Option<&TokenSpanned> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<TokenSpanned> {
        let token = self.tokens.get(self.position).cloned();
        if token.is_some() {
            self.position += 1;
        }
        token
    }

    fn error(&self, token: Option<&TokenSpanned>, message: impl Into<String>) -> PredicateError {
        match token {
            Some(token) => PredicateError {
                span_start: token.start,
                span_end: token.end,
                message: message.into(),
            },
            None => PredicateError {
                span_start: self.input_len,
                span_end: self.input_len,
                message: message.into(),
            },
        }
    }

    fn parse_disjunction(&mut self) -> Result<Predicate, PredicateError> {
        let mut operands = vec![self.parse_conjunction()?];
        while matches!(self.peek().map(|t| &t.token), Some(Token::Or)) {
            self.next();
            operands.push(self.parse_conjunction()?);
        }
        if operands.len() == 1 {
            Ok(operands.swap_remove(0))
        } else {
            Ok(Predicate::Or(operands))
        }
    }

    fn parse_conjunction(&mut self) -> Result<Predicate, PredicateError> {
        let mut operands = vec![self.parse_unary()?];
        while matches!(self.peek().map(|t| &t.token), Some(Token::And)) {
            self.next();
            operands.push(self.parse_unary()?);
        }
        if operands.len() == 1 {
            Ok(operands.swap_remove(0))
        } else {
            Ok(Predicate::And(operands))
        }
    }

    fn parse_unary(&mut self) -> Result<Predicate, PredicateError> {
        let Some(token) = self.peek() else {
            return Err(self.error(None, "unexpected end of input"));
        };
        match &token.token {
            Token::Not => {
                self.next();
                let inner = self.parse_unary()?;
                Ok(Predicate::Not(Box::new(inner)))
            }
            Token::LParen => {
                self.next();
                let inner = self.parse_disjunction()?;
                self.expect_rparen()?;
                Ok(inner)
            }
            _ => self.parse_atom(),
        }
    }

    fn parse_atom(&mut self) -> Result<Predicate, PredicateError> {
        let Some(token) = self.next() else {
            return Err(self.error(None, "expected an atom"));
        };
        let Token::Ident(name) = &token.token else {
            return Err(self.error(Some(&token), "expected an atom"));
        };
        match name.as_str() {
            "true" => Ok(Predicate::TRUE),
            "false" => Ok(Predicate::FALSE),
            "feature" => {
                let value = self.parse_string_argument(name)?;
                parse_feature_atom(&value, token.start, token.end)
            }
            "cfg" | "env" => {
                let (key, value) = self.parse_key_value_argument(name)?;
                if name == "cfg" {
                    Ok(Predicate::cfg(key, value))
                } else {
                    Ok(Predicate::env(key, value))
                }
            }
            "arch" => {
                let value = self.parse_string_argument(name)?;
                Ok(Predicate::arch(parse_machine_arch(&value)))
            }
            "platform" => {
                let value = self.parse_string_argument(name)?;
                Ok(Predicate::platform(value))
            }
            "build-profile" => {
                let value = self.parse_string_argument(name)?;
                Ok(Predicate::build_profile(value))
            }
            "series" => {
                let value = self.parse_string_argument(name)?;
                Ok(Predicate::series(value))
            }
            other => Err(self.error(Some(&token), format!("unknown atom '{other}'"))),
        }
    }

    fn parse_string_argument(&mut self, atom_name: &str) -> Result<String, PredicateError> {
        self.expect_lparen(atom_name)?;
        let value = self.expect_string(atom_name)?;
        self.expect_rparen()?;
        Ok(value)
    }

    fn parse_key_value_argument(
        &mut self,
        atom_name: &str,
    ) -> Result<(String, String), PredicateError> {
        self.expect_lparen(atom_name)?;
        let key = self.expect_string(atom_name)?;
        match self.peek() {
            Some(token) if token.token == Token::Equals => {
                self.next();
            }
            other => return Err(self.error(other, "expected '='")),
        }
        let value = self.expect_string(atom_name)?;
        self.expect_rparen()?;
        Ok((key, value))
    }

    fn expect_lparen(&mut self, atom_name: &str) -> Result<(), PredicateError> {
        match self.peek() {
            Some(token) if token.token == Token::LParen => {
                self.next();
                Ok(())
            }
            other => Err(self.error(other, format!("expected '(' after '{atom_name}'"))),
        }
    }

    fn expect_rparen(&mut self) -> Result<(), PredicateError> {
        match self.peek() {
            Some(token) if token.token == Token::RParen => {
                self.next();
                Ok(())
            }
            other => Err(self.error(other, "expected ')'")),
        }
    }

    fn expect_string(&mut self, atom_name: &str) -> Result<String, PredicateError> {
        match self.next() {
            Some(token) => match &token.token {
                Token::Str(value) => Ok(value.clone()),
                _ => Err(self.error(
                    Some(&token),
                    format!("expected a string argument for '{atom_name}'"),
                )),
            },
            None => Err(self.error(
                None,
                format!("expected a string argument for '{atom_name}'"),
            )),
        }
    }
}

/// Feature atoms are `name` or `package/name`; anything else is a parse
/// error.
fn parse_feature_atom(value: &str, start: usize, end: usize) -> Result<Predicate, PredicateError> {
    let malformed = |message: &str| PredicateError {
        span_start: start,
        span_end: end,
        message: message.to_string(),
    };
    match value.split_once('/') {
        Some((package, name)) => {
            if package.is_empty() || name.is_empty() || name.contains('/') {
                Err(malformed("feature must be 'name' or 'package/name'"))
            } else {
                Ok(Predicate::qualified_feature(package, name))
            }
        }
        None if value.is_empty() => Err(malformed("feature must be 'name' or 'package/name'")),
        None => Ok(Predicate::feature(value)),
    }
}

/// `arch("all")` is the `All` marker; known `ubuntu-info-rust` names map to
/// [`MachineArch::Ubuntu`]; anything else is recorded as an unsupported stub
/// (spec §4.4) and evaluates to `false`. The `_unsupported` display suffix is
/// stripped on parse so that `Display` output round-trips (the suffix is a
/// display convention only, never part of the internal name).
fn parse_machine_arch(value: &str) -> MachineArch {
    if value == "all" {
        return MachineArch::All;
    }
    let name = value.strip_suffix("_unsupported").unwrap_or(value);
    match name.parse::<Architecture>() {
        Ok(arch) => MachineArch::Ubuntu(arch),
        Err(_) => MachineArch::Unsupported(name.to_string()),
    }
}

// 4. Canonicalization
impl Predicate {
    /// Canonical form (spec §4.3): constant folding, flattening of nested
    /// same-operator operands, singleton unwrapping, and operands sorted by
    /// their canonical text with duplicates removed. Idempotent and logically
    /// equivalent to `self`. Negations are not pushed inward.
    pub fn canonicalized(&self) -> Self {
        match self {
            Self::And(operands) => {
                let mut flat: Vec<Self> = Vec::new();
                for operand in operands {
                    match operand.canonicalized() {
                        Self::And(inner) => flat.extend(inner),
                        other => flat.push(other),
                    }
                }
                Self::fold_joined(flat, true)
            }
            Self::Or(operands) => {
                let mut flat: Vec<Self> = Vec::new();
                for operand in operands {
                    match operand.canonicalized() {
                        Self::Or(inner) => flat.extend(inner),
                        other => flat.push(other),
                    }
                }
                Self::fold_joined(flat, false)
            }
            Self::Not(inner) => match inner.canonicalized() {
                Self::Atom(Atom::True) => Self::FALSE,
                Self::Atom(Atom::False) => Self::TRUE,
                Self::Not(innermost) => *innermost,
                other => Self::Not(Box::new(other)),
            },
            Self::Atom(atom) => Self::Atom(atom.clone()),
        }
    }

    /// The canonical serialization (spec §4.3): the `Display` of the
    /// canonical form. Used for storage and equality.
    pub fn canonical_text(&self) -> String {
        self.canonicalized().to_string()
    }

    fn fold_joined(operands: Vec<Self>, is_conjunction: bool) -> Self {
        let identity = if is_conjunction {
            Self::TRUE
        } else {
            Self::FALSE
        };
        let annihilator = if is_conjunction {
            Self::FALSE
        } else {
            Self::TRUE
        };
        let mut kept: Vec<Self> = Vec::new();
        for operand in operands {
            if operand == identity {
                continue;
            }
            if operand == annihilator {
                return annihilator;
            }
            kept.push(operand);
        }
        if kept.is_empty() {
            return identity;
        }
        if kept.len() == 1 {
            return kept.swap_remove(0);
        }
        let mut keyed: Vec<(String, Self)> = kept
            .into_iter()
            .map(|operand| (operand.to_string(), operand))
            .collect();
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        keyed.dedup_by(|a, b| a.0 == b.0);
        let mut kept: Vec<Self> = keyed.into_iter().map(|(_, operand)| operand).collect();
        if kept.len() == 1 {
            return kept.swap_remove(0);
        }
        if is_conjunction {
            Self::And(kept)
        } else {
            Self::Or(kept)
        }
    }
}

// 5. Evaluation
/// The concrete evaluation context for predicates (spec §2, §4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Configuration {
    /// The architectures being evaluated. `All` expands to every
    /// `ubuntu-info-rust` architecture; unsupported stubs never match.
    pub arches: BTreeSet<MachineArch>,
    /// The target platform; only `linux` is expanded (spec §4.4).
    pub platform: String,
    /// Enabled features per package name; unqualified `feature` atoms resolve
    /// against the current package passed to [`Evaluator::evaluate`].
    pub features: BTreeMap<String, BTreeSet<String>>,
    /// Active Debian build profiles.
    pub build_profiles: BTreeSet<String>,
    /// Environment variables visible to the analysis.
    pub env: BTreeMap<String, String>,
    /// The Ubuntu series, when known (Phase 2 context).
    pub series: Option<String>,
    /// Cargo `cfg` facts for the evaluation target (spec §4.1).
    pub target_cfg: BTreeMap<String, String>,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            arches: BTreeSet::new(),
            platform: "linux".to_string(),
            features: BTreeMap::new(),
            build_profiles: BTreeSet::new(),
            env: BTreeMap::new(),
            series: None,
            target_cfg: BTreeMap::new(),
        }
    }
}

impl Configuration {
    /// A single-architecture configuration for `arch`, with the Cargo `cfg`
    /// facts derived from it (`target_os`, `target_family`, `target_env`,
    /// `target_vendor`, and — for concrete architectures — `target_arch`,
    /// `target_endian`, `target_pointer_width`). This makes `arch("amd64")`
    /// and `cfg("target_arch" = "x86_64")` evaluate identically by
    /// construction (spec §4.1). Hand-built configurations must keep the two
    /// forms consistent; the store never rewrites between them.
    pub fn for_arch(arch: MachineArch) -> Self {
        let derived = match &arch {
            MachineArch::Ubuntu(arch) => derived_cfg(Some(*arch)),
            MachineArch::All | MachineArch::Unsupported(_) => derived_cfg(None),
        };
        let mut configuration = Self {
            arches: BTreeSet::from([arch]),
            ..Self::default()
        };
        configuration.target_cfg = derived;
        configuration
    }
}

fn derived_cfg(arch: Option<Architecture>) -> BTreeMap<String, String> {
    let mut cfg = BTreeMap::new();
    cfg.insert("target_os".to_string(), "linux".to_string());
    cfg.insert("target_family".to_string(), "unix".to_string());
    cfg.insert("target_env".to_string(), "gnu".to_string());
    cfg.insert("target_vendor".to_string(), "unknown".to_string());
    if let Some(arch) = arch {
        cfg.insert(
            "target_arch".to_string(),
            rust_target_arch(arch).to_string(),
        );
        cfg.insert("target_endian".to_string(), arch_endian(arch).to_string());
        cfg.insert(
            "target_pointer_width".to_string(),
            arch_pointer_width(arch).to_string(),
        );
    }
    cfg
}

/// The Ubuntu architecture → Rust `target_arch` mapping.
fn rust_target_arch(arch: Architecture) -> &'static str {
    match arch {
        Architecture::Amd64 | Architecture::Amd64v3 => "x86_64",
        Architecture::Arm64 => "aarch64",
        Architecture::Armhf => "armv7",
        Architecture::I386 => "i686",
        Architecture::Ppc64el => "powerpc64le",
        Architecture::Riscv64 => "riscv64",
        Architecture::S390x => "s390x",
    }
}

fn arch_endian(arch: Architecture) -> &'static str {
    match arch {
        Architecture::S390x => "big",
        _ => "little",
    }
}

fn arch_pointer_width(arch: Architecture) -> &'static str {
    match arch {
        Architecture::Armhf | Architecture::I386 => "32",
        _ => "64",
    }
}

/// Evaluates predicates against a [`Configuration`] (spec §4.3).
///
/// Evaluation is lazy (operands short-circuit) and memoized per
/// (configuration, current package, predicate) at the top level. An
/// `Evaluator` is not `Sync`; concurrent users each construct their own or
/// share one behind a lock.
pub struct Evaluator {
    configuration: Configuration,
    expanded_arches: BTreeSet<MachineArch>,
    cache: RefCell<HashMap<(Option<String>, Predicate), bool>>,
}

impl Evaluator {
    pub fn new(configuration: Configuration) -> Self {
        let expanded_arches = configuration
            .arches
            .iter()
            .flat_map(|arch| arch.expand())
            .filter(|arch| arch.is_supported())
            .collect();
        Self {
            configuration,
            expanded_arches,
            cache: RefCell::new(HashMap::new()),
        }
    }

    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Evaluates `predicate`. Unqualified `feature` atoms resolve against
    /// `current_package` (the edge's source package); `None` makes them
    /// false.
    pub fn evaluate(&self, predicate: &Predicate, current_package: Option<&str>) -> bool {
        let key = (current_package.map(str::to_string), predicate.clone());
        if let Some(&cached) = self.cache.borrow().get(&key) {
            return cached;
        }
        let value = self.evaluate_inner(predicate, current_package);
        self.cache.borrow_mut().insert(key, value);
        value
    }

    fn evaluate_inner(&self, predicate: &Predicate, current_package: Option<&str>) -> bool {
        match predicate {
            // `all`/`any` short-circuit: later operands are not evaluated.
            Predicate::And(operands) => operands
                .iter()
                .all(|operand| self.evaluate_inner(operand, current_package)),
            Predicate::Or(operands) => operands
                .iter()
                .any(|operand| self.evaluate_inner(operand, current_package)),
            Predicate::Not(inner) => !self.evaluate_inner(inner, current_package),
            Predicate::Atom(atom) => self.evaluate_atom(atom, current_package),
        }
    }

    fn evaluate_atom(&self, atom: &Atom, current_package: Option<&str>) -> bool {
        match atom {
            Atom::True => true,
            Atom::False => false,
            Atom::Feature { package, name } => {
                let resolved = package.as_deref().or(current_package);
                resolved.is_some_and(|pkg| {
                    self.configuration
                        .features
                        .get(pkg)
                        .is_some_and(|enabled| enabled.contains(name))
                })
            }
            Atom::Cfg { key, value } => self.configuration.target_cfg.get(key) == Some(value),
            Atom::Arch(arch) => match arch {
                // Unsupported architectures are recorded but never active (§4.4).
                MachineArch::Unsupported(_) => false,
                MachineArch::All => !self.expanded_arches.is_empty(),
                MachineArch::Ubuntu(arch) => {
                    self.expanded_arches.contains(&MachineArch::Ubuntu(*arch))
                }
            },
            Atom::Platform(name) => self.configuration.platform == *name,
            Atom::BuildProfile(name) => self.configuration.build_profiles.contains(name),
            Atom::Env { name, value } => self.configuration.env.get(name) == Some(value),
            Atom::Series(name) => self.configuration.series.as_deref() == Some(name.as_str()),
        }
    }
}

// 6. Disjunctive normal form
/// Default term cap for [`Predicate::dnf`].
pub const DEFAULT_DNF_TERM_CAP: usize = 10_000;

/// The DNF conversion exceeded its term cap (spec §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("DNF conversion exceeds the term cap of {cap}")]
pub struct DnfError {
    pub cap: usize,
}

impl Predicate {
    /// Disjunctive normal form: a disjunction of conjunctions of literals
    /// (spec §4.3). Computed on demand for enumeration and reporting; the
    /// term cap guards against exponential blowup. Contradictory terms
    /// (`x && !x`) are dropped.
    pub fn dnf(&self, max_terms: usize) -> Result<Self, DnfError> {
        let nnf = nnf(self);
        let terms = dnf_terms(&nnf, max_terms)?;
        let mut disjuncts: Vec<Self> = Vec::new();
        for term in terms {
            let mut literals: Vec<Self> = Vec::new();
            for literal in term {
                if !literals.contains(&literal) {
                    literals.push(literal);
                }
            }
            if literals.is_empty() {
                // An empty conjunction is `true`; the whole DNF collapses.
                return Ok(Self::TRUE);
            }
            let contradictory = literals.iter().any(|literal| match literal {
                Self::Not(inner) => literals.contains(inner.as_ref()),
                _ => false,
            });
            if contradictory {
                continue;
            }
            let conjunct = if literals.len() == 1 {
                literals.swap_remove(0)
            } else {
                Self::And(literals)
            };
            if !disjuncts.contains(&conjunct) {
                disjuncts.push(conjunct);
            }
        }
        match disjuncts.len() {
            0 => Ok(Self::FALSE),
            1 => Ok(disjuncts.swap_remove(0)),
            _ => Ok(Self::Or(disjuncts)),
        }
    }
}

/// Negation normal form: negations pushed onto atoms (De Morgan), double
/// negations removed.
fn nnf(predicate: &Predicate) -> Predicate {
    match predicate {
        Predicate::And(operands) => Predicate::And(operands.iter().map(nnf).collect()),
        Predicate::Or(operands) => Predicate::Or(operands.iter().map(nnf).collect()),
        Predicate::Not(inner) => nnf_neg(inner),
        Predicate::Atom(atom) => Predicate::Atom(atom.clone()),
    }
}

fn nnf_neg(predicate: &Predicate) -> Predicate {
    match predicate {
        Predicate::And(operands) => Predicate::Or(operands.iter().map(nnf_neg).collect()),
        Predicate::Or(operands) => Predicate::And(operands.iter().map(nnf_neg).collect()),
        Predicate::Not(inner) => nnf(inner),
        Predicate::Atom(Atom::True) => Predicate::FALSE,
        Predicate::Atom(Atom::False) => Predicate::TRUE,
        Predicate::Atom(atom) => Predicate::Not(Box::new(Predicate::Atom(atom.clone()))),
    }
}

/// The conjunction-of-literals terms of the DNF of an NNF predicate.
fn dnf_terms(predicate: &Predicate, cap: usize) -> Result<Vec<Vec<Predicate>>, DnfError> {
    match predicate {
        Predicate::And(operands) => {
            let mut accumulated: Vec<Vec<Predicate>> = vec![Vec::new()];
            for operand in operands {
                let operand_terms = dnf_terms(operand, cap)?;
                let mut combined: Vec<Vec<Predicate>> = Vec::new();
                for term in &accumulated {
                    for operand_term in &operand_terms {
                        let mut merged = term.clone();
                        merged.extend(operand_term.iter().cloned());
                        combined.push(merged);
                        if combined.len() > cap {
                            return Err(DnfError { cap });
                        }
                    }
                }
                accumulated = combined;
            }
            Ok(accumulated)
        }
        Predicate::Or(operands) => {
            let mut accumulated: Vec<Vec<Predicate>> = Vec::new();
            for operand in operands {
                accumulated.extend(dnf_terms(operand, cap)?);
                if accumulated.len() > cap {
                    return Err(DnfError { cap });
                }
            }
            Ok(accumulated)
        }
        // After NNF, `Not` wraps only atoms: a literal.
        Predicate::Not(_) | Predicate::Atom(_) => Ok(vec![vec![predicate.clone()]]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use ubuntu_info_rust::Architecture;

    const RAV1E_ASM: &str = "feature(\"asm\") && (arch(\"amd64\") || arch(\"arm64\"))";
    const NASM: &str = "feature(\"asm\") && arch(\"amd64\")";
    const GAS: &str = "feature(\"asm\") && arch(\"arm64\") && !env(\"CC\" = \"clang\")";
    const CLANG: &str = "feature(\"asm\") && arch(\"arm64\") && env(\"CC\" = \"clang\")";
    const NOCHECK: &str = "!build-profile(\"nocheck\")";
    const DEBIAN_QUALIFIER: &str = "arch(\"amd64\") && !arch(\"arm64\")";

    #[test]
    fn parses_spec_examples() {
        for text in [
            RAV1E_ASM,
            NASM,
            GAS,
            CLANG,
            NOCHECK,
            DEBIAN_QUALIFIER,
            "cfg(\"target_env\" = \"musl\")",
            "series(\"noble\")",
            "feature(\"serde/derive\")",
        ] {
            let parsed = Predicate::parse(text).unwrap_or_else(|error| panic!("{text}: {error}"));
            assert_eq!(
                parsed.to_string(),
                text,
                "display must round-trip for {text}"
            );
        }
    }

    #[test]
    fn empty_predicate_is_true() {
        assert_eq!(Predicate::parse("").unwrap(), Predicate::TRUE);
        assert_eq!(Predicate::parse("   ").unwrap(), Predicate::TRUE);
        assert!(
            Evaluator::new(Configuration::default())
                .evaluate(&Predicate::parse(" ").unwrap(), None)
        );
    }

    #[test]
    fn parse_errors_carry_spans_and_messages() {
        let error = Predicate::parse("feature(").unwrap_err();
        assert!(error.span_end >= error.span_start);
        assert!(!error.message.is_empty());

        assert!(Predicate::parse("feature(\"x\" && arch(\"amd64\")").is_err());
        assert!(
            Predicate::parse("wat(\"x\")")
                .unwrap_err()
                .message
                .contains("unknown atom")
        );
        assert!(
            Predicate::parse("feature(\"x\") & arch(\"amd64\")")
                .unwrap_err()
                .message
                .contains("expected '&&'")
        );
        assert!(
            Predicate::parse("feature(\"a\\q\")")
                .unwrap_err()
                .message
                .contains("unknown escape")
        );
        assert!(Predicate::parse("feature(\"unterminated").is_err());
        assert!(Predicate::parse("feature(\"x\") feature(\"y\")").is_err());
        assert!(Predicate::parse("true(\"x\")").is_err());
    }

    #[test]
    fn parses_qualified_features_and_rejects_malformed() {
        let parsed = Predicate::parse("feature(\"serde/derive\")").unwrap();
        assert_eq!(parsed, Predicate::qualified_feature("serde", "derive"));
        assert!(Predicate::parse("feature(\"/derive\")").is_err());
        assert!(Predicate::parse("feature(\"serde/\")").is_err());
        assert!(Predicate::parse("feature(\"a/b/c\")").is_err());
        assert!(Predicate::parse("feature(\"\")").is_err());
    }

    #[test]
    fn unknown_architectures_are_recorded_as_unsupported() {
        assert_eq!(
            Predicate::parse("arch(\"mips\")").unwrap(),
            Predicate::arch(MachineArch::Unsupported("mips".into()))
        );
        assert_eq!(
            Predicate::parse("arch(\"all\")").unwrap(),
            Predicate::arch(MachineArch::All)
        );
        assert_eq!(
            Predicate::parse("arch(\"amd64\")").unwrap(),
            Predicate::arch(MachineArch::Ubuntu(Architecture::Amd64))
        );
    }

    #[test]
    fn strings_round_trip_through_escapes() {
        let parsed = Predicate::parse("feature(\"a\\\"b\\\\c\")").unwrap();
        assert_eq!(parsed, Predicate::feature("a\"b\\c"));
        assert_eq!(parsed.to_string(), "feature(\"a\\\"b\\\\c\")");

        let parsed = Predicate::parse("cfg(\"k\\u{a}\" = \"v\")").unwrap();
        assert_eq!(parsed, Predicate::cfg("k\n", "v"));
        assert_eq!(parsed.to_string(), "cfg(\"k\\n\" = \"v\")");
    }

    fn asm_config(arch: Architecture) -> Configuration {
        let mut configuration = Configuration::for_arch(MachineArch::Ubuntu(arch));
        configuration
            .features
            .insert("rav1e".into(), BTreeSet::from(["asm".into()]));
        configuration
    }

    #[test]
    fn evaluates_rav1e_asm_example() {
        let predicate = Predicate::parse(RAV1E_ASM).unwrap();
        assert!(
            Evaluator::new(asm_config(Architecture::Amd64)).evaluate(&predicate, Some("rav1e"))
        );
        assert!(
            Evaluator::new(asm_config(Architecture::Arm64)).evaluate(&predicate, Some("rav1e"))
        );
        assert!(
            !Evaluator::new(asm_config(Architecture::S390x)).evaluate(&predicate, Some("rav1e"))
        );
        // Without the feature the edge is inactive everywhere.
        assert!(
            !Evaluator::new(Configuration::for_arch(MachineArch::Ubuntu(
                Architecture::Amd64
            )))
            .evaluate(&predicate, Some("rav1e"))
        );
    }

    #[test]
    fn evaluates_gas_and_clang_examples() {
        let gas = Predicate::parse(GAS).unwrap();
        let clang = Predicate::parse(CLANG).unwrap();

        let mut arm64_clang = asm_config(Architecture::Arm64);
        arm64_clang.env.insert("CC".into(), "clang".into());
        assert!(!Evaluator::new(arm64_clang.clone()).evaluate(&gas, Some("rav1e")));
        assert!(Evaluator::new(arm64_clang).evaluate(&clang, Some("rav1e")));

        let mut arm64_gcc = asm_config(Architecture::Arm64);
        arm64_gcc.env.insert("CC".into(), "gcc".into());
        assert!(Evaluator::new(arm64_gcc.clone()).evaluate(&gas, Some("rav1e")));
        assert!(!Evaluator::new(arm64_gcc).evaluate(&clang, Some("rav1e")));
    }

    #[test]
    fn evaluates_nasm_example() {
        let predicate = Predicate::parse(NASM).unwrap();
        assert!(
            Evaluator::new(asm_config(Architecture::Amd64)).evaluate(&predicate, Some("rav1e"))
        );
        assert!(
            !Evaluator::new(asm_config(Architecture::Arm64)).evaluate(&predicate, Some("rav1e"))
        );
    }

    #[test]
    fn evaluates_nocheck_example() {
        let predicate = Predicate::parse(NOCHECK).unwrap();
        assert!(Evaluator::new(Configuration::default()).evaluate(&predicate, None));
        let mut nocheck = Configuration::default();
        nocheck.build_profiles.insert("nocheck".into());
        assert!(!Evaluator::new(nocheck).evaluate(&predicate, None));
    }

    #[test]
    fn evaluates_debian_qualifier_example() {
        let predicate = Predicate::parse(DEBIAN_QUALIFIER).unwrap();
        let amd64 = Evaluator::new(Configuration::for_arch(MachineArch::Ubuntu(
            Architecture::Amd64,
        )));
        let arm64 = Evaluator::new(Configuration::for_arch(MachineArch::Ubuntu(
            Architecture::Arm64,
        )));
        assert!(amd64.evaluate(&predicate, None));
        assert!(!arm64.evaluate(&predicate, None));
    }

    #[test]
    fn arch_and_target_arch_evaluate_identically() {
        let evaluator = Evaluator::new(Configuration::for_arch(MachineArch::Ubuntu(
            Architecture::Amd64,
        )));
        assert!(evaluator.evaluate(
            &Predicate::arch(MachineArch::Ubuntu(Architecture::Amd64)),
            None
        ));
        assert!(evaluator.evaluate(&Predicate::cfg("target_arch", "x86_64"), None));
        assert!(!evaluator.evaluate(
            &Predicate::arch(MachineArch::Ubuntu(Architecture::Arm64)),
            None
        ));
        assert!(!evaluator.evaluate(&Predicate::cfg("target_arch", "aarch64"), None));
    }

    #[test]
    fn arch_all_and_unsupported_semantics() {
        let evaluator = Evaluator::new(Configuration::for_arch(MachineArch::Ubuntu(
            Architecture::Amd64,
        )));
        assert!(evaluator.evaluate(&Predicate::arch(MachineArch::All), None));
        assert!(!evaluator.evaluate(
            &Predicate::arch(MachineArch::Unsupported("mips".into())),
            None
        ));
        let empty = Evaluator::new(Configuration::default());
        assert!(!empty.evaluate(&Predicate::arch(MachineArch::All), None));
    }

    #[test]
    fn qualified_features_resolve_against_named_packages() {
        let mut configuration = Configuration::default();
        configuration
            .features
            .insert("serde".into(), BTreeSet::from(["derive".into()]));
        let evaluator = Evaluator::new(configuration);
        // Qualified features resolve against their named package, regardless
        // of the current package.
        assert!(evaluator.evaluate(
            &Predicate::qualified_feature("serde", "derive"),
            Some("other")
        ));
        assert!(evaluator.evaluate(&Predicate::qualified_feature("serde", "derive"), None));

        let mut configuration = Configuration::default();
        configuration
            .features
            .insert("rav1e".into(), BTreeSet::from(["asm".into()]));
        let evaluator = Evaluator::new(configuration);
        assert!(evaluator.evaluate(&Predicate::feature("asm"), Some("rav1e")));
        assert!(!evaluator.evaluate(&Predicate::feature("asm"), Some("other")));
        assert!(!evaluator.evaluate(&Predicate::feature("asm"), None));
    }

    #[test]
    fn series_and_platform_semantics() {
        let configuration = Configuration {
            series: Some("noble".into()),
            ..Default::default()
        };
        let evaluator = Evaluator::new(configuration);
        assert!(evaluator.evaluate(&Predicate::series("noble"), None));
        assert!(!evaluator.evaluate(&Predicate::series("questing"), None));

        assert!(
            Evaluator::new(Configuration::default()).evaluate(&Predicate::platform("linux"), None)
        );
        assert!(
            !Evaluator::new(Configuration::default())
                .evaluate(&Predicate::platform("windows"), None)
        );
    }

    #[test]
    fn canonicalization_folds_constants_and_sorts() {
        let predicate = Predicate::and(vec![
            Predicate::TRUE,
            Predicate::feature("b"),
            Predicate::feature("a"),
            Predicate::feature("b"),
        ]);
        assert_eq!(
            predicate.canonical_text(),
            "feature(\"a\") && feature(\"b\")"
        );

        let predicate = Predicate::and(vec![Predicate::FALSE, Predicate::feature("a")]);
        assert_eq!(predicate.canonical_text(), "false");

        let predicate = Predicate::or(vec![Predicate::TRUE, Predicate::feature("a")]);
        assert_eq!(predicate.canonical_text(), "true");

        let predicate = Predicate::or(vec![Predicate::FALSE, Predicate::feature("a")]);
        assert_eq!(predicate.canonical_text(), "feature(\"a\")");

        assert_eq!(Predicate::and(vec![]).canonical_text(), "true");
        assert_eq!(Predicate::or(vec![]).canonical_text(), "false");
        assert_eq!(
            (!(!Predicate::feature("a"))).canonical_text(),
            "feature(\"a\")"
        );
    }

    #[test]
    fn canonicalization_flattens_and_unwraps_singletons() {
        let predicate = Predicate::and(vec![
            Predicate::and(vec![Predicate::feature("a"), Predicate::feature("b")]),
            Predicate::feature("c"),
        ]);
        assert_eq!(
            predicate.canonical_text(),
            "feature(\"a\") && feature(\"b\") && feature(\"c\")"
        );
        let predicate = Predicate::and(vec![Predicate::feature("a")]);
        assert_eq!(predicate.canonical_text(), "feature(\"a\")");
    }

    #[test]
    fn canonicalization_does_not_push_negations() {
        let predicate = Predicate::parse("!(feature(\"a\") && feature(\"b\"))").unwrap();
        assert_eq!(
            predicate.canonical_text(),
            "!(feature(\"a\") && feature(\"b\"))"
        );
    }

    #[test]
    fn dnf_distributes_and_over_or() {
        let predicate = Predicate::and(vec![
            Predicate::or(vec![Predicate::feature("a"), Predicate::feature("b")]),
            Predicate::feature("c"),
        ]);
        let dnf = predicate.dnf(DEFAULT_DNF_TERM_CAP).unwrap();
        assert_eq!(
            dnf.to_string(),
            "feature(\"a\") && feature(\"c\") || feature(\"b\") && feature(\"c\")"
        );
    }

    #[test]
    fn dnf_pushes_negations_via_de_morgan() {
        let predicate = Predicate::parse("!(feature(\"a\") && feature(\"b\"))").unwrap();
        let dnf = predicate.dnf(DEFAULT_DNF_TERM_CAP).unwrap();
        assert_eq!(dnf.to_string(), "!feature(\"a\") || !feature(\"b\")");
    }

    #[test]
    fn dnf_drops_contradictory_terms() {
        let predicate = Predicate::or(vec![
            Predicate::and(vec![Predicate::feature("a"), !Predicate::feature("a")]),
            Predicate::feature("b"),
        ]);
        let dnf = predicate.dnf(DEFAULT_DNF_TERM_CAP).unwrap();
        assert_eq!(dnf.to_string(), "feature(\"b\")");
    }

    #[test]
    fn dnf_respects_term_cap() {
        let mut operands = vec![Predicate::feature("x")];
        for index in 0..10 {
            operands.push(Predicate::or(vec![
                Predicate::feature(format!("a{index}")),
                Predicate::feature(format!("b{index}")),
            ]));
        }
        let predicate = Predicate::and(operands);
        assert_eq!(predicate.dnf(100).unwrap_err().cap, 100);
        assert!(predicate.dnf(2000).is_ok());
    }

    #[test]
    fn dnf_preserves_evaluation() {
        let predicate = Predicate::parse(RAV1E_ASM).unwrap();
        let dnf = predicate.dnf(DEFAULT_DNF_TERM_CAP).unwrap();
        for arch in [
            Architecture::Amd64,
            Architecture::Arm64,
            Architecture::S390x,
        ] {
            let evaluator = Evaluator::new(asm_config(arch));
            assert_eq!(
                evaluator.evaluate(&dnf, Some("rav1e")),
                evaluator.evaluate(&predicate, Some("rav1e"))
            );
        }
    }

    fn name_strategy() -> impl Strategy<Value = String> {
        "[a-z_][a-z0-9_-]{0,7}"
    }

    fn atom_strategy() -> impl Strategy<Value = Predicate> {
        let arches = {
            let mut all: Vec<MachineArch> = Architecture::ALL
                .iter()
                .copied()
                .map(MachineArch::Ubuntu)
                .collect();
            all.push(MachineArch::All);
            all.push(MachineArch::Unsupported("mips".into()));
            all
        };
        prop_oneof![
            3 => name_strategy().prop_map(Predicate::feature),
            1 => (name_strategy(), name_strategy())
                .prop_map(|(package, name)| Predicate::qualified_feature(package, name)),
            2 => (name_strategy(), name_strategy()).prop_map(|(key, value)| Predicate::cfg(key, value)),
            2 => prop::sample::select(arches).prop_map(Predicate::arch),
            1 => prop::sample::select(vec!["linux".to_string(), "windows".to_string()])
                .prop_map(Predicate::platform),
            1 => name_strategy().prop_map(Predicate::build_profile),
            1 => (name_strategy(), name_strategy()).prop_map(|(name, value)| Predicate::env(name, value)),
            1 => name_strategy().prop_map(Predicate::series),
            1 => Just(Predicate::TRUE),
            1 => Just(Predicate::FALSE),
        ]
    }

    fn predicate_strategy() -> impl Strategy<Value = Predicate> {
        atom_strategy().prop_recursive(4, 24, 3, |inner| {
            prop_oneof![
                2 => prop::collection::vec(inner.clone(), 1..=3).prop_map(Predicate::and),
                2 => prop::collection::vec(inner.clone(), 1..=3).prop_map(Predicate::or),
                1 => inner.prop_map(|p| !p),
            ]
        })
    }

    fn configuration_strategy() -> impl Strategy<Value = Configuration> {
        let arches = {
            let mut all: Vec<MachineArch> = Architecture::ALL
                .iter()
                .copied()
                .map(MachineArch::Ubuntu)
                .collect();
            all.push(MachineArch::All);
            all.push(MachineArch::Unsupported("mips".into()));
            all
        };
        (
            prop::collection::vec(prop::sample::select(arches), 0..=3),
            prop::sample::select(vec!["linux".to_string(), "windows".to_string()]),
            prop::collection::hash_map(
                name_strategy(),
                prop::collection::vec(name_strategy(), 0..=3),
                0..=3,
            ),
            prop::collection::vec(
                prop::sample::select(vec![
                    "nocheck".to_string(),
                    "cross".to_string(),
                    "stage1".to_string(),
                ]),
                0..=2,
            ),
            prop::collection::hash_map("[A-Z_]{1,6}", "[a-z]{1,6}", 0..=3),
            proptest::option::of(name_strategy()),
            prop::collection::hash_map("[a-z_]{1,10}", "[a-z0-9]{1,8}", 0..=4),
        )
            .prop_map(
                |(arches, platform, features, profiles, env, series, target_cfg)| Configuration {
                    arches: arches.into_iter().collect(),
                    platform,
                    features: features
                        .into_iter()
                        .map(|(package, enabled)| (package, enabled.into_iter().collect()))
                        .collect(),
                    build_profiles: profiles.into_iter().collect(),
                    env: env.into_iter().collect(),
                    series,
                    target_cfg: target_cfg.into_iter().collect(),
                },
            )
    }

    proptest! {
        #[test]
        fn canonicalization_is_idempotent(predicate in predicate_strategy()) {
            let once = predicate.canonicalized();
            let twice = once.canonicalized();
            prop_assert_eq!(twice, once);
        }

        #[test]
        fn canonicalization_preserves_evaluation(
            predicate in predicate_strategy(),
            configuration in configuration_strategy(),
        ) {
            let evaluator = Evaluator::new(configuration);
            prop_assert_eq!(
                evaluator.evaluate(&predicate.canonicalized(), Some("pkg")),
                evaluator.evaluate(&predicate, Some("pkg"))
            );
        }

        #[test]
        fn de_morgan_holds(
            a in predicate_strategy(),
            b in predicate_strategy(),
            configuration in configuration_strategy(),
        ) {
            let evaluator = Evaluator::new(configuration);
            let lhs = !Predicate::and(vec![a.clone(), b.clone()]);
            let rhs = Predicate::or(vec![!a, !b]);
            prop_assert_eq!(
                evaluator.evaluate(&lhs, Some("pkg")),
                evaluator.evaluate(&rhs, Some("pkg"))
            );
        }

        #[test]
        fn display_round_trips_semantically(
            predicate in predicate_strategy(),
            configuration in configuration_strategy(),
        ) {
            let text = predicate.to_string();
            let reparsed = Predicate::parse(&text)
                .unwrap_or_else(|error| panic!("display output must parse: {error}; text: {text}"));
            let evaluator = Evaluator::new(configuration);
            prop_assert_eq!(
                evaluator.evaluate(&reparsed, Some("pkg")),
                evaluator.evaluate(&predicate, Some("pkg"))
            );
        }

        #[test]
        fn canonical_display_round_trips_structurally(predicate in predicate_strategy()) {
            let canonical = predicate.canonicalized();
            let text = canonical.to_string();
            let reparsed = Predicate::parse(&text).unwrap_or_else(|error| {
                panic!("canonical display must parse: {error}; text: {text}");
            });
            prop_assert_eq!(reparsed, canonical);
        }

        #[test]
        fn prop_dnf_preserves_evaluation(
            predicate in predicate_strategy(),
            configuration in configuration_strategy(),
        ) {
            let Ok(dnf) = predicate.dnf(DEFAULT_DNF_TERM_CAP) else {
                return Ok(());
            };
            let evaluator = Evaluator::new(configuration);
            prop_assert_eq!(
                evaluator.evaluate(&dnf, Some("pkg")),
                evaluator.evaluate(&predicate, Some("pkg"))
            );
        }
    }
}

//! Pure Rust implementation of Debian's dpkg version comparison algorithm, following the Debian Policy Manual (Section 5.6.12).
//! Parsing Rules & Comparison Mechanics
//! A Debian version string follows the format:
//! \[epoch:\]upstream_version\[-debian_revision\]
//! Epoch: An unsigned integer defaulting to 0 if omitted. If epochs differ, the numerical comparison determines the result immediately.
//! Upstream Version & Debian Revision: Compared chunk by chunk:
//! Alternating sequences of non-digit characters and digit characters.
//! Digits are compared numerically (e.g., 01 equals 1, 10 is greater than 9).
//! Non-digits are compared character by character using modified ASCII rules:
//! The tilde ~ sorts before everything, even before the end of a string (empty sequence). This is what enables pre-releases (e.g., 1.0~beta1 < 1.0).
//! Letters sort before non-letters/punctuation: [A-Za-z] come before characters like ., +, -.
//! Standard ASCII order applies among letters (A < B ... < z).
use crate::error::DpkgError;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DpkgVersion {
    pub epoch: u32,
    pub upstream_version: String,
    pub debian_revision: String,
}

impl DpkgVersion {
    pub fn parse(s: &str) -> Result<Self, DpkgError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(DpkgError::Empty);
        }

        // 1. Extract Epoch (optional: digits preceding the first colon ':')
        let (epoch, rest) = if let Some(colon_pos) = s.find(':') {
            let epoch_str = &s[..colon_pos];
            let epoch_num = epoch_str
                .parse::<u32>()
                .map_err(|_| DpkgError::InvalidEpoch {
                    epoch: epoch_str.to_string(),
                })?;
            (epoch_num, &s[colon_pos + 1..])
        } else {
            (0, s)
        };

        if rest.is_empty() {
            return Err(DpkgError::EmptyUpstream);
        }

        // 2. Extract Upstream and Debian Revision (optional: after the last hyphen '-')
        let (upstream, debian_revision) = if let Some(hyphen_pos) = rest.rfind('-') {
            let revision = &rest[hyphen_pos + 1..];
            if revision.is_empty() {
                return Err(DpkgError::EmptyRevision);
            }
            (&rest[..hyphen_pos], revision)
        } else {
            (rest, "")
        };
        if upstream.is_empty() {
            return Err(DpkgError::EmptyUpstream);
        }

        Ok(Self {
            epoch,
            upstream_version: upstream.to_string(),
            debian_revision: debian_revision.to_string(),
        })
    }

    /// Canonical form: numeric chunks are normalized (leading zeros stripped,
    /// trailing all-zero chunks omitted), and a zero revision is omitted.
    /// Structurally different but semantically equal versions (`1.02` and
    /// `1.2`, or `1.0` and `1.0-00`) share one canonical string.
    pub fn canonical_form(&self) -> String {
        let mut out = String::new();
        if self.epoch != 0 {
            out.push_str(&self.epoch.to_string());
            out.push(':');
        }
        let upstream = normalize_part(&self.upstream_version);
        // Keep an all-zero upstream printable rather than emitting an empty version.
        out.push_str(if upstream.is_empty() { "0" } else { &upstream });
        let revision = normalize_part(&self.debian_revision);
        if !revision.is_empty() {
            out.push('-');
            out.push_str(&revision);
        }
        out
    }
}

/// Normalizes one version part: digit chunks lose their leading zeros and
/// non-digit chunks are preserved verbatim. An all-zero chunk becomes "0"
/// internally, but is omitted at the end: dpkg compares a trailing zero chunk
/// equal to an absent chunk, while an internal zero still sorts before letters.
fn normalize_part(part: &str) -> String {
    let mut out = String::with_capacity(part.len());
    let mut chars = part.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            let mut digits = String::new();
            digits.push(c);
            while let Some(&next) = chars.peek() {
                if next.is_ascii_digit() {
                    digits.push(next);
                    chars.next();
                } else {
                    break;
                }
            }
            let trimmed = digits.trim_start_matches('0');
            if !trimmed.is_empty() {
                out.push_str(trimmed);
            } else if chars.peek().is_some() {
                out.push('0');
            }
        } else {
            out.push(c);
        }
    }
    out
}

impl FromStr for DpkgVersion {
    type Err = DpkgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for DpkgVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch > 0 {
            write!(f, "{}:", self.epoch)?;
        }
        write!(f, "{}", self.upstream_version)?;
        if !self.debian_revision.is_empty() {
            write!(f, "-{}", self.debian_revision)?;
        }
        Ok(())
    }
}

// Dpkg Ordering Engine

/// Assigns ranking weights to characters per Debian Policy rules:
/// - '~' sorts before everything (lowest priority)
/// - Empty/End-of-string sorts directly above '~'
/// - Letters 'A'-'Z' and 'a'-'z' sort next
/// - Other punctuation/characters sort after letters
///
/// Non-ASCII input accepted by the parser follows Unicode scalar order after
/// ASCII characters, preserving dpkg's ordering on Debian's ASCII alphabet.
fn char_order(c: Option<char>) -> i32 {
    match c {
        Some('~') => -1,
        None => 0,
        // Digits are compared numerically in a later step, but they can still
        // appear opposite a non-digit in the character loop. Debian's `order()`
        // gives digits rank 0 so that, for example, `1.0` sorts before `1.a`.
        Some(ch) if ch.is_ascii_digit() => 0,
        Some(ch) if ch.is_ascii_alphabetic() => ch as i32,
        Some(ch) => (ch as i32) + 256,
    }
}

/// Compares Debian version parts (upstream or revision string)
fn compare_parts(mut a: &str, mut b: &str) -> Ordering {
    while !a.is_empty() || !b.is_empty() {
        // Step A: Compare non-digit chunks
        let mut first_diff = Ordering::Equal;
        loop {
            let ac = a.chars().next();
            let bc = b.chars().next();

            let a_is_digit = ac.is_some_and(|c| c.is_ascii_digit());
            let b_is_digit = bc.is_some_and(|c| c.is_ascii_digit());

            // Break if both sides have reached digits or are exhausted
            if (a_is_digit || ac.is_none()) && (b_is_digit || bc.is_none()) {
                break;
            }

            if first_diff == Ordering::Equal {
                let order_a = char_order(ac);
                let order_b = char_order(bc);
                if order_a != order_b {
                    first_diff = order_a.cmp(&order_b);
                }
            }

            if let Some(c) = ac.filter(|c| !c.is_ascii_digit()) {
                a = &a[c.len_utf8()..];
            }
            if let Some(c) = bc.filter(|c| !c.is_ascii_digit()) {
                b = &b[c.len_utf8()..];
            }
        }

        if first_diff != Ordering::Equal {
            return first_diff;
        }

        // Step B: Compare digit chunks numerically
        let a_digits_len = a.bytes().take_while(u8::is_ascii_digit).count();
        let b_digits_len = b.bytes().take_while(u8::is_ascii_digit).count();

        if a_digits_len > 0 || b_digits_len > 0 {
            let a_digit_str = &a[..a_digits_len];
            let b_digit_str = &b[..b_digits_len];

            // Strip leading zeros for numeric evaluation
            let a_trimmed = a_digit_str.trim_start_matches('0');
            let b_trimmed = b_digit_str.trim_start_matches('0');

            // Numerical length comparison handles arbitrarily large numbers
            match a_trimmed.len().cmp(&b_trimmed.len()) {
                Ordering::Equal => {
                    let ord = a_trimmed.cmp(b_trimmed);
                    if ord != Ordering::Equal {
                        return ord;
                    }
                }
                unequal => return unequal,
            }

            a = &a[a_digits_len..];
            b = &b[b_digits_len..];
        }
    }

    Ordering::Equal
}

impl Ord for DpkgVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // 1. Compare Epochs
        match self.epoch.cmp(&other.epoch) {
            Ordering::Equal => {}
            unequal => return unequal,
        }

        // 2. Compare Upstream Versions
        match compare_parts(&self.upstream_version, &other.upstream_version) {
            Ordering::Equal => {}
            unequal => return unequal,
        }

        // 3. Compare Debian Revisions
        compare_parts(&self.debian_revision, &other.debian_revision)
    }
}

impl PartialOrd for DpkgVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// `PartialEq` agrees with `Ord`: versions that compare `Equal` (for example
/// `1.02` and `1.2`) are equal. The previous derived structural equality
/// violated the `Ord`/`Eq` contract and corrupted sorted containers.
impl PartialEq for DpkgVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for DpkgVersion {}

/// `Hash` agrees with the semantic `Eq`: the canonical form is hashed, so
/// `1.02` and `1.2`, as well as `1.0` and `1.0-00`, hash identically.
impl Hash for DpkgVersion {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical_form().hash(state);
    }
}

/// Verification and Test Suite
/// This test suite covers common edge cases, including epoch dominance, tilde priority over releases, alphanumeric segment switching, leading zeros, and revision checks.
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::string::string_regex;
    use std::collections::hash_map::DefaultHasher;
    use std::collections::{BTreeSet, HashSet};

    fn version_hash(version: &DpkgVersion) -> u64 {
        let mut hasher = DefaultHasher::new();
        version.hash(&mut hasher);
        hasher.finish()
    }

    fn assert_version_order(less: &str, greater: &str) {
        let v1: DpkgVersion = less.parse().unwrap();
        let v2: DpkgVersion = greater.parse().unwrap();
        assert_eq!(
            v1.cmp(&v2),
            Ordering::Less,
            "Expected '{}' < '{}', but got {:?}",
            less,
            greater,
            v1.cmp(&v2)
        );
        assert_eq!(v2.cmp(&v1), Ordering::Greater);
    }

    fn assert_version_eq(a: &str, b: &str) {
        let v1: DpkgVersion = a.parse().unwrap();
        let v2: DpkgVersion = b.parse().unwrap();
        assert_eq!(v1.cmp(&v2), Ordering::Equal, "Expected '{}' == '{}'", a, b);
        assert_eq!(v1, v2);
        assert_eq!(v1.canonical_form(), v2.canonical_form());
        assert_eq!(version_hash(&v1), version_hash(&v2));
    }

    #[test]
    fn test_epoch_handling() {
        assert_version_order("1:1.0", "2:0.1");
        assert_version_order("0.9.9", "1:0.1.0");
        assert_version_eq("1.0", "0:1.0");
    }

    #[test]
    fn test_tilde_ordering() {
        // Tilde must sort before empty string and ordinary strings
        assert_version_order("1.0~beta1", "1.0");
        assert_version_order("1.0~rc1", "1.0~rc2");
        assert_version_order("1.0~rc2", "1.0");
        assert_version_order("1.0~~", "1.0~");
    }

    #[test]
    fn test_numeric_and_leading_zeros() {
        assert_version_order("1.2", "1.10");
        assert_version_order("1.02", "1.3");
        assert_version_eq("1.02", "1.2");
        assert_version_eq("01.2", "1.2");
    }

    #[test]
    fn test_character_classes() {
        // Letters sort before symbols/punctuation
        assert_version_order("1.0a", "1.0.");
        assert_version_order("1.0a", "1.0+");
        assert_version_order("1.0-1", "1.0+");
    }

    #[test]
    fn test_digit_vs_non_digit() {
        // A digit sorts before letters and punctuation, but after '~'.
        assert_version_order("1.0", "1.a");
        assert_version_order("1.0", "1.+");
        assert_version_order("1.~", "1.0");
    }

    #[test]
    fn test_debian_revisions() {
        assert_version_order("1.0-1", "1.0-2");
        assert_version_order("1.0-1ubuntu1", "1.0-1ubuntu2");
        assert_version_order("1.0-1", "1.0-1build1");
        assert_version_order("1.0-0ubuntu1~22.04.1", "1.0-0ubuntu1");
    }

    #[test]
    fn eq_agrees_with_ord_for_leading_zeros() {
        let a: DpkgVersion = "1.02".parse().unwrap();
        let b: DpkgVersion = "1.2".parse().unwrap();
        assert_eq!(a.cmp(&b), Ordering::Equal);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_agrees_with_eq() {
        assert_version_eq("1.02", "1.2");
    }

    #[test]
    fn zero_revisions_share_equality_hash_and_canonical_form() {
        let versions: Vec<DpkgVersion> = ["1.0", "1.0-0", "1.0-00", "0:01.00-000"]
            .into_iter()
            .map(|text| text.parse().unwrap())
            .collect();
        for a in &versions {
            for b in &versions {
                assert_eq!(a.cmp(b), Ordering::Equal);
                assert_eq!(a, b);
                assert_eq!(a.canonical_form(), b.canonical_form());
                assert_eq!(version_hash(a), version_hash(b));
            }
        }
        assert_eq!(versions.iter().collect::<HashSet<_>>().len(), 1);
        assert_eq!(versions.iter().collect::<BTreeSet<_>>().len(), 1);
        assert_eq!(versions[0].canonical_form(), "1.");
        assert_version_order("1.0-~", "1.0-0");
        assert_version_order("1.0", "1.0-1");
    }

    #[test]
    fn trailing_zero_chunks_are_equivalent_but_internal_zeros_are_not() {
        assert_version_eq("1.0-a", "1.0-a000");
        assert_version_eq("1.0-0a", "1.0-000a000");
        assert_version_eq("1.", "1.000");
        assert_version_eq("0", "000");
        assert_eq!(DpkgVersion::parse("000").unwrap().canonical_form(), "0");
        assert_version_order("1.0-a0b", "1.0-ab");
    }

    #[test]
    fn non_ascii_comparison_is_safe_in_both_version_parts() {
        assert_version_eq("1.é02", "1.é2");
        assert_version_eq("1.0-🦀000", "1.0-🦀");
        assert_version_eq("1.٢", "1.٢0"); // Only ASCII digits form numeric chunks.
        assert_version_order("1.é1", "1.é2");
        assert_version_order("1.é", "1.ê");
        assert_version_order("1.z", "1.é");
        assert_version_order("1.2", "1.é");
        assert_version_order("1.aé", "1.bé");
        assert_version_order("1.é~", "1.é");
        assert_version_order("1.é", "1.éa");
        assert_version_order("1.0-🦀1", "1.0-🦀2");
        assert_version_order("1.0-é", "1.0-🦀");
    }

    #[test]
    fn parse_errors_are_typed() {
        assert!(matches!(DpkgVersion::parse(""), Err(DpkgError::Empty)));
        assert!(matches!(
            DpkgVersion::parse("x:1.0"),
            Err(DpkgError::InvalidEpoch { .. })
        ));
        assert!(matches!(
            DpkgVersion::parse("1:"),
            Err(DpkgError::EmptyUpstream)
        ));
        assert!(matches!(
            DpkgVersion::parse("1.0-"),
            Err(DpkgError::EmptyRevision)
        ));
        assert!(matches!(
            DpkgVersion::parse("-1"),
            Err(DpkgError::EmptyUpstream)
        ));
    }

    fn dpkg_available(test_name: &str) -> bool {
        match std::process::Command::new("/usr/bin/dpkg")
            .arg("--version")
            .output()
        {
            Ok(output) => {
                assert!(
                    output.status.success(),
                    "dpkg availability probe failed: {:?}; stderr: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                );
                true
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                // Write directly so the skip reason is visible even with test capture enabled.
                use std::io::Write;
                writeln!(
                    std::io::stderr(),
                    "SKIP {test_name}: /usr/bin/dpkg unavailable: {error}"
                )
                .expect("write dpkg test skip reason");
                false
            }
            Err(error) => panic!("cannot probe /usr/bin/dpkg: {error}"),
        }
    }

    fn dpkg_compare(a: &str, b: &str) -> Ordering {
        let relation = |operator: &str| {
            let output = std::process::Command::new("/usr/bin/dpkg")
                .args(["--compare-versions", a, operator, b])
                .env("LC_ALL", "C")
                .output()
                .unwrap_or_else(|error| panic!("dpkg {a:?} {operator} {b:?}: {error}"));
            assert!(
                output.stderr.is_empty(),
                "dpkg rejected or warned about {a:?} {operator} {b:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            match output.status.code() {
                Some(0) => true,
                Some(1) => false,
                _ => panic!(
                    "dpkg {a:?} {operator} {b:?} returned unexpected status {:?}",
                    output.status
                ),
            }
        };
        match (relation("lt"), relation("eq"), relation("gt")) {
            (true, false, false) => Ordering::Less,
            (false, true, false) => Ordering::Equal,
            (false, false, true) => Ordering::Greater,
            results => panic!("inconsistent dpkg relations for {a:?} vs {b:?}: {results:?}"),
        }
    }

    #[test]
    fn differential_dpkg_examples() {
        if !dpkg_available("differential_dpkg_examples") {
            return;
        }
        let examples = [
            ("1.0", "1.0"),
            ("1.0", "1.0-0"),
            ("1.0", "1.0-000"),
            ("0:01.00-00", "1.0"),
            ("1.0-a", "1.0-a000"),
            ("1.0-0a", "1.0-000a000"),
            ("1.0-a0b", "1.0-ab"),
            ("1.", "1.000"),
            ("0", "000"),
            ("1.02", "1.2"),
            ("1.9", "1.10"),
            ("1.000000000000000000001", "1.999999999999999999999"),
            ("1.0~rc1", "1.0"),
            ("1.0~~", "1.0~"),
            ("1.~", "1.0"),
            ("1.0", "1.a"),
            ("1.0", "1.+"),
            ("1.A", "1.a"),
            ("1.z", "1.+"),
            ("1.+", "1.."),
            ("1.0-~", "1.0-0"),
            ("1.0-1ubuntu1", "1.0-1ubuntu2"),
            ("1.0-1", "1.0-1build1"),
            ("1.0-0ubuntu1~22.04.1", "1.0-0ubuntu1"),
            ("1.0-1", "1.0+git1-1"),
            ("1.0-beta-1", "1.0-beta-2"),
            ("1:1.0:git-1", "1:1.0:git-2"),
            ("1:1.0", "2:0.1"),
            ("1.999", "1:0"),
        ];
        for (a, b) in examples {
            for (a, b) in [(a, b), (b, a)] {
                let actual = DpkgVersion::parse(a)
                    .unwrap()
                    .cmp(&DpkgVersion::parse(b).unwrap());
                assert_eq!(
                    actual,
                    dpkg_compare(a, b),
                    "dpkg discrepancy: {a:?} vs {b:?}"
                );
            }
        }
    }

    /// Debian ASCII grammar: digit-led upstream, nonempty optional revision,
    /// upstream ':' only with an epoch, and upstream '-' only with a revision.
    fn valid_debian_version_strategy() -> impl Strategy<Value = String> {
        (
            proptest::option::of(1u32..=4),
            string_regex("[0-9][0-9A-Za-z.+~:-]{0,23}").unwrap(),
            proptest::option::of(string_regex("[0-9A-Za-z.+~]{1,12}").unwrap()),
        )
            .prop_map(|(epoch, mut upstream, revision)| {
                if epoch.is_none() {
                    upstream = upstream.replace(':', "");
                }
                if revision.is_none() {
                    upstream = upstream.replace('-', "");
                }
                // dpkg rejects an upstream ending in '-' when no revision
                // follows it, and an empty revision after the final '-'.
                if upstream.ends_with('-') && revision.is_none() {
                    upstream.pop();
                }
                let mut text = match epoch {
                    Some(epoch) => format!("{epoch}:{upstream}"),
                    None => upstream,
                };
                if let Some(revision) = revision {
                    text.push('-');
                    text.push_str(&revision);
                }
                text
            })
    }

    #[test]
    fn differential_dpkg_randomized() {
        if !dpkg_available("differential_dpkg_randomized") {
            return;
        }
        use proptest::test_runner::{Config, TestRunner};

        let pairs = (
            valid_debian_version_strategy(),
            valid_debian_version_strategy(),
            0u8..4,
        )
            .prop_map(|(a, b, mode)| {
                let mut a = DpkgVersion::parse(&a).unwrap();
                let mut b = DpkgVersion::parse(&b).unwrap();
                // Correlated pairs exercise parts that unrelated epochs/upstreams would mask.
                match mode {
                    1 => {
                        a.epoch = 1;
                        b.epoch = 1;
                    }
                    2 => {
                        b.epoch = a.epoch;
                        b.upstream_version = a.upstream_version.clone();
                        // An upstream hyphen is only valid when a revision follows.
                        if b.upstream_version.contains('-') && b.debian_revision.is_empty() {
                            b.debian_revision = "0".into();
                        }
                    }
                    3 => {
                        b.epoch = a.epoch;
                        b.upstream_version = equivalent_part(&a.upstream_version, 3);
                        // A missing revision must stay missing: appending zeros
                        // to an empty revision would spell an explicit `-000`.
                        b.debian_revision = if a.debian_revision.is_empty() {
                            String::new()
                        } else {
                            equivalent_part(&a.debian_revision, 3)
                        };
                    }
                    _ => {}
                }
                (a.to_string(), b.to_string())
            });
        let mut runner = TestRunner::new(Config {
            cases: 128,
            max_shrink_iters: 128,
            // Keep discrepancies in the failure message without creating regression files.
            failure_persistence: None,
            ..Config::default()
        });
        runner
            .run(&pairs, |(a, b)| {
                let actual = DpkgVersion::parse(&a)
                    .unwrap()
                    .cmp(&DpkgVersion::parse(&b).unwrap());
                prop_assert_eq!(actual, dpkg_compare(&a, &b), "versions {:?} vs {:?}", a, b);
                Ok(())
            })
            .unwrap_or_else(|error| panic!("dpkg differential property failed: {error}"));
    }

    /// Generates versions whose `Display` output parses back unambiguously:
    /// no ':' (epoch separator) in either part, and no '-' in either part
    /// (the revision separator; parsing splits at the last hyphen).
    fn version_strategy() -> impl Strategy<Value = DpkgVersion> {
        (
            0u32..=4,
            string_regex("[0-9a-zA-Z.~+é中🦀٢][0-9a-zA-Z.~+é中🦀٢]{0,15}").unwrap(),
            proptest::option::of(string_regex("[0-9a-zA-Z.~+é中🦀٢]{1,10}").unwrap()),
        )
            .prop_map(|(epoch, upstream, revision)| DpkgVersion {
                epoch,
                upstream_version: upstream,
                debian_revision: revision.unwrap_or_default(),
            })
    }

    fn arbitrary_version_strategy() -> impl Strategy<Value = DpkgVersion> {
        (any::<u32>(), any::<String>(), any::<String>()).prop_map(
            |(epoch, upstream_version, debian_revision)| DpkgVersion {
                epoch,
                upstream_version,
                debian_revision,
            },
        )
    }

    /// Preserve each non-digit chunk while adding leading zeros to numeric
    /// chunks and, after a non-digit, appending a zero chunk (equal to end-of-string).
    fn equivalent_part(part: &str, zeros: usize) -> String {
        let mut out = String::new();
        let mut was_digit = false;
        for c in part.chars() {
            if c.is_ascii_digit() && !was_digit {
                out.extend(std::iter::repeat_n('0', zeros));
            }
            out.push(c);
            was_digit = c.is_ascii_digit();
        }
        if !was_digit {
            out.extend(std::iter::repeat_n('0', zeros));
        }
        out
    }

    proptest! {
        #[test]
        fn eq_agrees_with_ord(a in arbitrary_version_strategy(), b in arbitrary_version_strategy()) {
            prop_assert_eq!(a == b, a.cmp(&b) == Ordering::Equal);
            prop_assert_eq!(a.cmp(&b), b.cmp(&a).reverse());
            if a == b {
                prop_assert_eq!(version_hash(&a), version_hash(&b));
            }
        }

        #[test]
        fn equivalent_numeric_spellings_share_hash(a in arbitrary_version_strategy(), zeros in 1usize..8) {
            let b = DpkgVersion {
                epoch: a.epoch,
                upstream_version: equivalent_part(&a.upstream_version, zeros),
                debian_revision: equivalent_part(&a.debian_revision, zeros),
            };
            prop_assert_eq!(a.cmp(&b), Ordering::Equal);
            prop_assert_eq!(a.canonical_form(), b.canonical_form());
            prop_assert_eq!(version_hash(&a), version_hash(&b));
            prop_assert_eq!(a, b);
        }

        #[test]
        fn comparison_is_transitive(a in arbitrary_version_strategy(), b in arbitrary_version_strategy(), c in arbitrary_version_strategy()) {
            prop_assert_eq!(a.cmp(&a), Ordering::Equal);
            if a <= b && b <= c {
                prop_assert!(a <= c);
            }
        }

        #[test]
        fn display_round_trips(a in version_strategy()) {
            let parsed = DpkgVersion::parse(&a.to_string()).expect("generated versions must parse");
            assert_eq!(parsed.cmp(&a), Ordering::Equal);
        }

        #[test]
        fn canonical_form_matches_ord(a in version_strategy(), b in version_strategy()) {
            assert_eq!(
                a.canonical_form() == b.canonical_form(),
                a.cmp(&b) == Ordering::Equal
            );
        }
    }
}

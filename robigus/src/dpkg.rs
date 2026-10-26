/// Pure Rust implementation of Debian’s dpkg version comparison algorithm, following the Debian Policy Manual (Section 5.6.12).
/// Parsing Rules & Comparison Mechanics
/// A Debian version string follows the format:
/// [\text{epoch}:]\text{upstream\_version}[-\text{debian\_revision}]
/// Epoch: An unsigned integer defaulting to 0 if omitted. If epochs differ, the numerical comparison determines the result immediately.
/// Upstream Version & Debian Revision: Compared chunk by chunk:
/// Alternating sequences of non-digit characters and digit characters.
/// Digits are compared numerically (e.g., 01 equals 1, 10 is greater than 9).
/// Non-digits are compared character by character using modified ASCII rules:
/// The tilde ~ sorts before everything, even before the end of a string (empty sequence). This is what enables pre-releases (e.g., 1.0~beta1 < 1.0).
/// Letters sort before non-letters/punctuation: [A-Za-z] come before characters like ., +, -.
/// Standard ASCII order applies among letters (A < B ... < z).
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DpkgVersion {
    pub epoch: u32,
    pub upstream_version: String,
    pub debian_revision: String,
}

impl DpkgVersion {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("Empty version string".to_string());
        }

        // 1. Extract Epoch (optional: digits preceding the first colon ':')
        let (epoch, rest) = if let Some(colon_pos) = s.find(':') {
            let epoch_str = &s[..colon_pos];
            let epoch_num = epoch_str.parse::<u32>().map_err(|_| {
                format!("Invalid epoch '{}': must be an unsigned integer", epoch_str)
            })?;
            (epoch_num, &s[colon_pos + 1..])
        } else {
            (0, s)
        };

        if rest.is_empty() {
            return Err("Upstream version component cannot be empty".to_string());
        }

        // 2. Extract Upstream and Debian Revision (optional: after the last hyphen '-')
        let (upstream, debian_revision) = if let Some(hyphen_pos) = rest.rfind('-') {
            (&rest[..hyphen_pos], &rest[hyphen_pos + 1..])
        } else {
            (rest, "")
        };

        Ok(Self {
            epoch,
            upstream_version: upstream.to_string(),
            debian_revision: debian_revision.to_string(),
        })
    }
}

impl FromStr for DpkgVersion {
    type Err = String;

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

            // WP-1.1: clippy unnecessary_map_or
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

            if !a_is_digit && ac.is_some() {
                a = &a[1..];
            }
            if !b_is_digit && bc.is_some() {
                b = &b[1..];
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

/// Verification and Test Suite
/// This test suite covers common edge cases, including epoch dominance, tilde priority over releases, alphanumeric segment switching, leading zeros, and revision checks.
#[cfg(test)]
mod tests {
    use super::*;

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
}

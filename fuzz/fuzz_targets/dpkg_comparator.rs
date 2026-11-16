//! Fuzz target: accepted dpkg versions must compare without panicking, obey
//! total-order laws, and give equal versions identical hashes/canonical forms.

#![no_main]

use libfuzzer_sys::fuzz_target;
use robigus::dpkg::DpkgVersion;
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn version_hash(version: &DpkgVersion) -> u64 {
    let mut hasher = DefaultHasher::new();
    version.hash(&mut hasher);
    hasher.finish()
}

fn check_pair(a: &DpkgVersion, b: &DpkgVersion) {
    let ordering = a.cmp(b);
    assert_eq!(ordering, b.cmp(a).reverse());
    assert_eq!(a.partial_cmp(b), Some(ordering));
    assert_eq!(a == b, ordering == Ordering::Equal);
    if a == b {
        assert_eq!(a.canonical_form(), b.canonical_form());
        assert_eq!(version_hash(a), version_hash(b));
    }
}

/// Generate a distinct but equal spelling so hash/equality coverage does not
/// depend on the fuzzer happening to find two equivalent independent inputs.
fn equivalent_part(part: &str) -> String {
    let mut out = String::new();
    let mut was_digit = false;
    for c in part.chars() {
        if c.is_ascii_digit() && !was_digit {
            out.push('0');
        }
        out.push(c);
        was_digit = c.is_ascii_digit();
    }
    if !was_digit {
        out.push('0');
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Newline-separated versions make readable corpus seeds possible; a
    // single version still exercises comparison and equivalent spellings.
    let mut texts = text.splitn(3, '\n');
    let a = texts.next().unwrap_or_default();
    let b = texts.next().unwrap_or(a);
    let c = texts.next().unwrap_or(b);
    let (Ok(a), Ok(b), Ok(c)) = (
        DpkgVersion::parse(a),
        DpkgVersion::parse(b),
        DpkgVersion::parse(c),
    ) else {
        return;
    };
    let versions = [a, b, c];
    for a in &versions {
        assert_eq!(a.cmp(a), Ordering::Equal);
        let equivalent = DpkgVersion {
            epoch: a.epoch,
            upstream_version: equivalent_part(&a.upstream_version),
            debian_revision: if a.debian_revision.is_empty() {
                String::new()
            } else {
                equivalent_part(&a.debian_revision)
            },
        };
        assert_eq!(a, &equivalent);
        check_pair(a, &equivalent);
        for b in &versions {
            check_pair(a, b);
            for c in &versions {
                if a <= b && b <= c {
                    assert!(a <= c);
                }
            }
        }
    }
});

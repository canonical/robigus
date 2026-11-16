//! Fuzz target: the parser must never panic on arbitrary input, and any
//! successfully parsed predicate must round-trip through both display and
//! parse → canonicalize → display → parse (spec §4.3, §16).

#![no_main]

use libfuzzer_sys::fuzz_target;
use robigus::Predicate;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(predicate) = Predicate::parse(text) else {
        return;
    };
    let display = predicate.to_string();
    let reparsed = Predicate::parse(&display)
        .unwrap_or_else(|error| panic!("display output must parse: {error}; text: {display}"));
    assert_eq!(reparsed, predicate, "display must round-trip: {display}");

    let canonical = predicate.canonicalized();
    let canonical_text = canonical.to_string();
    let reparsed = Predicate::parse(&canonical_text).unwrap_or_else(|error| {
        panic!("canonical display must parse: {error}; text: {canonical_text}")
    });
    assert_eq!(
        reparsed, canonical,
        "canonical display must round-trip: {canonical_text}"
    );
    assert_eq!(
        reparsed.canonicalized(),
        canonical,
        "canonicalization must be idempotent: {canonical_text}"
    );
    assert_eq!(reparsed.to_string(), canonical_text);
});

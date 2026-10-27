//! Fuzz target: the parser must never panic on arbitrary input, and any
//! successfully parsed predicate must display to text that parses back to the
//! same predicate (spec §4.3, §16).

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
});

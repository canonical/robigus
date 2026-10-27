//! Fuzz target: `parse → canonicalize → display → parse` must succeed and be
//! stable (plan WP-1.3; spec §4.3, §16).

#![no_main]

use libfuzzer_sys::fuzz_target;
use robigus::{MachineArch, Predicate};
use ubuntu_info_rust::Architecture;

fn take_byte(data: &mut &[u8]) -> Option<u8> {
    let (&first, rest) = data.split_first()?;
    *data = rest;
    Some(first)
}

/// Builds a short name from fuzzer bytes. The alphabet deliberately excludes
/// characters with syntactic meaning (`"`, `\`, `/`, `?`) so that generated
/// atoms are well-formed.
fn take_name(data: &mut &[u8]) -> String {
    let mut name = String::new();
    for _ in 0..6 {
        let Some(byte) = take_byte(data) else { break };
        match byte % 4 {
            0 => name.push('a'),
            1 => name.push('z'),
            2 => name.push('0'),
            _ => name.push('_'),
        }
    }
    if name.is_empty() {
        name.push('x');
    }
    name
}

fn take_arch(data: &mut &[u8]) -> MachineArch {
    let Some(byte) = take_byte(data) else {
        return MachineArch::All;
    };
    match byte % 10 {
        0..=7 => {
            let all = Architecture::ALL;
            MachineArch::Ubuntu(all[byte as usize % all.len()])
        }
        8 => MachineArch::All,
        _ => MachineArch::Unsupported("mips".into()),
    }
}

fn generate_atom(data: &mut &[u8]) -> Predicate {
    let Some(kind) = take_byte(data) else {
        return Predicate::TRUE;
    };
    match kind % 8 {
        0 => Predicate::feature(take_name(data)),
        1 => match take_byte(data) {
            Some(byte) if byte % 2 == 0 => {
                let package = take_name(data);
                let name = take_name(data);
                Predicate::qualified_feature(package, name)
            }
            _ => Predicate::feature(take_name(data)),
        },
        2 => {
            let key = take_name(data);
            let value = take_name(data);
            Predicate::cfg(key, value)
        }
        3 => Predicate::arch(take_arch(data)),
        4 => Predicate::platform(take_name(data)),
        5 => Predicate::build_profile(take_name(data)),
        6 => {
            let name = take_name(data);
            let value = take_name(data);
            Predicate::env(name, value)
        }
        _ => Predicate::series(take_name(data)),
    }
}

fn generate_at(data: &mut &[u8], depth: u8) -> Option<Predicate> {
    if depth == 0 {
        return Some(generate_atom(data));
    }
    match take_byte(data)? % 4 {
        0 => Some(generate_atom(data)),
        1 => {
            let count = (take_byte(data)? % 3) + 1;
            let mut operands = Vec::new();
            for _ in 0..count {
                operands.push(generate_at(data, depth - 1)?);
            }
            Some(Predicate::and(operands))
        }
        2 => {
            let count = (take_byte(data)? % 3) + 1;
            let mut operands = Vec::new();
            for _ in 0..count {
                operands.push(generate_at(data, depth - 1)?);
            }
            Some(Predicate::or(operands))
        }
        _ => {
            let inner = generate_at(data, depth - 1)?;
            Some(!inner)
        }
    }
}

fn generate(data: &mut &[u8]) -> Option<Predicate> {
    let depth = take_byte(data)? % 4;
    generate_at(data, depth)
}

fuzz_target!(|data: &[u8]| {
    let Some(predicate) = generate(&mut &data[..]) else {
        return;
    };
    let canonical = predicate.canonicalized();
    let text = canonical.to_string();
    let reparsed = Predicate::parse(&text)
        .unwrap_or_else(|error| panic!("canonical display must parse: {error}; text: {text}"));
    assert_eq!(
        reparsed, canonical,
        "canonical display must round-trip: {text}"
    );
    assert_eq!(
        reparsed.canonicalized(),
        canonical,
        "canonicalization must be idempotent: {text}"
    );
});

//! Socket-creation policy for the bubblewrap backend (spec §10.2).
//!
//! Host-backed trees are exposed through private read-only overlays, which
//! already separate host socket and FIFO inodes from the sandbox. This filter
//! is defence in depth: it prevents the workload from creating any socket that
//! could address a host pathname socket, regardless of mount behaviour.
//!
//! Policy:
//! - `socket()` is limited to `AF_INET`/`AF_INET6` (the network namespace has
//!   no route off the host; allowlisted egress goes through the in-namespace
//!   proxy listener, see `sandbox::proxy`);
//! - `socketpair()` is limited to fixed-peer `AF_UNIX` stream/seqpacket pairs,
//!   which cannot be reconnected to another peer;
//! - io_uring entry points are denied, since rings can perform socket
//!   operations without passing through the syscalls above;
//! - the kernel key-management syscalls are denied: namespaces do not isolate
//!   the session keyring, so otherwise the workload could read host secrets
//!   (for example credential-helper keys) stored there;
//! - foreign audit architectures, x32, and the historical untagged x32
//!   syscall range are killed.
//!
//! Only native 64-bit little-endian Linux x86-64, AArch64 and RISC-V are
//! supported; other targets fail closed.

#![forbid(unsafe_code)]

use std::fs::File;

/// The descriptor number bubblewrap reads the filter from.
pub(crate) const FILTER_FD: i32 = 3;

/// Builds the sealed, rewound filter file. The caller maps it to
/// [`FILTER_FD`] and passes `--seccomp 3` to bubblewrap. Errors are fatal:
/// callers must never run a workload without this filter.
pub(crate) fn filter_file() -> Result<File, String> {
    #[cfg(all(
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ))]
    {
        supported::filter_file()
    }
    #[cfg(not(all(
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    )))]
    {
        Err(format!(
            "sandbox seccomp is unsupported on {}/{}; use native little-endian 64-bit Linux x86_64, aarch64 or riscv64",
            std::env::consts::OS,
            std::env::consts::ARCH
        ))
    }
}

#[cfg(all(
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )
))]
mod supported {
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::{Seek, Write};

    use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch, sock_filter,
    };

    // Classic BPF opcodes and `seccomp_data` offsets from the Linux UAPI.
    // Only forward jumps are used, and the compiled socket policy is appended
    // unchanged, so jump targets cannot escape the program.
    pub(super) const LD_W_ABS: u16 = 0x20;
    pub(super) const JMP_JEQ_K: u16 = 0x15;
    pub(super) const JMP_JGE_K: u16 = 0x35;
    pub(super) const JMP_JSET_K: u16 = 0x45;
    pub(super) const RET_K: u16 = 0x06;
    const NR_OFFSET: u32 = 0;
    const ARCH_OFFSET: u32 = 4;
    pub(super) const X32_BIT: u32 = 0x4000_0000;
    pub(super) const KILL: u32 = 0x8000_0000; // SECCOMP_RET_KILL_PROCESS
    pub(super) const ALLOW: u32 = 0x7fff_0000;
    pub(super) const DENY: u32 = 0x0005_0000 | libc::EPERM as u32; // SECCOMP_RET_ERRNO

    fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
        sock_filter { code, jt, jf, k }
    }

    pub(super) fn architecture() -> Result<(TargetArch, u32), String> {
        match std::env::consts::ARCH {
            "x86_64" => Ok((TargetArch::x86_64, 0xc000_003e)),
            "aarch64" => Ok((TargetArch::aarch64, 0xc000_00b7)),
            "riscv64" => Ok((TargetArch::riscv64, 0xc000_00f3)),
            arch => Err(format!("unsupported sandbox seccomp architecture: {arch}")),
        }
    }

    pub(super) fn abi_guard(arch: u32, x86_64: bool) -> BpfProgram {
        let mut guard = vec![
            instruction(LD_W_ABS, 0, 0, ARCH_OFFSET),
            instruction(JMP_JEQ_K, 1, 0, arch),
            instruction(RET_K, 0, 0, KILL),
            instruction(LD_W_ABS, 0, 0, NR_OFFSET),
        ];
        if x86_64 {
            // AUDIT_ARCH_X86_64 is shared by x86-64 and x32, so the arch check
            // alone leaves x32-tagged syscall numbers outside ordinary rules.
            guard.extend([
                instruction(JMP_JSET_K, 0, 1, X32_BIT),
                instruction(RET_K, 0, 0, KILL),
                // Kernels before 5.4 also accepted untagged x32 numbers
                // 512..=547; deny the whole reserved range.
                instruction(JMP_JGE_K, 0, 2, 512),
                instruction(JMP_JGE_K, 1, 0, 548),
                instruction(RET_K, 0, 0, KILL),
            ]);
        }
        guard
    }

    fn condition(index: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompCondition, String> {
        // Linux reads these socket arguments as 32-bit integers; compare only
        // the low word so high-register-bit aliases cannot bypass the rule.
        SeccompCondition::new(index, SeccompCmpArgLen::Dword, op, value)
            .map_err(|error| format!("cannot build sandbox socket condition: {error}"))
    }

    fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule, String> {
        SeccompRule::new(conditions)
            .map_err(|error| format!("cannot build sandbox socket rule: {error}"))
    }

    pub(super) fn policy() -> Result<BpfProgram, String> {
        let (target, audit_arch) = architecture()?;
        let mut rules = BTreeMap::new();
        rules.insert(
            libc::SYS_socket,
            [libc::AF_INET, libc::AF_INET6]
                .into_iter()
                .map(|family| rule(vec![condition(0, SeccompCmpOp::Eq, family as u64)?]))
                .collect::<Result<Vec<_>, String>>()?,
        );
        // Mask only the two permitted modifiers; every other type bit must
        // match an allowed base type, so unknown flags are not ignored.
        let type_mask = u64::from(!(libc::SOCK_CLOEXEC as u32 | libc::SOCK_NONBLOCK as u32));
        rules.insert(
            libc::SYS_socketpair,
            [libc::SOCK_STREAM, libc::SOCK_SEQPACKET]
                .into_iter()
                .map(|kind| {
                    rule(vec![
                        condition(0, SeccompCmpOp::Eq, libc::AF_UNIX as u64)?,
                        condition(1, SeccompCmpOp::MaskedEq(type_mask), kind as u64)?,
                    ])
                })
                .collect::<Result<Vec<_>, String>>()?,
        );
        // `SeccompFilter::new(rules, mismatch_action, match_action, arch)`:
        // a rule match allows the call; any other socket/socketpair is denied.
        let socket_policy: BpfProgram = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            target,
        )
        .map_err(|error| format!("cannot build sandbox seccomp filter: {error}"))?
        .try_into()
        .map_err(|error| format!("cannot compile sandbox seccomp filter: {error}"))?;

        let mut program = abi_guard(audit_arch, std::env::consts::ARCH == "x86_64");
        // Route socket/socketpair to the compiled policy, deny the listed
        // syscalls, and allow everything else. Each denied syscall takes two
        // instructions, so the socket jumps skip over the denials and the final
        // ALLOW to land on the compiled policy's first instruction.
        let denied = denied_syscalls();
        let skip = u8::try_from(denied.len() * 2 + 1)
            .map_err(|_| "sandbox seccomp deny list is too long".to_string())?;
        program.push(instruction(JMP_JEQ_K, skip + 1, 0, libc::SYS_socket as u32));
        program.push(instruction(JMP_JEQ_K, skip, 0, libc::SYS_socketpair as u32));
        for nr in denied {
            program.push(instruction(JMP_JEQ_K, 0, 1, nr as u32));
            program.push(instruction(RET_K, 0, 0, DENY));
        }
        program.push(instruction(RET_K, 0, 0, ALLOW));
        program.extend(socket_policy);
        if program.len() > 4096 {
            return Err("sandbox seccomp exceeds Linux's 4096-instruction limit".into());
        }
        Ok(program)
    }

    /// Syscalls denied with `EPERM` regardless of arguments.
    pub(super) fn denied_syscalls() -> [libc::c_long; 6] {
        [
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
        ]
    }

    pub(super) fn serialize(program: &[sock_filter]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(program.len() * 8);
        for op in program {
            // struct sock_filter is u16, u8, u8, u32 in native byte order;
            // serialize fields explicitly rather than Rust struct memory.
            bytes.extend_from_slice(&op.code.to_ne_bytes());
            bytes.extend_from_slice(&[op.jt, op.jf]);
            bytes.extend_from_slice(&op.k.to_ne_bytes());
        }
        bytes
    }

    pub(super) fn filter_file() -> Result<File, String> {
        let program = policy()?;
        let fd = memfd_create(
            "robigus-seccomp",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .map_err(|error| format!("cannot create anonymous sandbox seccomp file: {error}"))?;
        let mut file = File::from(fd);
        file.write_all(&serialize(&program))
            .and_then(|()| file.rewind())
            .map_err(|error| format!("cannot write sandbox seccomp file: {error}"))?;
        fcntl_add_seals(
            &file,
            SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
        )
        .map_err(|error| format!("cannot seal sandbox seccomp file: {error}"))?;
        Ok(file)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // Evaluate the generated BPF without installing a filter on the test
        // runner. An unknown opcode fails the test.
        fn evaluate(program: &[sock_filter], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
            let mut data = [0u8; 64];
            data[0..4].copy_from_slice(&nr.to_ne_bytes());
            data[4..8].copy_from_slice(&arch.to_ne_bytes());
            for (index, arg) in args.iter().enumerate() {
                data[16 + index * 8..24 + index * 8].copy_from_slice(&arg.to_ne_bytes());
            }
            let mut accumulator = 0;
            let mut pc = 0;
            for _ in 0..program.len() {
                let op = &program[pc];
                pc += 1;
                match op.code {
                    LD_W_ABS => {
                        let offset = op.k as usize;
                        accumulator =
                            u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap());
                    }
                    0x54 => accumulator &= op.k, // ALU AND K
                    0x05 => pc += op.k as usize, // JMP JA
                    JMP_JEQ_K | JMP_JGE_K | JMP_JSET_K | 0x25 => {
                        let yes = match op.code {
                            JMP_JEQ_K => accumulator == op.k,
                            JMP_JGE_K => accumulator >= op.k,
                            JMP_JSET_K => accumulator & op.k != 0,
                            0x25 => accumulator > op.k,
                            _ => unreachable!(),
                        };
                        pc += usize::from(if yes { op.jt } else { op.jf });
                    }
                    RET_K => return op.k,
                    code => panic!("unsupported generated BPF opcode: {code:#x}"),
                }
            }
            panic!("BPF did not terminate");
        }

        #[test]
        fn socket_families_and_integer_width() {
            let program = policy().unwrap();
            let arch = architecture().unwrap().1;
            for family in 0..=64 {
                let expected = if family == libc::AF_INET || family == libc::AF_INET6 {
                    ALLOW
                } else {
                    DENY
                };
                for upper in [0, 0xabcd_0000_0000_0000] {
                    assert_eq!(
                        evaluate(
                            &program,
                            libc::SYS_socket as u32,
                            arch,
                            [upper | family as u64, 0, 0, 0, 0, 0]
                        ),
                        expected,
                        "family {family}, upper {upper:#x}"
                    );
                }
            }
            assert_eq!(
                evaluate(&program, libc::SYS_getpid as u32, arch, [0; 6]),
                ALLOW
            );
        }

        #[test]
        fn pairs_allow_only_fixed_peers_and_known_flags() {
            let program = policy().unwrap();
            let arch = architecture().unwrap().1;
            for family in [libc::AF_UNIX, libc::AF_INET, libc::AF_INET6, libc::AF_VSOCK] {
                for kind in 0..=16 {
                    for flags in [
                        0,
                        libc::SOCK_CLOEXEC,
                        libc::SOCK_NONBLOCK,
                        libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                        0x100,
                        i32::MIN,
                    ] {
                        let expected = if family == libc::AF_UNIX
                            && [libc::SOCK_STREAM, libc::SOCK_SEQPACKET].contains(&kind)
                            && flags & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) == 0
                        {
                            ALLOW
                        } else {
                            DENY
                        };
                        assert_eq!(
                            evaluate(
                                &program,
                                libc::SYS_socketpair as u32,
                                arch,
                                [family as u64, (kind | flags) as u32 as u64, 0, 0, 0, 0]
                            ),
                            expected,
                            "family {family}, kind {kind}, flags {flags:#x}"
                        );
                    }
                }
            }
        }

        #[test]
        fn io_uring_and_compatibility_abis_are_blocked() {
            let program = policy().unwrap();
            let arch = architecture().unwrap().1;
            for nr in denied_syscalls() {
                assert_eq!(evaluate(&program, nr as u32, arch, [0; 6]), DENY);
            }
            for foreign in [
                0,
                0x4000_0003,
                0x4000_0028,
                0xc000_003e,
                0xc000_00b7,
                0xc000_00f3,
            ] {
                if foreign != arch {
                    assert_eq!(
                        evaluate(&program, libc::SYS_socket as u32, foreign, [0; 6]),
                        KILL
                    );
                }
            }
            // Exercise the x86 guard regardless of the native test ISA.
            let mut x86 = abi_guard(0xc000_003e, true);
            x86.push(instruction(RET_K, 0, 0, ALLOW));
            for nr in 512..=547 {
                assert_eq!(evaluate(&x86, nr, 0xc000_003e, [0; 6]), KILL);
            }
            for nr in [0, 41, 53, 425, 511, 512, 547, 548, 10000] {
                assert_eq!(evaluate(&x86, nr | X32_BIT, 0xc000_003e, [0; 6]), KILL);
            }
            for nr in [0, 511, 548] {
                assert_eq!(evaluate(&x86, nr, 0xc000_003e, [0; 6]), ALLOW);
            }
        }

        #[test]
        fn filter_is_rewound_sealed_and_field_serialized() {
            use std::io::Read;
            let program = policy().unwrap();
            let expected = serialize(&program);
            assert_eq!(expected.len(), program.len() * 8);
            assert_eq!(&expected[..2], &program[0].code.to_ne_bytes());
            let mut file = filter_file().unwrap();
            let mut actual = Vec::new();
            file.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, expected);
            assert!(file.write_all(b"change").is_err());
            assert!(file.set_len(0).is_err());
        }
    }
}

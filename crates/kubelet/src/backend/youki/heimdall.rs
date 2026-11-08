//! Feature `heimdall-seccomp`: a pod's seccomp profile (`linux.seccomp` of its
//! OCI spec) is compiled by Heimdall's classic-BPF builder instead of the
//! shim's default backend.
//!
//! Heimdall (git.gunnar.rs nordisk/heimdall, AGPL-3.0-only; a shim built with
//! this feature is AGPL-3.0-only as a whole) ships its builder as a backend of
//! youki's `SeccompBackend` trait (youki PR 3873): `heimdall-youki`, vendored
//! in `vendor/heimdall-youki`. `vendor/libcontainer` carries the same trait,
//! and the shim registers Heimdall's backend for its containers before it
//! builds one ([`register`]); libcontainer's init process then compiles and
//! installs the container's profile with it. The shim's own wait-phase filter
//! keeps the default backend.
//!
//! Heimdall reads the profiles its profiler writes: default
//! `SCMP_ACT_KILL_PROCESS`, the native architecture, `ALLOW` / `ERRNO` rules
//! with argument conditions. Every program it builds starts with the
//! architecture check, the x32 kill and the kernel-implied base set
//! (`restart_syscall`, `rt_sigreturn`, `exit`, `exit_group`).
//!
//! A profile Heimdall does not read (it refuses it by name: another default
//! action, several architectures; for example `RuntimeDefault`, moby's
//! profile, which the kubelet gives every pod that names no profile under
//! seccompDefault) is compiled by the shim's default backend instead, so the
//! pod starts under that profile, never unconfined. A profile Heimdall reads
//! but cannot build here (another architecture than the host's, a program
//! too long) is refused, and the shim says why.

use libcontainer::seccomp::{CompiledSeccomp, SeccompBackend, SeccompError};
use oci_spec::runtime::LinuxSeccomp;

/// The shim's default backend: the one a profile Heimdall does not read goes to.
#[cfg(not(feature = "seccomp-listener"))]
static DEFAULT: libcontainer::seccomp::SeccompBpfBackend = libcontainer::seccomp::SeccompBpfBackend;
#[cfg(feature = "seccomp-listener")]
static DEFAULT: libcontainer::seccomp::LibseccompBackend = libcontainer::seccomp::LibseccompBackend;

/// Heimdall's builder for the profiles it reads, the default backend for the
/// ones it refuses by kind (see the module docs).
struct HeimdallFirst;

impl SeccompBackend for HeimdallFirst {
    fn name(&self) -> &'static str {
        heimdall_youki::NAME
    }

    fn compile(&self, seccomp: &LinuxSeccomp) -> Result<CompiledSeccomp, SeccompError> {
        // The trait has no error of a backend's own: the reason travels as
        // an io::Error in LoadProgram, with the backend's message.
        let err = |e: String| SeccompError::LoadProgram {
            source: std::io::Error::other(e),
        };
        let json = serde_json::to_string(seccomp).map_err(|e| err(e.to_string()))?;
        match heimdall_youki::compile_oci_json(&json) {
            Ok(c) => Ok(CompiledSeccomp::from_program(
                c.program
                    .iter()
                    .map(|i| libcontainer::seccomp::SockFilter {
                        code: i.code,
                        jt: i.jt,
                        jf: i.jf,
                        k: i.k,
                    })
                    .collect(),
                c.flags,
                c.wants_listener,
            )),
            // not Heimdall's kind of profile: the default backend's program
            Err(heimdall_youki::BackendError::Profile(_)) => DEFAULT.compile(seccomp),
            Err(e) => Err(err(e.to_string())),
        }
    }
}

/// Make Heimdall's builder the seccomp backend of the containers this
/// process creates (once per process; a second call is a no-op).
pub fn register() -> Result<(), String> {
    use libcontainer::seccomp::{container_backend, set_container_backend};
    static HEIMDALL: HeimdallFirst = HeimdallFirst;
    if set_container_backend(&HEIMDALL).is_ok()
        || container_backend().name() == heimdall_youki::NAME
    {
        return Ok(());
    }
    Err(format!(
        "the containers' seccomp backend is already {:?}, not Heimdall's",
        container_backend().name()
    ))
}

#[cfg(test)]
mod tests {
    //! Each bench pod profile (tunnr, `fixtures/heimdall-seccomp/SOURCE.md`)
    //! through the shim's container backend gives the same answer as
    //! libseccomp's filter for the same profile, for every syscall number and
    //! the argument values the profile's conditions decide on, both programs
    //! run in a classic-BPF interpreter.

    use libcontainer::seccomp::{container_backend, SeccompBackend};
    use oci_spec::runtime::{LinuxSeccomp, LinuxSeccompAction, LinuxSeccompOperator};

    const PROFILES: [(&str, &str); 3] = [
        (
            "pod-busybox",
            include_str!("fixtures/heimdall-seccomp/pod-busybox.x86_64-glibc.oci.json"),
        ),
        (
            "pod-iperf3",
            include_str!("fixtures/heimdall-seccomp/pod-iperf3.x86_64-glibc.oci.json"),
        ),
        (
            "pod-nginx-alpine",
            include_str!("fixtures/heimdall-seccomp/pod-nginx-alpine.x86_64-musl.oci.json"),
        ),
    ];

    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const AUDIT_ARCH_I386: u32 = 0x4000_0003;
    const X32_BIT: i32 = 0x4000_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;
    const RET_ACTION_FULL: u32 = 0xffff_0000;

    /// One classic-BPF instruction.
    #[derive(Clone, Copy, Debug)]
    struct Insn {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    /// `struct seccomp_data` (64 bytes, native byte order).
    fn data(nr: i32, arch: u32, args: [u64; 6]) -> [u8; 64] {
        let mut d = [0u8; 64];
        d[0..4].copy_from_slice(&nr.to_ne_bytes());
        d[4..8].copy_from_slice(&arch.to_ne_bytes());
        for (i, a) in args.iter().enumerate() {
            d[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_ne_bytes());
        }
        d
    }

    /// A classic-BPF interpreter for every instruction the kernel's seccomp
    /// checker accepts (loads of `seccomp_data` words, the scratch memory,
    /// the ALU, jumps, returns, TAX/TXA). Anything else panics.
    fn run(prog: &[Insn], d: &[u8; 64]) -> u32 {
        let (mut a, mut x) = (0u32, 0u32);
        let mut mem = [0u32; 16];
        let mut pc = 0usize;
        let mut steps = 0usize;
        loop {
            steps += 1;
            assert!(steps <= 4096, "the program does not end");
            let i = *prog
                .get(pc)
                .unwrap_or_else(|| panic!("pc {pc} past the end"));
            pc += 1;
            let src = if i.code & 0x08 != 0 { x } else { i.k };
            match i.code & 0x07 {
                // LD / LDX
                0x00 | 0x01 => {
                    let v = match i.code & 0xe0 {
                        0x00 => i.k,
                        0x20 => {
                            assert_eq!(i.code & 0x18, 0x00, "only word loads: {i:?}");
                            let off = i.k as usize;
                            assert!(off.is_multiple_of(4) && off + 4 <= 64, "load at {off}");
                            u32::from_ne_bytes(d[off..off + 4].try_into().unwrap())
                        }
                        0x60 => mem[i.k as usize],
                        0x80 => 64,
                        m => panic!("load mode {m:#x}: {i:?}"),
                    };
                    if i.code & 0x07 == 0 {
                        a = v
                    } else {
                        x = v
                    }
                }
                0x02 => mem[i.k as usize] = a,
                0x03 => mem[i.k as usize] = x,
                0x04 => {
                    a = match i.code & 0xf0 {
                        0x00 => a.wrapping_add(src),
                        0x10 => a.wrapping_sub(src),
                        0x20 => a.wrapping_mul(src),
                        0x30 => a.checked_div(src).expect("division by 0"),
                        0x40 => a | src,
                        0x50 => a & src,
                        0x60 => a.checked_shl(src).unwrap_or(0),
                        0x70 => a.checked_shr(src).unwrap_or(0),
                        0x80 => a.wrapping_neg(),
                        0x90 => a.checked_rem(src).expect("modulo 0"),
                        0xa0 => a ^ src,
                        op => panic!("alu op {op:#x}"),
                    }
                }
                0x05 => {
                    let off = match i.code & 0xf0 {
                        0x00 => i.k as usize,
                        0x10 => usize::from(if a == src { i.jt } else { i.jf }),
                        0x20 => usize::from(if a > src { i.jt } else { i.jf }),
                        0x30 => usize::from(if a >= src { i.jt } else { i.jf }),
                        0x40 => usize::from(if a & src != 0 { i.jt } else { i.jf }),
                        op => panic!("jump op {op:#x}"),
                    };
                    pc += off;
                }
                0x06 => {
                    return match i.code & 0x18 {
                        0x00 => i.k,
                        0x10 => a,
                        r => panic!("ret source {r:#x}"),
                    }
                }
                _ => match i.code & 0xf8 {
                    0x00 => x = a,
                    0x80 => a = x,
                    m => panic!("misc {m:#x}"),
                },
            }
        }
    }

    /// The kernel's answer for a stack of filters: the action of highest
    /// precedence (the lowest `(s32)(ret & SECCOMP_RET_ACTION_FULL)`).
    fn run_stack(stack: &[Vec<Insn>], d: &[u8; 64]) -> u32 {
        stack
            .iter()
            .map(|p| run(p, d))
            .min_by_key(|r| (r & RET_ACTION_FULL) as i32)
            .expect("an empty stack")
    }

    /// libseccomp's filter for the profile, with the OCI fields as runc and
    /// crun give them to libseccomp: one context with the profile's default,
    /// its architectures, one rule per name, a rule's argument comparisons
    /// together (split when one argument is compared twice), MASKED_EQ as
    /// `(arg & value) == valueTwo`. Exported as BPF by libseccomp itself.
    fn libseccomp_program(spec: &LinuxSeccomp) -> Vec<Insn> {
        use libseccomp::{
            ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall,
        };
        let action = |a: LinuxSeccompAction, errno: Option<u32>| match a {
            LinuxSeccompAction::ScmpActKillProcess => ScmpAction::KillProcess,
            LinuxSeccompAction::ScmpActKill | LinuxSeccompAction::ScmpActKillThread => {
                ScmpAction::KillThread
            }
            LinuxSeccompAction::ScmpActErrno => {
                ScmpAction::Errno(errno.map_or(libc::EPERM, |e| e as i32))
            }
            LinuxSeccompAction::ScmpActAllow => ScmpAction::Allow,
            LinuxSeccompAction::ScmpActLog => ScmpAction::Log,
            LinuxSeccompAction::ScmpActTrap => ScmpAction::Trap,
            other => panic!("the bench profiles have no {other:?}"),
        };
        let default = action(spec.default_action(), spec.default_errno_ret());
        let mut ctx = ScmpFilterContext::new(default).unwrap();
        for arch in spec.architectures().iter().flatten() {
            assert_eq!(*arch, oci_spec::runtime::Arch::ScmpArchX86_64);
            ctx.add_arch(ScmpArch::X8664).unwrap();
        }
        ctx.set_ctl_nnp(false).unwrap();
        for s in spec.syscalls().iter().flatten() {
            let act = action(s.action(), s.errno_ret());
            if act == default {
                continue;
            }
            for name in s.names() {
                let Ok(sc) = ScmpSyscall::from_name(name) else {
                    continue;
                };
                let args = s.args().clone().unwrap_or_default();
                if args.is_empty() {
                    ctx.add_rule(act, sc).unwrap();
                    continue;
                }
                let cmps: Vec<ScmpArgCompare> = args
                    .iter()
                    .map(|a| {
                        let (op, datum) = match a.op() {
                            LinuxSeccompOperator::ScmpCmpMaskedEq => (
                                ScmpCompareOp::MaskedEqual(a.value()),
                                a.value_two().unwrap_or(0),
                            ),
                            LinuxSeccompOperator::ScmpCmpEq => (ScmpCompareOp::Equal, a.value()),
                            LinuxSeccompOperator::ScmpCmpNe => (ScmpCompareOp::NotEqual, a.value()),
                            LinuxSeccompOperator::ScmpCmpLt => (ScmpCompareOp::Less, a.value()),
                            LinuxSeccompOperator::ScmpCmpLe => {
                                (ScmpCompareOp::LessOrEqual, a.value())
                            }
                            LinuxSeccompOperator::ScmpCmpGe => {
                                (ScmpCompareOp::GreaterEqual, a.value())
                            }
                            LinuxSeccompOperator::ScmpCmpGt => (ScmpCompareOp::Greater, a.value()),
                        };
                        ScmpArgCompare::new(a.index() as u32, op, datum)
                    })
                    .collect();
                let mut seen = std::collections::HashSet::new();
                if args.iter().all(|a| seen.insert(a.index())) {
                    ctx.add_rule_conditional(act, sc, &cmps).unwrap();
                } else {
                    for c in &cmps {
                        ctx.add_rule_conditional(act, sc, std::slice::from_ref(c))
                            .unwrap();
                    }
                }
            }
        }
        let mut f = tempfile::tempfile().unwrap();
        ctx.export_bpf(&f).unwrap();
        use std::io::{Read, Seek};
        f.rewind().unwrap();
        let mut b = Vec::new();
        f.read_to_end(&mut b).unwrap();
        assert!(
            !b.is_empty() && b.len() % 8 == 0,
            "libseccomp exported {} bytes",
            b.len()
        );
        b.chunks(8)
            .map(|c| Insn {
                code: u16::from_ne_bytes([c[0], c[1]]),
                jt: c[2],
                jf: c[3],
                k: u32::from_ne_bytes([c[4], c[5], c[6], c[7]]),
            })
            .collect()
    }

    /// The inputs: every syscall number 0..=600 and a few far ones, with
    /// argument vectors built from the values the profile's conditions name
    /// (each value, its neighbours, the bits outside the mask, a high word),
    /// combined over the compared arguments, plus fixed pseudo-random vectors.
    fn inputs(spec: &LinuxSeccomp) -> Vec<(i32, [u64; 6])> {
        let mut nrs: Vec<i32> = (0..=600).collect();
        nrs.extend([1000, 4095, 0x3fff_ffff, -1]);
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut plain: Vec<[u64; 6]> = vec![[0; 6], [u64::MAX; 6]];
        for _ in 0..6 {
            plain.push([rnd(), rnd(), rnd(), rnd(), rnd(), rnd()]);
        }
        // per syscall number: per argument index, the candidate values
        let mut cond: std::collections::BTreeMap<i32, [Vec<u64>; 6]> = Default::default();
        for s in spec.syscalls().iter().flatten() {
            for a in s.args().iter().flatten() {
                for name in s.names() {
                    let Ok(sc) = libseccomp::ScmpSyscall::from_name(name) else {
                        continue;
                    };
                    let e = cond.entry(i32::from(sc)).or_default();
                    let (v, w) = (a.value(), a.value_two().unwrap_or(0));
                    e[a.index()].extend([
                        0,
                        u64::MAX,
                        v,
                        w,
                        w ^ 1,
                        w.wrapping_add(1),
                        w.wrapping_sub(1),
                        w | (1 << 32),
                        w | !v,
                        (w | !v) & 0xffff_ffff,
                        v.wrapping_add(1),
                        v.wrapping_sub(1),
                    ]);
                }
            }
        }
        let mut out = Vec::new();
        for nr in nrs {
            for p in &plain {
                out.push((nr, *p));
            }
            let Some(per) = cond.get(&nr) else { continue };
            let mut vecs: Vec<[u64; 6]> = vec![[0; 6]];
            for (i, vals) in per.iter().enumerate() {
                if vals.is_empty() {
                    continue;
                }
                let mut vals = vals.clone();
                vals.sort_unstable();
                vals.dedup();
                vecs = vecs
                    .iter()
                    .flat_map(|v| {
                        vals.iter().map(move |x| {
                            let mut v = *v;
                            v[i] = *x;
                            v
                        })
                    })
                    .collect();
            }
            out.extend(vecs.into_iter().map(|v| (nr, v)));
        }
        out
    }

    /// What a caller sees: allowed, an errno, or killed.
    fn class(ret: u32) -> &'static str {
        match ret & RET_ACTION_FULL {
            RET_ALLOW | 0x7ffc_0000 => "allow",
            0x0005_0000 => "errno",
            _ => "deny",
        }
    }

    fn program_of(name: &str, json: &str) -> (LinuxSeccomp, Vec<Insn>) {
        let spec: LinuxSeccomp = serde_json::from_str(json).unwrap();
        crate::backend::youki::heimdall::register().unwrap();
        let backend = container_backend();
        let c = backend
            .compile(&spec)
            .unwrap_or_else(|e| panic!("{name}: the container backend refused it: {e}"));
        let prog = c.program().unwrap_or_else(|| {
            panic!(
                "{name}: the container backend is {:?}, which gave no single program (Heimdall's builder gives one)",
                backend.name()
            )
        });
        assert!(!c.wants_listener, "{name}");
        let prog = prog
            .iter()
            .map(|i| Insn {
                code: i.code,
                jt: i.jt,
                jf: i.jf,
                k: i.k,
            })
            .collect();
        (spec, prog)
    }

    #[test]
    fn the_shims_containers_get_heimdalls_builder() {
        super::register().unwrap();
        assert_eq!(container_backend().name(), "heimdall");
        // a second registration changes nothing
        super::register().unwrap();
        assert_eq!(container_backend().name(), "heimdall");
    }

    #[test]
    fn the_shim_binary_registers_it_before_anything_else() {
        // A bad command line still goes through the shim's start.
        assert_eq!(crate::backend::youki::shim::main(vec!["shim".into()]), 2);
        assert_eq!(container_backend().name(), "heimdall");
    }

    #[test]
    fn each_bench_pod_profile_answers_as_libseccomp_does() {
        for (name, json) in PROFILES {
            let (spec, heimdall) = program_of(name, json);
            let reference = libseccomp_program(&spec);
            let mut checked = 0usize;
            let (mut allowed, mut errno, mut denied) = (0usize, 0usize, 0usize);
            for (nr, args) in inputs(&spec) {
                let d = data(nr, AUDIT_ARCH_X86_64, args);
                let (h, l) = (run(&heimdall, &d), run(&reference, &d));
                assert_eq!(
                    h, l,
                    "{name}: syscall {nr} args {args:x?}: Heimdall {h:#x}, libseccomp {l:#x}"
                );
                match class(h) {
                    "allow" => allowed += 1,
                    "errno" => errno += 1,
                    _ => denied += 1,
                }
                checked += 1;
            }
            // other ABIs: denied by both (Heimdall kills the process,
            // libseccomp gives its bad-arch action)
            for nr in [0, 1, 2, 59, 60, 231] {
                for d in [
                    data(nr, AUDIT_ARCH_I386, [0; 6]),
                    data(nr | X32_BIT, AUDIT_ARCH_X86_64, [0; 6]),
                ] {
                    let (h, l) = (run(&heimdall, &d), run(&reference, &d));
                    assert_eq!(class(h), "deny", "{name}: Heimdall {h:#x} for nr {nr:#x}");
                    assert_eq!(class(l), "deny", "{name}: libseccomp {l:#x} for nr {nr:#x}");
                    checked += 1;
                }
            }
            assert!(
                allowed > 50 && errno > 0 && denied > 300,
                "{name}: {allowed}/{errno}/{denied}"
            );
            eprintln!(
                "{name}: {checked} inputs, the same answer ({allowed} allowed, {errno} errno, {denied} killed); Heimdall {} insns, libseccomp {} insns",
                heimdall.len(),
                reference.len()
            );
        }
    }

    #[test]
    fn heimdalls_own_interpreter_agrees() {
        // The same programs through heimdall-seccomp's interpreter.
        for (name, json) in PROFILES {
            let (spec, prog) = program_of(name, json);
            let hp: Vec<heimdall_seccomp::bpf::SockFilter> = prog
                .iter()
                .map(|i| heimdall_seccomp::bpf::SockFilter {
                    code: i.code,
                    jt: i.jt,
                    jf: i.jf,
                    k: i.k,
                })
                .collect();
            for (nr, args) in inputs(&spec) {
                let sd = heimdall_seccomp::notif::SeccompData {
                    nr,
                    arch: AUDIT_ARCH_X86_64,
                    instruction_pointer: 0,
                    args,
                };
                let theirs = heimdall_seccomp::interp::run(&hp, &sd).unwrap();
                assert_eq!(
                    theirs,
                    run(&prog, &data(nr, AUDIT_ARCH_X86_64, args)),
                    "{name} {nr}"
                );
            }
        }
    }

    #[test]
    fn the_old_default_answers_the_same_as_well() {
        // The shim's default backend (seccompiler's stack) on the same inputs.
        let ours = libcontainer::seccomp::SeccompBpfBackend;
        for (name, json) in PROFILES {
            let (spec, heimdall) = program_of(name, json);
            let c = ours.compile(&spec).unwrap();
            let stack: Vec<Vec<Insn>> = c
                .stack()
                .unwrap()
                .iter()
                .map(|p| {
                    p.iter()
                        .map(|i| Insn {
                            code: i.code,
                            jt: i.jt,
                            jf: i.jf,
                            k: i.k,
                        })
                        .collect()
                })
                .collect();
            for (nr, args) in inputs(&spec) {
                let d = data(nr, AUDIT_ARCH_X86_64, args);
                let (h, s) = (run(&heimdall, &d), run_stack(&stack, &d));
                assert_eq!(
                    h, s,
                    "{name}: syscall {nr} args {args:x?}: Heimdall {h:#x}, seccompiler {s:#x}"
                );
            }
        }
    }

    #[test]
    fn a_profile_heimdall_does_not_read_is_compiled_by_the_default_backend() {
        // moby's RuntimeDefault, which the kubelet gives every pod that names
        // no profile under seccompDefault (the OVN pods of the bench): an
        // ERRNO default and three architectures. Heimdall's builder refuses
        // it by name; the container still starts, under the program the
        // default backend builds for it, never unconfined.
        super::register().unwrap();
        let spec: LinuxSeccomp = serde_json::from_value(
            crate::seccomp::to_oci(crate::seccomp::RUNTIME_DEFAULT, &[], "6.12.0").unwrap(),
        )
        .unwrap();
        let refused = heimdall_youki::compile_oci_json(&serde_json::to_string(&spec).unwrap())
            .unwrap_err()
            .to_string();
        assert!(refused.contains("SCMP_ACT_ERRNO"), "{refused}");
        let ours = container_backend()
            .compile(&spec)
            .unwrap_or_else(|e| panic!("refused: {:#}", anyhow::Error::from(e)));
        let theirs = libcontainer::seccomp::SeccompBpfBackend
            .compile(&spec)
            .unwrap();
        assert!(ours.program().is_none(), "not Heimdall's program");
        assert_eq!(
            (
                format!("{:?}", ours.stack()),
                ours.flags,
                ours.wants_listener
            ),
            (
                format!("{:?}", theirs.stack()),
                theirs.flags,
                theirs.wants_listener
            )
        );
        // a profile Heimdall reads is still Heimdall's one program
        let (_, prog) = program_of(PROFILES[0].0, PROFILES[0].1);
        assert!(!prog.is_empty());
    }
}

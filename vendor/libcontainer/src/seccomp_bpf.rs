//! A pure-Rust seccomp backend: no libseccomp (a C library) is linked.
//!
//! (Rusternetes `node/rtclass` patch on libcontainer 0.7.0; a candidate
//! upstream youki change.) The OCI `linux.seccomp` is compiled to classic
//! BPF with seccompiler's backend (rust-vmm, the filter builder of
//! Firecracker), syscall names are resolved for the native architecture with
//! the `syscalls` crate, and the filters are installed with seccomp(2).
//!
//! seccompiler builds one filter per pair of actions (match / mismatch), so a
//! profile becomes a small STACK of filters, and the kernel takes the action
//! of highest precedence over all of them (`KILL_PROCESS > KILL_THREAD > TRAP
//! > ERRNO > TRACE > LOG > ALLOW`):
//!
//! * the base filter: every listed syscall (with its argument conditions)
//!   allows, everything else gets `defaultAction` (left out when the default
//!   is `SCMP_ACT_ALLOW`);
//! * one filter per other action (and errno): its syscalls get that action,
//!   everything else allows.
//!
//! A listed syscall therefore gets its own action, an unlisted one the
//! default, as with libseccomp. Differences from the libseccomp backend:
//!
//! * only the native architecture is filtered; a call made through another
//!   ABI (e.g. i386 `int 0x80` on x86_64) kills the process (fail closed);
//! * `SCMP_ACT_NOTIFY` (a seccomp listener) is refused: build with the
//!   `libseccomp` feature for that.

use std::collections::BTreeMap;
use std::os::unix::io;
use std::str::FromStr;

use oci_spec::runtime::{
    LinuxSeccomp, LinuxSeccompAction, LinuxSeccompArg, LinuxSeccompFilterFlag,
    LinuxSeccompOperator, LinuxSyscall,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("SCMP_ACT_NOTIFY cannot be used as default action")]
    NotifyAsDefaultAction,
    #[error("SCMP_ACT_NOTIFY cannot be used for the write syscall")]
    NotifyWriteSyscall,
    #[error("SCMP_ACT_NOTIFY needs a seccomp listener, which the pure-Rust seccomp backend does not have (build libcontainer with the libseccomp feature)")]
    NotifyUnsupported,
    #[error("the pure-Rust seccomp backend has no syscall table for this architecture")]
    UnsupportedArch,
    #[error("errno {errno} of {action:?} does not fit the 16 data bits of a seccomp return")]
    ActionData {
        action: LinuxSeccompAction,
        errno: u32,
    },
    #[error("argument {index} of syscall {name}: there are only 6")]
    ArgIndex { name: String, index: usize },
    #[error("syscall {name}: {source}")]
    Rule {
        name: String,
        source: seccompiler::BackendError,
    },
    #[error("failed to build the seccomp filter: {0}")]
    Filter(#[source] seccompiler::BackendError),
    #[error("failed to load the seccomp filter: {0}")]
    Load(#[source] std::io::Error),
    #[error("seccomp program is too long: {len} instructions")]
    ProgramTooLong { len: usize },
    #[error("failed to load seccomp program")]
    LoadProgram { source: std::io::Error },
}

type Result<T> = std::result::Result<T, SeccompError>;

fn native_arch() -> Result<TargetArch> {
    TargetArch::try_from(std::env::consts::ARCH).map_err(|_| SeccompError::UnsupportedArch)
}

fn translate_action(action: LinuxSeccompAction, errno: Option<u32>) -> Result<SeccompAction> {
    let data = |default: u32| -> Result<u32> {
        let e = errno.unwrap_or(default);
        if e > 0xffff {
            return Err(SeccompError::ActionData { action, errno: e });
        }
        Ok(e)
    };
    Ok(match action {
        // libseccomp: SCMP_ACT_KILL is SCMP_ACT_KILL_THREAD.
        LinuxSeccompAction::ScmpActKill | LinuxSeccompAction::ScmpActKillThread => {
            SeccompAction::KillThread
        }
        LinuxSeccompAction::ScmpActKillProcess => SeccompAction::KillProcess,
        LinuxSeccompAction::ScmpActTrap => SeccompAction::Trap,
        LinuxSeccompAction::ScmpActErrno => SeccompAction::Errno(data(libc::EPERM as u32)?),
        LinuxSeccompAction::ScmpActTrace => SeccompAction::Trace(data(libc::EPERM as u32)?),
        LinuxSeccompAction::ScmpActAllow => SeccompAction::Allow,
        LinuxSeccompAction::ScmpActLog => SeccompAction::Log,
        LinuxSeccompAction::ScmpActNotify => return Err(SeccompError::NotifyUnsupported),
    })
}

fn translate_op(arg: &LinuxSeccompArg) -> (SeccompCmpOp, u64) {
    match arg.op() {
        LinuxSeccompOperator::ScmpCmpNe => (SeccompCmpOp::Ne, arg.value()),
        LinuxSeccompOperator::ScmpCmpLt => (SeccompCmpOp::Lt, arg.value()),
        LinuxSeccompOperator::ScmpCmpLe => (SeccompCmpOp::Le, arg.value()),
        LinuxSeccompOperator::ScmpCmpEq => (SeccompCmpOp::Eq, arg.value()),
        LinuxSeccompOperator::ScmpCmpGe => (SeccompCmpOp::Ge, arg.value()),
        LinuxSeccompOperator::ScmpCmpGt => (SeccompCmpOp::Gt, arg.value()),
        // libseccomp: (arg & value) == valueTwo.
        LinuxSeccompOperator::ScmpCmpMaskedEq => (
            SeccompCmpOp::MaskedEq(arg.value()),
            arg.value_two().unwrap_or(0),
        ),
    }
}

fn check_seccomp(seccomp: &LinuxSeccomp) -> Result<()> {
    if seccomp.default_action() == LinuxSeccompAction::ScmpActNotify {
        return Err(SeccompError::NotifyAsDefaultAction);
    }
    for syscall in seccomp.syscalls().iter().flatten() {
        if syscall.action() == LinuxSeccompAction::ScmpActNotify {
            if syscall.names().iter().any(|n| n == "write") {
                return Err(SeccompError::NotifyWriteSyscall);
            }
            return Err(SeccompError::NotifyUnsupported);
        }
    }
    Ok(())
}

/// One syscall's rules in one filter: `None` matches the number alone.
type Chains = BTreeMap<i64, Option<Vec<SeccompRule>>>;

/// The rules an entry adds for one syscall (libseccomp compares each
/// argument once per rule: comparisons of the same argument become separate
/// rules, as runc and the libseccomp backend do).
fn entry_rules(name: &str, syscall: &LinuxSyscall) -> Result<Option<Vec<SeccompRule>>> {
    let Some(args) = syscall.args().as_ref().filter(|a| !a.is_empty()) else {
        return Ok(None);
    };
    let mut conds = Vec::with_capacity(args.len());
    let mut seen = std::collections::HashSet::new();
    let mut dup = false;
    for arg in args {
        let index = u8::try_from(arg.index())
            .ok()
            .filter(|i| *i < 6)
            .ok_or_else(|| SeccompError::ArgIndex {
                name: name.to_string(),
                index: arg.index(),
            })?;
        dup |= !seen.insert(index);
        let (op, value) = translate_op(arg);
        conds.push(
            SeccompCondition::new(index, SeccompCmpArgLen::Qword, op, value).map_err(|e| {
                SeccompError::Rule {
                    name: name.to_string(),
                    source: e,
                }
            })?,
        );
    }
    let rule = |c: Vec<SeccompCondition>| {
        SeccompRule::new(c).map_err(|e| SeccompError::Rule {
            name: name.to_string(),
            source: e,
        })
    };
    Ok(Some(if dup {
        conds
            .into_iter()
            .map(|c| rule(vec![c]))
            .collect::<Result<_>>()?
    } else {
        vec![rule(conds)?]
    }))
}

fn add(chains: &mut Chains, nr: i64, rules: Option<Vec<SeccompRule>>) {
    match (chains.get_mut(&nr), rules) {
        (None, r) => {
            chains.insert(nr, r);
        }
        // Already unconditional: stays so.
        (Some(None), _) => {}
        (Some(slot @ Some(_)), None) => *slot = None,
        (Some(Some(have)), Some(mut more)) => have.append(&mut more),
    }
}

fn to_filter(
    chains: Chains,
    mismatch: SeccompAction,
    on_match: SeccompAction,
    arch: TargetArch,
) -> Result<BpfProgram> {
    let rules = chains
        .into_iter()
        .map(|(nr, r)| (nr, r.unwrap_or_default()))
        .collect();
    let filter =
        SeccompFilter::new(rules, mismatch, on_match, arch).map_err(SeccompError::Filter)?;
    BpfProgram::try_from(filter).map_err(SeccompError::Filter)
}

/// The profile as the stack of BPF programs to install, in order.
pub fn compile(seccomp: &LinuxSeccomp) -> Result<Vec<BpfProgram>> {
    check_seccomp(seccomp)?;
    let arch = native_arch()?;
    let default = translate_action(seccomp.default_action(), seccomp.default_errno_ret())?;
    let mut base: Chains = BTreeMap::new();
    let mut groups: Vec<(SeccompAction, Chains)> = Vec::new();
    for syscall in seccomp.syscalls().iter().flatten() {
        let action = translate_action(syscall.action(), syscall.errno_ret())?;
        if action == default {
            // Redundant with the default (libseccomp refuses such rules).
            continue;
        }
        for name in syscall.names() {
            let Ok(nr) = syscalls::Sysno::from_str(name) else {
                // Not a syscall of this architecture (profiles list every
                // architecture's names): nothing to filter.
                tracing::debug!(?name, "seccomp: no such syscall on this architecture");
                continue;
            };
            let nr = nr.id() as i64;
            let rules = entry_rules(name, syscall)?;
            add(&mut base, nr, rules.clone());
            if action != SeccompAction::Allow {
                let i = match groups.iter().position(|(a, _)| *a == action) {
                    Some(i) => i,
                    None => {
                        groups.push((action.clone(), BTreeMap::new()));
                        groups.len() - 1
                    }
                };
                add(&mut groups[i].1, nr, rules);
            }
        }
    }
    let mut programs = Vec::with_capacity(groups.len() + 1);
    // The other actions first, the allowlist LAST: each filter is installed
    // with seccomp(2), which the filters already in place must allow — the
    // per-action ones allow everything else, the allowlist may not name
    // seccomp at all (tunnr lane layers: a measured profile without seccomp
    // in it killed the process installing it). The kernel takes the strictest
    // answer of the whole stack, so the order changes nothing else.
    for (action, chains) in groups {
        programs.push(to_filter(chains, SeccompAction::Allow, action, arch)?);
    }
    if default != SeccompAction::Allow {
        programs.push(to_filter(base, default, SeccompAction::Allow, arch)?);
    }
    if programs.is_empty() {
        // Allow everything: still a filter, so the process reports one.
        programs.push(to_filter(
            BTreeMap::new(),
            SeccompAction::Allow,
            SeccompAction::KillProcess,
            arch,
        )?);
    }
    Ok(programs)
}

fn filter_flags(seccomp: &LinuxSeccomp) -> libc::c_ulong {
    let mut flags: libc::c_ulong = 0;
    for flag in seccomp.flags().iter().flatten() {
        match flag {
            LinuxSeccompFilterFlag::SeccompFilterFlagLog => flags |= libc::SECCOMP_FILTER_FLAG_LOG,
            LinuxSeccompFilterFlag::SeccompFilterFlagTsync => {
                flags |= libc::SECCOMP_FILTER_FLAG_TSYNC
            }
            LinuxSeccompFilterFlag::SeccompFilterFlagSpecAllow => {
                flags |= libc::SECCOMP_FILTER_FLAG_SPEC_ALLOW
            }
            // Only meaningful with a listener, which this backend has not.
            LinuxSeccompFilterFlag::SeccompFilterFlagWaitKillableRecv => {}
        }
    }
    flags
}

/// Install one program on the calling thread (seccomp(2); the caller holds
/// CAP_SYS_ADMIN or has set no_new_privs, as the OCI runtime spec says).
fn load(program: &BpfProgram, flags: libc::c_ulong) -> Result<()> {
    let prog = libc::sock_fprog {
        len: program.len() as libc::c_ushort,
        filter: program.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: `prog` points at `program`, which outlives the call; the
    // kernel copies the instructions.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            flags,
            &prog as *const libc::sock_fprog,
        )
    };
    if rc != 0 {
        return Err(SeccompError::Load(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Compile and install the profile with this module's own backend
/// ([`SeccompBpfBackend`]). Never returns a listener fd (this backend refuses
/// `SCMP_ACT_NOTIFY`).
#[tracing::instrument(level = "trace", skip(seccomp))]
pub fn initialize_seccomp(seccomp: &LinuxSeccomp) -> Result<Option<io::RawFd>> {
    initialize_seccomp_with(&SeccompBpfBackend, seccomp)
}

// ---- youki PR 3873's seccomp backend trait, for the pure-Rust backend too
// (Rusternetes vendor patch). The same names and shapes as the trait in
// `seccomp/mod.rs` (the libseccomp module, which carries the PR as it is), so
// a backend written against youki's trait (Heimdall's, heimdall-youki)
// builds against either module.

// Same layout as the kernel's struct sock_filter.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[derive(Debug)]
enum Filter {
    /// seccompiler's stack of programs (this module's own backend).
    Stack(Vec<BpfProgram>),
    /// One program a backend built.
    Program(Vec<SockFilter>),
}

#[derive(Debug)]
pub struct CompiledSeccomp {
    pub flags: u32,
    pub wants_listener: bool,
    filter: Filter,
}

impl CompiledSeccomp {
    pub fn from_program(program: Vec<SockFilter>, flags: u32, wants_listener: bool) -> Self {
        Self {
            flags,
            wants_listener,
            filter: Filter::Program(program),
        }
    }

    /// The BPF program, when the backend built one program (`None` for
    /// seccompiler's stack, see [`CompiledSeccomp::stack`]).
    pub fn program(&self) -> Option<&[SockFilter]> {
        match &self.filter {
            Filter::Program(p) => Some(p),
            Filter::Stack(_) => None,
        }
    }

    /// seccompiler's stack of programs, when this module's own backend
    /// compiled the profile.
    pub fn stack(&self) -> Option<&[BpfProgram]> {
        match &self.filter {
            Filter::Stack(s) => Some(s),
            Filter::Program(_) => None,
        }
    }
}

pub trait SeccompBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn compile(&self, seccomp: &LinuxSeccomp) -> Result<CompiledSeccomp>;
}

/// This module's own backend: seccompiler's stack of filters.
pub struct SeccompBpfBackend;

impl SeccompBackend for SeccompBpfBackend {
    fn name(&self) -> &'static str {
        "seccompiler"
    }

    fn compile(&self, seccomp: &LinuxSeccomp) -> Result<CompiledSeccomp> {
        Ok(CompiledSeccomp {
            flags: filter_flags(seccomp) as u32,
            wants_listener: false,
            filter: Filter::Stack(compile(seccomp)?),
        })
    }
}

/// The profile checks every backend gets (youki PR 3873 runs them before
/// any backend): no `SCMP_ACT_NOTIFY` default, no notify on `write`.
fn check_profile(seccomp: &LinuxSeccomp) -> Result<()> {
    if seccomp.default_action() == LinuxSeccompAction::ScmpActNotify {
        return Err(SeccompError::NotifyAsDefaultAction);
    }
    for syscall in seccomp.syscalls().iter().flatten() {
        if syscall.action() == LinuxSeccompAction::ScmpActNotify
            && syscall.names().iter().any(|n| n == "write")
        {
            return Err(SeccompError::NotifyWriteSyscall);
        }
    }
    Ok(())
}

/// Compile the profile with `backend` and install it on the calling thread.
pub fn initialize_seccomp_with(
    backend: &dyn SeccompBackend,
    seccomp: &LinuxSeccomp,
) -> Result<Option<io::RawFd>> {
    tracing::trace!(backend = backend.name(), "compiling seccomp profile");
    check_profile(seccomp)?;
    let compiled = backend.compile(seccomp)?;
    match &compiled.filter {
        Filter::Stack(programs) => {
            let flags = libc::c_ulong::from(compiled.flags);
            for p in programs {
                load(p, flags)?;
            }
            tracing::debug!(filters = programs.len(), "seccomp profile loaded");
            Ok(None)
        }
        Filter::Program(program) => {
            load_program(program, compiled.flags, compiled.wants_listener)
        }
    }
}

// youki PR 3873's loader of one program.
fn load_program(
    program: &[SockFilter],
    flags: u32,
    wants_listener: bool,
) -> Result<Option<io::RawFd>> {
    let len = u16::try_from(program.len())
        .map_err(|_| SeccompError::ProgramTooLong { len: program.len() })?;
    let prog = libc::sock_fprog {
        len,
        filter: program.as_ptr() as *mut libc::sock_filter,
    };

    let mut flags = libc::c_ulong::from(flags);
    if wants_listener {
        flags |= libc::SECCOMP_FILTER_FLAG_NEW_LISTENER;
        // With TSYNC a failure returns a thread id, which would be taken for
        // the listener fd. TSYNC_ESRCH makes it an error instead.
        if flags & libc::SECCOMP_FILTER_FLAG_TSYNC != 0 {
            flags |= libc::SECCOMP_FILTER_FLAG_TSYNC_ESRCH;
        }
    } else {
        // The kernel only accepts WAIT_KILLABLE_RECV together with a listener.
        flags &= !libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
    }

    // SAFETY: `prog` points at `program`, which outlives the call; the
    // kernel copies the instructions.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            flags,
            &raw const prog,
        )
    };
    if ret < 0 {
        return Err(SeccompError::LoadProgram {
            source: std::io::Error::last_os_error(),
        });
    }
    if wants_listener {
        return Ok(Some(ret as io::RawFd));
    }
    if ret > 0 {
        return Err(SeccompError::LoadProgram {
            source: std::io::Error::other(format!("failed to sync thread {ret}")),
        });
    }
    Ok(None)
}

// Rusternetes: the backend a container's init process compiles
// `linux.seccomp` with (see the same functions in `seccomp/mod.rs`).
static CONTAINER_BACKEND: std::sync::OnceLock<&'static dyn SeccompBackend> =
    std::sync::OnceLock::new();

/// Register the backend for containers' `linux.seccomp` (once per process);
/// a second call returns the backend it did not register.
pub fn set_container_backend(
    backend: &'static dyn SeccompBackend,
) -> std::result::Result<(), &'static dyn SeccompBackend> {
    CONTAINER_BACKEND.set(backend)
}

/// The backend containers' `linux.seccomp` is compiled with: the registered
/// one, else seccompiler's.
pub fn container_backend() -> &'static dyn SeccompBackend {
    CONTAINER_BACKEND
        .get()
        .copied()
        .unwrap_or(&SeccompBpfBackend)
}

/// Install a container's `linux.seccomp` with [`container_backend`].
pub fn initialize_container_seccomp(seccomp: &LinuxSeccomp) -> Result<Option<io::RawFd>> {
    initialize_seccomp_with(container_backend(), seccomp)
}

pub fn is_notify(seccomp: &LinuxSeccomp) -> bool {
    seccomp
        .syscalls()
        .iter()
        .flatten()
        .any(|syscall| syscall.action() == LinuxSeccompAction::ScmpActNotify)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::{LinuxSeccompArgBuilder, LinuxSeccompBuilder, LinuxSyscallBuilder};

    fn syscall(names: &[&str], action: LinuxSeccompAction) -> LinuxSyscall {
        LinuxSyscallBuilder::default()
            .names(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .action(action)
            .build()
            .unwrap()
    }

    fn profile(default: LinuxSeccompAction, syscalls: Vec<LinuxSyscall>) -> LinuxSeccomp {
        LinuxSeccompBuilder::default()
            .default_action(default)
            .syscalls(syscalls)
            .build()
            .unwrap()
    }

    /// Run `f` in a forked child with the profile loaded (no_new_privs set,
    /// so no privilege is needed); the child's wait status.
    fn in_child(seccomp: &LinuxSeccomp, f: fn() -> i32) -> nix::sys::wait::WaitStatus {
        let programs = compile(seccomp).unwrap();
        let flags = filter_flags(seccomp);
        // SAFETY: the child only calls async-signal-safe functions (prctl,
        // seccomp, the probe's syscall, _exit).
        match unsafe { nix::unistd::fork() }.unwrap() {
            nix::unistd::ForkResult::Child => {
                let _ = prctl::set_no_new_privileges(true);
                for p in &programs {
                    if load(p, flags).is_err() {
                        unsafe { libc::_exit(99) };
                    }
                }
                let code = f();
                unsafe { libc::_exit(code) }
            }
            nix::unistd::ForkResult::Parent { child } => {
                nix::sys::wait::waitpid(child, None).unwrap()
            }
        }
    }

    fn mkdir_errno() -> i32 {
        let p = b"/proc/self/seccomp-bpf-test\0";
        let rc = unsafe { libc::mkdirat(libc::AT_FDCWD, p.as_ptr().cast(), 0o700) };
        if rc == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        }
    }

    fn mkdir_0755_errno() -> i32 {
        let p = b"/proc/self/seccomp-bpf-test\0";
        let rc = unsafe { libc::mkdirat(libc::AT_FDCWD, p.as_ptr().cast(), 0o755) };
        if rc == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        }
    }

    fn getppid_ok() -> i32 {
        unsafe { libc::getppid() };
        7
    }

    #[test]
    fn a_kill_process_rule_kills_the_caller_with_sigsys() {
        let p = profile(
            LinuxSeccompAction::ScmpActAllow,
            vec![syscall(
                &["mkdir", "mkdirat"],
                LinuxSeccompAction::ScmpActKillProcess,
            )],
        );
        let st = in_child(&p, mkdir_errno);
        assert!(
            matches!(
                st,
                nix::sys::wait::WaitStatus::Signaled(_, nix::sys::signal::Signal::SIGSYS, _)
            ),
            "{st:?}"
        );
    }

    #[test]
    fn an_allowlist_lets_listed_calls_through_and_gives_the_rest_the_default_errno() {
        // Default ERRNO(ENOSYS-like 38): mkdirat is not listed.
        let mut p = profile(
            LinuxSeccompAction::ScmpActErrno,
            vec![syscall(
                &[
                    "getppid",
                    "exit",
                    "exit_group",
                    "rt_sigreturn",
                    "write",
                    "brk",
                    "mmap",
                    "munmap",
                ],
                LinuxSeccompAction::ScmpActAllow,
            )],
        );
        p.set_default_errno_ret(Some(38));
        assert!(matches!(
            in_child(&p, mkdir_errno),
            nix::sys::wait::WaitStatus::Exited(_, 38)
        ));
        assert!(matches!(
            in_child(&p, getppid_ok),
            nix::sys::wait::WaitStatus::Exited(_, 7)
        ));
    }

    #[test]
    fn a_listed_errno_wins_over_an_allowing_default() {
        let mut s = syscall(&["mkdirat", "mkdir"], LinuxSeccompAction::ScmpActErrno);
        s.set_errno_ret(Some(libc::EROFS as u32));
        let p = profile(LinuxSeccompAction::ScmpActAllow, vec![s]);
        assert!(matches!(
            in_child(&p, mkdir_errno),
            nix::sys::wait::WaitStatus::Exited(_, c) if c == libc::EROFS
        ));
    }

    #[test]
    fn argument_conditions_select_the_rule() {
        // mkdirat(.., mode == 0700) is refused; other modes are not touched
        // by this profile. (An unsigned argument: an int such as AT_FDCWD
        // reaches seccomp zero-extended by glibc, as with libseccomp.)
        let arg = LinuxSeccompArgBuilder::default()
            .index(2usize)
            .value(0o700u64)
            .op(LinuxSeccompOperator::ScmpCmpEq)
            .build()
            .unwrap();
        let s = LinuxSyscallBuilder::default()
            .names(vec!["mkdirat".to_string()])
            .action(LinuxSeccompAction::ScmpActErrno)
            .errno_ret(libc::EXDEV as u32)
            .args(vec![arg])
            .build()
            .unwrap();
        let p = profile(LinuxSeccompAction::ScmpActAllow, vec![s]);
        let st = in_child(&p, mkdir_errno);
        assert!(
            matches!(st, nix::sys::wait::WaitStatus::Exited(_, c) if c == libc::EXDEV),
            "{st:?}"
        );
        let st = in_child(&p, mkdir_0755_errno);
        assert!(
            matches!(st, nix::sys::wait::WaitStatus::Exited(_, c) if c != libc::EXDEV),
            "{st:?}"
        );
    }

    #[test]
    fn notify_is_refused_by_name() {
        let p = profile(
            LinuxSeccompAction::ScmpActAllow,
            vec![syscall(&["openat"], LinuxSeccompAction::ScmpActNotify)],
        );
        assert!(matches!(compile(&p), Err(SeccompError::NotifyUnsupported)));
        let p = profile(LinuxSeccompAction::ScmpActNotify, vec![]);
        assert!(matches!(
            compile(&p),
            Err(SeccompError::NotifyAsDefaultAction)
        ));
    }

    #[test]
    fn names_of_other_architectures_are_skipped_not_fatal() {
        let p = profile(
            LinuxSeccompAction::ScmpActErrno,
            vec![syscall(
                &["read", "arm_fadvise64_64", "no_such_call"],
                LinuxSeccompAction::ScmpActAllow,
            )],
        );
        assert_eq!(compile(&p).unwrap().len(), 1);
    }

    #[test]
    fn an_errno_too_large_for_the_return_data_is_refused() {
        let mut s = syscall(&["mkdirat"], LinuxSeccompAction::ScmpActErrno);
        s.set_errno_ret(Some(0x1_0000));
        let p = profile(LinuxSeccompAction::ScmpActAllow, vec![s]);
        assert!(matches!(compile(&p), Err(SeccompError::ActionData { .. })));
    }

    #[test]
    fn one_filter_per_action_plus_the_base() {
        let p = profile(
            LinuxSeccompAction::ScmpActErrno,
            vec![
                syscall(&["read", "write"], LinuxSeccompAction::ScmpActAllow),
                syscall(&["ptrace"], LinuxSeccompAction::ScmpActKillProcess),
                syscall(&["unshare"], LinuxSeccompAction::ScmpActLog),
            ],
        );
        // base (ERRNO default) + KILL_PROCESS + LOG
        assert_eq!(compile(&p).unwrap().len(), 3);
    }

    #[test]
    fn mkdir_is_allowed_where_the_profile_does_not_name_it() {
        // Control for the tests above: without a filter the probe succeeds
        // or fails with an ordinary errno, never by the profile.
        let p = profile(
            LinuxSeccompAction::ScmpActAllow,
            vec![syscall(&["ptrace"], LinuxSeccompAction::ScmpActKillProcess)],
        );
        assert!(matches!(
            in_child(&p, mkdir_errno),
            nix::sys::wait::WaitStatus::Exited(_, c) if c != libc::EXDEV && c != libc::EROFS
        ));
    }
}

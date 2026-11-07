// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Ignalina ApS and Vetra Automation AB

//! The kernel-implied base set. Heimdall is a defensive sandbox; these four
//! calls are made by every program that waits, handles a signal or ends,
//! whether its code names them or not:
//!
//! | Call | x86_64 | aarch64 | Why it appears |
//! |---|---|---|---|
//! | `restart_syscall` | 219 | 128 | the kernel resumes an interrupted timed wait (`nanosleep`, `clock_nanosleep`, `futex` with a timeout, `poll`) after a stop, a ptrace stop or io_uring task_work |
//! | `rt_sigreturn` | 15 | 139 | the return from every signal handler (the libc's restorer) |
//! | `exit` | 60 | 93 | the end of a thread |
//! | `exit_group` | 231 | 94 | the end of a process |
//!
//! A probe run that is never interrupted and never handles a signal does not
//! see the first two, so a learned allowlist misses them, and the program
//! dies of `SIGSYS` the first time a wait is resumed (gunnar.rs, 2026-11-06:
//! io_uring task_work interrupted a timed futex wait, the kernel resumed it
//! through `restart_syscall`, PID 1 died). None of them widens anything:
//! `restart_syscall` only resumes a call the filter already let through (with
//! the arguments the kernel kept), `rt_sigreturn` restores registers from the
//! signal frame, `exit` and `exit_group` end the task.
//!
//! So every filter built by [`crate::bpf::build_rules`] allows them first,
//! right after the arch check, whatever its rules and default; a profile may
//! name them only as bare allows ([`crate::ProfileError::DeniesBaseSet`]
//! otherwise, at load and at build); [`crate::Profile::evaluate`] and
//! [`crate::oci::to_oci`] agree.

use crate::arch::Arch;
use crate::profile::{Action, Rule};

/// The base set, in this order.
pub const BASE_SET: [&str; 4] = ["restart_syscall", "rt_sigreturn", "exit", "exit_group"];

/// Whether the base set is enforced: always, except in a test build with
/// `--cfg heimdall_test_no_base_set` (the kernel reproducers use it to show
/// that they fail without it). Never false in a release.
pub const ENFORCED: bool = !cfg!(heimdall_test_no_base_set);

/// Whether `syscall` is in the base set.
pub fn is_base(syscall: &str) -> bool {
    ENFORCED && BASE_SET.contains(&syscall)
}

/// The base set's numbers on `arch`, in [`BASE_SET`] order.
pub fn nrs(arch: Arch) -> [u32; 4] {
    BASE_SET.map(|n| arch.syscall_nr(n).expect("in both tables"))
}

/// Whether `nr` is a base call on `arch` (and the base set is enforced).
pub fn is_base_nr(arch: Arch, nr: u32) -> bool {
    ENFORCED && nrs(arch).contains(&nr)
}

/// The base set as bare allow rules (what a generated profile names).
pub fn rules() -> Vec<Rule> {
    if !ENFORCED {
        return Vec::new();
    }
    BASE_SET
        .iter()
        .map(|n| Rule::bare(n, Action::Allow))
        .collect()
}

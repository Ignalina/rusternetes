// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Ignalina ApS and Vetra Automation AB

//! The classic-BPF builder: pure Rust, no libseccomp. Heimdall is a
//! defensive sandbox; the program it builds is the whole allowlist.
//!
//! Layout:
//!
//! ```text
//!   ld  [arch]          ; foreign arch -> KILL_PROCESS (every mode)
//!   jeq AUDIT_ARCH, +1
//!   ret KILL_PROCESS
//!   ld  [nr]
//!   jge 0x40000000, ... ; x86_64 only: x32 calls -> KILL_PROCESS (every mode)
//!   jeq NR, ...         ; the kernel-implied base set (crate::base): ALLOW,
//!   ...                 ; whatever the rules and the default
//!   ja  +1
//!   ret ALLOW
//!   ; per syscall, in first-appearance order of its rules:
//!   jeq NR, +1          ; not this call: jump over its block
//!   ja  <block len>
//!     ; per rule, per alternative: every comparison, 32 bits at a time
//!     ld  [args[i] hi] ; and MASK_HI ; jeq VALUE_HI, +1 ; ja <next alternative>
//!     ld  [args[i] lo] ; and MASK_LO ; jeq VALUE_LO, +1 ; ja <next alternative>
//!     ret ACTION
//!   ret DEFAULT         ; the call's rules did not match
//!   ...
//!   ret DEFAULT         ; a call with no rules
//! ```
//!
//! Every forward jump past more than one instruction is a `ja` (32-bit
//! offset), so blocks of any length work; the only limit is the kernel's
//! 4096 instructions.

use crate::arch::{Arch, X32_SYSCALL_BIT};
use crate::profile::{validate_rules, Action, Profile, ProfileError, Rule, Width};

/// `struct sock_filter`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// `BPF_LD | BPF_W | BPF_ABS`.
pub const LD_W_ABS: u16 = 0x20;
/// `BPF_ALU | BPF_AND | BPF_K`.
pub const ALU_AND_K: u16 = 0x54;
/// `BPF_JMP | BPF_JA`.
pub const JMP_JA: u16 = 0x05;
/// `BPF_JMP | BPF_JEQ | BPF_K`.
pub const JMP_JEQ_K: u16 = 0x15;
/// `BPF_JMP | BPF_JGT | BPF_K`.
pub const JMP_JGT_K: u16 = 0x25;
/// `BPF_JMP | BPF_JGE | BPF_K`.
pub const JMP_JGE_K: u16 = 0x35;
/// `BPF_JMP | BPF_JSET | BPF_K`.
pub const JMP_JSET_K: u16 = 0x45;
/// `BPF_RET | BPF_K`.
pub const RET_K: u16 = 0x06;
/// The kernel's `BPF_MAXINSNS`.
pub const MAX_INSNS: usize = 4096;

/// Offsets in `struct seccomp_data`.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const fn off_arg_lo(i: u8) -> u32 {
    16 + 8 * i as u32
}
const fn off_arg_hi(i: u8) -> u32 {
    16 + 8 * i as u32 + 4
}

const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// A built filter for one arch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    arch: Arch,
    insns: Vec<SockFilter>,
}

impl Program {
    /// The arch the program checks for.
    pub fn arch(&self) -> Arch {
        self.arch
    }
    /// The instructions.
    pub fn insns(&self) -> &[SockFilter] {
        &self.insns
    }
    /// The instruction count.
    pub fn len(&self) -> usize {
        self.insns.len()
    }
    /// Never true for a built program.
    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }
    /// The program as the kernel reads it: each `struct sock_filter` as 8
    /// little-endian bytes (`code`, `jt`, `jf`, `k`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.insns.len() * 8);
        for i in &self.insns {
            b.extend_from_slice(&i.code.to_le_bytes());
            b.push(i.jt);
            b.push(i.jf);
            b.extend_from_slice(&i.k.to_le_bytes());
        }
        b
    }
    /// SHA-256 of [`Program::to_bytes`]: what a signed record names as the
    /// floor's digest.
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(self.to_bytes()).into()
    }
}

/// The token that allows audit mode. Heimdall is a defensive sandbox: audit
/// mode lets unknown calls RUN (logged), so it exists for staging runs on
/// test boxes only (spec §3.3), never in production.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestBox(());

/// The environment variable a test box sets to `1` to allow audit mode.
pub const TEST_BOX_ENV: &str = "HEIMDALL_SECCOMP_AUDIT_TEST_BOX";

/// Audit mode was asked for on a box that is not marked a test box.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("seccomp audit mode is for test boxes only: set {TEST_BOX_ENV}=1 on a test box (never in production)")]
pub struct NotATestBox;

impl TestBox {
    /// A token when this box is marked a test box (`HEIMDALL_SECCOMP_AUDIT_TEST_BOX=1`).
    pub fn from_env() -> Result<TestBox, NotATestBox> {
        match std::env::var_os(TEST_BOX_ENV) {
            Some(v) if v == "1" => Ok(TestBox(())),
            _ => Err(NotATestBox),
        }
    }
}

/// Enforcing or audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Production: a call outside the profile is `SECCOMP_RET_KILL_PROCESS`
    /// (the kernel writes an audit record for it).
    Enforce,
    /// Staging on test boxes: a call outside the profile is
    /// `SECCOMP_RET_LOG` (runs, and is logged).
    Audit(TestBox),
}

impl Mode {
    /// The action for a call outside the profile.
    pub fn default_action(&self) -> Action {
        match self {
            Mode::Enforce => Action::KillProcess,
            Mode::Audit(_) => Action::Log,
        }
    }
}

/// Why a program could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    #[error(transparent)]
    Profile(#[from] ProfileError),
    #[error("the filter needs {0} instructions; the kernel takes at most {MAX_INSNS}")]
    TooLong(usize),
}

/// Build the filter for a profile in a mode.
pub fn build(profile: &Profile, mode: &Mode) -> Result<Program, BuildError> {
    build_rules(profile.arch, &profile.rules, mode.default_action())
}

/// Build a filter from rules with any default action (the probe's learning
/// filter uses `UserNotif`). Rules are validated first.
pub fn build_rules(arch: Arch, rules: &[Rule], default: Action) -> Result<Program, BuildError> {
    validate_rules(arch, rules)?;
    let mut p = vec![
        stmt(LD_W_ABS, OFF_ARCH),
        jump(JMP_JEQ_K, arch.audit_arch(), 1, 0),
        stmt(RET_K, Action::KillProcess.ret()),
        stmt(LD_W_ABS, OFF_NR),
    ];
    if arch == Arch::X86_64 {
        p.push(jump(JMP_JGE_K, X32_SYSCALL_BIT, 0, 1));
        p.push(stmt(RET_K, Action::KillProcess.ret()));
    }
    // The kernel-implied base set, before every rule: no profile removes it.
    if crate::base::ENFORCED {
        let base = crate::base::nrs(arch);
        let n = base.len();
        for (i, nr) in base.into_iter().enumerate() {
            // Hit: jump to the `ret ALLOW` after the remaining jeqs and the ja.
            p.push(jump(JMP_JEQ_K, nr, (n - i) as u8, 0));
        }
        p.push(stmt(JMP_JA, 1));
        p.push(stmt(RET_K, Action::Allow.ret()));
    }
    // Group the rules by syscall, in first-appearance order (a base call's
    // bare allow is already answered above).
    let mut groups: Vec<(u32, Vec<&Rule>)> = Vec::new();
    for r in rules {
        if crate::base::is_base(&r.syscall) {
            continue;
        }
        let nr = arch.syscall_nr(&r.syscall).expect("validated");
        match groups.iter_mut().find(|(n, _)| *n == nr) {
            Some((_, v)) => v.push(r),
            None => groups.push((nr, vec![r])),
        }
    }
    for (nr, group) in groups {
        let block = syscall_block(&group, default);
        p.push(jump(JMP_JEQ_K, nr, 1, 0));
        p.push(stmt(JMP_JA, block.len() as u32));
        p.extend(block);
    }
    p.push(stmt(RET_K, default.ret()));
    if p.len() > MAX_INSNS {
        return Err(BuildError::TooLong(p.len()));
    }
    Ok(Program { arch, insns: p })
}

/// The block of one syscall: its rules in order, then `ret default`.
fn syscall_block(rules: &[&Rule], default: Action) -> Vec<SockFilter> {
    let mut b = Vec::new();
    for r in rules {
        if r.when.is_empty() {
            // Matches always: later rules of this call are unreachable.
            b.push(stmt(RET_K, r.action.ret()));
            return b;
        }
        for alt in &r.when {
            b.extend(alternative(alt, r.action));
        }
    }
    b.push(stmt(RET_K, default.ret()));
    b
}

/// One alternative: every comparison must hold, then `ret action`; any
/// failing comparison jumps to the instruction after the `ret`.
fn alternative(cmps: &[crate::profile::ArgCmp], action: Action) -> Vec<SockFilter> {
    // Each check is (offset, mask, value) on one 32-bit half.
    let mut checks = Vec::new();
    for c in cmps {
        let halves: Vec<(u32, u32, u32)> = match c.width {
            Width::W32 => vec![(off_arg_lo(c.arg), c.mask as u32, c.value as u32)],
            Width::W64 => vec![
                (
                    off_arg_hi(c.arg),
                    (c.mask >> 32) as u32,
                    (c.value >> 32) as u32,
                ),
                (off_arg_lo(c.arg), c.mask as u32, c.value as u32),
            ],
        };
        for (off, mask, value) in halves {
            if mask == 0 {
                // (x & 0) == value: value is 0 (validated), always true.
                continue;
            }
            checks.push((off, mask, value));
        }
    }
    // Emit, then patch the `ja` offsets to land just past the final `ret`.
    let mut out: Vec<SockFilter> = Vec::new();
    let mut jas = Vec::new();
    for (off, mask, value) in checks {
        out.push(stmt(LD_W_ABS, off));
        if mask != u32::MAX {
            out.push(stmt(ALU_AND_K, mask));
        }
        out.push(jump(JMP_JEQ_K, value, 1, 0));
        jas.push(out.len());
        out.push(stmt(JMP_JA, 0));
    }
    out.push(stmt(RET_K, action.ret()));
    let end = out.len();
    for i in jas {
        out[i].k = (end - i - 1) as u32;
    }
    out
}

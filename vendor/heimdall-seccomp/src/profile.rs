// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Ignalina ApS and Vetra Automation AB

//! Profile types (spec §3.1 step 4). Heimdall is a defensive sandbox: a
//! profile is the complete list of calls one workload may make; everything
//! else gets the mode's default action (kill in production).
//!
//! Two forms: [`StaticProfile`] is the `const` table a generated
//! `profiles/<workload>/<arch>-<libc>.rs` holds; [`Profile`] is the owned
//! form the builder, the probe and the JSON use. `Profile::from(&STATIC)`
//! converts.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::arch::{Arch, Libc};

/// What the filter does with a call.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// `SECCOMP_RET_ALLOW`.
    Allow,
    /// `SECCOMP_RET_LOG`: allow after a kernel audit log entry (audit mode).
    Log,
    /// `SECCOMP_RET_ERRNO`: fail the call with this errno, do not run it.
    Errno(u16),
    /// `SECCOMP_RET_USER_NOTIF`: pause the caller and ask the supervisor
    /// (the broker, or the probe in learning mode).
    UserNotif,
    /// `SECCOMP_RET_TRAP`: send SIGSYS to the thread.
    Trap,
    /// `SECCOMP_RET_KILL_THREAD`.
    KillThread,
    /// `SECCOMP_RET_KILL_PROCESS`: the enforcing default.
    KillProcess,
}

/// `SECCOMP_RET_KILL_PROCESS`.
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
/// `SECCOMP_RET_KILL_THREAD`.
pub const RET_KILL_THREAD: u32 = 0x0000_0000;
/// `SECCOMP_RET_TRAP`.
pub const RET_TRAP: u32 = 0x0003_0000;
/// `SECCOMP_RET_ERRNO`.
pub const RET_ERRNO: u32 = 0x0005_0000;
/// `SECCOMP_RET_USER_NOTIF`.
pub const RET_USER_NOTIF: u32 = 0x7fc0_0000;
/// `SECCOMP_RET_LOG`.
pub const RET_LOG: u32 = 0x7ffc_0000;
/// `SECCOMP_RET_ALLOW`.
pub const RET_ALLOW: u32 = 0x7fff_0000;

impl Action {
    /// The filter return value.
    pub const fn ret(self) -> u32 {
        match self {
            Action::Allow => RET_ALLOW,
            Action::Log => RET_LOG,
            Action::Errno(e) => RET_ERRNO | e as u32,
            Action::UserNotif => RET_USER_NOTIF,
            Action::Trap => RET_TRAP,
            Action::KillThread => RET_KILL_THREAD,
            Action::KillProcess => RET_KILL_PROCESS,
        }
    }

    /// The action of a filter return value (the data bits matter only for
    /// `ERRNO`; `TRACE` and unknown values give `None`).
    pub fn from_ret(ret: u32) -> Option<Action> {
        match ret & 0xffff_0000 {
            RET_ALLOW => Some(Action::Allow),
            RET_LOG => Some(Action::Log),
            RET_ERRNO => Some(Action::Errno((ret & 0xffff) as u16)),
            RET_USER_NOTIF => Some(Action::UserNotif),
            RET_TRAP => Some(Action::Trap),
            RET_KILL_THREAD => Some(Action::KillThread),
            RET_KILL_PROCESS => Some(Action::KillProcess),
            _ => None,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Allow => f.write_str("allow"),
            Action::Log => f.write_str("log"),
            Action::Errno(e) => write!(f, "errno {e}"),
            Action::UserNotif => f.write_str("user_notif"),
            Action::Trap => f.write_str("trap"),
            Action::KillThread => f.write_str("kill_thread"),
            Action::KillProcess => f.write_str("kill_process"),
        }
    }
}

/// How much of a 64-bit argument register a comparison looks at.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Width {
    /// The low 32 bits only: for `int`/`unsigned int` parameters, whose upper
    /// half the kernel ignores (and userspace may leave dirty).
    W32,
    /// All 64 bits: for `long`/pointer-sized parameters (e.g. `clone` flags).
    W64,
}

/// One argument test: matches when `(args[arg] & mask) == value`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ArgCmp {
    /// The argument index, 0..=5.
    pub arg: u8,
    pub width: Width,
    #[serde(with = "hex_u64")]
    pub mask: u64,
    #[serde(with = "hex_u64")]
    pub value: u64,
}

impl ArgCmp {
    /// `args[arg] as u32 == value`.
    pub const fn eq32(arg: u8, value: u32) -> ArgCmp {
        ArgCmp {
            arg,
            width: Width::W32,
            mask: 0xffff_ffff,
            value: value as u64,
        }
    }

    /// `args[arg] == value`.
    pub const fn eq64(arg: u8, value: u64) -> ArgCmp {
        ArgCmp {
            arg,
            width: Width::W64,
            mask: u64::MAX,
            value,
        }
    }

    /// No bit outside `allowed` is set in the low 32 bits (a flag field).
    pub const fn only_bits32(arg: u8, allowed: u32) -> ArgCmp {
        ArgCmp {
            arg,
            width: Width::W32,
            mask: (!allowed) as u64,
            value: 0,
        }
    }

    /// No bit outside `allowed` is set (a 64-bit flag field).
    pub const fn only_bits64(arg: u8, allowed: u64) -> ArgCmp {
        ArgCmp {
            arg,
            width: Width::W64,
            mask: !allowed,
            value: 0,
        }
    }

    /// Whether the comparison holds for these argument registers.
    pub fn matches(&self, args: &[u64; 6]) -> bool {
        let a = args[usize::from(self.arg)];
        let a = match self.width {
            Width::W32 => a & 0xffff_ffff,
            Width::W64 => a,
        };
        a & self.mask == self.value
    }
}

/// One rule of a syscall.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Rule {
    /// The syscall name, as the arch's table spells it (`openat`, `mmap`).
    pub syscall: String,
    pub action: Action,
    /// Empty: any arguments. Otherwise the rule matches when ANY of these
    /// alternatives matches, and an alternative matches when ALL its
    /// comparisons do.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub when: Vec<Vec<ArgCmp>>,
}

impl Rule {
    /// A bare rule: `syscall` with any arguments.
    pub fn bare(syscall: &str, action: Action) -> Rule {
        Rule {
            syscall: syscall.to_string(),
            action,
            when: Vec::new(),
        }
    }

    /// Whether this rule matches these argument registers.
    pub fn matches(&self, args: &[u64; 6]) -> bool {
        self.when.is_empty()
            || self
                .when
                .iter()
                .any(|alt| alt.iter().all(|c| c.matches(args)))
    }
}

/// A profile: one workload, one arch, one libc.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub workload: String,
    pub arch: Arch,
    pub libc: Libc,
    pub rules: Vec<Rule>,
}

/// Why a profile cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    #[error("{arch} has no syscall named {name:?}")]
    UnknownSyscall { arch: Arch, name: String },
    #[error("rule for {syscall}: argument index {arg} is not 0..=5")]
    BadArgIndex { syscall: String, arg: u8 },
    #[error("rule for {syscall}: a 32-bit comparison on arg {arg} has bits above 32 (mask {mask:#x}, value {value:#x})")]
    WideW32 {
        syscall: String,
        arg: u8,
        mask: u64,
        value: u64,
    },
    #[error("rule for {syscall}: arg {arg} value {value:#x} has bits outside its mask {mask:#x}, so it never matches")]
    NeverMatches {
        syscall: String,
        arg: u8,
        mask: u64,
        value: u64,
    },
    #[error(
        "rule for {syscall}: an empty alternative (it would match everything; use an empty `when`)"
    )]
    EmptyAlternative { syscall: String },
    #[error(
        "rule for {syscall}: {action}{cond}: {syscall} is in the kernel-implied base set \
         (restart_syscall, rt_sigreturn, exit, exit_group), which every Heimdall filter allows \
         and no profile may deny; name it only as a bare allow, or leave it out"
    )]
    DeniesBaseSet {
        syscall: String,
        action: Action,
        /// `" when ..."` for a conditional allow, else empty.
        cond: &'static str,
    },
    #[error("profile JSON: {0}")]
    Json(String),
    #[error("OCI seccomp JSON: {0}")]
    Oci(String),
}

impl Profile {
    /// Check every rule against the arch: known syscall names, argument
    /// indexes 0..=5, 32-bit comparisons within 32 bits, values within masks.
    pub fn validate(&self) -> Result<(), ProfileError> {
        validate_rules(self.arch, &self.rules)
    }

    /// The action for one call, with `default` when no rule matches. This is
    /// the reference the BPF program is tested against. A call of the
    /// kernel-implied base set ([`crate::base`]) is always `Allow`.
    pub fn evaluate(&self, nr: u32, args: &[u64; 6], default: Action) -> Action {
        if crate::base::is_base_nr(self.arch, nr) {
            return Action::Allow;
        }
        let Some(name) = self.arch.syscall_name(nr) else {
            return default;
        };
        self.rules
            .iter()
            .filter(|r| r.syscall == name)
            .find(|r| r.matches(args))
            .map(|r| r.action)
            .unwrap_or(default)
    }

    /// The syscall names this profile has rules for, sorted, once each.
    pub fn syscalls(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.rules.iter().map(|r| r.syscall.as_str()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Pretty JSON with a fixed field order (diff-friendly, deterministic).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a profile always serializes") + "\n"
    }

    /// Read a profile from JSON. Unknown fields (e.g. the probe's `review`
    /// section) are ignored; the result is validated.
    pub fn from_json(s: &str) -> Result<Profile, ProfileError> {
        let p: Profile = serde_json::from_str(s).map_err(|e| ProfileError::Json(e.to_string()))?;
        p.validate()?;
        Ok(p)
    }
}

pub(crate) fn validate_rules(arch: Arch, rules: &[Rule]) -> Result<(), ProfileError> {
    for r in rules {
        if arch.syscall_nr(&r.syscall).is_none() {
            return Err(ProfileError::UnknownSyscall {
                arch,
                name: r.syscall.clone(),
            });
        }
        if crate::base::is_base(&r.syscall) && (r.action != Action::Allow || !r.when.is_empty()) {
            return Err(ProfileError::DeniesBaseSet {
                syscall: r.syscall.clone(),
                action: r.action,
                cond: if r.when.is_empty() {
                    ""
                } else {
                    " with argument conditions"
                },
            });
        }
        for alt in &r.when {
            if alt.is_empty() {
                return Err(ProfileError::EmptyAlternative {
                    syscall: r.syscall.clone(),
                });
            }
            for c in alt {
                if c.arg > 5 {
                    return Err(ProfileError::BadArgIndex {
                        syscall: r.syscall.clone(),
                        arg: c.arg,
                    });
                }
                if c.width == Width::W32 && (c.mask >> 32 != 0 || c.value >> 32 != 0) {
                    return Err(ProfileError::WideW32 {
                        syscall: r.syscall.clone(),
                        arg: c.arg,
                        mask: c.mask,
                        value: c.value,
                    });
                }
                if c.value & !c.mask != 0 {
                    return Err(ProfileError::NeverMatches {
                        syscall: r.syscall.clone(),
                        arg: c.arg,
                        mask: c.mask,
                        value: c.value,
                    });
                }
            }
        }
    }
    Ok(())
}

/// The `const` form of a [`Rule`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StaticRule {
    pub syscall: &'static str,
    pub action: Action,
    pub when: &'static [&'static [ArgCmp]],
}

/// The `const` form of a [`Profile`], as generated `.rs` files hold it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StaticProfile {
    pub workload: &'static str,
    pub arch: Arch,
    pub libc: Libc,
    pub rules: &'static [StaticRule],
}

impl From<&StaticProfile> for Profile {
    fn from(s: &StaticProfile) -> Profile {
        Profile {
            workload: s.workload.to_string(),
            arch: s.arch,
            libc: s.libc,
            rules: s
                .rules
                .iter()
                .map(|r| Rule {
                    syscall: r.syscall.to_string(),
                    action: r.action,
                    when: r.when.iter().map(|alt| alt.to_vec()).collect(),
                })
                .collect(),
        }
    }
}

/// u64 as a `0x…` hex string in JSON (masks and flags read better in hex).
mod hex_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{v:#x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        let h = s
            .strip_prefix("0x")
            .ok_or_else(|| serde::de::Error::custom(format!("{s:?} is not 0x-hex")))?;
        u64::from_str_radix(h, 16).map_err(serde::de::Error::custom)
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Ignalina ApS and Vetra Automation AB

//! The profile as a standard OCI runtime-spec seccomp JSON, for a pod's
//! `securityContext.seccompProfile: Localhost` (docs/BUILD-THING.md).
//! Heimdall is a defensive sandbox; the OCI form carries the same rules.
//!
//! Mapping: one OCI syscall entry per alternative (entries are OR-ed, the
//! `args` of one entry AND-ed); every comparison is `SCMP_CMP_MASKED_EQ`
//! (`(arg & value) == valueTwo`). OCI runtimes compare all 64 bits, so a
//! [`Width::W32`] comparison is written with its 32-bit mask, which ignores
//! the upper half exactly as Heimdall does.

use serde_json::{json, Value};

use crate::arch::{Arch, Libc};
use crate::bpf::Mode;
use crate::profile::{Action, ArgCmp, Profile, ProfileError, Rule, Width};

fn act(a: Action) -> (&'static str, Option<u16>) {
    match a {
        Action::Allow => ("SCMP_ACT_ALLOW", None),
        Action::Log => ("SCMP_ACT_LOG", None),
        Action::Errno(e) => ("SCMP_ACT_ERRNO", Some(e)),
        Action::UserNotif => ("SCMP_ACT_NOTIFY", None),
        Action::Trap => ("SCMP_ACT_TRAP", None),
        Action::KillThread => ("SCMP_ACT_KILL_THREAD", None),
        Action::KillProcess => ("SCMP_ACT_KILL_PROCESS", None),
    }
}

/// The OCI seccomp object (`linux.seccomp`) for a profile in a mode.
pub fn to_oci(p: &Profile, mode: &Mode) -> Value {
    let arch = match p.arch {
        Arch::X86_64 => "SCMP_ARCH_X86_64",
        Arch::Aarch64 => "SCMP_ARCH_AARCH64",
    };
    let (default, _) = act(mode.default_action());
    let mut syscalls = Vec::new();
    // The kernel-implied base set (crate::base), for a runtime that builds
    // the filter itself (crun, runc): first, for the calls the profile does
    // not name (a profile can only name them as bare allows).
    let missing: Vec<&str> = crate::base::BASE_SET
        .into_iter()
        .filter(|n| crate::base::is_base(n) && !p.rules.iter().any(|r| r.syscall == *n))
        .collect();
    if !missing.is_empty() {
        syscalls.push(json!({ "names": missing, "action": "SCMP_ACT_ALLOW" }));
    }
    for r in &p.rules {
        let (action, errno) = act(r.action);
        let alts: Vec<Vec<Value>> = if r.when.is_empty() {
            vec![Vec::new()]
        } else {
            r.when
                .iter()
                .map(|alt| {
                    alt.iter()
                        .map(|c| {
                            json!({
                                "index": c.arg,
                                "value": c.mask,
                                "valueTwo": c.value,
                                "op": "SCMP_CMP_MASKED_EQ",
                            })
                        })
                        .collect()
                })
                .collect()
        };
        for args in alts {
            let mut e = json!({ "names": [r.syscall], "action": action });
            if let Some(n) = errno {
                e["errnoRet"] = json!(n);
            }
            if !args.is_empty() {
                e["args"] = Value::Array(args);
            }
            syscalls.push(e);
        }
    }
    json!({
        "defaultAction": default,
        "architectures": [arch],
        "syscalls": syscalls,
    })
}

/// Read an ENFORCING OCI seccomp JSON back into a [`Profile`] (the inverse of
/// [`to_oci`] with [`Mode::Enforce`]), so a runner can build and install it
/// with Heimdall's own BPF builder. Heimdall is a defensive sandbox: this
/// fails closed on anything it cannot represent exactly.
///
/// Refused: a `defaultAction` other than `SCMP_ACT_KILL_PROCESS` (a profile
/// that lets unknown calls through protects nothing), not exactly one
/// architecture or one other than `arch`'s, `SCMP_ACT_NOTIFY` (nobody would
/// answer) or `SCMP_ACT_TRACE`, any comparison other than
/// `SCMP_CMP_MASKED_EQ` / `SCMP_CMP_EQ`, docker's `includes`/`excludes`,
/// unknown syscall names. Consecutive entries of one syscall with one action
/// and arguments become one [`Rule`] with several alternatives; a comparison
/// whose mask and value fit in 32 bits reads as [`Width::W32`] (the same
/// test). `workload` and `libc` are not in the OCI form and are given.
/// An entry that denies a call of the kernel-implied base set ([`crate::base`])
/// is refused ([`ProfileError::DeniesBaseSet`]); a missing one is added by the
/// builder anyway.
pub fn from_oci(json: &str, workload: &str, libc: Libc) -> Result<Profile, ProfileError> {
    let bad = |m: String| ProfileError::Oci(m);
    let v: Value = serde_json::from_str(json).map_err(|e| bad(e.to_string()))?;
    let obj = v
        .as_object()
        .ok_or_else(|| bad("not a JSON object".into()))?;
    match obj.get("defaultAction").and_then(Value::as_str) {
        Some("SCMP_ACT_KILL_PROCESS") => {}
        other => {
            return Err(bad(format!(
                "defaultAction {other:?} is not SCMP_ACT_KILL_PROCESS: only enforcing profiles are applied"
            )))
        }
    }
    let arches: Vec<&str> = obj
        .get("architectures")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let arch = match arches.as_slice() {
        ["SCMP_ARCH_X86_64"] => Arch::X86_64,
        ["SCMP_ARCH_AARCH64"] => Arch::Aarch64,
        other => {
            return Err(bad(format!(
                "architectures {other:?}: exactly one of SCMP_ARCH_X86_64, SCMP_ARCH_AARCH64"
            )))
        }
    };
    let mut rules: Vec<Rule> = Vec::new();
    let entries = obj
        .get("syscalls")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("no syscalls array".into()))?;
    for (i, e) in entries.iter().enumerate() {
        let eo = e
            .as_object()
            .ok_or_else(|| bad(format!("syscalls[{i}] is not an object")))?;
        for k in eo.keys() {
            if !matches!(
                k.as_str(),
                "names" | "action" | "errnoRet" | "args" | "comment"
            ) {
                return Err(bad(format!("syscalls[{i}]: unsupported key {k:?}")));
            }
        }
        let action = match eo.get("action").and_then(Value::as_str) {
            Some("SCMP_ACT_ALLOW") => Action::Allow,
            Some("SCMP_ACT_LOG") => Action::Log,
            Some("SCMP_ACT_TRAP") => Action::Trap,
            Some("SCMP_ACT_KILL_THREAD") | Some("SCMP_ACT_KILL") => Action::KillThread,
            Some("SCMP_ACT_KILL_PROCESS") => Action::KillProcess,
            Some("SCMP_ACT_ERRNO") => {
                let n = eo.get("errnoRet").and_then(Value::as_u64).ok_or_else(|| {
                    bad(format!("syscalls[{i}]: SCMP_ACT_ERRNO without errnoRet"))
                })?;
                Action::Errno(
                    u16::try_from(n).map_err(|_| bad(format!("syscalls[{i}]: errnoRet {n}")))?,
                )
            }
            other => return Err(bad(format!("syscalls[{i}]: unsupported action {other:?}"))),
        };
        let mut alt = Vec::new();
        for (j, a) in eo
            .get("args")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            let num = |k: &str| a.get(k).and_then(Value::as_u64);
            let at = || format!("syscalls[{i}].args[{j}]");
            let arg = num("index")
                .filter(|x| *x <= 5)
                .ok_or_else(|| bad(format!("{}: index is not 0..=5", at())))?
                as u8;
            let (mask, value) = match a.get("op").and_then(Value::as_str) {
                Some("SCMP_CMP_MASKED_EQ") => (
                    num("value").ok_or_else(|| bad(format!("{}: no value", at())))?,
                    num("valueTwo").unwrap_or(0),
                ),
                Some("SCMP_CMP_EQ") => (
                    u64::MAX,
                    num("value").ok_or_else(|| bad(format!("{}: no value", at())))?,
                ),
                other => return Err(bad(format!("{}: unsupported op {other:?}", at()))),
            };
            let width = if mask >> 32 == 0 && value >> 32 == 0 {
                Width::W32
            } else {
                Width::W64
            };
            alt.push(ArgCmp {
                arg,
                width,
                mask,
                value,
            });
        }
        let names = eo
            .get("names")
            .and_then(Value::as_array)
            .filter(|n| !n.is_empty())
            .ok_or_else(|| bad(format!("syscalls[{i}]: no names")))?;
        for n in names {
            let name = n
                .as_str()
                .ok_or_else(|| bad(format!("syscalls[{i}]: a name is not a string")))?;
            // One rule per syscall and action: consecutive entries with
            // arguments are alternatives of the rule before them.
            match rules.last_mut() {
                Some(last)
                    if !alt.is_empty()
                        && !last.when.is_empty()
                        && last.syscall == name
                        && last.action == action =>
                {
                    last.when.push(alt.clone())
                }
                _ => rules.push(Rule {
                    syscall: name.to_string(),
                    action,
                    when: if alt.is_empty() {
                        vec![]
                    } else {
                        vec![alt.clone()]
                    },
                }),
            }
        }
    }
    let p = Profile {
        workload: workload.to_string(),
        arch,
        libc,
        rules,
    };
    p.validate()?;
    Ok(p)
}

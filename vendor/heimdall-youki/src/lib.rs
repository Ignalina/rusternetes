// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Ignalina ApS and Vetra Automation AB

//! heimdall-youki: **Heimdall is a defensive sandbox.** This crate is the
//! runtime plug of docs/v2/graph-filter.md §6: Heimdall's pure-Rust
//! classic-BPF builder as a seccomp backend for youki, the user's choice
//! beside libseccomp. It compiles the OCI seccomp section into ONE program,
//! static mode's floor: the arch check, the x32 kill and the kernel-implied
//! base set (`restart_syscall`, `rt_sigreturn`, `exit`, `exit_group`) first,
//! then the profile's rules, default `KILL_PROCESS`
//! ([`heimdall_seccomp::filter::compile_floor`]).
//!
//! It reads the profiles Heimdall's profiler writes (`<arch>-<libc>.oci.json`)
//! and refuses, by name, what Heimdall does not read (another default
//! action, other operators, several arches, a flag it does not know). It
//! holds no profiler, no broker and no follower: graph mode's follower is
//! attached by Heimdall on the host and needs nothing from the runtime.
//!
//! - [`compile_oci_json`]: the backend without youki (any OCI seccomp JSON).
//! - [`HeimdallBackend`] (feature `youki`): libcontainer's `SeccompBackend`,
//!   from Ignalina/youki `feat/seccomp-backend-trait` (youki PR 3873).

use heimdall_seccomp::bpf::SockFilter;
use heimdall_seccomp::filter::compile_floor;
use heimdall_seccomp::{Action, Arch, Libc};

/// The backend's name in youki.
pub const NAME: &str = "heimdall";

/// A compiled OCI seccomp section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compiled {
    pub program: Vec<SockFilter>,
    /// `SECCOMP_FILTER_FLAG_*` of the section's `flags`.
    pub flags: u32,
    /// A rule hands calls to a supervisor (`SCMP_ACT_NOTIFY`).
    pub wants_listener: bool,
}

/// Why a section was not compiled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    #[error("heimdall seccomp backend: not JSON: {0}")]
    Json(String),
    #[error("heimdall seccomp backend: {0}")]
    Profile(String),
    #[error("heimdall seccomp backend: the seccomp flag {0:?} is not one Heimdall knows")]
    Flag(String),
    #[error("heimdall seccomp backend: the profile is for {profile}, this host is {host}")]
    Arch { profile: Arch, host: String },
    #[error("heimdall seccomp backend: {0}")]
    Build(String),
}

/// The `SECCOMP_FILTER_FLAG_*` value of an OCI flag name.
fn flag(name: &str) -> Option<u32> {
    Some(match name {
        "SECCOMP_FILTER_FLAG_TSYNC" => 1,
        "SECCOMP_FILTER_FLAG_LOG" => 2,
        "SECCOMP_FILTER_FLAG_SPEC_ALLOW" => 4,
        "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV" => 32,
        _ => return None,
    })
}

/// Compile an OCI seccomp section (its JSON).
pub fn compile_oci_json(json: &str) -> Result<Compiled, BackendError> {
    let mut v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| BackendError::Json(e.to_string()))?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| BackendError::Json("not a JSON object".into()))?;
    let mut flags = 0u32;
    if let Some(f) = obj.remove("flags") {
        for n in f.as_array().into_iter().flatten() {
            let n = n.as_str().unwrap_or("");
            flags |= flag(n).ok_or_else(|| BackendError::Flag(n.to_string()))?;
        }
    }
    // The runtime's own fields (the listener is youki's to hand out).
    for k in ["listenerPath", "listenerMetadata", "defaultErrnoRet"] {
        if obj.get(k).is_some_and(|x| x.is_null()) {
            obj.remove(k);
        }
    }
    let wants_listener = obj
        .get("syscalls")
        .and_then(|s| s.as_array())
        .into_iter()
        .flatten()
        .any(|s| s.get("action").and_then(|a| a.as_str()) == Some("SCMP_ACT_NOTIFY"));
    let text = serde_json::to_string(&v).expect("a JSON value serializes");
    let p = heimdall_seccomp::oci::from_oci(&text, "oci", Libc::Glibc)
        .map_err(|e| BackendError::Profile(e.to_string()))?;
    if let Some(host) = Arch::native() {
        if host != p.arch {
            return Err(BackendError::Arch {
                profile: p.arch,
                host: host.to_string(),
            });
        }
    }
    let prog = compile_floor(p.arch, &[], &p.rules, Action::KillProcess)
        .map_err(|e| BackendError::Build(e.to_string()))?;
    Ok(Compiled {
        program: prog.insns().to_vec(),
        flags,
        wants_listener,
    })
}

/// Heimdall as libcontainer's seccomp backend.
#[cfg(feature = "youki")]
#[derive(Clone, Copy, Debug, Default)]
pub struct HeimdallBackend;

#[cfg(feature = "youki")]
impl libcontainer::seccomp::SeccompBackend for HeimdallBackend {
    fn name(&self) -> &'static str {
        NAME
    }

    fn compile(
        &self,
        seccomp: &oci_spec::runtime::LinuxSeccomp,
    ) -> Result<libcontainer::seccomp::CompiledSeccomp, libcontainer::seccomp::SeccompError> {
        // The trait has no error of a backend's own: the reason travels as
        // an io::Error in LoadProgram, with the backend's message.
        let err = |e: String| libcontainer::seccomp::SeccompError::LoadProgram {
            source: std::io::Error::other(e),
        };
        let json = serde_json::to_string(seccomp).map_err(|e| err(e.to_string()))?;
        let c = compile_oci_json(&json).map_err(|e| err(e.to_string()))?;
        let program = c
            .program
            .iter()
            .map(|i| libcontainer::seccomp::SockFilter {
                code: i.code,
                jt: i.jt,
                jf: i.jf,
                k: i.k,
            })
            .collect();
        Ok(libcontainer::seccomp::CompiledSeccomp::from_program(
            program,
            c.flags,
            c.wants_listener,
        ))
    }
}

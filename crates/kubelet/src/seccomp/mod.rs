//! A pod's `securityContext.seccompProfile`, as the upstream kubelet reads it.
//!
//! * The container's `seccompProfile` wins over the pod's.
//! * `Unconfined`: no filter. `RuntimeDefault`: the runtime's default
//!   profile (here moby's default profile, `runtime-default.json`, the one
//!   Docker and containerd ship; Apache-2.0, github.com/moby/profiles
//!   seccomp/v0.2.4). `Localhost`: the file `localhostProfile` names, relative
//!   to the kubelet's seccomp profile root (`$KUBELET_SECCOMP_PROFILE_ROOT`,
//!   default `/var/lib/kubelet/seccomp`).
//! * No profile anywhere: nothing is set and the backend keeps its own
//!   default (the upstream kubelet's `seccompDefault: false`).
//! * A privileged container always runs Unconfined (upstream).
//! * A profile that is missing or unreadable refuses the container
//!   (`CreateContainerError`, the pod stays Pending); a bad type or path is a
//!   `CreateContainerConfigError`.
//!
//! Profiles are in Docker's format (what containerd and CRI-O load):
//! `defaultAction`, `defaultErrnoRet`, `archMap` or `architectures`,
//! `syscalls` with `names`/`name`, `action`, `errnoRet`, `args`, and
//! `includes`/`excludes` on `caps`, `arches` and `minKernel`. [`to_oci`]
//! resolves them for one container into the OCI runtime spec's
//! `linux.seccomp`, as containerd does.

use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use rusternetes_common::resources::SeccompProfile;
use serde_json::{json, Map, Value};

/// moby's default seccomp profile (github.com/moby/profiles, tag
/// seccomp/v0.2.4, sha256 785b2429…f9334), unchanged.
pub const RUNTIME_DEFAULT: &str = include_str!("runtime-default.json");

/// Where `Localhost` profiles live when `$KUBELET_SECCOMP_PROFILE_ROOT` is unset.
pub const DEFAULT_PROFILE_ROOT: &str = "/var/lib/kubelet/seccomp";

/// The seccomp setting of one container.
#[derive(Debug, Clone, PartialEq)]
pub enum Seccomp {
    Unconfined,
    RuntimeDefault,
    /// A node-local profile: its path and its contents (Docker format JSON).
    Localhost {
        path: PathBuf,
        profile: String,
    },
}

/// The kubelet's seccomp profile root.
pub fn profile_root() -> PathBuf {
    std::env::var_os("KUBELET_SECCOMP_PROFILE_ROOT")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_ROOT))
}

/// `seccompDefault` (upstream kubelet `--seccomp-default`): on when
/// `$KUBELET_SECCOMP_DEFAULT` is `true` or `1`.
pub fn default_on() -> bool {
    matches!(
        std::env::var("KUBELET_SECCOMP_DEFAULT").as_deref(),
        Ok("true") | Ok("1")
    )
}

/// `seccompDefault` applied to a resolved setting: a container that names no
/// profile (pod or container) runs under RuntimeDefault, not unconfined; a
/// privileged one stays unconfined (upstream).
pub fn apply_default(resolved: Option<Seccomp>, privileged: bool, on: bool) -> Option<Seccomp> {
    match resolved {
        None if on && !privileged => Some(Seccomp::RuntimeDefault),
        r => r,
    }
}

/// The container's setting: its own profile, else the pod's; `None` when
/// neither names one.
pub fn resolve(
    pod: Option<&SeccompProfile>,
    container: Option<&SeccompProfile>,
    privileged: bool,
    root: &Path,
) -> Result<Option<Seccomp>> {
    let Some(p) = container.or(pod) else {
        return Ok(None);
    };
    if privileged {
        return Ok(Some(Seccomp::Unconfined));
    }
    match p.r#type.as_str() {
        "Unconfined" => Ok(Some(Seccomp::Unconfined)),
        "RuntimeDefault" => Ok(Some(Seccomp::RuntimeDefault)),
        "Localhost" => {
            let Some(rel) = p.localhost_profile.as_deref().filter(|s| !s.is_empty()) else {
                bail!("CreateContainerConfigError: seccompProfile type Localhost needs localhostProfile");
            };
            let relp = Path::new(rel);
            if !relp.components().all(|c| matches!(c, Component::Normal(_))) {
                bail!("CreateContainerConfigError: seccompProfile localhostProfile {rel:?} must be a relative path below the profile root, without ..");
            }
            let path = root.join(relp);
            let profile = std::fs::read_to_string(&path).map_err(|e| {
                anyhow::anyhow!(
                    "CreateContainerError: cannot load seccomp profile {:?}: {}",
                    path.display().to_string(),
                    e
                )
            })?;
            let v: Value = serde_json::from_str(&profile).map_err(|e| {
                anyhow::anyhow!(
                    "CreateContainerError: cannot load seccomp profile {:?}: not JSON: {}",
                    path.display().to_string(),
                    e
                )
            })?;
            if v.get("defaultAction").and_then(Value::as_str).is_none() {
                bail!(
                    "CreateContainerError: cannot load seccomp profile {:?}: no defaultAction",
                    path.display().to_string()
                );
            }
            Ok(Some(Seccomp::Localhost { path, profile }))
        }
        other => bail!(
            "CreateContainerConfigError: unknown seccompProfile type {other:?} (RuntimeDefault, Unconfined or Localhost)"
        ),
    }
}

/// Docker's arch names for this machine (`includes.arches`).
fn native_go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "arm" => "arm",
        "riscv64" => "riscv64",
        "s390x" => "s390x",
        "powerpc64" => "ppc64le",
        other => other,
    }
}

/// libseccomp's name for this machine's architecture.
fn native_scmp_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "SCMP_ARCH_X86_64",
        "aarch64" => "SCMP_ARCH_AARCH64",
        "riscv64" => "SCMP_ARCH_RISCV64",
        "s390x" => "SCMP_ARCH_S390X",
        _ => "SCMP_ARCH_NATIVE",
    }
}

/// `"6.12.3-tunnr"` -> (6, 12).
fn kernel_version(release: &str) -> (u32, u32) {
    let mut it = release
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0))
}

/// The running kernel's release (`uname -r`).
pub fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn strings(v: Option<&Value>) -> Vec<&str> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Whether a Docker-format entry applies to this container (moby's rules:
/// every `includes` cap present, the arch listed, the kernel new enough; no
/// `excludes` cap present, the arch not listed).
fn applies(entry: &Value, caps: &[String], arch: &str, kernel: (u32, u32)) -> bool {
    let has = |c: &str| caps.iter().any(|x| x == c);
    if let Some(inc) = entry.get("includes") {
        let arches = strings(inc.get("arches"));
        if !arches.is_empty() && !arches.contains(&arch) {
            return false;
        }
        if !strings(inc.get("caps")).iter().all(|c| has(c)) {
            return false;
        }
        if let Some(min) = inc.get("minKernel").and_then(Value::as_str) {
            if kernel < kernel_version(min) {
                return false;
            }
        }
    }
    if let Some(exc) = entry.get("excludes") {
        if strings(exc.get("arches")).contains(&arch) {
            return false;
        }
        if strings(exc.get("caps")).iter().any(|c| has(c)) {
            return false;
        }
    }
    true
}

/// A Docker-format profile resolved for one container (`caps`: its bounding
/// set) into the OCI runtime spec's `linux.seccomp`.
pub fn to_oci(profile: &str, caps: &[String], kernel_release: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(profile).context("seccomp profile: not JSON")?;
    let default = v
        .get("defaultAction")
        .and_then(Value::as_str)
        .context("seccomp profile: no defaultAction")?;
    let arch = native_go_arch();
    let kernel = kernel_version(kernel_release);
    let mut out = Map::new();
    out.insert("defaultAction".into(), json!(default));
    if let Some(e) = v.get("defaultErrnoRet") {
        out.insert("defaultErrnoRet".into(), e.clone());
    }
    // The native architecture and its sub-architectures from archMap, or the
    // listed architectures.
    let native = native_scmp_arch();
    let mut arches: Vec<String> = Vec::new();
    if let Some(map) = v.get("archMap").and_then(Value::as_array) {
        for m in map {
            if m.get("architecture").and_then(Value::as_str) == Some(native) {
                arches.push(native.to_string());
                arches.extend(
                    strings(m.get("subArchitectures"))
                        .iter()
                        .map(|s| s.to_string()),
                );
            }
        }
    } else {
        arches.extend(
            strings(v.get("architectures"))
                .iter()
                .map(|s| s.to_string()),
        );
    }
    if !arches.is_empty() {
        out.insert("architectures".into(), json!(arches));
    }
    for k in ["flags", "listenerPath", "listenerMetadata"] {
        if let Some(x) = v.get(k) {
            out.insert(k.into(), x.clone());
        }
    }
    let mut syscalls = Vec::new();
    for entry in v
        .get("syscalls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if !applies(entry, caps, arch, kernel) {
            continue;
        }
        let mut names: Vec<&str> = strings(entry.get("names"));
        if let Some(n) = entry.get("name").and_then(Value::as_str) {
            names.push(n);
        }
        if names.is_empty() {
            continue;
        }
        let action = entry
            .get("action")
            .and_then(Value::as_str)
            .context("seccomp profile: a syscall entry has no action")?;
        let mut s = Map::new();
        s.insert("names".into(), json!(names));
        s.insert("action".into(), json!(action));
        if let Some(e) = entry.get("errnoRet") {
            s.insert("errnoRet".into(), e.clone());
        }
        if let Some(args) = entry.get("args").filter(|a| !a.is_null()) {
            s.insert("args".into(), args.clone());
        }
        syscalls.push(Value::Object(s));
    }
    out.insert("syscalls".into(), Value::Array(syscalls));
    // Checked against the OCI types here, so a bad profile refuses the
    // container before the runtime sees it.
    serde_json::from_value::<oci_seccomp::LinuxSeccompShape>(Value::Object(out.clone()))
        .context("seccomp profile: not a valid OCI seccomp profile")?;
    Ok(Value::Object(out))
}

/// The shape of OCI `linux.seccomp` (what oci-spec accepts), so a profile
/// is checked here even without the youki backend.
mod oci_seccomp {
    use serde::Deserialize;

    const ACTIONS: &[&str] = &[
        "SCMP_ACT_KILL",
        "SCMP_ACT_KILL_PROCESS",
        "SCMP_ACT_KILL_THREAD",
        "SCMP_ACT_TRAP",
        "SCMP_ACT_ERRNO",
        "SCMP_ACT_TRACE",
        "SCMP_ACT_ALLOW",
        "SCMP_ACT_LOG",
        "SCMP_ACT_NOTIFY",
    ];
    const OPS: &[&str] = &[
        "SCMP_CMP_NE",
        "SCMP_CMP_LT",
        "SCMP_CMP_LE",
        "SCMP_CMP_EQ",
        "SCMP_CMP_GE",
        "SCMP_CMP_GT",
        "SCMP_CMP_MASKED_EQ",
    ];

    fn action<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
        let s = String::deserialize(d)?;
        if ACTIONS.contains(&s.as_str()) {
            Ok(s)
        } else {
            Err(serde::de::Error::custom(format!(
                "unknown seccomp action {s:?}"
            )))
        }
    }

    fn op<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
        let s = String::deserialize(d)?;
        if OPS.contains(&s.as_str()) {
            Ok(s)
        } else {
            Err(serde::de::Error::custom(format!(
                "unknown seccomp operator {s:?}"
            )))
        }
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(dead_code)]
    pub struct LinuxSeccompShape {
        #[serde(deserialize_with = "action")]
        default_action: String,
        default_errno_ret: Option<u32>,
        #[serde(default)]
        syscalls: Vec<Syscall>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(dead_code)]
    struct Syscall {
        names: Vec<String>,
        #[serde(deserialize_with = "action")]
        action: String,
        errno_ret: Option<u32>,
        #[serde(default)]
        args: Vec<Arg>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(dead_code)]
    struct Arg {
        index: usize,
        value: u64,
        value_two: Option<u64>,
        #[serde(deserialize_with = "op")]
        op: String,
    }
}

/// The setting for Docker's API (`HostConfig.SecurityOpt`): `None` keeps
/// Docker's own default (which is RuntimeDefault).
/// The Docker-API `SecurityOpt` for `s`, the profile named by its PATH: podman's
/// Docker-compatible API opens `seccomp=<value>` as a file (it refuses the JSON
/// text Docker's API takes: "opening seccomp profile failed: ... file name too
/// long"); the kubelet and podman share the node's filesystem.
pub fn docker_security_opt_by_path(s: &Seccomp) -> Option<String> {
    match s {
        Seccomp::Localhost { path, .. } => Some(format!("seccomp={}", path.display())),
        other => docker_security_opt(other),
    }
}

/// `$KUBELET_DOCKER_SECCOMP_BY_PATH` (`true`/`1`): name Localhost profiles by path (podman).
pub fn docker_seccomp_by_path() -> bool {
    matches!(
        std::env::var("KUBELET_DOCKER_SECCOMP_BY_PATH").as_deref(),
        Ok("true") | Ok("1")
    )
}

pub fn docker_security_opt(s: &Seccomp) -> Option<String> {
    match s {
        Seccomp::Unconfined => Some("seccomp=unconfined".into()),
        Seccomp::RuntimeDefault => None,
        Seccomp::Localhost { profile, .. } => Some(format!("seccomp={profile}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(t: &str, l: Option<&str>) -> SeccompProfile {
        SeccompProfile {
            r#type: t.into(),
            localhost_profile: l.map(String::from),
        }
    }

    fn caps(c: &[&str]) -> Vec<String> {
        c.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_profile_anywhere_sets_nothing() {
        assert_eq!(resolve(None, None, false, Path::new("/x")).unwrap(), None);
    }

    #[test]
    fn the_container_profile_wins_over_the_pod_profile() {
        let pod = sp("Unconfined", None);
        let c = sp("RuntimeDefault", None);
        assert_eq!(
            resolve(Some(&pod), Some(&c), false, Path::new("/x")).unwrap(),
            Some(Seccomp::RuntimeDefault)
        );
        assert_eq!(
            resolve(Some(&c), None, false, Path::new("/x")).unwrap(),
            Some(Seccomp::RuntimeDefault)
        );
    }

    #[test]
    fn a_privileged_container_runs_unconfined() {
        let c = sp("RuntimeDefault", None);
        assert_eq!(
            resolve(None, Some(&c), true, Path::new("/x")).unwrap(),
            Some(Seccomp::Unconfined)
        );
    }

    #[test]
    fn a_localhost_profile_is_read_from_below_the_root() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("tunnr")).unwrap();
        let body = r#"{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[]}"#;
        std::fs::write(d.path().join("tunnr/a.json"), body).unwrap();
        let c = sp("Localhost", Some("tunnr/a.json"));
        assert_eq!(
            resolve(None, Some(&c), false, d.path()).unwrap(),
            Some(Seccomp::Localhost {
                path: d.path().join("tunnr/a.json"),
                profile: body.into()
            })
        );
    }

    #[test]
    fn a_missing_localhost_profile_refuses_the_container() {
        let d = tempfile::tempdir().unwrap();
        let c = sp("Localhost", Some("nope.json"));
        let e = resolve(None, Some(&c), false, d.path())
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with("CreateContainerError: cannot load seccomp profile"),
            "{e}"
        );
        assert!(e.contains("nope.json"), "{e}");
    }

    #[test]
    fn a_profile_that_is_not_json_refuses_the_container() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("bad.json"), "{not json").unwrap();
        let c = sp("Localhost", Some("bad.json"));
        let e = resolve(None, Some(&c), false, d.path())
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("CreateContainerError:"), "{e}");
    }

    #[test]
    fn paths_out_of_the_root_and_bad_types_are_config_errors() {
        let d = tempfile::tempdir().unwrap();
        for l in ["../etc/passwd", "/etc/passwd", "a/../../b", ""] {
            let c = sp("Localhost", Some(l));
            let e = resolve(None, Some(&c), false, d.path())
                .unwrap_err()
                .to_string();
            assert!(e.starts_with("CreateContainerConfigError:"), "{l}: {e}");
        }
        let c = sp("Localhost", None);
        assert!(resolve(None, Some(&c), false, d.path()).is_err());
        let c = sp("Strict", None);
        let e = resolve(None, Some(&c), false, d.path())
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with("CreateContainerConfigError: unknown seccompProfile type"),
            "{e}"
        );
    }

    #[test]
    fn the_runtime_default_is_moby_v0_2_4_unchanged() {
        use sha2::Digest;
        let h = sha2::Sha256::digest(RUNTIME_DEFAULT.as_bytes());
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334"
        );
    }

    fn names_of(v: &Value, action: &str) -> Vec<String> {
        v["syscalls"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s["action"] == action)
            .flat_map(|s| {
                s["names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n.as_str().unwrap().to_string())
            })
            .collect()
    }

    #[test]
    fn runtime_default_resolves_caps_arches_and_kernel_like_moby() {
        let plain = to_oci(RUNTIME_DEFAULT, &caps(&["CAP_CHOWN"]), "6.12.0").unwrap();
        let allowed = names_of(&plain, "SCMP_ACT_ALLOW");
        assert!(allowed.iter().any(|n| n == "read"));
        assert!(
            !allowed.iter().any(|n| n == "mount"),
            "mount needs CAP_SYS_ADMIN"
        );
        assert!(
            !allowed.iter().any(|n| n == "chroot"),
            "chroot needs CAP_SYS_CHROOT"
        );
        // clone3 gets ENOSYS without CAP_SYS_ADMIN so libc falls back to clone.
        assert!(names_of(&plain, "SCMP_ACT_ERRNO")
            .iter()
            .any(|n| n == "clone3"));
        if std::env::consts::ARCH == "x86_64" {
            assert!(allowed.iter().any(|n| n == "arch_prctl"));
            assert!(!allowed.iter().any(|n| n == "arm_fadvise64_64"));
            assert_eq!(
                plain["architectures"],
                json!(["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"])
            );
        }
        // ptrace is allowed from kernel 4.8 on.
        assert!(allowed.iter().any(|n| n == "ptrace"));
        let old = to_oci(RUNTIME_DEFAULT, &caps(&[]), "4.4.0").unwrap();
        assert!(!names_of(&old, "SCMP_ACT_ALLOW")
            .iter()
            .any(|n| n == "ptrace"));

        let admin = to_oci(
            RUNTIME_DEFAULT,
            &caps(&["CAP_SYS_ADMIN", "CAP_SYS_CHROOT"]),
            "6.12.0",
        )
        .unwrap();
        let allowed = names_of(&admin, "SCMP_ACT_ALLOW");
        assert!(allowed.iter().any(|n| n == "mount"));
        assert!(allowed.iter().any(|n| n == "chroot"));
        assert!(!names_of(&admin, "SCMP_ACT_ERRNO")
            .iter()
            .any(|n| n == "clone3"));
        assert_eq!(admin["defaultAction"], "SCMP_ACT_ERRNO");
        assert_eq!(admin["defaultErrnoRet"], 1);
    }

    /// **io_uring is not in a pod's RuntimeDefault** (tunnr lane layers, owner
    /// 2026-10-31): moby's profile left it out, with every capability set and
    /// on every kernel, so a RuntimeDefault pod gets EPERM (the profile's
    /// default errno); a pod that needs it (Postgres 18 `io_method=io_uring`)
    /// names a Localhost profile that allows it. The node's own floor allows it.
    #[test]
    fn io_uring_is_denied_by_the_runtime_default_with_every_capability() {
        let all = caps(&[
            "CAP_SYS_ADMIN",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_BOOT",
            "CAP_SYS_MODULE",
            "CAP_SYS_PACCT",
            "CAP_SYS_RAWIO",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_SYS_NICE",
            "CAP_BPF",
            "CAP_PERFMON",
            "CAP_SYSLOG",
            "CAP_NET_ADMIN",
            "CAP_IPC_LOCK",
        ]);
        for (c, kernel) in [(caps(&[]), "6.12.0"), (all, "7.0.0")] {
            let v = to_oci(RUNTIME_DEFAULT, &c, kernel).unwrap();
            for action in [
                "SCMP_ACT_ALLOW",
                "SCMP_ACT_LOG",
                "SCMP_ACT_TRACE",
                "SCMP_ACT_NOTIFY",
            ] {
                let named = names_of(&v, action);
                for call in ["io_uring_setup", "io_uring_enter", "io_uring_register"] {
                    assert!(
                        !named.iter().any(|n| n == call),
                        "{call} under {action} with {c:?}"
                    );
                }
            }
            assert_eq!(v["defaultAction"], "SCMP_ACT_ERRNO");
            assert_eq!(v["defaultErrnoRet"], 1, "EPERM");
        }
    }

    #[test]
    fn single_name_entries_and_args_pass_through() {
        let p = r#"{"defaultAction":"SCMP_ACT_ALLOW","architectures":["SCMP_ARCH_X86_64"],
            "syscalls":[{"name":"mkdirat","action":"SCMP_ACT_KILL_PROCESS",
              "args":[{"index":0,"value":1,"op":"SCMP_CMP_EQ"}]}]}"#;
        let v = to_oci(p, &[], "6.1").unwrap();
        assert_eq!(v["syscalls"][0]["names"], json!(["mkdirat"]));
        assert_eq!(v["syscalls"][0]["args"][0]["op"], "SCMP_CMP_EQ");
        assert_eq!(v["architectures"], json!(["SCMP_ARCH_X86_64"]));
    }

    #[test]
    fn unknown_actions_and_operators_are_refused() {
        let p = r#"{"defaultAction":"SCMP_ACT_MAYBE","syscalls":[]}"#;
        assert!(to_oci(p, &[], "6.1").is_err());
        let p = r#"{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["read"],"action":"SCMP_ACT_ERRNO",
            "args":[{"index":0,"value":1,"op":"SCMP_CMP_ROUGHLY"}]}]}"#;
        assert!(to_oci(p, &[], "6.1").is_err());
    }

    #[test]
    fn docker_gets_security_opts() {
        assert_eq!(
            docker_security_opt(&Seccomp::Unconfined).as_deref(),
            Some("seccomp=unconfined")
        );
        assert_eq!(docker_security_opt(&Seccomp::RuntimeDefault), None);
        let l = Seccomp::Localhost {
            path: "/p".into(),
            profile: "{}".into(),
        };
        assert_eq!(docker_security_opt(&l).as_deref(), Some("seccomp={}"));
    }

    #[test]
    fn kernel_versions_parse() {
        assert_eq!(kernel_version("6.12.3-tunnr"), (6, 12));
        assert_eq!(kernel_version("4.8"), (4, 8));
        assert!(kernel_version("7.0.0") > kernel_version("4.8"));
    }

    /// seccompDefault (lane TUNNR-OPEN): a pod that names no profile is filtered.
    #[test]
    fn seccomp_default_puts_a_container_without_a_profile_under_runtime_default() {
        assert_eq!(
            apply_default(None, false, true),
            Some(Seccomp::RuntimeDefault)
        );
        assert_eq!(apply_default(None, false, false), None, "off: as before");
        assert_eq!(
            apply_default(None, true, true),
            None,
            "privileged stays unconfined"
        );
        assert_eq!(
            apply_default(Some(Seccomp::Unconfined), false, true),
            Some(Seccomp::Unconfined),
            "a named profile wins"
        );
    }

    /// podman's Docker API takes a Localhost profile by its path, not its text.
    #[test]
    fn a_localhost_profile_goes_to_podman_by_path() {
        let l = Seccomp::Localhost {
            path: PathBuf::from("/var/lib/kubelet/seccomp/bench/busybox.json"),
            profile: "{}".into(),
        };
        assert_eq!(
            docker_security_opt_by_path(&l).as_deref(),
            Some("seccomp=/var/lib/kubelet/seccomp/bench/busybox.json")
        );
        assert_eq!(
            docker_security_opt_by_path(&Seccomp::Unconfined).as_deref(),
            Some("seccomp=unconfined")
        );
        assert_eq!(docker_security_opt_by_path(&Seccomp::RuntimeDefault), None);
        assert_eq!(
            docker_security_opt(&l).as_deref(),
            Some("seccomp={}"),
            "Docker's API: the text, as before"
        );
    }
}

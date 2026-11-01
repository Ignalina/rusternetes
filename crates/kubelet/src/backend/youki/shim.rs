//! `rusternetes-youki-shim`: a small single-threaded process per container
//! (and per exec) that calls libcontainer and stays the parent of the
//! container's init process.
//!
//! libcontainer clones processes, which is not safe from the kubelet's
//! multi-threaded tokio runtime. The shim also outlives kubelet restarts and
//! is the one that reaps the container, so exit codes are never lost.
//!
//! ```text
//! rusternetes-youki-shim create <state-root> <id> <bundle> <log> <exit-file>
//! rusternetes-youki-shim exec   <state-root> <id> <args.json> <out|-> <err|-> <exit-file>
//! ```
//!
//! `create` prints `ok <pid>` (or `err <message>`) on stdout once the
//! container exists, then waits for it and writes the exit file.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};

/// Written by the shim when the process it watches exits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitRecord {
    pub exit_code: i64,
    /// RFC 3339.
    pub finished_at: String,
    #[serde(default)]
    pub error: Option<String>,
}

pub fn write_exit(path: &Path, exit_code: i64, error: Option<String>) {
    let rec = ExitRecord {
        exit_code,
        finished_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        error,
    };
    let _ = super::image::write_json(path, &rec);
}

fn wait_exit_code(pid: Pid) -> i64 {
    loop {
        match waitpid(pid, None) {
            Ok(WaitStatus::Exited(_, code)) => return code as i64,
            Ok(WaitStatus::Signaled(_, sig, _)) => return 128 + sig as i64,
            Ok(_) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return 255,
        }
    }
}

fn devnull() -> std::io::Result<OwnedFd> {
    Ok(File::open("/dev/null")?.into())
}

fn append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// **The shim's own filter for its waiting** (tunnr lane layers): the node's
/// PID 1, which starts every shim, names an approved seccomp profile (OCI
/// `linux.seccomp` JSON) here. The shim installs it on itself once the
/// container's process exists — its containers were forked before and keep
/// their own profiles; from then on the shim only waits, reaps and writes the
/// exit file, and that is all its filter allows. Unset: no filter of its own.
pub const WAIT_PROFILE_ENV: &str = "RUSTERNETES_SHIM_WAIT_SECCOMP";

/// Read the wait-phase profile at `path` (OCI `linux.seccomp`).
pub fn load_wait_profile(path: &Path) -> anyhow::Result<oci_spec::runtime::LinuxSeccomp> {
    use anyhow::Context as _;
    let bytes = std::fs::read(path).with_context(|| format!("{}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("{}: not an OCI linux.seccomp", path.display()))
}

/// Install the wait-phase profile [`WAIT_PROFILE_ENV`] names, if any; a
/// profile that cannot be installed is said on stderr (the shim log) and the
/// shim goes on waiting (its container must not lose its reaper).
pub fn tighten() {
    let Some(path) = std::env::var_os(WAIT_PROFILE_ENV) else {
        return;
    };
    let path = PathBuf::from(path);
    let installed = load_wait_profile(&path).and_then(|s| {
        libcontainer::seccomp::initialize_seccomp(&s).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(())
    });
    if let Err(e) = installed {
        eprintln!("rusternetes-youki-shim: the wait-phase filter {} was NOT installed: {e:#}", path.display());
    }
}

/// Entry point of the shim binary; returns the process exit code.
pub fn main(args: Vec<String>) -> i32 {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        [_, "create", state, id, bundle, log, exit] => create(
            state.into(),
            id,
            bundle.into(),
            Path::new(log),
            Path::new(exit),
        ),
        [_, "exec", state, id, args, out, err, exit] => exec(
            state.into(),
            id,
            Path::new(args),
            Path::new(out),
            Path::new(err),
            Path::new(exit),
        ),
        _ => {
            eprintln!("usage: rusternetes-youki-shim create|exec ...");
            2
        }
    }
}

fn create(state: PathBuf, id: &str, bundle: PathBuf, log: &Path, exit: &Path) -> i32 {
    // Own session: signals to the kubelet's process group do not reach us.
    let _ = nix::unistd::setsid();
    let built = (|| -> anyhow::Result<i32> {
        let log = append(log)?;
        let container = ContainerBuilder::new(id.to_string(), SyscallType::default())
            .with_root_path(state)?
            .with_stdin(devnull()?)
            .with_stdout(log.try_clone()?)
            .with_stderr(log)
            .as_init(bundle)
            .with_systemd(false)
            .with_detach(true)
            .build()?;
        container
            .pid()
            .map(|p| p.as_raw())
            .ok_or_else(|| anyhow::anyhow!("container has no init pid"))
    })();
    let mut stdout = std::io::stdout();
    let pid = match built {
        Ok(pid) => {
            let _ = writeln!(stdout, "ok {}", pid);
            let _ = stdout.flush();
            // From here the shim only waits: its own filter (the container keeps its own).
            tighten();
            pid
        }
        Err(e) => {
            let _ = writeln!(stdout, "err {:#}", e);
            return 1;
        }
    };
    let code = wait_exit_code(Pid::from_raw(pid));
    write_exit(exit, code, None);
    0
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecArgs {
    pub cmd: Vec<String>,
    /// The process reads the shim's own stdin (a pipe from the kubelet)
    /// instead of /dev/null.
    #[serde(default)]
    pub stdin: bool,
}

/// `-` is the shim's own stdout or stderr (a pipe the kubelet streams),
/// anything else a file appended to.
fn out_fd(path: &Path, own: std::os::fd::BorrowedFd<'_>) -> std::io::Result<OwnedFd> {
    if path == Path::new("-") {
        own.try_clone_to_owned()
    } else {
        Ok(append(path)?.into())
    }
}

fn exec(state: PathBuf, id: &str, args: &Path, out: &Path, err: &Path, exit: &Path) -> i32 {
    let result = (|| -> anyhow::Result<i64> {
        use std::os::fd::AsFd;
        let args: ExecArgs = serde_json::from_slice(&std::fs::read(args)?)?;
        let stdin: OwnedFd = if args.stdin {
            std::io::stdin().as_fd().try_clone_to_owned()?
        } else {
            devnull()?
        };
        let pid = ContainerBuilder::new(id.to_string(), SyscallType::default())
            .with_root_path(state)?
            .with_stdin(stdin)
            .with_stdout(out_fd(out, std::io::stdout().as_fd())?)
            .with_stderr(out_fd(err, std::io::stderr().as_fd())?)
            .as_tenant()
            .with_container_args(args.cmd)
            .with_detach(true)
            .build()?;
        // The exec'd process exists: from here the shim only waits.
        tighten();
        Ok(wait_exit_code(pid))
    })();
    match result {
        Ok(code) => {
            write_exit(exit, code, None);
            code as i32
        }
        Err(e) => {
            let msg = format!("{:#}", e);
            if err == Path::new("-") {
                eprintln!("{}", msg);
            } else if let Ok(mut f) = append(err) {
                let _ = writeln!(f, "{}", msg);
            }
            // Docker: 127 for a missing command, 126 for one that cannot run.
            let code = if msg.contains("not found") || msg.contains("No such file") {
                127
            } else {
                126
            };
            write_exit(exit, code, Some(msg));
            code as i32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A heimdall-generated profile as the node packs it (OCI JSON with
    /// argument conditions), the shape PID 1 hands the shim.
    const WAIT_PROFILE: &str = r#"{
  "architectures": ["SCMP_ARCH_X86_64"],
  "defaultAction": "SCMP_ACT_KILL_PROCESS",
  "syscalls": [
    {"action": "SCMP_ACT_ALLOW", "names": ["exit_group", "exit", "wait4", "write", "rt_sigreturn"]},
    {"action": "SCMP_ACT_ALLOW", "args": [{"index": 1, "op": "SCMP_CMP_MASKED_EQ", "value": 4294967295, "valueTwo": 2}], "names": ["fcntl"]},
    {"action": "SCMP_ACT_ERRNO", "errnoRet": 38, "names": ["clone3"]}
  ]
}"#;

    fn write_profile(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("shim-wait-{tag}-{}.json", std::process::id()));
        std::fs::write(&p, WAIT_PROFILE).unwrap();
        p
    }

    #[test]
    fn the_wait_profile_loads_from_the_nodes_oci_json() {
        let s = load_wait_profile(&write_profile("load")).unwrap();
        assert_eq!(s.default_action(), oci_spec::runtime::LinuxSeccompAction::ScmpActKillProcess);
        assert_eq!(s.syscalls().as_ref().map(|v| v.len()), Some(3));
        assert!(load_wait_profile(Path::new("/nonexistent/shim.json")).is_err());
    }

    /// The kernel's word: after `tighten`, a call outside the wait profile kills the shim.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn after_tighten_a_call_outside_the_wait_profile_is_killed() {
        let p = write_profile("kill");
        // SAFETY: the child makes raw syscalls only and leaves with _exit.
        match unsafe { libc_fork() } {
            0 => {
                std::env::set_var(WAIT_PROFILE_ENV, &p);
                tighten();
                // SAFETY: a raw getppid, outside the profile.
                unsafe { nix::libc::syscall(nix::libc::SYS_getppid) };
                unsafe { nix::libc::_exit(0) }
            }
            pid => {
                let st = waitpid(Pid::from_raw(pid), None).unwrap();
                assert!(matches!(st, WaitStatus::Signaled(_, nix::sys::signal::Signal::SIGSYS, _)), "{st:?}");
            }
        }
    }

    /// The profile goes on as a STACK of filters (one per action), so a
    /// profile that does not name `seccomp` must still install whole; the
    /// shim then lives on under it (KVM 2026-11-01: every short pod ended
    /// "exit status was not recorded" — the shim died installing its wait
    /// profile, which the node's measured list had no `seccomp` in).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_wait_profile_without_seccomp_in_it_still_installs_whole() {
        let p = write_profile("whole");
        match unsafe { libc_fork() } {
            0 => {
                std::env::set_var(WAIT_PROFILE_ENV, &p);
                tighten();
                unsafe { nix::libc::_exit(7) }
            }
            pid => {
                let st = waitpid(Pid::from_raw(pid), None).unwrap();
                assert!(matches!(st, WaitStatus::Exited(_, 7)), "the shim must survive its own install: {st:?}");
            }
        }
    }

    unsafe fn libc_fork() -> i32 {
        unsafe { nix::libc::fork() }
    }
}

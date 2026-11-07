// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Ignalina ApS and Vetra Automation AB

//! Start a program with a seccomp filter installed just before exec.
//! Heimdall is a defensive sandbox: the filter covers the program from its
//! first instruction.
//!
//! The child, after fork (async-signal-safe calls only, nothing allocated):
//!
//! 1. sets up stdio, puts the program's `O_PATH` fd at [`EXEC_FD`] and (with
//!    a listener) one end of a unix socket at [`HANDOFF_FD`], both close-on-exec;
//! 2. `PR_SET_NO_NEW_PRIVS`, then installs the filter (`NEW_LISTENER` when
//!    the parent asked for the USER_NOTIF listener);
//! 3. sends the listener fd to the parent over [`HANDOFF_FD`];
//! 4. `execveat(EXEC_FD, "", argv, envp, AT_EMPTY_PATH)`.
//!
//! Steps 3 and 4 run under the filter, so every filter built here starts
//! with the [`prelude`]: `execveat` only on `EXEC_FD` with `AT_EMPTY_PATH`,
//! and `sendmsg` only on `HANDOFF_FD` (with a listener). The worker's own
//! profile does not need a bare `execve`. Both fds are close-on-exec, so the
//! worker starts without them; the prelude is part of every filter, in
//! learning mode too, so the probe and enforcement agree.
//!
//! [`Launch::exec_by_path`] (the dynamic-trace job, heimdall-trace) starts the
//! program with a plain `execve(path, ..)` instead and leaves the `execveat`
//! rule out of the prelude: the first exec then goes through the filter like
//! every later one (a listener sees it), and no process under the filter can
//! exec unseen through `EXEC_FD`. It works where `execveat` is refused (the
//! fixed profile of heimdall-container) and needs a filter that lets `execve`
//! through (a rule, or a listener that answers it).

use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::arch::Arch;
use crate::bpf::{BuildError, Mode, Program, SockFilter};
use crate::notif::{raw_send_fd, recv_fd, Listener};
use crate::profile::{Action, ArgCmp, Profile, Rule};

/// The fd number the program to exec sits at in the child (close-on-exec).
pub const EXEC_FD: RawFd = 1022;
/// The fd number of the child's end of the listener hand-off socket.
pub const HANDOFF_FD: RawFd = 1021;

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
/// `SECCOMP_FILTER_FLAG_TSYNC`.
pub const FILTER_FLAG_TSYNC: libc::c_ulong = 1;
/// `SECCOMP_FILTER_FLAG_LOG`.
pub const FILTER_FLAG_LOG: libc::c_ulong = 2;
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
pub const FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 8;

/// The rules every filter built by [`Launch`] starts with (see module docs).
pub fn prelude(listener: bool) -> Vec<Rule> {
    prelude_for(listener, false)
}

/// The prelude of a [`Launch`]; `by_path`: [`Launch::exec_by_path`], no
/// `execveat` rule.
pub fn prelude_for(listener: bool, by_path: bool) -> Vec<Rule> {
    let mut v = Vec::new();
    if !by_path {
        v.push(Rule {
            syscall: "execveat".into(),
            action: Action::Allow,
            when: vec![vec![
                ArgCmp::eq32(0, EXEC_FD as u32),
                ArgCmp::eq32(4, libc::AT_EMPTY_PATH as u32),
            ]],
        });
    }
    if listener {
        v.push(Rule {
            syscall: "sendmsg".into(),
            action: Action::Allow,
            when: vec![vec![ArgCmp::eq32(0, HANDOFF_FD as u32)]],
        });
    }
    v
}

#[repr(C)]
struct Fprog {
    len: libc::c_ushort,
    filter: *const SockFilter,
}

/// Install a filter on the calling thread (`flags` e.g. [`FILTER_FLAG_TSYNC`]
/// for every thread), after `PR_SET_NO_NEW_PRIVS`. With
/// [`FILTER_FLAG_NEW_LISTENER`] the listener fd is returned.
pub fn install(prog: &Program, flags: libc::c_ulong) -> io::Result<Option<OwnedFd>> {
    let fprog = Fprog {
        len: prog.len() as libc::c_ushort,
        filter: prog.insns().as_ptr(),
    };
    // SAFETY: prctl and seccomp with a valid sock_fprog that outlives the call.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        let r = libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &fprog);
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & FILTER_FLAG_NEW_LISTENER != 0 {
            Ok(Some(OwnedFd::from_raw_fd(r as RawFd)))
        } else {
            Ok(None)
        }
    }
}

/// Where a child's stdin/stdout/stderr goes.
#[derive(Debug)]
pub enum Stdio {
    Inherit,
    Null,
    Fd(OwnedFd),
}

/// How the child ended.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    Signal { signal: i32, core: bool },
}

impl Exit {
    /// Killed by `SIGSYS`: what `SECCOMP_RET_KILL_PROCESS` does.
    pub fn killed_by_seccomp(&self) -> bool {
        matches!(self, Exit::Signal { signal, .. } if *signal == libc::SIGSYS)
    }
    /// Exit code 0.
    pub fn success(&self) -> bool {
        *self == Exit::Code(0)
    }
}

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Exit::Code(c) => write!(f, "exit {c}"),
            Exit::Signal { signal, .. } if *signal == libc::SIGSYS => {
                f.write_str("killed by seccomp (SIGSYS)")
            }
            Exit::Signal { signal, .. } => write!(f, "killed by signal {signal}"),
        }
    }
}

/// A program to start under a filter.
#[derive(Debug)]
pub struct Launch {
    program: PathBuf,
    arg0: Option<OsString>,
    args: Vec<OsString>,
    env_clear: bool,
    env: Vec<(OsString, OsString)>,
    cwd: Option<PathBuf>,
    stdio: [Stdio; 3],
    filter: Option<(Arch, Vec<Rule>, Action)>,
    listener: bool,
    by_path: bool,
}

/// A started program.
#[derive(Debug)]
pub struct Launched {
    pid: libc::pid_t,
    listener: Option<Listener>,
    exit: Option<Exit>,
}

impl Launch {
    /// `program`: a path, or a bare name searched in `PATH`.
    pub fn new(program: impl AsRef<Path>) -> Launch {
        Launch {
            program: program.as_ref().to_path_buf(),
            arg0: None,
            args: Vec::new(),
            env_clear: false,
            env: Vec::new(),
            cwd: None,
            stdio: [Stdio::Inherit, Stdio::Inherit, Stdio::Inherit],
            filter: None,
            listener: false,
            by_path: false,
        }
    }
    pub fn arg0(mut self, a: impl AsRef<OsStr>) -> Launch {
        self.arg0 = Some(a.as_ref().to_os_string());
        self
    }
    pub fn arg(mut self, a: impl AsRef<OsStr>) -> Launch {
        self.args.push(a.as_ref().to_os_string());
        self
    }
    pub fn args<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(mut self, a: I) -> Launch {
        self.args
            .extend(a.into_iter().map(|s| s.as_ref().to_os_string()));
        self
    }
    /// Start from an empty environment instead of this process's.
    pub fn env_clear(mut self) -> Launch {
        self.env_clear = true;
        self.env.clear();
        self
    }
    pub fn env(mut self, k: impl AsRef<OsStr>, v: impl AsRef<OsStr>) -> Launch {
        self.env
            .push((k.as_ref().to_os_string(), v.as_ref().to_os_string()));
        self
    }
    pub fn cwd(mut self, d: impl AsRef<Path>) -> Launch {
        self.cwd = Some(d.as_ref().to_path_buf());
        self
    }
    pub fn stdin(mut self, s: Stdio) -> Launch {
        self.stdio[0] = s;
        self
    }
    pub fn stdout(mut self, s: Stdio) -> Launch {
        self.stdio[1] = s;
        self
    }
    pub fn stderr(mut self, s: Stdio) -> Launch {
        self.stdio[2] = s;
        self
    }
    /// Enforce or audit this profile.
    pub fn profile(self, p: &Profile, mode: &Mode) -> Launch {
        self.rules(p.arch, p.rules.clone(), mode.default_action())
    }
    /// Any rules with any default action (the probe: `UserNotif`).
    pub fn rules(mut self, arch: Arch, rules: Vec<Rule>, default: Action) -> Launch {
        self.filter = Some((arch, rules, default));
        self
    }
    /// The floor of a call filter ([`crate::filter::CallFilter`]: its rules
    /// and its default), behind this launch's prelude. The enforcing path:
    /// the program is built by the same pipeline as [`crate::filter::compile`].
    pub fn filter(self, f: &dyn crate::filter::CallFilter) -> Launch {
        self.rules(f.arch(), f.floor().to_vec(), f.floor_default())
    }
    /// Hand the filter's USER_NOTIF listener to the parent
    /// ([`Launched::take_listener`]). Needed whenever a rule (or the default)
    /// is `UserNotif`; the parent must then serve it, or the child blocks.
    pub fn listener(mut self, on: bool) -> Launch {
        self.listener = on;
        self
    }

    /// Start the program with `execve(path, ..)` under the filter instead of
    /// `execveat(EXEC_FD, ..)`, and leave the `execveat` rule out of the
    /// prelude (module docs). The filter must let that `execve` through.
    pub fn exec_by_path(mut self, on: bool) -> Launch {
        self.by_path = on;
        self
    }

    /// The program this launch would install (prelude included).
    pub fn program(&self) -> Result<Program, BuildError> {
        let (arch, rules, default) = self
            .filter
            .as_ref()
            .expect("Launch needs a filter: call .profile() or .rules()");
        crate::filter::compile_floor(
            *arch,
            &prelude_for(self.listener, self.by_path),
            rules,
            *default,
        )
    }

    /// Fork, install, exec. Errors before exec (no such program, the filter
    /// does not build or install) come back here; an exec failure after the
    /// install shows as exit 127.
    pub fn spawn(self) -> io::Result<Launched> {
        let prog = self.program().map_err(io::Error::other)?;
        let fprog = Fprog {
            len: prog.len() as libc::c_ushort,
            filter: prog.insns().as_ptr(),
        };
        let exe = open_program(&self.program)?;
        let exe_path = if self.by_path {
            Some(cstring(resolve_program(&self.program)?.as_os_str())?)
        } else {
            None
        };
        let arg0 = self
            .arg0
            .clone()
            .unwrap_or_else(|| self.program.clone().into_os_string());
        let argv_c: Vec<CString> = std::iter::once(&arg0)
            .chain(self.args.iter())
            .map(|a| cstring(a))
            .collect::<io::Result<_>>()?;
        let mut env: Vec<(OsString, OsString)> = if self.env_clear {
            Vec::new()
        } else {
            std::env::vars_os().collect()
        };
        for (k, v) in &self.env {
            env.retain(|(ek, _)| ek != k);
            env.push((k.clone(), v.clone()));
        }
        let envp_c: Vec<CString> = env
            .iter()
            .map(|(k, v)| {
                let mut kv = k.clone();
                kv.push("=");
                kv.push(v);
                cstring(&kv)
            })
            .collect::<io::Result<_>>()?;
        let argv: Vec<*const libc::c_char> = argv_c
            .iter()
            .map(|c| c.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp: Vec<*const libc::c_char> = envp_c
            .iter()
            .map(|c| c.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let cwd = self
            .cwd
            .as_ref()
            .map(|d| cstring(d.as_os_str()))
            .transpose()?;
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")?;
        let stdio: [RawFd; 3] = [0, 1, 2].map(|i| match &self.stdio[i] {
            Stdio::Inherit => -1,
            Stdio::Null => null.as_raw_fd(),
            Stdio::Fd(f) => f.as_raw_fd(),
        });
        let (err_r, err_w) = pipe_cloexec()?;
        let (sock_parent, sock_child) = if self.listener {
            let (a, b) = socketpair_cloexec()?;
            (Some(a), Some(b))
        } else {
            (None, None)
        };
        let mut flags = 0;
        if self.listener {
            flags |= FILTER_FLAG_NEW_LISTENER;
        }
        let child = ChildSpec {
            stdio,
            exe: exe.as_raw_fd(),
            exe_path: exe_path.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            sock: sock_child.as_ref().map_or(-1, |s| s.as_raw_fd()),
            err: err_w.as_raw_fd(),
            cwd: cwd.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            fprog: &fprog,
            flags,
            argv: argv.as_ptr(),
            envp: envp.as_ptr(),
        };
        // SAFETY: the child runs only async-signal-safe libc calls on data
        // prepared above, then execs or _exits.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // SAFETY: see above.
            unsafe { child_main(&child) }
        }
        drop(err_w);
        drop(sock_child);
        let mut launched = Launched {
            pid,
            listener: None,
            exit: None,
        };
        // Wait for: an error report on the pipe, or the listener on the socket.
        match wait_handoff(&err_r, sock_parent.as_ref()) {
            Ok(Some(l)) => launched.listener = Some(Listener::from_fd(l)),
            Ok(None) => {}
            Err(e) => {
                let _ = launched.wait();
                return Err(e);
            }
        }
        Ok(launched)
    }
}

impl Launched {
    /// The child's pid.
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }
    /// The USER_NOTIF listener (once), when [`Launch::listener`] was set.
    pub fn take_listener(&mut self) -> Option<Listener> {
        self.listener.take()
    }
    /// Send a signal to the child.
    pub fn signal(&self, sig: i32) -> io::Result<()> {
        if self.exit.is_some() {
            return Ok(());
        }
        // SAFETY: kill on our own, not yet reaped child.
        if unsafe { libc::kill(self.pid, sig) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    /// Wait for the child to end (reaps it).
    pub fn wait(&mut self) -> io::Result<Exit> {
        if let Some(e) = self.exit {
            return Ok(e);
        }
        let mut st: libc::c_int = 0;
        loop {
            // SAFETY: waitpid on our own child.
            let r = unsafe { libc::waitpid(self.pid, &mut st, 0) };
            if r == self.pid {
                break;
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
        let exit = if libc::WIFEXITED(st) {
            Exit::Code(libc::WEXITSTATUS(st))
        } else {
            Exit::Signal {
                signal: libc::WTERMSIG(st),
                core: libc::WCOREDUMP(st),
            }
        };
        self.exit = Some(exit);
        Ok(exit)
    }
}

impl Drop for Launched {
    fn drop(&mut self) {
        if self.exit.is_none() {
            let _ = self.signal(libc::SIGKILL);
            let _ = self.wait();
        }
    }
}

struct ChildSpec {
    stdio: [RawFd; 3],
    exe: RawFd,
    /// [`Launch::exec_by_path`]: the program's path (else null).
    exe_path: *const libc::c_char,
    sock: RawFd,
    err: RawFd,
    cwd: *const libc::c_char,
    fprog: *const Fprog,
    flags: libc::c_ulong,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
}

/// Report `errno` with a stage byte on the error pipe, then `_exit`.
unsafe fn child_fail(c: &ChildSpec, stage: u8) -> ! {
    let e = *libc::__errno_location();
    let mut msg = [0u8; 5];
    msg[0] = stage;
    msg[1..].copy_from_slice(&e.to_ne_bytes());
    libc::write(c.err, msg.as_ptr().cast(), msg.len());
    libc::_exit(126)
}

unsafe fn child_main(c: &ChildSpec) -> ! {
    for (i, &fd) in c.stdio.iter().enumerate() {
        if fd >= 0 && libc::dup2(fd, i as RawFd) < 0 {
            child_fail(c, b's');
        }
    }
    if c.exe_path.is_null() && libc::dup3(c.exe, EXEC_FD, libc::O_CLOEXEC) < 0 {
        child_fail(c, b'x');
    }
    if c.sock >= 0 && libc::dup3(c.sock, HANDOFF_FD, libc::O_CLOEXEC) < 0 {
        child_fail(c, b'h');
    }
    if !c.cwd.is_null() && libc::chdir(c.cwd) != 0 {
        child_fail(c, b'c');
    }
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        child_fail(c, b'n');
    }
    let r = libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, c.flags, c.fprog);
    if r < 0 {
        child_fail(c, b'f');
    }
    // From here on every call is filtered: only the prelude's.
    if c.flags & FILTER_FLAG_NEW_LISTENER != 0 && raw_send_fd(HANDOFF_FD, r as RawFd) < 0 {
        libc::_exit(125);
    }
    if !c.exe_path.is_null() {
        libc::syscall(libc::SYS_execve, c.exe_path, c.argv, c.envp);
        libc::_exit(127)
    }
    let empty = c"".as_ptr();
    libc::syscall(
        libc::SYS_execveat,
        EXEC_FD,
        empty,
        c.argv,
        c.envp,
        libc::AT_EMPTY_PATH,
    );
    libc::_exit(127)
}

fn stage_name(b: u8) -> &'static str {
    match b {
        b's' => "set up stdio",
        b'x' => "place the program fd",
        b'h' => "place the hand-off socket",
        b'c' => "chdir",
        b'n' => "set no_new_privs",
        b'f' => "install the seccomp filter",
        _ => "start",
    }
}

/// Read the error pipe / receive the listener.
fn wait_handoff(err_r: &OwnedFd, sock: Option<&OwnedFd>) -> io::Result<Option<OwnedFd>> {
    let mut fds = vec![libc::pollfd {
        fd: err_r.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }];
    if let Some(s) = sock {
        fds.push(libc::pollfd {
            fd: s.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
    }
    loop {
        // SAFETY: valid pollfd array.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if let Some(s) = sock {
            if fds[1].revents & libc::POLLIN != 0 {
                return recv_fd(s.as_fd()).map(Some);
            }
        }
        if fds[0].revents != 0 {
            let mut msg = [0u8; 5];
            // SAFETY: read into a local buffer.
            let n = unsafe { libc::read(err_r.as_raw_fd(), msg.as_mut_ptr().cast(), 5) };
            if n == 5 {
                let errno = i32::from_ne_bytes(msg[1..].try_into().unwrap());
                let os = io::Error::from_raw_os_error(errno);
                return Err(io::Error::new(
                    os.kind(),
                    format!("the child could not {}: {os}", stage_name(msg[0])),
                ));
            }
            if sock.is_none() {
                // EOF: the exec happened (or the child died after the install;
                // its exit status says so).
                return Ok(None);
            }
            if fds.len() == 2 && fds[1].revents == 0 {
                // EOF on the pipe but no listener: the child died after the
                // install without sending it.
                return Err(io::Error::other(
                    "the child exited before handing over its seccomp listener",
                ));
            }
        }
        if let Some(s) = sock {
            if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                return recv_fd(s.as_fd()).map(Some);
            }
        }
    }
}

fn cstring(s: &OsStr) -> io::Result<CString> {
    CString::new(s.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a NUL byte in an argument"))
}

fn open_program(p: &Path) -> io::Result<OwnedFd> {
    let path = resolve_program(p)?;
    let c = cstring(path.as_os_str())?;
    // SAFETY: open with a valid C string.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("{}: {e}", path.display())));
    }
    // SAFETY: a fresh fd we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `p` itself when it holds a `/`, else the first file of that name in `PATH`.
fn resolve_program(p: &Path) -> io::Result<PathBuf> {
    Ok(if p.as_os_str().as_bytes().contains(&b'/') {
        p.to_path_buf()
    } else {
        std::env::var_os("PATH")
            .and_then(|path| {
                std::env::split_paths(&path)
                    .map(|d| d.join(p))
                    .find(|c| c.is_file())
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{} not found in PATH", p.display()),
                )
            })?
    })
}

fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 writes two fds.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fds we own.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn socketpair_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: socketpair writes two fds.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fds we own.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Replace the CALLING process with a program under a filter: the in-place
/// form of [`Launch`] for a runtime that already is the job's process (a
/// container's init right before `execve`, heimdall-container's executor).
/// Heimdall is a defensive sandbox: the filter covers the program from its
/// first instruction, with the same [`prelude`] as [`Launch`] (`execveat` only
/// on [`EXEC_FD`] with `AT_EMPTY_PATH`), so a profile the probe generated
/// through [`Launch`] fits unchanged.
///
/// Steps: [`ExecSelf::new`] prepares everything that allocates (opens the
/// program `O_PATH` at [`EXEC_FD`], close-on-exec; builds argv, envp and the
/// program); [`ExecSelf::install`] sets no-new-privs and installs the filter
/// on every thread (`TSYNC`); [`ExecSelf::exec`] calls `execveat` and returns
/// only on failure. Between `install` and `exec` the caller may use only the
/// calls its own `extra` rules allow.
#[derive(Debug)]
pub struct ExecSelf {
    exe: OwnedFd,
    argv_c: Vec<CString>,
    envp_c: Vec<CString>,
    prog: Program,
}

impl ExecSelf {
    /// `program` must be a path (no `PATH` search here: the caller knows the
    /// job's environment). `argv[0]` is the program's own argv\[0\].
    /// The filter: [`prelude`]`(false)`, then `extra` (e.g. a `write` to a
    /// report fd), then the profile's rules; default `default`.
    pub fn new(
        program: &Path,
        argv: &[OsString],
        env: &[OsString],
        arch: Arch,
        extra: Vec<Rule>,
        rules: &[Rule],
        default: Action,
    ) -> io::Result<ExecSelf> {
        let mut pre = prelude(false);
        pre.extend(extra);
        let prog =
            crate::filter::compile_floor(arch, &pre, rules, default).map_err(io::Error::other)?;
        ExecSelf::with_program(program, argv, env, prog)
    }

    /// The same with a compiled filter ([`crate::filter::compile`] with
    /// [`prelude`]`(false)` and the caller's extra rules as its prelude): the
    /// enforcing path of a generated profile.
    pub fn from_compiled(
        program: &Path,
        argv: &[OsString],
        env: &[OsString],
        compiled: &crate::filter::Compiled,
    ) -> io::Result<ExecSelf> {
        ExecSelf::with_program(program, argv, env, compiled.floor.clone())
    }

    fn with_program(
        program: &Path,
        argv: &[OsString],
        env: &[OsString],
        prog: Program,
    ) -> io::Result<ExecSelf> {
        if !program.as_os_str().as_bytes().contains(&b'/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a path", program.display()),
            ));
        }
        let opened = open_program(program)?;
        // SAFETY: dup3 onto a fixed fd number; the new fd is ours.
        let fd = unsafe { libc::dup3(opened.as_raw_fd(), EXEC_FD, libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh fd we own (dup3 returned it).
        let exe = unsafe { OwnedFd::from_raw_fd(fd) };
        drop(opened);
        let argv_c = argv.iter().map(|a| cstring(a)).collect::<io::Result<_>>()?;
        let envp_c = env.iter().map(|a| cstring(a)).collect::<io::Result<_>>()?;
        Ok(ExecSelf {
            exe,
            argv_c,
            envp_c,
            prog,
        })
    }

    /// The program that [`ExecSelf::install`] installs (prelude included).
    pub fn program(&self) -> &Program {
        &self.prog
    }

    /// No-new-privs and the filter, on every thread of the calling process.
    pub fn install(&self) -> io::Result<()> {
        install(&self.prog, FILTER_FLAG_TSYNC).map(|_| ())
    }

    /// No-new-privs and the filter with a USER_NOTIF listener
    /// ([`FILTER_FLAG_NEW_LISTENER`]) on the calling thread; returns the
    /// listener (close-on-exec). Learning mode inside a container's init
    /// (heimdall-container's `probe-container` path). The kernel refuses
    /// `TSYNC` together with `NEW_LISTENER`, so call it from a
    /// single-threaded process.
    pub fn install_listener(&self) -> io::Result<OwnedFd> {
        install(&self.prog, FILTER_FLAG_NEW_LISTENER)?
            .ok_or_else(|| io::Error::other("seccomp returned no listener fd"))
    }

    /// `execveat(EXEC_FD, "", argv, envp, AT_EMPTY_PATH)`; returns only on
    /// failure (after [`ExecSelf::install`], the filter decides what the
    /// caller may still do: usually only `exit_group`).
    pub fn exec(self) -> io::Error {
        let argv: Vec<*const libc::c_char> = self
            .argv_c
            .iter()
            .map(|c| c.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp: Vec<*const libc::c_char> = self
            .envp_c
            .iter()
            .map(|c| c.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let empty = c"";
        // SAFETY: execveat with NUL-terminated argv/envp arrays of valid C
        // strings that live until the call returns (it returns only on error).
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                self.exe.as_raw_fd(),
                empty.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
        }
        io::Error::last_os_error()
    }
}

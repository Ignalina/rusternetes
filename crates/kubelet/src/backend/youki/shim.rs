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
    wait_outcome(pid).0
}

/// `(Docker exit code, exit code, signal)` of `pid`.
fn wait_outcome(pid: Pid) -> (i64, Option<i64>, Option<i32>) {
    loop {
        match waitpid(pid, None) {
            Ok(WaitStatus::Exited(_, code)) => return (code as i64, Some(code as i64), None),
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                return (128 + sig as i64, None, Some(sig as i32))
            }
            Ok(_) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return (255, None, None),
        }
    }
}

/// The RuntimeClass result hook: when the kubelet left a handler record
/// naming a result socket in the bundle, send it the [`ResultRequest`]
/// (one JSON object, then end of stream) and append its answer to the
/// container's log, before the exit file is written (so a log read after the
/// container is seen terminated has it). A hook that cannot be reached is
/// named in the log (`heimdall-refused: ...`); the container's exit stands.
///
/// [`ResultRequest`]: super::handler::ResultRequest
pub fn result_hook(
    bundle: &Path,
    log: &Path,
    id: &str,
    exit_code: Option<i64>,
    signal: Option<i32>,
    started_unix: i64,
    finished_unix: i64,
) {
    use super::handler::{Record, ResultRequest, RECORD_FILE};
    let Ok(text) = std::fs::read(bundle.join(RECORD_FILE)) else {
        return;
    };
    let answer = (|| -> anyhow::Result<String> {
        let record: Record = serde_json::from_slice(&text)?;
        let Some(sock) = record.result_socket.clone() else {
            return Ok(String::new());
        };
        let req = ResultRequest {
            container: id.to_string(),
            record,
            exit_code,
            signal,
            started_unix,
            finished_unix,
        };
        let mut s = std::os::unix::net::UnixStream::connect(&sock)
            .map_err(|e| anyhow::anyhow!("no result hook at {}: {e}", sock.display()))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(60)))?;
        s.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
        s.write_all(&serde_json::to_vec(&req)?)?;
        s.shutdown(std::net::Shutdown::Write)?;
        let mut out = String::new();
        std::io::Read::read_to_string(&mut s, &mut out)?;
        if out.is_empty() {
            anyhow::bail!("the result hook at {} answered nothing", sock.display());
        }
        Ok(out)
    })();
    let line = match answer {
        Ok(a) if a.is_empty() => return,
        Ok(a) if a.ends_with('\n') => a,
        Ok(a) => a + "\n",
        Err(e) => format!("heimdall-refused: {e:#}\n"),
    };
    if let Ok(mut f) = append(log) {
        let _ = f.write_all(line.as_bytes());
    }
}

fn devnull() -> std::io::Result<OwnedFd> {
    Ok(File::open("/dev/null")?.into())
}

fn append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
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
        let bundle = bundle.clone();
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
            pid
        }
        Err(e) => {
            let _ = writeln!(stdout, "err {:#}", e);
            return 1;
        }
    };
    let started = chrono::Utc::now().timestamp();
    let (code, exit_code, signal) = wait_outcome(Pid::from_raw(pid));
    result_hook(
        &bundle,
        log,
        id,
        exit_code,
        signal,
        started,
        chrono::Utc::now().timestamp(),
    );
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
    use crate::backend::youki::handler::{Record, ResultRequest, RECORD_FILE};

    fn record(sock: Option<PathBuf>) -> Record {
        Record {
            handler: "heimdall".into(),
            result_socket: sock,
            image: "busybox@sha256:00".into(),
            ..Default::default()
        }
    }

    #[test]
    fn the_result_hook_gets_the_request_and_its_answer_lands_in_the_log() {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("k8s.sock");
        let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        l.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            // A hook that never calls must fail the test, not hang it.
            let t0 = std::time::Instant::now();
            let mut s = loop {
                match l.accept() {
                    Ok((s, _)) => break s,
                    Err(_) if t0.elapsed() < std::time::Duration::from_secs(10) => {
                        std::thread::sleep(std::time::Duration::from_millis(20))
                    }
                    Err(e) => return Err(format!("the hook never called: {e}")),
                }
            };
            s.set_nonblocking(false).unwrap();
            let mut req = String::new();
            std::io::Read::read_to_string(&mut s, &mut req).unwrap();
            let req: ResultRequest = serde_json::from_str(&req).unwrap();
            s.write_all(b"heimdall-features: {}\nheimdall-signed-result: AAAA\n")
                .unwrap();
            Ok(req)
        });
        std::fs::write(
            d.path().join(RECORD_FILE),
            serde_json::to_vec(&record(Some(sock))).unwrap(),
        )
        .unwrap();
        let log = d.path().join("output.log");
        std::fs::write(&log, "job output\n").unwrap();
        result_hook(d.path(), &log, "c1", Some(0), None, 10, 12);
        let req = server.join().unwrap().unwrap();
        assert_eq!(req.container, "c1");
        assert_eq!(req.record.handler, "heimdall");
        assert_eq!((req.exit_code, req.signal), (Some(0), None));
        assert_eq!((req.started_unix, req.finished_unix), (10, 12));
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "job output\nheimdall-features: {}\nheimdall-signed-result: AAAA\n"
        );
    }

    #[test]
    fn a_missing_result_hook_is_named_in_the_log() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join(RECORD_FILE),
            serde_json::to_vec(&record(Some(d.path().join("absent.sock")))).unwrap(),
        )
        .unwrap();
        let log = d.path().join("output.log");
        result_hook(d.path(), &log, "c1", None, Some(9), 1, 2);
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(
            text.starts_with("heimdall-refused: no result hook at "),
            "{text}"
        );
    }

    #[test]
    fn no_record_or_no_socket_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let log = d.path().join("output.log");
        result_hook(d.path(), &log, "c1", Some(0), None, 1, 2);
        assert!(!log.exists());
        std::fs::write(
            d.path().join(RECORD_FILE),
            serde_json::to_vec(&record(None)).unwrap(),
        )
        .unwrap();
        result_hook(d.path(), &log, "c1", Some(0), None, 1, 2);
        assert!(!log.exists());
    }
}

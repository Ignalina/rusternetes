// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Ignalina ApS and Vetra Automation AB

//! The seccomp USER_NOTIF API (kernel >= 5.0; `CONTINUE` >= 5.5, `ADDFD` >=
//! 5.9, `ADDFD_FLAG_SEND` >= 5.14). Heimdall is a defensive sandbox: this is
//! the small surface the broker (heimdall-broker, spec §4) and the probe
//! (heimdall-probe, learning mode) are built on. It is deliberately thin:
//!
//! ```text
//! let l = Listener::from_fd(fd);           // from launch::Launched, or SCM_RIGHTS
//! loop {
//!     let n = l.recv()?;                   // blocks; n.data = nr, arch, ip, args
//!     // read the target's memory (broker), check policy, open the file itself...
//!     if !l.id_valid(n.id)? { continue; }  // the target died or the call was interrupted
//!     l.add_fd(n.id, file.as_fd(), AddFd::send())?;  // inject + answer atomically, or
//!     l.respond(n.id, Response::Errno(libc::EACCES))?;
//! }
//! ```
//!
//! Rules for callers (the TOCTOU contract of spec §4):
//! - Never answer [`Response::Continue`] after checking memory the target can
//!   change (a path, a sockaddr): the kernel would act on the racy pointer.
//!   `Continue` is only for calls whose decision depends on registers alone
//!   (the probe's log-and-allow).
//! - Call [`Listener::id_valid`] after reading target memory and before acting
//!   on it, so a recycled pid cannot hand you another process's memory.
//! - [`Listener::recv`] returns `ENOENT` when the target died between the
//!   kernel queueing the notification and the receive; just receive again.
//! - [`Listener::wait`] reports [`Readiness::Hangup`] once every task using
//!   the filter has exited: the supervisor loop is done.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

/// `struct seccomp_data`: what the filter (and the supervisor) sees.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SeccompData {
    pub nr: i32,
    /// `AUDIT_ARCH_*` of the call (see [`crate::Arch::from_audit_arch`]).
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

impl SeccompData {
    /// The 64 bytes the kernel hands a filter (native, little-endian layout).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[0..4].copy_from_slice(&self.nr.to_ne_bytes());
        b[4..8].copy_from_slice(&self.arch.to_ne_bytes());
        b[8..16].copy_from_slice(&self.instruction_pointer.to_ne_bytes());
        for (i, a) in self.args.iter().enumerate() {
            b[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_ne_bytes());
        }
        b
    }
}

/// `struct seccomp_notif`: one paused call.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Notif {
    /// The cookie every answer must name.
    pub id: u64,
    /// The calling thread's tid, in the supervisor's pid namespace (0 when
    /// the target is not visible from it).
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

/// `struct seccomp_notif_resp`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct NotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

/// `struct seccomp_notif_addfd`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct NotifAddfd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

/// `struct seccomp_notif_sizes`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct NotifSizes {
    notif: u16,
    resp: u16,
    data: u16,
}

const SECCOMP_GET_NOTIF_SIZES: libc::c_uint = 3;
/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
pub const USER_NOTIF_FLAG_CONTINUE: u32 = 1;
/// `SECCOMP_ADDFD_FLAG_SETFD`.
pub const ADDFD_FLAG_SETFD: u32 = 1;
/// `SECCOMP_ADDFD_FLAG_SEND`.
pub const ADDFD_FLAG_SEND: u32 = 2;

const fn iowr(nr: u32, size: usize) -> libc::c_ulong {
    // _IOC(_IOC_READ|_IOC_WRITE, '!', nr, size)
    ((3u32 << 30) | ((size as u32) << 16) | ((b'!' as u32) << 8) | nr) as libc::c_ulong
}
const fn iow(nr: u32, size: usize) -> libc::c_ulong {
    // _IOC(_IOC_WRITE, '!', nr, size)
    ((1u32 << 30) | ((size as u32) << 16) | ((b'!' as u32) << 8) | nr) as libc::c_ulong
}

/// `SECCOMP_IOCTL_NOTIF_RECV` (0xc0502100).
pub const IOCTL_NOTIF_RECV: libc::c_ulong = iowr(0, std::mem::size_of::<Notif>());
/// `SECCOMP_IOCTL_NOTIF_SEND` (0xc0182101).
pub const IOCTL_NOTIF_SEND: libc::c_ulong = iowr(1, std::mem::size_of::<NotifResp>());
/// `SECCOMP_IOCTL_NOTIF_ID_VALID` (0x40082102).
pub const IOCTL_NOTIF_ID_VALID: libc::c_ulong = iow(2, 8);
/// `SECCOMP_IOCTL_NOTIF_ADDFD` (0x40182103).
pub const IOCTL_NOTIF_ADDFD: libc::c_ulong = iow(3, std::mem::size_of::<NotifAddfd>());

/// How to answer a paused call.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// Let the call run as the target made it (`FLAG_CONTINUE`). See the
    /// module docs: only when the decision used registers alone.
    Continue,
    /// Fail the call with this errno (positive, e.g. `libc::EACCES`); the
    /// call does not run.
    Errno(i32),
    /// Do not run the call; it returns this value.
    Value(i64),
}

/// How [`Listener::add_fd`] places the fd in the target.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct AddFd {
    /// Place it at exactly this fd number (`ADDFD_FLAG_SETFD`), replacing
    /// what is there; `None`: the lowest free number.
    pub target_fd: Option<u32>,
    /// `O_CLOEXEC` on the new fd in the target.
    pub cloexec: bool,
    /// Also answer the call with the new fd number, atomically
    /// (`ADDFD_FLAG_SEND`, kernel >= 5.14): the right answer for a brokered
    /// `openat`/`socket`.
    pub send: bool,
}

impl AddFd {
    /// Inject and answer the call with the new fd (cloexec as the target asked
    /// is the caller's job: set `cloexec` from the call's flags).
    pub fn send() -> AddFd {
        AddFd {
            send: true,
            ..AddFd::default()
        }
    }
}

/// What [`Listener::wait`] saw.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Readiness {
    /// A notification is waiting: call [`Listener::recv`].
    Ready,
    /// Every task using the filter has exited.
    Hangup,
    /// The timeout passed.
    Timeout,
}

/// The kernel's notification struct sizes (`SECCOMP_GET_NOTIF_SIZES`).
pub fn kernel_sizes() -> io::Result<(u16, u16, u16)> {
    let mut s = NotifSizes::default();
    // SAFETY: the kernel writes a seccomp_notif_sizes into `s`.
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut s as *mut NotifSizes,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((s.notif, s.resp, s.data))
}

/// A seccomp USER_NOTIF listener fd (the supervisor's end of a filter).
#[derive(Debug)]
pub struct Listener {
    fd: OwnedFd,
}

impl Listener {
    /// Wrap a listener fd (from [`crate::launch::Launched::listener`], or
    /// received over a unix socket with [`recv_fd`]).
    pub fn from_fd(fd: OwnedFd) -> Listener {
        Listener { fd }
    }

    /// Check that the kernel's notification structs have the sizes this
    /// crate was written for; call once before the first [`Listener::recv`].
    pub fn check_kernel() -> io::Result<()> {
        let (n, r, d) = kernel_sizes()?;
        let want = (
            std::mem::size_of::<Notif>(),
            std::mem::size_of::<NotifResp>(),
            std::mem::size_of::<SeccompData>(),
        );
        if (usize::from(n), usize::from(r), usize::from(d)) != want {
            return Err(io::Error::other(format!(
                "kernel seccomp notif sizes {n}/{r}/{d} differ from {}/{}/{}",
                want.0, want.1, want.2
            )));
        }
        Ok(())
    }

    /// Wait until a notification is ready, every target exited, or the
    /// timeout passed (`None`: wait forever).
    pub fn wait(&self, timeout: Option<Duration>) -> io::Result<Readiness> {
        let ms = match timeout {
            None => -1,
            Some(t) => i32::try_from(t.as_millis()).unwrap_or(i32::MAX),
        };
        let mut p = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: one valid pollfd.
            let r = unsafe { libc::poll(&mut p, 1, ms) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if r == 0 {
                return Ok(Readiness::Timeout);
            }
            if p.revents & libc::POLLIN != 0 {
                return Ok(Readiness::Ready);
            }
            if p.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return Ok(Readiness::Hangup);
            }
        }
    }

    /// Receive one notification (blocks). `EINTR` is retried; `ENOENT`
    /// means the target died before the receive: receive again.
    pub fn recv(&self) -> io::Result<Notif> {
        loop {
            // The kernel requires a zeroed buffer.
            let mut n = Notif::default();
            // SAFETY: the kernel writes a seccomp_notif into `n`.
            let r = unsafe { libc::ioctl(self.fd.as_raw_fd(), IOCTL_NOTIF_RECV as _, &mut n) };
            if r == 0 {
                return Ok(n);
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }

    /// Whether `id` still names a live, paused call (`NOTIF_ID_VALID`).
    pub fn id_valid(&self, id: u64) -> io::Result<bool> {
        let mut v = id;
        // SAFETY: the kernel reads one u64.
        let r = unsafe { libc::ioctl(self.fd.as_raw_fd(), IOCTL_NOTIF_ID_VALID as _, &mut v) };
        if r == 0 {
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOENT) {
            Ok(false)
        } else {
            Err(e)
        }
    }

    /// Answer a paused call. `ENOENT`: the call is gone (target died or the
    /// call was interrupted by a signal); that is not a supervisor error.
    pub fn respond(&self, id: u64, resp: Response) -> io::Result<()> {
        let mut r = NotifResp {
            id,
            ..NotifResp::default()
        };
        match resp {
            Response::Continue => r.flags = USER_NOTIF_FLAG_CONTINUE,
            Response::Errno(e) => r.error = -e.abs(),
            Response::Value(v) => r.val = v,
        }
        loop {
            // SAFETY: the kernel reads a seccomp_notif_resp.
            let rc = unsafe { libc::ioctl(self.fd.as_raw_fd(), IOCTL_NOTIF_SEND as _, &mut r) };
            if rc == 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }

    /// Install `fd` in the target (`NOTIF_ADDFD`) and return its number
    /// there. With [`AddFd::send`] the call is answered with that number in
    /// the same step and must not be answered again.
    pub fn add_fd(&self, id: u64, fd: BorrowedFd<'_>, how: AddFd) -> io::Result<i32> {
        let mut a = NotifAddfd {
            id,
            flags: 0,
            srcfd: fd.as_raw_fd() as u32,
            newfd: 0,
            newfd_flags: if how.cloexec {
                libc::O_CLOEXEC as u32
            } else {
                0
            },
        };
        if let Some(t) = how.target_fd {
            a.flags |= ADDFD_FLAG_SETFD;
            a.newfd = t;
        }
        if how.send {
            a.flags |= ADDFD_FLAG_SEND;
        }
        loop {
            // SAFETY: the kernel reads a seccomp_notif_addfd.
            let rc = unsafe { libc::ioctl(self.fd.as_raw_fd(), IOCTL_NOTIF_ADDFD as _, &mut a) };
            if rc >= 0 {
                return Ok(rc);
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

impl AsFd for Listener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Listener {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl From<Listener> for OwnedFd {
    fn from(l: Listener) -> OwnedFd {
        l.fd
    }
}

/// Send one fd over a unix socket (`SCM_RIGHTS`, one dummy byte).
pub fn send_fd(sock: BorrowedFd<'_>, fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: raw sendmsg with a correctly sized control buffer.
    let rc = unsafe { raw_send_fd(sock.as_raw_fd(), fd.as_raw_fd()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Async-signal-safe `send_fd` (no allocation), for a forked child before
/// exec. Returns sendmsg's result.
///
/// # Safety
/// `sock` and `fd` must be open fds.
pub(crate) unsafe fn raw_send_fd(sock: RawFd, fd: RawFd) -> isize {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // CMSG_SPACE(sizeof(int)) = 24 on 64-bit; 8-byte aligned buffer.
    let mut cbuf = [0u64; 4];
    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
    let c = libc::CMSG_FIRSTHDR(&msg);
    (*c).cmsg_level = libc::SOL_SOCKET;
    (*c).cmsg_type = libc::SCM_RIGHTS;
    (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
    std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<RawFd>(), fd);
    libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL)
}

/// Receive one fd sent with [`send_fd`]. `UnexpectedEof`: the peer closed
/// without sending one.
pub fn recv_fd(sock: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut cbuf = [0u64; 4];
    // SAFETY: zeroed msghdr filled with valid buffers; the kernel writes the
    // control message; only a SCM_RIGHTS int is read back.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
        let n = loop {
            let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break n;
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let c = libc::CMSG_FIRSTHDR(&msg);
        if n == 0 || c.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the peer sent no fd",
            ));
        }
        if (*c).cmsg_level != libc::SOL_SOCKET || (*c).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::other("not an SCM_RIGHTS message"));
        }
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<RawFd>());
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

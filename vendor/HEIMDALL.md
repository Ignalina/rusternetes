# Heimdall's seccomp backend (vendored)

Feature `heimdall-seccomp` of `rusternetes-kubelet` (default off) compiles a
pod's seccomp profile with Heimdall's classic-BPF builder instead of the
youki backend's default (seccompiler). Heimdall is AGPL-3.0-only; the
vendored crates keep their licence and SPDX headers, and a shim built with
the feature is AGPL-3.0-only as a whole.

## The vendored crates

Both from Heimdall, git.gunnar.rs nordisk/heimdall, main
`9d4114d0d7d59e24f1bf91bb157e625fa3e8399c` (2026-11-07):

| here | there | changed |
|---|---|---|
| `heimdall-youki/src/lib.rs` | `runtime/heimdall-youki/src/lib.rs` | nothing |
| `heimdall-youki/Cargo.toml` | `runtime/heimdall-youki/Cargo.toml` | `libcontainer` is the crates.io name (this workspace patches it to `vendor/libcontainer`) with `v2` + `seccomp-bpf` instead of the git branch with `libseccomp`; `heimdall-seccomp` is the copy beside it; no dev-dependencies |
| `heimdall-seccomp/src/`, `LICENSE` | `crates/heimdall-seccomp/src/`, `LICENSE` | nothing |
| `heimdall-seccomp/Cargo.toml` | `crates/heimdall-seccomp/Cargo.toml` | the workspace keys written out, no tests, no dev-dependencies |

Why vendored and not a git dependency: Heimdall's forge serves git over SSH
only, and cargo fetches every git dependency in the lock file, an optional one
too, for every build. A git dependency would make every default build (and
upstream CI) need SSH access to git.gunnar.rs.

To move to a newer Heimdall: copy the same files from that commit, keep the
two manifest changes, and change the commit above.

## vendor/libcontainer

- `src/seccomp/mod.rs` (the libseccomp module) is youki's file at
  Ignalina/youki `feat/seccomp-backend-trait` 5aeca235 (youki PR 3873, the
  pluggable seccomp backend), plus `CompiledSeccomp::program` and the
  container backend registration below. The module was identical to youki's
  base of that branch before.
- `src/seccomp_bpf.rs` (the pure-Rust module the shim builds with) has the
  same trait, types and loader (`SockFilter`, `CompiledSeccomp`,
  `SeccompBackend`, `initialize_seccomp_with`, `LoadProgram`,
  `ProgramTooLong`), with seccompiler's stack as its own backend
  (`SeccompBpfBackend`), so a backend written against youki's trait builds
  against either module.
- The PR's init paths still call `initialize_seccomp`. Both modules add
  `set_container_backend` / `container_backend` /
  `initialize_container_seccomp`, and `process/init/process.rs` installs a
  container's `linux.seccomp` with the registered backend (else the
  module's own). The shim registers Heimdall's before it builds a container;
  its own wait-phase filter keeps the default.

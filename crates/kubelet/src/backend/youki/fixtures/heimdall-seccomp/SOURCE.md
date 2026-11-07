# Bench pod profiles (test inputs, never edited)

Copied from tunnr (git.gunnar.rs mikronova/tunnr) at main
817c3a3dc71a5b45800cedfcf3e3c48364f46d0d7dcfc3ae378035a9e968b9b3; the files
last changed in f3984af4 (2026-11-07, "the bench pod profiles learned again
with the clone3 fix", tool pin heimdall main 9d4114d):

| here | tunnr | sha256 |
|---|---|---|
| `pod-busybox.x86_64-glibc.oci.json` | `.nornir/profiles/rusternetes-node/pod-busybox/x86_64-glibc.oci.json` | `63d15748e22e16449a5961cae296c513995e4c7d933b2f299e6a1dabb3bc2756` |
| `pod-iperf3.x86_64-glibc.oci.json` | `.nornir/profiles/rusternetes-node/pod-iperf3/x86_64-glibc.oci.json` | `02ef749f997d512fe1a163b018051a223480f5fd1f0147bb11a685263344307a` |
| `pod-nginx-alpine.x86_64-musl.oci.json` | `.nornir/profiles/rusternetes-node/pod-nginx-alpine/x86_64-musl.oci.json` | `c02ab950328a8c77856fc8bd34bfcd8d88dc8d498bad9e6e414f61122c79e745` |

They are the OCI `linux.seccomp` sections Heimdall's profiler wrote for the
bench pods; `../../heimdall.rs` (feature `heimdall-seccomp`) runs each one
through the shim's container backend and through libseccomp and compares the
answers in a BPF interpreter.

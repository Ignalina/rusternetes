// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Ignalina ApS and Vetra Automation AB

//! The arch and libc a profile is for. Heimdall is a defensive sandbox: a
//! profile is only ever enforced on the arch it was generated for, and musl
//! and glibc get separate profiles because the libc changes the calls.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::tables;

/// `AUDIT_ARCH_X86_64` (`EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`).
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
/// `AUDIT_ARCH_AARCH64` (`EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`).
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
/// x86_64: the x32 ABI marks its calls with this bit; Heimdall kills them all.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// A CPU architecture Heimdall builds filters for (little-endian, 64-bit).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// The arch this process runs on, when Heimdall supports it.
    pub fn native() -> Option<Arch> {
        if cfg!(target_arch = "x86_64") {
            Some(Arch::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Arch::Aarch64)
        } else {
            None
        }
    }

    /// The `AUDIT_ARCH_*` value the kernel puts in `seccomp_data.arch`.
    pub const fn audit_arch(self) -> u32 {
        match self {
            Arch::X86_64 => AUDIT_ARCH_X86_64,
            Arch::Aarch64 => AUDIT_ARCH_AARCH64,
        }
    }

    /// The arch whose `AUDIT_ARCH_*` value this is.
    pub fn from_audit_arch(v: u32) -> Option<Arch> {
        match v {
            AUDIT_ARCH_X86_64 => Some(Arch::X86_64),
            AUDIT_ARCH_AARCH64 => Some(Arch::Aarch64),
            _ => None,
        }
    }

    /// Every (name, number) of this arch, sorted by number.
    pub fn syscalls(self) -> &'static [(&'static str, u32)] {
        match self {
            Arch::X86_64 => tables::x86_64::SYSCALLS,
            Arch::Aarch64 => tables::aarch64::SYSCALLS,
        }
    }

    /// The number of a syscall by name (`None`: this arch has no such call).
    pub fn syscall_nr(self, name: &str) -> Option<u32> {
        self.syscalls()
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, nr)| *nr)
    }

    /// The name of a syscall number.
    pub fn syscall_name(self, nr: u32) -> Option<&'static str> {
        let t = self.syscalls();
        t.binary_search_by_key(&nr, |(_, n)| *n)
            .ok()
            .map(|i| t[i].0)
    }

    /// The name used in file names and JSON: `x86_64`, `aarch64`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Arch {
    type Err = String;
    fn from_str(s: &str) -> Result<Arch, String> {
        match s {
            "x86_64" => Ok(Arch::X86_64),
            "aarch64" => Ok(Arch::Aarch64),
            _ => Err(format!("unknown arch {s:?} (x86_64, aarch64)")),
        }
    }
}

/// The C library a worker is linked with.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Libc {
    Glibc,
    Musl,
}

impl Libc {
    /// The name used in file names and JSON: `glibc`, `musl`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Libc::Glibc => "glibc",
            Libc::Musl => "musl",
        }
    }

    /// Detect the libc of an ELF file: its `PT_INTERP` names `ld-musl` or
    /// `ld-linux`; a static file is glibc when it has glibc's
    /// `.note.ABI-tag` section, musl when it has none and names musl.
    /// `None` when neither shows.
    pub fn detect(elf: &[u8]) -> Option<Libc> {
        if let Some(interp) = elf_interp(elf) {
            if interp.contains("ld-musl") {
                return Some(Libc::Musl);
            }
            if interp.contains("ld-linux") {
                return Some(Libc::Glibc);
            }
        }
        // Static: glibc always links its `.note.ABI-tag` note; musl has none.
        let has = |needle: &[u8]| elf.windows(needle.len()).any(|w| w == needle);
        if elf.get(0..4)? != b"\x7fELF" {
            None
        } else if has(b".note.ABI-tag") {
            Some(Libc::Glibc)
        } else if has(b"musl") {
            Some(Libc::Musl)
        } else {
            None
        }
    }
}

impl fmt::Display for Libc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Libc {
    type Err = String;
    fn from_str(s: &str) -> Result<Libc, String> {
        match s {
            "glibc" | "gnu" => Ok(Libc::Glibc),
            "musl" => Ok(Libc::Musl),
            _ => Err(format!("unknown libc {s:?} (glibc, musl)")),
        }
    }
}

/// The `PT_INTERP` string of a little-endian ELF64 file.
fn elf_interp(elf: &[u8]) -> Option<String> {
    let u16_at = |o: usize| elf.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| {
        elf.get(o..o + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    let u64_at = |o: usize| {
        elf.get(o..o + 8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    };
    if elf.get(0..4)? != b"\x7fELF" || *elf.get(4)? != 2 || *elf.get(5)? != 1 {
        return None;
    }
    let phoff = usize::try_from(u64_at(0x20)?).ok()?;
    let phentsize = usize::from(u16_at(0x36)?);
    let phnum = usize::from(u16_at(0x38)?);
    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize)?)?;
        if u32_at(ph)? == 3 {
            let off = usize::try_from(u64_at(ph + 8)?).ok()?;
            let len = usize::try_from(u64_at(ph + 32)?).ok()?;
            let raw = elf.get(off..off.checked_add(len)?)?;
            let raw = raw.split(|b| *b == 0).next()?;
            return Some(String::from_utf8_lossy(raw).into_owned());
        }
    }
    None
}

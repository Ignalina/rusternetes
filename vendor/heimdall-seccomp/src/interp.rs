// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Ignalina ApS and Vetra Automation AB

//! A classic-BPF interpreter for seccomp programs: the subset the builder
//! emits (and the kernel's seccomp checker accepts). Heimdall is a defensive
//! sandbox; this lets tests and offline checks run a filter on any
//! `seccomp_data` without installing it.

use crate::bpf::{
    SockFilter, ALU_AND_K, JMP_JA, JMP_JEQ_K, JMP_JGE_K, JMP_JGT_K, JMP_JSET_K, LD_W_ABS, RET_K,
};
use crate::notif::SeccompData;

/// Why a program could not be run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InterpError {
    #[error("instruction {pc}: opcode {code:#x} is not supported")]
    Opcode { pc: usize, code: u16 },
    #[error("instruction {pc}: load at offset {off} is outside seccomp_data or unaligned")]
    Load { pc: usize, off: u32 },
    #[error("instruction {pc}: jump lands outside the program")]
    Jump { pc: usize },
    #[error("the program falls off its end without a ret")]
    NoRet,
}

/// Run `prog` on `data` and return the filter's 32-bit return value.
pub fn run(prog: &[SockFilter], data: &SeccompData) -> Result<u32, InterpError> {
    let bytes = data.to_bytes();
    let mut a: u32 = 0;
    let mut pc = 0usize;
    while let Some(i) = prog.get(pc) {
        let next = pc + 1;
        let target = |off: usize| -> Result<usize, InterpError> {
            let t = next.checked_add(off).ok_or(InterpError::Jump { pc })?;
            if t >= prog.len() {
                Err(InterpError::Jump { pc })
            } else {
                Ok(t)
            }
        };
        match i.code {
            LD_W_ABS => {
                let off = i.k as usize;
                if off % 4 != 0 || off + 4 > bytes.len() {
                    return Err(InterpError::Load { pc, off: i.k });
                }
                a = u32::from_ne_bytes(bytes[off..off + 4].try_into().unwrap());
                pc = next;
            }
            ALU_AND_K => {
                a &= i.k;
                pc = next;
            }
            JMP_JA => pc = target(i.k as usize)?,
            JMP_JEQ_K | JMP_JGT_K | JMP_JGE_K | JMP_JSET_K => {
                let hit = match i.code {
                    JMP_JEQ_K => a == i.k,
                    JMP_JGT_K => a > i.k,
                    JMP_JGE_K => a >= i.k,
                    _ => a & i.k != 0,
                };
                pc = target(usize::from(if hit { i.jt } else { i.jf }))?;
            }
            RET_K => return Ok(i.k),
            code => return Err(InterpError::Opcode { pc, code }),
        }
    }
    Err(InterpError::NoRet)
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Ignalina ApS and Vetra Automation AB

//! The call filter model (docs/v2/graph-filter.md §5). **Heimdall is a
//! defensive sandbox**: every system call of a filtered program is checked at
//! the kernel's system-call entry, and this module is the one model of that
//! check:
//!
//! ```text
//! decide(position, call) → (valid, next position) | invalid
//! ```
//!
//! - [`StaticFilter`] is the model with ONE position that never moves: the
//!   generated profile of 0.4.2, compiled fully into one classic-BPF program.
//! - A graph filter (crate `nordisk-heimdall-graph`) keeps a STACK of
//!   positions per thread, followed in the kernel by the eBPF follower, with
//!   the same static program as its floor.
//!
//! [`compile`] is the pipeline, OUTSIDE every [`CallFilter`]: it builds the
//! floor as one program through [`crate::bpf::build_rules`], so the arch
//! check, the x32 kill and the kernel-implied base set ([`crate::base`]) are
//! in every program whatever the implementation says, and it takes the
//! follower's tables from a filter that has them. [`compile_floor`] is the
//! same assembly for a launch that has rules but no filter object (the
//! learning filters of the probe).

use std::fmt;

use crate::arch::Arch;
use crate::bpf::{build_rules, BuildError, Program};
use crate::profile::{Action, Profile, Rule};

/// An entry of a program's graph: the process start, a thread body, a signal
/// handler (the row of kind `entry` in `exec.marks`). Static mode has one.
pub type EntryId = u32;

/// The position "before the first call of the entry" (`ε`).
pub const EPS: u32 = u32::MAX;

/// At most this many frames per thread: its own entry and 7 handlers.
pub const MAX_FRAMES: usize = 8;

/// One frame of a thread's stack: an entry, the position on it (the set of
/// sites the frame's last call can have come from, sorted; [`EPS`] = before
/// its first call), and the system-call number of the frame's last call.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Frame {
    pub entry: EntryId,
    pub sites: Vec<u32>,
    pub last: Option<u32>,
}

impl Frame {
    /// The start frame of `entry`: `(entry, {ε}, none)`.
    pub fn start(entry: EntryId) -> Frame {
        Frame {
            entry,
            sites: vec![EPS],
            last: None,
        }
    }
}

/// Where a thread is.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Position {
    /// Static mode: the one position `q₀`.
    One,
    /// Graph mode: the thread's stack, bottom first, at most [`MAX_FRAMES`].
    Stack(Vec<Frame>),
}

/// What the filter is asked about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A system call with its register arguments.
    Call { nr: u32, args: [u64; 6] },
    /// A signal handler starts on the thread: the handler's entry, `None`
    /// when the graph has no entry for that handler's address.
    Signal { handler: Option<EntryId> },
    /// The thread creates a thread (`clone` with `CLONE_THREAD`): the answer
    /// is the CHILD's start position.
    Spawn,
    /// The thread forks a process: the child goes on where the parent is.
    Fork,
}

/// Why a step is invalid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// The call is outside the floor (static mode: outside `I ∪ F`).
    Floor { nr: u32 },
    /// No site of the graph can make this call next.
    NotNext { nr: u32 },
    /// A handler the graph does not have.
    UnknownHandler,
    /// A ninth frame.
    TooDeep,
    /// A thread start the graph does not have.
    UnknownSpawn,
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Invalid::Floor { nr } => write!(f, "call {nr} is outside the floor"),
            Invalid::NotNext { nr } => write!(f, "call {nr} is not a next step of the graph"),
            Invalid::UnknownHandler => f.write_str("a signal handler the graph does not have"),
            Invalid::TooDeep => write!(f, "more than {MAX_FRAMES} frames"),
            Invalid::UnknownSpawn => f.write_str("a thread start the graph does not have"),
        }
    }
}

/// The answer of [`CallFilter::decide`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// A valid step, and the position after it (for [`Event::Spawn`]: the
    /// child's start position; the parent does not move).
    Valid(Position),
    /// An invalid step: Enforce kills, Audit logs and counts.
    Invalid(Invalid),
}

/// What a signed record names about the filter.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FilterDigests {
    /// The pin of the generated profile (`sha256:<hex>` of its OCI JSON), as
    /// static mode's record names it.
    pub profile: Option<String>,
    /// SHA-256 over the graph's `exec.nodes` bytes, then its `exec.edges`.
    pub graph: Option<[u8; 32]>,
}

/// The follower's tables: the graph made deterministic by the loader side
/// (`nordisk-heimdall-graph`). One state id per reachable position of an
/// entry; state 0 is never used, so a zero in a map means "none".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FollowerTables {
    /// The number of states (ids `1..=states`).
    pub states: u32,
    /// `(state, system-call number) → state` when the call is NOT the
    /// frame's last call: `step_e(P, c)`; absent = an invalid step. Sorted.
    pub next: Vec<((u32, u32), u32)>,
    /// `(state, system-call number) → state` when the call IS the frame's
    /// last call ("again"): `P ∪ step_e(P, c)`; absent = the same state.
    pub again: Vec<((u32, u32), u32)>,
    /// Each entry's start state (`(entry, {ε})`), sorted by entry.
    pub start: Vec<(EntryId, u32)>,
    /// The process entry (where the follower starts a program).
    pub process: EntryId,
    /// The entry a new thread starts on, when the graph has one.
    pub thread: Option<EntryId>,
    /// The signal-handler entries.
    pub handlers: Vec<EntryId>,
}

/// One filter model. `decide` in Rust is the reference: the in-kernel
/// follower must agree with it on every run of the tests.
pub trait CallFilter: Send + Sync {
    /// `"static"` or `"graph"`.
    fn name(&self) -> &'static str;
    /// The arch the floor is for.
    fn arch(&self) -> Arch;
    /// The position a thread of `entry` starts at.
    fn start(&self, entry: EntryId) -> Position;
    /// One step. The base set is valid at every position (and moves no
    /// position; `rt_sigreturn` pops a handler's frame).
    fn decide(&self, at: &Position, event: &Event) -> Decision;
    /// The floor's rules: static mode's profile.
    fn floor(&self) -> &[Rule];
    /// The floor's default action (kill in production).
    fn floor_default(&self) -> Action {
        Action::KillProcess
    }
    /// What the signed record names.
    fn digests(&self) -> FilterDigests;
    /// The follower's tables; `None` for a filter without a follower.
    fn follower(&self) -> Option<&FollowerTables> {
        None
    }
}

/// Why a filter could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    #[error(transparent)]
    Build(#[from] BuildError),
    #[error("the filter is for {filter}, the program is built for {arch}")]
    Arch { filter: Arch, arch: Arch },
}

/// A compiled filter: the floor program, whether it needs a USER_NOTIF
/// listener, the follower's tables, and what the record names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compiled {
    pub floor: Program,
    pub wants_listener: bool,
    pub follower: Option<FollowerTables>,
    pub digests: FilterDigests,
    /// SHA-256 of the floor program's bytes ([`Program::to_bytes`]).
    pub floor_digest: [u8; 32],
}

/// The floor of one launch: `prelude` (the launcher's own rules: the
/// `execveat` of the program, a report write) and then `rules`, with
/// `default`, as ONE program. The arch check, the x32 kill and the base set
/// come from [`build_rules`], before every rule.
pub fn compile_floor(
    arch: Arch,
    prelude: &[Rule],
    rules: &[Rule],
    default: Action,
) -> Result<Program, BuildError> {
    let mut all = Vec::with_capacity(prelude.len() + rules.len());
    all.extend_from_slice(prelude);
    all.extend_from_slice(rules);
    build_rules(arch, &all, default)
}

/// The pipeline: the floor of `f` behind `prelude`, for `arch`, and the
/// follower's tables when `f` has them.
pub fn compile(f: &dyn CallFilter, arch: Arch, prelude: &[Rule]) -> Result<Compiled, FilterError> {
    if f.arch() != arch {
        return Err(FilterError::Arch {
            filter: f.arch(),
            arch,
        });
    }
    let floor = compile_floor(arch, prelude, f.floor(), f.floor_default())?;
    let wants_listener = prelude
        .iter()
        .chain(f.floor())
        .any(|r| r.action == Action::UserNotif)
        || f.floor_default() == Action::UserNotif;
    let floor_digest = floor.digest();
    Ok(Compiled {
        floor,
        wants_listener,
        follower: f.follower().cloned(),
        digests: f.digests(),
        floor_digest,
    })
}

/// Whether a floor answer lets the call run (`always` or `brokered`).
pub fn runs(action: Action) -> bool {
    matches!(action, Action::Allow | Action::Log | Action::UserNotif)
}

/// The floor's answer for one call: the base set first, then the rules, then
/// `None` for "no rule matched" (the default).
pub fn floor_answer(arch: Arch, rules: &[Rule], nr: u32, args: &[u64; 6]) -> Option<Action> {
    if crate::base::is_base_nr(arch, nr) {
        return Some(Action::Allow);
    }
    let name = arch.syscall_name(nr)?;
    rules
        .iter()
        .filter(|r| r.syscall == name)
        .find(|r| r.matches(args))
        .map(|r| r.action)
}

/// Static mode: one position, `decide(q₀, c) = valid iff c ∈ I ∪ F`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticFilter {
    profile: Profile,
    digest: Option<String>,
    default: Action,
}

impl StaticFilter {
    /// Enforce `profile` (default `KILL_PROCESS`); `digest` is its pin
    /// (`sha256:<hex>` of its OCI JSON), when it has one.
    pub fn new(profile: Profile, digest: Option<String>) -> StaticFilter {
        StaticFilter {
            profile,
            digest,
            default: Action::KillProcess,
        }
    }

    /// The same profile in a mode ([`crate::Mode`]: audit needs a test box).
    pub fn with_mode(profile: Profile, digest: Option<String>, mode: &crate::Mode) -> StaticFilter {
        StaticFilter {
            profile,
            digest,
            default: mode.default_action(),
        }
    }

    /// The profile.
    pub fn profile(&self) -> &Profile {
        &self.profile
    }
}

impl CallFilter for StaticFilter {
    fn name(&self) -> &'static str {
        "static"
    }
    fn arch(&self) -> Arch {
        self.profile.arch
    }
    fn start(&self, _entry: EntryId) -> Position {
        Position::One
    }
    fn decide(&self, _at: &Position, event: &Event) -> Decision {
        match event {
            Event::Call { nr, args } => {
                match floor_answer(self.profile.arch, &self.profile.rules, *nr, args) {
                    Some(a) if runs(a) => Decision::Valid(Position::One),
                    _ => Decision::Invalid(Invalid::Floor { nr: *nr }),
                }
            }
            // One position: a handler, a thread, a fork are all at q₀.
            Event::Signal { .. } | Event::Spawn | Event::Fork => Decision::Valid(Position::One),
        }
    }
    fn floor(&self) -> &[Rule] {
        &self.profile.rules
    }
    fn floor_default(&self) -> Action {
        self.default
    }
    fn digests(&self) -> FilterDigests {
        FilterDigests {
            profile: self.digest.clone(),
            graph: None,
        }
    }
}

/// The floor's answer for one call in graph mode (graph-filter.md §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The profile does not let it run: its action (kill, or the profile's
    /// own errno rule).
    Never(Action),
    /// ALLOW: the call runs, and the follower follows it.
    Always,
    /// USER_NOTIF: the supervisor brokers it.
    Brokered,
}

/// The reference answer: the profile first (`rules`, default kill), then
/// the brokered set (`brokered`: its `syscall` and `when`; the action is
/// not read) for a call the profile allows. The base set is always ALLOW.
pub fn answer(arch: Arch, rules: &[Rule], brokered: &[Rule], nr: u32, args: &[u64; 6]) -> Answer {
    match floor_answer(arch, rules, nr, args) {
        None => Answer::Never(Action::KillProcess),
        Some(Action::Allow) => {
            if crate::base::is_base_nr(arch, nr) {
                return Answer::Always;
            }
            let name = arch.syscall_name(nr).unwrap_or("");
            if brokered
                .iter()
                .any(|b| b.syscall == name && b.matches(args))
            {
                Answer::Brokered
            } else {
                Answer::Always
            }
        }
        Some(Action::UserNotif) => Answer::Brokered,
        Some(a) => Answer::Never(a),
    }
}

/// The floor's rules with three answers, for ONE program with default
/// `KILL_PROCESS`: every allow rule of the profile that a brokered rule can
/// also match is preceded by the conjunction of the two with action
/// `USER_NOTIF`. The program answers each call as the kernel answers the
/// profile and the broker filter stacked (the strictest of the two), so a
/// brokered call the profile does not allow is still killed. Without
/// brokered rules it returns the profile unchanged (static mode).
pub fn floor_three(arch: Arch, rules: &[Rule], brokered: &[Rule]) -> Vec<Rule> {
    let mut out = Vec::with_capacity(rules.len());
    for r in rules {
        if r.action == Action::Allow
            && !crate::base::is_base(&r.syscall)
            && arch.syscall_nr(&r.syscall).is_some()
        {
            for b in brokered.iter().filter(|b| b.syscall == r.syscall) {
                out.push(Rule {
                    syscall: r.syscall.clone(),
                    action: Action::UserNotif,
                    when: conjunction(&r.when, &b.when),
                });
            }
        }
        out.push(r.clone());
    }
    out
}

/// `a ∧ b` over alternatives (an empty list matches everything).
fn conjunction(
    a: &[Vec<crate::profile::ArgCmp>],
    b: &[Vec<crate::profile::ArgCmp>],
) -> Vec<Vec<crate::profile::ArgCmp>> {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => Vec::new(),
        (true, false) => b.to_vec(),
        (false, true) => a.to_vec(),
        (false, false) => a
            .iter()
            .flat_map(|x| b.iter().map(move |y| [x.clone(), y.clone()].concat()))
            .collect(),
    }
}

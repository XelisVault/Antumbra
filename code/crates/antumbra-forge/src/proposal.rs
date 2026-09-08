//! The Proposal state machine: Draft to Active, and the honest
//! exits.

use crate::error::ForgeError;
use crate::rail::Rail;

/// The ramp stages a surviving change climbs, in percent of
/// the nodes: one, ten, one hundred.
pub const RAMP_STAGES: [u32; 3] = [1, 10, 100];

/// The states a proposal walks.
///
/// Corona v2, finally a protocol: every arrow is an event with
/// a tick, every dwell has a meaning, every exit is honest.
/// Nothing here is a feeling; the machine is the spec.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// Any Cipher C1+ published an argument and a rail intent.
    Draft,
    /// ATU locked, Kleos_agent above theta(rail).
    Bonded,
    /// The fixed red-team window: auditors outside the
    /// proposer's family.
    RedTeam,
    /// The spec and the vectors regenerated, when a rule moved.
    SpecDiff,
    /// Fuzz, differential, replay, bench, two Nix builds.
    Arena,
    /// Silence for the fluid rails, a positive vote else.
    HumanGate,
    /// The binary side, never mainnet's place.
    Antechamber,
    /// A share of volunteer nodes runs the change.
    Canary,
    /// The ramp: one, ten, one hundred percent.
    Ramp {
        /// The current stage, in percent of the nodes.
        pct: u32,
    },
    /// The code commitment is active at its height.
    Active,
    /// A critical finding closed the road: the bond may be
    /// partially seized.
    Rejected,
    /// The proposer walked away after Bonded: the bond is
    /// seized.
    Expired,
    /// Thymus froze the ramp: the ramp resumes on resolve.
    Frozen {
        /// The stage the freeze caught.
        pct: u32,
    },
    /// An invariant broke inside the responsibility window: the
    /// previous code commitment returns, the proposer and the
    /// integrator are slashed.
    RolledBack,
}

impl State {
    /// The canonical label of the state.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Bonded => "bonded",
            Self::RedTeam => "redteam",
            Self::SpecDiff => "specdiff",
            Self::Arena => "arena",
            Self::HumanGate => "humangate",
            Self::Antechamber => "antechamber",
            Self::Canary => "canary",
            Self::Ramp { .. } => "ramp",
            Self::Active => "active",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Frozen { .. } => "frozen",
            Self::RolledBack => "rolledback",
        }
    }
}

/// The events the machine takes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    /// The bond locks.
    BondLocked,
    /// The red-team window closed.
    RedTeamDone {
        /// Critical findings still open: any of them rejects.
        critical_findings: u32,
    },
    /// The vectors regenerated (or nothing moved).
    SpecDiffDone,
    /// The Arena went green.
    ArenaGreen,
    /// The human gate passed: silence or vote.
    HumanGatePassed,
    /// The antechamber went green.
    AntechamberGreen,
    /// The canary window survived.
    CanaryHeld,
    /// The next ramp stage opened.
    RampStage,
    /// Thymus froze the upgrade.
    ThymusFreeze,
    /// Thymus resolved the freeze.
    ThymusResolve,
    /// An invariant broke inside the window.
    InvariantBroke,
    /// The proposer abandoned the proposal.
    Abandoned,
}

impl Event {
    /// The canonical label of the event.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BondLocked => "bond_locked",
            Self::RedTeamDone { .. } => "redteam_done",
            Self::SpecDiffDone => "specdiff_done",
            Self::ArenaGreen => "arena_green",
            Self::HumanGatePassed => "human_gate_passed",
            Self::AntechamberGreen => "antechamber_green",
            Self::CanaryHeld => "canary_held",
            Self::RampStage => "ramp_stage",
            Self::ThymusFreeze => "thymus_freeze",
            Self::ThymusResolve => "thymus_resolve",
            Self::InvariantBroke => "invariant_broke",
            Self::Abandoned => "abandoned",
        }
    }
}

/// One proposal walking the machine.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Proposal {
    /// The state.
    pub state: State,
    /// The rail of the change.
    pub rail: Rail,
    /// The ramp stage index the proposal is at.
    ramp_index: u32,
}

impl Proposal {
    /// A new draft on `rail`.
    #[must_use]
    pub const fn new(rail: Rail) -> Self {
        Self {
            state: State::Draft,
            rail,
            ramp_index: 0,
        }
    }
}

/// Applies one event to the proposal.
///
/// # Errors
///
/// Returns [`ForgeError::IllegalTransition`] when the event
/// cannot arrive in the state: an illegal transition is a bug
/// in the caller, never a silent no-op.
pub fn transition(proposal: &mut Proposal, event: Event) -> Result<State, ForgeError> {
    let next = match (proposal.state, event) {
        (State::Draft, Event::BondLocked) => State::Bonded,
        (State::Bonded, Event::RedTeamDone { critical_findings }) => {
            if critical_findings > 0 {
                State::Rejected
            } else {
                State::SpecDiff
            }
        }
        (State::SpecDiff, Event::SpecDiffDone) => State::Arena,
        (State::Arena, Event::ArenaGreen) => State::HumanGate,
        (State::HumanGate, Event::HumanGatePassed) => State::Antechamber,
        (State::Antechamber, Event::AntechamberGreen) => State::Canary,
        (State::Canary, Event::CanaryHeld) => State::Ramp {
            pct: RAMP_STAGES[0],
        },
        (State::Ramp { pct }, Event::RampStage) => {
            let index = RAMP_STAGES.iter().position(|&s| s == pct);
            match index {
                Some(i) if i + 1 < RAMP_STAGES.len() => State::Ramp {
                    pct: RAMP_STAGES[i + 1],
                },
                Some(_) => State::Active,
                None => {
                    return Err(ForgeError::IllegalTransition {
                        state: proposal.state.label(),
                        event: event.label(),
                    })
                }
            }
        }
        (State::Ramp { pct }, Event::ThymusFreeze) => State::Frozen { pct },
        (State::Canary, Event::ThymusFreeze) => State::Frozen { pct: 0 },
        (State::Frozen { pct }, Event::ThymusResolve) => State::Ramp { pct },
        (State::Ramp { .. }, Event::InvariantBroke)
        | (State::Canary, Event::InvariantBroke)
        | (State::Active, Event::InvariantBroke) => State::RolledBack,
        (State::Bonded, Event::Abandoned)
        | (State::RedTeam, Event::Abandoned)
        | (State::SpecDiff, Event::Abandoned)
        | (State::Arena, Event::Abandoned) => State::Expired,
        (other_state, other_event) => {
            return Err(ForgeError::IllegalTransition {
                state: other_state.label(),
                event: other_event.label(),
            })
        }
    };
    if let State::Ramp { pct } = next {
        proposal.ramp_index = pct;
    }
    proposal.state = next;
    Ok(next)
}

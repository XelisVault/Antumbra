//! ANTUMBRA evolution layer: the Forge, the Arena, the Senate
//! (ADR-024, ADR-025).
//!
//! Agents propose, the Arena proves, the predicate merges, the
//! chain activates. This crate is the constitution of that
//! pipeline as code:
//!
//! - [`merge`]: the merge predicate, a boolean function, never
//!   a feeling. Unanimity is Sybil; the predicate wants fuzzed
//!   code, two reproducible builders, acks from distinct
//!   families, zero open critical findings, a locked bond, the
//!   human gate, and a Thymus that did not freeze.
//! - [`registry`]: the bounded parameter table of rail A: a
//!   senator cannot push a value outside `[min, max]` without a
//!   constitutional vote, and a change waits out its cooldown.
//! - [`proposal`]: the state machine a change walks: Draft,
//!   Bonded, RedTeam, SpecDiff, Arena, HumanGate, Antechamber,
//!   Canary, Ramp, Active, with Rejected, Expired, Frozen and
//!   RolledBack as the honest exits.
//! - [`debate`]: the structured argument: a claim without
//!   evidence in a day is caduc, a nack without a finding is
//!   noise, a synthesis is never a source of truth.
//! - [`vote`]: the Senate tally: weights dampened by family,
//!   quorum diverse by definition. A bloc is loud, never
//!   sovereign.
//!
//! Integers only, per-mille fixed point, floor division,
//! deterministic order. Every output-producing routine is
//! cross-validated by an independent implementation
//! (`code/scripts/gen_forge_vectors.py`) over an archived
//! vector set (`tests/vectors.json`).

pub mod debate;
pub mod error;
pub mod merge;
pub mod proposal;
pub mod rail;
pub mod registry;
pub mod vote;

pub use debate::{
    claim_live, counter_equipped, objection_counts, NodeKind, ARG_EVIDENCE_WINDOW_TICKS,
};
pub use error::ForgeError;
pub use merge::{merge_ok, MergeDecision, MergeFacts};
pub use proposal::{transition, Event, Proposal, State, RAMP_STAGES};
pub use rail::Rail;
pub use registry::{change, Parameter, Registry, PARAM_COOLDOWN_HEIGHTS};
pub use vote::{dampen_pm, quorum_ok, tally, Tally, Vote};

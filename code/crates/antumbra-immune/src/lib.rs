//! ANTUMBRA immunity layer: Thymus (ADR-020).
//!
//! Thymus is what makes the chain "relatively very resistant"
//! instead of "perfect": an always-on watchdog that pays powerful
//! attackers to break the protocol HERE rather than elsewhere.
//! More capable models do not make ANTUMBRA flawless; they make
//! the life of a flaw shorter, its discovery paid, and the
//! surface a deployable change may touch bounded. The honest
//! metrics of that resistance (MTTD, MTTC, MTTR) are state this
//! machine computes, not adjectives a paper claims.
//!
//! The layer holds:
//!
//! - the nine invariants every node and every Sentinel replays
//!   ( [`invariant`] ),
//! - the canaries, synthetic transactions with known results
//!   ( [`canary`] ),
//! - the alert state machine: who freezes what, when, and how it
//!   unfreezes ( [`thymus`] ),
//! - the automatic bounty, paid from the forty percent treasury
//!   pole on a replayable proof, uniqueness first ( [`mod@bounty`] ),
//! - the code commitments the rollback returns to
//!   ( [`commitment`] ).
//!
//! Two rules of the constitution are load-bearing here:
//!
//! 1. **Thymus freezes an upgrade, never a valid payment.** The
//!    type of an alert target has no payment variant: the freeze
//!    surface cannot express "stop the money". A Veil payment
//!    that is valid stays valid while an upgrade is frozen.
//! 2. **Freeze is fail-closed on sources, fail-open on money.**
//!    A critical alert on an upgrade freezes only with a
//!    replayable proof OR a quorum of distinct Sentinels: one
//!    lying Sentinel (or one lying attacker with a proof) is a
//!    nuisance, not a halt. And either way, the halt stops
//!    ramp-ups, not settlements.
//!
//! As everywhere in the consensus code: integers only, floor
//! division, saturating bounds, no silent defaults, and every
//! output-producing routine is cross-validated by an independent
//! implementation (`code/scripts/gen_immune_vectors.py`) over an
//! archived vector set (`tests/vectors.json`); both must agree
//! bit for bit.

pub mod alert;
pub mod bounty;
pub mod canary;
pub mod commitment;
pub mod error;
pub mod invariant;
pub mod thymus;

pub use alert::{Alert, AlertTarget, Severity};
pub use bounty::{bounty, BOUNTY_BASE_ATOMIC, BOUNTY_POLE_PPM};
pub use canary::{Canary, CanarySuite};
pub use commitment::{previous_hot, CodeCommitment};
pub use error::ImmuneError;
pub use invariant::{Invariant, INVARIANT_COUNT};
pub use thymus::{Metrics, Outcome, Thymus, SENTINEL_QUORUM, SENTINEL_WINDOW};

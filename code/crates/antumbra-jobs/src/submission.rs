//! The submissions and the contest window.

use antumbra_primitives::Hash;

/// How long a submission stays contestable: forty-eight hours
/// of ten-minute ticks. After the window, an objection is
/// noise, however equipped.
pub const CONTEST_WINDOW_TICKS: u32 = 288;

/// The fraction of the bond a proven-false submission loses,
/// per mille: the whole bond. Half measures teach nothing to a
/// liar.
pub const SLASH_FRACTION_PM: u32 = 1_000;

/// One submission: the artifact, the declared cost, the model.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Submission {
    /// The job the submission answers.
    pub job_id: u32,
    /// The hash of the artifact (patch, proof, report).
    pub artifact_hash: Hash,
    /// The cost the worker declares, atomic units: the
    /// efficiency factor divides this by the reference cost.
    /// Lying about it is a slash, because the reference median
    /// catches outliers.
    pub cost_declared_atomic: u64,
    /// The hash of the model identity: published, because a
    /// market that cannot see families cannot pay diversity.
    pub model_id_hash: Hash,
    /// Whether the acceptance tests passed.
    pub tests_ok: bool,
    /// The tick the submission landed.
    pub submitted_tick: u32,
}

/// What a contest resolves to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ContestOutcome {
    /// The window is still open: the objection is live, the
    /// payout waits.
    Live,
    /// The window closed with no proof: the worker keeps the
    /// bounty, the bond unlocks.
    Settled,
    /// The proof landed inside the window and the submission
    /// is false: the worker's bond is slashed (the whole
    /// fraction), and the bounty moves to the auditor.
    Slashed {
        /// The slashed amount, atomic units.
        slash_atomic: u64,
        /// Whether the bounty moved to the auditor.
        bounty_transferred: bool,
    },
}

/// Resolves a contest attempt against a submission.
///
/// # Errors
///
/// No errors: a late contest is [`ContestOutcome::Settled`]
/// with the payout standing, an early one is
/// [`ContestOutcome::Live`]; only a proof inside the window
/// cuts. The formula is pure so both implementations agree bit
/// for bit.
#[must_use]
pub fn contest(
    submission: &Submission,
    contest_tick: u32,
    proven_false: bool,
    bond_atomic: u64,
) -> ContestOutcome {
    let settled_at = submission
        .submitted_tick
        .saturating_add(CONTEST_WINDOW_TICKS);
    if contest_tick > settled_at {
        // Late: noise, the payout stands.
        return ContestOutcome::Settled;
    }
    if !proven_false {
        // Inside the window, unequipped: live, waiting.
        return ContestOutcome::Live;
    }
    // Equipped, inside, proven: the full fraction of the bond.
    let slash = u128::from(bond_atomic) * u128::from(SLASH_FRACTION_PM) / 1_000;
    ContestOutcome::Slashed {
        slash_atomic: slash as u64,
        bounty_transferred: true,
    }
}

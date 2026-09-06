//! The Kleos state: the three layers, the queries, the
//! sanctions (ADR-003, ADR-015).
//!
//! The state is a `u32` of millipoints per layer with saturating
//! bounds: the Deed in `[0, 40 000]`, the Echo in `[0, 30 000]`,
//! the Tenure in `[0, 30 000]`, the total in `[0, 100 000]`. The
//! Tenure layer can die: an incident freezes it at zero forever,
//! because a reputation built on time must not survive the
//! incident that time was measuring.

use crate::error::KleosError;

/// The Deed bound: observed behavior, forty points.
pub const DEED_MAX: u32 = 40_000;
/// The Echo bound: peer attestations, thirty points.
pub const ECHO_MAX: u32 = 30_000;
/// The Tenure bound: continuous seniority, thirty points.
pub const TENURE_MAX: u32 = 30_000;
/// The Deed decay per era, a tenth of a point.
pub const DEED_DECAY: u32 = 100;
/// The Echo decay per era, a twentieth of a point.
pub const ECHO_DECAY: u32 = 50;
/// The attestation budget a witness may spend on one target per
/// era, a tenth of a point.
pub const ECHO_BUDGET: u32 = 100;
/// The Echo gain cap per target per era, two points: without it,
/// a farm of bought witnesses inflates the Echo in one era.
pub const ECHO_TARGET_CAP: u32 = 2_000;
/// The floor weight of a fresh witness.
pub const W_MIN: u32 = 150;
/// The minimum Deed for a testimony to carry any weight (R2).
pub const WITNESS_MIN_DEED: u32 = 20_000;
/// The Ring candidacy threshold, applied to the total (R1).
pub const RING_THRESHOLD: u32 = 70_000;
/// The minimum incident-free Tenure for Ring candidacy (R1).
pub const RING_MIN_TENURE: u32 = 15_000;
/// The Deed a liable witness loses on a fraud conviction (R3).
pub const WITNESS_PENALTY: u32 = 3_000;
/// The Deed a liable sponsor loses on a fraud conviction (R3).
pub const SPONSOR_PENALTY: u32 = 5_000;

/// The reputation state of one identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Kleos {
    deed: u32,
    echo: u32,
    tenure: u32,
    tenure_dead: bool,
}

impl Kleos {
    /// The state of a fresh identity: all layers zero, the
    /// Tenure layer alive.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            deed: 0,
            echo: 0,
            tenure: 0,
            tenure_dead: false,
        }
    }

    /// Builds a state from its parts, bounds checked.
    ///
    /// # Errors
    ///
    /// Returns a [`KleosError`] if a layer exceeds its bound.
    pub fn from_parts(
        deed: u32,
        echo: u32,
        tenure: u32,
        tenure_dead: bool,
    ) -> Result<Self, KleosError> {
        if deed > DEED_MAX {
            return Err(KleosError::LayerOverflow {
                layer: "deed",
                value: deed,
            });
        }
        if echo > ECHO_MAX {
            return Err(KleosError::LayerOverflow {
                layer: "echo",
                value: echo,
            });
        }
        if tenure > TENURE_MAX {
            return Err(KleosError::LayerOverflow {
                layer: "tenure",
                value: tenure,
            });
        }
        Ok(Self {
            deed,
            echo,
            tenure,
            tenure_dead,
        })
    }

    /// The Deed layer: observed behavior.
    #[must_use]
    pub const fn deed(&self) -> u32 {
        self.deed
    }

    /// The Echo layer: peer attestations.
    #[must_use]
    pub const fn echo(&self) -> u32 {
        self.echo
    }

    /// The Tenure layer: continuous seniority.
    #[must_use]
    pub const fn tenure(&self) -> u32 {
        self.tenure
    }

    /// Whether the Tenure layer is dead: an incident froze it.
    #[must_use]
    pub const fn tenure_dead(&self) -> bool {
        self.tenure_dead
    }

    /// The total score, in millipoints.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.deed + self.echo + self.tenure
    }

    /// The witness weight of this identity (R2): zero below a
    /// Deed of twenty points, then linear from the floor
    /// `W_MIN` to one thousand at the Deed bound.
    #[must_use]
    pub const fn witness_weight(&self) -> u32 {
        if self.deed < WITNESS_MIN_DEED {
            return 0;
        }
        W_MIN + 850 * (self.deed - WITNESS_MIN_DEED) / (DEED_MAX - WITNESS_MIN_DEED)
    }

    /// Whether this identity may run for the Ring (R1): a total
    /// of at least seventy points, a Tenure of at least fifteen
    /// points, and a living Tenure layer. The wall of time,
    /// applied for real to finality.
    #[must_use]
    pub const fn is_ring_candidate(&self) -> bool {
        self.total() >= RING_THRESHOLD && self.tenure >= RING_MIN_TENURE && !self.tenure_dead
    }

    /// Advances one era (ADR-015): the Deed and the Echo grow by
    /// their era inputs and lose their decay, the Tenure gains
    /// one point if its layer is alive. Every layer saturates at
    /// its bound; a layer at zero stays at zero until behavior
    /// outgrows the decay.
    pub fn advance_era(&mut self, inputs: &EraInputs) {
        let deed = ((u64::from(self.deed) + u64::from(inputs.deed_gain))
            .saturating_sub(u64::from(DEED_DECAY)))
        .clamp(0, u64::from(DEED_MAX));
        self.deed = deed as u32;
        let echo = ((u64::from(self.echo) + u64::from(inputs.echo_gain))
            .saturating_sub(u64::from(ECHO_DECAY)))
        .clamp(0, u64::from(ECHO_MAX));
        self.echo = echo as u32;
        if !self.tenure_dead {
            self.tenure = (self.tenure + 1).min(TENURE_MAX);
        }
    }

    /// The fraud conviction of this identity (R3): the Echo
    /// empties, the Deed halves (floor), the Tenure layer dies
    /// at zero, forever.
    pub fn convict_fraud(&mut self) {
        self.echo = 0;
        self.deed /= 2;
        self.tenure = 0;
        self.tenure_dead = true;
    }

    /// The sanction of a liable witness (R3): three points of
    /// Deed, saturating at zero.
    pub fn penalize_witness(&mut self) {
        self.deed = self.deed.saturating_sub(WITNESS_PENALTY);
    }

    /// The sanction of a liable sponsor (R3): five points of
    /// Deed, saturating at zero.
    pub fn penalize_sponsor(&mut self) {
        self.deed = self.deed.saturating_sub(SPONSOR_PENALTY);
    }

    /// The total stripping of a Ring seat (ADR-002): a seat that
    /// signed a competing fork loses everything, and the years
    /// that constituted it. The sanction falls on the only thing
    /// a validator owns that is precious.
    pub fn strip(&mut self) {
        self.deed = 0;
        self.echo = 0;
        self.tenure = 0;
        self.tenure_dead = true;
    }
}

/// The era inputs of one identity: the gains the chain observed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct EraInputs {
    /// The Deed gain of the era, in millipoints, already
    /// discounted by the closed-graph rule when it applies.
    pub deed_gain: u32,
    /// The Echo gain of the era, in millipoints, already capped
    /// per target.
    pub echo_gain: u32,
}

/// The closed-graph discount of the Deed (R4): activity pooled
/// inside a clique counts at one quarter.
#[must_use]
pub const fn pooled_deed(accrual: u32) -> u32 {
    accrual / 4
}

/// The closed-graph discount of the Echo: attestations exchanged
/// inside the clique count at one tenth.
#[must_use]
pub const fn mutual_echo(budget: u32) -> u32 {
    budget / 10
}

/// The Echo contribution of one attestation: the witness budget
/// weighted by the witness weight (R2), floored.
#[must_use]
pub const fn echo_contribution(witness: &Kleos, budget: u32) -> u32 {
    ((budget as u64 * witness.witness_weight() as u64) / 1_000) as u32
}

/// The per-era Echo gain of one target: the sum of the
/// attestations it received, capped at two points (the cap
/// without which a farm of bought witnesses inflates the Echo in
/// a single era).
#[must_use]
pub fn capped_echo_gain(contributions: &[u32]) -> u32 {
    contributions
        .iter()
        .fold(0u64, |sum, c| sum + u64::from(*c))
        .min(u64::from(ECHO_TARGET_CAP)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_identity_starts_at_zero() {
        let k = Kleos::new();
        assert_eq!(k.deed(), 0);
        assert_eq!(k.echo(), 0);
        assert_eq!(k.tenure(), 0);
        assert!(!k.tenure_dead());
        assert_eq!(k.total(), 0);
        assert_eq!(k.witness_weight(), 0);
        assert!(!k.is_ring_candidate());
    }

    #[test]
    fn the_layers_are_bounded() {
        assert!(Kleos::from_parts(40_001, 0, 0, false).is_err());
        assert!(Kleos::from_parts(0, 30_001, 0, false).is_err());
        assert!(Kleos::from_parts(0, 0, 30_001, false).is_err());
        assert!(Kleos::from_parts(40_000, 30_000, 30_000, false).is_ok());
    }

    #[test]
    fn the_witness_weight_is_linear_above_the_floor() {
        let below = Kleos::from_parts(19_999, 0, 0, false).expect("bounds");
        assert_eq!(below.witness_weight(), 0);
        let floor = Kleos::from_parts(20_000, 0, 0, false).expect("bounds");
        assert_eq!(floor.witness_weight(), W_MIN);
        let top = Kleos::from_parts(40_000, 0, 0, false).expect("bounds");
        assert_eq!(top.witness_weight(), 1_000);
        let mid = Kleos::from_parts(30_000, 0, 0, false).expect("bounds");
        assert_eq!(mid.witness_weight(), W_MIN + 850 * 10_000 / 20_000);
    }

    #[test]
    fn the_era_transition_decays_and_saturates() {
        let mut k = Kleos::new();
        k.advance_era(&EraInputs {
            deed_gain: 2_200,
            echo_gain: 0,
        });
        assert_eq!(k.deed(), 2_100);
        assert_eq!(k.tenure(), 1);
        // A layer at zero with no gain stays at zero.
        let mut idle = Kleos::from_parts(50, 40, 0, false).expect("bounds");
        idle.advance_era(&EraInputs::default());
        assert_eq!(idle.deed(), 0);
        assert_eq!(idle.echo(), 0);
        // The bounds saturate.
        let mut rich = Kleos::from_parts(39_999, 29_999, 29_999, false).expect("bounds");
        rich.advance_era(&EraInputs {
            deed_gain: 40_000,
            echo_gain: 30_000,
        });
        assert_eq!(rich.deed(), DEED_MAX);
        assert_eq!(rich.echo(), ECHO_MAX);
        assert_eq!(rich.tenure(), TENURE_MAX);
    }

    #[test]
    fn a_dead_tenure_layer_never_grows_again() {
        let mut k = Kleos::from_parts(10_000, 5_000, 12_000, false).expect("bounds");
        k.advance_era(&EraInputs::default());
        assert_eq!(k.tenure(), 12_001);
        assert_eq!(k.deed(), 9_900);
        k.convict_fraud();
        assert_eq!(k.echo(), 0);
        assert_eq!(k.deed(), 4_950);
        assert_eq!(k.tenure(), 0);
        assert!(k.tenure_dead());
        for era in 0..20 {
            k.advance_era(&EraInputs {
                deed_gain: 500,
                echo_gain: 100,
            });
            assert_eq!(k.tenure(), 0, "the dead layer stays at zero (era {era})");
        }
    }

    #[test]
    fn the_sanctions_saturate_at_zero() {
        let mut witness = Kleos::from_parts(2_000, 0, 0, false).expect("bounds");
        witness.penalize_witness();
        assert_eq!(witness.deed(), 0);
        let mut sponsor = Kleos::from_parts(4_000, 0, 0, false).expect("bounds");
        sponsor.penalize_sponsor();
        assert_eq!(sponsor.deed(), 0);
    }

    #[test]
    fn the_stripping_takes_everything() {
        let mut seat = Kleos::from_parts(40_000, 30_000, 30_000, false).expect("bounds");
        seat.strip();
        assert_eq!(seat.total(), 0);
        assert!(seat.tenure_dead());
        assert!(!seat.is_ring_candidate());
    }

    #[test]
    fn ring_candidacy_requires_the_wall_of_time() {
        // Total above the threshold, Tenure below the wall.
        let young = Kleos::from_parts(40_000, 30_000, 14_999, false).expect("bounds");
        assert!(!young.is_ring_candidate());
        // Total above the threshold, Tenure above the wall but dead.
        let forgiven = Kleos::from_parts(40_000, 30_000, 20_000, true).expect("bounds");
        assert!(!forgiven.is_ring_candidate());
        // The wall is passed and alive.
        let elder = Kleos::from_parts(40_000, 15_000, 15_000, false).expect("bounds");
        assert!(elder.is_ring_candidate());
    }

    #[test]
    fn the_closed_graph_discounts_apply() {
        assert_eq!(pooled_deed(2_500), 625);
        assert_eq!(pooled_deed(3), 0);
        assert_eq!(mutual_echo(1_000), 100);
        let strong = Kleos::from_parts(40_000, 0, 0, false).expect("bounds");
        assert_eq!(echo_contribution(&strong, ECHO_BUDGET), 100);
        let weak = Kleos::from_parts(10_000, 0, 0, false).expect("bounds");
        assert_eq!(echo_contribution(&weak, ECHO_BUDGET), 0);
    }

    #[test]
    fn the_echo_gain_caps_at_two_points() {
        assert_eq!(capped_echo_gain(&[]), 0);
        assert_eq!(capped_echo_gain(&[100; 19]), 1_900);
        assert_eq!(capped_echo_gain(&[100; 20]), 2_000);
        assert_eq!(capped_echo_gain(&[100; 21]), ECHO_TARGET_CAP);
        assert_eq!(capped_echo_gain(&[4_000_000]), ECHO_TARGET_CAP);
    }
}

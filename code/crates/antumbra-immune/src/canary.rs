//! The canaries: synthetic transactions with known results.

use crate::alert::{Alert, AlertTarget, Severity};
use crate::invariant::Invariant;

/// One canary: a synthetic transaction whose correct result the
/// network already knows.
///
/// The result is a single `u64` (a balance delta, a nullifier
/// count, a fee total): the check is exact, the deviation is an
/// alert. Canaries run on isolated test accounts even on
/// mainnet; a canary failing is the earliest smoke detector the
/// chain has, and the error rate of the suite is a public
/// metric, not an internal log.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Canary {
    /// The canary id, stable across the vector set.
    pub id: u32,
    /// The invariant the canary watches.
    pub invariant: Invariant,
    /// The known-correct result.
    pub expects: u64,
    /// The severity a deviation raises.
    pub severity: Severity,
}

/// A suite of canaries with its public error-rate counters.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CanarySuite {
    checked: u32,
    failed: u32,
}

impl CanarySuite {
    /// The empty suite: nothing checked, nothing failed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            checked: 0,
            failed: 0,
        }
    }

    /// Observes one canary result: exact match or alert.
    ///
    /// Counts the check, counts the failure, and returns the
    /// alert a deviation raises (an observation, never a freeze:
    /// the canary corroborates, the proof decides). Canary alerts
    /// count in the sentinel quorum like any other observation.
    pub fn observe(&mut self, canary: Canary, observed: u64) -> Option<Alert> {
        self.checked += 1;
        if observed == canary.expects {
            return None;
        }
        self.failed += 1;
        Some(Alert {
            invariant: canary.invariant,
            severity: canary.severity,
            target: AlertTarget::Observation,
            proof: None,
            reporter: canary.id,
            height: 0,
        })
    }

    /// The error rate of the suite, in per mille, floor
    /// division: zero checks read as a zero rate, a division by
    /// zero is not a consensus event. The product is computed
    /// in `u64` so the counters cannot overflow it.
    #[must_use]
    pub const fn error_rate_pm(self) -> u32 {
        if self.checked == 0 {
            0
        } else {
            ((self.failed as u64 * 1_000) / self.checked as u64) as u32
        }
    }

    /// The raw counters, for the vector set.
    #[must_use]
    pub const fn counters(self) -> (u32, u32) {
        (self.checked, self.failed)
    }
}

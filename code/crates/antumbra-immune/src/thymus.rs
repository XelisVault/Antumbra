//! The Thymus state machine: detect, contain, repair.

use crate::alert::{Alert, AlertTarget, Severity};
use crate::error::ImmuneError;
use crate::invariant::Invariant;

/// How many distinct Sentinels must corroborate a critical alert
/// on an upgrade to freeze it when no replayable proof exists.
pub const SENTINEL_QUORUM: u32 = 3;

/// The window, in heights, inside which the sentinel corroboration
/// counts: old observations do not halt new upgrades forever.
pub const SENTINEL_WINDOW: u32 = 10;

/// What `observe` did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// The alert was recorded and counted; nothing froze.
    Recorded,
    /// The alert froze the upgrade ramp.
    ///
    /// The payment flow is untouched by construction: the target
    /// of a freeze is an upgrade, never a settlement. `by_proof`
    /// tells whether a single replayable proof decided or the
    /// sentinel quorum did.
    Frozen {
        /// A replayable proof decided alone.
        by_proof: bool,
    },
}

/// The honest metrics of the immunity: the numbers that replace
/// the word "perfect".
///
/// All heights: mean time to detect is the height gap between
/// the injected fault and the first alert, to contain the gap
/// between the fault and the freeze, to repair the gap between
/// the freeze and the resolve. Zero means unknown, not instant:
/// the phase table of the paper sets the targets, this struct
/// measures whether they are met.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Metrics {
    /// Mean time to detect, in heights; zero reads unknown.
    pub mttd: u32,
    /// Mean time to contain, in heights; zero reads unknown.
    pub mttc: u32,
    /// Mean time to repair, in heights; zero reads unknown.
    pub mttr: u32,
    /// Critical alerts observed since the last resolve.
    pub open_crits: u32,
}

/// The Thymus machine of one view: alert intake, freeze, resolve.
///
/// The machine is monotone in height and pure in state: the same
/// sequence of injects, alerts and resolves produces the same
/// freeze decisions and the same metrics bit for bit, on any
/// node, forever.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Thymus {
    frozen: bool,
    fault_height: Option<u32>,
    detected: bool,
    last_height: u32,
    open_crits: u32,
    mttd: u32,
    mttc: u32,
    mttr: u32,
    freeze_height: u32,
    corroborations: [(Invariant, u32, u32); SENTINEL_QUORUM as usize],
    corroborations_len: usize,
}

impl Default for Thymus {
    /// The fresh machine, the same as [`Thymus::new`].
    fn default() -> Self {
        Self::new()
    }
}

impl Thymus {
    /// The fresh machine: nothing frozen, nothing measured.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            frozen: false,
            fault_height: None,
            detected: false,
            last_height: 0,
            open_crits: 0,
            mttd: 0,
            mttc: 0,
            mttr: 0,
            freeze_height: 0,
            corroborations: [(Invariant::Conservation, 0, 0); SENTINEL_QUORUM as usize],
            corroborations_len: 0,
        }
    }

    /// Declares a fault injected at `height` (a test, a drill, a
    /// canary seed): the clock of MTTD and MTTC starts here.
    pub fn inject(&mut self, height: u32) {
        self.fault_height = Some(height);
        self.detected = false;
    }

    /// Observes one alert: records, counts, freezes.
    ///
    /// Freeze rule (fail-closed on sources, fail-open on money):
    /// a critical alert on an upgrade freezes the ramp when it
    /// carries a replayable proof, or when `SENTINEL_QUORUM`
    /// distinct reporters flagged the same invariant inside the
    /// window. A single lying Sentinel is a nuisance; a single
    /// lying proof is impossible (the proof replays or it does
    /// not); and either way, only the upgrade stops.
    ///
    /// # Errors
    ///
    /// Returns [`ImmuneError::NonMonotoneHeight`] when the alert
    /// is older than the last height the machine saw.
    pub fn observe(&mut self, alert: &Alert) -> Result<Outcome, ImmuneError> {
        if alert.height < self.last_height {
            return Err(ImmuneError::NonMonotoneHeight {
                height: alert.height,
                last: self.last_height,
            });
        }
        self.last_height = alert.height;

        // Detection: the first alert after an injection starts
        // the containment clock.
        if !self.detected {
            if let Some(fault) = self.fault_height {
                self.mttd = alert.height.saturating_sub(fault);
            }
            self.detected = true;
        }
        if alert.severity == Severity::Crit {
            self.open_crits = self.open_crits.saturating_add(1);
        }

        // Corroboration bookkeeping: distinct reporters, same
        // invariant, inside the window.
        if alert.proof.is_none() {
            self.record_corroboration(alert.invariant, alert.reporter, alert.height);
        }

        // Freeze decision.
        let upgrade = matches!(alert.target, AlertTarget::Upgrade { .. });
        if !self.frozen
            && upgrade
            && alert.severity == Severity::Crit
            && (alert.proof.is_some() || self.quorum_reached(alert.invariant, alert.height))
        {
            self.frozen = true;
            self.freeze_height = alert.height;
            if let Some(fault) = self.fault_height {
                self.mttc = alert.height.saturating_sub(fault);
            }
            self.corroborations_len = 0;
            return Ok(Outcome::Frozen {
                by_proof: alert.proof.is_some(),
            });
        }
        Ok(Outcome::Recorded)
    }

    /// Resolves the freeze and returns the measured MTTR.
    ///
    /// # Errors
    ///
    /// Returns [`ImmuneError::NotFrozen`] when nothing is frozen.
    pub fn resolve(&mut self, height: u32) -> Result<u32, ImmuneError> {
        if !self.frozen {
            return Err(ImmuneError::NotFrozen);
        }
        self.mttr = height.saturating_sub(self.freeze_height);
        self.frozen = false;
        self.open_crits = 0;
        Ok(self.mttr)
    }

    /// The machine state, as the vector set archives it.
    #[must_use]
    pub const fn snapshot(&self) -> (bool, Metrics) {
        (
            self.frozen,
            Metrics {
                mttd: self.mttd,
                mttc: self.mttc,
                mttr: self.mttr,
                open_crits: self.open_crits,
            },
        )
    }

    /// Whether an upgrade is frozen: the payment flow never is,
    /// there is no such state to ask about.
    #[must_use]
    pub const fn frozen(&self) -> bool {
        self.frozen
    }

    /// Records a corroboration slot: distinct reporters only.
    fn record_corroboration(&mut self, invariant: Invariant, reporter: u32, height: u32) {
        for slot in &mut self.corroborations[..self.corroborations_len] {
            if slot.1 == reporter {
                // The same reporter cannot corroborate itself:
                // refresh the slot, do not stack it.
                slot.0 = invariant;
                slot.2 = height;
                return;
            }
        }
        if self.corroborations_len < self.corroborations.len() {
            self.corroborations[self.corroborations_len] = (invariant, reporter, height);
            self.corroborations_len += 1;
        }
    }

    /// Whether the sentinel quorum is reached for the invariant.
    fn quorum_reached(&self, invariant: Invariant, height: u32) -> bool {
        let mut distinct = 0;
        for slot in &self.corroborations[..self.corroborations_len] {
            if slot.0 == invariant && height.saturating_sub(slot.2) <= SENTINEL_WINDOW {
                distinct += 1;
            }
        }
        distinct >= SENTINEL_QUORUM
    }
}

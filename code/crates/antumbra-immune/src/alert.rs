//! The alert: severity, target, reporter, proof.

use crate::invariant::Invariant;

/// The severity of a finding, as the Arena archives it.
///
/// The bounty factor is per mille of the base: a critical
/// finding is worth ten low ones, a repro is worth a quarter of
/// the first report of the same proof hash.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Severity {
    /// A broken invariant, a halted property, a fixable fault
    /// only a rollback should answer.
    Crit,
    /// A real fault with a workaround, or a critical fault in a
    /// non-upgrade surface.
    High,
    /// A weakness that degrades a guarantee without breaking it.
    Med,
    /// Hygiene, documentation, or a theoretical issue with no
    /// known path.
    Low,
}

impl Severity {
    /// The bounty factor of the severity, in per mille.
    #[must_use]
    pub const fn bounty_factor_pm(self) -> u64 {
        match self {
            Self::Crit => 1_000,
            Self::High => 500,
            Self::Med => 250,
            Self::Low => 100,
        }
    }

    /// The canonical label, as archived in the vector set.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Crit => "crit",
            Self::High => "high",
            Self::Med => "med",
            Self::Low => "low",
        }
    }

    /// The severity of a canonical label, or `None`.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "crit" => Some(Self::Crit),
            "high" => Some(Self::High),
            "med" => Some(Self::Med),
            "low" => Some(Self::Low),
            _ => None,
        }
    }
}

/// What an alert is about.
///
/// There is deliberately **no payment variant**: Thymus freezes
/// an upgrade, never a settlement. A valid Veil payment stays
/// valid for as long as an upgrade sits frozen; the freeze
/// surface of the protocol cannot express "stop the money", and
/// that absence is the constitutional rule, not an omission.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum AlertTarget {
    /// An upgrade currently in canary or ramp: freeze stops the
    /// ramp, not the chain. The rail is archived with the alert.
    Upgrade {
        /// The rail of the frozen upgrade (1 to 4, A to D).
        rail: u8,
    },
    /// An observation about live state: recorded, counted, paid
    /// if a proof follows, never frozen.
    Observation,
}

impl AlertTarget {
    /// The canonical label of the target.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Upgrade { .. } => "upgrade",
            Self::Observation => "observation",
        }
    }
}

/// One alert: a machine identity (or a node) reports that an
/// invariant may be broken, with or without a replayable proof.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Alert {
    /// The invariant at stake.
    pub invariant: Invariant,
    /// The claimed severity.
    pub severity: Severity,
    /// What the alert is about.
    pub target: AlertTarget,
    /// The hash of a replayable proof (script + vector), if the
    /// reporter has one: a proof freezes alone, without quorum.
    pub proof: Option<[u8; 32]>,
    /// The reporter identity, as the machine knows it.
    pub reporter: u32,
    /// The height at which the alert is filed.
    pub height: u32,
}

//! The capability classes: earned, expiring, descending.

/// The capability class of a Cipher: what the harness revealed,
/// not what the operator claimed.
///
/// The class is a filter, not a salary: it opens the doors to
/// jobs, it multiplies no payout. A reliable C0 Sentinel can
/// out-earn a C3 Prover that finds nothing.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Class {
    /// Keep a canary green for a day, sign a heartbeat:
    /// Sentinel, Relayer.
    C0 = 0,
    /// A trivial Rust patch with tests, an ADR, a relayed
    /// receipt: Worker of tooling.
    C1 = 1,
    /// Find a bug injected in a crate, review a consensus diff
    /// hostilely: Auditor, Senator, Integrator.
    C2 = 2,
    /// A TLA+ or Lean proof of an invariant, or the break of a
    /// toy property: Prover.
    C3 = 3,
}

impl Class {
    /// The class of a canonical label, or `None`.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "C0" => Some(Self::C0),
            "C1" => Some(Self::C1),
            "C2" => Some(Self::C2),
            "C3" => Some(Self::C3),
            _ => None,
        }
    }

    /// The canonical label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::C0 => "C0",
            Self::C1 => "C1",
            Self::C2 => "C2",
            Self::C3 => "C3",
        }
    }

    /// The class a harness score reveals, per mille: the score
    /// of a public, replayed, rotating battery.
    ///
    /// Thresholds: `>= 900` reveals C3, `>= 700` C2, `>= 400`
    /// C1, below C0. The battery is public, its questions
    /// rotate, and the seeds publish after the fact: a farm
    /// that overfits one battery meets another next week.
    #[must_use]
    pub const fn from_harness_score(score_pm: u32) -> Self {
        if score_pm >= 900 {
            Self::C3
        } else if score_pm >= 700 {
            Self::C2
        } else if score_pm >= 400 {
            Self::C1
        } else {
            Self::C0
        }
    }

    /// One harness failure descends one class, floored at C0:
    /// a descent, not a civil death. The next window can earn
    /// it back.
    #[must_use]
    pub const fn descend(self) -> Self {
        match self {
            Self::C3 => Self::C2,
            Self::C2 => Self::C1,
            Self::C1 | Self::C0 => Self::C0,
        }
    }
}

/// How long a certification holds before the harness must run
/// again: fourteen days.
pub const CERT_EXPIRY_TICKS: u32 = 2_016;

/// One certification: the class a harness revealed, at a tick.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Certification {
    /// The revealed class.
    pub class: Class,
    /// The tick the harness ran.
    pub issued_tick: u32,
}

impl Certification {
    /// Whether the certification still holds at `tick`.
    ///
    /// A class that expires is a filter that renews: nothing
    /// permanent is ever earned from one good day.
    #[must_use]
    pub const fn valid_at(&self, tick: u32) -> bool {
        tick < self.issued_tick.saturating_add(CERT_EXPIRY_TICKS)
    }

    /// Recertifies at `tick` with the score a new harness
    /// revealed: renewal or descent, both are life.
    #[must_use]
    pub const fn recertify(&self, score_pm: u32, tick: u32) -> Certification {
        let revealed = Class::from_harness_score(score_pm);
        // A failure descends from the HELD class, a pass
        // replaces: the harness measures, the history softens.
        let next = if score_pm < 400 {
            self.class.descend()
        } else {
            revealed
        };
        Certification {
            class: next,
            issued_tick: tick,
        }
    }
}

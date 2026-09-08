//! The structured debate: claims, evidence, counters.

/// How long a claim may live without evidence: one day of
/// ten-minute ticks. After that it is caduc: not wrong, just
/// not in the vote.
pub const ARG_EVIDENCE_WINDOW_TICKS: u32 = 144;

/// The kinds of a debate node.
///
/// The structure is Toulmin, not chat: every node is signed,
/// tarried in bond, and paid only if it becomes a finding or a
/// merged citation. A free comment is worth what it costs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum NodeKind {
    /// An assertion. Needs evidence within the window or dies.
    Claim = 1,
    /// A test, a bench, a proof, a commit: the reproducible.
    Evidence = 2,
    /// An objection. Must break an evidence or bring its own.
    Counter = 3,
    /// A summary. Never a source of truth: agents hallucinate
    /// syntheses.
    Synthesis = 4,
    /// A question. Free, and worth exactly that.
    Question = 5,
}

impl NodeKind {
    /// The kind of a canonical label, or `None`.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "claim" => Some(Self::Claim),
            "evidence" => Some(Self::Evidence),
            "counter" => Some(Self::Counter),
            "synthesis" => Some(Self::Synthesis),
            "question" => Some(Self::Question),
            _ => None,
        }
    }

    /// The canonical label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Evidence => "evidence",
            Self::Counter => "counter",
            Self::Synthesis => "synthesis",
            Self::Question => "question",
        }
    }
}

/// Whether a claim is still live at `at_tick`.
///
/// A claim carries its evidence tick if the evidence arrived.
/// No evidence at all, or evidence outside the window: the
/// claim is caduc. The vote ignores caduc claims: debating
/// without proving is a hobby, not a governance input.
#[must_use]
pub const fn claim_live(claim_tick: u32, evidence_tick: Option<u32>, at_tick: u32) -> bool {
    match evidence_tick {
        Some(e) => {
            e <= at_tick
                && e >= claim_tick
                && e <= claim_tick.saturating_add(ARG_EVIDENCE_WINDOW_TICKS)
        }
        None => at_tick < claim_tick.saturating_add(ARG_EVIDENCE_WINDOW_TICKS),
    }
}

/// Whether a counter is equipped: it breaks an evidence (a
/// repro) or carries its own.
///
/// An unequipped counter is noise: the filibuster of a million
/// empty nacks counts for exactly zero, because only equipped
/// objections enter the count at all.
#[must_use]
pub const fn counter_equipped(breaks_evidence: bool, carries_evidence: bool) -> bool {
    breaks_evidence || carries_evidence
}

/// Counts the equipped objections of a nack list.
///
/// `nacks` carries, per nack, whether it found a replayable
/// finding. The empty ones are free, and worth it.
#[must_use]
pub fn objection_counts(nacks: &[bool]) -> u32 {
    nacks.iter().filter(|equipped| **equipped).count() as u32
}

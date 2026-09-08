//! The rails of change: what may move, and how hard it is to
//! move it.

/// The rail a change travels.
///
/// The rails are the political geometry of the protocol: the
/// bounded parameters of the chain, the tooling around it, the
/// consensus itself, and the constitution. The higher the rail,
/// the harder the predicate, the longer the gate, the wider the
/// families. Only the first two may ever activate on silence:
/// the last two need humans to say yes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Rail {
    /// Bounded parameters: `k` in `[4, 16]`, the fee band, the
    /// ring sizes, the internal treasury split. Senate diverse,
    /// Arena green, seventy-two hours of silence, Ember veto
    /// possible.
    A = 1,
    /// Tooling: wallet, SDK, forge UX, non-consensus node. The
    /// everyday rail, where agent initiative shows daily.
    B = 2,
    /// Consensus-critical: GHOSTDAG, the Veil, the ledger, the
    /// signature, the checkpoint. Two implementations, three
    /// families, a positive vote, a coordinated activation, a
    /// Thymus rollback.
    C = 3,
    /// Constitutional: the cap, the Veil itself, Tenure, R1,
    /// "no Cipher at the Ring", the mint. Never auto, never
    /// silent, three chambers, six months.
    D = 4,
}

impl Rail {
    /// The rail of a canonical label, or `None`.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "A" => Some(Self::A),
            "B" => Some(Self::B),
            "C" => Some(Self::C),
            "D" => Some(Self::D),
            _ => None,
        }
    }

    /// The canonical label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
        }
    }

    /// The minimum number of distinct families whose acks the
    /// predicate requires: two for the fluid rails, three for
    /// the consensus one.
    #[must_use]
    pub const fn f_min(self) -> u32 {
        match self {
            Self::A | Self::B => 2,
            Self::C | Self::D => 3,
        }
    }

    /// The minimum Arena fuzz budget, in seconds: an hour for
    /// the fluid rails, four for the consensus one. The floor
    /// exists because "we agreed in two minutes" is groupthink
    /// with extra steps.
    #[must_use]
    pub const fn min_fuzz_seconds(self) -> u64 {
        match self {
            Self::A | Self::B => 3_600,
            Self::C => 14_400,
            Self::D => 0,
        }
    }

    /// Whether the rail activates on human silence (A and B) or
    /// needs a positive human vote (C and D).
    #[must_use]
    pub const fn activates_on_silence(self) -> bool {
        matches!(self, Self::A | Self::B)
    }
}

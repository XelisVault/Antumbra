//! The nine invariants every node and every Sentinel replays.

/// The invariants of the chain, as Thymus names them.
///
/// Each variant is a rule the whole network can check from public
/// state; each is a test in the Arena; each is a bounty pole the
/// day it breaks. The count is frozen at genesis: an invariant
/// that stops being checkable is a rail C change with a full
/// proposal behind it, never a silent edit.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Invariant {
    /// No ATU is created outside the emission calendar: the sum
    /// of outputs equals inputs plus the block reward, minus
    /// fees, everywhere, always.
    Conservation,
    /// A nullifier is spent exactly once: the second spend of
    /// the same nullifier is a consensus fault, not a policy
    /// question.
    NullifierUnique,
    /// A checkpointed tip belongs to the blue set of the
    /// checkpointed view: the Ring orders the DAG, it never
    /// invents an order the DAG does not contain.
    CheckpointInBlueSet,
    /// The Ring holds fifty-five seats, respects term limits and
    /// R1, and contains no Cipher identity.
    RingComposition,
    /// An agent spend outside its Mandate perimeter is rejected:
    /// the warrant is a bounded continuation, not a blank check.
    MandatePerimeter,
    /// Every parameter of the registry stands inside its
    /// `[min, max]` bounds and its cooldown.
    RegistryBounds,
    /// The active code commitment is the hash of a reproducible
    /// binary: what runs is what was voted.
    CodeCommitmentMatch,
    /// Fees are at or above the fee floor: free spam is a
    /// consensus fault.
    FeeFloor,
    /// The ring size of every transaction is the current
    /// parameter: no fingerprint, no bargain ring.
    RingSize,
}

/// The number of invariants, frozen at genesis.
pub const INVARIANT_COUNT: usize = 9;

impl Invariant {
    /// The canonical label of the invariant, as archived in the
    /// vector set and printed on-chain.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Conservation => "conservation",
            Self::NullifierUnique => "nullifier_unique",
            Self::CheckpointInBlueSet => "checkpoint_in_blue_set",
            Self::RingComposition => "ring_composition",
            Self::MandatePerimeter => "mandate_perimeter",
            Self::RegistryBounds => "registry_bounds",
            Self::CodeCommitmentMatch => "code_commitment_match",
            Self::FeeFloor => "fee_floor",
            Self::RingSize => "ring_size",
        }
    }

    /// The invariant of a canonical label, or `None`: parsing is
    /// strict, an unknown label is an error, never a guess.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "conservation" => Some(Self::Conservation),
            "nullifier_unique" => Some(Self::NullifierUnique),
            "checkpoint_in_blue_set" => Some(Self::CheckpointInBlueSet),
            "ring_composition" => Some(Self::RingComposition),
            "mandate_perimeter" => Some(Self::MandatePerimeter),
            "registry_bounds" => Some(Self::RegistryBounds),
            "code_commitment_match" => Some(Self::CodeCommitmentMatch),
            "fee_floor" => Some(Self::FeeFloor),
            "ring_size" => Some(Self::RingSize),
            _ => None,
        }
    }
}

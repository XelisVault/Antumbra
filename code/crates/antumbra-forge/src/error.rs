//! One enum for every rejection of the evolution layer.

/// A failure of a Forge rule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ForgeError {
    /// The merge predicate refused: the archived reason.
    MergeRefused {
        /// The refusal clause, as the vector set archives it.
        clause: &'static str,
    },
    /// A parameter change is out of the bounds of its spec.
    OutOfBounds {
        /// The parameter key.
        key: &'static str,
        /// The offending value.
        value: u64,
    },
    /// A parameter change lands inside the cooldown of the last
    /// one.
    Cooldown {
        /// The parameter key.
        key: &'static str,
        /// The height the change must wait for.
        until: u32,
    },
    /// The proposal machine cannot take this event in this
    /// state.
    IllegalTransition {
        /// The state the proposal is in.
        state: &'static str,
        /// The event that arrived.
        event: &'static str,
    },
    /// A debate node violates the structure rules.
    DebateMalformed {
        /// The rule that broke.
        rule: &'static str,
    },
}

impl core::fmt::Display for ForgeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MergeRefused { clause } => {
                write!(f, "the merge predicate refused: {clause}")
            }
            Self::OutOfBounds { key, value } => {
                write!(f, "parameter {key} = {value} is out of bounds")
            }
            Self::Cooldown { key, until } => {
                write!(f, "parameter {key} is cooling down until height {until}")
            }
            Self::IllegalTransition { state, event } => {
                write!(f, "a proposal in {state} cannot take {event}")
            }
            Self::DebateMalformed { rule } => {
                write!(f, "the debate structure broke: {rule}")
            }
        }
    }
}

impl std::error::Error for ForgeError {}

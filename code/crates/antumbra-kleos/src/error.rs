//! One enum for every rejection of the reputation layer.
//!
//! Every variant carries the offending value: a rejection that
//! cannot be reproduced from its message cannot be audited.

/// A failure of a Kleos rule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KleosError {
    /// A layer exceeded its bound.
    LayerOverflow {
        /// The layer name.
        layer: &'static str,
        /// The offending value, in millipoints.
        value: u32,
    },
    /// The draw pool holds no weight at all.
    EmptyPool,
    /// The candidates are not strictly ascending by identity.
    UnsortedCandidates,
}

impl core::fmt::Display for KleosError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LayerOverflow { layer, value } => {
                write!(
                    f,
                    "the {layer} layer holds {value} millipoints, out of bounds"
                )
            }
            Self::EmptyPool => write!(f, "the draw pool holds no weight"),
            Self::UnsortedCandidates => {
                write!(f, "the candidates are not strictly ascending by identity")
            }
        }
    }
}

impl std::error::Error for KleosError {}

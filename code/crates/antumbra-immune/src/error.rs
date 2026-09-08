//! One enum for every rejection of the immunity layer.

/// A failure of a Thymus rule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImmuneError {
    /// A canary result arrived for an unknown canary id.
    UnknownCanary {
        /// The offending canary id.
        id: u32,
    },
    /// `resolve` was called while nothing is frozen.
    NotFrozen,
    /// A rollback was requested with fewer than two hot code
    /// commitments: there is nothing to return to.
    EmptyHistory,
    /// The bounty product overflowed the atomic-unit domain.
    BountyOverflow {
        /// The intermediate product that did not fit.
        product: u128,
    },
    /// An alert carries a height lower than the last one seen:
    /// the machine is monotone, alerts cannot time-travel.
    NonMonotoneHeight {
        /// The offending height.
        height: u32,
        /// The height the machine already stands at.
        last: u32,
    },
}

impl core::fmt::Display for ImmuneError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownCanary { id } => {
                write!(f, "canary {id} is not registered in the suite")
            }
            Self::NotFrozen => {
                write!(f, "nothing is frozen: there is nothing to resolve")
            }
            Self::EmptyHistory => {
                write!(f, "fewer than two hot code commitments: no rollback target")
            }
            Self::BountyOverflow { product } => {
                write!(
                    f,
                    "the bounty product {product} overflows the atomic unit domain"
                )
            }
            Self::NonMonotoneHeight { height, last } => {
                write!(
                    f,
                    "alert height {height} is below the last height seen ({last})"
                )
            }
        }
    }
}

impl std::error::Error for ImmuneError {}

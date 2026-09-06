//! Errors of the Veil cryptographic core.
//!
//! One enum for the whole crate: every rejection carries the
//! offending 32 bytes so that a decoder fault names its input, never
//! a bare boolean. The exhaustion error of the hash to point is
//! reachable with a probability below two to the minus two hundred
//! and is still handled: no path of this crate panics.

/// Every way the Veil core can fail.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VeilError {
    /// The 32 bytes are not a canonical point encoding: the
    /// recompression of the decoded point differs from the input.
    NonCanonicalPoint([u8; 32]),
    /// The decoded point is the identity, which no published key,
    /// one-time address or commitment may ever be.
    IdentityPoint([u8; 32]),
    /// The decoded point is outside the prime-order subgroup: a
    /// torsion point or a point of mixed order. The subgroup rule
    /// excludes the whole torsion attack class from the private
    /// sphere in one invariant.
    OutsideSubgroup([u8; 32]),
    /// The 32 bytes are not a canonical scalar: the value is zero or
    /// at least the group order.
    NonCanonicalScalar([u8; 32]),
    /// The hash to point exhausted its 256 rounds. Probability
    /// below 2^-2040; the decoder still refuses to panic.
    HashToPointExhausted,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl core::fmt::Display for VeilError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonCanonicalPoint(bytes) => {
                write!(f, "point encoding {} is not canonical", hex(bytes))
            }
            Self::IdentityPoint(bytes) => {
                write!(f, "point encoding {} is the identity", hex(bytes))
            }
            Self::OutsideSubgroup(bytes) => {
                write!(
                    f,
                    "point encoding {} is outside the prime-order subgroup",
                    hex(bytes)
                )
            }
            Self::NonCanonicalScalar(bytes) => {
                write!(
                    f,
                    "scalar encoding {} is zero or above the group order",
                    hex(bytes)
                )
            }
            Self::HashToPointExhausted => {
                write!(f, "the hash to point exhausted its 256 rounds")
            }
        }
    }
}

impl std::error::Error for VeilError {}

//! Errors of the Veil cryptographic core.
//!
//! One enum for the whole crate: every rejection carries the
//! offending value so that a decoder fault names its input, never a
//! bare boolean. Structural rejections of the ring signature carry
//! the size or the index at fault. The exhaustion error of the hash
//! to point is reachable with a probability below two to the minus
//! two hundred and is still handled: no path of this crate panics.

use antumbra_primitives::DecodeError;

/// Every way the Veil core can fail.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VeilError {
    /// The bytes are not a decodable canonical structure.
    Decode(DecodeError),
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
    /// A ring size outside the accepted bounds (ADR-012).
    RingSize(u64),
    /// Two members of a ring are the same key: the anonymity set
    /// collapses, and no encoder ever produces it.
    DuplicateMember,
    /// The real index of a signature lies outside its ring.
    Index {
        /// The offending index.
        index: usize,
        /// The length of the ring.
        len: usize,
    },
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
            Self::Decode(e) => write!(f, "canonical decoding failed: {e}"),
            Self::RingSize(n) => write!(f, "ring size {n} is outside the accepted bounds"),
            Self::DuplicateMember => write!(f, "two ring members are the same key"),
            Self::Index { index, len } => {
                write!(f, "real index {index} is outside the ring of {len} members")
            }
            Self::HashToPointExhausted => {
                write!(f, "the hash to point exhausted its 256 rounds")
            }
        }
    }
}

impl std::error::Error for VeilError {}

impl From<DecodeError> for VeilError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

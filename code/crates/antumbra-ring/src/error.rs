//! One enum for every rejection of the finality layer.
//!
//! Every variant carries the offending value, so that a log line
//! names the exact fault: a rejection that cannot be reproduced
//! from its message cannot be audited.

use antumbra_primitives::DecodeError;

/// A failure of decoding or of a Ring rule.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RingError {
    /// The bytes are not a canonical Ring object.
    Decode(DecodeError),
    /// The container version is not the one this node speaks.
    InvalidVersion(u16),
    /// An era of zero: eras are counted from one.
    EraZero,
    /// A sequence of zero: sequences are counted from one.
    SequenceZero,
    /// A checkpoint signing the zero hash: a checkpoint signs a
    /// real block.
    ZeroTip,
    /// A roster larger than the seat count.
    TooManySeats(usize),
    /// A roster with the same key on two seats.
    DuplicateKey,
    /// A signature from a seat the roster does not hold.
    SeatOutOfRange {
        /// The seat index announced.
        seat: u16,
        /// The number of seats the roster holds.
        seats: usize,
    },
    /// Two signatures from one seat in one checkpoint.
    DuplicateSeat(u16),
    /// Seat pairs not strictly ascending in the encoding.
    UnsortedSeats,
    /// More signatures than seats.
    TooManySignatures(usize),
    /// A signature that does not verify under the roster key.
    InvalidSignature {
        /// The seat that produced it.
        seat: u16,
    },
    /// The checkpoint and the roster disagree on the era.
    EraMismatch {
        /// The era of the roster.
        roster: u64,
        /// The era of the message.
        message: u64,
    },
    /// Stripping evidence over two different eras.
    DifferentEra {
        /// The era of the first message.
        first: u64,
        /// The era of the second message.
        second: u64,
    },
    /// Stripping evidence over two different sequences.
    DifferentSequence {
        /// The sequence of the first message.
        first: u64,
        /// The sequence of the second message.
        second: u64,
    },
    /// Stripping evidence over one message signed twice.
    IdenticalMessages,
}

impl core::fmt::Display for RingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "decode failure: {e}"),
            Self::InvalidVersion(v) => write!(f, "unsupported container version {v}"),
            Self::EraZero => write!(f, "eras are counted from one"),
            Self::SequenceZero => write!(f, "sequences are counted from one"),
            Self::ZeroTip => write!(f, "a checkpoint signs a real block, not the zero hash"),
            Self::TooManySeats(n) => write!(f, "{n} seats announced, at most 55"),
            Self::DuplicateKey => write!(f, "the same key holds two seats"),
            Self::SeatOutOfRange { seat, seats } => {
                write!(f, "seat {seat} announced, the roster holds {seats}")
            }
            Self::DuplicateSeat(seat) => write!(f, "seat {seat} signed twice"),
            Self::UnsortedSeats => write!(f, "seats are not strictly ascending"),
            Self::TooManySignatures(n) => write!(f, "{n} signatures, at most 55"),
            Self::InvalidSignature { seat } => write!(f, "the signature of seat {seat} is invalid"),
            Self::EraMismatch { roster, message } => {
                write!(f, "roster era {roster}, message era {message}")
            }
            Self::DifferentEra { first, second } => {
                write!(f, "the messages disagree on the era: {first} and {second}")
            }
            Self::DifferentSequence { first, second } => {
                write!(
                    f,
                    "the messages disagree on the sequence: {first} and {second}"
                )
            }
            Self::IdenticalMessages => write!(f, "one message signed twice is not a fork"),
        }
    }
}

impl std::error::Error for RingError {}

impl From<DecodeError> for RingError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

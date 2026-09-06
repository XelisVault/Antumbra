//! One enum for every rejection of the ordering layer.
//!
//! Every variant carries the offending value or the offending
//! pair, so that a log line names the exact fault: a rejection
//! that cannot be reproduced from its message cannot be audited.

use antumbra_primitives::{DecodeError, Hash};

/// A failure of decoding or of an ordering-layer rule.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DagError {
    /// The bytes are not a canonical header or block.
    Decode(DecodeError),
    /// The header version is not the one this node speaks.
    InvalidVersion(u16),
    /// A header announced no parent at all.
    NoParents,
    /// A header announced more than the maximum of sixteen.
    TooManyParents(usize),
    /// The parent list is not strictly ascending.
    UnsortedParents,
    /// A block carries more transaction ids than the maximum.
    TooManyTransactions(usize),
    /// The transaction id list is not strictly ascending.
    UnsortedTransactions,
    /// The payload root does not commit the announced ids.
    PayloadRootMismatch {
        /// The root announced in the header.
        announced: Hash,
        /// The root recomputed from the payload.
        computed: Hash,
    },
    /// A block other than the genesis points at the zero parent.
    ZeroParent,
    /// A parent is not in the DAG.
    UnknownParent(Hash),
    /// The block id is already in the DAG.
    Duplicate(Hash),
    /// The announced height is not one plus the parent maximum.
    HeightMismatch {
        /// The height announced in the header.
        announced: u64,
        /// The height computed from the parents.
        computed: u64,
    },
    /// The timestamp is behind a parent timestamp.
    TimestampBehind {
        /// The timestamp of the block.
        timestamp: u64,
        /// The timestamp of the most recent parent.
        parent: u64,
    },
    /// The timestamp is further in the future than the policy
    /// allows.
    TimestampFuture {
        /// The timestamp of the block.
        timestamp: u64,
        /// The clock limit the policy granted.
        limit: u64,
    },
    /// The block id does not carry the required work.
    InsufficientWork {
        /// The leading zero bits of the block id.
        found: u32,
        /// The difficulty the policy requires.
        required: u32,
    },
    /// A query named a block the DAG does not hold.
    UnknownBlock(Hash),
}

impl core::fmt::Display for DagError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "decode failure: {e}"),
            Self::InvalidVersion(v) => write!(f, "unsupported header version {v}"),
            Self::NoParents => write!(f, "a header must announce parents"),
            Self::TooManyParents(n) => write!(f, "{n} parents announced, at most 16"),
            Self::UnsortedParents => write!(f, "parents are not strictly ascending"),
            Self::TooManyTransactions(n) => {
                write!(f, "{n} transaction ids announced, at most 64")
            }
            Self::UnsortedTransactions => {
                write!(f, "transaction ids are not strictly ascending")
            }
            Self::PayloadRootMismatch {
                announced,
                computed,
            } => write!(
                f,
                "payload root mismatch: announced {announced}, computed {computed}"
            ),
            Self::ZeroParent => write!(f, "the zero parent belongs to the genesis alone"),
            Self::UnknownParent(h) => write!(f, "unknown parent {h}"),
            Self::Duplicate(h) => write!(f, "block {h} is already in the DAG"),
            Self::HeightMismatch {
                announced,
                computed,
            } => {
                write!(f, "height announced {announced}, computed {computed}")
            }
            Self::TimestampBehind { timestamp, parent } => {
                write!(f, "timestamp {timestamp} behind parent {parent}")
            }
            Self::TimestampFuture { timestamp, limit } => {
                write!(f, "timestamp {timestamp} beyond the future limit {limit}")
            }
            Self::InsufficientWork { found, required } => {
                write!(f, "work found {found} bits, required {required}")
            }
            Self::UnknownBlock(h) => write!(f, "unknown block {h}"),
        }
    }
}

impl std::error::Error for DagError {}

impl From<DecodeError> for DagError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

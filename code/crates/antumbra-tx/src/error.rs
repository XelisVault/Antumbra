//! Errors of the transaction layer.
//!
//! One enum for the whole crate: canonical decoding failures wrap
//! the primitives [`DecodeError`], structural rejections carry the
//! offending value, and verification failures point at the input
//! that failed.

use antumbra_primitives::DecodeError;

use crate::amount::Amount;

/// Every way a transaction can fail.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TxError {
    /// The bytes are not a decodable canonical structure.
    Decode(DecodeError),
    /// The version is not version 1.
    InvalidVersion(u16),
    /// The type tag is not a transaction type of this protocol.
    UnknownType(u8),
    /// The version 1 scaffold carries transfers only.
    UnsupportedType(u8),
    /// More inputs than the structural limit (ADR-010).
    TooManyInputs(usize),
    /// More outputs than the structural limit (ADR-010).
    TooManyOutputs(usize),
    /// More extra data than the structural limit (ADR-010).
    ExtraTooLarge(usize),
    /// Inputs are not strictly ascending by (hash, index): the
    /// encoding is not canonical, or a reference is duplicated.
    UnsortedInputs,
    /// A transaction must spend at least one output.
    NoInputs,
    /// A transaction must create at least one output.
    NoOutputs,
    /// The output at this index carries a zero amount.
    ZeroAmount(usize),
    /// The fee is below the schedule minimum.
    FeeTooLow {
        /// The fee the transaction declared.
        fee: Amount,
        /// The minimum the schedule computed.
        minimum: Amount,
    },
    /// The signature key list does not match the input count.
    KeyCountMismatch {
        /// The number of inputs to sign.
        expected: usize,
        /// The number of keys provided.
        provided: usize,
    },
    /// The key at this index does not match the input it must
    /// unlock.
    KeyMismatch(usize),
    /// The Ed25519 signature at this input index does not verify.
    InvalidSignature(usize),
}

impl core::fmt::Display for TxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "canonical decoding failed: {e}"),
            Self::InvalidVersion(v) => write!(f, "unsupported transaction version {v}"),
            Self::UnknownType(t) => write!(f, "unknown transaction type tag {t}"),
            Self::UnsupportedType(t) => {
                write!(f, "transaction type tag {t} is not a version 1 transfer")
            }
            Self::TooManyInputs(n) => write!(f, "{n} inputs exceed the limit"),
            Self::TooManyOutputs(n) => write!(f, "{n} outputs exceed the limit"),
            Self::ExtraTooLarge(n) => write!(f, "{n} bytes of extra data exceed the limit"),
            Self::UnsortedInputs => {
                write!(f, "inputs must be strictly ascending by (hash, index)")
            }
            Self::NoInputs => write!(f, "a transaction needs at least one input"),
            Self::NoOutputs => write!(f, "a transaction needs at least one output"),
            Self::ZeroAmount(i) => write!(f, "output {i} carries a zero amount"),
            Self::FeeTooLow { fee, minimum } => {
                write!(f, "fee {fee} is below the minimum {minimum}")
            }
            Self::KeyCountMismatch { expected, provided } => {
                write!(f, "{provided} keys provided for {expected} inputs")
            }
            Self::KeyMismatch(i) => write!(f, "key {i} does not match its input"),
            Self::InvalidSignature(i) => write!(f, "signature {i} does not verify"),
        }
    }
}

impl std::error::Error for TxError {}

impl From<DecodeError> for TxError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

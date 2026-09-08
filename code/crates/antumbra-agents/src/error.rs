//! One enum for every rejection of the machine-account layer.

/// A failure of a Mandate, a Warrant, an encoding or a receipt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AgentError {
    /// The Mandate is malformed: a bound, a version or a
    /// destination slot violates the grammar.
    MalformedMandate {
        /// The offending field.
        field: &'static str,
        /// The offending value, as archived.
        value: u64,
    },
    /// A destination of the Mandate repeats: the set is a set.
    DuplicateDest,
    /// The Warrant is revoked: future spends are rejected,
    /// streams are cut, unsold receipts read `Failed`.
    Revoked,
    /// The spend lands at or after the expiry tick.
    Expired {
        /// The tick of the attempt.
        tick: u32,
        /// The expiry tick of the Mandate.
        expiry: u32,
    },
    /// The nonce is not exactly the successor of the last one:
    /// replays and gaps are both refused.
    NonceNotMonotone {
        /// The nonce the spend presented.
        given: u32,
        /// The nonce the Warrant expected.
        expected: u32,
    },
    /// A spend of zero: amounts are positive.
    ZeroAmount,
    /// The amount exceeds the per-tick rate bound.
    OverRate {
        /// The offending amount.
        amount: u64,
        /// The rate bound of the Mandate.
        max_rate: u64,
    },
    /// The amount exceeds what the Warrant still holds.
    OverCap {
        /// The offending amount.
        amount: u64,
        /// What the Warrant still holds.
        remaining: u64,
    },
    /// The destination is not in the Mandate perimeter.
    PerimeterDest,
    /// The batch holds more payments than the protocol accepts.
    BatchTooLarge {
        /// The offending length.
        len: usize,
    },
    /// The 64-byte authority field is not well formed: the
    /// padding half does not derive from the payload half.
    MalformedAuthority,
    /// The receipt does not verify: the commitment, the fact
    /// and the salt do not recompose.
    CommitmentMismatch,
}

impl core::fmt::Display for AgentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedMandate { field, value } => {
                write!(f, "malformed mandate: {field} = {value}")
            }
            Self::DuplicateDest => write!(f, "a mandate destination repeats"),
            Self::Revoked => write!(f, "the warrant is revoked: fail-closed"),
            Self::Expired { tick, expiry } => {
                write!(f, "tick {tick} lands at or after expiry {expiry}")
            }
            Self::NonceNotMonotone { given, expected } => {
                write!(f, "nonce {given} is not the successor of {expected}")
            }
            Self::ZeroAmount => write!(f, "a spend of zero is not a spend"),
            Self::OverRate { amount, max_rate } => {
                write!(f, "amount {amount} exceeds the rate bound {max_rate}")
            }
            Self::OverCap { amount, remaining } => {
                write!(f, "amount {amount} exceeds the remaining {remaining}")
            }
            Self::PerimeterDest => {
                write!(f, "the destination is outside the mandate perimeter")
            }
            Self::BatchTooLarge { len } => {
                write!(f, "a batch of {len} payments exceeds the protocol bound")
            }
            Self::MalformedAuthority => {
                write!(f, "the authority field is not well formed")
            }
            Self::CommitmentMismatch => {
                write!(f, "the receipt commitment does not verify")
            }
        }
    }
}

impl std::error::Error for AgentError {}

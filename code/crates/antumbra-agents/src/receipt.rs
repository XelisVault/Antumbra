//! The receipts: public facts with selective opening (the
//! machine Lumen, without ZK at genesis).

use crate::error::AgentError;
use antumbra_primitives::{keccak256, Hash};

/// The fact kinds of the receipt vocabulary.
pub const FACT_KIND_BALANCE: u8 = 1;
/// A payment fact: "this amount moved for this job".
pub const FACT_KIND_PAYMENT: u8 = 2;
/// An uptime fact: "this warrant stayed alive until this tick".
pub const FACT_KIND_UPTIME: u8 = 3;

/// One fact a receipt may commit to.
///
/// The form follows the thesis: "at least `amount` was paid
/// under `warrant_root` for `job_id` before `tick`". A receipt
/// is the object another agent consumes without any human
/// Lumen in the loop: the machine-readable proof of a settled
/// result.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fact {
    /// The fact kind (see the `FACT_KIND_*` constants).
    pub kind: u8,
    /// The job the fact is about.
    pub job_id: u32,
    /// The amount at stake, atomic units.
    pub amount: u64,
    /// The tick before which the fact held.
    pub tick: u32,
    /// The Warrant the fact is about.
    pub warrant_root: Hash,
}

impl Fact {
    /// The canonical encoding of the fact.
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; FACT_BYTES] {
        let mut out = [0u8; FACT_BYTES];
        out[0] = self.kind;
        out[1..5].copy_from_slice(&self.job_id.to_be_bytes());
        out[5..13].copy_from_slice(&self.amount.to_be_bytes());
        out[13..17].copy_from_slice(&self.tick.to_be_bytes());
        out[17..49].copy_from_slice(&self.warrant_root.0);
        out
    }
}

/// The fixed width of the canonical fact encoding: one byte of
/// kind, four of job, eight of amount, four of tick, thirty-two
/// of warrant root.
pub const FACT_BYTES: usize = 49;

/// The status of a receipt at read time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReceiptStatus {
    /// Committed, unopened: a promise still standing.
    Open,
    /// Opened and settled while the warrant lived: paid.
    Paid,
    /// The warrant was revoked before the opening: the promise
    /// died, the receipt reads `Failed` for everyone.
    Failed,
}

/// Receipt operations: commit, open, verify.
pub struct Receipt;

impl Receipt {
    /// Commits to a fact under a salt: the public receipt.
    ///
    /// Hiding without ZK at genesis: without the salt, the
    /// commitment is a Keccak preimage the counterparty cannot
    /// invert; with the fact and the salt, the opening verifies
    /// in one hash.
    #[must_use]
    pub fn commit(fact: &Fact, salt: &Hash) -> Hash {
        let mut material = [0u8; FACT_BYTES + 32];
        material[..FACT_BYTES].copy_from_slice(&fact.canonical_bytes());
        material[FACT_BYTES..].copy_from_slice(&salt.0);
        keccak256(&material)
    }

    /// Verifies an opening: the commitment, the fact, the salt.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::CommitmentMismatch`] when the
    /// three do not recompose.
    pub fn verify(commitment: &Hash, fact: &Fact, salt: &Hash) -> Result<(), AgentError> {
        if *commitment == Self::commit(fact, salt) {
            Ok(())
        } else {
            Err(AgentError::CommitmentMismatch)
        }
    }

    /// The status of a receipt, given the warrant state: the
    /// wall is the same everywhere, a revoked warrant fails
    /// every unopened promise.
    #[must_use]
    pub fn status(warrant_revoked: bool, opened: bool) -> ReceiptStatus {
        match (warrant_revoked, opened) {
            (true, _) => ReceiptStatus::Failed,
            (false, true) => ReceiptStatus::Paid,
            (false, false) => ReceiptStatus::Open,
        }
    }
}

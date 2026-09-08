//! The batches: many outputs, one ring verification, one fee.

use crate::error::AgentError;
use crate::warrant::Warrant;
use antumbra_primitives::Hash;

/// How many payments one batch may carry.
pub const BATCH_MAX_PAYMENTS: usize = 64;

/// One payment of a batch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Payment {
    /// The destination, inside the Mandate perimeter.
    pub dest: Hash,
    /// The amount, atomic units, strictly positive.
    pub amount: u64,
}

/// What a settled batch returns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BatchOutcome {
    /// The total the batch moved.
    pub total: u64,
    /// How many ring verifications the batch costs: one,
    /// always. The whole point: N micropayments must not pay N
    /// ring-signature verifications and N fee floors.
    pub ring_verifications: u32,
}

/// Runs one batch under one Warrant: one logical spend.
///
/// The batch is ONE spend for the state machine: one nonce
/// successor, one rate bound on the total (not on each atom:
/// micro-payments of one ATU must survive), one perimeter check
/// per destination, and one ring verification at settlement.
/// The fee schedule charges the batch as one transaction: this
/// is the primitive that keeps a ten-cents-per-call agent
/// economy alive.
///
/// # Errors
///
/// Returns [`AgentError::BatchTooLarge`] above the protocol
/// bound, and the Warrant rejections otherwise (revocation,
/// expiry, nonce, perimeter, rate on the total, cap).
pub fn batch(
    payments: &[Payment],
    warrant: &mut Warrant,
    nonce: u32,
    tick: u32,
) -> Result<BatchOutcome, AgentError> {
    if payments.len() > BATCH_MAX_PAYMENTS {
        return Err(AgentError::BatchTooLarge {
            len: payments.len(),
        });
    }
    if payments.is_empty() {
        // An empty batch is not a spend: fail closed, not free.
        return Err(AgentError::ZeroAmount);
    }
    let mut total: u64 = 0;
    for payment in payments {
        if payment.amount == 0 {
            return Err(AgentError::ZeroAmount);
        }
        if !warrant.mandate().permits_dest(&payment.dest) {
            return Err(AgentError::PerimeterDest);
        }
        total = total
            .checked_add(payment.amount)
            .ok_or(AgentError::OverCap {
                amount: u64::MAX,
                remaining: warrant.state().0,
            })?;
    }
    // The spend itself: one logical movement of `total`.
    warrant.spend(&payments[0].dest, total, nonce, tick)?;
    Ok(BatchOutcome {
        total,
        ring_verifications: 1,
    })
}

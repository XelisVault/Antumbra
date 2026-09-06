//! The fee schedule: fixed part, size part, ring surcharge
//! (ADR-009).
//!
//! Fees are explicit, in clear, in atomic units. The minimum fee of
//! a transaction is `f0 + f_kB * n_kB + f_ring * m` for `n_kB`
//! started kibibytes of canonical encoding and `m` ringed outputs.
//! The provisional values below are development values; genesis
//! freezes them, and governance moves the fixed part only within
//! the published bounds.

use crate::amount::Amount;

/// The provisional fixed part: 100,000 atomic units (0.001 ATU).
pub const FEE_BASE: Amount = Amount::from_atomic(100_000);

/// The provisional per-kibibyte part: 100,000 atomic units.
pub const FEE_PER_KIB: Amount = Amount::from_atomic(100_000);

/// The provisional surcharge per ringed output: 500,000 atomic
/// units. A ring of sixteen keys is the most expensive construction
/// a node verifies.
pub const FEE_PER_RINGED_OUTPUT: Amount = Amount::from_atomic(500_000);

/// The lower governance bound on the fixed part (ADR-009).
pub const F0_MIN: Amount = Amount::from_atomic(10_000);

/// The upper governance bound on the fixed part (ADR-009).
pub const F0_MAX: Amount = Amount::from_atomic(1_000_000);

/// Charges per started kibibyte, minimum one: a transaction of one
/// byte and a transaction of 1024 bytes occupy the same started
/// kibibyte.
#[must_use]
fn kibibytes(size_bytes: usize) -> u64 {
    let chunks = (size_bytes as u64).div_ceil(1024);
    chunks.max(1)
}

/// A fee schedule: the three components of the whitepaper formula.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FeeSchedule {
    /// The fixed part `f0`.
    pub base: Amount,
    /// The per-started-kibibyte part `f_kB`.
    pub per_kib: Amount,
    /// The surcharge per ringed output `f_ring`.
    pub per_ringed_output: Amount,
}

impl FeeSchedule {
    /// The provisional development schedule of ADR-009.
    pub const PROVISIONAL: Self = Self {
        base: FEE_BASE,
        per_kib: FEE_PER_KIB,
        per_ringed_output: FEE_PER_RINGED_OUTPUT,
    };

    /// Builds a schedule from its three components.
    #[must_use]
    pub const fn new(base: Amount, per_kib: Amount, per_ringed_output: Amount) -> Self {
        Self {
            base,
            per_kib,
            per_ringed_output,
        }
    }

    /// The minimum fee of a transaction of `size_bytes` canonical
    /// bytes carrying `ringed_outputs` ringed outputs.
    ///
    /// Returns `None` when the computation would overflow: a
    /// consensus caller rejects the transaction rather than
    /// accepting it under an uncomputable minimum.
    #[must_use]
    pub fn minimum_fee(&self, size_bytes: usize, ringed_outputs: u64) -> Option<Amount> {
        let kib = kibibytes(size_bytes);
        let size_part = self.per_kib.atomic().checked_mul(kib)?;
        let ring_part = self
            .per_ringed_output
            .atomic()
            .checked_mul(ringed_outputs)?;
        let total = self
            .base
            .atomic()
            .checked_add(size_part)?
            .checked_add(ring_part)?;
        Some(Amount::from_atomic(total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisional_values_match_the_adr() {
        assert_eq!(FEE_BASE.atomic(), 100_000);
        assert_eq!(FEE_PER_KIB.atomic(), 100_000);
        assert_eq!(FEE_PER_RINGED_OUTPUT.atomic(), 500_000);
        assert_eq!(FeeSchedule::PROVISIONAL.base, FEE_BASE);
    }

    #[test]
    fn governance_bounds_contain_the_provisional_fixed_part() {
        assert!(F0_MIN < FEE_BASE);
        assert!(FEE_BASE < F0_MAX);
    }

    #[test]
    fn one_byte_costs_one_started_kibibyte() {
        let fee = FeeSchedule::PROVISIONAL.minimum_fee(1, 0).expect("fits");
        assert_eq!(fee, Amount::from_atomic(200_000));
        // The empty size is still one started kibibyte: the minimum
        // is never below the fixed part plus one size chunk.
        let zero = FeeSchedule::PROVISIONAL.minimum_fee(0, 0).expect("fits");
        assert_eq!(zero, Amount::from_atomic(200_000));
    }

    #[test]
    fn kibibyte_boundaries_charge_by_started_chunk() {
        let s = FeeSchedule::PROVISIONAL;
        assert_eq!(
            s.minimum_fee(1024, 0),
            s.minimum_fee(1, 0),
            "1024 bytes is still one kibibyte"
        );
        assert_eq!(
            s.minimum_fee(1025, 0),
            s.minimum_fee(2048, 0),
            "1025 bytes starts the second kibibyte"
        );
        let two = s.minimum_fee(1025, 0).expect("fits");
        assert_eq!(two, Amount::from_atomic(300_000));
    }

    #[test]
    fn ringed_outputs_are_surcharged() {
        let s = FeeSchedule::PROVISIONAL;
        let base_fee = s.minimum_fee(2048, 0).expect("fits");
        let with_ring = s.minimum_fee(2048, 3).expect("fits");
        assert_eq!(
            with_ring
                .checked_sub(base_fee)
                .expect("surcharge is positive"),
            Amount::from_atomic(1_500_000)
        );
    }

    #[test]
    fn overflow_returns_none() {
        let s = FeeSchedule::PROVISIONAL;
        // 2^63 bytes is more than 8 exabibytes: the size part
        // alone overflows u64.
        assert_eq!(s.minimum_fee(usize::MAX / 2, 0), None);
        // A ring count near u64::MAX overflows the ring part.
        assert_eq!(s.minimum_fee(2048, u64::MAX), None);
    }

    #[test]
    fn custom_schedules_compute_the_same_formula() {
        let s = FeeSchedule::new(
            Amount::from_atomic(1),
            Amount::from_atomic(2),
            Amount::from_atomic(3),
        );
        // size 2049 -> 3 kibibytes -> 1 + 6 + 12.
        assert_eq!(
            s.minimum_fee(2049, 4),
            Some(Amount::from_atomic(1 + 3 * 2 + 4 * 3))
        );
    }
}

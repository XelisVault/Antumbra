//! Amounts: unsigned atomic units, eight decimals (ADR-008).
//!
//! One ATU is 100,000,000 atomic units. The full supply leaves a
//! factor of more than eleven thousand of headroom under the u64
//! limit, so checked sums of supply-scale amounts cannot overflow.
//! There is no floating point and no signed amount anywhere in
//! consensus arithmetic.

use core::fmt;

/// Atomic units in one ATU (ADR-008).
pub const ATOMIC_PER_ATU: u64 = 100_000_000;

/// A monetary amount in atomic units.
///
/// The inner value is private so that every construction goes
/// through a checked path: consensus code never wraps an amount.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Amount(u64);

impl Amount {
    /// The zero amount.
    pub const ZERO: Self = Self(0);

    /// One ATU.
    pub const ONE_ATU: Self = Self(ATOMIC_PER_ATU);

    /// The total supply ever: 16,180,339 ATU (ADR-008).
    pub const MAX_SUPPLY: Self = Self(16_180_339 * ATOMIC_PER_ATU);

    /// Builds an amount from atomic units.
    #[must_use]
    pub const fn from_atomic(units: u64) -> Self {
        Self(units)
    }

    /// Builds an amount from whole ATU.
    ///
    /// Returns `None` when the conversion would exceed the u64
    /// range: a consensus caller rejects instead of truncating.
    #[must_use]
    pub const fn from_atu(whole: u64) -> Option<Self> {
        match whole.checked_mul(ATOMIC_PER_ATU) {
            Some(units) => Some(Self(units)),
            None => None,
        }
    }

    /// The amount in atomic units.
    #[must_use]
    pub const fn atomic(&self) -> u64 {
        self.0
    }

    /// Checked addition: `None` on overflow, never a wrap.
    #[must_use]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(units) => Some(Self(units)),
            None => None,
        }
    }

    /// Checked subtraction: `None` on underflow, never a wrap.
    #[must_use]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(units) => Some(Self(units)),
            None => None,
        }
    }

    /// Whether the amount is exactly zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / ATOMIC_PER_ATU;
        let frac = self.0 % ATOMIC_PER_ATU;
        write!(f, "{whole}.{frac:08} ATU")
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Amount({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_atu_is_one_hundred_million_atomic() {
        assert_eq!(Amount::ONE_ATU.atomic(), 100_000_000);
        assert_eq!(Amount::from_atu(1), Some(Amount::ONE_ATU));
        assert_eq!(Amount::ONE_ATU.to_string(), "1.00000000 ATU");
    }

    #[test]
    fn zero_displays_with_eight_decimals() {
        assert_eq!(Amount::ZERO.to_string(), "0.00000000 ATU");
        assert!(Amount::ZERO.is_zero());
    }

    #[test]
    fn fractional_display_is_exact() {
        let a = Amount::from_atomic(12_345_678);
        assert_eq!(a.to_string(), "0.12345678 ATU");
        let b = Amount::from_atomic(16_180_339 * 100_000_000 + 1);
        assert_eq!(b.to_string(), "16180339.00000001 ATU");
    }

    #[test]
    fn max_supply_is_exactly_the_cap() {
        assert_eq!(
            Amount::MAX_SUPPLY,
            Amount::from_atu(16_180_339).expect("fits")
        );
        assert_eq!(Amount::MAX_SUPPLY.atomic(), 1_618_033_900_000_000);
    }

    #[test]
    fn supply_leaves_headroom_for_sums() {
        // ADR-008: more than a factor of eleven thousand under u64.
        assert!(u64::MAX / Amount::MAX_SUPPLY.atomic() > 11_000);
        // Summing thousands of supply-scale amounts cannot overflow.
        let sum = Amount::MAX_SUPPLY
            .checked_add(Amount::MAX_SUPPLY)
            .expect("two supplies fit");
        assert!(sum > Amount::MAX_SUPPLY);
    }

    #[test]
    fn from_atu_rejects_overflow() {
        // Overflow starts above u64::MAX / 10^8 = 184,467,440,737,095,516.
        assert_eq!(Amount::from_atu(u64::MAX), None);
        assert_eq!(Amount::from_atu(200_000_000_000), None);
        assert_eq!(Amount::from_atu(184_467_440_737_095_517), None);
        assert_eq!(
            Amount::from_atu(18_446_744_073),
            Some(Amount::from_atomic(1_844_674_407_300_000_000))
        );
    }

    #[test]
    fn checked_arithmetic_never_wraps() {
        let one = Amount::ONE_ATU;
        assert_eq!(
            one.checked_add(Amount::MAX_SUPPLY),
            Some(Amount::from_atomic(1_618_034_000_000_000))
        );
        assert_eq!(
            Amount::from_atomic(u64::MAX).checked_add(one),
            None,
            "overflow must be None, not a wrap"
        );
        assert_eq!(one.checked_sub(one), Some(Amount::ZERO));
        assert_eq!(Amount::ZERO.checked_sub(one), None);
    }

    #[test]
    fn ordering_follows_atomic_units() {
        assert!(Amount::from_atomic(1) < Amount::ONE_ATU);
        assert!(Amount::ONE_ATU < Amount::MAX_SUPPLY);
        assert_eq!(Amount::from_atomic(42), Amount::from_atomic(42));
    }
}

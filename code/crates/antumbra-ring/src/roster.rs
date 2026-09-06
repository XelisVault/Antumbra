//! The roster of an era: the seat keys (ADR-014).
//!
//! The roster is the scaffold of the finality layer: the
//! weighted draw of ADR-002 (linear in Kleos over the candidacy
//! window) is a later milestone that produces this input. A
//! roster is an era number and at most fifty-five public keys,
//! one per seat, pairwise distinct: the draw is without
//! replacement, so no identity holds two seats.

use antumbra_primitives::PublicKey;

use crate::error::RingError;

/// The seat count of a full Ring (ADR-002: `n = 3f + 1 = 55`).
pub const SEATS: usize = 55;

/// The signature quorum that finalizes (ADR-002: `2f + 1 = 37`
/// of 55, the strict two thirds).
pub const QUORUM: usize = 37;

/// The cadence of checkpoints (ADR-002: every four seconds).
pub const CHECKPOINT_INTERVAL_MS: u64 = 4_000;

/// The seats of one era.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Roster {
    era: u64,
    keys: Vec<PublicKey>,
}

impl Roster {
    /// Builds the roster of an era.
    ///
    /// # Errors
    ///
    /// Returns a [`RingError`] if the era is zero, the roster
    /// exceeds [`SEATS`] seats, or the same key holds two seats.
    pub fn new(era: u64, keys: Vec<PublicKey>) -> Result<Self, RingError> {
        if era == 0 {
            return Err(RingError::EraZero);
        }
        if keys.len() > SEATS {
            return Err(RingError::TooManySeats(keys.len()));
        }
        // The duplicate check is order-free and must not reorder
        // the seats: the key of seat i is the announced one.
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        for pair in sorted.windows(2) {
            if pair[0] == pair[1] {
                return Err(RingError::DuplicateKey);
            }
        }
        Ok(Self { era, keys })
    }

    /// The era this roster governs.
    #[must_use]
    pub const fn era(&self) -> u64 {
        self.era
    }

    /// The number of seats held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the roster is empty. A bootstrap era can be: not
    /// enough identities reach the candidacy threshold yet, and
    /// finality falls back on proof-of-work depth.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The public key of a seat.
    #[must_use]
    pub fn key(&self, seat: u16) -> Option<&PublicKey> {
        self.keys.get(usize::from(seat))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antumbra_primitives::keys::KeyPair;

    fn key(seed: u8) -> PublicKey {
        KeyPair::spend(&[seed; 32]).public()
    }

    #[test]
    fn a_roster_holds_its_seats_in_order() {
        let keys: Vec<PublicKey> = (1..=55u8).map(key).collect();
        let roster = Roster::new(7, keys.clone()).expect("a full roster builds");
        assert_eq!(roster.era(), 7);
        assert_eq!(roster.len(), SEATS);
        assert_eq!(roster.key(0), Some(&keys[0]));
        assert_eq!(roster.key(54), Some(&keys[54]));
        assert_eq!(roster.key(55), None);
    }

    #[test]
    fn a_zero_era_is_rejected() {
        assert_eq!(Roster::new(0, vec![key(1)]), Err(RingError::EraZero));
    }

    #[test]
    fn a_oversized_roster_is_rejected() {
        let keys: Vec<PublicKey> = (1..=56u8).map(key).collect();
        let expected = RingError::TooManySeats(56);
        assert_eq!(Roster::new(1, keys), Err(expected));
    }

    #[test]
    fn a_duplicate_key_is_rejected() {
        let keys = vec![key(1), key(2), key(1)];
        assert_eq!(Roster::new(1, keys), Err(RingError::DuplicateKey));
    }

    #[test]
    fn a_bootstrap_roster_is_smaller_than_the_quorum() {
        let roster = Roster::new(1, vec![key(1), key(2)]).expect("a bootstrap roster builds");
        assert_eq!(roster.len(), 2);
        assert!(roster.len() < QUORUM);
    }
}

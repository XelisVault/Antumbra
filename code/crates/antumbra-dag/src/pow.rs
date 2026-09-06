//! The proof of work of the development network: the scaffold
//! (ADR-013).
//!
//! On the devnet the work function is Keccak-256 itself: a block
//! carries the required work when its id has at least `d` leading
//! zero bits. Mainnet replaces the function by RandomX over the
//! same canonical header bytes and checks the same difficulty
//! semantics on the RandomX output; the container does not move.
//! The difficulty is a policy parameter (consensus state), not a
//! header field, until an ADR says otherwise.
//!
//! The mining helper walks the nonce from zero: deterministic, so
//! that the cross vector set can archive the exact nonce an
//! independent implementation finds.

use antumbra_primitives::Hash;

use crate::header::Header;

/// Counts the leading zero bits of a digest, most significant bit
/// of the first byte first. An all-zero digest counts 256.
#[must_use]
pub fn leading_zero_bits(hash: &Hash) -> u32 {
    for (index, byte) in hash.as_bytes().iter().enumerate() {
        if *byte != 0 {
            return (index as u32) * 8 + byte.leading_zeros();
        }
    }
    256
}

/// Whether a digest carries at least the required leading zero
/// bits.
#[must_use]
pub fn meets_difficulty(id: &Hash, bits: u32) -> bool {
    leading_zero_bits(id) >= bits
}

/// Walks the nonce from zero until the header id carries the
/// required work, at most `max_attempts` tries.
///
/// The input header supplies every field but the nonce; the
/// returned header, if any, is the first one whose id meets the
/// difficulty, with the nonce that achieved it. Deterministic:
/// the same input yields the same output on every machine, which
/// is what the cross vector set archives.
#[must_use]
pub fn mine(header: &Header, bits: u32, max_attempts: u64) -> Option<Header> {
    for nonce in 0..max_attempts {
        let candidate = Header::new(
            header.parents().to_vec(),
            header.height(),
            header.timestamp(),
            nonce,
            header.payload_root(),
        );
        if meets_difficulty(&candidate.id(), bits) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_all_zero_hash_counts_two_hundred_fifty_six_bits() {
        assert_eq!(leading_zero_bits(&Hash::ZERO), 256);
        assert!(meets_difficulty(&Hash::ZERO, 256));
    }

    #[test]
    fn the_bit_count_is_exact() {
        let mut bytes = [0xffu8; 32];
        assert_eq!(leading_zero_bits(&Hash(bytes)), 0);
        bytes[0] = 0x0f;
        assert_eq!(leading_zero_bits(&Hash(bytes)), 4);
        bytes[0] = 0;
        bytes[1] = 0x01;
        assert_eq!(leading_zero_bits(&Hash(bytes)), 15);
        assert!(meets_difficulty(&Hash(bytes), 15));
        assert!(!meets_difficulty(&Hash(bytes), 16));
    }

    #[test]
    fn mining_finds_a_header_that_meets_the_difficulty() {
        let parents = vec![Hash([7u8; 32])];
        let target = Header::new(parents, 1, 1_750_000_000_000, 0, Hash([9u8; 32]));
        let mined = mine(&target, 16, 1_000_000).expect("sixteen bits are found fast");
        assert!(meets_difficulty(&mined.id(), 16));
        assert_eq!(mined.height(), 1);
        assert_eq!(mined.timestamp(), 1_750_000_000_000);
        assert_eq!(mined.payload_root(), Hash([9u8; 32]));
    }

    #[test]
    fn a_bound_of_zero_attempts_mines_nothing() {
        let target = Header::new(vec![Hash::ZERO], 0, 1, 0, Hash::ZERO);
        assert!(mine(&target, 0, 0).is_none());
    }
}

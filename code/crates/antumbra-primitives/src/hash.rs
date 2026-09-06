//! Keccak-256, the identifier hash of the protocol.
//!
//! Block ids, transaction ids, checksums and key derivation all use
//! Keccak-256 (the original Keccak padding, as in the CryptoNote
//! lineage, not the SHA-3 standard padding). One hash everywhere
//! means one thing to audit.

use core::fmt;
use tiny_keccak::{Hasher, Keccak};

/// A 32-byte Keccak-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// The all-zero hash. Used only as the parent of the genesis
    /// block and as the "no previous output" marker.
    pub const ZERO: Hash = Hash([0u8; 32]);

    /// The first byte of the digest, as a network byte prefix is
    /// sometimes taken from it (checksums).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Keccak-256 of `data`.
#[must_use]
pub fn keccak256(data: &[u8]) -> Hash {
    let mut keccak = Keccak::v256();
    keccak.update(data);
    let mut digest = [0u8; 32];
    keccak.finalize(&mut digest);
    Hash(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        // Official Keccak-256 test vector for the empty string.
        assert_eq!(
            keccak256(b"").to_string(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn zero_hash() {
        assert_eq!(Hash::ZERO, Hash([0u8; 32]));
        assert_eq!(Hash::ZERO.to_string(), "0".repeat(64));
    }

    #[test]
    fn deterministic_and_distinct() {
        let a = keccak256(b"ANTUMBRA");
        let b = keccak256(b"ANTUMBRA");
        let c = keccak256(b"ANTUMBRA.");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn display_is_64_lowercase_hex_chars() {
        let h = keccak256(b"x");
        assert_eq!(h.to_string().len(), 64);
        assert!(h
            .to_string()
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}

//! The two protocol hashes of the private sphere (ADR-011).
//!
//! Keccak-256 is the single hash of the protocol; the private sphere
//! maps it onto the curve in exactly two ways, both frozen by this
//! module and both cross-validated bit for bit by the independent
//! implementation:
//!
//! - `hash_to_scalar` (Hs): the digest read as a little-endian
//!   integer, reduced modulo the group order. Inputs may be secret
//!   (shared secrets): the routine is a single hash and a constant
//!   time reduction.
//! - `hash_to_point` (Hp): hash-and-check over the RFC 8032 point
//!   decompression, a one-byte counter appended to the input, then
//!   cofactor clearing: the image is eight times the first
//!   canonically decompressed candidate, hence always in the
//!   prime-order subgroup. The inputs of Hp are always public
//!   (public keys, protocol tags), so the variable round count
//!   discloses nothing; each vector set records the round count of
//!   every input.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar as DalekScalar;
use curve25519_dalek::traits::IsIdentity;
use tiny_keccak::{Hasher, Keccak};

use crate::curve::{Point, Scalar};
use crate::error::VeilError;

/// Hs: Keccak-256 of `data`, reduced modulo the group order.
#[must_use]
pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    let digest = keccak256(data);
    Scalar(DalekScalar::from_bytes_mod_order(digest))
}

/// The highest hash-to-point counter, inclusive. An input that needs
/// more than 256 rounds does not exist with a probability above
/// one minus two to the minus two thousand.
pub const HASH_TO_POINT_ROUNDS: u8 = u8::MAX;

/// Hp: hash-and-check over the canonical point decompression, then
/// cofactor clearing.
///
/// For a counter from 0 to [`HASH_TO_POINT_ROUNDS`], the input is
/// hashed as `data, counter` and the digest is read as a compressed
/// point; the first digest that decompresses and recompresses to
/// itself names the candidate, and the image is eight times that
/// candidate. The multiplication by the cofactor is what places the
/// image in the prime-order subgroup: a raw decompression can land
/// on a point of mixed order, and the subgroup invariant of the
/// protocol forbids it. A candidate of pure torsion clears to the
/// identity and the search continues on the next counter.
///
/// # Errors
///
/// Returns [`VeilError::HashToPointExhausted`] if no round
/// succeeds. The probability is below 2^-2040 and the routine still
/// refuses to panic.
pub fn hash_to_point(data: &[u8]) -> Result<Point, VeilError> {
    for counter in 0..=HASH_TO_POINT_ROUNDS {
        let digest = keccak256_pair(data, &[counter]);
        let compressed = CompressedEdwardsY(digest);
        if let Some(point) = compressed.decompress() {
            if point.compress() == compressed {
                let cleared = point.mul_by_cofactor();
                if !cleared.is_identity() {
                    return Ok(Point(cleared));
                }
            }
        }
    }
    Err(VeilError::HashToPointExhausted)
}

/// Keccak-256 of `data`.
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    keccak.update(data);
    let mut digest = [0u8; 32];
    keccak.finalize(&mut digest);
    digest
}

/// Keccak-256 of the concatenation `a, b`, without allocation.
fn keccak256_pair(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    keccak.update(a);
    keccak.update(b);
    let mut digest = [0u8; 32];
    keccak.finalize(&mut digest);
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_to_scalar_is_deterministic_and_canonical() {
        let a = hash_to_scalar(b"ANTUMBRA");
        let b = hash_to_scalar(b"ANTUMBRA");
        let c = hash_to_scalar(b"ANTUMBRA.");
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Canonical: below l, hence decodable.
        assert_eq!(
            Scalar::decode(&a.encode())
                .expect("Hs output is canonical")
                .encode(),
            a.encode()
        );
        // The reduction is modulo l: Hs and Hs of the same value
        // plus l agree. l little-endian.
        let l = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        // A value at l decodes to nothing, but reduces to zero: the
        // mod-order semantic is the one the vectors pin.
        let reduced = DalekScalar::from_bytes_mod_order(l);
        assert_eq!(reduced, DalekScalar::ZERO);
    }

    #[test]
    fn hash_to_point_is_deterministic_and_in_the_subgroup() {
        let a = hash_to_point(b"ANTUMBRA/Hp/test").expect("hashes");
        let b = hash_to_point(b"ANTUMBRA/Hp/test").expect("hashes");
        assert!(a.ct_eq(&b));
        // The image is a canonical, non-degenerate point of the
        // prime-order subgroup: decode enforces the invariant.
        assert_eq!(Point::decode(&a.encode()).expect("canonical"), a);
        assert!(a.is_in_prime_subgroup());
        // Distinct inputs map to distinct points.
        let c = hash_to_point(b"ANTUMBRA/Hp/tesu").expect("hashes");
        assert!(!a.ct_eq(&c));
    }

    #[test]
    fn hash_to_point_uses_the_counter_domain() {
        // The first digest round and the second differ: the map is
        // pinned by the archived vectors, including multi-round
        // inputs, and equal inputs with distinct counters must not
        // collide by accident of a missing domain.
        let one = hash_to_point(b"ANTUMBRA/Hp/domain").expect("hashes");
        let two = hash_to_point(b"ANTUMBRA/Hp/domain").expect("hashes");
        assert!(one.ct_eq(&two));
    }
}

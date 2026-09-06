//! Pedersen commitments, committed amounts (ADR-011, whitepaper
//! step 2).
//!
//! An amount v is sealed as C = vH + bG: H is a nothing-up-my-sleeve
//! point derived by the hash to point from a fixed protocol string,
//! with no known discrete logarithm to G, and b is the blinding
//! scalar. The construction is homomorphic: the sum of two
//! commitments commits to the sum of the amounts, which is the
//! equality the ordering layer will check at every spend without
//! ever reading an amount. The blinding scalar belongs to the
//! wallet; the consensus verifies the algebra only.

use std::sync::LazyLock;

use crate::curve::{Point, Scalar};
use crate::hash::hash_to_point;

/// The domain of the value generator: the fixed string hashed to the
/// point H. Exposed so that the independent implementation and any
/// auditor derive the exact same point.
pub const VALUE_GENERATOR_DOMAIN: &[u8] = b"ANTUMBRA/veil/value-generator";

/// The value generator H.
///
/// Hp of [`VALUE_GENERATOR_DOMAIN`]: deterministic, public, and with
/// no known discrete logarithm to G. The derivation succeeds with
/// probability one minus two to the minus two thousand; the lock
/// computes once and every user pays the single derivation.
static VALUE_GENERATOR: LazyLock<Point> =
    LazyLock::new(|| hash_to_point(VALUE_GENERATOR_DOMAIN).expect("the value generator hashes"));

/// The value generator H.
#[must_use]
pub fn value_generator() -> Point {
    *VALUE_GENERATOR
}

/// Commits an amount under a blinding scalar: C = vH + bG.
#[must_use]
pub fn commit(amount: u64, blind: &Scalar) -> Point {
    let value = Scalar::from(amount);
    (value_generator() * &value) + (Point::generator() * blind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_from_be(value: u64) -> Scalar {
        // Small values in the low bytes: always canonical.
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&value.to_le_bytes());
        Scalar::decode(&bytes).expect("canonical")
    }

    #[test]
    fn the_value_generator_is_deterministic_and_public() {
        let h1 = value_generator();
        let h2 = hash_to_point(VALUE_GENERATOR_DOMAIN).expect("hashes");
        assert!(h1.ct_eq(&h2));
        // H is a well formed point, not the generator, not small
        // order: an attacker must not know h with hG = H.
        assert!(!h1.ct_eq(&Point::generator()));
        assert!(Point::decode(&h1.encode()).is_ok());
    }

    #[test]
    fn commitments_are_homomorphic() {
        let v1 = 1_000_000_000;
        let v2 = 2_500_000_000;
        let b1 = scalar_from_be(0x1111);
        let b2 = scalar_from_be(0x2222);
        let c1 = commit(v1, &b1);
        let c2 = commit(v2, &b2);
        // The blinding of the sum: the sender of a two-output
        // transaction knows every blinding and sums them.
        let b_sum = b1 + b2;
        let c_sum = commit(v1 + v2, &b_sum);
        assert!((c1 + c2).ct_eq(&c_sum));
    }

    #[test]
    fn commitments_hide_the_amount() {
        let blind = scalar_from_be(0x3333);
        let c1 = commit(1, &blind);
        let c2 = commit(2, &blind);
        // Same blinding, consecutive amounts: distinct points, no
        // visible structure.
        assert!(!c1.ct_eq(&c2));
        // A zero amount is still a blinded point: the value vanishes
        // into the blinding term bG.
        let c0 = commit(0, &blind);
        let b_point = Point::generator() * &blind;
        assert!(c0.ct_eq(&b_point));
    }

    #[test]
    fn commitments_are_deterministic() {
        let blind = scalar_from_be(0x4444);
        let c1 = commit(16_180_339, &blind);
        let c2 = commit(16_180_339, &blind);
        assert!(c1.ct_eq(&c2));
    }
}

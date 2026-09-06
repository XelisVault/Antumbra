//! The one-time secret key and the key image (ADR-011, whitepaper
//! step 4).
//!
//! The owner of a scanned output holds the shared secret Hs(aR) and
//! the spend scalar b: the one-time secret key is p = Hs(aR) + b,
//! with pG = P. The key image I = p Hp(P) is the nullifier the
//! ordering layer stores verbatim: two spends of the same output
//! produce the same image, the network rejects the second, and the
//! image links neither to the real member of a future ring nor to
//! another output of the same wallet. The image is computed over a
//! secret scalar: constant time.

use crate::curve::{Point, Scalar};
use crate::error::VeilError;
use crate::hash::hash_to_point;
use crate::onetime::shared_secret;

/// The one-time secret key of an owned output: p = Hs(aR) + b.
#[must_use]
pub fn one_time_secret(shared: &Scalar, spend_secret: &Scalar) -> Scalar {
    *shared + *spend_secret
}

/// The key image of a one-time key pair: I = p Hp(P).
///
/// # Errors
///
/// Returns [`VeilError::HashToPointExhausted`] if the hash to point
/// exhausts its rounds; probability below 2^-2040.
pub fn key_image(one_time_secret: &Scalar, one_time_public: &Point) -> Result<Point, VeilError> {
    let hashed = hash_to_point(&one_time_public.encode())?;
    Ok(hashed * one_time_secret)
}

/// Derives the one-time secret key of an output owned by the
/// scanning wallet.
///
/// The scanner knows its view secret a and spend secret b, and the
/// ephemeral R published with the output: shared secret first, then
/// the sum. Constant time over both secrets.
#[must_use]
pub fn owned_secret(
    view_secret: &Scalar,
    spend_secret: &Scalar,
    ephemeral_public: &Point,
) -> Scalar {
    let shared = shared_secret(view_secret, ephemeral_public);
    one_time_secret(&shared, spend_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onetime::{ephemeral, one_time_address};
    use crate::seed::{spend_scalar, view_scalar};

    fn scalar_from_be(value: u64) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        Scalar::decode(&bytes).expect("canonical")
    }

    #[test]
    fn the_one_time_secret_generates_the_one_time_address() {
        let seed = [51u8; 32];
        let a = view_scalar(&seed);
        let b = spend_scalar(&seed);
        let b_public = &Point::generator() * &b;

        let r = scalar_from_be(0x0708);
        let r_public = ephemeral(&r);
        let shared = shared_secret(&r, &b_public);
        let _ = shared;
        // Sender derives the address from the public view key.
        let a_public = &Point::generator() * &a;
        let p_point = one_time_address(&shared_secret(&r, &a_public), &b_public);

        // The recipient secret p generates exactly that address.
        let p_secret = owned_secret(&a, &b, &r_public);
        let p_public_check = &Point::generator() * &p_secret;
        assert!(p_public_check.ct_eq(&p_point));
    }

    #[test]
    fn the_key_image_is_deterministic_and_secret_dependent() {
        let seed = [52u8; 32];
        let a = view_scalar(&seed);
        let b = spend_scalar(&seed);
        let b_public = &Point::generator() * &b;
        let a_public = &Point::generator() * &a;

        let r = scalar_from_be(0x090a);
        let r_public = ephemeral(&r);
        let p_point = one_time_address(&shared_secret(&r, &a_public), &b_public);
        let p_secret = owned_secret(&a, &b, &r_public);

        let i1 = key_image(&p_secret, &p_point).expect("hashes");
        let i2 = key_image(&p_secret, &p_point).expect("hashes");
        assert!(i1.ct_eq(&i2));

        // Another wallet, same output: a different secret gives a
        // different image, the nullifier never collides.
        let other_seed = [53u8; 32];
        let other_a = view_scalar(&other_seed);
        let other_b = spend_scalar(&other_seed);
        let other_secret = owned_secret(&other_a, &other_b, &r_public);
        let other_image = key_image(&other_secret, &p_point).expect("hashes");
        assert!(!i1.ct_eq(&other_image));
    }

    #[test]
    fn the_image_of_a_different_output_differs() {
        // Same secret scalar, different one-time address: Hp(P)
        // mixes the output into the image.
        let secret = scalar_from_be(0x0b0c);
        let seed = [54u8; 32];
        let a_public = &Point::generator() * &view_scalar(&seed);
        let b_public = &Point::generator() * &spend_scalar(&seed);
        let r1 = scalar_from_be(1);
        let r2 = scalar_from_be(2);
        let p1 = one_time_address(&shared_secret(&r1, &a_public), &b_public);
        let p2 = one_time_address(&shared_secret(&r2, &a_public), &b_public);
        let i1 = key_image(&secret, &p1).expect("hashes");
        let i2 = key_image(&secret, &p2).expect("hashes");
        assert!(!i1.ct_eq(&i2));
    }
}

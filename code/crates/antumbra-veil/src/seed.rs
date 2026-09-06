//! Wallet seeds to Veil scalars (ADR-011).
//!
//! A payment identity publishes two Ed25519 keys: the spending key B
//! and the viewing key A, both carried by the address of the
//! primitives crate. The private sphere needs the scalars behind
//! them: b with bG = B for the one-time secret key, a with aG = A
//! for scanning. Both are the RFC 8032 secret scalars of the
//! respective seeds (SHA-512, first half, clamped), reduced to their
//! canonical residue modulo the group order. The reduction changes
//! no public key: clamped and reduced differ by a multiple of the
//! order and the base point has order l. The vector set proves the
//! equality on both sides, Rust and Python.

use curve25519_dalek::scalar::Scalar as DalekScalar;
use sha2::{Digest, Sha512};

use crate::curve::{Point, Scalar};

/// The clamped first half of the SHA-512 of `seed`, as 32 raw bytes.
///
/// This is the RFC 8032 secret scalar before reduction: the value
/// exceeds the group order, and every routine of this crate uses its
/// canonical residue instead.
#[must_use]
pub fn rfc8032_clamped_bytes(seed: &[u8; 32]) -> [u8; 32] {
    let digest = Sha512::digest(seed);
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(&digest[0..32]);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    clamped
}

/// The reduced RFC 8032 secret scalar of `seed`.
///
/// The reduction is the plain modulo l of the group: no hash, no
/// domain, the residue of the clamped value itself.
#[must_use]
pub fn clamped_scalar(seed: &[u8; 32]) -> Scalar {
    Scalar(DalekScalar::from_bytes_mod_order(rfc8032_clamped_bytes(
        seed,
    )))
}

/// The spend scalar of a wallet seed: b with bG equal to the spend
/// public key of the primitives crate.
#[must_use]
pub fn spend_scalar(seed: &[u8; 32]) -> Scalar {
    clamped_scalar(seed)
}

/// The view scalar of a wallet seed: a with aG equal to the view
/// public key, itself the Ed25519 key of the Keccak-256 view seed.
#[must_use]
pub fn view_scalar(seed: &[u8; 32]) -> Scalar {
    let view_seed = antumbra_primitives::keys::SecretKey::derive_view_seed(seed);
    clamped_scalar(&view_seed.0)
}

/// The public key of a scalar, for the bridge checks.
#[must_use]
pub fn public_of(scalar: &Scalar) -> Point {
    Point::generator() * scalar
}

#[cfg(test)]
mod tests {
    use antumbra_primitives::keys::KeyPair;

    use super::*;

    const RFC8032_T1_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_T1_PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    #[test]
    fn the_clamped_bytes_match_rfc8032() {
        // The clamping is the RFC 8032 one: low three bits cleared,
        // bit 254 set, bit 255 cleared.
        let clamped = rfc8032_clamped_bytes(&RFC8032_T1_SEED);
        assert_eq!(clamped[0] & 7, 0);
        assert_eq!(clamped[31] & 0x80, 0);
        assert_eq!(clamped[31] & 0x40, 0x40);
    }

    #[test]
    fn the_spend_scalar_public_is_the_ed25519_public_key() {
        // The bridge to the transparent sphere: the scalar of the
        // Veil is the scalar of the published key.
        let scalar = spend_scalar(&RFC8032_T1_SEED);
        let public = public_of(&scalar);
        assert_eq!(public.encode(), RFC8032_T1_PUBLIC);
        let keypair = KeyPair::spend(&RFC8032_T1_SEED);
        assert_eq!(public.encode(), keypair.public().0);
    }

    #[test]
    fn the_view_scalar_public_is_the_view_public_key() {
        let seed = [13u8; 32];
        let scalar = view_scalar(&seed);
        let public = public_of(&scalar);
        let keypair = KeyPair::view(&seed);
        assert_eq!(public.encode(), keypair.public().0);
    }

    #[test]
    fn the_reduction_changes_no_public_key() {
        // The clamped value exceeds the order and is not a canonical
        // scalar encoding; its residue is. Both generate the same
        // published key: the residue here, the raw value inside
        // Ed25519, and the archived vectors recompute the equality
        // from the specification on the Python side.
        let seed = [21u8; 32];
        let clamped = rfc8032_clamped_bytes(&seed);
        let scalar = clamped_scalar(&seed);
        assert!(Scalar::decode(&clamped).is_err());
        assert!(Scalar::decode(&scalar.encode()).is_ok());
        let keypair = KeyPair::spend(&seed);
        assert_eq!(public_of(&scalar).encode(), keypair.public().0);
    }
}

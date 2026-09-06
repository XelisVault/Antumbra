//! The MLSAG linkable ring signature (ADR-012, whitepaper steps 3
//! and 4).
//!
//! A spend hides its real one-time key inside a ring of candidate
//! keys: the signature proves knowledge of the secret behind one
//! member without saying which, and the key image links two spends
//! of the same output while linking nothing else. The construction
//! is the CryptoNote lineage MLSAG over the Veil core: the challenge
//! chain walks the ring once, the real index closes it, and the
//! verifier recomputes everything.
//!
//! The crate is RNG-free: the nonces derive deterministically from a
//! wallet-supplied 32-byte seed. The wallet must supply a fresh
//! uniformly random seed per signature; the derivation and the
//! reuse hazard are specified in ADR-012.

use antumbra_primitives::{Reader, Writer};

use crate::curve::{Point, Scalar};
use crate::error::VeilError;
use crate::hash::{hash_to_point, hash_to_scalar_parts};
use crate::keyimage::key_image;

/// The fixed domain tag of the challenge hash: one use of Hs, never
/// shared with another construction.
pub const MLSAG_DOMAIN: &[u8] = b"ANTUMBRA/veil/mlsag";

/// The smallest accepted ring: the real key and one decoy.
pub const MIN_RING_SIZE: usize = 2;

/// The largest accepted ring of the primitive. The version 2
/// transaction layer pins the protocol ring at sixteen; the bound
/// here only guards the decoder against oversized counts.
pub const MAX_RING_SIZE: usize = 1024;

/// An MLSAG signature over one ring of one-time public keys.
///
/// The image is the nullifier of the spent output; the first
/// challenge and the member scalars are the signature proper. The
/// ring itself is not carried: the verifier supplies it, and the
/// member count of the encoding must match it exactly.
#[derive(Clone, PartialEq, Eq)]
pub struct RingSignature {
    image: Point,
    first_challenge: Scalar,
    members: Vec<Scalar>,
}

impl core::fmt::Debug for RingSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Every field of a signature is public on-chain data: the
        // image, the first challenge and the member count print, the
        // member scalars summarize.
        let challenge: String = self
            .first_challenge
            .encode()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        write!(
            f,
            "RingSignature(image: {}, first_challenge: {challenge}, members: {})",
            self.image,
            self.members.len()
        )
    }
}

impl RingSignature {
    /// The key image: the nullifier the ordering layer stores.
    #[must_use]
    pub fn image(&self) -> &Point {
        &self.image
    }

    /// The first challenge of the chain.
    #[must_use]
    pub fn first_challenge(&self) -> &Scalar {
        &self.first_challenge
    }

    /// The member scalars, one per ring member.
    #[must_use]
    pub fn members(&self) -> &[Scalar] {
        &self.members
    }

    /// The canonical encoding: image, first challenge, member count
    /// varint, then every member scalar (ADR-012, rule 5).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_array(&self.image.encode());
        writer.write_array(&self.first_challenge.encode());
        writer.write_varint(self.members.len() as u64);
        for member in &self.members {
            writer.write_array(&member.encode());
        }
        writer.finish()
    }

    /// Strict decoding: canonical image, canonical challenge, the
    /// member count in [MIN_RING_SIZE, MAX_RING_SIZE], canonical
    /// scalars, and no trailing bytes.
    ///
    /// # Errors
    ///
    /// Wraps the primitives decode error for the structure, returns
    /// [`VeilError::NonCanonicalPoint`] for a malformed image,
    /// [`VeilError::NonCanonicalScalar`] for a malformed scalar, and
    /// [`VeilError::RingSize`] for a count outside the accepted
    /// bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, VeilError> {
        let mut reader = Reader::new(bytes);
        let image = Point::decode(&reader.read_array::<32>()?)
            .map_err(|_| VeilError::NonCanonicalPoint(bytes[..32].try_into().unwrap_or([0; 32])))?;
        let first_challenge = Scalar::decode(&reader.read_array::<32>()?)?;
        let count = reader.read_varint()?;
        if count < MIN_RING_SIZE as u64 || count > MAX_RING_SIZE as u64 {
            return Err(VeilError::RingSize(count));
        }
        let mut members = Vec::with_capacity(count as usize);
        for _ in 0..count {
            members.push(Scalar::decode(&reader.read_array::<32>()?)?);
        }
        reader.finish()?;
        Ok(Self {
            image,
            first_challenge,
            members,
        })
    }
}

/// Signs a message over a ring, hiding the real member (ADR-012,
/// rule 3).
///
/// `real_index` is the position of the owned key in `ring`;
/// `secret` is the one-time secret p with pG = P_real; `nonce_seed`
/// is fresh wallet entropy for this signature alone (rule 4: a
/// reused seed across two signatures of the same secret leaks the
/// secret exactly as a reused Schnorr nonce does).
///
/// # Errors
///
/// Returns [`VeilError::RingSize`] when the ring is outside the
/// accepted bounds, [`VeilError::DuplicateMember`] when two members
/// are the same key, [`VeilError::Index`] when the real index is
/// outside the ring, and the key image errors of the Veil core.
pub fn sign(
    message: &[u8],
    ring: &[Point],
    real_index: usize,
    secret: &Scalar,
    nonce_seed: &[u8; 32],
) -> Result<RingSignature, VeilError> {
    check_ring(ring)?;
    if real_index >= ring.len() {
        return Err(VeilError::Index {
            index: real_index,
            len: ring.len(),
        });
    }
    let n = ring.len();

    // The key image of the real output.
    let image = key_image(secret, &ring[real_index])?;

    // The nonce and the decoy scalars, derived from the wallet seed.
    let alpha = derive_nonce(nonce_seed, 0x00, real_index);

    // The chain starts right after the real member.
    let mut challenges = vec![Scalar::ZERO; n];
    let mut members = vec![Scalar::ZERO; n];
    let real_hashed = hash_to_point(&ring[real_index].encode())?;
    let mut next = (real_index + 1) % n;
    challenges[next] = challenge(
        message,
        &(Point::generator() * &alpha),
        &(real_hashed * &alpha),
    );
    while next != real_index {
        let s = derive_nonce(nonce_seed, 0x01, next);
        let c = challenges[next];
        let left = (Point::generator() * &s) + (&ring[next] * &c);
        let hashed = hash_to_point(&ring[next].encode())?;
        let right = (hashed * &s) + (&image * &c);
        members[next] = s;
        let following = (next + 1) % n;
        challenges[following] = challenge(message, &left, &right);
        next = following;
    }

    // The ring closes on the real member: s = alpha - c p.
    let c_real = challenges[real_index];
    let negated_secret = -*secret;
    members[real_index] = alpha + c_real * negated_secret;

    Ok(RingSignature {
        image,
        first_challenge: challenges[0],
        members,
    })
}

/// Verifies a signature over the supplied ring and message
/// (ADR-012, rule 6).
///
/// The member count of the signature must equal the ring size, the
/// ring must satisfy the structural rules, and the recomputed chain
/// must close: c_n = c_0.
#[must_use]
pub fn verify(message: &[u8], ring: &[Point], signature: &RingSignature) -> bool {
    if check_ring(ring).is_err() {
        return false;
    }
    if signature.members.len() != ring.len() {
        return false;
    }
    let mut c = signature.first_challenge;
    for (i, member) in signature.members.iter().enumerate() {
        let Ok(hashed) = hash_to_point(&ring[i].encode()) else {
            return false;
        };
        let left = (Point::generator() * member) + (&ring[i] * &c);
        let right = (hashed * member) + (signature.image * &c);
        c = challenge(message, &left, &right);
    }
    c.ct_eq(&signature.first_challenge)
}

/// The challenge of one ring step: Hs of the domain tag, the
/// message, and the two step points.
fn challenge(message: &[u8], left: &Point, right: &Point) -> Scalar {
    hash_to_scalar_parts(&[MLSAG_DOMAIN, message, &left.encode(), &right.encode()])
}

/// A nonce derived from the wallet seed: Hs(seed, label, index),
/// the index in four little-endian bytes.
fn derive_nonce(seed: &[u8; 32], label: u8, index: usize) -> Scalar {
    let index_bytes = (index as u32).to_le_bytes();
    hash_to_scalar_parts(&[seed, &[label], &index_bytes])
}

/// The structural ring rules: size in bounds, strictly distinct
/// members (a duplicate collapses the anonymity set, and no encoder
/// ever produces one).
fn check_ring(ring: &[Point]) -> Result<(), VeilError> {
    if ring.len() < MIN_RING_SIZE || ring.len() > MAX_RING_SIZE {
        return Err(VeilError::RingSize(ring.len() as u64));
    }
    let mut encodings: Vec<[u8; 32]> = ring.iter().map(|p| p.encode()).collect();
    encodings.sort_unstable();
    if encodings.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(VeilError::DuplicateMember);
    }
    Ok(())
}

#[cfg(test)]
impl RingSignature {
    /// Test-only mutator for tamper cases.
    fn members_mut(&mut self) -> &mut [Scalar] {
        &mut self.members
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onetime::{ephemeral, one_time_address, shared_secret};
    use crate::seed::{spend_scalar, view_scalar};

    /// Builds a ring of one-time addresses and the secret of the
    /// real member: the wallet of `seed` owns the output at
    /// `real_index`, the other members are decoys.
    fn build_ring(seed: &[u8; 32], size: usize, real_index: usize) -> (Vec<Point>, Scalar) {
        let a = view_scalar(seed);
        let b = spend_scalar(seed);
        let a_public = Point::generator() * &a;
        let b_public = Point::generator() * &b;
        let mut ring = Vec::with_capacity(size);
        let mut real_secret = Scalar::ZERO;
        for i in 0..size {
            if i == real_index {
                // A one-time output of the wallet of `seed`.
                let mut r_bytes = [0u8; 32];
                r_bytes[0] = (i + 1) as u8;
                let r = Scalar::decode(&r_bytes).expect("canonical");
                let shared = shared_secret(&r, &a_public);
                let destination = one_time_address(&shared, &b_public);
                real_secret = crate::keyimage::owned_secret(&a, &b, &ephemeral(&r));
                ring.push(destination);
            } else {
                // A decoy: a valid point of another wallet.
                let mut decoy_seed = *seed;
                decoy_seed[0] ^= i as u8;
                ring.push(Point::generator() * &spend_scalar(&decoy_seed));
            }
        }
        (ring, real_secret)
    }

    #[test]
    fn sign_and_verify_round_trip() {
        for (size, index) in [(2, 0), (2, 1), (3, 1), (16, 7), (32, 31)] {
            let seed = [77u8; 32];
            let (ring, secret) = build_ring(&seed, size, index);
            let mut nonce = [0u8; 32];
            nonce[0] = size as u8;
            nonce[1] = index as u8;
            let signature = sign(b"payment", &ring, index, &secret, &nonce)
                .unwrap_or_else(|e| panic!("signs: {e}"));
            assert!(verify(b"payment", &ring, &signature), "size {size}");
            assert_eq!(signature.members().len(), size);
        }
    }

    #[test]
    fn the_image_is_the_key_image_of_the_real_output() {
        let seed = [78u8; 32];
        let (ring, secret) = build_ring(&seed, 16, 5);
        let signature = sign(b"payment", &ring, 5, &secret, &[1u8; 32]).expect("signs");
        let expected = key_image(&secret, &ring[5]).expect("hashes");
        assert!(signature.image().ct_eq(&expected));
    }

    #[test]
    fn linkability_the_same_secret_gives_the_same_image() {
        // The same output spent in two different rings: the
        // nullifier is identical, everything else differs.
        let seed = [79u8; 32];
        let (ring_a, secret) = build_ring(&seed, 16, 3);
        let (mut ring_b, _) = build_ring(&[80u8; 32], 16, 9);
        // The same real output at another position.
        ring_b[9] = ring_a[3];
        let signature_a = sign(b"first", &ring_a, 3, &secret, &[2u8; 32]).expect("signs");
        let signature_b = sign(b"second", &ring_b, 9, &secret, &[3u8; 32]).expect("signs");
        assert!(signature_a.image().ct_eq(signature_b.image()));
        assert!(!signature_a
            .first_challenge()
            .ct_eq(signature_b.first_challenge()));
        // Both verify over their respective rings.
        assert!(verify(b"first", &ring_a, &signature_a));
        assert!(verify(b"second", &ring_b, &signature_b));
        // A cross verification fails: the messages differ.
        assert!(!verify(b"second", &ring_a, &signature_a));
    }

    #[test]
    fn tampering_breaks_verification() {
        let seed = [81u8; 32];
        let (ring, secret) = build_ring(&seed, 16, 4);
        let signature = sign(b"payment", &ring, 4, &secret, &[4u8; 32]).expect("signs");

        // A tampered message.
        assert!(!verify(b"paymenf", &ring, &signature));

        // A tampered member scalar.
        let mut tampered = signature.clone();
        tampered.members_mut()[0] = tampered.members()[0] + Scalar::from(1u64);
        assert!(!verify(b"payment", &ring, &tampered));

        // A truncated ring: the count no longer matches.
        let short_ring = &ring[..15];
        assert!(!verify(b"payment", short_ring, &signature));

        // A reordered ring: the chain is bound to the member order.
        let mut reordered = ring.clone();
        reordered.swap(0, 1);
        assert!(!verify(b"payment", &reordered, &signature));
    }

    #[test]
    fn a_ring_of_duplicates_is_refused() {
        let seed = [82u8; 32];
        let (mut ring, secret) = build_ring(&seed, 4, 0);
        ring[1] = ring[2];
        assert_eq!(
            sign(b"payment", &ring, 0, &secret, &[5u8; 32]).unwrap_err(),
            VeilError::DuplicateMember
        );
        // The verifier refuses it too: structural rules are shared.
        let (clean_ring, clean_secret) = build_ring(&seed, 4, 0);
        let signature = sign(b"payment", &clean_ring, 0, &clean_secret, &[5u8; 32]).expect("signs");
        assert!(!verify(b"payment", &ring, &signature));
    }

    #[test]
    fn out_of_bounds_rings_and_indices_are_refused() {
        let seed = [83u8; 32];
        let (ring, secret) = build_ring(&seed, 2, 0);
        // A single-member ring is below the minimum.
        let single = vec![ring[0]];
        assert_eq!(
            sign(b"payment", &single, 0, &secret, &[6u8; 32]).unwrap_err(),
            VeilError::RingSize(1)
        );
        // An index outside the ring.
        assert!(matches!(
            sign(b"payment", &ring, 2, &secret, &[6u8; 32]).unwrap_err(),
            VeilError::Index { index: 2, len: 2 }
        ));
    }

    #[test]
    fn encoding_round_trips_strictly() {
        let seed = [84u8; 32];
        let (ring, secret) = build_ring(&seed, 5, 2);
        let signature = sign(b"payment", &ring, 2, &secret, &[7u8; 32]).expect("signs");
        let encoded = signature.encode();
        let decoded = RingSignature::decode(&encoded).expect("decodes");
        assert_eq!(decoded, signature);
        assert_eq!(decoded.encode(), encoded);

        // Trailing bytes are refused.
        let mut extended = encoded.clone();
        extended.push(0);
        assert_eq!(
            RingSignature::decode(&extended).unwrap_err(),
            VeilError::Decode(antumbra_primitives::DecodeError::Trailing(1))
        );
        // A truncated body is refused.
        assert!(matches!(
            RingSignature::decode(&encoded[..63]),
            Err(VeilError::Decode(antumbra_primitives::DecodeError::Eof))
        ));
        // A count outside the bounds is refused: the two points,
        // then a varint of 1.
        let mut small = Vec::new();
        small.extend_from_slice(&encoded[..64]);
        small.push(1);
        assert_eq!(
            RingSignature::decode(&small).unwrap_err(),
            VeilError::RingSize(1)
        );
    }

    #[test]
    fn nonces_are_deterministic_and_fresh_per_seed() {
        let seed = [85u8; 32];
        let (ring, secret) = build_ring(&seed, 8, 3);
        let first = sign(b"payment", &ring, 3, &secret, &[8u8; 32]).expect("signs");
        let again = sign(b"payment", &ring, 3, &secret, &[8u8; 32]).expect("signs");
        assert!(first.first_challenge().ct_eq(again.first_challenge()));
        // A different seed gives a different signature, both valid.
        let other = sign(b"payment", &ring, 3, &secret, &[9u8; 32]).expect("signs");
        assert!(!first.first_challenge().ct_eq(other.first_challenge()));
        assert!(verify(b"payment", &ring, &first));
        assert!(verify(b"payment", &ring, &other));
    }
}

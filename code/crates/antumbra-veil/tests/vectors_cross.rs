//! Cross-implementation vector tests for the Veil cryptographic core
//! (CONTRIBUTING.md, layer 1).
//!
//! The archived vector set in `tests/vectors.json` is produced by
//! `code/scripts/gen_veil_vectors.py`: a from-spec Edwards25519
//! implementation (field arithmetic, affine addition, RFC 8032
//! compression and decompression) over pycryptodome hashes, with the
//! RFC 8032 reference public keys cross-checked against
//! pycryptodome. The Rust implementation must agree bit for bit on
//! every derived scalar, public key, hash image, one-time address,
//! commitment and key image, and reject every invalid encoding with
//! the matching error. A disagreement here is not a test failure: it
//! is a consensus fault, and it blocks the phase.

use antumbra_primitives::keys::KeyPair;
use antumbra_veil::commitment::{commit, value_generator};
use antumbra_veil::curve::{Point, Scalar};
use antumbra_veil::error::VeilError;
use antumbra_veil::hash::{hash_to_point, hash_to_scalar};
use antumbra_veil::keyimage::{key_image, owned_secret};
use antumbra_veil::onetime::{ephemeral, one_time_address, shared_secret};
use antumbra_veil::ring::{self, RingSignature};
use antumbra_veil::seed::{rfc8032_clamped_bytes, spend_scalar, view_scalar};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    #[allow(dead_code)] // archived metadata, read for completeness
    format: u32,
    scalar: Vec<ScalarVector>,
    hash_to_scalar: Vec<HashScalarVector>,
    hash_to_point: Vec<HashPointVector>,
    value_generator: ValueGeneratorVector,
    onetime: Vec<OnetimeVector>,
    commitment: Vec<CommitmentVector>,
    homomorphism: HomomorphismVector,
    key_image: Vec<KeyImageVector>,
    ring: Vec<RingVector>,
    invalid_point: Vec<InvalidVector>,
    invalid_scalar: Vec<InvalidVector>,
}

#[derive(Deserialize)]
struct ScalarVector {
    seed: String,
    clamped: String,
    reduced: String,
    public: String,
    view_reduced: String,
    view_public: String,
}

#[derive(Deserialize)]
struct HashScalarVector {
    data: String,
    scalar: String,
}

#[derive(Deserialize)]
struct HashPointVector {
    data: String,
    point: String,
    rounds: u8,
}

#[derive(Deserialize)]
struct ValueGeneratorVector {
    point: String,
    #[allow(dead_code)] // archived metadata, read for completeness
    rounds: u8,
}

#[derive(Deserialize)]
struct OnetimeVector {
    seed: String,
    r: String,
    ephemeral: String,
    shared: String,
    one_time_public: String,
    one_time_secret: String,
    key_image: String,
}

#[derive(Deserialize)]
struct CommitmentVector {
    amount: u64,
    blind: String,
    point: String,
}

#[derive(Deserialize)]
struct HomomorphismVector {
    amount1: u64,
    blind1: String,
    point1: String,
    amount2: u64,
    blind2: String,
    point2: String,
    amount_sum: u64,
    blind_sum: String,
    point_sum: String,
}

#[derive(Deserialize)]
struct KeyImageVector {
    secret: String,
    public: String,
    image: String,
}

#[derive(Deserialize)]
struct RingVector {
    message: String,
    ring: Vec<String>,
    real_index: usize,
    secret: String,
    nonce_seed: String,
    image: String,
    first_challenge: String,
    members: Vec<String>,
    encoding: String,
    tampered_member0: String,
}

#[derive(Deserialize)]
struct InvalidVector {
    bytes: String,
    error: String,
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length in vectors");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex digit"))
        .collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_point(s: &str) -> Point {
    Point::decode(&unhex32(s)).expect("a valid point in the vectors")
}

fn decode_scalar(s: &str) -> Scalar {
    Scalar::decode(&unhex32(s)).expect("a valid scalar in the vectors")
}

fn load() -> Vectors {
    let raw = include_str!("vectors.json");
    serde_json::from_str(raw).expect("valid archived vector set")
}

/// The public key of a scalar, as encoded bytes.
fn public_of(scalar: &Scalar) -> [u8; 32] {
    (Point::generator() * scalar).encode()
}

#[test]
fn wallet_scalars_match_the_independent_implementation() {
    for v in load().scalar {
        let seed = unhex32(&v.seed);

        // The RFC 8032 clamping, byte for byte.
        assert_eq!(hex(&rfc8032_clamped_bytes(&seed)), v.clamped);

        // The reduced spend and view scalars.
        assert_eq!(hex(&spend_scalar(&seed).encode()), v.reduced);
        assert_eq!(hex(&view_scalar(&seed).encode()), v.view_reduced);

        // The bridge to the transparent sphere: the scalar of the
        // Veil generates exactly the published Ed25519 keys.
        assert_eq!(hex(&public_of(&spend_scalar(&seed))), v.public);
        assert_eq!(KeyPair::spend(&seed).public().0, unhex32(&v.public));
        assert_eq!(hex(&public_of(&view_scalar(&seed))), v.view_public);
        assert_eq!(KeyPair::view(&seed).public().0, unhex32(&v.view_public));
    }
}

#[test]
fn hash_to_scalar_matches_the_independent_implementation() {
    for v in load().hash_to_scalar {
        assert_eq!(
            hex(&hash_to_scalar(&unhex(&v.data)).encode()),
            v.scalar,
            "Hs diverged on input {}",
            v.data
        );
    }
}

#[test]
fn hash_to_point_matches_the_independent_implementation() {
    let vectors = load().hash_to_point;
    for v in &vectors {
        let image = hash_to_point(&unhex(&v.data))
            .unwrap_or_else(|e| panic!("Hp diverged on input {}: {e}", v.data));
        assert_eq!(
            hex(&image.encode()),
            v.point,
            "Hp diverged on input {}",
            v.data
        );
        // Every image is a canonical point of the prime-order
        // subgroup: the invariant the cofactor clearing buys.
        assert!(Point::decode(&image.encode()).is_ok());
        assert!(image.is_in_prime_subgroup());
    }
    // The set pins the counter behavior: first-round images and
    // multi-round images both exist.
    assert!(vectors.iter().any(|v| v.rounds == 0));
    assert!(vectors.iter().any(|v| v.rounds >= 1));
}

#[test]
fn the_value_generator_matches_the_independent_implementation() {
    let vector = load().value_generator;
    assert_eq!(hex(&value_generator().encode()), vector.point);
    // The domain tag itself hashes to the generator.
    let recomputed =
        hash_to_point(b"ANTUMBRA/veil/value-generator").expect("the domain tag hashes to a point");
    assert!(recomputed.ct_eq(&value_generator()));
    assert!(value_generator().is_in_prime_subgroup());
    // The generator is not the base point: no known discrete log
    // between them, by construction.
    assert!(!value_generator().ct_eq(&Point::generator()));
}

#[test]
fn the_one_time_pipeline_matches_the_independent_implementation() {
    for v in load().onetime {
        let seed = unhex32(&v.seed);
        let r = decode_scalar(&v.r);

        // The published keys of the recipient, from the primitives
        // crate, decoded as Veil points.
        let view_public =
            Point::decode(&KeyPair::view(&seed).public().0).expect("the view key decodes");
        let spend_public =
            Point::decode(&KeyPair::spend(&seed).public().0).expect("the spend key decodes");

        // Sender side: R = rG and P = Hs(rA) G + B.
        assert_eq!(hex(&ephemeral(&r).encode()), v.ephemeral);
        let shared = shared_secret(&r, &view_public);
        assert_eq!(hex(&shared.encode()), v.shared);
        let destination = one_time_address(&shared, &spend_public);
        assert_eq!(hex(&destination.encode()), v.one_time_public);

        // Scanner side: the same shared secret from (a, R), the
        // same destination, and the owned secret p.
        let a = view_scalar(&seed);
        let b = spend_scalar(&seed);
        let r_public = decode_point(&v.ephemeral);
        assert!(shared_secret(&a, &r_public).ct_eq(&shared));
        let p = owned_secret(&a, &b, &r_public);
        assert_eq!(hex(&p.encode()), v.one_time_secret);
        // pG = P, the ownership proof.
        assert!((Point::generator() * &p).ct_eq(&destination));

        // The key image of the spent output.
        let image = key_image(&p, &destination).expect("the image hashes");
        assert_eq!(hex(&image.encode()), v.key_image);
        assert!(image.is_in_prime_subgroup());
    }
}

#[test]
fn commitments_match_the_independent_implementation() {
    for v in load().commitment {
        let blind = decode_scalar(&v.blind);
        assert_eq!(hex(&commit(v.amount, &blind).encode()), v.point);
    }
}

#[test]
fn commitment_homomorphism_matches_the_independent_implementation() {
    let v = load().homomorphism;
    let b1 = decode_scalar(&v.blind1);
    let b2 = decode_scalar(&v.blind2);
    let b_sum = decode_scalar(&v.blind_sum);
    let c1 = commit(v.amount1, &b1);
    let c2 = commit(v.amount2, &b2);
    let c_sum = commit(v.amount_sum, &b_sum);
    assert_eq!(hex(&c1.encode()), v.point1);
    assert_eq!(hex(&c2.encode()), v.point2);
    assert_eq!(hex(&c_sum.encode()), v.point_sum);
    // C(v1, b1) + C(v2, b2) = C(v1 + v2, b1 + b2): the equality the
    // ordering layer will check at every spend, replayed here.
    assert!((c1 + c2).ct_eq(&c_sum));
    assert_eq!(hex(&(b1 + b2).encode()), v.blind_sum);
}

#[test]
fn key_images_match_the_independent_implementation() {
    for v in load().key_image {
        let secret = decode_scalar(&v.secret);
        let public = decode_point(&v.public);
        let image = key_image(&secret, &public).expect("the image hashes");
        assert_eq!(hex(&image.encode()), v.image);
        // Deterministic: the same pair gives the same image.
        let replay = key_image(&secret, &public).expect("the image hashes again");
        assert!(replay.ct_eq(&image));
        assert!(image.is_in_prime_subgroup());
    }
    // The images of a same secret on two outputs differ: Hp(P)
    // mixes the output, and the vectors pin it.
    let vectors = load().key_image;
    let same_secret: Vec<&KeyImageVector> = vectors
        .iter()
        .filter(|v| v.secret == vectors[3].secret)
        .collect();
    assert!(same_secret.len() >= 2);
    let mut images = same_secret
        .iter()
        .map(|v| v.image.as_str())
        .collect::<Vec<_>>();
    images.dedup();
    assert_eq!(images.len(), same_secret.len());
}

#[test]
fn ring_signatures_match_the_independent_implementation() {
    let vectors = load().ring;
    for v in &vectors {
        let message = unhex(&v.message);
        let ring: Vec<Point> = v.ring.iter().map(|p| decode_point(p)).collect();
        let secret = decode_scalar(&v.secret);
        let nonce_seed = unhex32(&v.nonce_seed);

        // The independent Python implementation signs; the Rust one
        // must produce the identical signature, field by field and
        // byte for byte.
        let signature = ring::sign(&message, &ring, v.real_index, &secret, &nonce_seed)
            .unwrap_or_else(|e| panic!("signs: {e}"));
        assert_eq!(hex(&signature.image().encode()), v.image);
        assert_eq!(
            hex(&signature.first_challenge().encode()),
            v.first_challenge
        );
        assert_eq!(signature.members().len(), v.members.len());
        for (rust, python) in signature.members().iter().zip(&v.members) {
            assert_eq!(hex(&rust.encode()), *python);
        }
        assert_eq!(hex(&signature.encode()), v.encoding);

        // The signature verifies, and the archived encoding decodes
        // back to the same structure.
        assert!(ring::verify(&message, &ring, &signature));
        let decoded = RingSignature::decode(&unhex(&v.encoding))
            .unwrap_or_else(|e| panic!("archived signature decodes: {e}"));
        assert_eq!(decoded, signature);

        // The tampered member, as archived by the generator, fails
        // verification: replace the first member scalar inside the
        // encoding and decode the tampered form.
        let tampered_scalar = decode_scalar(&v.tampered_member0);
        let mut tampered_encoding = unhex(&v.encoding);
        // The layout: 32 bytes image, 32 bytes challenge, one varint
        // byte for ring sizes below 128, then the member scalars.
        let first_member_offset = 65;
        tampered_encoding[first_member_offset..first_member_offset + 32]
            .copy_from_slice(&tampered_scalar.encode());
        let tampered = RingSignature::decode(&tampered_encoding).expect("tampered form decodes");
        assert!(!ring::verify(&message, &ring, &tampered));

        // A wrong message fails.
        assert!(!ring::verify(b"other", &ring, &signature));
    }

    // The linkability pair: two vectors share the secret and the
    // image across different rings.
    assert!(vectors.len() >= 2);
    let pair: Vec<&RingVector> = vectors
        .iter()
        .filter(|v| v.secret == vectors[0].secret)
        .collect();
    assert_eq!(pair.len(), 2);
    assert_eq!(pair[0].image, pair[1].image);
    assert_ne!(pair[0].encoding, pair[1].encoding);
    assert_ne!(pair[0].ring, pair[1].ring);

    // The protocol ring of sixteen is covered.
    assert!(vectors.iter().any(|v| v.ring.len() == 16));
}

#[test]
fn invalid_points_are_refused_with_the_matching_error() {
    for v in load().invalid_point {
        let bytes = unhex32(&v.bytes);
        let error = Point::decode(&bytes).expect_err("an invalid point is refused");
        match v.error.as_str() {
            "identity" => assert_eq!(error, VeilError::IdentityPoint(bytes)),
            "outside_subgroup" => assert_eq!(error, VeilError::OutsideSubgroup(bytes)),
            "non_canonical" => assert_eq!(error, VeilError::NonCanonicalPoint(bytes)),
            other => panic!("unknown error kind in vectors: {other}"),
        }
    }
}

#[test]
fn invalid_scalars_are_refused_with_the_matching_error() {
    for v in load().invalid_scalar {
        let bytes = unhex32(&v.bytes);
        assert_eq!(
            Scalar::decode(&bytes),
            Err(VeilError::NonCanonicalScalar(bytes))
        );
    }
}

#[test]
fn the_vector_set_covers_the_structural_boundaries() {
    let vectors = load();
    // Wallet scalars: the RFC 8032 reference seeds and generated
    // seeds both covered.
    assert!(vectors.scalar.len() >= 6);
    // Commitments: the zero amount, one atom, and a large value.
    let amounts: Vec<u64> = vectors.commitment.iter().map(|v| v.amount).collect();
    assert!(amounts.contains(&0));
    assert!(amounts.contains(&1));
    assert!(amounts.iter().any(|a| *a > 1_000_000_000_000_000));
    // Invalid encodings: every rejection class of the decoder.
    let point_errors: Vec<&str> = vectors
        .invalid_point
        .iter()
        .map(|v| v.error.as_str())
        .collect();
    assert!(point_errors.contains(&"identity"));
    assert!(point_errors.contains(&"outside_subgroup"));
    assert!(point_errors.contains(&"non_canonical"));
    assert!(!vectors.invalid_scalar.is_empty());
}

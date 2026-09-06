//! Cross-implementation vector tests for the finality layer
//! (CONTRIBUTING.md, layer 1).
//!
//! The archived vector set in `tests/vectors.json` is produced by
//! `code/scripts/gen_ring_vectors.py`, an independent
//! implementation of the checkpoint message codec, the order
//! root, the checkpoint codec with its seat signatures, the
//! verification battery against a roster, and the stripping
//! evidence (pycryptodome for Keccak-256 and Ed25519, from-spec
//! reimplementations for the rest). The Rust implementation must
//! agree bit for bit. A disagreement here is not a test failure:
//! it is a consensus fault, and it blocks the phase.

use antumbra_primitives::{Hash, KeyPair};
use antumbra_ring::checkpoint::SeatSignature;
use antumbra_ring::{
    order_root, Checkpoint, CheckpointMessage, Equivocation, RingError, Roster, QUORUM, SEATS,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    #[allow(dead_code)] // archived metadata, read for completeness
    format: u32,
    seeds: Vec<String>,
    order_root: Vec<OrderRootVector>,
    message: Vec<MessageVector>,
    checkpoint: Vec<CheckpointVector>,
    invalid: Vec<InvalidVector>,
    equivocation: Vec<EquivocationVector>,
}

#[derive(Deserialize)]
struct OrderRootVector {
    ids: Vec<String>,
    root: String,
}

#[derive(Deserialize)]
struct MessageVector {
    era: u64,
    sequence: u64,
    tip: String,
    order_root: String,
    canonical_hex: String,
    digest: String,
}

#[derive(Deserialize)]
struct CheckpointVector {
    era: u64,
    sequence: u64,
    tip: String,
    order_root: String,
    signatures: Vec<SignatureVector>,
    roster_era: u64,
    roster_count: usize,
    #[serde(rename = "final")]
    is_final: bool,
    error: Option<String>,
    canonical_hex: String,
}

#[derive(Deserialize)]
struct SignatureVector {
    seat: u16,
    seed: String,
}

#[derive(Deserialize)]
struct InvalidVector {
    hex: String,
    error: String,
}

#[derive(Deserialize)]
struct EquivocationVector {
    seat: u16,
    signing_seed: String,
    roster_era: u64,
    first: MessageFields,
    second: MessageFields,
    error: Option<String>,
    canonical_hex: String,
}

#[derive(Deserialize)]
struct MessageFields {
    era: u64,
    sequence: u64,
    tip: String,
    order_root: String,
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

fn load() -> Vectors {
    let raw = include_str!("vectors.json");
    serde_json::from_str(raw).expect("valid archived vector set")
}

/// The seat seeds of the vector roster.
fn seat_seeds(vectors: &Vectors) -> Vec<[u8; 32]> {
    vectors.seeds.iter().map(|s| unhex32(s)).collect()
}

/// The roster of an era over the first `count` seat seeds.
fn roster(seeds: &[[u8; 32]], era: u64, count: usize) -> Roster {
    let keys = seeds[..count]
        .iter()
        .map(|s| KeyPair::spend(s).public())
        .collect();
    Roster::new(era, keys).expect("the vector roster builds")
}

fn rebuild_message(v: &MessageFields) -> CheckpointMessage {
    CheckpointMessage::new(
        v.era,
        v.sequence,
        Hash(unhex32(&v.tip)),
        Hash(unhex32(&v.order_root)),
    )
}

fn expect_reject(name: &str, error: &RingError) {
    let matches = match name {
        "InvalidVersion" => matches!(error, RingError::InvalidVersion(_)),
        "EraZero" => matches!(error, RingError::EraZero),
        "SequenceZero" => matches!(error, RingError::SequenceZero),
        "ZeroTip" => matches!(error, RingError::ZeroTip),
        "TooManySeats" => matches!(error, RingError::TooManySeats(_)),
        "DuplicateKey" => matches!(error, RingError::DuplicateKey),
        "SeatOutOfRange" => matches!(error, RingError::SeatOutOfRange { .. }),
        "DuplicateSeat" => matches!(error, RingError::DuplicateSeat(_)),
        "UnsortedSeats" => matches!(error, RingError::UnsortedSeats),
        "TooManySignatures" => matches!(error, RingError::TooManySignatures(_)),
        "InvalidSignature" => matches!(error, RingError::InvalidSignature { .. }),
        "EraMismatch" => matches!(error, RingError::EraMismatch { .. }),
        "DifferentEra" => matches!(error, RingError::DifferentEra { .. }),
        "DifferentSequence" => matches!(error, RingError::DifferentSequence { .. }),
        "IdenticalMessages" => matches!(error, RingError::IdenticalMessages),
        "Decode" => matches!(error, RingError::Decode(_)),
        other => panic!("unknown rejection name in vectors: {other}"),
    };
    assert!(matches, "expected {name}, got {error}");
}

#[test]
fn the_seat_seeds_form_a_valid_roster() {
    let vectors = load();
    let seeds = seat_seeds(&vectors);
    assert_eq!(seeds.len(), SEATS);
    let full = roster(&seeds, 1, SEATS);
    assert_eq!(full.len(), SEATS);
    // The public keys are pairwise distinct: no seat holds two
    // seats, exactly as the without-replacement draw requires.
    assert!(Roster::new(1, {
        let mut keys: Vec<_> = seeds.iter().map(|s| KeyPair::spend(s).public()).collect();
        keys.push(keys[0]);
        keys
    })
    .is_err());
}

#[test]
fn order_roots_match_the_independent_implementation() {
    for v in load().order_root {
        let ids: Vec<Hash> = v.ids.iter().map(|s| Hash(unhex32(s))).collect();
        assert_eq!(hex(order_root(&ids).as_bytes()), v.root);
    }
}

#[test]
fn messages_match_the_independent_implementation() {
    for v in load().message {
        let fields = MessageFields {
            era: v.era,
            sequence: v.sequence,
            tip: v.tip.clone(),
            order_root: v.order_root.clone(),
        };
        let message = rebuild_message(&fields);
        // Canonical encoding, bit for bit.
        assert_eq!(
            hex(&message.encode()),
            v.canonical_hex,
            "canonical encoding diverged (era {})",
            v.era
        );
        // The digest is Keccak-256 of the encoding.
        assert_eq!(message.digest().to_string(), v.digest);
        // Strict decoding of the archived bytes.
        let decoded = CheckpointMessage::decode(&unhex(&v.canonical_hex))
            .unwrap_or_else(|e| panic!("archived message decodes: {e}"));
        assert_eq!(decoded, message);
    }
}

#[test]
fn checkpoints_match_the_independent_implementation() {
    let vectors = load();
    let seeds = seat_seeds(&vectors);
    for v in &vectors.checkpoint {
        let fields = MessageFields {
            era: v.era,
            sequence: v.sequence,
            tip: v.tip.clone(),
            order_root: v.order_root.clone(),
        };
        let message = rebuild_message(&fields);
        let mut checkpoint = Checkpoint::new(message.clone());
        for signature in &v.signatures {
            checkpoint
                .sign(signature.seat, &KeyPair::spend(&unhex32(&signature.seed)))
                .expect("the archived seats sign");
        }
        // Canonical encoding, bit for bit, and the roundtrip.
        assert_eq!(hex(&checkpoint.encode()), v.canonical_hex);
        let decoded = Checkpoint::decode(&unhex(&v.canonical_hex))
            .unwrap_or_else(|e| panic!("archived checkpoint decodes: {e}"));
        assert_eq!(decoded, checkpoint);
        // Verification against the roster of the announced era.
        let seats = roster(&seeds, v.roster_era, v.roster_count);
        match &v.error {
            None => {
                assert_eq!(checkpoint.verify(&seats), Ok(()));
                assert_eq!(checkpoint.is_final(), v.is_final);
                assert_eq!(checkpoint.finalized(&seats), Ok(v.is_final));
            }
            Some(name) => match checkpoint.verify(&seats) {
                Err(e) => expect_reject(name, &e),
                Ok(()) => panic!("the checkpoint must be rejected ({name})"),
            },
        }
    }
}

#[test]
fn the_checkpoint_vectors_cover_the_quorum_boundaries() {
    let vectors = load();
    // The quorum exactly, below it, a bootstrap roster, all the
    // seats, and three rejection paths.
    let counts: Vec<usize> = vectors
        .checkpoint
        .iter()
        .map(|v| v.signatures.len())
        .collect();
    assert!(counts.contains(&QUORUM));
    assert!(counts.contains(&(QUORUM - 1)));
    assert!(counts.contains(&SEATS));
    assert!(vectors
        .checkpoint
        .iter()
        .any(|v| v.roster_count < QUORUM && v.error.is_none() && !v.is_final));
}

#[test]
fn the_invalid_bytes_are_rejected_with_the_archived_reason() {
    for v in load().invalid {
        let bytes = unhex(&v.hex);
        match Checkpoint::decode(&bytes) {
            Err(e) => expect_reject(&v.error, &e),
            Ok(checkpoint) => panic!(
                "the bytes must be rejected ({}) but decoded as {}",
                v.error,
                hex(checkpoint.encode().as_slice())
            ),
        }
    }
}

#[test]
fn equivocations_match_the_independent_implementation() {
    let vectors = load();
    let seeds = seat_seeds(&vectors);
    for v in &vectors.equivocation {
        let first = rebuild_message(&v.first);
        let second = rebuild_message(&v.second);
        let signing = KeyPair::spend(&unhex32(&v.signing_seed));
        let first_signature = signing.sign(&first.encode());
        let second_signature = signing.sign(&second.encode());
        let evidence = Equivocation::new(v.seat, first, first_signature, second, second_signature);
        // Canonical encoding, bit for bit, and the roundtrip.
        assert_eq!(hex(&evidence.encode()), v.canonical_hex);
        let decoded = Equivocation::decode(&unhex(&v.canonical_hex))
            .unwrap_or_else(|e| panic!("archived evidence decodes: {e}"));
        assert_eq!(decoded, evidence);
        // The stripping battery against the roster of the era.
        let seats = roster(&seeds, v.roster_era, SEATS);
        match &v.error {
            None => assert_eq!(evidence.verify(&seats), Ok(())),
            Some(name) => match evidence.verify(&seats) {
                Err(e) => expect_reject(name, &e),
                Ok(()) => panic!("the evidence must be rejected ({name})"),
            },
        }
    }
}

#[test]
fn the_seat_signature_accessors_read_what_was_collected() {
    // A small coverage check of the collected signature view: the
    // seats ascend and the signatures roundtrip through the
    // encoding.
    let vectors = load();
    let seeds = seat_seeds(&vectors);
    let v = vectors
        .checkpoint
        .iter()
        .find(|v| v.signatures.len() == QUORUM)
        .expect("a quorum vector exists");
    let fields = MessageFields {
        era: v.era,
        sequence: v.sequence,
        tip: v.tip.clone(),
        order_root: v.order_root.clone(),
    };
    let mut checkpoint = Checkpoint::new(rebuild_message(&fields));
    for signature in &v.signatures {
        checkpoint
            .sign(
                signature.seat,
                &KeyPair::spend(&seeds[usize::from(signature.seat)]),
            )
            .expect("the archived seats sign");
    }
    let seats: Vec<u16> = checkpoint
        .signatures()
        .iter()
        .map(SeatSignature::seat)
        .collect();
    for pair in seats.windows(2) {
        assert!(pair[0] < pair[1], "the seats ascend");
    }
    assert_eq!(seats.len(), checkpoint.signature_count());
    assert!(checkpoint
        .signatures()
        .iter()
        .all(|collected| collected.signature().0.len() == 64));
}

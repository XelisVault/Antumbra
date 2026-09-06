//! Cross-implementation vector tests for the reputation machine
//! (CONTRIBUTING.md, layer 1).
//!
//! The archived vector set in `tests/vectors.json` is produced by
//! `code/scripts/gen_kleos_vectors.py`, an independent Python
//! implementation of the millipoint state machine (era transition,
//! decay, saturation, the four sanctions), the queries (witness
//! weight, Ring candidacy, the total), the closed-graph discounts
//! and Echo helpers, and the era draw over its Keccak word stream
//! (pycryptodome for Keccak-256, from-spec reimplementations for
//! the rest). The Rust implementation must agree bit for bit. A
//! disagreement here is not a test failure: it is a consensus
//! fault, and it blocks the phase.

use antumbra_kleos::{
    capped_echo_gain, draw, echo_contribution, mutual_echo, pooled_deed, WordStream,
};
use antumbra_kleos::{EraInputs, Kleos, KleosError};
use antumbra_primitives::Hash;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    #[allow(dead_code)] // archived metadata, read for completeness
    format: u32,
    #[allow(dead_code)]
    comment: String,
    word_stream: Vec<WordStreamVector>,
    state: Vec<StateVector>,
    helpers: HelperVectors,
    draw: Vec<DrawVector>,
    draw_rejected: Vec<RejectedVector>,
}

#[derive(Deserialize)]
struct WordStreamVector {
    entropy_hex: String,
    count: usize,
    words_hex: Vec<String>,
}

/// One operation of a state sequence, as a flat object: `{"op":
/// "era", "deed_gain": n, "echo_gain": m}` or `{"op": "fraud"}`.
/// A plain struct keeps the archived set deserializable without
/// any tagged-enum machinery.
#[derive(Deserialize)]
struct Op {
    op: String,
    #[serde(default)]
    deed_gain: u32,
    #[serde(default)]
    echo_gain: u32,
}

#[derive(Deserialize)]
struct StateVector {
    #[allow(dead_code)] // archived name, read for completeness
    name: String,
    initial: (u32, u32, u32, bool),
    ops: Vec<Op>,
    after_each: Vec<(u32, u32, u32, bool)>,
    #[serde(rename = "final")]
    final_state: (u32, u32, u32, bool),
    total: u32,
    witness_weight: u32,
    is_ring_candidate: bool,
}

#[derive(Deserialize)]
struct HelperVectors {
    pooled_deed: Vec<(u32, u32)>,
    mutual_echo: Vec<(u32, u32)>,
    echo_contribution: Vec<(u32, u32, u32)>,
    capped_echo_gain: Vec<(Vec<u32>, u32)>,
}

#[derive(Deserialize)]
struct DrawVector {
    #[allow(dead_code)] // archived name, read for completeness
    name: String,
    candidates: Vec<(String, u32)>,
    entropy_hex: String,
    seats: usize,
    drawn: Vec<usize>,
}

#[derive(Deserialize)]
struct RejectedVector {
    #[allow(dead_code)] // archived name, read for completeness
    name: String,
    candidates: Vec<(String, u32)>,
    seats: usize,
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

fn rebuild(parts: &(u32, u32, u32, bool)) -> Kleos {
    Kleos::from_parts(parts.0, parts.1, parts.2, parts.3).expect("the vector state is bounded")
}

fn apply(op: &Op, state: &mut Kleos) {
    match op.op.as_str() {
        "era" => state.advance_era(&EraInputs {
            deed_gain: op.deed_gain,
            echo_gain: op.echo_gain,
        }),
        "fraud" => state.convict_fraud(),
        "witness" => state.penalize_witness(),
        "sponsor" => state.penalize_sponsor(),
        "strip" => state.strip(),
        other => panic!("unknown operation word in vectors: {other}"),
    }
}

fn load() -> Vectors {
    let raw = include_str!("vectors.json");
    serde_json::from_str(raw).expect("valid archived vector set")
}

#[test]
fn the_word_streams_match_the_independent_implementation() {
    for v in load().word_stream {
        let entropy = unhex(&v.entropy_hex);
        let mut stream = WordStream::new(&entropy);
        for (position, expected) in v.words_hex.iter().enumerate() {
            let word = stream.next_word();
            assert_eq!(
                format!("{word:032x}"),
                *expected,
                "word {position} of the stream diverged"
            );
        }
        assert_eq!(v.words_hex.len(), v.count, "the word count is archived");
    }
}

#[test]
fn the_state_sequences_match_after_every_operation() {
    for v in load().state {
        let mut state = rebuild(&v.initial);
        assert_eq!(v.after_each.len(), v.ops.len(), "one state per operation");
        for (op, after) in v.ops.iter().zip(&v.after_each) {
            apply(op, &mut state);
            let actual = (
                state.deed(),
                state.echo(),
                state.tenure(),
                state.tenure_dead(),
            );
            assert_eq!(
                actual,
                (after.0, after.1, after.2, after.3),
                "the state diverged after {} (vector {})",
                op.op,
                v.name
            );
        }
        let final_state = (
            state.deed(),
            state.echo(),
            state.tenure(),
            state.tenure_dead(),
        );
        assert_eq!(
            final_state,
            (
                v.final_state.0,
                v.final_state.1,
                v.final_state.2,
                v.final_state.3
            ),
            "the final state diverged (vector {})",
            v.name
        );
        assert_eq!(state.total(), v.total, "the total diverged");
        assert_eq!(
            state.witness_weight(),
            v.witness_weight,
            "the witness weight diverged"
        );
        assert_eq!(
            state.is_ring_candidate(),
            v.is_ring_candidate,
            "the Ring candidacy diverged"
        );
    }
}

#[test]
fn the_helpers_match_the_independent_implementation() {
    let helpers = load().helpers;
    for (accrual, expected) in helpers.pooled_deed {
        assert_eq!(pooled_deed(accrual), expected, "pooled_deed({accrual})");
    }
    for (budget, expected) in helpers.mutual_echo {
        assert_eq!(mutual_echo(budget), expected, "mutual_echo({budget})");
    }
    for (deed, budget, expected) in helpers.echo_contribution {
        let witness = Kleos::from_parts(deed, 0, 0, false).expect("the witness is bounded");
        assert_eq!(
            echo_contribution(&witness, budget),
            expected,
            "echo_contribution(deed {deed}, budget {budget})"
        );
    }
    for (contributions, expected) in helpers.capped_echo_gain {
        assert_eq!(
            capped_echo_gain(&contributions),
            expected,
            "capped_echo_gain over {contributions:?}"
        );
    }
}

#[test]
fn the_draws_match_the_independent_implementation() {
    for v in load().draw {
        let candidates: Vec<(Hash, u32)> = v
            .candidates
            .iter()
            .map(|(id, weight)| (Hash(unhex32(id)), *weight))
            .collect();
        let entropy = unhex(&v.entropy_hex);
        let drawn = draw(&candidates, &entropy, v.seats).expect("the vector draw runs");
        assert_eq!(drawn, v.drawn, "the draw diverged (vector {})", v.name);
        // No replacement: every seat is a distinct candidate.
        let mut unique = drawn.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), drawn.len(), "the draw is without replacement");
        // Replaying with the same entropy reproduces the cohort.
        let replay = draw(&candidates, &entropy, v.seats).expect("the replay runs");
        assert_eq!(replay, v.drawn, "the draw is deterministic");
    }
}

#[test]
fn the_rejected_pools_are_rejected_with_the_archived_reason() {
    for v in load().draw_rejected {
        let candidates: Vec<(Hash, u32)> = v
            .candidates
            .iter()
            .map(|(id, weight)| (Hash(unhex32(id)), *weight))
            .collect();
        match draw(&candidates, b"entropy", v.seats) {
            Err(error) => {
                let matches = match v.error.as_str() {
                    "EmptyPool" => matches!(error, KleosError::EmptyPool),
                    "UnsortedCandidates" => matches!(error, KleosError::UnsortedCandidates),
                    other => panic!("unknown rejection name in vectors: {other}"),
                };
                assert!(matches, "expected {}, got {error}", v.error);
            }
            Ok(drawn) => panic!("the pool must be rejected ({}) but drew {drawn:?}", v.name),
        }
    }
}

#[test]
fn the_draw_vectors_cover_the_shapes_of_an_era() {
    let vectors = load();
    // A full era draw exists: fifty-five seats over at least
    // fifty-five candidates.
    assert!(vectors
        .draw
        .iter()
        .any(|v| { v.seats == 55 && v.candidates.len() == 60 && v.drawn.len() == 55 }));
    // A short pool draws every candidate it holds.
    assert!(vectors
        .draw
        .iter()
        .any(|v| v.seats > v.candidates.len() && v.drawn.len() == v.candidates.len()));
    // A pool that exhausts its weight draws fewer seats than
    // asked: the zero-weight whales never enter.
    assert!(vectors
        .draw
        .iter()
        .any(|v| v.drawn.len() < v.seats && v.drawn.len() < v.candidates.len()));
}

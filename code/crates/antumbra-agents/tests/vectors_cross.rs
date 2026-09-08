//! Cross-implementation vector tests for the machine-account
//! layer (CONTRIBUTING.md, layer 1).
//!
//! The archived vector set in `tests/vectors.json` is produced
//! by `code/scripts/gen_agents_vectors.py`, an independent
//! Python implementation of the Mandate grammar, the Warrant
//! state machine (monotone nonce, fail-closed revocation, the
//! drain delay), the uniform authority encoding, the receipts,
//! the streams and the batches, re-implemented from the ADR
//! text alone. The Rust implementation must agree bit for bit.
//! A disagreement here is not a test failure: it is a consensus
//! fault, and it blocks the phase.

use antumbra_agents::{
    batch, AgentError, Authority, Fact, Mandate, Receipt, ReceiptStatus, Stream, StreamState,
    Warrant, AUTHORITY_BYTES, BATCH_MAX_PAYMENTS, MANDATE_MAX_DESTS,
};
use antumbra_primitives::{keccak256, Hash};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    #[allow(dead_code)] // archived metadata, read for completeness
    format: u32,
    #[allow(dead_code)]
    comment: String,
    mandate: Vec<MandateVector>,
    warrant: WarrantVector,
    encoding: EncodingVector,
    receipt: ReceiptVector,
    stream: StreamVector,
    batch: BatchVector,
}

#[derive(Deserialize)]
struct MandateVector {
    #[allow(dead_code)] // archived name, read for completeness
    name: String,
    version: u8,
    max_amount: u64,
    max_rate: u64,
    expiry_tick: u32,
    job_types: u16,
    rails: u8,
    dests_hex: Vec<String>,
    dest_count: u8,
    valid: bool,
    rejection: Option<String>,
    permits_first_three: Vec<bool>,
    canonical_sha: String,
}

#[derive(Deserialize)]
struct WarrantVector {
    max_amount: u64,
    max_rate: u64,
    expiry_tick: u32,
    job_types: u16,
    rails: u8,
    dests_hex: Vec<String>,
    dest_count: u8,
    mandate_root: String,
    ops: Vec<WarrantOp>,
    final_state: (u64, u32, bool),
}

#[derive(Deserialize)]
struct WarrantOp {
    #[allow(dead_code)] // archived op name, matched by order
    op: String,
    #[serde(default)]
    dest_hex: Option<String>,
    amount: u64,
    nonce: u32,
    tick: u32,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    drain_ready: Option<bool>,
    after: (u64, u32, bool),
}

#[derive(Deserialize)]
struct EncodingVector {
    human_payload_hex: String,
    agent_payload_hex: String,
    human_field_hex: String,
    agent_field_hex: String,
    human_len: usize,
    agent_len: usize,
    human_well_formed: bool,
    agent_well_formed: bool,
    broken_well_formed: bool,
    same_prefix_free: bool,
}

#[derive(Deserialize)]
struct ReceiptVector {
    kind: u8,
    job_id: u32,
    amount: u64,
    tick: u32,
    warrant_root_hex: String,
    salt_hex: String,
    commitment_hex: String,
    verify_right: bool,
    verify_wrong_amount: bool,
    verify_wrong_salt: bool,
    status_open: String,
    status_paid: String,
    status_failed: String,
    wrong_commitment_hex: String,
}

#[derive(Deserialize)]
struct StreamVector {
    rate_per_tick: u64,
    cap: u64,
    ops: Vec<StreamOp>,
}

#[derive(Deserialize)]
struct StreamOp {
    tick: u32,
    revoked: bool,
    paid: u64,
    state: (u64, u32, bool),
    #[serde(default)]
    series: Option<String>,
}

#[derive(Deserialize)]
struct BatchVector {
    max_amount: u64,
    max_rate: u64,
    expiry_tick: u32,
    job_types: u16,
    rails: u8,
    dests_hex: Vec<String>,
    dest_count: u8,
    ok: BatchCase,
    empty: BatchCase,
    perimeter: BatchCase,
    over_rate: BatchCase,
    after: (u64, u32, bool),
}

#[derive(Deserialize, Debug)]
struct BatchCase {
    outcome: String,
    result: Option<BatchResult>,
}

#[derive(Deserialize, Debug)]
struct BatchResult {
    total: u64,
    ring_verifications: u32,
}

fn hex32(text: &str) -> Hash {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex byte");
    }
    Hash(out)
}

fn dests_of_hex(texts: &[String]) -> [Hash; MANDATE_MAX_DESTS] {
    let mut dests = [Hash::ZERO; MANDATE_MAX_DESTS];
    for (i, text) in texts.iter().take(MANDATE_MAX_DESTS).enumerate() {
        dests[i] = hex32(text);
    }
    dests
}

fn dests_of(vector: &MandateVector) -> [Hash; MANDATE_MAX_DESTS] {
    dests_of_hex(&vector.dests_hex)
}

fn error_label(error: &AgentError) -> String {
    match error {
        AgentError::MalformedMandate { field, value } => {
            format!("malformed_mandate:{field}:{value}")
        }
        AgentError::DuplicateDest => "duplicate_dest".into(),
        AgentError::Revoked => "revoked".into(),
        AgentError::Expired { .. } => "expired".into(),
        AgentError::NonceNotMonotone { .. } => "nonce".into(),
        AgentError::ZeroAmount => "zero_amount".into(),
        AgentError::OverRate { .. } => "over_rate".into(),
        AgentError::OverCap { .. } => "over_cap".into(),
        AgentError::PerimeterDest => "perimeter".into(),
        AgentError::BatchTooLarge { len } => format!("batch_too_large:{len}"),
        AgentError::MalformedAuthority => "malformed_authority".into(),
        AgentError::CommitmentMismatch => "commitment_mismatch".into(),
    }
}

fn mandate_of(vector: &MandateVector) -> Mandate {
    Mandate {
        version: vector.version,
        max_amount: vector.max_amount,
        max_rate: vector.max_rate,
        expiry_tick: vector.expiry_tick,
        job_types: vector.job_types,
        rails: vector.rails,
        dests: dests_of(vector),
        dest_count: vector.dest_count,
    }
}

fn warrant_for(vector: &WarrantVector) -> Warrant {
    let mandate = Mandate::new(
        vector.max_amount,
        vector.max_rate,
        vector.expiry_tick,
        vector.job_types,
        vector.rails,
        dests_of_hex(&vector.dests_hex),
        vector.dest_count,
    )
    .expect("the scenario mandate is valid");
    let warrant = Warrant::new(mandate).expect("the warrant opens");
    assert_eq!(warrant.root().to_string(), vector.mandate_root);
    warrant
}

fn status_of(label: &str) -> ReceiptStatus {
    match label {
        "open" => ReceiptStatus::Open,
        "paid" => ReceiptStatus::Paid,
        "failed" => ReceiptStatus::Failed,
        other => panic!("unknown receipt status {other}"),
    }
}

#[test]
fn mandate_grammar_agrees_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for vector in &vectors.mandate {
        let built = mandate_of(vector);
        let outcome = built.validate();
        match (vector.valid, vector.rejection.as_deref()) {
            (true, None) => assert!(outcome.is_ok(), "case {}", vector.name),
            (false, Some(expected)) => {
                let error = outcome.expect_err("the vector says malformed");
                assert_eq!(error_label(&error), expected, "case {}", vector.name);
            }
            other => panic!("case {}: inconsistent vector {other:?}", vector.name),
        }
        for (i, expected) in vector.permits_first_three.iter().enumerate() {
            let dest = hex32(&vector.dests_hex[i]);
            assert_eq!(
                built.permits_dest(&dest),
                *expected,
                "case {} dest {i}",
                vector.name
            );
        }
        let sha = keccak256(&built.canonical_bytes());
        assert_eq!(
            sha.to_string(),
            vector.canonical_sha,
            "case {}",
            vector.name
        );
    }
}

#[test]
fn warrant_machine_agrees_step_by_step() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    let mut warrant = warrant_for(&vectors.warrant);
    for op in &vectors.warrant.ops {
        match op.op.as_str() {
            "revoke" => warrant.revoke(op.tick),
            "drain_early" | "drain_ready" => {
                assert_eq!(
                    warrant.drain_ready(op.tick),
                    op.drain_ready.unwrap_or(false)
                );
            }
            _ => {
                let dest = hex32(op.dest_hex.as_deref().expect("spend op holds a dest"));
                let outcome = warrant.spend(&dest, op.amount, op.nonce, op.tick);
                let label = match &outcome {
                    Ok(_) => "ok".to_string(),
                    Err(error) => error_label(error),
                };
                assert_eq!(Some(label), op.outcome, "op {} at tick {}", op.op, op.tick);
            }
        }
        assert_eq!(warrant.state(), op.after, "op {}", op.op);
    }
    assert_eq!(warrant.state(), vectors.warrant.final_state);
}

#[test]
fn uniform_encoding_agrees_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    let encoding = &vectors.encoding;

    let human = Authority::Human {
        stealth: hex32(&encoding.human_payload_hex),
    };
    let agent = Authority::Agent {
        warrant_root: hex32(&encoding.agent_payload_hex),
    };

    let human_field = human.encode();
    let agent_field = agent.encode();
    assert_eq!(human_field.len(), encoding.human_len);
    assert_eq!(agent_field.len(), encoding.agent_len);
    assert_eq!(human_field.len(), agent_field.len());
    assert_eq!(hex_of(&human_field), encoding.human_field_hex);
    assert_eq!(hex_of(&agent_field), encoding.agent_field_hex);

    let mut human_bytes = [0u8; AUTHORITY_BYTES];
    human_bytes.copy_from_slice(&human_field);
    let mut agent_bytes = [0u8; AUTHORITY_BYTES];
    agent_bytes.copy_from_slice(&agent_field);
    assert!(Authority::well_formed(&human_bytes).is_ok() == encoding.human_well_formed);
    assert!(Authority::well_formed(&agent_bytes).is_ok() == encoding.agent_well_formed);

    let mut broken = agent_bytes;
    broken[63] ^= 0x01;
    assert!(Authority::well_formed(&broken).is_err());
    assert_eq!(
        Authority::well_formed(&broken).is_ok(),
        encoding.broken_well_formed
    );

    // No structural constant leaks the kind: neither half of the
    // two fields coincides, and both use the same derivation.
    assert!(encoding.same_prefix_free);
    assert_ne!(&human_field[..32], &agent_field[..32]);
    assert_ne!(&human_field[32..], &agent_field[32..]);
}

fn hex_of(bytes: &[u8]) -> String {
    // The primitives crate prints a Hash the same way; here the
    // raw field halves need the same hex, built by fold to keep
    // the lint (format-collect) quiet.
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[test]
fn receipts_agree_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    let v = &vectors.receipt;
    let fact = Fact {
        kind: v.kind,
        job_id: v.job_id,
        amount: v.amount,
        tick: v.tick,
        warrant_root: hex32(&v.warrant_root_hex),
    };
    let salt = hex32(&v.salt_hex);
    let commitment = Receipt::commit(&fact, &salt);
    assert_eq!(commitment.to_string(), v.commitment_hex);

    assert_eq!(
        Receipt::verify(&commitment, &fact, &salt).is_ok(),
        v.verify_right
    );
    let mut wrong_amount = fact;
    wrong_amount.amount += 1;
    assert_eq!(
        Receipt::verify(&commitment, &wrong_amount, &salt).is_ok(),
        v.verify_wrong_amount
    );
    let wrong_salt = Hash([0xff; 32]);
    assert_eq!(
        Receipt::verify(&commitment, &fact, &wrong_salt).is_ok(),
        v.verify_wrong_salt
    );
    assert!(Receipt::verify(&hex32(&v.wrong_commitment_hex), &fact, &salt).is_err());

    assert_eq!(Receipt::status(false, false), status_of(&v.status_open));
    assert_eq!(Receipt::status(false, true), status_of(&v.status_paid));
    assert_eq!(Receipt::status(true, false), status_of(&v.status_failed));
}

#[test]
fn streams_agree_tick_by_tick() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    let stream = Stream {
        to: Hash::ZERO,
        rate_per_tick: vectors.stream.rate_per_tick,
        cap: vectors.stream.cap,
    };
    let mut state = StreamState::default();
    let mut state2 = StreamState::default();
    for op in &vectors.stream.ops {
        let target = if op.series.as_deref() == Some("cap_exhausts") {
            &mut state2
        } else {
            &mut state
        };
        let paid = antumbra_agents::tick(target, &stream, op.revoked);
        assert_eq!(paid, op.paid, "tick {}", op.tick);
        assert_eq!((target.paid, target.ticks, target.closed), op.state);
    }
}

#[test]
fn batches_agree_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    let dests = dests_of_hex(&vectors.batch.dests_hex);
    let mandate = Mandate::new(
        vectors.batch.max_amount,
        vectors.batch.max_rate,
        vectors.batch.expiry_tick,
        vectors.batch.job_types,
        vectors.batch.rails,
        dests,
        vectors.batch.dest_count,
    )
    .expect("the batch mandate is valid");
    let mut warrant = Warrant::new(mandate).expect("the warrant opens");

    // The ok batch: three payments, one ring verification.
    let payments = vec![
        antumbra_agents::Payment {
            dest: dests[0],
            amount: 3_000_000,
        },
        antumbra_agents::Payment {
            dest: dests[1],
            amount: 2_000_000,
        },
        antumbra_agents::Payment {
            dest: dests[2],
            amount: 1_000_000,
        },
    ];
    let outcome = batch(&payments, &mut warrant, 1, 100);
    match (&vectors.batch.ok, &outcome) {
        (case, Ok(result)) => {
            assert_eq!(case.outcome, "ok");
            let expected = case.result.as_ref().expect("ok case holds the result");
            assert_eq!(result.total, expected.total);
            assert_eq!(result.ring_verifications, expected.ring_verifications);
        }
        (case, Err(error)) => panic!("batch ok case: {case:?} vs {error}"),
    }

    // The rejections, in the same order the vectors archive.
    let empty = match batch(&[], &mut warrant, 2, 101) {
        Err(error) => error_label(&error),
        Ok(outcome) => panic!("empty batch accepted: {outcome:?}"),
    };
    assert_eq!(empty, vectors.batch.empty.outcome);
    let outside = hex32(&(0xee.to_string().repeat(64)));
    let perimeter = match batch(
        &[
            antumbra_agents::Payment {
                dest: dests[0],
                amount: 1_000,
            },
            antumbra_agents::Payment {
                dest: outside,
                amount: 1_000,
            },
        ],
        &mut warrant,
        2,
        102,
    ) {
        Err(error) => error_label(&error),
        Ok(outcome) => panic!("outside perimeter accepted: {outcome:?}"),
    };
    assert_eq!(perimeter, vectors.batch.perimeter.outcome);
    let over_rate = match batch(
        &[
            antumbra_agents::Payment {
                dest: dests[0],
                amount: 6_000_000,
            },
            antumbra_agents::Payment {
                dest: dests[1],
                amount: 6_000_000,
            },
        ],
        &mut warrant,
        2,
        103,
    ) {
        Err(error) => error_label(&error),
        Ok(outcome) => panic!("over rate accepted: {outcome:?}"),
    };
    assert_eq!(over_rate, vectors.batch.over_rate.outcome);
    assert_eq!(warrant.state(), vectors.batch.after);
    // The protocol bound is archived with the vectors: a batch
    // this large must be refused, not clamped.
    let many = vec![
        antumbra_agents::Payment {
            dest: dests[0],
            amount: 1,
        };
        BATCH_MAX_PAYMENTS + 1
    ];
    assert!(batch(&many, &mut warrant, 3, 104).is_err());
}

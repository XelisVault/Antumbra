//! Cross-implementation vector tests for the labor market
//! (CONTRIBUTING.md, layer 1).
//!
//! The archived vector set in `tests/vectors.json` is produced
//! by `code/scripts/gen_jobs_vectors.py`, an independent Python
//! implementation of the pay-for-result formula, the capability
//! classes, the job grammar, the inverse auction and the
//! contest window, re-implemented from the ADR text alone. The
//! Rust implementation must agree bit for bit. A disagreement
//! here is not a test failure: it is a consensus fault, and it
//! blocks the phase.

use antumbra_jobs::{
    auction_winner, pay, Acceptance, Bid, Certification, Class, ContestOutcome, Exclusivity, Job,
    JobFactors, JobsError, Submission,
};
use antumbra_primitives::Hash;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    #[allow(dead_code)] // archived metadata, read for completeness
    format: u32,
    #[allow(dead_code)]
    comment: String,
    pay: Vec<PayVector>,
    class_from_score: Vec<ClassScoreVector>,
    class_descend: Vec<ClassDescendVector>,
    cert_valid: Vec<CertValidVector>,
    cert_recertify: Vec<CertRecertifyVector>,
    job: Vec<JobVector>,
    auction: Vec<AuctionVector>,
    contest: Vec<ContestVector>,
}

#[derive(Deserialize)]
struct PayVector {
    bounty: u64,
    quality_pm: u32,
    uniqueness_pm: u32,
    efficiency_pm: u32,
    diversity_pm: u32,
    slash_atomic: u64,
    rejection: Option<String>,
    #[serde(default)]
    pay: Option<u64>,
}

#[derive(Deserialize)]
struct ClassScoreVector {
    harness_score_pm: u32,
    class: String,
}

#[derive(Deserialize)]
struct ClassDescendVector {
    from: String,
    to: String,
}

#[derive(Deserialize)]
struct CertValidVector {
    issued_tick: u32,
    at_tick: u32,
    valid: bool,
}

#[derive(Deserialize)]
struct CertRecertifyVector {
    held: String,
    harness_score_pm: u32,
    tick: u32,
    class: String,
    issued_tick: u32,
}

#[derive(Deserialize)]
struct JobVector {
    #[allow(dead_code)] // archived name, read for completeness
    name: String,
    job_id: u32,
    bounty: u64,
    bond: u64,
    deadline: u32,
    reviewers: u32,
    spec_hash_hex: String,
    rejection: Option<String>,
    open_at_9_999: bool,
    open_at_10_001: bool,
}

#[derive(Deserialize)]
struct AuctionVector {
    #[allow(dead_code)] // archived name, read for completeness
    name: String,
    class_min: String,
    bids: Vec<BidVector>,
    winner: Option<u32>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct BidVector {
    bidder: u32,
    price: u64,
    efficiency_pm: u32,
    class: String,
}

#[derive(Deserialize)]
struct ContestVector {
    submitted_tick: u32,
    contest_tick: u32,
    proven_false: bool,
    bond: u64,
    outcome: String,
    #[serde(default)]
    slash: Option<u64>,
    bounty_transferred: Option<bool>,
}

fn class_of(label: &str) -> Class {
    Class::from_label(label).expect("the vector set only holds canonical labels")
}

fn error_label(error: &JobsError) -> String {
    match error {
        JobsError::MalformedJob { field, value } => format!("malformed_job:{field}:{value}"),
        JobsError::UnderQualified { class_min } => format!("under_qualified:{class_min}"),
        other => panic!("unexpected jobs error: {other}"),
    }
}

fn hex32(text: &str) -> Hash {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex byte");
    }
    Hash(out)
}

#[test]
fn pay_formula_agrees_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for vector in &vectors.pay {
        let factors = JobFactors {
            quality_pm: vector.quality_pm,
            uniqueness_pm: vector.uniqueness_pm,
            efficiency_pm: vector.efficiency_pm,
            diversity_pm: vector.diversity_pm,
            slash_atomic: vector.slash_atomic,
        };
        let outcome = pay(vector.bounty, &factors);
        match (&vector.rejection, &outcome) {
            (None, Ok(payed)) => {
                assert_eq!(Some(*payed), vector.pay, "the accepted case pays");
            }
            (Some(expected), Err(error)) => {
                assert_eq!(error_label(error), *expected);
            }
            other => panic!("inconsistent pay vector: {other:?}"),
        }
    }
}

#[test]
fn classes_agree_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for vector in &vectors.class_from_score {
        assert_eq!(
            Class::from_harness_score(vector.harness_score_pm).label(),
            vector.class
        );
    }
    for vector in &vectors.class_descend {
        assert_eq!(class_of(&vector.from).descend().label(), vector.to);
    }
    for vector in &vectors.cert_valid {
        let cert = Certification {
            class: Class::C2,
            issued_tick: vector.issued_tick,
        };
        assert_eq!(cert.valid_at(vector.at_tick), vector.valid);
    }
    for vector in &vectors.cert_recertify {
        let cert = Certification {
            class: class_of(&vector.held),
            issued_tick: 0,
        };
        let next = cert.recertify(vector.harness_score_pm, vector.tick);
        assert_eq!(next.class.label(), vector.class);
        assert_eq!(next.issued_tick, vector.issued_tick);
    }
}

#[test]
fn job_grammar_agrees_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for vector in &vectors.job {
        let job = Job {
            job_id: vector.job_id,
            class_min: Class::C1,
            spec_hash: hex32(&vector.spec_hash_hex),
            bounty_atomic: vector.bounty,
            bond_required_atomic: vector.bond,
            deadline_height: vector.deadline,
            exclusivity: Exclusivity::Open,
            acceptance: Acceptance::Reviewers {
                n: vector.reviewers as u8,
            },
            sealed: false,
        };
        let outcome = job.validate();
        match (&vector.rejection, &outcome) {
            (None, Ok(())) => {}
            (Some(expected), Err(error)) => {
                assert_eq!(error_label(error), *expected, "case {}", vector.name);
            }
            other => panic!("inconsistent job vector: {other:?}"),
        }
        if vector.deadline != 0 {
            assert_eq!(
                job.open_at(9_999),
                vector.open_at_9_999,
                "case {}",
                vector.name
            );
            assert_eq!(
                job.open_at(10_001),
                vector.open_at_10_001,
                "case {}",
                vector.name
            );
        }
    }
}

#[test]
fn auction_agrees_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for vector in &vectors.auction {
        let bids: Vec<Bid> = vector
            .bids
            .iter()
            .map(|b| Bid {
                bidder: b.bidder,
                price_atomic: b.price,
                efficiency_pm: b.efficiency_pm,
                class: class_of(&b.class),
            })
            .collect();
        let outcome = auction_winner(&bids, class_of(&vector.class_min));
        match (&vector.winner, &vector.error, &outcome) {
            (Some(expected), None, Ok(Some(winner))) => {
                assert_eq!(winner.bidder, *expected, "case {}", vector.name);
            }
            (None, None, Ok(None)) => {}
            (None, Some(expected), Err(error)) => {
                assert_eq!(error_label(error), *expected, "case {}", vector.name);
            }
            other => panic!("inconsistent auction vector: {other:?}"),
        }
    }
}

#[test]
fn contest_window_agrees_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for vector in &vectors.contest {
        let submission = Submission {
            job_id: 1,
            artifact_hash: Hash::ZERO,
            cost_declared_atomic: 1_000,
            model_id_hash: Hash::ZERO,
            tests_ok: true,
            submitted_tick: vector.submitted_tick,
        };
        let outcome = antumbra_jobs::contest(
            &submission,
            vector.contest_tick,
            vector.proven_false,
            vector.bond,
        );
        match (vector.outcome.as_str(), &outcome) {
            ("settled", ContestOutcome::Settled) => {
                assert_eq!(vector.slash, None);
            }
            ("live", ContestOutcome::Live) => {
                assert_eq!(vector.slash, None);
            }
            (
                "slashed",
                ContestOutcome::Slashed {
                    slash_atomic,
                    bounty_transferred,
                },
            ) => {
                assert_eq!(Some(*slash_atomic), vector.slash);
                assert_eq!(Some(*bounty_transferred), vector.bounty_transferred);
            }
            other => panic!("inconsistent contest vector: {other:?}"),
        }
    }
}

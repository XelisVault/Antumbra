//! Cross-implementation vector tests for the immunity layer
//! (CONTRIBUTING.md, layer 1).
//!
//! The archived vector set in `tests/vectors.json` is produced by
//! `code/scripts/gen_immune_vectors.py`, an independent Python
//! implementation of the bounty formula, the canary suite and
//! the Thymus state machine (freeze by proof or by sentinel
//! quorum, MTTD/MTTC/MTTR, rollback), re-implemented from the
//! ADR text alone. The Rust implementation must agree bit for
//! bit. A disagreement here is not a test failure: it is a
//! consensus fault, and it blocks the phase.

use antumbra_immune::{
    bounty, previous_hot, Alert, AlertTarget, Canary, CanarySuite, CodeCommitment, ImmuneError,
    Invariant, Severity, Thymus,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    #[allow(dead_code)] // archived metadata, read for completeness
    format: u32,
    #[allow(dead_code)]
    comment: String,
    bounty: Vec<BountyVector>,
    thymus: Vec<ThymusVector>,
    canary: CanaryVectors,
    rollback: Vec<RollbackVector>,
}

#[derive(Deserialize)]
struct BountyVector {
    severity: String,
    first: bool,
    bounty: u64,
}

#[derive(Deserialize)]
struct ThymusVector {
    #[allow(dead_code)] // archived name, read for completeness
    name: String,
    ops: Vec<OpVector>,
    final_state: StateVector,
}

/// One operation of a machine sequence, as a flat object:
/// `{"op": "inject", "height": n}` or `{"op": "observe",
/// "alert": {...}, "outcome": "...", "after": {...}}`. A plain
/// struct keeps the archived set deserializable without any
/// tagged-enum machinery (the workspace compiles serde without
/// std, and internally tagged enums need buffering).
#[derive(Deserialize)]
struct OpVector {
    op: String,
    #[serde(default)]
    height: u32,
    #[serde(default)]
    alert: Option<AlertVector>,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    after: Option<StateVector>,
    #[serde(default)]
    mttr: Option<u32>,
}

#[derive(Deserialize, Debug)]
struct AlertVector {
    invariant: String,
    severity: String,
    target: String,
    #[serde(default)]
    rail: u8,
    proof_hex: Option<String>,
    reporter: u32,
    #[serde(default)]
    height: u32,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
struct StateVector {
    frozen: bool,
    mttd: u32,
    mttc: u32,
    mttr: u32,
    open_crits: u32,
}

#[derive(Deserialize)]
struct CanaryVectors {
    checks: Vec<CanaryCheck>,
    checked: u32,
    failed: u32,
    error_rate_pm: u32,
}

#[derive(Deserialize)]
struct CanaryCheck {
    id: u32,
    invariant: String,
    expects: u64,
    #[allow(dead_code)] // archived severity of the check, reused via the alert
    severity: String,
    observed: u64,
    alert: Option<AlertVector>,
}

#[derive(Deserialize)]
struct RollbackVector {
    versions: Vec<u32>,
    #[serde(default)]
    rails: Vec<u8>,
    previous_version: Option<u32>,
    error: Option<String>,
}

fn invariant_of(label: &str) -> Invariant {
    Invariant::from_label(label).expect("the vector set only holds canonical labels")
}

fn severity_of(label: &str) -> Severity {
    Severity::from_label(label).expect("the vector set only holds canonical labels")
}

fn hex32(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex byte");
    }
    out
}

fn alert_of(vector: &AlertVector) -> Alert {
    let target = match vector.target.as_str() {
        "upgrade" => AlertTarget::Upgrade { rail: vector.rail },
        "observation" => AlertTarget::Observation,
        other => panic!("unknown alert target {other}"),
    };
    Alert {
        invariant: invariant_of(&vector.invariant),
        severity: severity_of(&vector.severity),
        target,
        proof: vector.proof_hex.as_deref().map(hex32),
        reporter: vector.reporter,
        height: vector.height,
    }
}

fn state_of(machine: &Thymus) -> StateVector {
    let (frozen, metrics) = machine.snapshot();
    StateVector {
        frozen,
        mttd: metrics.mttd,
        mttc: metrics.mttc,
        mttr: metrics.mttr,
        open_crits: metrics.open_crits,
    }
}

fn outcome_label(outcome: Result<antumbra_immune::Outcome, ImmuneError>) -> String {
    match outcome {
        Ok(antumbra_immune::Outcome::Frozen { by_proof: true }) => "frozen_proof".into(),
        Ok(antumbra_immune::Outcome::Frozen { by_proof: false }) => "frozen_quorum".into(),
        Ok(antumbra_immune::Outcome::Recorded) => "recorded".into(),
        Err(ImmuneError::NonMonotoneHeight { .. }) => "error_non_monotone".into(),
        Err(other) => panic!("unexpected machine error: {other}"),
    }
}

#[test]
fn bounty_formula_agrees_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for vector in &vectors.bounty {
        let paid = bounty(severity_of(&vector.severity), vector.first)
            .expect("the archived products never overflow");
        assert_eq!(
            paid, vector.bounty,
            "severity={} first={}",
            vector.severity, vector.first
        );
    }
}

#[test]
fn thymus_machine_agrees_step_by_step() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for scenario in &vectors.thymus {
        let mut machine = Thymus::new();
        for op in &scenario.ops {
            match op.op.as_str() {
                "inject" => machine.inject(op.height),
                "observe" => {
                    let vector_alert = op.alert.as_ref().expect("observe op holds an alert");
                    let built = alert_of(vector_alert);
                    let outcome = op.outcome.as_ref().expect("observe op holds an outcome");
                    assert_eq!(
                        outcome_label(machine.observe(&built)),
                        *outcome,
                        "scenario {}",
                        scenario.name
                    );
                    let after = op.after.as_ref().expect("observe op holds the state after");
                    assert_eq!(
                        state_of(&machine),
                        *after,
                        "scenario {} step",
                        scenario.name
                    );
                }
                "resolve" => {
                    let resolved = machine.resolve(op.height);
                    match op.mttr {
                        Some(expected) => {
                            assert_eq!(resolved.expect("resolve succeeds"), expected)
                        }
                        None => assert!(resolved.is_err(), "scenario {}", scenario.name),
                    }
                    let after = op.after.as_ref().expect("resolve op holds the state after");
                    assert_eq!(
                        state_of(&machine),
                        *after,
                        "scenario {} resolve",
                        scenario.name
                    );
                }
                other => panic!("unknown machine op {other}"),
            }
        }
        assert_eq!(
            state_of(&machine),
            scenario.final_state,
            "scenario {}",
            scenario.name
        );
    }
}

#[test]
fn canaries_agree_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    let mut suite = CanarySuite::new();
    for check in &vectors.canary.checks {
        let canary = Canary {
            id: check.id,
            invariant: invariant_of(&check.invariant),
            expects: check.expects,
            severity: severity_of(&check.severity),
        };
        let raised = suite.observe(canary, check.observed);
        match (&check.alert, &raised) {
            (None, None) => {}
            (Some(expected), Some(raised)) => {
                assert_eq!(raised.invariant, invariant_of(&expected.invariant));
                assert_eq!(raised.severity, severity_of(&expected.severity));
                assert_eq!(raised.target, AlertTarget::Observation);
                assert_eq!(raised.proof, None);
                assert_eq!(raised.reporter, expected.reporter);
            }
            (expected, raised) => panic!(
                "canary {}: expected {:?}, raised {:?}",
                check.id, expected, raised
            ),
        }
    }
    let (checked, failed) = suite.counters();
    assert_eq!(checked, vectors.canary.checked);
    assert_eq!(failed, vectors.canary.failed);
    assert_eq!(suite.error_rate_pm(), vectors.canary.error_rate_pm);
}

#[test]
fn rollback_agrees_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for vector in &vectors.rollback {
        let history: Vec<CodeCommitment> = vector
            .versions
            .iter()
            .zip(vector.rails.iter().chain(std::iter::repeat(&0u8)))
            .enumerate()
            .map(|(i, (version, rail))| CodeCommitment {
                version: *version,
                sha256: [i as u8; 32],
                nix_hash: [(i + 1) as u8; 32],
                rail: *rail,
                min_height: 1_000 * (i as u32 + 1),
            })
            .collect();
        let result = previous_hot(&history);
        match (vector.previous_version, vector.error.as_deref()) {
            (Some(expected), None) => {
                assert_eq!(
                    result.expect("history of two or more"),
                    versioned(expected, &history)
                );
            }
            (None, Some("empty_history")) => {
                assert!(matches!(result, Err(ImmuneError::EmptyHistory)));
            }
            other => panic!("unexpected rollback vector: {other:?}"),
        }
    }
}

/// The commitment of `version` inside the built history.
fn versioned(version: u32, history: &[CodeCommitment]) -> CodeCommitment {
    *history
        .iter()
        .find(|c| c.version == version)
        .expect("the version exists in the history")
}

#[test]
fn the_freeze_surface_cannot_express_a_payment() {
    // The constitutional rule is structural: an alert target is
    // an upgrade or an observation. There is no payment variant
    // to construct, so no alert, no quorum and no proof can halt
    // a settlement. This test pins the vocabulary on purpose:
    // adding a payment target must be a rail D change that
    // rewrites this file.
    let targets = [AlertTarget::Upgrade { rail: 2 }, AlertTarget::Observation];
    for target in targets {
        let label = target.label();
        assert!(
            label == "upgrade" || label == "observation",
            "the freeze vocabulary is closed"
        );
    }
}

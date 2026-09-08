//! Cross-implementation vector tests for the evolution layer
//! (CONTRIBUTING.md, layer 1).
//!
//! The archived vector set in `tests/vectors.json` is produced
//! by `code/scripts/gen_forge_vectors.py`, an independent
//! Python implementation of the merge predicate, the parameter
//! registry, the proposal machine, the debate structure and the
//! Senate tally, re-implemented from the ADR text alone. The
//! Rust implementation must agree bit for bit. A disagreement
//! here is not a test failure: it is a consensus fault, and it
//! blocks the phase.

use antumbra_forge::{
    change, dampen_pm, merge_ok, objection_counts, quorum_ok, tally, transition, Event, MergeFacts,
    Parameter, Proposal, Rail, Registry, State, Vote, ARG_EVIDENCE_WINDOW_TICKS,
    PARAM_COOLDOWN_HEIGHTS, RAMP_STAGES,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    #[allow(dead_code)] // archived metadata, read for completeness
    format: u32,
    #[allow(dead_code)]
    comment: String,
    rails: RailsVector,
    merge: Vec<MergeVector>,
    registry: RegistryVectors,
    proposal: Vec<ProposalVector>,
    debate: DebateVectors,
    tally: Vec<TallyVector>,
}

#[derive(Deserialize)]
struct RailsVector {
    f_min: std::collections::BTreeMap<String, u32>,
    fuzz: std::collections::BTreeMap<String, u64>,
    silence: std::collections::BTreeMap<String, bool>,
}

#[derive(Deserialize)]
struct MergeVector {
    #[allow(dead_code)] // archived name, read for completeness
    name: String,
    #[allow(dead_code)] // the facts carry the rail; the case name keeps it
    #[serde(default)]
    rail: String,
    facts: FactsVector,
    decision: String,
}

#[derive(Deserialize)]
struct FactsVector {
    rail: String,
    files_match_rail: bool,
    fuzz_seconds: u64,
    nix_builders: u32,
    ack_families: u32,
    open_critical_findings: u32,
    max_family_share_pm: u32,
    max_operator_share_pm: u32,
    bond_locked: bool,
    human_gate: bool,
    thymus_frozen: bool,
}

#[derive(Deserialize)]
struct RegistryVectors {
    genesis: Vec<ParameterVector>,
    #[allow(dead_code)] // archived constant, mirrored on both sides
    cooldown_heights: u32,
    cases: Vec<RegistryCase>,
}

#[derive(Deserialize, Clone)]
struct ParameterVector {
    #[allow(dead_code)] // archived key, matched by position
    key: String,
    min: u64,
    max: u64,
    value: u64,
    last_change_height: u32,
}

#[derive(Deserialize)]
struct RegistryCase {
    #[allow(dead_code)] // archived name, read for completeness
    name: String,
    key: String,
    value: u64,
    height: u32,
    rejection: Option<String>,
}

#[derive(Deserialize)]
struct ProposalVector {
    #[allow(dead_code)] // archived name, read for completeness
    name: String,
    rail: String,
    ops: Vec<ProposalOp>,
    final_state: String,
    final_pct: u32,
}

#[derive(Deserialize)]
struct ProposalOp {
    event: String,
    #[serde(default)]
    next: Option<String>,
    #[serde(default)]
    pct: u32,
    #[allow(dead_code)] // the refusal is matched by the None next
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    critical: u32,
}

#[derive(Deserialize)]
struct DebateVectors {
    claims: Vec<ClaimVector>,
    objections: Vec<ObjectionVector>,
    dampen: Vec<DampenVector>,
}

#[derive(Deserialize)]
struct ClaimVector {
    claim_tick: u32,
    evidence_tick: Option<u32>,
    at_tick: u32,
    live: bool,
}

#[derive(Deserialize)]
struct ObjectionVector {
    nacks: Vec<bool>,
    counted: u32,
}

#[derive(Deserialize)]
struct DampenVector {
    k: u32,
    pm: u32,
}

#[derive(Deserialize)]
struct TallyVector {
    #[allow(dead_code)] // archived name, read for completeness
    name: String,
    votes: Vec<VoteVector>,
    total: u64,
    families: u32,
    heaviest: u64,
    quorum: bool,
}

#[derive(Deserialize)]
struct VoteVector {
    voter: u32,
    kleos_mp: u64,
    family: u32,
}

fn rail_of(label: &str) -> Rail {
    Rail::from_label(label).expect("the vector set only holds canonical rails")
}

fn facts_of(vector: &FactsVector) -> MergeFacts {
    MergeFacts {
        rail: rail_of(&vector.rail),
        files_match_rail: vector.files_match_rail,
        fuzz_seconds: vector.fuzz_seconds,
        nix_builders: vector.nix_builders,
        ack_families: vector.ack_families,
        open_critical_findings: vector.open_critical_findings,
        max_family_share_pm: vector.max_family_share_pm,
        max_operator_share_pm: vector.max_operator_share_pm,
        bond_locked: vector.bond_locked,
        human_gate: vector.human_gate,
        thymus_frozen: vector.thymus_frozen,
    }
}

fn decision_label(decision: antumbra_forge::MergeDecision) -> String {
    match decision {
        antumbra_forge::MergeDecision::Merge => "merge".into(),
        antumbra_forge::MergeDecision::Refuse { clause } => clause.into(),
    }
}

fn event_of(label: &str, critical: u32) -> Event {
    match label {
        "bond_locked" => Event::BondLocked,
        "redteam_done" => Event::RedTeamDone {
            critical_findings: critical,
        },
        "specdiff_done" => Event::SpecDiffDone,
        "arena_green" => Event::ArenaGreen,
        "human_gate_passed" => Event::HumanGatePassed,
        "antechamber_green" => Event::AntechamberGreen,
        "canary_held" => Event::CanaryHeld,
        "ramp_stage" => Event::RampStage,
        "thymus_freeze" => Event::ThymusFreeze,
        "thymus_resolve" => Event::ThymusResolve,
        "invariant_broke" => Event::InvariantBroke,
        "abandoned" => Event::Abandoned,
        other => panic!("unknown event {other}"),
    }
}

fn state_label(state: State) -> (String, u32) {
    match state {
        State::Ramp { pct } => ("ramp".into(), pct),
        State::Frozen { pct } => ("frozen".into(), pct),
        other => (other.label().into(), 0),
    }
}

#[test]
fn rail_constants_agree() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for (label, f_min) in &vectors.rails.f_min {
        assert_eq!(rail_of(label).f_min(), *f_min, "rail {label}");
    }
    for (label, fuzz) in &vectors.rails.fuzz {
        assert_eq!(rail_of(label).min_fuzz_seconds(), *fuzz, "rail {label}");
    }
    for (label, silence) in &vectors.rails.silence {
        assert_eq!(
            rail_of(label).activates_on_silence(),
            *silence,
            "rail {label}"
        );
    }
}

#[test]
fn merge_predicate_agrees_clause_by_clause() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for vector in &vectors.merge {
        let facts = facts_of(&vector.facts);
        let decision = merge_ok(&facts).expect("the predicate never errors");
        assert_eq!(
            decision_label(decision),
            vector.decision,
            "case {}",
            vector.name
        );
    }
}

#[test]
fn registry_agrees_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    assert_eq!(PARAM_COOLDOWN_HEIGHTS, vectors.registry.cooldown_heights);

    // The genesis table: values, bands, keys.
    let genesis = Registry::genesis();
    for (i, archived) in vectors.registry.genesis.iter().enumerate() {
        let live = genesis.entries[i];
        assert_eq!(live.key, archived.key);
        assert_eq!(live.min, archived.min);
        assert_eq!(live.max, archived.max);
        assert_eq!(live.value, archived.value);
        assert_eq!(live.last_change_height, archived.last_change_height);
    }

    // The cases: every change attempt, accepted or refused.
    for case in &vectors.registry.cases {
        // The scenario state: the genesis entry, with the first
        // one pre-changed at height 1000 (the cooldown setup).
        let mut entry = match case.key.as_str() {
            "ghostdag_k" => {
                let mut p = Parameter::ghostdag_k();
                p.last_change_height = 1_000;
                p
            }
            "fee_floor_atomic" => Parameter::fee_floor(),
            "ring_size" => Parameter::ring_size(),
            "treasury_immunity_share_pm" => Parameter::immunity_share(),
            _ => Parameter {
                key: "unknown",
                min: 0,
                max: 0,
                value: 0,
                last_change_height: 0,
            },
        };
        let outcome = change(&mut entry, case.value, case.height);
        match (&case.rejection, &outcome) {
            (None, Ok(())) => {
                assert_eq!(entry.value, case.value);
                assert_eq!(entry.last_change_height, case.height);
            }
            (Some(expected), Err(error)) => {
                let label = match error {
                    antumbra_forge::ForgeError::OutOfBounds { key, value } => {
                        format!("out_of_bounds: {key} or {value}")
                    }
                    antumbra_forge::ForgeError::Cooldown { key, until } => {
                        format!("cooldown: {key} or {until}")
                    }
                    other => panic!("unexpected registry error: {other}"),
                };
                // The label names the kind; the detail is the
                // archived pair (key, offending value).
                let kind = expected.split(':').next().unwrap_or_default();
                assert!(
                    label.starts_with(kind),
                    "case {}: expected {expected}, got {label}",
                    case.name
                );
            }
            other => panic!("case {}: inconsistent registry vector {other:?}", case.name),
        }
    }
}

#[test]
fn proposal_machine_agrees_step_by_step() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for scenario in &vectors.proposal {
        let mut proposal = Proposal::new(rail_of(&scenario.rail));
        for op in &scenario.ops {
            let event = event_of(&op.event, op.critical);
            match op.next.as_deref() {
                Some(expected) => {
                    let next = transition(&mut proposal, event)
                        .unwrap_or_else(|e| panic!("case {}: {e}", scenario.name));
                    let (label, pct) = state_label(next);
                    assert_eq!(label, expected, "case {}", scenario.name);
                    assert_eq!(pct, op.pct, "case {}", scenario.name);
                }
                None => {
                    // The machine refuses: the state stays.
                    let error =
                        transition(&mut proposal, event).expect_err("the vector says refused");
                    let message = error.to_string();
                    assert!(
                        message.contains("cannot take"),
                        "case {}: expected a refusal, got {message}",
                        scenario.name
                    );
                }
            }
        }
        let (label, pct) = state_label(proposal.state);
        assert_eq!(label, scenario.final_state, "case {}", scenario.name);
        assert_eq!(pct, scenario.final_pct, "case {}", scenario.name);
    }
    assert_eq!(RAMP_STAGES, [1, 10, 100]);
}

#[test]
fn debate_agrees_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for claim in &vectors.debate.claims {
        let live = antumbra_forge::claim_live(claim.claim_tick, claim.evidence_tick, claim.at_tick);
        assert_eq!(live, claim.live);
    }
    for objection in &vectors.debate.objections {
        assert_eq!(objection_counts(&objection.nacks), objection.counted);
    }
    for step in &vectors.debate.dampen {
        assert_eq!(dampen_pm(step.k), step.pm, "k = {}", step.k);
    }
    assert_eq!(ARG_EVIDENCE_WINDOW_TICKS, 144);
}

#[test]
fn senate_tally_agrees_bit_for_bit() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors.json")).expect("well-formed vector set");
    for vector in &vectors.tally {
        let votes: Vec<Vote> = vector
            .votes
            .iter()
            .map(|v| Vote {
                voter: v.voter,
                kleos_agent_mp: v.kleos_mp,
                family: v.family,
            })
            .collect();
        let result = tally(&votes);
        assert_eq!(result.total_weight_mp, vector.total, "case {}", vector.name);
        assert_eq!(result.families, vector.families, "case {}", vector.name);
        assert_eq!(
            result.heaviest_family_weight_mp, vector.heaviest,
            "case {}",
            vector.name
        );
        assert_eq!(
            quorum_ok(&result).expect("the quorum never errors"),
            vector.quorum,
            "case {}",
            vector.name
        );
    }
}

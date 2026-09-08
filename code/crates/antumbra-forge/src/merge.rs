//! The merge predicate: agreement as a boolean function.

use crate::error::ForgeError;
use crate::rail::Rail;

/// The family share cap of every ack set: one model family at
/// or under thirty-three percent, or the merge refuses.
pub const FAMILY_CAP_PM: u32 = 330;

/// The operator share cap: one operator at or under eight
/// percent.
pub const OPERATOR_CAP_PM: u32 = 80;

/// How many builders must reproduce the artifact bit for bit.
pub const MIN_BUILDERS: u32 = 2;

/// What the predicate looks at: the archived facts of one
/// proposal at merge time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MergeFacts {
    /// The rail the proposal declares.
    pub rail: Rail,
    /// Whether the diff actually touches only files the rail
    /// may touch (the policy-as-code check).
    pub files_match_rail: bool,
    /// How long the Arena fuzzed, in seconds.
    pub fuzz_seconds: u64,
    /// How many distinct builders reproduced the binary.
    pub nix_builders: u32,
    /// How many distinct families acked.
    pub ack_families: u32,
    /// Open critical findings against the proposal.
    pub open_critical_findings: u32,
    /// The largest family share of the ack set, per mille.
    pub max_family_share_pm: u32,
    /// The largest operator share of the ack set, per mille.
    pub max_operator_share_pm: u32,
    /// Whether the proposer's bond is locked.
    pub bond_locked: bool,
    /// Whether the human gate passed: silence elapsed for the
    /// fluid rails, positive vote for the others.
    pub human_gate: bool,
    /// Whether Thymus froze upgrades at merge time.
    pub thymus_frozen: bool,
}

/// What the predicate decided.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MergeDecision {
    /// Merge and activate: the proposal survives this date, not
    /// forever (Thymus keeps looking).
    Merge,
    /// The refusal, with the first clause that broke.
    Refuse {
        /// The clause that refused, archived.
        clause: &'static str,
    },
}

/// The merge predicate of the Forge.
///
/// Every clause is checked in a fixed order, the first refusal
/// names its clause: a merge that cannot explain itself is a
/// merge nobody audited. Unanimity is not a clause anywhere:
/// the families must be distinct and numerous, not unanimous.
///
/// # Errors
///
/// Never: the refusal is a value ([`MergeDecision::Refuse`]),
/// not an error. Only an impossible fact set errors.
pub fn merge_ok(facts: &MergeFacts) -> Result<MergeDecision, ForgeError> {
    if !facts.files_match_rail {
        return Ok(MergeDecision::Refuse {
            clause: "files_do_not_match_rail",
        });
    }
    if facts.fuzz_seconds < facts.rail.min_fuzz_seconds() {
        return Ok(MergeDecision::Refuse {
            clause: "fuzz_under_floor",
        });
    }
    if facts.nix_builders < MIN_BUILDERS {
        return Ok(MergeDecision::Refuse {
            clause: "single_builder",
        });
    }
    if facts.ack_families < facts.rail.f_min() {
        return Ok(MergeDecision::Refuse {
            clause: "family_floor",
        });
    }
    if facts.open_critical_findings > 0 {
        return Ok(MergeDecision::Refuse {
            clause: "open_critical_findings",
        });
    }
    if facts.max_family_share_pm > FAMILY_CAP_PM {
        return Ok(MergeDecision::Refuse {
            clause: "family_cap",
        });
    }
    if facts.max_operator_share_pm > OPERATOR_CAP_PM {
        return Ok(MergeDecision::Refuse {
            clause: "operator_cap",
        });
    }
    if !facts.bond_locked {
        return Ok(MergeDecision::Refuse {
            clause: "bond_unlocked",
        });
    }
    if !facts.human_gate {
        return Ok(MergeDecision::Refuse {
            clause: "human_gate",
        });
    }
    if facts.thymus_frozen {
        return Ok(MergeDecision::Refuse {
            clause: "thymus_frozen",
        });
    }
    Ok(MergeDecision::Merge)
}

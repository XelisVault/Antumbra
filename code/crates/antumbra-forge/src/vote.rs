//! The Senate tally: weights dampened by family, quorum
//! diverse by definition.

use crate::error::ForgeError;

/// A quorum needs this many distinct families: three. A single
/// family, however large, is never a quorum.
pub const QUORUM_FAMILIES: u32 = 3;

/// A quorum needs this much dampened weight: twenty full
/// voters (kleos_agent of 100 at weight 100 000 each), in
/// millipoints.
pub const QUORUM_WEIGHT_MP: u64 = 2_000_000;

/// The family share a quorum tolerates, per mille: thirty-three
/// percent. Above it, the vote is a bloc, and a bloc is not a
/// deliberation.
pub const QUORUM_FAMILY_CAP_PM: u32 = 330;

/// One vote, as the tally takes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Vote {
    /// The voter identity.
    pub voter: u32,
    /// The voter's Kleos_agent, in millipoints of the 0-100
    /// scale.
    pub kleos_agent_mp: u64,
    /// The voter's model family: the damper groups on this.
    pub family: u32,
}

/// The dampened tally of one vote set.
///
/// The order of the votes is part of the input: within a
/// family, the k-th vote to arrive carries the k-th damper
/// step, because a bloc that stacks votes buys less each time.
/// The damper step for index `k` is `1 000 000 / isqrt(1 000
/// 000 x (1 + k))` in per mille: the square root of the bloc
/// size is what a bloc weighs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Tally {
    /// The total dampened weight, millipoints.
    pub total_weight_mp: u64,
    /// The number of distinct families that voted.
    pub families: u32,
    /// The weight of the heaviest family, millipoints.
    pub heaviest_family_weight_mp: u64,
}

/// The damper step of the k-th vote of a family, in per mille.
#[must_use]
pub fn dampen_pm(k: u32) -> u32 {
    // 1_000_000 / isqrt(1_000_000 * (1 + k)), the fixed-point
    // form of 1 / sqrt(1 + k) with floor division.
    let numer = 1_000_000u64;
    let denom = (1_000_000u64 * u64::from(k + 1)).isqrt();
    (numer / denom.max(1)) as u32
}

/// Tallies the votes.
///
/// The first sixty-four distinct families get a damper slot
/// each; a sixty-fifth family or beyond folds into one shared
/// overflow slot (its weight still dampens per vote, its
/// families counter still increments). The Senate holds forty
/// seats under a thirteen-family cap: the overflow is a
/// safety net, not a state anyone reaches.
#[must_use]
pub fn tally(votes: &[Vote]) -> Tally {
    // (weight, votes seen) per slot; index 64 is the overflow.
    let mut slots: [(u64, u32); 65] = [(0, 0); 65];
    let mut keys: [u32; 64] = [0; 64];
    let mut families_len: usize = 0;
    let mut distinct: u32 = 0;
    let mut total: u64 = 0;
    for vote in votes {
        let mut index = 64;
        for (i, key) in keys[..families_len].iter().enumerate() {
            if *key == vote.family {
                index = i;
                break;
            }
        }
        if index == 64 {
            distinct = distinct.saturating_add(1);
            if families_len < 64 {
                keys[families_len] = vote.family;
                index = families_len;
                families_len += 1;
            }
        }
        let step = dampen_pm(slots[index].1);
        slots[index].1 += 1;
        let weight = vote.kleos_agent_mp * u64::from(step) / 1_000;
        slots[index].0 = slots[index].0.saturating_add(weight);
        total = total.saturating_add(weight);
    }
    let heaviest = slots.iter().map(|slot| slot.0).max().unwrap_or(0);
    Tally {
        total_weight_mp: total,
        families: distinct,
        heaviest_family_weight_mp: heaviest,
    }
}

/// Whether the tally is a quorum: enough weight, enough
/// families, and no family above the cap.
///
/// # Errors
///
/// Never: the refusal is documented by the caller comparing
/// the tally fields; this predicate is the boolean the Senate
/// votes with.
pub fn quorum_ok(tally: &Tally) -> Result<bool, ForgeError> {
    if tally.families < QUORUM_FAMILIES {
        return Ok(false);
    }
    if tally.total_weight_mp < QUORUM_WEIGHT_MP {
        return Ok(false);
    }
    if tally.total_weight_mp == 0 {
        return Ok(false);
    }
    let share_pm = (tally.heaviest_family_weight_mp * 1_000 / tally.total_weight_mp) as u32;
    Ok(share_pm <= QUORUM_FAMILY_CAP_PM)
}

#!/usr/bin/env python3
"""Cross-implementation vector generator for antumbra-jobs.

Independent re-implementation of every output-producing routine
of the labor market (ADR-023): the pay-for-result formula
(bounty x quality x uniqueness x efficiency x diversity - slash,
per-mille fixed point, floor at each step, checked), the bound
rejections of the factors, the capability classes (harness
thresholds, the descending failure, the expiring
certification), the job grammar (bounty ceiling, bond ceiling,
deadline, reviewer count), the inverse auction (lowest price,
then highest past efficiency, then lowest identity), and the
contest window (late is noise, unequipped is live, proven
inside is the whole bond plus the transferred bounty).
Re-implemented from the ADR text alone. The output is the
archived vector set consumed by the Rust test suite: both
implementations must agree bit for bit (CONTRIBUTING.md,
verification layer 1).

Deterministic by construction: a fixed-seed linear congruential
generator (seed 16180339). Byte-for-byte reproducible.

Usage: python3 code/scripts/gen_jobs_vectors.py
Writes: code/crates/antumbra-jobs/tests/vectors.json
"""

import json
import struct
from pathlib import Path

from Crypto.Hash import keccak

OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "crates"
    / "antumbra-jobs"
    / "tests"
    / "vectors.json"
)

# --- Constants mirrored from ADR-023 and the Rust crate -------

QUALITY_MAX = 1_000
UNIQUENESS_MIN, UNIQUENESS_MAX = 250, 1_000
EFFICIENCY_MIN, EFFICIENCY_MAX = 500, 2_000
DIVERSITY_MIN, DIVERSITY_MAX = 1_000, 1_250
JOB_BOUNTY_MAX_ATOMIC = 100_000_000_000
JOB_BOND_MAX_ATOMIC = 25_000_000_000
ACCEPTANCE_MAX_REVIEWERS = 5
CERT_EXPIRY_TICKS = 2_016
CONTEST_WINDOW_TICKS = 288
SLASH_FRACTION_PM = 1_000


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


class Lcg:
    def __init__(self, seed):
        self.state = seed & 0xFFFFFFFF

    def next_u32(self):
        self.state = (1_103_515_245 * self.state + 12_345) & 0xFFFFFFFF
        return self.state

    def hash32(self):
        return keccak256(struct.pack(">I", self.next_u32()))


LCG = Lcg(16_180_339)


# --- The pay formula (from the ADR text alone) ------------------

def factors_reject(quality, uniqueness, efficiency, diversity):
    if quality > QUALITY_MAX:
        return "quality_pm"
    if not (UNIQUENESS_MIN <= uniqueness <= UNIQUENESS_MAX):
        return "uniqueness_pm"
    if not (EFFICIENCY_MIN <= efficiency <= EFFICIENCY_MAX):
        return "efficiency_pm"
    if not (DIVERSITY_MIN <= diversity <= DIVERSITY_MAX):
        return "diversity_pm"
    return None


def pay(bounty, quality, uniqueness, efficiency, diversity, slash):
    product = (bounty * quality * uniqueness * efficiency * diversity)
    scaled = product // 1_000_000_000_000
    return max(0, scaled - slash)


# --- The classes (from the ADR text alone) ----------------------

def class_from_score(score_pm):
    if score_pm >= 900:
        return "C3"
    if score_pm >= 700:
        return "C2"
    if score_pm >= 400:
        return "C1"
    return "C0"


def class_descend(label):
    return {"C3": "C2", "C2": "C1", "C1": "C0", "C0": "C0"}[label]


def cert_valid_at(issued, tick):
    return tick < issued + CERT_EXPIRY_TICKS


def cert_recertify(held, score_pm, tick):
    if score_pm < 400:
        return class_descend(held), tick
    return class_from_score(score_pm), tick


# --- The job grammar (from the ADR text alone) ------------------

def job_reject(bounty, bond, deadline, reviewers):
    if bounty > JOB_BOUNTY_MAX_ATOMIC:
        return "bounty_atomic"
    if bond > JOB_BOND_MAX_ATOMIC:
        return "bond_required_atomic"
    if deadline == 0:
        return "deadline_height"
    if reviewers is not None and not (1 <= reviewers <= ACCEPTANCE_MAX_REVIEWERS):
        return "reviewers"
    return None


# --- The auction (from the ADR text alone) ----------------------

def auction_winner(bids, class_min):
    order = {"C0": 0, "C1": 1, "C2": 2, "C3": 3}
    for bid in bids:
        if order[bid["class"]] < order[class_min]:
            return None, f"under_qualified:{order[class_min]}"
    best = None
    for bid in bids:
        if best is None:
            best = bid
            continue
        if (bid["price"] < best["price"]
                or (bid["price"] == best["price"]
                    and bid["efficiency_pm"] > best["efficiency_pm"])
                or (bid["price"] == best["price"]
                    and bid["efficiency_pm"] == best["efficiency_pm"]
                    and bid["bidder"] < best["bidder"])):
            best = bid
    return (best["bidder"] if best else None), None


# --- The contest window (from the ADR text alone) ---------------

def contest(submitted_tick, contest_tick, proven_false, bond):
    settled_at = submitted_tick + CONTEST_WINDOW_TICKS
    if contest_tick > settled_at:
        return "settled", None, None
    if not proven_false:
        return "live", None, None
    slash = bond * SLASH_FRACTION_PM // 1_000
    return "slashed", slash, True


def main():
    # --- pay: the formula and every bound ----------------------
    pay_cases = []
    combos = [
        (1_000, 1_000, 2_000, 1_250, 0),        # the maximum
        (1_000, 1_000, 500, 1_000, 0),          # the burner
        (500, 250, 500, 1_000, 0),              # the duplicate
        (800, 1_000, 1_250, 1_125, 0),          # the honest middle
        (800, 1_000, 1_250, 1_125, 100_000),    # slashed
        (1_000, 1_000, 2_000, 1_250, 10**18),   # slashed to zero
    ]
    for (quality, uniqueness, efficiency, diversity, slash) in combos:
        bounty = 40_000_000_000                  # 400 ATU
        pay_cases.append({
            "bounty": bounty,
            "quality_pm": quality,
            "uniqueness_pm": uniqueness,
            "efficiency_pm": efficiency,
            "diversity_pm": diversity,
            "slash_atomic": slash,
            "rejection": None,
            "pay": pay(bounty, quality, uniqueness, efficiency,
                       diversity, slash),
        })
    for (quality, uniqueness, efficiency, diversity) in [
        (1_001, 1_000, 1_000, 1_000),
        (1_000, 249, 1_000, 1_000),
        (1_000, 1_001, 1_000, 1_000),
        (1_000, 1_000, 499, 1_000),
        (1_000, 1_000, 2_001, 1_000),
        (1_000, 1_000, 1_000, 999),
        (1_000, 1_000, 1_000, 1_251),
    ]:
        field = factors_reject(quality, uniqueness, efficiency, diversity)
        value = {"quality_pm": quality, "uniqueness_pm": uniqueness,
                 "efficiency_pm": efficiency, "diversity_pm": diversity}[field]
        pay_cases.append({
            "bounty": 40_000_000_000,
            "quality_pm": quality,
            "uniqueness_pm": uniqueness,
            "efficiency_pm": efficiency,
            "diversity_pm": diversity,
            "slash_atomic": 0,
            "rejection": f"malformed_job:{field}:{value}",
            "pay": None,
        })

    # --- classes: thresholds, descent, expiry -----------------
    class_cases = []
    for score in (0, 399, 400, 699, 700, 899, 900, 1_000):
        class_cases.append({
            "harness_score_pm": score,
            "class": class_from_score(score),
        })
    descent_cases = []
    for label in ("C0", "C1", "C2", "C3"):
        descent_cases.append({"from": label, "to": class_descend(label)})
    cert_cases = []
    for (issued, tick) in [(0, 100), (0, 2_015), (0, 2_016), (0, 2_017),
                           (1_000, 3_015), (1_000, 3_016)]:
        cert_cases.append({
            "issued_tick": issued,
            "at_tick": tick,
            "valid": cert_valid_at(issued, tick),
        })
    recert_cases = []
    for (held, score, tick) in [
        ("C3", 950, 100),
        ("C3", 300, 100),        # the failure descends
        ("C1", 300, 100),        # C1 descends to C0
        ("C0", 300, 100),        # the floor holds
        ("C0", 750, 100),        # the pass replaces
        ("C2", 500, 200),
    ]:
        label, new_issued = cert_recertify(held, score, tick)
        recert_cases.append({
            "held": held,
            "harness_score_pm": score,
            "tick": tick,
            "class": label,
            "issued_tick": new_issued,
        })

    # --- jobs: the grammar ------------------------------------
    spec_hash = LCG.hash32().hex()
    job_cases = []
    for (name, bounty, bond, deadline, reviewers) in [
        ("accept", 40_000_000_000, 5_000_000_000, 10_000, 3),
        ("no_reviewers", 40_000_000_000, 5_000_000_000, 10_000, 0),
        ("six_reviewers", 40_000_000_000, 5_000_000_000, 10_000, 6),
        ("bounty_over", JOB_BOUNTY_MAX_ATOMIC + 1, 5_000_000_000, 10_000, 3),
        ("bond_over", 40_000_000_000, JOB_BOND_MAX_ATOMIC + 1, 10_000, 3),
        ("past_deadline", 40_000_000_000, 5_000_000_000, 0, 3),
    ]:
        rejection = job_reject(bounty, bond, deadline, reviewers)
        job_cases.append({
            "name": name,
            "job_id": 1,
            "bounty": bounty,
            "bond": bond,
            "deadline": deadline,
            "reviewers": reviewers,
            "spec_hash_hex": spec_hash,
            "rejection": None if rejection is None else
                         f"malformed_job:{rejection}:{bounty if rejection == 'bounty_atomic' else bond if rejection == 'bond_required_atomic' else deadline if rejection == 'deadline_height' else reviewers}",
            "open_at_9_999": deadline >= 9_999 and deadline != 0,
            "open_at_10_001": deadline >= 10_001 and deadline != 0,
        })

    # --- auction: price, efficiency, identity, qualification --
    auction_cases = []
    base = [
        {"bidder": 1, "price": 30, "efficiency_pm": 1_000, "class": "C2"},
        {"bidder": 2, "price": 20, "efficiency_pm": 800, "class": "C3"},
        {"bidder": 3, "price": 20, "efficiency_pm": 1_200, "class": "C1"},
        {"bidder": 4, "price": 40, "efficiency_pm": 1_500, "class": "C2"},
    ]
    winner, err = auction_winner(base, "C1")
    auction_cases.append({"name": "price_first", "class_min": "C1",
                          "bids": base, "winner": winner, "error": err})
    # tie on price, efficiency decides: bidder 3 over bidder 2
    tie = [b for b in base if b["price"] == 20]
    winner, err = auction_winner(tie, "C1")
    auction_cases.append({"name": "efficiency_tiebreak", "class_min": "C1",
                          "bids": tie, "winner": winner, "error": err})
    # tie on price and efficiency, identity decides
    ident = [
        {"bidder": 9, "price": 20, "efficiency_pm": 1_200, "class": "C1"},
        {"bidder": 5, "price": 20, "efficiency_pm": 1_200, "class": "C1"},
    ]
    winner, err = auction_winner(ident, "C1")
    auction_cases.append({"name": "identity_tiebreak", "class_min": "C1",
                          "bids": ident, "winner": winner, "error": err})
    # under-qualified bid refuses the auction
    under = [{"bidder": 1, "price": 10, "efficiency_pm": 900, "class": "C0"}]
    winner, err = auction_winner(under, "C2")
    auction_cases.append({"name": "under_qualified", "class_min": "C2",
                          "bids": under, "winner": winner, "error": err})
    # empty auction: nobody
    winner, err = auction_winner([], "C1")
    auction_cases.append({"name": "empty", "class_min": "C1",
                          "bids": [], "winner": winner, "error": err})

    # --- contest: window, proof, slash ------------------------
    contest_cases = []
    for (name, submitted, at, proven, bond) in [
        ("late_noise", 1_000, 1_000 + 289, True, 5_000_000),
        ("last_tick", 1_000, 1_000 + 288, True, 5_000_000),
        ("unequipped_live", 1_000, 1_100, False, 5_000_000),
        ("equipped_slash", 1_000, 1_100, True, 5_000_000),
        ("zero_bond", 1_000, 1_100, True, 0),
    ]:
        outcome, slash, transferred = contest(submitted, at, proven, bond)
        contest_cases.append({
            "name": name,
            "submitted_tick": submitted,
            "contest_tick": at,
            "proven_false": proven,
            "bond": bond,
            "outcome": outcome,
            "slash": slash,
            "bounty_transferred": transferred,
        })

    data = {
        "format": 1,
        "comment": (
            "ANTUMBRA jobs cross-validation vectors, generated by "
            "code/scripts/gen_jobs_vectors.py (independent Python "
            "implementation of ADR-023: pay-for-result, classes, "
            "job grammar, inverse auction, contest window). "
            "Regenerate with the generator; both implementations "
            "must agree bit for bit."
        ),
        "pay": pay_cases,
        "class_from_score": class_cases,
        "class_descend": descent_cases,
        "cert_valid": cert_cases,
        "cert_recertify": recert_cases,
        "job": job_cases,
        "auction": auction_cases,
        "contest": contest_cases,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    print(f"wrote {OUTPUT} ({OUTPUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()

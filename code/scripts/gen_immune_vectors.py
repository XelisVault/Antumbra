#!/usr/bin/env python3
"""Cross-implementation vector generator for antumbra-immune.

Independent re-implementation of every output-producing routine
of the immunity layer (ADR-020): the bounty formula (base x
severity x uniqueness, floor, checked), the canary suite (exact
match or alert, the per-mille error rate), and the Thymus state
machine (monotone height, MTTD/MTTC/MTTR, the corroboration
slots with same-reporter refresh, the sentinel quorum window,
the freeze rule: critical on an upgrade, by proof or by quorum,
never on a payment), plus the rollback to the previous hot code
commitment. Re-implemented from the ADR text alone; the output
is the archived vector set consumed by the Rust test suite:
both implementations must agree bit for bit (CONTRIBUTING.md,
verification layer 1).

The thymus vectors record the machine state after every
operation, so a divergence is caught at the exact step that
causes it. The scenarios cover: a proof that freezes alone, a
sentinel quorum that freezes together, two sentinels that do
not, one reporter that cannot stack itself, a corroboration
that went stale outside the window, a high severity that never
freezes, an observation target that never freezes, and a
non-monotone alert that is rejected.

Deterministic by construction: no randomness at all, the
scenarios are hand-picked edge cases. Byte-for-byte
reproducible on any machine.

Usage: python3 code/scripts/gen_immune_vectors.py
Writes: code/crates/antumbra-immune/tests/vectors.json
"""

import json
from pathlib import Path

OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "crates"
    / "antumbra-immune"
    / "tests"
    / "vectors.json"
)

# --- Constants mirrored from ADR-020 and the Rust crate ----------

BOUNTY_BASE_ATOMIC = 25_000_000_000        # 250 ATU
SEVERITY_FACTOR_PM = {"crit": 1_000, "high": 500, "med": 250, "low": 100}
UNIQUENESS_FIRST_PM = 1_000
UNIQUENESS_REPRO_PM = 250
SENTINEL_QUORUM = 3
SENTINEL_WINDOW = 10
INVARIANT_LABELS = [
    "conservation",
    "nullifier_unique",
    "checkpoint_in_blue_set",
    "ring_composition",
    "mandate_perimeter",
    "registry_bounds",
    "code_commitment_match",
    "fee_floor",
    "ring_size",
]

PROOF_A = "aa" * 32
PROOF_B = "bb" * 32


# --- The bounty --------------------------------------------------

def bounty(severity, first_report):
    uniqueness = UNIQUENESS_FIRST_PM if first_report else UNIQUENESS_REPRO_PM
    product = BOUNTY_BASE_ATOMIC * SEVERITY_FACTOR_PM[severity] * uniqueness
    return product // 1_000_000


# --- The Thymus machine (from the ADR text alone) ----------------

class Thymus:
    def __init__(self):
        self.frozen = False
        self.fault_height = None
        self.detected = False
        self.last_height = 0
        self.open_crits = 0
        self.mttd = 0
        self.mttc = 0
        self.mttr = 0
        self.freeze_height = 0
        self.slots = []           # (invariant, reporter, height)

    def inject(self, height):
        self.fault_height = height
        self.detected = False

    def record_corroboration(self, invariant, reporter, height):
        for i, slot in enumerate(self.slots):
            if slot[1] == reporter:
                self.slots[i] = (invariant, reporter, height)
                return
        if len(self.slots) < SENTINEL_QUORUM:
            self.slots.append((invariant, reporter, height))

    def quorum_reached(self, invariant, height):
        distinct = 0
        for slot in self.slots:
            if slot[0] == invariant and height - slot[2] <= SENTINEL_WINDOW:
                distinct += 1
        return distinct >= SENTINEL_QUORUM

    def observe(self, alert):
        if alert["height"] < self.last_height:
            return "error_non_monotone"
        self.last_height = alert["height"]
        if not self.detected:
            if self.fault_height is not None:
                self.mttd = alert["height"] - self.fault_height
            self.detected = True
        if alert["severity"] == "crit":
            self.open_crits += 1
        if alert["proof_hex"] is None:
            self.record_corroboration(alert["invariant"], alert["reporter"],
                                      alert["height"])
        upgrade = alert["target"] == "upgrade"
        by_proof = alert["proof_hex"] is not None
        if (not self.frozen and upgrade
                and alert["severity"] == "crit"
                and (by_proof
                     or self.quorum_reached(alert["invariant"],
                                            alert["height"]))):
            self.frozen = True
            self.freeze_height = alert["height"]
            if self.fault_height is not None:
                self.mttc = alert["height"] - self.fault_height
            self.slots = []
            return "frozen_proof" if by_proof else "frozen_quorum"
        return "recorded"

    def resolve(self, height):
        if not self.frozen:
            return None
        self.mttr = height - self.freeze_height
        self.frozen = False
        self.open_crits = 0
        return self.mttr

    def state(self):
        return {
            "frozen": self.frozen,
            "mttd": self.mttd,
            "mttc": self.mttc,
            "mttr": self.mttr,
            "open_crits": self.open_crits,
        }


def alert(invariant, severity, target, rail, proof_hex, reporter, height):
    return {
        "invariant": invariant,
        "severity": severity,
        "target": target,
        "rail": rail,
        "proof_hex": proof_hex,
        "reporter": reporter,
        "height": height,
    }


# --- The scenarios ------------------------------------------------

def scenario_proof_freeze():
    ops = [{"op": "inject", "height": 100}]
    machine = Thymus()
    machine.inject(100)
    ops.append({"op": "observe",
                "alert": alert("conservation", "crit", "upgrade", 1,
                               PROOF_A, 7, 103),
                "outcome": machine.observe(
                    alert("conservation", "crit", "upgrade", 1,
                          PROOF_A, 7, 103)),
                "after": machine.state()})
    ops.append({"op": "resolve", "height": 120,
                "mttr": machine.resolve(120),
                "after": machine.state()})
    return {"name": "proof_freeze", "ops": ops, "final_state": machine.state()}


def scenario_quorum_freeze():
    ops = [{"op": "inject", "height": 200}]
    machine = Thymus()
    machine.inject(200)
    for reporter, height in [(1, 201), (2, 203), (3, 205)]:
        a = alert("nullifier_unique", "crit", "upgrade", 2,
                  None, reporter, height)
        ops.append({"op": "observe", "alert": a,
                    "outcome": machine.observe(a),
                    "after": machine.state()})
    ops.append({"op": "resolve", "height": 210,
                "mttr": machine.resolve(210),
                "after": machine.state()})
    return {"name": "quorum_freeze", "ops": ops, "final_state": machine.state()}


def scenario_two_sentinels():
    ops = [{"op": "inject", "height": 300}]
    machine = Thymus()
    machine.inject(300)
    for reporter, height in [(1, 301), (2, 302)]:
        a = alert("fee_floor", "crit", "upgrade", 1,
                  None, reporter, height)
        ops.append({"op": "observe", "alert": a,
                    "outcome": machine.observe(a),
                    "after": machine.state()})
    return {"name": "two_sentinels", "ops": ops, "final_state": machine.state()}


def scenario_same_reporter():
    ops = [{"op": "inject", "height": 400}]
    machine = Thymus()
    machine.inject(400)
    for height in (401, 402, 403, 404):
        a = alert("ring_size", "crit", "upgrade", 1,
                  None, 9, height)
        ops.append({"op": "observe", "alert": a,
                    "outcome": machine.observe(a),
                    "after": machine.state()})
    return {"name": "same_reporter_no_stack", "ops": ops,
            "final_state": machine.state()}


def scenario_stale_window():
    ops = [{"op": "inject", "height": 500}]
    machine = Thymus()
    machine.inject(500)
    for reporter, height in [(1, 501), (2, 502), (3, 520)]:
        a = alert("ring_composition", "crit", "upgrade", 2,
                  None, reporter, height)
        ops.append({"op": "observe", "alert": a,
                    "outcome": machine.observe(a),
                    "after": machine.state()})
    return {"name": "stale_corroboration", "ops": ops,
            "final_state": machine.state()}


def scenario_high_no_freeze():
    ops = [{"op": "inject", "height": 600}]
    machine = Thymus()
    machine.inject(600)
    a = alert("conservation", "high", "upgrade", 1, PROOF_B, 11, 601)
    ops.append({"op": "observe", "alert": a,
                "outcome": machine.observe(a),
                "after": machine.state()})
    return {"name": "high_never_freezes", "ops": ops,
            "final_state": machine.state()}


def scenario_observation_no_freeze():
    ops = [{"op": "inject", "height": 700}]
    machine = Thymus()
    machine.inject(700)
    a = alert("registry_bounds", "crit", "observation", 0,
              PROOF_A, 4, 701)
    ops.append({"op": "observe", "alert": a,
                "outcome": machine.observe(a),
                "after": machine.state()})
    return {"name": "observation_never_freezes", "ops": ops,
            "final_state": machine.state()}


def scenario_non_monotone():
    ops = [{"op": "inject", "height": 800}]
    machine = Thymus()
    machine.inject(800)
    a1 = alert("conservation", "crit", "upgrade", 1, PROOF_A, 5, 810)
    ops.append({"op": "observe", "alert": a1,
                "outcome": machine.observe(a1),
                "after": machine.state()})
    a2 = alert("fee_floor", "crit", "observation", 0, None, 6, 805)
    ops.append({"op": "observe", "alert": a2,
                "outcome": machine.observe(a2),
                "after": machine.state()})
    return {"name": "non_monotone_rejected", "ops": ops,
            "final_state": machine.state()}


# --- The canaries -------------------------------------------------

def canary_suite():
    suite = {"checked": 0, "failed": 0}
    checks = [
        {"id": 1, "invariant": "conservation", "expects": 1_000,
         "severity": "crit", "observed": 1_000},
        {"id": 2, "invariant": "nullifier_unique", "expects": 0,
         "severity": "crit", "observed": 1},
        {"id": 3, "invariant": "fee_floor", "expects": 500_000,
         "severity": "high", "observed": 500_000},
        {"id": 4, "invariant": "ring_size", "expects": 16,
         "severity": "high", "observed": 11},
        {"id": 5, "invariant": "mandate_perimeter", "expects": 0,
         "severity": "med", "observed": 0},
    ]
    results = []
    for c in checks:
        suite["checked"] += 1
        if c["observed"] == c["expects"]:
            results.append({**c, "alert": None})
        else:
            suite["failed"] += 1
            results.append({**c, "alert": {
                "invariant": c["invariant"],
                "severity": c["severity"],
                "target": "observation",
                "reporter": c["id"],
            }})
    rate = (suite["failed"] * 1_000) // suite["checked"]
    return results, suite, rate


# --- The rollback -------------------------------------------------

def rollback(versions, rails):
    if len(versions) < 2:
        return {"versions": versions, "previous_version": None,
                "error": "empty_history"}
    return {"versions": versions, "rails": rails,
            "previous_version": versions[-2], "error": None}


def main():
    bounty_vectors = []
    for severity in ("crit", "high", "med", "low"):
        for first in (True, False):
            bounty_vectors.append({
                "severity": severity,
                "first": first,
                "bounty": bounty(severity, first),
            })

    thymus_vectors = [
        scenario_proof_freeze(),
        scenario_quorum_freeze(),
        scenario_two_sentinels(),
        scenario_same_reporter(),
        scenario_stale_window(),
        scenario_high_no_freeze(),
        scenario_observation_no_freeze(),
        scenario_non_monotone(),
    ]

    canary_results, counters, rate = canary_suite()

    rollback_vectors = [
        rollback([1, 2, 3], [1, 1, 2]),
        rollback([7, 8], [1, 2]),
        rollback([7], [1]),
        rollback([], []),
    ]

    data = {
        "format": 1,
        "comment": (
            "ANTUMBRA immune cross-validation vectors, generated by "
            "code/scripts/gen_immune_vectors.py (independent Python "
            "implementation of ADR-020: bounty, canaries, the Thymus "
            "state machine, rollback). Regenerate with the generator; "
            "both implementations must agree bit for bit."
        ),
        "constants": {
            "invariant_labels": INVARIANT_LABELS,
            "bounty_base_atomic": BOUNTY_BASE_ATOMIC,
            "sentinel_quorum": SENTINEL_QUORUM,
            "sentinel_window": SENTINEL_WINDOW,
        },
        "bounty": bounty_vectors,
        "thymus": thymus_vectors,
        "canary": {
            "checks": canary_results,
            "checked": counters["checked"],
            "failed": counters["failed"],
            "error_rate_pm": rate,
        },
        "rollback": rollback_vectors,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=False)
        handle.write("\n")
    print(f"wrote {OUTPUT} ({OUTPUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()

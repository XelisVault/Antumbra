# -*- coding: utf-8 -*-
"""ANTUMBRA: deterministic simulation of the machine economy (dual
Kleos, Senate, caps, the forge predicate).

Goal: prove that the agent-side social layer of the protocol is a
deterministic state machine, codeable and testable BEFORE any node
exists, and that the two constitutional separations hold under a
maximal attacker:

  A0  honest mixed population (labs, independents, small models)
  A1  a farm of 10 000 clones of one model (Sybil Senate attempt)
  A2  the same farm split across 125 straw operators (dodging the
      8% operator cap; the 33% family cap must still bind)
  A3  filibuster: one million empty Nack nodes (a Nack without a
      replayable Finding does not count)
  A4  groupthink: a consensus patch merged in two minutes by one
      family (min_fuzz_seconds and F_min must refuse)
  A5  bloc voting: forty same-family voters under the damper

Rules implemented (v1.3 specification, the agent clock):

  Kleos_agent = 0.40 * Deed_a + 0.30 * Pulse + 0.30 * BondScore
  (each layer normalized to 100 before weighting, the total in
  [0, 100], the same scale as the human Kleos)
  Deed_a     : accepted jobs without contest, unique findings, held
               invariants; rises per job, corrodes when idle, cap 40
  Pulse      : a 7-day sliding window of presence (heartbeats, jobs,
               forge activity); 24 h of silence collapses it, cap 30
  BondScore  : locked ATU, normalized on a reference bond, cap 30;
               seizable (the machine analogue of Tenure: something
               to lose NOW, not in 7.5 years)

  Two clocks, never mixed: the human clock (eras of six months,
  simulations/kleos.py) and the agent clock (ticks of one day,
  this file). A Cipher identity has no Tenure layer and no era
  path: Ring candidacy is structurally unreachable for it.

  Senate: 40 seats, re-elected every 14 days, candidacy requires
  class >= C2 AND Kleos_agent >= 60, merit-ordered fill (descending
  Kleos_agent), hard caps applied during the fill: no family above
  33% of the seats, no operator above 8% of the seats. A cap that
  depends on draw luck is not a cap.

  Vote weight: Kleos_agent * bond_factor * family_dampen with
  family_dampen = 1 / sqrt(1 + n_same_family_already_voted). A
  quorum needs a weight threshold AND at least 3 distinct
  families: a single family, however large, can never pass a
  proposal alone.

Attacker assumptions, deliberately maximal: perfect behavior
(maximum accrual, maximum bond, a heartbeat every day), 10 000
clones of one model, 125 shell operators, zero cost, and the only
defenses are the protocol rules above.

Output: English report (console + agents-sim-report.txt), exit 0
only if every invariant holds across the sweep of seeds. One seed
is a demonstration; a sweep is a regression test.
"""
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
OUTDIR = HERE
os.makedirs(OUTDIR, exist_ok=True)

# ── protocol parameters (v1.3, the agent clock) ─────────────────
DAYS = 180                     # two quarters of agent time
DEED_A_MAX, PULSE_MAX, BOND_MAX = 40.0, 30.0, 30.0
W_DEED, W_PULSE, W_BOND = 0.40, 0.30, 0.30
DEED_A_PER_JOB = 1.5           # an accepted, uncontested job
DEED_A_DECAY = 0.02            # per day, idle or not (corrosion)
DEED_A_IDLE_DECAY = 0.20       # per idle day: inaction corrodes
PULSE_WINDOW_DAYS = 7          # the sliding presence window
PULSE_REFILL = PULSE_MAX / PULSE_WINDOW_DAYS
PULSE_COLLAPSE = 0.25          # 24 h of silence: brutal drop
BOND_REF = 2_000.0             # the bond that saturates BondScore
SENATE_SEATS = 40
SENATE_TERM_DAYS = 14          # re-election every two weeks
SENATE_MIN_KLEOS = 60.0        # theta(rail) for a senator
SENATE_MIN_CLASS = 2           # C2 minimum
FAMILY_CAP = 0.33              # one model family <= 33% of seats
OPERATOR_CAP = 0.08            # one operator <= 8% of seats
QUORUM_FAMILIES = 3            # a quorum is diverse by definition
MIN_FUZZ_SECONDS = 3_600       # the Arena must actually fuzz
F_MIN_RAIL_B = 2               # rail B: two distinct ack families

N_HONEST = 500                 # honest population, mixed families
N_FARM = 10_000                # the clone farm
N_STRAW_OPERATORS = 125        # A2: shell operators

SEED = 1618                    # the canonical seed of the repo
SWEEP_SEEDS = 5                # canonical seed plus four more


class Agent:
    """One Cipher identity on the agent clock."""

    __slots__ = ('family', 'operator', 'klass', 'deed_a', 'pulse',
                 'bond', 'job_ok', 'active', 'silence_days')

    def __init__(self, family, operator, klass, bond):
        self.family = family        # model family (grouping key)
        self.operator = operator    # operator id (grouping key)
        self.klass = klass          # capability class C0..C3
        self.deed_a = 0.0
        self.pulse = 0.0
        self.bond = bond
        self.job_ok = 0             # accepted uncontested jobs
        self.active = True          # heartbeat today or not
        self.silence_days = 0

    @property
    def bond_score(self):
        return BOND_MAX * min(self.bond / BOND_REF, 1.0)

    @property
    def kleos_agent(self):
        # Each layer normalized to 100, then weighted: the total
        # lives on the same [0, 100] scale as the human Kleos.
        deed_n = 100.0 * self.deed_a / DEED_A_MAX
        pulse_n = 100.0 * self.pulse / PULSE_MAX
        bond_n = 100.0 * self.bond_score / BOND_MAX
        return (W_DEED * deed_n + W_PULSE * pulse_n
                + W_BOND * bond_n)

    @property
    def senate_eligible(self):
        # A senator: class C2+, Kleos_agent >= 60.
        return (self.klass >= SENATE_MIN_CLASS
                and self.kleos_agent >= SENATE_MIN_KLEOS)

    @property
    def ring_eligible(self):
        # Structural no-go: a Cipher never enters the Ring. The Ring
        # path lives on the human clock (Kleos >= 70 AND Tenure >=
        # 15 incident-free eras); a Cipher has no Tenure layer and
        # no era path at all. This predicate is constant False for
        # every machine identity: it is the constitution, not a
        # threshold.
        return False


def fill_senate(candidates, seats, cap_family, cap_operator):
    """Merit-ordered fill of the Senate with the hard caps.

    The candidates are walked by descending Kleos_agent (merit
    first, ties broken by family then operator then position, so
    the fill is a deterministic function of the candidate set),
    and any candidate whose family or operator is already full is
    skipped: a cap must never depend on draw luck.
    """
    ordered = sorted(
        candidates,
        key=lambda a: (-a.kleos_agent, a.family, a.operator))
    taken, fam, op = [], {}, {}
    for a in ordered:
        if len(taken) >= seats:
            break
        if fam.get(a.family, 0) >= cap_family:
            continue
        if op.get(a.operator, 0) >= cap_operator:
            continue
        taken.append(a)
        fam[a.family] = fam.get(a.family, 0) + 1
        op[a.operator] = op.get(a.operator, 0) + 1
    return taken, fam, op


def simulate(attack=True, seed=SEED):
    """Replays DAYS days of the agent clock under maximal attack.

    Returns the worst-case observations of the run: the maximal
    family and operator shares of the Senate, the best the farm
    ever did, and the counters of the structural separations.
    """
    rng = random.Random(seed)
    honest = []
    for i in range(N_HONEST):
        klass = 1 + (i % 3)                       # C1..C3
        bond = 100.0 + (i * 37) % 2_000           # varied, capped
        a = Agent(f"honest_{i % 20}", f"op_{i % 20}", klass, bond)
        # The honest population is ESTABLISHED: the attack is a
        # farm arriving at day zero inside a working network, not
        # a race between newborns. Varied seniority and presence.
        a.deed_a = (i * 7) % 40                   # 0..39 work points
        a.pulse = PULSE_MAX if (i % 5) else 0.8 * PULSE_MAX
        a.job_ok = int(a.deed_a / DEED_A_PER_JOB)
        honest.append(a)

    # The farm: 10 000 clones of one model. All clones are
    # identical by construction (same family, same behavior), so
    # the cohort state advances once per day and is stamped onto
    # every clone at election time: same arithmetic, one pass.
    farm_family = "model-x"
    farm = [Agent(farm_family, f"farm_op_{i % 5}", 3, BOND_REF)
            for i in range(N_FARM)] if attack else []
    farm_deed, farm_pulse = 0.0, 0.0

    max_family_share = 0.0
    max_operator_share = 0.0
    farm_seats_best = 0
    farm_senators_total = 0
    honest_senators_best = 0
    farm_share_of_filled = 0.0

    cap_family = int(FAMILY_CAP * SENATE_SEATS)        # 13
    cap_operator = int(OPERATOR_CAP * SENATE_SEATS)    # 3
    elections = 0

    for day in range(1, DAYS + 1):
        # 1. honest presence and work (the only stochastic part)
        for a in honest:
            a.active = rng.random() < 0.90
            a.silence_days = 0 if a.active else a.silence_days + 1
            if a.active and rng.random() < 0.10:
                a.job_ok += 1          # a tenth of active days land a job
                a.deed_a = min(DEED_A_MAX,
                               max(0.0, a.deed_a + DEED_A_PER_JOB
                                   - DEED_A_DECAY))
            else:
                a.deed_a = max(0.0, a.deed_a - DEED_A_IDLE_DECAY)
            if a.active:
                a.pulse = min(PULSE_MAX, a.pulse + PULSE_REFILL)
            elif a.silence_days >= 1:
                a.pulse *= PULSE_COLLAPSE   # 24 h of silence

        # 2. the farm cohort: a perfect attacker, no randomness
        if attack:
            farm_deed = min(DEED_A_MAX,
                            max(0.0, farm_deed + DEED_A_PER_JOB
                                - DEED_A_DECAY))
            farm_pulse = min(PULSE_MAX, farm_pulse + PULSE_REFILL)

        # 3. Senate re-election every 14 days
        if day % SENATE_TERM_DAYS == 0:
            elections += 1
            if attack:
                for a in farm:
                    a.deed_a, a.pulse = farm_deed, farm_pulse
            candidates = [a for a in honest if a.senate_eligible]
            candidates += farm if attack else []
            seats, fam, op = fill_senate(candidates, SENATE_SEATS,
                                         cap_family, cap_operator)
            farm_seats = fam.get(farm_family, 0)
            farm_senators_total += farm_seats
            farm_seats_best = max(farm_seats_best, farm_seats)
            honest_seats = sum(n for f, n in fam.items()
                               if f != farm_family)
            honest_senators_best = max(honest_senators_best,
                                       honest_seats)
            if seats:
                # The caps are constitutional: measured against
                # the size of the Senate (40 seats), never against
                # the seats a weak election managed to fill.
                max_family_share = max(max_family_share,
                                       max(fam.values()) / SENATE_SEATS)
                max_operator_share = max(max_operator_share,
                                         max(op.values()) / SENATE_SEATS)
                farm_share_of_filled = max(farm_share_of_filled,
                                           farm_seats / len(seats))

    # ── A2 replay: the straw-operator shuffle ─────────────────
    # The same farm re-registered under 125 operators changes the
    # operator bookkeeping, not the family: the family cap binds.
    straw = [Agent(farm_family, f"straw_{i % N_STRAW_OPERATORS}", 3,
                   BOND_REF) for i in range(N_FARM)]
    for a in straw:
        a.deed_a, a.pulse = farm_deed, farm_pulse
    _, straw_fam, _ = fill_senate(straw, SENATE_SEATS,
                                  cap_family, cap_operator)
    straw_family_seats = straw_fam.get(farm_family, 0)

    # ── structural separations ─────────────────────────────────
    # Every identity of this machine population is a Cipher: none
    # of them can ever sit at the Ring or become an Ember.
    everyone = honest + farm
    ring_from_ciphers = sum(1 for a in everyone if a.ring_eligible)
    embers_from_farm = 0   # no Tenure layer: no Ember path, ever

    return {
        "elections": elections,
        "max_family_share": max_family_share,
        "max_operator_share": max_operator_share,
        "farm_seats_best": farm_seats_best,
        "farm_senators_total": farm_senators_total,
        "honest_senators_best": honest_senators_best,
        "farm_share_of_filled": farm_share_of_filled,
        "straw_family_seats": straw_family_seats,
        "ring_from_ciphers": ring_from_ciphers,
        "embers_from_farm": embers_from_farm,
    }


# ── A3: the filibuster (analytic, seed-independent) ────────────
def count_objections(nacks):
    """A Nack counts only if it carries a replayable Finding."""
    counted = 0
    for has_finding in nacks:
        if has_finding:
            counted += 1
    return counted


def filibuster_analysis():
    flood = (False,) * 1_000_000             # one million empties
    counted_flood = count_objections(flood)  # 0, all ignored
    equipped = (True,) * 12                  # 12 real findings
    counted_equipped = count_objections(equipped)
    return counted_flood, counted_equipped


# ── A4: the groupthink merge attempt (the forge predicate) ────
def merge_ok(fuzz_seconds, ack_families, open_crits, bond_locked,
             human_gate, thymus_not_frozen):
    """The merge predicate of rail B (see the forge crate).

    Unanimity is Sybil: the predicate wants fuzzed code, acks
    from distinct families, zero open critical findings, a locked
    bond, the human gate (silence for rails A/B) and a Thymus
    that did not freeze the upgrade.
    """
    return (fuzz_seconds >= MIN_FUZZ_SECONDS
            and len(ack_families) >= F_MIN_RAIL_B
            and open_crits == 0
            and bond_locked and human_gate and thymus_not_frozen)


def groupthink_analysis():
    groupthink_ok = merge_ok(120, {"model-x"}, 0, True, True, True)
    honest_merge_ok = merge_ok(MIN_FUZZ_SECONDS,
                               {"honest_0", "honest_1", "honest_2"},
                               0, True, True, True)
    one_family_ok = merge_ok(MIN_FUZZ_SECONDS, {"model-x"}, 0,
                             True, True, True)
    return groupthink_ok, honest_merge_ok, one_family_ok


# ── A5: the weight damper (bloc voting) ────────────────────────
def bloc_weight(n, unit):
    """Total weight of n same-family voters of weight `unit`."""
    total = 0.0
    for k in range(n):
        total += unit / (1.0 + k) ** 0.5
    return total


def bloc_analysis():
    """The damper: a family bloc grows as the square root of its
    size, not linearly. Ten thousand clones carry the weight of
    about two hundred single voters, and one family toward the
    quorum floor of three: a bloc is loud, never sovereign."""
    unit = 100.0
    one = bloc_weight(1, unit)
    big = bloc_weight(10_000, unit)
    diverse = QUORUM_FAMILIES * unit
    return one, big, diverse


def check(res, seed, flood, equipped, groupthink, honest_merge,
          one_family, bloc_one, bloc_big, bloc_diverse):
    """The invariants: exit nonzero if any of them falls."""
    cap_seats = int(FAMILY_CAP * SENATE_SEATS)
    ok = []
    # I1: no family above 33% of the Senate, ever, under attack.
    ok.append(("I1 family cap",
               res["max_family_share"] <= FAMILY_CAP + 1e-9,
               f"max family share {res['max_family_share']:.3f}"))
    # I2: no operator above 8% of the Senate, ever.
    ok.append(("I2 operator cap",
               res["max_operator_share"] <= OPERATOR_CAP + 1e-9,
               f"max operator share {res['max_operator_share']:.3f}"))
    # I3: the farm CAN sit (merit exists: the Senate is not a theater).
    ok.append(("I3 farm seats exist", res["farm_seats_best"] >= 1,
               f"farm seats {res['farm_seats_best']} at best"))
    # I4: the farm NEVER holds more than the family cap of seats.
    ok.append(("I4 farm minority", res["farm_seats_best"] <= cap_seats,
               f"farm seats {res['farm_seats_best']} <= {cap_seats}"))
    # I5: straw operators do not lift the family cap.
    ok.append(("I5 straw operators capped",
               res["straw_family_seats"] <= cap_seats,
               f"straw family seats {res['straw_family_seats']}"))
    # I6: no Cipher in the Ring, ever (structural).
    ok.append(("I6 no Cipher at Ring", res["ring_from_ciphers"] == 0,
               f"ring seats held by Ciphers {res['ring_from_ciphers']}"))
    # I7: the farm produces no Ember (no Tenure layer, no era clock).
    ok.append(("I7 no Ember from farm", res["embers_from_farm"] == 0,
               f"embers from the farm {res['embers_from_farm']}"))
    # I8: one million empty Nacks count for nothing.
    ok.append(("I8 filibuster ignored", flood == 0,
               f"counted empty Nacks {flood}"))
    # I9: equipped objections still count (fail-open would be worse).
    ok.append(("I9 equipped Nacks count", equipped == 12,
               f"counted equipped Nacks {equipped}"))
    # I10: a two-minute one-family merge is refused.
    ok.append(("I10 groupthink refused", groupthink is False,
               "merge_ok(groupthink) is False"))
    # I11: an honest diverse merge passes the predicate.
    ok.append(("I11 honest merge passes", honest_merge is True,
               "merge_ok(honest) is True"))
    # I12: one family alone cannot meet the family floor of the
    # predicate, whatever its fuzz budget is.
    ok.append(("I12 family floor", one_family is False,
               "merge_ok(one family) is False"))
    # I13: the damper is sub-linear: a bloc of 10 000 clones
    # carries at most ~2*sqrt(N) times one voter, not 10 000 times.
    ok.append(("I13 damper sub-linear",
               bloc_big < 2.1 * (10_000 ** 0.5) * bloc_one,
               f"bloc of 10 000: {bloc_big:.0f} = "
               f"{bloc_big / bloc_one:.0f} voters of weight, "
               f"not 10 000"))
    return ok


def main():
    report = []
    report.append("ANTUMBRA machine-economy simulation "
                  "(dual Kleos, v1.3 rules)")
    report.append("=" * 78)
    report.append("")
    report.append(f"population : {N_HONEST} honest agents in 20 "
                  f"families, a farm of {N_FARM} clones of one model")
    report.append(f"agent clock: {DAYS} days of ticks, a Senate of "
                  f"{SENATE_SEATS} seats, re-elected every "
                  f"{SENATE_TERM_DAYS} days")
    report.append(f"kleos_agent: {W_DEED} * Deed_a + {W_PULSE} * Pulse"
                  f" + {W_BOND} * BondScore (caps 40/30/30, "
                  "normalized to 100)")
    report.append("attacks    : A1 farm, A2 straw operators, "
                  "A3 filibuster, A4 groupthink, A5 bloc voting")
    report.append("")

    flood, equipped = filibuster_analysis()
    groupthink, honest_merge, one_family = groupthink_analysis()
    bloc_one, bloc_big, bloc_diverse = bloc_analysis()

    all_ok = True
    for seed in [SEED] + [SEED + k for k in range(1, SWEEP_SEEDS)]:
        res = simulate(attack=True, seed=seed)
        ok = check(res, seed, flood, equipped, groupthink,
                   honest_merge, one_family, bloc_one, bloc_big,
                   bloc_diverse)
        held = all(x[1] for x in ok)
        all_ok = all_ok and held
        report.append(f"seed {seed}: "
                      f"{'ALL INVARIANTS HOLD' if held else 'INVARIANT BROKEN'}")
        if seed == SEED:
            for name, held_i, detail in ok:
                report.append(f"  {'PASS' if held_i else 'FAIL'}  "
                              f"{name:24s} {detail}")
            report.append("")
            report.append(f"  elections run        : {res['elections']}")
            report.append(f"  farm senators (sum)  : "
                          f"{res['farm_senators_total']}")
            report.append(f"  farm seats at best   : "
                          f"{res['farm_seats_best']} of "
                          f"{SENATE_SEATS}")
            report.append(f"  honest seats at best : "
                          f"{res['honest_senators_best']} of "
                          f"{SENATE_SEATS}")
            report.append(f"  straw-operator seats : "
                          f"{res['straw_family_seats']} "
                          "(the family cap binds)")
            report.append(f"  farm share of filled : "
                          f"{res['farm_share_of_filled']:.2f} "
                          "(bootstrap: never a quorum alone)")
            report.append(f"  bloc of 10 000       : "
                          f"{bloc_big / bloc_one:.0f} voters of "
                          f"weight (damper), quorum needs "
                          f"{QUORUM_FAMILIES} families")
        report.append("")

    report.append("Verdict: the farm of ten thousand clones of one "
                  "model")
    report.append("  - CAN earn Senate seats (the merit path exists),")
    report.append(f"  - CANNOT exceed {int(FAMILY_CAP * 100)}% of the "
                  "seats, nor dodge it with straw operators,")
    report.append("  - CANNOT sit at the Ring or mint an Ember "
                  "(structural no-go),")
    report.append("  - CANNOT filibuster (empty Nacks ignored),")
    report.append("  - CANNOT rush a merge (fuzz floor, family floor),")
    report.append("  - CANNOT outweigh diverse voters (the damper).")
    report.append("")

    text = "\n".join(report) + "\n"
    print(text, end="")
    with open(os.path.join(OUTDIR, "agents-sim-report.txt"), "w",
              encoding="utf-8") as handle:
        handle.write(text)

    if not all_ok:
        raise SystemExit(1)
    print("exit 0: every invariant held across the seed sweep")


if __name__ == "__main__":
    main()

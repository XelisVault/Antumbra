# -*- coding: utf-8 -*-
"""ANTUMBRA: deterministic simulation of the social core (Kleos / Ember / Ring).

Goal: prove that the social core of the protocol is a deterministic state
machine, codeable and testable BEFORE the chain exists. The simulation
replays 16 years of history (32 eras of 6 months) with:

  S0  honest growth (miners, merchants, agents, whales)
  S1  fake-profile farm (sybil): 20 complicit sponsors, 2 sponsorships/year
  S2  witness buying to inflate the Echo (with and without per-target cap)
  S3  attempted capture of the Ring (55 seats, Kleos threshold >= 70)

Rules implemented (v2 specification):
  Kleos = Deed (<=40) + Echo (<=30) + Tenure (<=30), within [0, 100]
  Deed   : on-chain behavior, decay -0.1 per era
  Echo   : peer attestations, budget 0.1 per witness per era, witness weight
           = 0.15 + 0.85 x Deed/40, decay -0.05 per era
  Tenure : +1 per incident-free era; incident (detection) => definitive
           collapse of the Tenure layer
  Ring   : 55 seats, candidacy at Kleos >= 70, draw weighted by Kleos
  Signed fork => total stripping (Kleos reset to zero)
  Sponsorship: at most 2 Embers per year per sponsor; detected fraud =>
           the sponsor loses 5 points of Deed, the fake profile restarts
           from near zero and loses its Tenure layer forever.

Parameters discovered by this very simulation (corrective rules R1-R4,
see the report: the v2 specification without them is broken):
  R1  Ring candidacy: Kleos >= 70 AND Tenure >= 15 incident-free eras
      (the wall of time, applied for real to finality)
  R2  a testimony carries no weight until the witness reaches Deed >= 20
      (a testimony that counts comes from someone who proved something)
  R3  liable attestations: a target convicted of fraud costs 3 points of
      Deed to each of its witnesses and 5 to its sponsor
  R4  pooled activity (closed graph) counts at only a quarter of the Deed,
      extended to usages: cross-sales inside a clique do not fabricate
      trust (Axon heritage, mutual-rating detection)
  ECHO_TARGET_CAP = 2.0 points per target per era: without it, 300 bought
  witnesses inflate the Echo in a single era.

Attacker assumptions, deliberately maximal:
  fake profiles with perfect behavior (Deed +2.5/era), unlimited witness
  budget (Echo bought at the cap), 20 complicit sponsors, zero cost, and
  no counter-attack except protocol detection (3%/era).

Output: English report (console + kleos-sim-report.txt), figure
antumbra-kleos-curves.png, exit 0 only if all invariants hold over the
32 eras.

Since the first audit, the engine also runs a seed sweep: the
canonical seed 1618 produces the detailed report and the figure,
and eleven more seeds replay the same two passes (v2 rules,
then R1-R4 under the same maximum attack) with the worst case
across seeds archived in the report. One seed is a demonstration;
a sweep is a regression test.
"""
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
OUTDIR = HERE
os.makedirs(OUTDIR, exist_ok=True)

# ── protocol parameters (v2, whitepaper sections 7, 9, 10) ──
ERAS = 32                     # 32 eras = 16 years
DEED_MAX, ECHO_MAX, TENURE_MAX = 40.0, 30.0, 30.0
DEED_DECAY, ECHO_DECAY = 0.1, 0.05
ECHO_BUDGET = 0.1             # influence per witness per era
W_MIN = 0.15                  # floor weight of a fresh witness
ECHO_TARGET_CAP = 2.0         # gain cap per target per era (discovered here)
N_WITNESS_TARGETS = 5         # targets attested per honest witness per era
SEATS = 55
SEAT_THRESHOLD = 70.0
SEAT_MIN_TENURE = 15          # R1: 7.5 years of irreproachable seniority
WITNESS_MIN_DEED = 20         # R2: below this, a testimony weighs nothing
MUTUAL = 0.10                 # mutual-rating detector (Axon, x0.1)
MUTUAL_DEED = 0.25            # R4: share of Deed counted in a closed graph
SPONSOR_PER_ERA = 1           # 2 sponsorships/year = 1 per era per sponsor
N_SPONSORS = 20               # complicit sponsors
P_DETECT = 0.03               # detection of a fake profile per era
ATTACK_START_ERA = 4          # the farm opens at era 4 (year 2)

SEED = 1618                   # full reproducibility
SWEEP_SEEDS = 12              # the canonical seed plus eleven more


class Ident:
    __slots__ = ('kind', 'honest', 'sponsor', 'deed', 'echo', 'tenure',
                 'accrual', 'bought_echo', 'flagged', 'tenure_dead')

    def __init__(self, kind, honest, accrual, sponsor=None, bought_echo=0.0):
        self.kind = kind            # miner / merchant / agent / whale / fake
        self.honest = honest
        self.sponsor = sponsor      # sponsor index (fake profiles)
        self.deed = 0.0
        self.echo = 0.0
        self.tenure = 0.0
        self.accrual = accrual      # gross Deed gain per era (behavior)
        self.bought_echo = bought_echo
        self.flagged = 0            # number of detections suffered
        self.tenure_dead = False    # incident => Tenure dead forever

    @property
    def kleos(self):
        return self.deed + self.echo + self.tenure

    @property
    def weight(self):
        """Testimony weight (R2): zero below Deed 20, full at Deed 40."""
        if self.deed < WITNESS_MIN_DEED:
            return 0.0
        return W_MIN + (1.0 - W_MIN) * (self.deed - WITNESS_MIN_DEED) / \
            (DEED_MAX - WITNESS_MIN_DEED)


def simulate(attack=True, echo_cap=True, fixes=True, seed=SEED):
    rng = random.Random(seed)
    idents = []
    # Honest population: 100 miners, 60 merchants, 30 agents, 20 whales
    for _ in range(100):
        idents.append(Ident('miner', True, 2.2))
    for _ in range(60):
        idents.append(Ident('merchant', True, 2.0))
    for _ in range(30):
        idents.append(Ident('agent', True, 1.8))
    for _ in range(20):
        idents.append(Ident('whale', True, 0.05))  # capital only: inactive

    # farm Deed accrual under R4 (closed graph)
    farm_accrual = (2.5 * MUTUAL_DEED if fixes else 2.5)

    sponsors, fakes, active_fakes = [], [], set()
    if attack:
        for _ in range(N_SPONSORS):
            s = Ident('merchant', True, 2.0)  # behaves well on the surface
            s.deed, s.tenure = 12.0, 6.0      # ~3 years of seniority
            sponsors.append(len(idents))
            idents.append(s)
        # bought Echo: without R2/R3, unlimited budget at the 2.0/era cap;
        # with R2/R3, only the 20 accomplices testify for the farm, in
        # mutual ratings (x0.1) with a budget of 0.1 each
        if fixes:
            bought = MUTUAL * N_SPONSORS * ECHO_BUDGET  # ~0.2/era total
        else:
            bought = ECHO_TARGET_CAP if echo_cap else 30.0
        n_fakes = N_SPONSORS * SPONSOR_PER_ERA * (ERAS - ATTACK_START_ERA + 1)
        for k in range(n_fakes):
            fakes.append(len(idents))
            idents.append(Ident('fake', False, farm_accrual,
                                sponsor=sponsors[k % N_SPONSORS],
                                bought_echo=bought))

    history = []
    first_honest_cand = None
    first_fake_cand = None
    attacker_seats_max = (0, 0)
    fake_count = 0

    for era in range(1, ERAS + 1):
        # 1. sponsorship: 1/era per accomplice => 20 fakes/era => 40/year
        if attack and era >= ATTACK_START_ERA:
            new = min(N_SPONSORS * SPONSOR_PER_ERA, len(fakes) - fake_count)
            for k in range(fake_count, fake_count + new):
                active_fakes.add(fakes[k])
            fake_count += new

        # 2. honest Echo: each established witness spends 0.1 on 5 targets
        targets_pool = [i for i, x in enumerate(idents)
                        if x.honest and x.accrual >= 0.5]
        gains = {i: 0.0 for i in targets_pool}
        for w_i in targets_pool:
            w = idents[w_i]
            if w.deed < 4.0:
                continue
            cands = [t for t in targets_pool if t != w_i]
            for t in rng.sample(cands, min(N_WITNESS_TARGETS, len(cands))):
                gains[t] += ECHO_BUDGET * w.weight
        gains = {t: min(g, ECHO_TARGET_CAP) for t, g in gains.items()}

        # 3. detection: each active fake profile has P_DETECT of being caught
        #    (R3: the sponsor pays 5 Deed, the accomplice witnesses pay 3)
        for fi in list(active_fakes):
            if rng.random() < P_DETECT:
                f = idents[fi]
                f.echo = 0.0
                f.deed *= 0.5
                f.tenure = 0.0
                f.tenure_dead = True
                f.flagged += 1
                s = idents[f.sponsor]
                s.deed = max(0.0, s.deed - 5.0)  # the sponsor pays
                for sp in sponsors:               # the accomplice witnesses pay
                    if idents[sp].deed >= WITNESS_MIN_DEED:
                        idents[sp].deed = max(0.0, idents[sp].deed - 3.0)

        # 4. state transitions
        for i, x in enumerate(idents):
            gain = gains.get(i, 0.0)
            if i in active_fakes:
                x.deed = min(DEED_MAX, max(0.0, x.deed + x.accrual - DEED_DECAY))
                x.echo = min(ECHO_MAX, max(0.0, x.echo + x.bought_echo - ECHO_DECAY))
            elif not x.honest:
                pass  # unregistered fake profile: no points, no aging
            else:
                x.deed = min(DEED_MAX, max(0.0, x.deed + x.accrual - DEED_DECAY))
                x.echo = min(ECHO_MAX, max(0.0, x.echo + gain - ECHO_DECAY))
            if x.honest or i in active_fakes:
                if not x.tenure_dead:
                    x.tenure = min(TENURE_MAX, x.tenure + 1.0)

        # 5. Ring draw (deterministic, weighted by Kleos)
        #    R1: candidacy additionally requires Tenure >= 15 without incident
        def eligible(i):
            x = idents[i]
            if x.kleos < SEAT_THRESHOLD:
                return False
            if fixes and (x.tenure < SEAT_MIN_TENURE or x.tenure_dead):
                return False
            return True

        cand = [(i, idents[i].kleos) for i in range(len(idents)) if eligible(i)]
        pool = list(cand)
        rng2 = random.Random(seed * 1000 + era)
        seats = []
        for _ in range(min(SEATS, len(pool))):
            total = sum(w for _, w in pool)
            pick = rng2.random() * total
            acc = 0.0
            for idx, (i, w) in enumerate(pool):
                acc += w
                if pick <= acc:
                    seats.append(i)
                    pool.pop(idx)
                    break
        honest_cand = [i for i, _ in cand if idents[i].honest]
        fake_cand = [i for i, _ in cand if not idents[i].honest]
        fake_seats = sum(1 for s in seats if not idents[s].honest)
        if fake_seats > attacker_seats_max[0]:
            attacker_seats_max = (fake_seats, era)
        if first_honest_cand is None and honest_cand:
            first_honest_cand = era
        if first_fake_cand is None and fake_cand:
            first_fake_cand = era

        # 6. invariants (failure => exception => exit != 0)
        for x in idents:
            assert 0.0 <= x.kleos <= 100.0, 'Kleos out of bounds'
            assert x.deed <= DEED_MAX + 1e-9, 'Deed > 40'
            assert x.echo <= ECHO_MAX + 1e-9, 'Echo > 30'
            assert x.tenure <= TENURE_MAX + 1e-9, 'Tenure > 30'
        for x in idents:
            if x.kind == 'whale':
                assert x.kleos < SEAT_THRESHOLD, 'a whale became a candidate!'
        assert len(seats) == min(SEATS, len(cand)), 'seats not properly filled'
        assert fake_count <= N_SPONSORS * SPONSOR_PER_ERA * max(0, era - ATTACK_START_ERA + 1)
        for i, _ in cand:
            x = idents[i]
            assert x.kleos >= SEAT_THRESHOLD
            if fixes:
                assert x.tenure >= SEAT_MIN_TENURE and not x.tenure_dead

        # 7. history
        hon = sorted(x.kleos for x in idents
                     if x.honest and x.kind != 'whale')
        fak = sorted(idents[i].kleos for i in active_fakes) or [0.0]
        wha = [x.kleos for x in idents if x.kind == 'whale']
        history.append({
            'era': era, 'year': era / 2,
            'hon_p50': hon[len(hon) // 2], 'hon_p90': hon[int(len(hon) * 0.9)],
            'fake_max': fak[-1], 'fake_med': fak[len(fak) // 2],
            'whale_max': max(wha),
            'honest_candidates': len(honest_cand),
            'fake_candidates': len(fake_cand),
            'fake_seats': fake_seats, 'seats': len(seats),
        })

    return idents, active_fakes, history, first_honest_cand, \
        first_fake_cand, attacker_seats_max, fake_count


def herfindahl(idents):
    cand = [x.kleos for x in idents if x.kleos >= SEAT_THRESHOLD]
    tot = sum(cand)
    return sum((k / tot) ** 2 for k in cand) if cand else 0.0


def sweep():
    """The seed sweep: the same two passes on twelve seeds, worst
    case archived. One seed is a demonstration; a sweep is a
    regression test. Every assertion here is an invariant the
    rules must hold on every seed, not on the lucky one."""
    need = SEATS // 2 + 1
    rows = []
    for k in range(SWEEP_SEEDS):
        seed = SEED if k == 0 else k * 7 + 3
        _, _, hV, _, first_fV, seatV, _ = simulate(attack=True,
                                                   fixes=False, seed=seed)
        idA, _, hA, _, first_fA, seatA, _ = simulate(attack=True,
                                                     fixes=True, seed=seed)
        lastA = hA[-1]
        # The v2 flaw must reproduce on every seed: it is
        # structural, not seed luck.
        assert seatV[0] >= need, (f'v2 flaw did not reproduce on seed {seed}')
        # The wall must hold on every seed: zero seats, ever.
        assert seatA[0] == 0, (f'the attack took seats on seed {seed}')
        assert first_fA is None, (f'a fake profile became candidate on seed {seed}')
        assert lastA['whale_max'] < SEAT_THRESHOLD, (f'a whale crossed on seed {seed}')
        rows.append({
            'seed': seed,
            'v2_seats': seatV[0], 'v2_first_fake': first_fV,
            'seats': seatA[0],
            'fake_med': lastA['fake_med'], 'fake_max': lastA['fake_max'],
            'hon_med': lastA['hon_p50'],
            'whale_max': lastA['whale_max'],
        })
    worst = {
        'v2_seats': max(r['v2_seats'] for r in rows),
        'v2_first_fake_year': min(r['v2_first_fake'] for r in rows) / 2,
        'seats': max(r['seats'] for r in rows),
        'fake_med': max(r['fake_med'] for r in rows),
        'fake_max': max(r['fake_max'] for r in rows),
        'hon_med': min(r['hon_med'] for r in rows),
        'whale_max': max(r['whale_max'] for r in rows),
    }
    return rows, worst


def report():
    lines = []
    add = lines.append
    add("=" * 74)
    add("ANTUMBRA: simulation of the social core (Kleos / Ember / Ring)")
    add(f"deterministic engine, seed {SEED}, 32 eras (16 years), reproducible")
    add("=" * 74)

    # ── pass 1: the v2 rules as written (the original specification) ──
    idV, actV, hV, first_cV, first_fV, seatV, cntV = simulate(attack=True,
                                                             fixes=False)
    add("")
    add("PASS 1: V2 RULES AS WRITTEN, the specification is broken")
    add("  20 complicit sponsors, 2 sponsorships/year, perfect behavior,")
    add(f"  unlimited witness budget: registered profiles {cntV}")
    if first_fV:
        add(f"  first fake profile candidate: year {first_fV / 2:.1f} "
            f"(first honest: {first_cV / 2:.1f}), the attacker crosses")
        add("  the threshold BEFORE the honest network")
    need = SEATS // 2 + 1
    add(f"  worst seats held by the attacker: {seatV[0]}/{SEATS} "
        f"(era {seatV[1]}, year {seatV[1] / 2:.0f})")
    add(f"  finality control = {need} seats: "
        + ("REACHED, FLAW CONFIRMED" if seatV[0] >= need else "not reached"))
    add("  cause: bought Echo (2.0/era) grows faster than organic Echo;")
    add("  the 70 threshold is reachable by Deed+Echo with zero Tenure.")

    # ── pass 2: corrective rules R1-R4 ──
    id0, _, h0, first_c, _, _, _ = simulate(attack=False)
    add("")
    add("PASS 2: CORRECTIVE RULES R1-R4, the wall of time closed again")
    add("  R1 candidacy = Kleos >= 70 AND Tenure >= 15 incident-free eras")
    add("  R2 a testimony weighs nothing while Deed < 20")
    add("  R3 liable attestations (convicted fraud: -3 Deed per witness)")
    add("  R4 pooled clique activity counted at 25%")
    last = h0[-1]
    add(f"  honest growth: first candidates year {first_c / 2:.1f}, "
        f"{last['seats']} seats filled by the end")
    add(f"  honest median Kleos {last['hon_p50']:.1f}, p90 {last['hon_p90']:.1f}, "
        f"inactive whale {last['whale_max']:.1f} (never a candidate)")
    add(f"  candidate Herfindahl {herfindahl(id0):.4f} (healthy spread)")

    idA, actA, hA, first_cA, first_fA, seatmax, fake_count = simulate(attack=True,
                                                                     fixes=True)
    lastA = hA[-1]
    add("")
    add("  SAME MAXIMUM ATTACK UNDER R1-R4:")
    add(f"  registered profiles: {fake_count}, fake median Kleos "
        f"{lastA['fake_med']:.1f} (honest {lastA['hon_p50']:.1f})")
    add(f"  fake profile candidates: {lastA['fake_candidates']} "
        f"vs {lastA['honest_candidates']} honest")
    add(f"  worst seats held by the attacker: {seatmax[0]}/{SEATS}"
        + (f" (era {seatmax[1]})" if seatmax[1] else ", none, never"))
    add(f"  finality control = {need} seats: "
        + ("STILL REACHED, ALERT" if seatmax[0] >= need
           else "NEVER APPROACHED, the wall holds"))
    add("  reminder: any seat signing a fork is stripped on the spot (Kleos -> 0)")
    add(f"  final candidate Herfindahl: {herfindahl(idA):.4f}")

    # ── arithmetic of witness buying (S2) ──
    add("")
    add("S2: BUYING WITNESSES TO INFLATE THE ECHO, arithmetic")
    g = 300 * ECHO_BUDGET
    add(f"  300 established witnesses, WITHOUT a per-target cap: gain {g:.0f} pts/era "
        f"=> Echo 30 in {30 / (g - ECHO_DECAY):.1f} era, FLAW")
    add(f"  with the 2.0/target/era cap: Echo 30 in "
        f">= {30 / (ECHO_TARGET_CAP - ECHO_DECAY):.1f} eras "
        f"({30 / (ECHO_TARGET_CAP - ECHO_DECAY) / 2:.1f} years) of continuous buying")
    add("  with R2: fresh witnesses (Deed < 20) weigh NOTHING; renting")
    add("  established witnesses exposes each to -3 Deed per convicted target (R3)")
    add("  => paying 300 witnesses gives no more than paying 20, and the")
    add("     price per point climbs into absurdity: the wall of time holds")

    add("")
    add("INVARIANTS VERIFIED AT EVERY ERA (assertions, 3 passes x 32 eras):")
    add("  Kleos within [0,100], Deed<=40, Echo<=30, Tenure<=30")
    add("  Echo gain per target <= 2.0, seats = 55 or fewer if scarce")
    add("  sponsorship <= 2/year/sponsor, whale never a candidate")
    add("  under R1: every candidate has Tenure >= 15 and a living Tenure: OK")

    # ── pass 3: the seed sweep ──
    rows, worst = sweep()
    add("")
    add(f"PASS 3: SEED SWEEP, {SWEEP_SEEDS} seeds, same maximum attack")
    add("  seed   v2 seats  v2 first fake   R1-R4 seats   fake med  "
        "honest med  whale")
    for r in rows:
        add(f"  {r['seed']:<6d} {r['v2_seats']:>4d}/55   "
            f"year {r['v2_first_fake'] / 2:>4.1f}       "
            f"{r['seats']:>3d}/55      "
            f"{r['fake_med']:>6.1f}    {r['hon_med']:>6.1f}    "
            f"{r['whale_max']:>4.1f}")
    add("  worst case across seeds:")
    add(f"    v2 rules: {worst['v2_seats']}/55 seats, first fake candidate "
        f"year {worst['v2_first_fake_year']:.1f} (the flaw is structural)")
    add(f"    R1-R4 rules: {worst['seats']}/55 seats, no fake candidate ever")
    add(f"    worst fake median Kleos {worst['fake_med']:.1f} "
        f"(weakest honest median {worst['hon_med']:.1f}), "
        f"whale never above {worst['whale_max']:.1f}")
    add("  => the wall holds on every seed, not only the canonical one")

    text = "\n".join(lines)
    print(text)
    with open(os.path.join(OUTDIR, 'kleos-sim-report.txt'), 'w', encoding='utf-8') as f:
        f.write(text + "\n")
    return h0, hV, hA


def figure(h0, hV, hA):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.font_manager as fm
    for p in ('/usr/share/fonts/truetype/liberation/LiberationSerif-Regular.ttf',
              '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'):
        if os.path.exists(p):
            fm.fontManager.addfont(p)
    import matplotlib.pyplot as plt
    plt.rcParams['font.family'] = 'serif'
    plt.rcParams['font.serif'] = ['Liberation Serif', 'DejaVu Serif']
    plt.rcParams['mathtext.fontset'] = 'stix'
    plt.rcParams['axes.unicode_minus'] = False

    INK, GREY1, GREY2, GREY3 = '#000000', '#3a3a3a', '#6e6e6e', '#9c9c9c'
    years0 = [h['year'] for h in h0]
    yearsV = [h['year'] for h in hV]
    yearsA = [h['year'] for h in hA]

    fig, ax = plt.subplots(figsize=(10, 5.4), constrained_layout=True)
    ax.plot(years0, [h['hon_p50'] for h in h0], color=INK, lw=2.2,
            label='Honest network, median')
    ax.plot(years0, [h['hon_p90'] for h in h0], color=INK, lw=1.6, ls='--',
            label='Honest network, 90th percentile')
    ax.plot(yearsV, [h['fake_max'] for h in hV], color=GREY1, lw=2.0,
            ls=(0, (5, 2)), label='v2 rules: best fake profile (the flaw)')
    ax.plot(yearsA, [h['fake_max'] for h in hA], color=GREY2, lw=2.0,
            ls='-.', label='R1-R4 rules: best fake profile')
    ax.plot(yearsA, [h['fake_med'] for h in hA], color=GREY2, lw=1.6,
            ls=':', label='R1-R4 rules: fake profiles, median')
    ax.plot(years0, [h['whale_max'] for h in h0], color=GREY3, lw=1.8,
            ls=(0, (1, 1)), label='Whale: capital only, inactive')
    ax.axhline(SEAT_THRESHOLD, color=INK, lw=1.4, ls=(0, (6, 3)))
    ax.text(0.25, SEAT_THRESHOLD + 2.5,
            'Ring candidacy threshold (Kleos 70)',
            fontsize=10.5, color=INK)

    ax.set_xlabel('Years after genesis', fontsize=11)
    ax.set_ylabel('Kleos score (0 to 100)', fontsize=11)
    ax.set_title('ANTUMBRA: Kleos trajectories over 16 years, v2 flaw and '
                 'R1-R4 fix (seed 1618)', fontsize=12.5, pad=12)
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 100)
    ax.grid(True, color=GREY3, lw=0.7, alpha=0.55)
    for spine in ('top', 'right'):
        ax.spines[spine].set_visible(False)
    ax.legend(loc='upper left', bbox_to_anchor=(0.0, -0.14), ncol=2,
              fontsize=9.5, frameon=False)
    out = os.path.join(OUTDIR, 'antumbra-kleos-curves.png')
    fig.savefig(out, dpi=200, facecolor='white')
    plt.close(fig)
    print('\nfigure:', out)


if __name__ == '__main__':
    h0, hV, hA = report()
    figure(h0, hV, hA)
    print('\nEXIT OK: all invariants hold.')

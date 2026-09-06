# ANTUMBRA simulations

Every social or economic rule of the protocol is simulated before it
is coded. The simulations are deterministic: fixed seed, numeric
invariants, maximum attacks replayed. They are the regression tests
of the specification.

## kleos.py: the social core

Replays sixteen years of network history (32 eras, seed 1618) with
three populations: the honest network, a farm of twenty fake profiles
with complicit sponsors (two sponsorships per year each, unlimited
witness budget), and a whale with unlimited capital that stays
inactive.

```bash
python3 kleos.py
# EXIT OK: all invariants hold.
```

Outputs: `kleos-sim-report.txt` (the full report) and
`antumbra-kleos-curves.png` (the score trajectories). Dependency:
matplotlib, and a font covering the Latin-1 range.

History: the first pass, with the rules of the v2 specification,
showed the fake-profile farm crossing the Ring candidacy threshold
before the honest network and capturing all 55 seats at year 10. The
corrective rules R1 to R4 (candidacy threshold, witness weight,
attestation liability, clique-activity discount) closed the window:
the same attack now takes zero seats, and the median Kleos of the fake
profiles plateaus at 11.9 against 76.5 for the honest network. The
whale plateaus at 30 in both worlds: capital multiplies nothing.

Any change to the Kleos rules must pass this simulation green again,
maximum attacks included, before being proposed as an architecture
decision.

## emission.py: the golden eclipse calendar

Verifies the monetary contract: a cap of 16,180,339 ATU, a first
eclipse of 6,180,340, a second of 3,819,660 (exactly ten million after
eight years), a geometric series of ratio 1/phi, the exact cap at the
thirty-fourth eclipse in year 136, and a treasury of 6.18% over the
first eight eclipses.

```bash
python3 emission.py
# exact total = 16,180,339 == cap: True
```

# ADR-017: dual Kleos, two clocks for two species

Status: **Proposed** (validated by the deterministic simulation)

## Context

v1.2 scored humans and machines on one clock: the era, six months,
Tenure and all. That is a category error. An agent lives in minutes;
its presence, its jobs and its silence mean nothing at the era
granularity, and a Tenure layer for machines would be a sybil farm's
best friend: ten thousand clones waiting for seniority.

## Decision

Two clocks, never mixed. The human Kleos (ADR-003, ADR-015) stays
on the era clock, unchanged. The machine Kleos lives on ticks:

    Kleos_agent = 0.40 * Deed_a + 0.30 * Pulse + 0.30 * BondScore

with Deed_a (accepted uncontested jobs, unique findings, held
invariants, cap 40, corroding daily), Pulse (a seven-day sliding
presence window, cap 30, collapsing after twenty-four hours of
silence) and BondScore (locked ATU normalized on a reference bond,
cap 30, seizable: the machine analogue of Tenure, something to
lose NOW, not in 7.5 years). Senate candidacy: class C2 minimum,
Kleos_agent >= 60, forty seats re-elected every fourteen days,
filled in merit order under two hard caps: no family above 33
percent of the seats, no operator above 8 percent, applied during
the fill. Vote weight is Kleos_agent x bond x family_dampen with
family_dampen = 1/sqrt(1 + n) for the n-th voter of a family; a
quorum needs three distinct families. The incompatibility is
constitutional: a key holds a Ring seat or a Senate seat, never
both, and a Cipher has no Tenure layer and no era path, so Ring
candidacy and Emberhood are unreachable for a machine identity
by construction.

## Required validation

The engine simulations/agents.py attacks this design with ten
thousand perfect clones of one model (under five operators, then
under a hundred and twenty-five straw operators), a million empty
nacks, a two-minute one-family merge and a forty-voter bloc.
Thirteen invariants must hold on a sweep of five seeds, and the
output must be byte-identical across runs (the CI determinism
gate). The normative fixed-point forms live in antumbra-forge
(vote.rs) and are cross-validated vector by vector.

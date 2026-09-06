# ADR-003: Kleos, the three-layer reputation

Status: **Proposed** (validated by simulation)

## Context

Reputation must be strong enough to carry finality, and sober enough
never to become a currency. The project that inspired this part
indexed reputation on capital: the formula multiplied the two, and
the rich stayed in power.

## Decision

A score from 0 to 100, consensus-computed, non-transferable: the Deed
(observed behavior, cap 40), the Echo (peer attestations, cap 30,
budget of 0.1 per witness per era), the Tenure (continuous seniority,
cap 30). Natural decay; cheating: the Deed resets to zero; major
incident: the Tenure collapses. Four corrective rules derived from the
simulation: R1 candidacy threshold at 70 and fifteen eras, R2 a
witness stays mute below twenty points of Deed, R3 liable attestations,
R4 pooled clique activity counted at one quarter.

## Required validation

The deterministic simulation (seed 1618) is the regression test: any
modification of the rules must pass it green again, maximum attacks
included.

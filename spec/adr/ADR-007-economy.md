# ADR-007: economy, the golden ratio contract

Status: **Proposed** (calendar verified by exact computation)

## Context

The cap, the decay and the emission duration must be recitable from
memory in ten years, and emission must outlive its first miners:
every generation must find an active emission.

## Decision

A cap of 16,180,339 ATU, the golden ratio multiplied by ten million;
the same proportion already drives RandomX (constant 0x9E3779B9).
Emission by four-year eclipses, each emitting the fraction 1/phi of
the previous one: 6,180,340 then 3,819,660, whose sum equals exactly
ten million after eight years; the exact cap at the thirty-fourth
eclipse, in year 136. A community treasury of 6.18% of rewards for
eight eclipses, governed by the Embers, extinguished automatically
afterward. No premine. A strict cap, with a constitutional tail
safety valve activatable by the three chambers.

## Required validation

The exact calendar is an archived computation script (the emission
calendar); any modification goes through the constitutional track and
replays the computation.

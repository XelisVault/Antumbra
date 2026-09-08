# ADR-022: the genesis Embers, an annuary, not a council

Status: **Proposed** (C7 of the second review, closed in the v1.3
paper)

## Context

The Ring ratchet of v1.2 (eras 0 to 2, 45 and 55 seats) draws
from a population that has to come from somewhere: who sponsors
the first Embers, what do they weigh, and what stops them from
being a founding council in disguise?

## Decision

The genesis Embers are an annuary, not a council: published at
genesis, Kleos zero, Tenure zero, no seat of right. Their
sponsorships are the seed of the human web: auto-sponsorship
forbidden, two sponsorships per year per sponsor as everywhere,
the presence proof of eras 0 to 2 counted in HOURS, not
seconds (a botnet does not out-stubborn a calendar). The graph
of genesis sponsorships is published with the annuary. R1
applies to them the moment they are candidates, term limits as
everyone, and the ratchet does the rest: the founding set is
diluted by the first honest cohorts before any of them can sit
anywhere.

## Required validation

The Kleos simulation (simulations/kleos.py) already replays the
ratchet with a maximal sponsor-farm attack; the genesis table
is published as data (spec/genesis/) before testnet, and the
hours-based presence proof is a rule of the identity crate, not
a narrative line.

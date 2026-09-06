# ADR-005: Cipher, the agent accountable by construction

Status: **Proposed**

## Context

The agent payment rails of 2026 transport machine-to-machine payments
without saying who answers for the agent or how far it may spend.

## Decision

Every agent registers with three bindings: a human sponsor (an Ember,
answerable and revoking), a declarative spending perimeter verified at
every transaction (ceilings, recipients, usage markers, validity
window), and a revocation switch that costs one transaction. The agent
Kleos builds its commercial asset.

## Required validation

Prototype of the perimeters in phase 4: every agent transaction is
rejected if it leaves the perimeter, and revocation freezes spending
from the next block onward.

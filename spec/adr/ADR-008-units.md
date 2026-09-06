# ADR-008: units, eight decimals of atomic precision

Status: **Proposed**

## Context

Consensus arithmetic needs a smallest indivisible unit, a fixed
subdivision, and a representation that cannot overflow silently. The
choice is frozen at genesis: changing it later is a redenomination,
the kind of event that breaks every wallet, explorer and ledger at
once.

## Decision

One ATU equals 100,000,000 atomic units (eight decimal digits, the
Bitcoin and NERVA convention). Amounts are unsigned 64-bit integers
of atomic units. The full supply, 16,180,339 ATU, is 1,618,033,900
million atomic units, leaving a factor of more than eleven thousand
of headroom under the u64 limit for intermediate sums and fee
arithmetic. All consensus arithmetic is checked: an overflow is a
validation error, never a wrap. Amounts display with exactly eight
decimals; there is no floating point anywhere in consensus code.

## Discarded options

Twelve decimals (Monero): the supply would occupy 19 digits and
leave under two percent of u64 headroom for sums. Six decimals:
coarser than the fee floor will ever need. Signed amounts: no
consensus rule ever produces a negative balance.

## Required validation

The unit constant and the display format are part of the transaction
vector set of the `antumbra-tx` crate; a divergence is a consensus
fault.

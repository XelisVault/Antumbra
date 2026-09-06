# ADR-009: the fee schedule, three visible components

Status: **Proposed**

## Context

The whitepaper fixes the fee model: a fixed part, a part proportional
to size, and a surcharge per ringed output. The values must exist
before the development network runs, be recitable, and leave the
adjustment path to governance as specified (the fixed part stays
within bounds by fast track, outside only by constitutional track).

## Decision

Fees are paid in atomic units, explicitly, in a clear field of every
transaction (amounts themselves remain committed under the Veil; the
fee is the one value written in clear, as in the CryptoNote lineage
since RingCT). The minimum fee is

`f = f0 + f_kB * ceil(size / 1024) + f_ring * m`

for a canonical transaction of `size` bytes and `m` ringed outputs.
Size is the size of the canonical encoding; charging is per started
kibibyte, minimum one. Provisional development values, frozen for
genesis at the end of phase 2: `f0 = 100,000` atomic units (0.001
ATU), `f_kB = 100,000`, `f_ring = 500,000` (a ring of sixteen keys
is the most expensive construction a node verifies). Governance
bounds on the fixed part: `[10,000, 1,000,000]` atomic units.

## Discarded options

Per-byte charging (finer but harder to recite and to audit on the
relay path); a market-priced mempool (contrary to the whitepaper: the
DAG ordering closes the front-running niche); a protocol levy on
fees (fees go entirely to miners).

## Required validation

The schedule and the minimum-fee function are covered by the
transaction vector set of `antumbra-tx`; every generated transaction
carries a fee at or above the formula output.

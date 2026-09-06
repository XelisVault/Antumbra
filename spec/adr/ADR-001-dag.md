# ADR-001: ordering layer, a fast-converging BlockDAG

Status: **Proposed**

## Context

The target cadence is two seconds per block. A linear
proof-of-work chain would lose an unsustainable share of its blocks to
orphans at that cadence; ring privacy also requires unspent outputs
to be numerous and well distributed.

## Decision

The ordering layer is a fast-converging block DAG of the GHOSTDAG
family: parallel blocks are ordered by consensus rule instead of being
rejected, and cumulative security grows with the total volume of
blocks. Pruning keeps the recent state and the proofs of the past so
that a full node fits on a personal computer.

## Discarded options

A linear chain with short blocks (prohibitive orphan rate); a chain
with a long cadence (confirmation too slow for the counter); committee
consensus for block production (capital lock, contrary to the
egalitarian principle).

## Required validation

An isolated prototype mining a CPU DAG at two seconds, then
twenty-four hours of development network without unexpected
reorganization (phase 2 of the roadmap).

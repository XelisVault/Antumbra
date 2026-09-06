# ADR-010: transparent transactions as the development scaffold

Status: **Proposed**

## Context

The whitepaper requires the Veil everywhere on mainnet: one-time
addresses, committed amounts, rings of sixteen, key images,
Bulletproofs. That stack is the correct final state and it is large.
Building it in one step would couple the validation of the
transaction container, the fee model and the canonical hashing to
the validation of five cryptographic constructions at once: the
zero-defect method forbids that coupling, because a fault found late
does not say which layer it came from.

## Decision

Version 1 transactions are transparent: outputs pay to a published
address and carry amounts in clear; inputs reference spent outputs
by transaction hash and index, embed the spend public key they claim
to unlock, and carry one Ed25519 signature each over the
zero-signature canonical encoding of the whole transaction. The
canonical encoding, the transaction id (Keccak-256 of the signed
encoding), the fee field, the sorted-inputs rule and the structural
limits defined here are final and survive unchanged into version 2.

Version 1 is a scaffold for the development network and the DAG
prototype only. Mainnet genesis accepts version 2 (Veil)
transactions exclusively: there is no transparent pool at genesis,
and version 1 transactions never existed on mainnet, so nothing has
to be migrated. The transition replaces, per input, the pair (key,
signature) by a ring of sixteen keys with an MLSAG signature, and,
per output, the pair (address, clear amount) by a one-time address
with a Pedersen commitment: the container around them does not
move.

Structural limits of the container, identical for both versions: at
most 64 inputs, 32 outputs, 512 bytes of extra data; inputs strictly
sorted by (transaction hash, index) and duplicate-free, so that the
canonical encoding is unique and transaction ids are
non-malleable.

## Discarded options

Implementing the Veil immediately (one fault, five suspects);
keeping a transparent pool on mainnet (contradicts privacy by
default and the data-minimization posture of the whitepaper);
segregating a test-only code path (double the surface to audit).

## Required validation

The full vector set of `antumbra-tx`: canonical encoding, id,
signatures and fee formula reproduced bit for bit by the independent
Python implementation; the limits and the sorted-inputs rule
exercised by rejection tests.

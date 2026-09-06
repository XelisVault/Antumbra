# The ANTUMBRA node code

This directory will host the full node implementation, starting at
phase 2 of the roadmap. The base is an assembly of proven foundations:
the CryptoNote lineage for the private sphere (one-time addresses,
Pedersen commitments, ring signatures, Bulletproofs), the GHOSTDAG
literature for the ordering layer, RandomX for CPU mining. Nothing
exotic: the novelty of the project is in the rules (Kleos, Ember,
Cipher, Lumen, Mandates), not in the primitives.

## Planned structure

```
code/
  node/          the full node: DAG, validation, propagation, RPC
  veil/          private transactions: ring 16, commitments, nullifiers
  ring/          signed checkpoints, quorum 37/55, era rotation
  kleos/         the three-layer reputation score and rules R1 to R4
  identities/    Ember (sponsorship, presence) and Cipher (perimeters)
  lumen/         bounded viewing keys and compliance proofs
  mandates/      predicate outputs: escrow, scheduled payments, caps
```

Every directory will be born with its test vectors and its crossing
reference, following the method of CONTRIBUTING.md: double
implementation always precedes assembly.

## The phase 2 starting point

The first milestone is a development network mining a CPU DAG at two
seconds, with Dandelion++ stem propagation, holding twenty-four hours
without unexpected reorganization. Everything before that milestone is
specification, not code.

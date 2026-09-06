# Contributing to ANTUMBRA

This project codes money: one fault can cost strangers real funds.
The bar is therefore higher than in an ordinary application project,
and the method below is not negotiable. It is detailed in the
whitepaper; this document is its executable version.

## The six verification layers

1. **Cross double implementation.** Every encoding, serialization or
   cryptography routine is ported twice, from the reference (C++, Rust,
   specification), and both implementations must produce bit to bit
   identical results over a generated and archived set of test vectors.
   A convention fault is not found by re-reading: it is crossed.
2. **Deterministic simulation before code.** Every social or economic
   rule (Kleos, sponsorships, the Ring draw, emission) is simulated
   first: fixed seed, numeric invariants, maximum attack replayed. See
   `simulations/kleos.py`, which revealed and fixed the flaw of the v2
   specification.
3. **Reproducible builds and random testing.** Executables build
   deterministically; massive random states are replayed continuously
   on the development network.
4. **Cross review.** Every merge is reviewed by a second person (human
   or assisted), with an archived report.
5. **External audit of the differential.** At phases 4 and 6 of the
   roadmap, an external auditor re-reads the complete differential
   since the previous phase.
6. **Public GO/NO-GO criteria.** Every roadmap phase has one measurable
   exit criterion; an unmet criterion blocks the next phase, and the
   NO-GO is published.

## Hygiene rules

- Never release-candidate code on a release branch; the main network
  runs only on stable, audited foundations.
- No unaudited exotic cryptographic primitive: we compose proven
  primitives, we do not invent them.
- Every consensus behavior change goes through an architecture decision
  (`spec/adr/`) before a single line of code.
- Commit messages stay factual: what changed, why, and which test
  proves it.
- Generated test vectors are archived: they are the memory of faults
  already caught.

## Reporting a flaw

A discovered flaw is reported privately through GitHub security
advisories, with a 90-day responsible disclosure window. Confirmed
flaws are credited in the public register once fixed.

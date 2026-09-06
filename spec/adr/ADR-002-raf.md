# ADR-002: finality, the Ring anchored on reputation (RAF)

Status: **Proposed**

## Context

Two-second inclusion is not enough: the payment must become
irreversible in seconds. Classical committee consensus obtains that
by locking capital, which amounts to selling finality.

## Decision

A committee of fifty-five seats, drawn each era among identities with
Kleos of at least 70 and Tenure of at least fifteen eras, signs
checkpoints every four seconds; the quorum of thirty-seven signatures
finalizes everything the checkpoint covers. A seat that signs a
competing fork is stripped: its Kleos is reset to zero. Should a third
of the seats fall silent, finality falls back on proof-of-work depth
(ten blocks, twenty seconds) and the next era removes the silent
seats. No capital is locked, no yield is paid: this is not proof of
stake.

## Required validation

Finality measured under six seconds over one hundred thousand replayed
blocks in phase 3, with injected failures and silent seats.

## Addendum (v1.2, from the first external audit): the Genesis Ring

The strict candidacy rule leaves a hole the audit named correctly: for
the first fifteen eras nobody can satisfy R1, so who signs on day one?
The answer is a published ratchet, stricter than the steady state,
never weaker, and with no appointed seats of any kind.

- Eras 0 to 2: no Ring exists; finality is proof-of-work depth (ten
  blocks, twenty seconds), the same fallback as a total committee
  outage.
- Era 3 on: candidacy opens with the tenure rule
  `min(15, era - 2)` eras of incident-free existence, alongside the
  Kleos threshold of 70 which never moves.
- Quorum ratchet: eras 3 to 9, quorum 45 of 55 (tolerates 10
  faulters); eras 10 to 17, quorum 41 of 55 (tolerates 14); era 18 on,
  the steady quorum 37 of 55 (tolerates 18). The committee weakens its
  supermajority only as the honest population deepens.
- Partial Ring: if fewer than 55 identities qualify, the committee is
  the qualified set, `n` seats with quorum `floor(2n/3) + 1`,
  activating at all only once at least 21 qualify; if none qualify,
  checkpoints do not start and depth finality continues.
- Anti-entrenchment: the draw happens every era as in the steady
  state, and no identity may hold a seat more than three consecutive
  eras; the fourth draw excludes it for one era.

No founder keys, no appointed council, no lowered guard: finality
degrades to twenty seconds for at most eighteen months, in exchange
for never once trusting an unearned reputation. The whitepaper
(Section 5, Table: the bootstrap ratchet) carries the full reasoning.

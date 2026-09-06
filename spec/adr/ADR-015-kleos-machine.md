# ADR-015: Kleos, the fixed-point reputation machine and the Ring draw

Status: **Proposed** (validated by the deterministic simulation)

## Context

ADR-003 defined the three-layer reputation (Deed 40, Echo 30,
Tenure 30) and the corrective rules R1 to R4; the simulation is
the regression test. The node now needs the consensus computation
itself, and the zero-defect method forbids floating point in
consensus code: float arithmetic is not associative, not
reproducible across platforms, and a reputation the chain computes
must be computable bit for bit by every node.

## Decision

**Millipoints, integers only.** Every Kleos quantity is a `u32`
count of thousandths of a point: Deed in `[0, 40 000]`, Echo in
`[0, 30 000]`, Tenure in `[0, 30 000]`, the total in
`[0, 100 000]`. Every constant of the simulation becomes an
integer: decay 100 (Deed) and 50 (Echo) per era, the attestation
budget 100, the per-target Echo cap 2 000 per era, the witness
floor weight 150, the minimum witnessing Deed 20 000 (R2), the
Ring threshold 70 000, the minimum Tenure 15 000 (R1), the fraud
penalties 3 000 (witness) and 5 000 (sponsor), the pooled Deed
share one quarter and the mutual Echo share one tenth (R4).
Rounding is floor division, the operation order is specified,
and every transition saturates at the layer bounds.

**The era transition is a pure state machine.** For an identity
with inputs `g_d` (Deed gain of the era, already discounted by
the closed-graph rule when it applies) and `g_e` (Echo gain of
the era, already capped per target):

```text
deed'   = clamp(deed + g_d - 100, 0, 40 000)
echo'   = clamp(echo + g_e - 50, 0, 30 000)
tenure' = tenure + 1            if the Tenure layer is alive,
          capped at 30 000;      frozen otherwise
```

The sanctions, applied as state transitions: a fraud conviction
empties the Echo, halves the Deed (floor), kills the Tenure layer
forever (zero and dead); a liable witness loses 3 000 Deed; a
liable sponsor 5 000; a Ring seat stripped by fork evidence
resets all three layers to zero and kills the Tenure. The witness
weight (R2) is zero below 20 000 Deed, then
`150 + 850 * (deed - 20 000) / 20 000` (floor), capped at 1 000;
an attestation contributes `budget * weight / 1 000` (floor) to
its target. Ring candidacy (R1) requires a total of at least
70 000, a Tenure of at least 15 000 and a living Tenure layer.

**The Ring draw is deterministic and weighted.** The draw of an
era takes the candidates (distinct identities, strictly ascending
by identity key), their Kleos totals as weights, an entropy
string (the chain commits it: the order root of the last
finalized checkpoint of the previous era), and a seat count. The
entropy is stretched into a word stream:
`word(i) = the first sixteen bytes, little endian, of
Keccak-256(entropy || u64_le(i))`. At each seat, the next word
`u` (a `u128`) selects the candidate whose cumulative weight
covers `r = u mod total`, the pool shrinks without replacement,
and the total is recomputed. The modulo bias is bounded by
`total / 2^128`, below 2^-100 for any reachable pool: smaller
than the rounding of the simulation that specified the rules.
Zero-weight candidates are never drawn; an empty total is an
error, never a panic.

## Discarded options

Floating point (not reproducible bit for bit; the simulation
keeps floats as the model, the integer crate is the normative
implementation); rational arithmetic (denominators grow without
bound across eras); rejection sampling for the draw (an
uncoverable branch in consensus code; the u128 word makes the
bias provably negligible instead); a rotation rule instead of a
fresh draw (the whitepaper fixes a weighted draw each era).

## Required validation

The full vector set of `antumbra-kleos`: era transition
sequences, sanction transitions, witness weights, capped Echo
accumulations and complete draw outputs reproduced bit for bit by
the independent Python implementation; the deterministic
simulation of `simulations/` still exits zero (the model and the
normative implementation state the same rules).

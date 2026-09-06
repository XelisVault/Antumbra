# ADR-014: the Ring container: checkpoints, quorum, stripping

Status: **Proposed**

## Context

ADR-002 chose Reputation-Anchored Finality: fifty-five seats
drawn each era, checkpoints every four seconds, a quorum of
thirty-seven signatures. The node prototype needs the exact
container of that mechanism before any network code, and the
zero-defect method (ADR-010, ADR-013) separates the final
container from the development scaffold.

## Decision

**The checkpoint message is final.** A checkpoint signs the
order, not a bare block: the message carries the era (`u64`, at
least one), the sequence within the era (`u64`, at least one),
the tip block id (`Hash`, never the zero hash: a checkpoint
signs a real block), and the order root, the canonical list hash
(the varint count then the ids, Keccak-256) of the consensus
order of that tip. The canonical encoding is
`version:u16 LE (1) | era:u64 LE | sequence:u64 LE | tip:32B |
order root:32B`, and the signing message is exactly those bytes:
a seat signs the encoding, a notary verifies without holding the
DAG.

**The checkpoint is final.** A checkpoint is the message plus a
list of at most fifty-five `(seat:u16 LE, signature:64B)` pairs,
strictly ascending by seat and distinct. Every signature must be
an Ed25519 signature of the message encoding under the public
key the roster of that era publishes for that seat. The quorum
is thirty-seven valid signatures (BFT: `n = 3f + 1 = 55`,
`f = 18`, `2f + 1 = 37`): at quorum, everything the message
covers is finalized. A roster smaller than the quorum (the
bootstrap eras, before enough identities reach the candidacy
threshold) simply never finalizes: finality falls back on
proof-of-work depth, ten blocks, twenty seconds, exactly as
ADR-002 specifies for silent seats.

**The stripping evidence is final.** A seat that signs a
competing fork is stripped: its Kleos resets to zero. The
evidence is a self-contained object: the seat index, and two
signatures of that seat over two different messages of the same
era and the same sequence. The verification: both signatures are
valid under the roster key of that seat, the eras match, the
sequences match, and the messages differ. Valid evidence is
consensus data: any node verifies it without trusting its
source, and the reputation layer (a later crate) consumes it to
reset the score.

**The scaffold is the roster.** The draw of ADR-002 (linear in
Kleos over the candidacy window) is a later, separately
validated milestone; here the roster is the input: an era number
and at most fifty-five public keys, one per seat. The draw
replaces the roster source without moving the container, exactly
as RandomX replaces the work function of ADR-013 and the Veil
replaces the transparent scaffold of ADR-010.

## Discarded options

A quorum scaling with the roster size (the whitepaper fixes 37
of 55; a smaller committee has a different fault economy and
deserves its own ADR if ever needed); signature aggregation
schemes (BLS, a new trust base for one byte saved); signing the
tip alone (does not commit the order the notary is supposed to
notarize); slashing a deposit (there is none: the sanction falls
on reputation, the only thing a validator owns that is precious).

## Required validation

The full vector set of `antumbra-ring`: message encodings and
digests, order roots, checkpoints at and below quorum, every
rejection path (bad signature, duplicate seat, out-of-range
seat, malformed bytes), and stripping evidence (valid and every
invalid shape) reproduced bit for bit by the independent Python
implementation; then finality measured under six seconds over
one hundred thousand replayed blocks in phase 3, with injected
failures and silent seats.

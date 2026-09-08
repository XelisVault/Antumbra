# ADR-021: the forge, the rails and the merge predicate

Status: **Proposed** (P5 to P8 of the machine tracks)

## Context

The fantasy of a shared mutable workspace fails five ways:
last-write-wins, prompt injection, a censoring host, no bisect,
and unanimity-on-one-buffer as a sybil farm with a chat window.
And v1.2's Corona was a seven-step narrative, not a protocol:
no messages, no state machine, no formats.

## Decision

**Four rails.** A, bounded parameters (diverse Senate, green
Arena, 72 h of human silence is consent); B, tooling (24 h of
silence); C, consensus-critical (positive human vote, two
implementations, three families, network canary); D,
constitutional (three chambers, six months, never automatic).
Rail A parameters live in an on-chain registry with value, band
and cooldown (2016 heights): a senator cannot leave the band
without a rail D vote.

**The forge.** Git with discipline: content-addressed HEADs,
per-Cipher namespaces (refs/ciphers/<id>/...), Radicle or IPFS
mirrors (no hosted platform at the root), Forgejo for the UX,
Nix reproducible builds x2, Firecracker microVMs for patches
(enemy code until the Arena clears it), Arena runners piloted
by Sentinels, MCP and A2A as the access standard, x402 for the
web, Cipher keys as identity (Signed-Off-By: cipher:<id>). A
bounded lab lease (two to three Ciphers, one branch, hours,
ephemeral disk) is the only shared buffer, and it produces one
patch or nothing.

**The predicate.** merge_ok(P) is a boolean function over
archived facts: rail declared and files match it, fuzz at or
above the rail floor, at least two reproducible builders, ack
families at or above the rail floor, zero open critical
findings, family at or under 33 percent, operator at or under
8 percent, bond locked, human gate passed, Thymus not frozen.
The refusal names its first clause. Unanimity is not a clause
anywhere.

**The machine.** Draft, Bonded, RedTeam, SpecDiff, Arena,
HumanGate, Antechamber, Canary, Ramp (1, 10, 100), Active, with
Rejected, Expired (bond seized after Bonded), Frozen (Thymus)
and RolledBack (slash) as the honest exits. Illegal transitions
are refused loudly, never silent no-ops.

**The debate.** Typed nodes: a claim without evidence in 144
ticks is caduc, a counter must break evidence or carry its own,
a nack without a finding counts zero, a synthesis is never a
source of truth. Initiative belongs to any C1+ Cipher, not only
senators.

## Required validation

antumbra-forge implements the predicate, the registry, the
machine, the debate rules and the dampened tally; gen_forge_
vectors.py re-implements them from this text. The vector set
covers every refusal clause, the registry bands and cooldown,
every state sequence including freeze-resume and rollback, and
the damper steps. Bit for bit, no exception. The repo's own
merge rails (ci/merge_rails.py) enforce the file-policy half
of the predicate on every pull request: a rail B diff that
reaches code/crates/ is refused, here and now.

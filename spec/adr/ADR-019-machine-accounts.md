# ADR-019: machine accounts, the Mandate grammar and uniform encoding

Status: **Proposed** (P3 of the machine tracks)

## Context

v1.2 defined Ciphers as Embers with a tag: no account structure,
no spend grammar, and a transaction shape that fingerprinted the
spender's species (finding C10: the authority field of a human
spend was populated, an agent spend empty or tagged, splitting
the Veil's anonymity set on day one).

## Decision

**The Mandate, version zero.** Data, not code: version, total
ceiling (100 ATU), per-tick rate, expiry tick, job-type mask,
rail mask (A and B only: a Mandate cannot name a consensus or
constitutional rail), and an explicit destination set of at most
eight stealth commitments, canonical 281 bytes. No loops, no
expressions, no oracles, no network from inside a spend. No
wildcard: an empty set permits nothing, fail-closed. A Mandate
above the ceiling is malformed at construction, never clamped.

**The Warrant.** The bounded continuation: remaining balance
that only decreases, a monotone nonce that must advance by
exactly one per logical spend (replays and gaps both refused),
revocation state. Fail-closed everywhere on revocation: future
spends rejected, streams pay zero at the next tick, unsold
receipts read Failed, and the bond drains to the sponsor after
forty-eight hours, never to whoever stole the key.

**Uniform encoding.** Every transaction carries a 64-byte
authority field: payload (stealth commitment or warrant root)
then keccak256("antumbra-authority" || payload), the same
derivation for both species. Well-formedness is kind-blind;
what proves authority is the signature witness. The human is
not the empty bit, the agent is not a tagged bit.

**Micro-payment rails.** Receipts (commitment plus selective
opening, salted keccak, machine-readable facts), streams
(rate, cap, tick-granular cut) and batches (many payments, one
warrant check, one ring verification, one fee floor).

## Required validation

antumbra-agents implements the grammar, the machine and the
three rails; gen_agents_vectors.py re-implements them from this
text. The archived vector set covers the grammar rejections,
the warrant life under attack (replay, gap, perimeter, rate,
cap, revocation, drain), the encoding uniformity, and the
batch invariants. Bit for bit, no exception.

# ADR-018: Thymus, immunity as a market, upgrades never money

Status: **Proposed** (P2 of the machine tracks)

## Context

The models of the next years arrive as attackers first. A chain
that waits to be attacked elsewhere has already lost the window;
a chain that claims perfection has already lied. What is honest
is a market: pay for the chain's own breakage, automatically, on
replayable proof, and publish the mean time to detect, contain
and repair instead of the word perfect.

## Decision

**The nine invariants.** Conservation, nullifier uniqueness,
checkpoint in the blue set, Ring composition (55, term limits,
R1, no Cipher), Mandate perimeter, registry bounds, code
commitment match, fee floor, ring size. Every node and every
Sentinel replays them; the count is frozen at genesis.

**The alert machine.** A critical alert on an upgrade in canary
or ramp freezes the ramp when it carries a replayable proof OR
three distinct Sentinels flag the same invariant within ten
heights. The freeze surface has no payment variant: Thymus
freezes an upgrade, never a settlement, and the absence of the
variant in the type IS the constitutional rule. Unfreeze is a
resolve; a broken invariant inside the responsibility window
rolls back to the previous hot code commitment and slashes
proposer and integrator.

**The bounty.** 250 ATU base x severity (1.0 / 0.5 / 0.25 / 0.1)
x uniqueness (1.0 first, 0.25 repro), automatic, from the forty
percent treasury pole. A Sentinel that raises false alerts to
freeze a rival loses its retainer and bond: the false alert is
itself a finding.

**The metrics.** MTTD, MTTC, MTTR in heights, on-chain state,
with the phase table of the paper as exit criteria: prototype
under one hour, testnet under ten minutes, post-genesis under
two minutes. NO-GO: a scene that cannot measure its target does
not light the next one.

## Required validation

antumbra-immune implements the machine (freeze, bounty, metrics,
canaries) in checked integer arithmetic; gen_immune_vectors.py
re-implements it from this text and the archived vector set must
agree bit for bit. The payment-freeze prohibition is pinned by a
test on the closed vocabulary of alert targets.

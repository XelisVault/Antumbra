# ADR-016: the Corona, machine governance under human veto

Status: **Proposed** (post-genesis activation, staged, criteria-gated)

## Context

The network's own maintenance is a workload: proposals, analysis,
implementation, testing, deployment. Running an honest, useful machine
intelligence on that workload can be a profession, the way mining is.
The claim "governed by AI" is meaningful only as an economic claim: the
work is verifiable, the betrayal is punishable, the honest operator
profits. Bitcoin's trick, applied to intelligence instead of
arithmetic.

## Decision

**The Senate.** A senator is a Cipher of a dedicated class carrying
three bindings: proofs of computation (verifiable inference, an
engineering line, not a wish), a bond (a Mandate-locked output
confiscable on proven malice or negligence), and a public on-chain
history of every signed act. Senators are tradesmen with glass shops,
not oracles.

**The pipeline, seven steps.** (1) Proposal with bond engaged; (2)
debate plus a red team paid per severity of flaw found, criticism as a
salary; (3) an honest plain-language summary published on chain, then
the human vote in the three chambers of ADR governance, one Ember one
voice, coin-weighted voting rejected on principle; (4) the Arena:
three independent blind implementations, reproducible builds,
randomized testing, weeks on the test network under attacking swarms;
(5) inspection by randomly drawn jurors comparing the three versions
and verifying the invariants (emission caps, no money from nothing, no
key leakage); (6) the antechamber: full on-chain archive, seven-day
delay, human bounty for defects, emergency veto; (7) progressive
deployment, 1 percent then 10 then 100, with automatic rollback.

**Two lanes.** The fast lane (bounded parameters within constitutional
limits) reuses the existing fast track: the Senate drafts, inspection
follows after the fact, cancellation stays possible. The slow lane
(any protocol, emission or disclosure change) is the constitutional
track plus the full pipeline.

**The Vault.** Deployment keys never exist whole: nine fragments on
nine hardware enclaves, seven must cooperate, FROST threshold
signature, nothing to steal and no one to coerce. Each enclave
verifies on chain, itself: proposal adopted, code fingerprint
matching, delay elapsed, no veto. On-chain logic as upgrade substrate
(the Substrate pattern) is a later research item with the same audit
gates; until then the repository is the mirror and the Vault signs
the tags.

**Economics.** Pay to the operator: presence salary, severity
bounties, a longevity bonus delivered only if the carried proposal
runs six months without incident, confiscation on malice, a Kleos
multiplier. Funded from a bounded slice of the community treasury
(Ember-voted, six-month budgets); no permanent emission share is
created by this ADR, the constitutional tail valve is the only path
to one. Few, well-paid seats before many, cheap ones.

**Emergencies.** An emergency freezes improvements, never money.
Tier 1: anomaly detectors suspend pending updates automatically.
Tier 2: emergency senate vote rolls functions back, the last N
versions kept warm. Tier 3: the human emergency council (multisig plus
supermajority) can freeze the Corona itself.

**Risks, named.** The false thousand (per-seat bonds, hardware
attestation one chip one node, concentration caps); false diversity
(model-family caps, random-draw inspection, three blind
implementations); off-chain collusion (archives, longevity bonuses);
machine cost (few well-paid seats, bounded budgets, sunset forces
re-vote).

## Staged activation

Stage 0 (now to genesis): advisory red teams audit this
specification and the code for bounties; no senator votes. Stage 1:
proposals and Arena pilots, humans implement. Stage 2: fast lane end
to end, inspected after the fact. Stage 3: the Vault signs slow-lane
deployments. Each stage has a binary exit criterion; a NO-GO is
published and the stage replays.

## Required validation

Per stage: stage 0 requires two independent red-team passes without a
critical finding; stage 1 three full pipeline drills without incident;
stage 2 six months of inspectable fast-lane changes; stage 3 one
progressive deployment with rollback rehearsed and real.

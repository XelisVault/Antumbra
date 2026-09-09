# ADR-025: the development node

Status: **Proposed**

## Context

The roadmap phase 2 (P0) asks for one thing before anything else: a node.
The repository holds the layers as libraries — the ordering layer
(`antumbra-dag`), the transaction container (`antumbra-tx`), the state
ledger with the emission transaction (`antumbra-state`), the primitives
beneath them — and no binary that assembles them into a running network
participant. The exit criterion of P0 is written in the whitepaper:
`antumbra-node` assembled, an honest status of the development network,
the minimum invariants, and a day of DAG — twenty-four hours of blocks
with the conservation and tip invariants held.

The assembly surfaced two holes that this decision records.

**The store.** The reference `Dag` of the ordering layer is the normative
oracle, and it is deliberately simple: it materializes the transitive
past and the blue set of every block. That is exact and wrong to scale:
the closures are quadratic in the block count, so a day of development
blocks (43,200 at two seconds each) would ask for tens of gigabytes.
The crate itself announces the replacement ("the production window
replaces it"); the node is where it becomes necessary.

**The key binding.** The state ledger (ADR-024) checks existence,
unspentness, double spending, maturity, conservation and the coinbase
rules — and never checks that an input's claimed key is the spend key of
the output it spends. The transaction layer verifies each signature
against the key the input claims, and nothing binds that key to the
output's address. On the development network a hand-built block can
therefore spend someone else's output with its own key. This is a
consensus rule missing from the state layer, not from the node: it is
recorded here, enforced at node admission (below), and scheduled as the
next rail-C change to `antumbra-state` with its regenerated vector set.
Until that change lands, P2P block validation is a NO-GO: a node that
accepts remote blocks cannot yet reject theft.

## Decision

**The crate `antumbra-node` is the assembly.** A library plus one
binary, `antumbra-node`, depending only on the four protocol crates:
no new external dependency, no clock of its own, no configuration
files. The binary exposes two commands:

- `antumbra-node genesis` — prints the development network genesis id.
  The genesis is the frozen constant of the ordering layer; the command
  exists so that an operator can compare a boot against the archived
  vector.
- `antumbra-node day [--blocks N] [--difficulty B] [--spend-every K]` —
  the P0 driver: boots the node on the devnet genesis, mines N blocks
  (default 43,200, one devnet day), applies each to the ledger, checks
  the invariant battery after every block, and prints the honest
  status. The process exits zero only if every invariant held on every
  block and no breach was recorded.

**The store is two paths over one bookkeeping.** The node keeps, for
every accepted block: its header, its blue score, its selected parent,
its children, the fresh set (the blocks its view adds over its selected
parent's view, sorted by height then id), and its order length. It
maintains the tips and the materialized consensus order of the best tip
with a position index. The order is append-only along selected-parent
chains, so extending it is O(1) in the common case and a walk bounded
by the fork depth otherwise.

- *The chain path.* A single-parent block is colored exactly in O(1):
  its past is its parent's past plus the parent, so the candidate set
  of the coloring is empty, the blue set inherits the selected parent
  and the parent itself, the blue score is the parent's plus one, and
  the fresh set is the block alone. No closure is materialized, ever.
  This path serves blocks at any height; the day of DAG runs on it.
- *The fork path.* A multi-parent block is a merge, and its coloring
  needs the full reference algorithm. The node holds a live mirror of
  the reference `Dag`, fed every accepted block, while the total block
  count stays within the **reference window** of 1,024 blocks; a merge
  is colored by the mirror and the bookkeeping copies its answers
  (selected parent, blue score, fresh set as the order suffix). Past
  the window the mirror is dropped and a multi-parent block is a
  policy rejection, `MergeBeyondWindow`: the development network is a
  solo miner that appends to the best tip and never merges; deeper
  merge validation belongs to the P2P phase, with a store of its own.

The equivalence claim is exact and bounded: on every reachable state
within the reference window, the two paths answer the selected parent,
the blue score, the tips, the best tip and the consensus order exactly
as the reference crate does. The differential tests prove it on
randomized fork-heavy DAGs, mixed single- and multi-parent, against an
independent reference instance; the chain path is additionally compared
past the window on a solo run. The reference `Dag` remains the
normative oracle; this store is the production shape the ordering
layer's own documentation announces.

**The ledger application is incremental with a total rebuild
fallback.** After every insertion the node applies the suffix the best
tip adds over the ledger's frontier (the common case: one block). If
the best tip moved to a chain whose order does not extend the
frontier's, the ledger is rebuilt from scratch over the new order,
exactly as ADR-024 specifies for reorganizations. The incremental path
is an optimization that must match the reference rebuild — the tests
compare the engine's rebuilt state against an independently rebuilt
ledger after a deliberate deep reorg.

**Admission enforces what consensus does not yet.** A transaction
enters a block only through the mempool, which checks: the container
and fee rules of the transaction layer, the signature verification, the
existence and unspentness of every input in the ledger and in the
mempool itself, the maturity of coinbase outputs — and **the key
binding**: the claimed key must be the spend key of the output's
address. The last rule is the node-level enforcement of the finding
above; it moves into the state layer with the next rail-C change.

**The development network policy.** The devnet node mines under the
devnet policy of the ordering layer (sixteen bits of Keccak work, two
minutes of tolerated drift; the scaffold, not RandomX). The clock is
synthetic and deterministic: block n carries the timestamp
`GENESIS_TIMESTAMP_MS + n * 2_000`. The driver mines on the best tip
alone. The activity script is deterministic: every `spend-every` blocks
(default sixteen) the miner wallet spends its oldest matured output
worth spending — at least twice the schedule minimum fee — one
third to Alice, the rest back as change, the fee the schedule
minimum — and every twice that, Alice spends half of her oldest
output worth spending to Bob. The worth floor keeps the script
honest forever: the half-splits of a spending lineage decay
geometrically against the flat fee, and the decayed outputs below
the floor are dust — honest residue that stays unspent — instead
of a breach. All wallets derive from fixed devnet seeds by
Keccak-256, the treasury included (ADR-024). Everything the run
prints is a function of the block count and the seeds alone.

**The minimum invariants, after every block.**

1. Conservation: `created = spent + emitted` (the state layer's own
   check).
2. Slot alignment: the ledger's applied count equals the best tip's
   view size, and the frontier is the best tip.
3. Emission accounting: the emitted total equals the independent sum
   of `reward_of_slot` over the applied slots (recomputed by the node,
   not trusted from the ledger).
4. Treasury accounting: the treasury balance equals the independent
   sum of the treasury shares.
5. Tip shape: the solo driver holds exactly one tip at all times.
6. Wallet truth: the wallet trackers equal the ledger snapshot
   filtered by address (checked periodically and at the end).
7. Mempool hygiene: no admitted transaction claims a spent output.

A breach of any invariant stops the day and fails the process: the
numbers are published, not hidden. A day that ends green says exactly
"these invariants held on these blocks" and nothing else.

**The honest status.** The status is a fixed set of fields (blocks,
height, tips, order length, best tip, created, spent, emitted,
treasury, unspent outputs, transactions, spend transactions, rebuilds,
breaches, invariant verdicts) canonically encoded and hashed: the
**status id**. Two runs of the same day must print the same status id —
that is the determinism gate, in CI and in the wild. The rendered text
adds the devnet time (block count times two seconds) and the wall time,
which the id excludes, and the honest language of ADR-023: this is a
development scaffold under the Keccak work function, RandomX and the
privacy layer arrive later, and the claim of the run is the invariant
list above, nothing more.

## Discarded options

A clap-based CLI (a binary with no external dependency is auditable in
one read); persistent storage on disk (the day is one process; state on
disk arrives with sync, when there is something to sync); running the
day on the reference store (quadratic memory, tens of gigabytes);
a windowed reimplementation of the coloring inside the node (the
reference mirror is exact by construction within the window; a
hand-rolled window would need its own proof of equivalence against the
same oracle); fixing the key binding inside this change (the state
layer, its vectors and the Python mirror move together on rail-C, and
the assembly does not amend consensus rules in passing).

## Required validation

The differential battery: randomized mixed DAGs against an independent
reference, comparing tips, best tip, blue scores, selected parents and
full consensus orders after every insertion, single-parent insertions
exercising the chain path and merges the fork path; the same battery
past the window with a merge rejection. The day battery: a
deterministic day slice run twice with identical status ids; the
maturity gate (an early spend refused at admission, a matured spend
applied); the double-spend refusal at admission and the in-block
rejection by the ledger; the fork reorg that switches the best tip and
rebuilds the ledger to the state an independent rebuild computes; the
invariant list green. The CI runs a day slice twice under the
sixteen-bit devnet difficulty with the determinism gate, and the full
43,200-block day is an operator run recorded as P0 exit evidence.

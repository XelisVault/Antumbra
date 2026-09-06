# ADR-013: the ordering layer protocol: block container, work scaffold, coloring, order

Status: **Proposed**

## Context

ADR-001 chose a fast-converging BlockDAG of the GHOSTDAG family; the
node prototype needs its exact consensus rules before any line of
the DAG code. The zero-defect method (ADR-010) separates what is
final from what is a development scaffold, so that a fault found in
the prototype says which layer it came from.

## Decision

**The block container is final.** A block header carries: a version
(`u16`, value 1), the parent list (one to sixteen block ids,
strictly ascending, distinct; the genesis block alone carries the
single zero hash), the height (`u64`: one plus the maximum parent
height, zero for the genesis), a timestamp (`u64`, milliseconds
since the Unix epoch), a nonce (`u64`), and the payload root
(Keccak-256 of the canonical transaction id list: varint count then
the ids, strictly ascending, distinct, at most sixty-four). The
block id is Keccak-256 of the canonical header encoding. The
canonical encoding, the structural limits, the sorted rules and the
id are frozen: they survive unchanged into mainnet.

**The work function is the scaffold.** On the development network
the proof of work is Keccak-256 itself: a block is valid when its
id carries at least `d` leading zero bits (`d = 16` on the devnet,
a policy parameter, not a header field). Mainnet replaces the
function by RandomX over the same canonical header bytes and checks
the difficulty on the RandomX output; the container, the difficulty
semantics and the nonce field do not move. As with ADR-010, the
scaffold is never a mainnet pool: no devnet block exists on
mainnet, so nothing migrates.

**The coloring is normative and simple.** For a block `B` with
parents `P` and selected parent `sp` (the parent with the highest
blue score, ties broken by the smallest id), the blue set of `B`
is inherited then grown: the working set starts as the blue set of
`sp` plus `sp` itself (the selected parent is always blue, and the
blues of `sp` survive, so the blue score strictly grows along the
chain); then every block of `past(B) \ (past(sp) ∪ {sp})` is a
candidate, in decreasing blue score then increasing id, and a
candidate `v` joins when the number of blocks of the working blue
set that are neither in `past(v)`, nor in `future(v)`, nor equal
to `v` (the anticone of `v` inside the view of `B`) is at most
`K = 8`. The blue score of `B` is one plus the size of its blue
set. Blocks of the view that are not blue are red; red blocks
stay ordered, they only weigh nothing in chain selection. This
closure-based definition is the reference: any optimized
implementation (incremental merges, bounded windows) must
reproduce it exactly on every reachable state, verified by
differential testing against this one.

**The consensus order is a stable chain append.** The order of the
view of `B` (the genesis plus every ancestor of `B`) is defined
recursively: the order of the genesis is the genesis alone; the
order of `B` is the order of `sp` followed by the blocks of
`view(B) \ view(sp)` sorted by height then id. The sorted block is
topologically consistent (heights strictly increase along
ancestry), and no block of `view(sp)` can be a descendant of a new
block, so the concatenation is a total order that extends, never
reshuffles: a payment confirmed in an order stays at its position.
The genesis of the development network is fixed: timestamp
1,750,000,000,000 (2025-06-15T15:06:40Z), nonce zero, empty
payload; its id is archived in the cross vector set.

Insertion validates, in order: the canonical form (strict decode),
the payload root against the transaction id list, the block id
against the encoding, a duplicate id, a parent list that is neither
empty nor the genesis list, every parent known, the announced
height, a timestamp at or after every parent timestamp, a timestamp
at most `max_future` milliseconds after the node clock, and the
proof of work under the policy difficulty. The ledger rules
(existence, unspentness, double-spend resolution by order, fee
schedules) are not ordering rules: they consume the order and
belong to the state layer.

## Discarded options

A linear chain (rejected in ADR-001); the exact Kaspa merge order
(operational complexity without a stability benefit at devnet
scale; this order is simpler to specify, to cross-validate and to
prove topological); difficulty as a header field (consensus state,
not block data, until an ADR says otherwise); adaptive difficulty
(a devnet constant first; the adaptation controller is a later,
separately validated milestone).

## Required validation

The full vector set of `antumbra-dag`: header and block encodings,
ids, the payload root, the work function, the coloring and the
consensus order of complete DAGs reproduced bit for bit by the
independent Python implementation; the rejection paths exercised
by decode and insertion vectors; the topological and
prefix-stability invariants of the order asserted on generated
DAGs; then twenty-four hours of development network without
unexpected reorganization (phase 2 exit criterion).

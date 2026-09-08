# ADR-024: the emission transaction (coinbase)

Status: **Proposed**

## Context

ADR-007 fixed the emission calendar: a cap of 16,180,339 ATU, thirty-four
four-year eclipses each emitting the fraction 1/phi of the first, a
community treasury of 6.18% of rewards for the first eight eclipses, no
premine. ADR-013 froze the block container: the header carries no reward
field, and the payload is a list of transaction ids. The transaction
types (ADR-010) froze tags 0 to 5 without an emission type. The result
is a hole the assembly of the node (P0) made unavoidable: the state
layer cannot be written until the protocol says, exactly, how new units
enter the ledger and how fees return to miners.

## Decision

**The emission is a transaction, type Coinbase, wire tag 6.** The tag is
additive: tags 0 to 5 keep their frozen numbering and their reserved
status; no existing encoding changes meaning.

**Container rules, enforced by the transaction layer.** A Coinbase
transaction has no inputs, a zero fee field, one or two outputs, and an
extra field of exactly eight bytes carrying the height of the block it
pays, little-endian `u64`. The generic rules (at least one output,
non-zero amounts) are unchanged. A Coinbase pays no fee and is exempt
from the minimum-fee rule: it has no inputs to pay with.

**One coinbase per block, the state layer enforces the value.** Every
block except the genesis carries exactly one Coinbase transaction; the
genesis payload is empty (no premine). The declared height in the extra
field must equal the containing block's height. The total of the
outputs must equal the reward of the block's slot plus the fee fields
of every other transaction of the same payload: a coinbase claims its
own block's fees and nothing else.

**The reward arithmetic is integer and exact.** One eclipse spans
B = 63,115,200 blocks (four years of two-second blocks, the calendar
year of 365.25 days). The reward of a block is a function of its
**slot**: its position in the consensus order, the genesis being slot
0 and minting nothing, so the eclipse of slot n is `(n - 1) / B` for
`n >= 1`. Slot indexing keeps every reward unique over any DAG shape
(two blocks may share a height; no two blocks share a slot), closes
the cap exactly over any order, and makes a reorg reprice the rewards
of the winning order by construction, which the rebuild already
does. The eclipse emissions, in whole ATU, are the archived table of
the emission calendar: 6,180,340 then 3,819,660, thirty-three values
in all, the thirty-fourth absorbing the remainder to the cap. The
table is reproduced exactly, without floating point, by the closed
form `e(n) = floor(E0 * R^n)` with `R = (sqrt(5) - 1) / 2` evaluated
over integers: expanding `(sqrt(5) - 1)^n = A + B*sqrt(5)` by the
binomial theorem with integer A and B, the floor is
`(E0*A + isqrt(5*(E0*B)^2)) / 2^n` when `B > 0`, and
`(E0*A - isqrt(5*(E0*B)^2) adjusted) / 2^n` when `B < 0`, the
fractional correction of one unit applied as the floor of a negative
irrational. The per-block reward in atomic units is the eclipse
emission times 10^8 spread over B slots: `base + 1` atom for the
first `remainder` slots of the eclipse, `base` afterwards, where
`base` and `remainder` are the quotient and the rest of the division
of the eclipse emission (in atomic units) by B. The spread closes
each eclipse exactly and the cap exactly.

**The development network pays every block of the order.** The
payment set of the mainnet — every ordered block, or the blue set
alone, red blocks weighing nothing — is an economic decision the
development scaffold does not freeze: it is a rail-C change, decided
by ADR before genesis. The ledger therefore consumes the consensus
order and pays the coinbase of each block at that block's slot; the
node passes the order, and the payment set of a future ADR becomes a
filter the node applies when it builds that order.

**The treasury is mechanical.** For the first eight eclipses (slots 1
to 8B), the coinbase carries exactly two outputs: the first pays the
miner, the second pays the treasury and equals
`(reward * 618) / 10000` atomic units, rounded down; the miner keeps
the rest. From the ninth eclipse on, the coinbase carries exactly one
output and the treasury is extinguished. The treasury address is a
consensus constant: on the development network it is derived from the
fixed seeds `antumbra-treasury-spend-devnet` and
`antumbra-treasury-view-devnet` (Keccak-256, devnet network byte); on
mainnet it is published at the genesis ceremony. The governance of the
treasury key belongs to the Ember chamber and to no one else; the
ledger only verifies the destination.

**Maturity.** An output of a coinbase may not be spent by a
transaction whose block sits earlier than ten slots after the
coinbase's block in the consensus order. Ten is the depth of the
proof-of-work fallback of ADR-002: a coinbase output becomes spendable
no earlier than it becomes depth-final. The number is policy: the
governance tracks may move it.

**The intra-block order is the canonical one.** The ledger consumes
blocks in the consensus order and, inside a block, transactions by
ascending transaction id: the payload is stored sorted, the order is
the id order. Double spending resolves by this total order: the first
spender wins, later spenders are rejected.

**Reorganizations rebuild.** The reference ledger is rebuilt from the
consensus order of the winning tip, exactly like the reference DAG is
rebuilt from its closures: simple, total, reproducible. Incremental
rebuilds are an optimization that must match this reference by
differential testing.

## Discarded options

A reward field in the header (the header is frozen by ADR-013, and the
reward is policy, not block data); paying fees outside a transaction
(the UTXO set could not see the payment); immediate spendability of
coinbase outputs (the depth-finality window of ADR-002 exists); a
float-based calendar (not bit-exact across languages; the archived
float script is validated by the integer closed form instead, not
replaced); chaining `floor(e/phi)` eclipse by eclipse (floor drift:
the third eclipse would differ from the archived table by one ATU).

## Required validation

The vector set of `antumbra-state`: the thirty-four eclipse emissions
reproduced from the integer closed form in both implementations; the
reward and treasury split at boundary heights; accepted and rejected
coinbases (value, split, treasury destination, height, count,
maturity); the ledger applied over generated block sequences with
chained spends, double spends resolved by order, the conservation
invariant `created = spent + emitted` after every case; the rebuild of
a reorganized tip reproducing the state of the winning order; the
rejected-transaction battery naming every violated rule.

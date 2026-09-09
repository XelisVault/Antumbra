# ADR-026: the key binding rule

Status: **Proposed**

## Context

ADR-024 built the state ledger around what a block payload does: it
resolves inputs against the UTXO set, refuses double spends, holds
coinbases to maturity, and conserves value. It never asks *who* is
spending. The transaction layer (ADR-010) verifies each signature
against the key the input claims — and nothing binds that key to the
output being spent. An address is a network byte, a spend public key
and a view public key (the primitives layer); the spend key is the
owner, and the ledger holds it in every entry, unused.

ADR-025 assembled the node, hit exactly this hole, and recorded it: a
hand-built block can spend someone else's output with its own key —
a valid signature over a theft. The node enforces the binding at
mempool admission as a stopgap, and the ADR schedules the real fix as
the next rail-C change to `antumbra-state` with its regenerated
vector set. Until the rule lives in the ledger, P2P block validation
is a NO-GO: a node that accepts remote blocks cannot reject theft.
This ADR is that change.

## Decision

**The binding is a ledger rule, not a transaction-layer rule.** The
transaction layer is self-contained: it validates one payload against
its own encoding, and resolving an output reference requires the very
UTXO set the ledger owns. The rule therefore lands where the
reference resolves.

**The rule.** In the transfer validation loop, immediately after the
referenced entry resolves (from the ledger or from the same-block
scratch) and after the in-block unspentness check, and before the
maturity check: the public key an input claims must equal the spend
public key of the resolved entry's address. A mismatch is the named
error `KeyNotBound { reference }`; the ledger stands exactly where it
stood. The order is deliberate and mirrored in the Python
implementation: existence, unspentness, ownership, maturity — the
owner is checked before the clock, so a case that is both unbound and
immature reports the binding, and the reject case names are stable.

**The coinbase is exempt.** A Coinbase transaction has no inputs
(ADR-024), so the loop never runs for it; nothing else changes for
coinbase validation. Outputs created by a coinbase are bound the
moment they exist: their entry carries the miner address, and only
its spend key may spend them, after maturity.

**The node admission keeps its check.** The mempool of ADR-025
already refuses a mis-bound input (`KeyNotOwner`) before a block is
assembled. The check stays, re-documented from "the stopgap" to
admission feedback: it rejects a theft in milliseconds instead of
after a mining round, and it is defense in depth in front of the
consensus boundary. The boundary itself is now the ledger: a
hand-built or remote block that carries a mis-bound input is rejected
by `Ledger::apply_block` with `KeyNotBound`, which lifts the P2P
NO-GO of ADR-025.

**The vector set regenerates (rail-C).** The archived vectors of
ADR-024 claim arbitrary keys for honest spends — valid under the old
rules, theft under the new one. The generator now derives every
party's address from a recorded seed, honest inputs claim the true
spend public key of the output's address, and two new reject cases
pin the rule: a correctly-signed theft of a transfer output and a
correctly-signed theft of a matured coinbase output — both with
valid signatures by the thief's key, both rejected as `KeyNotBound`
with the ledger at the prefix state. The Python mirror adds the rule
in the same position of the same loop.

## Discarded options

**Binding in the transaction layer.** Rejected: `antumbra-tx` sees
bytes, not the UTXO set. Moving reference resolution there would
duplicate the ledger or invert the layering.

**Waiting for the Veil core.** The ring-signature layers re-express
ownership entirely; one could argue the scaffold binding is
throwaway. It is not: the devnet and every future test network run
on the scaffold, P2P validation must be sound on the scaffold, and
the transparent binding is the simplest statement of the invariant
the veil layers must preserve — the spender proves ownership of the
spent output, not of a claimed key.

**Removing the mempool check** once the ledger owns the rule.
Rejected: admission is the cheap place to refuse; the consensus
check is the authoritative one, and both naming the same fault is
the intended shape.

## Required validation

The regenerated state vector set: every apply case replays with
honest keys and conserves; the reject battery grows by the two theft
cases, each leaving the ledger exactly at the prefix; both
implementations agree bit for bit on stats and snapshots. The node
day battery: the theft of a matured output is refused at admission
(`KeyNotOwner`) and, as a hand-built block, breaches at the ledger
(`StateError::KeyNotBound`) with the store, the ledger and the
invariant battery intact after the breach. The differential battery
of ADR-025 unchanged and green. The CI runs the whole wall; the
43,200-block day remains the operator run, now with the binding on
every input of every block.

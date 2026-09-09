# The ANTUMBRA node code

This directory is the Cargo workspace of the node: one crate per
subsystem of the whitepaper, born in roadmap order, and the
`antumbra-node` binary that assembles them into one running
network participant (ADR-025). The primitives layer comes first
because every other layer hashes, signs, encodes or parses through
it; the node comes last because it is the assembly.

## Layout

```
code/
  Cargo.toml                  workspace root
  deny.toml                   license and advisory policy
  crates/
    antumbra-primitives/      hashes, canonical encoding, keys, addresses
    antumbra-tx/              version 1 transactions: fees, canonical hashing, the Coinbase type
    antumbra-veil/            the private sphere: one-time addresses,
                              commitments, key images, ring signatures
    antumbra-dag/             the ordering layer: the BlockDAG, headers,
                              the work scaffold, the consensus order
    antumbra-ring/            the finality layer: checkpoint messages,
                              seat signatures, quorum, stripping evidence
    antumbra-kleos/           the reputation layer: the fixed-point
                              score machine, the era draw
    antumbra-immune/          Thymus: invariants, canaries, alerts,
                              bounties, the honest metrics
    antumbra-agents/          machine accounts: Cipher keys, mandates,
                              warrants, payment batches
    antumbra-jobs/            the JobBoard: classes, jobs,
                              submissions, pay-for-result
    antumbra-forge/           the Corona v2: rails, proposals,
                              debates, votes, the merge predicate
    antumbra-state/           the state layer: the UTXO ledger, the
                              coinbase and the emission calendar (ADR-024)
    antumbra-node/            the assembly: the store, the engine, the
                              mempool, the wallets, the invariant
                              battery, the honest status, the binary
  scripts/
    gen_vectors.py            the independent (Python) implementation
                              that generates the primitives cross vectors
    gen_tx_vectors.py         the independent (Python) implementation
                              that generates the transaction cross vectors
    gen_veil_vectors.py       the independent (Python) implementation
                              that generates the Veil core cross vectors
    gen_dag_vectors.py        the independent (Python) implementation
                              that generates the ordering layer cross vectors
    gen_ring_vectors.py       the independent (Python) implementation
                              that generates the finality layer cross vectors
    gen_kleos_vectors.py      the independent (Python) implementation
                              that generates the reputation layer cross vectors
    gen_immune_vectors.py     the independent (Python) implementation
                              that generates the Thymus cross vectors
    gen_agents_vectors.py     the independent (Python) implementation
                              that generates the machine-account cross vectors
    gen_jobs_vectors.py       the independent (Python) implementation
                              that generates the JobBoard cross vectors
    gen_forge_vectors.py      the independent (Python) implementation
                              that generates the Corona cross vectors
    gen_state_vectors.py      the independent (Python) implementation
                              that generates the ledger and calendar cross vectors
    requirements.txt          the Python dependencies of the generators
```

Crates to come, in milestone order: `antumbra-identities` (Ember
and Cipher on chain), `antumbra-lumen` (viewing keys), and the
network layer that turns one node into many (peer discovery,
gossip, sync) — the P2P phase after the node prototype holds.

## The primitives crate

Everything consensus-critical at the byte level:

| Module | Contents |
|---|---|
| `hash` | Keccak-256, the single identifier hash of the protocol |
| `varint` | canonical unsigned LEB128, non-canonical forms rejected |
| `encode` | canonical `Writer`/`Reader`: fixed-width integers, strict booleans, varint counts, length-prefixed bytes |
| `keys` | Ed25519 key pairs, view seed derivation (Keccak of the spend seed), strict verification |
| `base58` | CryptoNote block base58 with full canonicality checks |
| `address` | network byte + spend key + view key + Keccak-4 checksum, 95 characters |

## The transaction crate

Version 1 transactions, the transparent scaffold of ADR-010: a
final container (canonical encoding, transaction id, fee field,
structural limits, strictly sorted inputs) around clear amounts and
per-input Ed25519 signatures, replaced by the Veil constructions in
version 2 without moving the container. The Coinbase type of
ADR-024 (wire tag 6, additive to the frozen tags 0 to 5) joins the
container here: no inputs, a zero fee, one or two outputs, an
eight-byte little-endian height in the extra field.

| Module | Contents |
|---|---|
| `amount` | u64 atomic units, eight decimals (ADR-008), checked arithmetic |
| `fee` | the three-component schedule and the minimum-fee formula (ADR-009) |
| `error` | one enum for every rejection, each carrying the offending value |
| `tx` | canonical encoding, signing message, transaction id, strict decoding, stateless validation, the Coinbase container rules |

## The Veil core crate

The cryptographic core of the private sphere (ADR-011), the four
constructions every version 2 transaction assembles. The curve is
the Ed25519 curve of the transparent sphere; the group arithmetic
is curve25519-dalek, cross-validated by a from-spec Edwards25519 in
the vector generator. One invariant everywhere: every point of the
protocol belongs to the prime-order subgroup, which closes the
torsion attack class on key images in a single rule.

| Module | Contents |
|---|---|
| `curve` | Edwards25519 scalars and points, strict canonical decoding, prime-order subgroup rule |
| `error` | one enum for every rejection, each carrying the offending bytes |
| `hash` | Hs, the hash to scalar; Hp, the hash to point with cofactor clearing |
| `seed` | RFC 8032 wallet scalars, spend and view, reduced to canonical form |
| `onetime` | the shared secret Hs(rA) = Hs(aR), the one-time address P = Hs(rA) G + B, wallet scanning |
| `commitment` | the value generator H (a NUMS point), Pedersen commitments C = vH + bG |
| `keyimage` | the one-time secret key p = Hs(aR) + b, the key image I = p Hp(P) |
| `ring` | the MLSAG linkable ring signature over the ring of sixteen (ADR-012) |

The range proof arrives in a later milestone and reuses this crate
unchanged: it consumes the points, scalars, hashes and commitments
defined here.

## The ordering layer crate

The BlockDAG of ADR-001 as ADR-013 specifies it exactly: a final
block container (canonical header encoding, block id, structural
limits, sorted parents, sorted transaction ids, payload root)
around a development scaffold for the work function (Keccak-256
leading bits; RandomX replaces the function on mainnet without
moving the container). The coloring and the order are the
normative, closure-based reference: blue set, blue score, selected
parent and the append-only consensus order, all deterministic in
the accepted set alone:

| Module | Contents |
|---|---|
| `header` | the final header container: canonical encoding, block id, sorted parents, height, timestamp, nonce, payload root |
| `block` | the header plus the ordered transaction ids, the payload root commitment, strict decoding, the devnet genesis |
| `pow` | the work scaffold: leading zero bits, the difficulty check, the deterministic mining walk |
| `dag` | the reference store: insertion rule battery, the coloring (K-cluster), the selected parent, tips, the consensus order |
| `error` | one enum for every rejection, each carrying the offending value |

The ledger rules (existence, unspentness, double-spend resolution
by order) consume the consensus order and live in the state layer.

## The finality layer crate

The Ring of ADR-002 as ADR-014 specifies it exactly: the final
containers of Reputation-Anchored Finality, not proof of stake —
no capital is locked, no yield is paid. The scaffold is the
roster source: the weighted draw over the candidacy window is a
later milestone; here the roster is the input, an era and at
most fifty-five keys:

| Module | Contents |
|---|---|
| `message` | the checkpoint message: era, sequence, tip, order root; the canonical encoding is the signing message |
| `roster` | the seats of an era, the quorum constant (37 of 55), the checkpoint cadence (4 s) |
| `checkpoint` | the message plus the strictly sorted seat signatures, the verification battery, the quorum |
| `equivocation` | the stripping evidence: two conflicting signatures of one seat, verifiable by any node |
| `error` | one enum for every rejection, each carrying the offending value |

The order root reuses the canonical list hash of the ordering
layer (`payload_root`): one implementation of one hash,
cross-validated by two vector sets.

## The reputation layer crate

The Kleos machine of ADR-003 as ADR-015 specifies it exactly: the
three-layer score (Deed 40, Echo 30, Tenure 30) as a fixed-point
integer state machine, because consensus code must compute bit
for bit on every platform and floating point cannot promise that.
Every quantity is a `u32` of millipoints, every transition
saturates at the layer bounds, every rounding is a floor, and the
operation order is specified:

| Module | Contents |
|---|---|
| `score` | the state: era transition with decay and saturation, the sanctions (fraud conviction, liable witness, liable sponsor, seat stripping), the queries (witness weight, Ring candidacy), the Echo helpers (R2 weighting, the per-target cap, the R4 discounts) |
| `draw` | the era draw of the Ring: the Keccak word stream, the weighted linear draw without replacement over the live pool |
| `error` | one enum for every rejection, each carrying the offending value |

The chain feeds the era inputs and the draw entropy (the order
root of the last finalized checkpoint of the previous era); it
never touches the arithmetic. The deterministic simulation of
`simulations/` remains the regression test of the rules
themselves; this crate is their normative integer form.

## The machine-economy crates (v1.3)

Four crates specify the machine economy as code, each
cross-validated like the protocol layers:

| Crate | Contents |
|---|---|
| `antumbra-immune` | Thymus: the nine invariants, the canaries, the alerts with severities, the bounty accounting, the commitment to publish MTTD, MTTC and MTTR on chain — "relatively very resistant", never "perfect" |
| `antumbra-agents` | the machine accounts: Cipher keys under sponsor warrants, bounded Mandates with the declarative grammar and its interdits, receipts, payment batching |
| `antumbra-jobs` | the JobBoard: job classes and certifications, the job lifecycle, submissions, the pay-for-result split of ADR-020 |
| `antumbra-forge` | the Corona v2: the four rails, the bounded proposals, the Senate debate rounds, the votes under the family and operator caps, the merge predicate a node can check in one read |

## The state layer crate

The ledger the ordering layer deferred (ADR-024): the UTXO set,
the spent references, the totals, and the emission as a
transaction. Every rule is checked before any mutation (the apply
is atomic), the double spending resolves by the consensus order,
and the reorganization rebuild is total and reproducible. The
eclipse calendar is an exact integer closed form — no floating
point anywhere, reproducible in any language, equal to the
archived float calendar eclipse for eclipse.

| Module | Contents |
|---|---|
| `coinbase` | the emission calendar: the 34 eclipse emissions by the integer Lucas-Fibonacci closed form, the per-slot reward spread, the treasury split (6.18%, eight eclipses), the ten-slot maturity, the devnet treasury address |
| `ledger` | the UTXO ledger: existence, unspentness, in-block chaining, double spend, maturity, conservation, the coinbase battery, the atomic apply, the totals, the snapshot, the rebuild over an order |
| `error` | one enum for every rejection, each carrying the offending value |

## The node crate

The assembly (ADR-025): the library and the binary that turn the
protocol crates into a running network participant. No external
dependency beyond the protocol crates; no clock of its own; no
configuration file. Two paths color a block in the store — the
O(1) exact chain path for single-parent blocks (the candidate set
of the coloring is provably empty for them) and the fork path
that delegates merges to a live mirror of the reference `Dag`
within a 1,024-block window, refusing deeper merges as policy.
The differential tests compare every answer against an
independent reference instance on randomized fork-heavy DAGs.

| Module | Contents |
|---|---|
| `store` | the node store: the per-block bookkeeping (header, ids, score, selected parent, fresh set, order length), the tips, the materialized best order, the two coloring paths, the reference mirror and its window |
| `engine` | the assembly: the payload and coinbase assembler, the mining step, the suffix application, the total rebuild on reorg, the deterministic activity script, the day driver |
| `mempool` | the admission layer: container and fee rules, signatures, existence, unspentness, maturity, and the key binding the ledger does not check yet (ADR-025) |
| `wallet` | the devnet wallets from fixed seeds: the coinbase construction, the one-input transfer with the minimum fee, the output trackers in credit order |
| `invariants` | the minimum battery: conservation, slot alignment, emission and treasury accounting recomputed independently, tip shape, mempool hygiene, wallet truth |
| `status` | the honest devnet status: the canonical fields, the deterministic status id, the rendered report with the honest language of ADR-023 |
| `devnet` | the development network constants: the synthetic clock, the difficulty, the wallets from fixed seeds |
| `cli` | the two commands: `genesis` and `day`, hand-parsed |

## Building and testing

```bash
cargo test --workspace       # unit tests + cross vectors + the node battery
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo build --workspace --release --locked
```

The CI runs the full battery on every push and every pull request
(format, lint, tests, release build, docs, dependency audit,
license policy, vector regeneration, the Kleos and emission
simulations, the whitepaper compile, repository hygiene, the
merge-rail policy, and the node day slice run twice under the
determinism gate).

## Running the node

```bash
cargo run --release --locked --bin antumbra-node -- genesis
cargo run --release --locked --bin antumbra-node -- day
```

The first command prints the frozen devnet genesis id — the
constant the ordering layer's cross vector set archives. The
second mines one devnet day (43,200 two-second blocks by default)
on the best tip, applies each block to the ledger, checks the
invariant battery after every block, and prints the honest
status: the numbers, the invariant verdicts, the deterministic
status id. The process exits zero only if every invariant held on
every block; a breach is printed, named, and red. `--blocks`,
`--difficulty` and `--spend-every` tune the run; two runs of the
same parameters print the same status id.

## The cross vector method

Every output-producing routine is implemented twice: once here in
Rust, once independently in `scripts/` (pycryptodome for Keccak-256,
SHA-512 and the Ed25519 reference keys, from-spec reimplementations
for the encodings and the whole Edwards25519 group of the Veil).
Eleven generators cover the eleven crates that compute: the
primitives, the transactions, the Veil core, the ordering layer,
the finality layer, the reputation layer, Thymus, the machine
accounts, the JobBoard, the Corona and the state layer; each
writes an archived vector set to the `tests/vectors.json` of its
crate, and each Rust test suite must reproduce all of it bit for
bit. To regenerate:

```bash
pip install -r scripts/requirements.txt
python3 scripts/gen_vectors.py
python3 scripts/gen_tx_vectors.py
python3 scripts/gen_veil_vectors.py
python3 scripts/gen_dag_vectors.py
python3 scripts/gen_ring_vectors.py
python3 scripts/gen_kleos_vectors.py
python3 scripts/gen_immune_vectors.py
python3 scripts/gen_agents_vectors.py
python3 scripts/gen_jobs_vectors.py
python3 scripts/gen_forge_vectors.py
python3 scripts/gen_state_vectors.py
```

The generators verify their own output before writing it (strict
roundtrip, signature verification, rule checks); the vectors are
committed: they are the memory of faults already caught. Editing
them by hand is forbidden; only the generators write those files.

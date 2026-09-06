# The ANTUMBRA node code

This directory is the Cargo workspace of the node: one crate per
subsystem of the whitepaper, born in roadmap order. The primitives
layer comes first because every other layer hashes, signs, encodes
or parses through it.

## Layout

```
code/
  Cargo.toml                  workspace root
  deny.toml                   license and advisory policy
  crates/
    antumbra-primitives/      hashes, canonical encoding, keys, addresses
    antumbra-tx/              version 1 transactions: fees, canonical hashing
    antumbra-veil/            the private sphere: one-time addresses,
                              commitments, key images, ring signatures
    antumbra-dag/             the ordering layer: the BlockDAG, headers,
                              the work scaffold, the consensus order
    antumbra-ring/            the finality layer: checkpoint messages,
                              seat signatures, quorum, stripping evidence
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
    requirements.txt          the Python dependencies of the generators
```

Crates to come, in milestone order: `antumbra-kleos` (reputation),
`antumbra-identities` (Ember and Cipher), `antumbra-lumen`
(viewing keys), `antumbra-mandates` (predicate outputs) and the
`antumbra-node` binary that assembles them.

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
version 2 without moving the container:

| Module | Contents |
|---|---|
| `amount` | u64 atomic units, eight decimals (ADR-008), checked arithmetic |
| `fee` | the three-component schedule and the minimum-fee formula (ADR-009) |
| `error` | one enum for every rejection, each carrying the offending value |
| `tx` | canonical encoding, signing message, transaction id, strict decoding, stateless validation |

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
| `block` | the header plus the ordered transaction ids, the payload root commitment, strict decoding |
| `pow` | the work scaffold: leading zero bits, the difficulty check, the deterministic mining walk |
| `dag` | the store: insertion rule battery, the coloring (K-cluster), the selected parent, tips, the consensus order |
| `error` | one enum for every rejection, each carrying the offending value |

The ledger rules (existence, unspentness, double-spend resolution
by order) consume the consensus order and live in the state layer,
a later milestone.

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

## Building and testing

```bash
cargo test --workspace       # unit tests + cross vectors
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo build --workspace --release --locked
```

The CI runs the full battery on every push and every pull request
(format, lint, tests, release build, docs, dependency audit,
license policy, vector regeneration, and the Kleos and emission
simulations).

## The cross vector method

Every output-producing routine is implemented twice: once here in
Rust, once independently in `scripts/` (pycryptodome for Keccak-256,
SHA-512 and the Ed25519 reference keys, from-spec reimplementations
for the encodings and the whole Edwards25519 group of the Veil).
`gen_vectors.py` covers the primitives, `gen_tx_vectors.py` the
transaction layer, `gen_veil_vectors.py` the Veil core,
`gen_dag_vectors.py` the ordering layer, `gen_ring_vectors.py`
the finality layer; each writes
an archived vector set to the `tests/vectors.json` of its crate, and
each Rust test suite must reproduce all of it bit for bit. To
regenerate:

```bash
pip install -r scripts/requirements.txt
python3 scripts/gen_vectors.py
python3 scripts/gen_tx_vectors.py
python3 scripts/gen_veil_vectors.py
python3 scripts/gen_dag_vectors.py
python3 scripts/gen_ring_vectors.py
```

The generators verify their own output before writing it (strict
roundtrip, signature verification, rule checks); the vectors are
committed: they are the memory of faults already caught. Editing
them by hand is forbidden; only the generators write those files.

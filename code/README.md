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
  scripts/
    gen_vectors.py            the independent (Python) implementation
                              that generates the primitives cross vectors
    gen_tx_vectors.py         the independent (Python) implementation
                              that generates the transaction cross vectors
```

Crates to come, in milestone order: `antumbra-veil` (one-time
addresses, rings, commitments, replacing the transparent scaffold
of version 1), `antumbra-dag` (the BlockDAG ordering layer),
`antumbra-ring` (checkpoints and finality), `antumbra-kleos`
(reputation), `antumbra-identities` (Ember and Cipher),
`antumbra-lumen` (viewing keys), `antumbra-mandates` (predicate
outputs) and the `antumbra-node` binary that assembles them.

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

## Building and testing

```bash
cargo test --workspace       # unit tests + cross vectors
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo build --workspace --release --locked
```

The CI runs the full battery on every push and every pull request
(format, lint, tests, release build, docs, dependency audit,
license policy, and the Kleos and emission simulations).

## The cross vector method

Every output-producing routine is implemented twice: once here in
Rust, once independently in `scripts/` (pycryptodome for Keccak-256
and Ed25519, from-spec reimplementations for the encodings).
`gen_vectors.py` covers the primitives, `gen_tx_vectors.py` the
transaction layer; each writes an archived vector set to the
`tests/vectors.json` of its crate, and each Rust test suite must
reproduce all of it bit for bit. To regenerate:

```bash
python3 scripts/gen_vectors.py
python3 scripts/gen_tx_vectors.py
```

The generators verify their own output before writing it (strict
roundtrip, signature verification, rule checks); the vectors are
committed: they are the memory of faults already caught. Editing
them by hand is forbidden; only the generators write those files.

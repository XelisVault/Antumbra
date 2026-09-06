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
  scripts/
    gen_vectors.py            the independent (Python) implementation
                              that generates the cross vectors
```

Crates to come, in milestone order: `antumbra-veil` (private
transactions), `antumbra-dag` (the BlockDAG ordering layer),
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
| `encode` | canonical `Writer`/`Reader`: fixed-width integers, strict booleans, length-prefixed bytes |
| `keys` | Ed25519 key pairs, view seed derivation (Keccak of the spend seed), strict verification |
| `base58` | CryptoNote block base58 with full canonicality checks |
| `address` | network byte + spend key + view key + Keccak-4 checksum, 95 characters |

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
Rust, once independently in `scripts/gen_vectors.py` (pycryptodome
for Keccak-256 and Ed25519, a from-spec reimplementation for the
encodings). The generator writes an archived vector set to
`crates/antumbra-primitives/tests/vectors.json`; the Rust test
suite must reproduce all of it bit for bit. To regenerate:

```bash
python3 scripts/gen_vectors.py
```

The vectors are committed: they are the memory of faults already
caught. Editing them by hand is forbidden; only the generator
writes that file.

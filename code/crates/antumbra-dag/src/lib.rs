//! ANTUMBRA ordering layer: the BlockDAG (ADR-013).
//!
//! This crate implements the consensus rules of the ordering layer
//! that ADR-001 chose (a fast-converging BlockDAG of the GHOSTDAG
//! family) as ADR-013 specifies them exactly. The block container
//! (canonical header encoding, block id, structural limits, sorted
//! parents, sorted transaction ids, payload root) is final and
//! survives unchanged into mainnet; the proof-of-work function is
//! the development scaffold: Keccak-256 leading bits here, RandomX
//! over the same canonical header bytes on mainnet, the difficulty
//! semantics untouched.
//!
//! The same three rules as the primitives crate apply:
//!
//! 1. No silent defaults. Decoding is strict and total: a
//!    non-canonical, oversized or unsorted block is an error, never
//!    a normalization.
//! 2. Cross double implementation. Every output-producing routine
//!    (encodings, ids, the payload root, the work function, the
//!    coloring, the consensus order) is reproduced independently
//!    (`code/scripts/gen_dag_vectors.py`) over an archived vector
//!    set (`tests/vectors.json`); both must agree bit for bit.
//! 3. The normative algorithms are the simple ones. The blue set
//!    and the order are defined over transitive closures: exact,
//!    reproducible, reference-grade. Optimized implementations must
//!    match this crate on every state, by differential testing.
//!
//! The ledger rules (existence, unspentness, double-spend
//! resolution by order) consume the consensus order and belong to
//! the state layer, not here.

pub mod block;
pub mod dag;
pub mod error;
pub mod header;
pub mod pow;

pub use block::{payload_root, Block, MAX_TXS};
pub use dag::{Dag, Policy, GENESIS_TIMESTAMP_MS, K};
pub use error::DagError;
pub use header::{Header, MAX_PARENTS, VERSION_1};
pub use pow::{leading_zero_bits, meets_difficulty, mine};

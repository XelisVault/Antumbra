//! ANTUMBRA consensus primitives.
//!
//! The smallest layer of the node: everything every other subsystem
//! (transactions, blocks, the DAG, the Ring) hashes, signs, encodes
//! or parses goes through this crate. Because these routines are
//! consensus-critical, three rules apply:
//!
//! 1. No silent defaults. Encoding is canonical and decoding is
//!    strict: a non-canonical byte sequence is an error, never a
//!    normalization.
//! 2. Cross double implementation. Every output-producing routine
//!    is reproduced by an independent implementation
//!    (`code/scripts/gen_vectors.py`) over an archived vector set
//!    (`tests/vectors.json`). Both must agree bit for bit.
//! 3. Proven primitives only. Keccak-256, Ed25519, block base58:
//!    assembled, never invented.

pub mod address;
pub mod base58;
pub mod encode;
pub mod hash;
pub mod keys;
pub mod varint;

pub use address::{Address, Network};
pub use base58::{base58_decode, base58_encode};
pub use encode::{DecodeError, Reader, Writer};
pub use hash::{keccak256, Hash};
pub use keys::{KeyPair, PublicKey, SecretKey, Signature};

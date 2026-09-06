//! ANTUMBRA Veil: the cryptographic core of the private sphere
//! (ADR-011).
//!
//! Four constructions of the whitepaper live here, each a named,
//! cross-validated routine with one encoding and one error surface:
//! the one-time destination addresses, the deterministic shared
//! secret, the Pedersen commitments and the key images. The ring
//! signature and the range proof of version 2 transactions arrive in
//! later milestones and reuse this crate unchanged.
//!
//! The same three rules as the primitives and transaction crates
//! apply:
//!
//! 1. No silent defaults. Decoding is strict: a non-canonical,
//!    small-order or identity point, a zero or oversized scalar is
//!    an error, never a normalization.
//! 2. Cross double implementation. Every output-producing routine is
//!    reproduced independently (`code/scripts/gen_veil_vectors.py`,
//!    a from-spec Edwards25519 over pycryptodome hashes) over an
//!    archived vector set (`tests/vectors.json`); both must agree
//!    bit for bit.
//! 3. Proven primitives only. The curve arithmetic is
//!    curve25519-dalek, the hashes Keccak-256 and SHA-512 as
//!    specified by RFC 8032: assembled, never invented.
//!
//! State-dependent rules (nullifier storage, commitment equality
//! across a spend, ring composition) belong to the transaction
//! assembly and the ordering layer; this crate validates and derives
//! everything that is decidable from the keys alone.

pub mod commitment;
pub mod curve;
pub mod error;
pub mod hash;
pub mod keyimage;
pub mod onetime;
pub mod seed;

pub use commitment::{commit, value_generator, VALUE_GENERATOR_DOMAIN};
pub use curve::{Point, Scalar};
pub use error::VeilError;
pub use hash::{hash_to_point, hash_to_scalar, HASH_TO_POINT_ROUNDS};
pub use keyimage::{key_image, one_time_secret, owned_secret};
pub use onetime::{ephemeral, is_ours, one_time_address, shared_secret};
pub use seed::{clamped_scalar, rfc8032_clamped_bytes, spend_scalar, view_scalar};

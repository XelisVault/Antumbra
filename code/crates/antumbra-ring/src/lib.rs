//! ANTUMBRA finality layer: the Ring (ADR-002, ADR-014).
//!
//! Being included in a two-second block is not enough: a payment
//! must become irreversible in seconds. The Ring is a committee
//! of at most fifty-five seats, drawn each era among high
//! reputation identities, that signs a checkpoint every four
//! seconds; thirty-seven valid signatures finalize everything
//! the checkpoint covers. A seat that signs a competing fork is
//! stripped: its Kleos resets to zero. This is not proof of
//! stake: no capital is locked, no yield is paid; the power of
//! finality derives from reputation, and reputation derives from
//! behavior and time.
//!
//! The containers of this crate are final (ADR-014): the
//! checkpoint message (era, sequence, tip, order root), the
//! checkpoint with its strictly sorted seat signatures, and the
//! stripping evidence (two conflicting signatures of one seat).
//! The scaffold is the roster source: the weighted draw of
//! ADR-002 is a later milestone; here the roster is an input,
//! an era number and at most fifty-five public keys.
//!
//! The same three rules as the primitives crate apply:
//!
//! 1. No silent defaults: decoding is strict and total.
//! 2. Cross double implementation: every output-producing
//!    routine is reproduced independently
//!    (`code/scripts/gen_ring_vectors.py`) over an archived
//!    vector set (`tests/vectors.json`); both must agree bit
//!    for bit.
//! 3. Verification never trusts its source: a checkpoint or a
//!    stripping evidence is checked against the roster alone.

pub mod checkpoint;
pub mod equivocation;
pub mod error;
pub mod message;
pub mod roster;

pub use checkpoint::Checkpoint;
pub use equivocation::Equivocation;
pub use error::RingError;
pub use message::CheckpointMessage;
pub use roster::{Roster, CHECKPOINT_INTERVAL_MS, QUORUM, SEATS};

/// The canonical list hash reused as the order root: the varint
/// count, then the ids, then Keccak-256. The same construction
/// as the payload root of the ordering layer, one implementation
/// of one hash, cross-validated by two vector sets.
pub use antumbra_dag::payload_root as order_root;

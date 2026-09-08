//! ANTUMBRA machine-account layer (ADR-021, ADR-022).
//!
//! A Cipher is a machine identity: an Ed25519 key held by an
//! agent process, sponsored by a human Ember, spending under a
//! [`Mandate`] through a [`Warrant`]. The Mandate is the
//! envelope of rights (what, how much, to whom, until when);
//! the Warrant is the bounded continuation that actually moves
//! value. Neither can mint, read the Veil, vote at the Ring, or
//! touch a constitutional rail: those powers do not exist in
//! these types, and their absence is the design, not an
//! omission.
//!
//! Four rules are load-bearing:
//!
//! 1. **The permit is explicit.** An empty destination set
//!    permits nothing: there is no wildcard, "*" is not a
//!    destination, and a Mandate above the amount ceiling is
//!    malformed at construction, never clamped later.
//! 2. **Fail-closed on revocation.** A revoked Warrant rejects
//!    future spends, its streams pay zero at the next tick,
//!    and its unsold receipts read `Failed`: the bond drains
//!    to the sponsor, never to the attacker.
//! 3. **Uniform encoding.** A human stealth authority and an
//!    agent warrant authority encode to the same sixty-four
//!    bytes with the same internal derivation: an observer
//!    cannot split the anonymity set by field shape. The
//!    human is not the empty bit.
//! 4. **Micro-payments live.** A batch amortizes one ring
//!    verification over many outputs under the same warrant:
//!    the fee schedule charges the batch, not each atom.
//!
//! Integers only, floor division, saturating bounds, no silent
//! defaults: the same arithmetic on every node, forever. Every
//! output-producing routine is cross-validated by an independent
//! implementation (`code/scripts/gen_agents_vectors.py`) over an
//! archived vector set (`tests/vectors.json`).

pub mod batch;
pub mod encode;
pub mod error;
pub mod mandate;
pub mod receipt;
pub mod stream;
pub mod warrant;

pub use batch::{batch, BatchOutcome, Payment, BATCH_MAX_PAYMENTS};
pub use encode::{Authority, AUTHORITY_BYTES};
pub use error::AgentError;
pub use mandate::{Mandate, MANDATE_MAX_DESTS};
pub use receipt::{Fact, Receipt, ReceiptStatus};
pub use stream::{tick, Stream, StreamState};
pub use warrant::{Warrant, DRAIN_DELAY_TICKS};

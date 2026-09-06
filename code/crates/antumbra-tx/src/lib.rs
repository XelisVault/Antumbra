//! ANTUMBRA version 1 transactions: the transparent scaffold.
//!
//! This crate implements the transaction layer of the whitepaper as
//! architecture decision ADR-010 specifies it: a final container
//! (canonical encoding, transaction id, fee field, structural limits,
//! sorted inputs) around a development scaffold of clear amounts and
//! per-input Ed25519 signatures. The Veil constructions of version 2
//! (one-time addresses, committed amounts, rings, key images) replace
//! the scaffold without moving the container.
//!
//! The same three rules as the primitives crate apply:
//!
//! 1. No silent defaults. Decoding is strict and total: a
//!    non-canonical, oversized or unsorted transaction is an error,
//!    never a normalization.
//! 2. Cross double implementation. Every output-producing routine
//!    is reproduced independently (`code/scripts/gen_tx_vectors.py`)
//!    over an archived vector set (`tests/vectors.json`); both must
//!    agree bit for bit.
//! 3. Checked arithmetic only. Amounts and fees never wrap: an
//!    overflow is a rejection.
//!
//! State-dependent rules (existence and unspentness of referenced
//! outputs, amount conservation against the referenced outputs,
//! network consistency) belong to the ordering layer and are not
//! reimplemented here; this crate validates everything that is
//! decidable from the transaction bytes alone.

pub mod amount;
pub mod error;
pub mod fee;
pub mod tx;

pub use amount::{Amount, ATOMIC_PER_ATU};
pub use error::TxError;
pub use fee::{FeeSchedule, F0_MAX, F0_MIN, FEE_BASE, FEE_PER_KIB, FEE_PER_RINGED_OUTPUT};
pub use tx::{
    OutputRef, Transaction, TxIn, TxOut, TxType, MAX_EXTRA_LEN, MAX_INPUTS, MAX_OUTPUTS, VERSION_1,
};

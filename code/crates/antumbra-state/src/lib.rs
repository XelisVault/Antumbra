//! ANTUMBRA state layer: the ledger (ADR-024, ADR-026).
//!
//! The ordering layer (ADR-013) deferred its state rules to this
//! crate: existence, unspentness, double-spend resolution by the
//! consensus order, the key binding of an input to the spend key of
//! the output it spends (ADR-026), conservation, and the emission
//! transaction of ADR-024 with its calendar, its treasury split and
//! its maturity.
//!
//! The same three rules as the other protocol crates apply:
//!
//! 1. No silent defaults. Every rule is named: a rejected block
//!    returns an error that says which rule it broke, and the
//!    ledger is left exactly where it stood.
//! 2. Cross double implementation. Every output-producing routine
//!    (the calendar, the reward and treasury arithmetic, the
//!    ledger applied over generated orders) is reproduced
//!    independently (`code/scripts/gen_state_vectors.py`) over an
//!    archived vector set (`tests/vectors.json`); both must agree
//!    bit for bit.
//! 3. Checked arithmetic only. Amounts never wrap: an overflow is
//!    a rejection, not a surprise.
//!
//! The ledger is pure: it holds no clock, no network and no
//! configuration. Two nodes holding the same consensus order and
//! the same payloads compute the same state, which is the whole
//! point of the layer.

pub mod coinbase;
pub mod error;
pub mod ledger;

pub use coinbase::{
    calendar, devnet_treasury_address, expected_coinbase, reward_of_slot, treasury_active_at_slot,
    treasury_share_of, BLOCKS_PER_ECLIPSE, CAP_ATOMIC, E0_ATU, ECLIPSES, ECLIPSE_EMISSIONS_ATU,
    MATURITY, TREASURY_DENOMINATOR, TREASURY_ECLIPSES, TREASURY_NUMERATOR,
};
pub use error::StateError;
pub use ledger::{BlockPayload, Entry, Ledger};

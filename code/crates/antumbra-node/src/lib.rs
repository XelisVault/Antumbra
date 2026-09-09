//! ANTUMBRA node: the assembly (ADR-025).
//!
//! The protocol crates of this workspace are libraries: the
//! ordering layer, the transaction container, the state ledger and
//! the primitives beneath them. This crate is the node that
//! assembles them into one running network participant, and the
//! `antumbra-node` binary that drives the development network of
//! the P0 milestone: a boot on the frozen devnet genesis, a mining
//! and ledger loop, the minimum invariant battery after every
//! block, and the honest status that ends a day of DAG.
//!
//! The same three rules as the protocol crates apply:
//!
//! 1. No silent defaults. Every rejection is named: a store
//!    refusal, a mempool admission refusal, a ledger rejection and
//!    an invariant breach are distinct, reported, and never
//!    swallowed.
//! 2. The reference stays the oracle. The node store colors
//!    single-parent blocks exactly in O(1) (the candidate set of
//!    the coloring is empty for them) and delegates merges to a
//!    live mirror of the reference `Dag` within the reference
//!    window; the differential tests compare every answer against
//!    an independent reference instance.
//! 3. Determinism everywhere. No clock reading enters consensus
//!    data: the devnet clock is synthetic, the activity script is
//!    a function of the block count and the fixed devnet seeds,
//!    and two runs of the same day print the same status id.
//!
//! The node enforces one rule the ledger does not have yet
//! (ADR-025, the key binding): an admitted input must claim the
//! spend key of the output it spends. The consensus-level rule and
//! its vector set are the next rail-C change; until it lands,
//! accepting remote blocks is a NO-GO.

pub mod cli;
pub mod devnet;
pub mod engine;
pub mod invariants;
pub mod mempool;
pub mod status;
pub mod store;
pub mod wallet;

pub use devnet::{
    alice, bob, miner, BLOCK_INTERVAL_MS, DEFAULT_DAY_BLOCKS, DEFAULT_DIFFICULTY, SPEND_EVERY,
};
pub use engine::{run_day, Breach, DayOutcome, DevnetWallets, EmissionChecks, Engine, Stats};
pub use mempool::{AdmitError, Mempool};
pub use status::{Reported, Status};
pub use store::{NodeError, Store, REFERENCE_WINDOW};
pub use wallet::{SpendError, TrackedWallet, Tracker, Wallet};

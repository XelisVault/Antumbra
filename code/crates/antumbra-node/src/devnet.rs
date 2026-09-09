//! The development network constants and wallets (ADR-025).
//!
//! Everything here is a fixed seed or a fixed number: two nodes,
//! two runs, two languages reproduce the same devnet. The clock is
//! synthetic — block `n` carries `GENESIS_TIMESTAMP_MS +
//! n * BLOCK_INTERVAL_MS` — so no wall reading ever enters a
//! header. The wallets of the activity script derive from Keccak
//! seeds the same way the treasury address of ADR-024 does.

use antumbra_primitives::{keccak256, KeyPair, Network};

use crate::wallet::Wallet;

/// Two seconds per block: the cadence of the whitepaper.
pub const BLOCK_INTERVAL_MS: u64 = 2_000;

/// One devnet day of blocks: 43,200 two-second blocks.
pub const DEFAULT_DAY_BLOCKS: u64 = 43_200;

/// The devnet difficulty: sixteen bits of Keccak work, the
/// scaffold of the ordering layer. RandomX arrives on mainnet and
/// changes the function, not the cadence.
pub const DEFAULT_DIFFICULTY: u32 = 16;

/// The activity script interval: every sixteen blocks the miner
/// wallet spends its oldest matured coinbase output.
pub const SPEND_EVERY: u64 = 16;

/// The mining budget: mean work at sixteen bits is 65,536 tries;
/// four million tries leaves a failure probability below 2^-40.
pub const MINING_ATTEMPTS: u64 = 1 << 22;

/// The synthetic devnet timestamp of a block height.
#[must_use]
pub fn clock(height: u64) -> u64 {
    antumbra_dag::GENESIS_TIMESTAMP_MS + height * BLOCK_INTERVAL_MS
}

/// The development network policy at a given difficulty: the
/// devnet drift of the ordering layer (two minutes).
#[must_use]
pub fn devnet_policy(difficulty: u32) -> antumbra_dag::Policy {
    antumbra_dag::Policy {
        difficulty_bits: difficulty,
        max_future_ms: antumbra_dag::Policy::DEVNET.max_future_ms,
    }
}

/// A devnet wallet from a fixed label: the spend and view seeds
/// are independent Keccak derivations of the label, the pattern of
/// the treasury address of ADR-024.
#[must_use]
pub fn devnet_wallet(label: &[u8]) -> Wallet {
    let mut spend_seed = Vec::with_capacity(label.len() + 6);
    spend_seed.extend_from_slice(label);
    spend_seed.extend_from_slice(b"-spend");
    let mut view_seed = Vec::with_capacity(label.len() + 5);
    view_seed.extend_from_slice(label);
    view_seed.extend_from_slice(b"-view");
    let spend = KeyPair::from_seed(keccak256(&spend_seed).as_bytes());
    let view = KeyPair::from_seed(keccak256(&view_seed).as_bytes());
    Wallet::from_keys(spend, view, Network::Devnet)
}

/// The miner wallet of the devnet activity script: it receives
/// every coinbase of the solo driver.
#[must_use]
pub fn miner() -> Wallet {
    devnet_wallet(b"antumbra-miner-devnet")
}

/// Alice: the first hop of the activity script, one third of every
/// miner spend.
#[must_use]
pub fn alice() -> Wallet {
    devnet_wallet(b"antumbra-alice-devnet")
}

/// Bob: the second hop, half of Alice's oldest output every other
/// spend round.
#[must_use]
pub fn bob() -> Wallet {
    devnet_wallet(b"antumbra-bob-devnet")
}

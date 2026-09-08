//! Cross-implementation vector tests for the state layer
//! (CONTRIBUTING.md, layer 1).
//!
//! The archived vector set in `tests/vectors.json` is produced by
//! `code/scripts/gen_state_vectors.py`, an independent Python
//! implementation of the emission calendar (the Lucas-Fibonacci
//! closed form of the eclipse table, the per-slot reward spread,
//! the treasury share and window), the devnet treasury address,
//! the coinbase rules and the UTXO ledger itself, re-implemented
//! from the ADR text alone. The Rust implementation must agree bit
//! for bit. A disagreement here is not a test failure: it is a
//! consensus fault, and it blocks the phase.

use antumbra_primitives::Address;
use antumbra_state::{
    calendar, devnet_treasury_address, reward_of_slot, treasury_active_at_slot, treasury_share_of,
    BlockPayload, Ledger, StateError, BLOCKS_PER_ECLIPSE, CAP_ATOMIC, MATURITY,
};
use antumbra_tx::Transaction;
use serde::Deserialize;
use std::collections::HashMap;

use antumbra_primitives::Hash;

#[derive(Deserialize)]
struct Vectors {
    #[allow(dead_code)] // archived metadata, read for completeness
    format: u32,
    #[allow(dead_code)]
    comment: String,
    calendar: CalendarVectors,
    apply: Vec<ApplyCase>,
    reject: Vec<RejectCase>,
    reorg: ReorgVectors,
}

#[derive(Deserialize)]
struct CalendarVectors {
    cap_atomic: u64,
    blocks_per_eclipse: u64,
    maturity: u64,
    eclipses_atu: Vec<u64>,
    rewards: Vec<RewardCase>,
    treasury_address: String,
}

#[derive(Deserialize)]
struct RewardCase {
    slot: u64,
    reward: u64,
    treasury_share: u64,
    treasury_active: bool,
}

#[derive(Deserialize)]
struct ApplyCase {
    name: String,
    blocks: Vec<BlockCase>,
    order: Vec<String>,
    expected: ExpectedState,
}

#[derive(Deserialize)]
struct RejectCase {
    name: String,
    blocks: Vec<BlockCase>,
    order: Vec<String>,
    error: String,
    after_reject: ExpectedState,
}

#[derive(Deserialize)]
struct ReorgVectors {
    pool: HashMap<String, BlockCase>,
    order_a: Vec<String>,
    order_b: Vec<String>,
    expected_a: ExpectedState,
    expected_b: ExpectedState,
}

#[derive(Deserialize)]
struct BlockCase {
    height: u64,
    txs: Vec<String>,
}

#[derive(Deserialize)]
struct ExpectedState {
    stats: StatsCase,
    utxos: Vec<UtxoCase>,
}

#[derive(Deserialize)]
struct StatsCase {
    applied: u64,
    created: u64,
    spent_value: u64,
    emitted: u64,
    utxos: usize,
}

#[derive(Deserialize, Debug, PartialEq)]
struct UtxoCase {
    tx: String,
    index: u32,
    address: String,
    amount: u64,
    coinbase_slot: Option<u64>,
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length in vectors");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex digit"))
        .collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

fn unhex_hash(s: &str) -> Hash {
    Hash(unhex32(s))
}

fn error_name(error: &StateError) -> &'static str {
    match error {
        StateError::MissingPayload(_) => "MissingPayload",
        StateError::NotGenesis(_) => "NotGenesis",
        StateError::GenesisPayload(_) => "GenesisPayload",
        StateError::UnsortedPayload => "UnsortedPayload",
        StateError::CoinbaseCount(_) => "CoinbaseCount",
        StateError::CoinbaseInputs(_) => "CoinbaseInputs",
        StateError::CoinbaseFee => "CoinbaseFee",
        StateError::CoinbaseExtra(_) => "CoinbaseExtra",
        StateError::CoinbaseHeight { .. } => "CoinbaseHeight",
        StateError::CoinbaseOutputs { .. } => "CoinbaseOutputs",
        StateError::CoinbaseValue { .. } => "CoinbaseValue",
        StateError::CoinbaseTreasuryAddress => "CoinbaseTreasuryAddress",
        StateError::CoinbaseTreasuryShare { .. } => "CoinbaseTreasuryShare",
        StateError::NoInputs => "NoInputs",
        StateError::UnknownOutput(_) => "UnknownOutput",
        StateError::DoubleSpend(_) => "DoubleSpend",
        StateError::ImmatureCoinbase { .. } => "ImmatureCoinbase",
        StateError::Conservation { .. } => "Conservation",
        StateError::OutputCollision(_) => "OutputCollision",
        StateError::Overflow => "Overflow",
    }
}

/// Decodes a block case: the height and the transactions, in the
/// archived payload order.
fn decode_block(block: &BlockCase) -> BlockPayload {
    let txs = block
        .txs
        .iter()
        .map(|s| Transaction::decode(&unhex(s)).expect("the vectors carry canonical transactions"))
        .collect();
    BlockPayload {
        height: block.height,
        txs,
    }
}

/// Builds the fetch closure over a block store keyed by id.
fn store_of(blocks: &[BlockCase], order: &[String]) -> HashMap<Hash, BlockPayload> {
    assert_eq!(blocks.len(), order.len(), "the order covers the blocks");
    let mut store = HashMap::new();
    for (block, id) in blocks.iter().zip(order) {
        let previous = store.insert(unhex_hash(id), decode_block(block));
        assert!(previous.is_none(), "a block id appears twice");
    }
    store
}

fn compare_state(ledger: &Ledger, expected: &ExpectedState, name: &str) {
    let stats = &expected.stats;
    assert_eq!(ledger.applied(), stats.applied, "{name}: applied slots");
    assert_eq!(ledger.created(), stats.created, "{name}: created total");
    assert_eq!(
        ledger.spent_value(),
        stats.spent_value,
        "{name}: spent total"
    );
    assert_eq!(ledger.emitted(), stats.emitted, "{name}: emitted total");
    assert_eq!(ledger.len(), stats.utxos, "{name}: utxo count");
    assert!(
        ledger.check_conservation().is_ok(),
        "{name}: the ledger does not conserve"
    );

    let snapshot = ledger.snapshot();
    assert_eq!(
        snapshot.len(),
        expected.utxos.len(),
        "{name}: snapshot length"
    );
    for ((reference, entry), case) in snapshot.iter().zip(&expected.utxos) {
        assert_eq!(reference.tx(), unhex_hash(&case.tx), "{name}: utxo tx id");
        assert_eq!(reference.index(), case.index, "{name}: utxo index");
        let address_bytes: [u8; 69] = unhex(&case.address)
            .try_into()
            .expect("the vectors carry 69-byte addresses");
        assert_eq!(
            entry.address(),
            Address::from_bytes(&address_bytes).expect("a valid address"),
            "{name}: utxo address"
        );
        assert_eq!(entry.amount().atomic(), case.amount, "{name}: utxo amount");
        assert_eq!(
            entry.coinbase_slot(),
            case.coinbase_slot,
            "{name}: utxo coinbase slot"
        );
    }
}

fn load_vectors() -> Vectors {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors.json");
    let text = std::fs::read_to_string(path).expect("the archived vector set exists");
    serde_json::from_str(&text).expect("the archived vector set is well formed")
}

#[test]
fn the_constants_of_the_protocol_match_the_archive() {
    let vectors = load_vectors();
    let calendar_vectors = &vectors.calendar;
    assert_eq!(CAP_ATOMIC, calendar_vectors.cap_atomic);
    assert_eq!(BLOCKS_PER_ECLIPSE, calendar_vectors.blocks_per_eclipse);
    assert_eq!(MATURITY, calendar_vectors.maturity);
    assert_eq!(calendar().as_slice(), calendar_vectors.eclipses_atu);
    assert_eq!(calendar().len(), 34, "thirty-four eclipses");
    assert_eq!(
        calendar().iter().sum::<u64>() * 100_000_000,
        CAP_ATOMIC,
        "the calendar closes on the cap"
    );
}

#[test]
fn the_reward_spread_and_treasury_match_bit_for_bit() {
    let vectors = load_vectors();
    for case in &vectors.calendar.rewards {
        let reward = reward_of_slot(case.slot);
        assert_eq!(reward, case.reward, "slot {}", case.slot);
        assert_eq!(
            treasury_share_of(reward),
            case.treasury_share,
            "slot {}",
            case.slot
        );
        assert_eq!(
            treasury_active_at_slot(case.slot),
            case.treasury_active,
            "slot {}",
            case.slot
        );
    }
}

#[test]
fn the_treasury_address_is_the_archived_one() {
    let vectors = load_vectors();
    let bytes = unhex(&vectors.calendar.treasury_address);
    let raw: [u8; 69] = bytes.try_into().expect("69 raw address bytes");
    assert_eq!(
        devnet_treasury_address(),
        Address::from_bytes(&raw).expect("a valid archived address"),
        "the devnet treasury address"
    );
}

#[test]
fn the_ledger_applies_the_generated_orders() {
    let vectors = load_vectors();
    for case in &vectors.apply {
        let store = store_of(&case.blocks, &case.order);
        let order: Vec<Hash> = case.order.iter().map(|s| unhex_hash(s)).collect();
        let mut ledger = Ledger::new();
        let mut fetch = |id: &Hash| store.get(id).cloned();
        ledger
            .apply_order(&order, &mut fetch)
            .unwrap_or_else(|e| panic!("{}: the apply case must hold: {e}", case.name));
        compare_state(&ledger, &case.expected, &case.name);
    }
}

#[test]
fn the_ledger_rejects_and_names_every_rule() {
    let vectors = load_vectors();
    assert!(vectors.reject.len() >= 16, "the battery covers every rule");
    for case in &vectors.reject {
        let store = store_of(&case.blocks, &case.order);
        let order: Vec<Hash> = case.order.iter().map(|s| unhex_hash(s)).collect();
        let mut ledger = Ledger::new();
        let mut fetch = |id: &Hash| store.get(id).cloned();
        let error = ledger
            .apply_order(&order, &mut fetch)
            .expect_err(&format!("{}: the reject case must fail", case.name));
        assert_eq!(
            error_name(&error),
            case.error,
            "{}: the wrong rule fired: {error}",
            case.name
        );
        compare_state(&ledger, &case.after_reject, &case.name);
    }
}

#[test]
fn the_reorg_rebuilds_both_orders_exactly() {
    let vectors = load_vectors();
    let reorg = &vectors.reorg;
    let mut store = HashMap::new();
    for (id, block) in &reorg.pool {
        let previous = store.insert(unhex_hash(id), decode_block(block));
        assert!(previous.is_none(), "a pool block id appears twice");
    }
    for (order, expected, name) in [
        (&reorg.order_a, &reorg.expected_a, "reorg-a"),
        (&reorg.order_b, &reorg.expected_b, "reorg-b"),
    ] {
        let order: Vec<Hash> = order.iter().map(|s| unhex_hash(s)).collect();
        let mut ledger = Ledger::new();
        let mut fetch = |id: &Hash| store.get(id).cloned();
        ledger
            .apply_order(&order, &mut fetch)
            .unwrap_or_else(|e| panic!("{name}: the reorg order must hold: {e}"));
        compare_state(&ledger, expected, name);
    }
    // The two orders really fork: their states differ.
    assert_ne!(reorg.expected_a.utxos, reorg.expected_b.utxos);
}

#[test]
fn the_rebuild_is_reproducible() {
    let vectors = load_vectors();
    let case = &vectors.apply[0];
    let store = store_of(&case.blocks, &case.order);
    let order: Vec<Hash> = case.order.iter().map(|s| unhex_hash(s)).collect();

    let mut first = Ledger::new();
    let mut fetch = |id: &Hash| store.get(id).cloned();
    first.apply_order(&order, &mut fetch).expect("holds");

    let mut second = Ledger::new();
    let mut fetch2 = |id: &Hash| store.get(id).cloned();
    second.apply_order(&order, &mut fetch2).expect("holds");

    assert_eq!(
        first.snapshot().len(),
        second.snapshot().len(),
        "two rebuilds of the same order agree"
    );
    for ((ra, ea), (rb, eb)) in first.snapshot().iter().zip(second.snapshot()) {
        assert_eq!(ra, &rb, "the same references");
        assert_eq!(ea, &eb, "the same entries");
    }
}

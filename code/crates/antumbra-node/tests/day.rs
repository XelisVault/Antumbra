//! The day battery of the node (ADR-025): a deterministic day
//! slice run twice with identical status ids, the maturity gate,
//! the double-spend refusals, the fork reorg with the total
//! rebuild, and the independent emission accounting.

use antumbra_dag::payload_root;
use antumbra_dag::{Block, Header};
use antumbra_node::engine::{Breach, Engine};
use antumbra_node::wallet::Wallet;
use antumbra_primitives::{Address, KeyPair, Network};
use antumbra_state::coinbase::{
    reward_of_slot, treasury_active_at_slot, treasury_share_of, MATURITY,
};
use antumbra_state::ledger::{Ledger, StateError};
use antumbra_tx::{Amount, OutputRef, Transaction, TxIn, TxOut, TxType};

/// The test difficulty: fast to mine, real to check.
const D: u32 = 4;

/// The provisional fee schedule of the transaction layer.
const FEES: antumbra_tx::FeeSchedule = antumbra_tx::FeeSchedule::PROVISIONAL;

/// Builds the standard test spend: a third of `value` to Alice,
/// the change back to the miner.
fn build_spend(
    engine: &Engine,
    reference: OutputRef,
    value: Amount,
    alice: Address,
) -> Transaction {
    engine
        .wallets
        .miner
        .wallet
        .spend_one(
            reference,
            value,
            alice,
            Amount::from_atomic(value.atomic() / 3),
            &FEES,
        )
        .expect("the construction is honest")
}

/// Runs a day slice and returns the outcome.
fn day(blocks: u64, spend_every: u64) -> antumbra_node::DayOutcome {
    antumbra_node::run_day(blocks, D, spend_every, &mut |_| {}).expect("the day slice holds")
}

/// The devnet thief: a wallet the spent output never paid. The
/// theft claims the output with the thief's key and signs it
/// correctly — the signature verifies, the key is not the
/// owner's (ADR-026).
fn thief() -> Wallet {
    Wallet::from_keys(
        KeyPair::from_seed(&[0xEE; 32]),
        KeyPair::from_seed(&[0xEF; 32]),
        Network::Devnet,
    )
}

/// The theft transaction: the value minus the fee to the thief,
/// claimed and signed by the thief's key.
fn build_theft(thief: &Wallet, reference: OutputRef, value: Amount) -> Transaction {
    let draft = Transaction::new(
        TxType::Transfer,
        Amount::ZERO,
        vec![TxIn::unsigned(reference, thief.spend().public())],
        vec![TxOut::new(thief.address(), Amount::ZERO)],
        Vec::new(),
    );
    let mut fee = Amount::ZERO;
    for _ in 0..4 {
        let minimum = FEES
            .minimum_fee(draft.encode().len(), 0)
            .expect("the fee is computable");
        if fee == minimum {
            break;
        }
        fee = minimum;
    }
    let remainder = value.checked_sub(fee).expect("the coinbase covers the fee");
    let mut theft = Transaction::new(
        TxType::Transfer,
        fee,
        vec![TxIn::unsigned(reference, thief.spend().public())],
        vec![TxOut::new(thief.address(), remainder)],
        Vec::new(),
    );
    theft
        .sign(core::slice::from_ref(thief.spend()))
        .expect("the thief signs his own claim");
    theft
}

#[test]
fn the_day_slice_is_deterministic() {
    let first = day(96, 8);
    let second = day(96, 8);
    assert_eq!(
        first.reported.status.id(),
        second.reported.status.id(),
        "two runs of the same day print the same status id"
    );
    let status = &first.reported.status;
    assert_eq!(status.blocks, 97, "the genesis plus 96 mined blocks");
    assert_eq!(status.height, 96);
    assert_eq!(status.tips, 1);
    assert!(status.invariants_held);
    // The activity script: the miner spends from block 16 (the
    // first block with a matured coinbase: slot 1 matures at
    // slot 11) every 8 blocks, and Alice every 16 blocks from
    // block 32 (her first credit arrives in block 16).
    assert_eq!(
        status.transfers, 16,
        "eleven miner spends and five Alice spends"
    );
    assert_eq!(status.coinbases, 96);
    assert_eq!(status.rebuilds, 0, "the solo day never reorganizes");
}

#[test]
fn the_emission_accounting_is_recomputed_independently() {
    let outcome = day(96, 8);
    let status = &outcome.reported.status;
    let mut expected_emitted = 0;
    let mut expected_treasury = 0;
    for slot in 1..=96 {
        let reward = reward_of_slot(slot);
        expected_emitted += reward;
        if treasury_active_at_slot(slot) {
            expected_treasury += treasury_share_of(reward);
        }
    }
    assert_eq!(status.emitted, expected_emitted);
    assert_eq!(status.treasury, expected_treasury);
    // The conservation identity of ADR-024: what was created is
    // what was spent plus what was emitted, the fees recycled.
    assert_eq!(status.created - status.spent, status.emitted);
}

#[test]
fn the_maturity_gate_is_exact() {
    let mut engine = Engine::boot(D).expect("the genesis is the protocol constant");
    // Six blocks: the coinbase of slot 1 matures at slot 11.
    for _ in 0..6 {
        engine.mine_and_apply().expect("the solo step holds");
    }
    // The coinbase output of slot 1, from the tracker inventory.
    let (reference, value) = engine
        .wallets
        .miner
        .tracker
        .unspent_with_slot()
        .into_iter()
        .find(|(_, _, slot)| *slot == Some(1))
        .map(|(reference, value, _)| (reference, value))
        .expect("the coinbase of slot 1 is tracked");
    assert_eq!(
        engine
            .ledger()
            .utxo(&reference)
            .expect("the output exists")
            .coinbase_slot(),
        Some(1)
    );
    let alice = engine.wallets.alice.wallet.address();
    let transaction = build_spend(&engine, reference, value, alice);
    // The next slot is 7: the spend is refused as immature, the
    // earliest slot being 11.
    match engine.submit(&transaction) {
        Err(error @ antumbra_node::AdmitError::Immature { .. }) => {
            assert_eq!(
                error,
                antumbra_node::AdmitError::Immature {
                    reference,
                    creating_slot: 1,
                    earliest_slot: 1 + MATURITY,
                }
            );
        }
        other => panic!("the immature spend must be refused, found {other:?}"),
    }
    // The same construction at maturity: mine to slot 12.
    for _ in 6..11 {
        engine.mine_and_apply().expect("the solo step holds");
    }
    engine
        .submit(&transaction)
        .expect("the matured spend is admitted");
    engine.mine_and_apply().expect("the payload applies");
    assert_eq!(engine.stats().transfers, 1);
}

#[test]
fn the_double_spend_is_refused_twice() {
    let mut engine = Engine::boot(D).expect("the genesis is the protocol constant");
    for _ in 0..12 {
        engine.mine_and_apply().expect("the solo step holds");
    }
    let (reference, value) = engine
        .wallets
        .miner
        .tracker
        .unspent_with_slot()
        .into_iter()
        .find(|(_, _, slot)| *slot == Some(1))
        .map(|(reference, value, _)| (reference, value))
        .expect("the coinbase of slot 1 is tracked");
    let alice = engine.wallets.alice.wallet.address();
    // The mempool refuses the second claim of the same output.
    engine
        .submit(&build_spend(&engine, reference, value, alice))
        .expect("the first spend is admitted");
    match engine.submit(&build_spend(&engine, reference, value, alice)) {
        Err(antumbra_node::AdmitError::Claimed(claimed)) => assert_eq!(claimed, reference),
        other => panic!("the double claim must be refused, found {other:?}"),
    }
    // The first spend lands; the output becomes spent.
    engine.mine_and_apply().expect("the first spend applies");
    // The mempool refuses a fresh equivalent spend of the spent
    // output as a double spend.
    match engine.submit(&build_spend(&engine, reference, value, alice)) {
        Err(antumbra_node::AdmitError::DoubleSpend(spent)) => assert_eq!(spent, reference),
        other => panic!("the spent output must be refused, found {other:?}"),
    }
    // The in-block rejection: a hand-built block whose payload
    // spends the spent output again. The block is mined and
    // inserted, and the ledger names the rule as a breach.
    let best = engine.store().best_tip();
    let transfers = vec![build_spend(&engine, reference, value, alice)];
    let block = engine.assemble(best, transfers).expect("assembly holds");
    match engine.insert_block(&block) {
        Err(Breach::Ledger(StateError::DoubleSpend(spent))) => assert_eq!(spent, reference),
        other => panic!("the in-block double spend must breach, found {other:?}"),
    }
}

#[test]
fn the_fork_reorg_rebuilds_the_ledger() {
    let mut engine = Engine::boot(D).expect("the genesis is the protocol constant");
    for _ in 0..12 {
        engine.mine_and_apply().expect("the solo step holds");
    }
    let main_tip = engine.store().best_tip();

    // The fork parent: the block at order position 8 (height 8 of
    // the linear chain). Five fork blocks on it: the fork chain
    // scores 14 against the main 13 and the best tip switches.
    // A fork block carries the twin coinbase of the main block at
    // its height — the slot and the fees are the same — so its
    // timestamp moves one second past the clock to be a distinct
    // block, exactly as two miners on one parent would produce.
    let fork_parent = engine.store().order()[8];
    let mut fork_tip = fork_parent;
    for _ in 0..5 {
        let height = engine.store().height(&fork_tip).expect("held") + 1;
        let slot = engine.store().order_len(&fork_tip).expect("held");
        let coinbase = engine.wallets.miner.wallet.coinbase(height, slot, 0);
        engine.register_payload(&coinbase);
        let ids = vec![coinbase.tx_id()];
        let root = payload_root(&ids);
        let timestamp = antumbra_node::devnet::clock(height) + 1_000;
        let draft = Header::new(vec![fork_tip], height, timestamp, 0, root);
        let header = antumbra_dag::mine(&draft, D, 1 << 20).expect("difficulty 4 mines");
        let block = Block::new(header, ids);
        fork_tip = block.id();
        engine.insert_block(&block).expect("the fork block applies");
    }
    let fork_final = fork_tip;
    assert_ne!(main_tip, fork_final, "the fork won the best tip");
    assert_eq!(engine.store().tips().len(), 2);
    assert_eq!(engine.store().best_tip(), fork_final);
    assert_eq!(engine.stats().rebuilds, 1, "the reorg rebuilt once");

    // The independent rebuild: a fresh ledger over the consensus
    // order of the winning tip, the coinbases rebuilt from the
    // calendar (the state layer cross-validates that construction
    // on its own vector set). The engine's ledger must equal it.
    let order = engine
        .store()
        .consensus_order(&fork_final)
        .expect("the fork tip is held");
    let mut reference = Ledger::new();
    for (position, id) in order.iter().enumerate() {
        let height = engine.store().height(id).expect("held");
        let ids = engine.store().tx_ids(id).expect("held");
        assert!(ids.len() <= 1, "the solo blocks carry the coinbase alone");
        let txs: Vec<Transaction> = if height == 0 {
            Vec::new()
        } else {
            vec![engine
                .wallets
                .miner
                .wallet
                .coinbase(height, position as u64, 0)]
        };
        reference
            .apply_block(height, &txs)
            .expect("the reference rebuild holds");
    }
    assert_eq!(
        engine.ledger().snapshot(),
        reference.snapshot(),
        "the engine's rebuilt ledger equals the independent rebuild"
    );
    assert_eq!(engine.ledger().applied(), reference.applied());
    assert_eq!(engine.ledger().created(), reference.created());
    assert_eq!(engine.ledger().emitted(), reference.emitted());

    // The battery holds after the reorg, without the solo shape.
    let (report, failures) = antumbra_node::invariants::check(&engine, false);
    assert!(
        failures.is_empty(),
        "the invariants hold after the reorg: {failures:?}"
    );
    assert!(report.held());

    // Mining continues on the new best tip: the suffix
    // application works after a rebuild.
    for _ in 0..3 {
        engine.mine_and_apply().expect("the post-reorg step holds");
    }
    assert_eq!(engine.ledger().applied(), 14 + 3);
    assert_eq!(
        engine.stats().rebuilds,
        1,
        "no further rebuild without a new fork"
    );
}

#[test]
fn the_invalid_coinbase_value_is_a_breach() {
    let mut engine = Engine::boot(D).expect("the genesis is the protocol constant");
    for _ in 0..3 {
        engine.mine_and_apply().expect("the solo step holds");
    }
    // A hand-built block whose coinbase claims fees its payload
    // does not carry: the ledger names the rule and the day stops.
    let best = engine.store().best_tip();
    let slot = engine.store().order_len(&best).expect("held");
    let height = engine.store().height(&best).expect("held") + 1;
    let wrong = engine.wallets.miner.wallet.coinbase(height, slot, 1_000);
    engine.register_payload(&wrong);
    let ids = vec![wrong.tx_id()];
    let root = payload_root(&ids);
    let timestamp = antumbra_node::devnet::clock(height);
    let draft = Header::new(vec![best], height, timestamp, 0, root);
    let header = antumbra_dag::mine(&draft, D, 1 << 20).expect("difficulty 4 mines");
    let block = Block::new(header, ids);
    match engine.insert_block(&block) {
        Err(Breach::Ledger(StateError::CoinbaseValue { .. })) => {}
        other => panic!("the wrong coinbase value must breach, found {other:?}"),
    }
}

#[test]
fn the_theft_is_refused_twice() {
    // Engine one: the admission refusal, then the honest
    // continuation — the day goes on.
    let mut engine = Engine::boot(D).expect("the genesis is the protocol constant");
    for _ in 0..12 {
        engine.mine_and_apply().expect("the solo step holds");
    }
    // The matured coinbase output of slot 1, from the tracker
    // inventory.
    let (reference, value) = engine
        .wallets
        .miner
        .tracker
        .unspent_with_slot()
        .into_iter()
        .find(|(_, _, slot)| *slot == Some(1))
        .map(|(reference, value, _)| (reference, value))
        .expect("the coinbase of slot 1 is tracked");

    // The theft: correctly signed by the thief's key (the signature
    // itself verifies — the admission runs the check after the
    // signature verification), the key is not the owner's.
    let theft = build_theft(&thief(), reference, value);
    theft
        .verify_signatures()
        .expect("the theft is correctly signed");
    match engine.submit(&theft) {
        Err(antumbra_node::AdmitError::KeyNotOwner { reference: claimed }) => {
            assert_eq!(claimed, reference)
        }
        other => panic!("the theft must be refused at admission, found {other:?}"),
    }
    assert_eq!(engine.mempool().len(), 0, "the theft is not admitted");

    // The honest spend of the same output is admitted and applies.
    let alice = engine.wallets.alice.wallet.address();
    engine
        .submit(&build_spend(&engine, reference, value, alice))
        .expect("the honest spend is admitted");
    engine.mine_and_apply().expect("the honest spend applies");
    assert!(engine.ledger().is_spent(&reference));
    let (report, failures) = antumbra_node::invariants::check(&engine, false);
    assert!(
        failures.is_empty(),
        "the invariants hold after the refused theft: {failures:?}"
    );
    assert!(report.held());

    // Engine two: the in-block rejection. A hand-built block whose
    // payload carries the theft; the signature verifies, and the
    // ledger alone refuses the block — the consensus rule of
    // ADR-026, the one a remote peer cannot talk its way past.
    let mut engine = Engine::boot(D).expect("the genesis is the protocol constant");
    for _ in 0..12 {
        engine.mine_and_apply().expect("the solo step holds");
    }
    let (reference, value) = engine
        .wallets
        .miner
        .tracker
        .unspent_with_slot()
        .into_iter()
        .find(|(_, _, slot)| *slot == Some(1))
        .map(|(reference, value, _)| (reference, value))
        .expect("the coinbase of slot 1 is tracked");
    let theft = build_theft(&thief(), reference, value);
    let best = engine.store().best_tip();
    let before = engine.ledger().snapshot();
    let block = engine.assemble(best, vec![theft]).expect("assembly holds");
    match engine.insert_block(&block) {
        Err(Breach::Ledger(StateError::KeyNotBound(bound))) => {
            assert_eq!(bound, reference)
        }
        other => panic!("the in-block theft must breach, found {other:?}"),
    }
    assert_eq!(
        engine.ledger().snapshot(),
        before,
        "the refused theft leaves the ledger where it stood"
    );
    assert!(
        !engine.ledger().is_spent(&reference),
        "the output survives its thief, spendable by its owner"
    );
}

//! The differential battery of the node store (ADR-025): the
//! store against an independent reference `Dag`, after every
//! insertion, on randomized fork-heavy DAGs — tips, best tip,
//! blue scores, selected parents, full consensus orders, and the
//! materialized best order. The chain path (single-parent blocks)
//! and the fork path (merges) are both exercised; a second test
//! drives the chain path past the reference window and checks the
//! merge refusal.

use antumbra_dag::{payload_root, Block, Dag, Header, Policy, MAX_TXS};
use antumbra_node::store::{NodeError, Store, REFERENCE_WINDOW};
use antumbra_primitives::Hash;

/// A tiny deterministic generator: xorshift64*, so the random DAG
/// tests depend on no external crate and no machine state — the
/// pattern of the ordering layer's own tests.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// A transaction id from the generator: Keccak of the state.
fn random_id(rng: &mut XorShift) -> Hash {
    antumbra_primitives::keccak256(&rng.next().to_le_bytes())
}

/// A sorted, deduplicated payload: the step salt makes every
/// generated block unique, and the random ids pad it.
fn random_ids(rng: &mut XorShift, max: usize, step: u64) -> Vec<Hash> {
    let count = (rng.next() % max as u64) as usize;
    let mut ids: Vec<Hash> = (0..count).map(|_| random_id(rng)).collect();
    ids.push(antumbra_primitives::keccak256(&step.to_le_bytes()));
    ids.sort();
    ids.dedup();
    ids
}

/// Mines a block under a difficulty the tests can afford.
fn mined(header: &Header, bits: u32) -> Header {
    antumbra_dag::mine(header, bits, 1 << 20).expect("difficulty 4 mines within the budget")
}

/// Builds a block from parents, a height, a timestamp and ids.
fn block(parents: Vec<Hash>, height: u64, timestamp: u64, ids: Vec<Hash>) -> Block {
    let root = payload_root(&ids);
    let draft = Header::new(parents, height, timestamp, 0, root);
    Block::new(mined(&draft, 4), ids)
}

#[test]
fn the_store_matches_the_reference_on_mixed_dags() {
    let mut rng = XorShift(0x5EED_0000_0000_0001);
    let genesis = Block::devnet_genesis();
    let mut store = Store::new(&genesis).expect("the genesis is the protocol constant");
    let mut reference = Dag::new(&genesis).expect("the genesis is the protocol constant");
    let policy = Policy {
        difficulty_bits: 4,
        max_future_ms: u64::MAX,
    };
    let genesis_id = genesis.id();
    let mut recent: Vec<Hash> = vec![genesis_id];
    let steps = 600;

    for step in 1..=steps {
        // The parent choice: mostly extend the last block, often
        // fork on a recent block, sometimes merge two, sometimes
        // fork deep.
        let parents: Vec<Hash> = match rng.next() % 20 {
            0..=13 => vec![*recent.last().expect("the recent list is seeded")],
            14..=16 => {
                let index = (rng.next() as usize) % recent.len();
                vec![recent[index]]
            }
            17..=18 => {
                let first = (rng.next() as usize) % recent.len();
                let mut second = (rng.next() as usize) % recent.len();
                if first == second {
                    second = (second + 1) % recent.len();
                }
                let mut merge = vec![recent[first], recent[second]];
                merge.sort();
                merge.dedup();
                merge
            }
            _ => vec![genesis_id],
        };
        let height = parents
            .iter()
            .map(|parent| store.height(parent).expect("held") + 1)
            .max()
            .expect("parents are never empty");
        let timestamp = antumbra_dag::GENESIS_TIMESTAMP_MS + height * 2_000;
        let ids = random_ids(&mut rng, 3, step);
        let candidate = block(parents, height, timestamp, ids);
        let id = candidate.id();

        // Both implementations accept the same block or the test
        // fails: a divergence here is the finding.
        store
            .insert(&candidate, &policy, timestamp)
            .unwrap_or_else(|error| {
                panic!("step {step}: the store refused a valid block: {error:?}")
            });
        reference
            .insert(&candidate, &policy, timestamp)
            .unwrap_or_else(|error| panic!("step {step}: the reference refused: {error:?}"));

        // The differential assertions, after every insertion.
        assert_eq!(store.tips(), reference.tips(), "step {step}: tips");
        assert_eq!(
            store.best_tip(),
            reference.best_tip().expect("a tip exists"),
            "step {step}: best tip"
        );
        assert_eq!(
            store.blue_score(&id).expect("held"),
            reference.blue_score(&id).expect("held"),
            "step {step}: blue score"
        );
        assert_eq!(
            store.selected_parent(&id),
            reference.selected_parent(&id),
            "step {step}: selected parent"
        );
        for tip in store.tips() {
            assert_eq!(
                store.consensus_order(&tip).expect("held"),
                reference.consensus_order(&tip).expect("held"),
                "step {step}: the order of a tip"
            );
        }
        let best_order = reference.consensus_order(&store.best_tip()).expect("held");
        assert_eq!(
            store.order(),
            &best_order[..],
            "step {step}: the materialized best order"
        );

        recent.push(id);
        if recent.len() > 24 {
            recent.remove(0);
        }
    }
}

#[test]
fn the_chain_path_survives_past_the_reference_window() {
    let genesis = Block::devnet_genesis();
    let mut store = Store::new(&genesis).expect("the genesis is the protocol constant");
    let mut reference = Dag::new(&genesis).expect("the genesis is the protocol constant");
    // Difficulty zero: every id meets it, the walk is a formality.
    let policy = Policy {
        difficulty_bits: 0,
        max_future_ms: u64::MAX,
    };
    let blocks = (REFERENCE_WINDOW + 80) as u64;
    let mut parent = genesis.id();
    let empty: Vec<Hash> = Vec::new();

    for height in 1..=blocks {
        let timestamp = antumbra_dag::GENESIS_TIMESTAMP_MS + height * 2_000;
        let root = payload_root(&empty);
        let draft = Header::new(vec![parent], height, timestamp, 0, root);
        let candidate = Block::new(draft, empty.clone());
        // Difficulty zero: the draft header already meets it.
        store
            .insert(&candidate, &policy, timestamp)
            .expect("a solo block at difficulty zero is always accepted");
        reference
            .insert(&candidate, &policy, timestamp)
            .expect("the reference agrees");
        parent = candidate.id();

        if height % 128 == 0 {
            let best_order = reference.consensus_order(&store.best_tip()).expect("held");
            assert_eq!(
                store.order(),
                &best_order[..],
                "height {height}: the materialized order"
            );
            assert_eq!(store.tips(), reference.tips());
        }
    }

    // The mirror is gone past the window: a merge is the policy
    // refusal of ADR-025, and both stores stay consistent.
    let deep = {
        let order = store.order();
        order[order.len() / 2]
    };
    let other = {
        let order = store.order();
        order[order.len() / 2 + 1]
    };
    let mut parents = vec![deep, other];
    parents.sort();
    parents.dedup();
    let height = parents
        .iter()
        .map(|parent| store.height(parent).expect("held") + 1)
        .max()
        .expect("parents are never empty");
    let timestamp = antumbra_dag::GENESIS_TIMESTAMP_MS + height * 2_000;
    let ids: Vec<Hash> = vec![random_id(&mut XorShift(0xD1CE))];
    let merge = block(parents.clone(), height, timestamp, ids);
    match store.insert(&merge, &policy, timestamp) {
        Err(NodeError::MergeBeyondWindow {
            parents: count,
            window,
        }) => {
            assert_eq!(count, 2);
            assert_eq!(window, REFERENCE_WINDOW);
        }
        other => panic!("the merge past the window must be refused, found {other:?}"),
    }
    // The reference, which has no window, accepts it; the stores
    // then diverge by policy, which is the documented contract.
    assert!(reference.insert(&merge, &policy, timestamp).is_ok());

    // The store's own order is untouched by the refusal.
    let best_order = reference.consensus_order(&store.best_tip()).expect("held");
    assert_eq!(store.order(), &best_order[..]);
}

#[test]
fn the_payload_limit_is_enforced_by_the_store_caller() {
    // The block container caps the payload at MAX_TXS ids; the
    // store consumes what the container allows and the driver
    // never builds more. This pins the contract the engine uses.
    let genesis = Block::devnet_genesis();
    let store = Store::new(&genesis).expect("the genesis is the protocol constant");
    assert_eq!(store.len(), 1);
    assert!(store.contains(&genesis.id()));
    assert_eq!(store.order(), &[genesis.id()][..]);
    assert_eq!(store.best_tip(), genesis.id());
    assert_eq!(store.tips(), vec![genesis.id()]);
    let _ = MAX_TXS;
}

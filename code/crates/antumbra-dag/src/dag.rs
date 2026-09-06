//! The BlockDAG store: insertion, coloring, consensus order
//! (ADR-013).
//!
//! A block is inserted once its container is canonical and its
//! network rules hold; insertion then computes, once and for all,
//! the derived state every consumer reads: the blue set (the
//! greedy `K`-cluster of the GHOSTDAG family) and, on demand, the
//! consensus order of any view. The algorithms here are the
//! normative, closure-based reference of ADR-013: exact and
//! deliberately simple. Optimized implementations (incremental
//! merges, bounded windows) must reproduce this crate on every
//! reachable state, by differential testing, before they may
//! serve consensus.
//!
//! The selected parent `sp` of a block `B` is the parent with the
//! highest blue score, ties by the smallest id. The selected
//! parent is always blue in `B`, and the blues of `sp` survive:
//! the blue set is inherited, then grown. The coloring:
//!
//! ```text
//! working  := blues(sp) ∪ {sp}
//! for v in past(B) \ (past(sp) ∪ {sp}), by score desc, id asc:
//!     if |{u in working : u not in past(v) ∪ future(v) ∪ {v}}| <= K:
//!         working := working ∪ {v}
//! blues(B) := working                       (B itself excluded)
//! score(B) := 1 + |blues(B)|
//! ```
//!
//! The consensus order of a view, recursive and append-only:
//!
//! ```text
//! order(genesis) := [genesis]
//! order(B)       := order(sp) ++ sort(view(B) \ view(sp),
//!                                      by height asc then id asc)
//! ```
//!
//! The sort is topologically consistent because heights strictly
//! increase along ancestry, and no block of `view(sp)` is a
//! descendant of a new block, so the append never reshuffles: a
//! confirmed position is final. That is the property the Ring
//! checkpoints and the ledger consume.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use antumbra_primitives::Hash;

use crate::block::payload_root;
use crate::block::Block;
use crate::error::DagError;
use crate::header::Header;
use crate::pow::{leading_zero_bits, meets_difficulty};

/// The anticone bound of the coloring (ADR-013): a candidate
/// joins the blue set when its anticone inside the working blue
/// set is at most this many blocks.
pub const K: usize = 8;

/// The timestamp of the development network genesis, in
/// milliseconds since the Unix epoch (2025-06-15T15:06:40Z).
pub const GENESIS_TIMESTAMP_MS: u64 = 1_750_000_000_000;

/// The validation policy of an insertion: the work requirement
/// and the tolerated clock drift.
///
/// The policy is consensus state, not block data: two honest
/// nodes must agree on it out of band, and changing it is a
/// network parameter change, never a header change.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Policy {
    /// The leading zero bits a block id must carry.
    pub difficulty_bits: u32,
    /// How far in the future a timestamp may sit past the node
    /// clock, in milliseconds.
    pub max_future_ms: u64,
}

impl Policy {
    /// The development network policy: sixteen bits of Keccak
    /// work, two minutes of tolerated drift.
    pub const DEVNET: Self = Self {
        difficulty_bits: 16,
        max_future_ms: 120_000,
    };

    /// The relaxed policy of the cross vector sets: no work
    /// requirement, no future bound. The vectors exercise the
    /// ordering rules, not the work walk; the work has its own
    /// vector set.
    pub const VECTORS: Self = Self {
        difficulty_bits: 0,
        max_future_ms: u64::MAX,
    };
}

/// The derived state of one accepted block.
struct Node {
    header: Header,
    /// The blue ancestors of this block, itself excluded. Always
    /// contains the selected parent and the blues it inherited.
    blues: BTreeSet<Hash>,
    /// One plus the size of the blue set; cached at insertion.
    blue_score: u64,
    /// The selected parent: highest blue score, ties by smallest
    /// id. `None` for the genesis alone.
    selected_parent: Option<Hash>,
    /// The transitive ancestors, this block excluded. Normative
    /// reference storage; the production window replaces it.
    past: BTreeSet<Hash>,
    /// The known children.
    children: BTreeSet<Hash>,
}

/// The BlockDAG: accepted blocks, their derived state, and the
/// mining tips.
///
/// Every query is deterministic in the accepted set alone: two
/// nodes holding the same blocks compute the same scores and the
/// same orders, which is the whole point of the layer.
pub struct Dag {
    genesis: Hash,
    nodes: BTreeMap<Hash, Node>,
    tips: BTreeSet<Hash>,
}

impl Dag {
    /// Opens a DAG on its genesis block.
    ///
    /// The genesis must be the zero-parent, zero-height block of
    /// the network, with a payload root that commits its
    /// transaction list. Its work is not checked: the genesis is
    /// a protocol constant, not a mined block.
    ///
    /// # Errors
    ///
    /// Returns a [`DagError`] if the block is not of the genesis
    /// shape or its payload root does not commit its payload.
    pub fn new(genesis: &Block) -> Result<Self, DagError> {
        let header = genesis.header();
        if header.parents().len() != 1 || header.parents()[0] != Hash::ZERO {
            return Err(DagError::ZeroParent);
        }
        if header.height() != 0 {
            return Err(DagError::HeightMismatch {
                announced: header.height(),
                computed: 0,
            });
        }
        let computed = payload_root(genesis.tx_ids());
        if computed != header.payload_root() {
            return Err(DagError::PayloadRootMismatch {
                announced: header.payload_root(),
                computed,
            });
        }
        let id = genesis.id();
        let node = Node {
            blues: BTreeSet::new(),
            blue_score: 1,
            selected_parent: None,
            past: BTreeSet::new(),
            children: BTreeSet::new(),
            header: header.clone(),
        };
        let mut nodes = BTreeMap::new();
        nodes.insert(id, node);
        let mut tips = BTreeSet::new();
        tips.insert(id);
        Ok(Self {
            genesis: id,
            nodes,
            tips,
        })
    }

    /// Inserts a block after the full rule check of ADR-013, in
    /// order: the payload root, the duplicate id, the parent list
    /// shape, every parent known, the announced height, the
    /// parent timestamps, the future bound, and the work under
    /// the policy. On success the coloring is computed and the
    /// block becomes a tip; its parents stop being tips.
    ///
    /// # Errors
    ///
    /// Returns a [`DagError`] naming the first violated rule.
    pub fn insert(
        &mut self,
        block: &Block,
        policy: &Policy,
        now_ms: u64,
    ) -> Result<Hash, DagError> {
        let header = block.header();
        let computed_root = payload_root(block.tx_ids());
        if computed_root != header.payload_root() {
            return Err(DagError::PayloadRootMismatch {
                announced: header.payload_root(),
                computed: computed_root,
            });
        }
        let id = block.id();
        if self.nodes.contains_key(&id) {
            return Err(DagError::Duplicate(id));
        }
        if header.parents().len() == 1 && header.parents()[0] == Hash::ZERO {
            return Err(DagError::ZeroParent);
        }
        let mut past = BTreeSet::new();
        let mut computed_height = 0;
        let mut max_parent_timestamp = 0;
        for parent in header.parents() {
            let node = self
                .nodes
                .get(parent)
                .ok_or(DagError::UnknownParent(*parent))?;
            past.extend(node.past.iter().copied());
            past.insert(*parent);
            computed_height = computed_height.max(node.header.height() + 1);
            max_parent_timestamp = max_parent_timestamp.max(node.header.timestamp());
        }
        if header.height() != computed_height {
            return Err(DagError::HeightMismatch {
                announced: header.height(),
                computed: computed_height,
            });
        }
        if header.timestamp() < max_parent_timestamp {
            return Err(DagError::TimestampBehind {
                timestamp: header.timestamp(),
                parent: max_parent_timestamp,
            });
        }
        let limit = now_ms.saturating_add(policy.max_future_ms);
        if header.timestamp() > limit {
            return Err(DagError::TimestampFuture {
                timestamp: header.timestamp(),
                limit,
            });
        }
        let found = leading_zero_bits(&id);
        if !meets_difficulty(&id, policy.difficulty_bits) {
            return Err(DagError::InsufficientWork {
                found,
                required: policy.difficulty_bits,
            });
        }

        // The selected parent: highest blue score, ties by the
        // smallest id.
        let mut selected_parent = header.parents()[0];
        let mut best_score = self.nodes[&selected_parent].blue_score;
        for parent in header.parents() {
            let score = self.nodes[parent].blue_score;
            if score > best_score || (score == best_score && *parent < selected_parent) {
                best_score = score;
                selected_parent = *parent;
            }
        }
        let sp = self
            .nodes
            .get(&selected_parent)
            .expect("the loop above only names held parents");

        // The coloring of ADR-013: the blues of the selected
        // parent and the selected parent itself are inherited;
        // every other block of the new past is a candidate, by
        // score descending then id ascending.
        let mut working: BTreeSet<Hash> = sp.blues.clone();
        working.insert(selected_parent);
        let sp_past = &sp.past;
        let mut candidates: Vec<Hash> = past
            .iter()
            .copied()
            .filter(|h| *h != selected_parent && !sp_past.contains(h))
            .collect();
        candidates.sort_by(|a, b| {
            let sa = self.nodes[a].blue_score;
            let sb = self.nodes[b].blue_score;
            sb.cmp(&sa).then(a.cmp(b))
        });
        for candidate in candidates {
            let candidate_past = &self.nodes[&candidate].past;
            let anticone = working.iter().filter(|u| {
                let u = **u;
                u != candidate
                    && !candidate_past.contains(&u)
                    && !self.nodes[&u].past.contains(&candidate)
            });
            if anticone.count() <= K {
                working.insert(candidate);
            }
        }
        let blue_score = working.len() as u64 + 1;

        let node = Node {
            header: header.clone(),
            blue_score,
            selected_parent: Some(selected_parent),
            blues: working,
            past,
            children: BTreeSet::new(),
        };
        for parent in header.parents() {
            self.nodes
                .get_mut(parent)
                .expect("checked above")
                .children
                .insert(id);
            self.tips.remove(parent);
        }
        self.nodes.insert(id, node);
        self.tips.insert(id);
        Ok(id)
    }

    /// Whether the DAG holds this block.
    #[must_use]
    pub fn contains(&self, id: &Hash) -> bool {
        self.nodes.contains_key(id)
    }

    /// The genesis id this DAG opened on.
    #[must_use]
    pub const fn genesis(&self) -> Hash {
        self.genesis
    }

    /// The number of accepted blocks, genesis included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the DAG holds nothing. It never does once opened:
    /// the method exists because a length exists.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The mining tips, ascending by id.
    #[must_use]
    pub fn tips(&self) -> Vec<Hash> {
        self.tips.iter().copied().collect()
    }

    /// The best tip: highest blue score, ties by smallest id.
    /// This is where a miner appends and where a wallet reads the
    /// consensus order.
    ///
    /// # Errors
    ///
    /// Returns [`DagError::UnknownBlock`] never in practice: the
    /// DAG always holds at least the genesis, and the genesis is
    /// a tip until a first block arrives.
    pub fn best_tip(&self) -> Result<Hash, DagError> {
        self.tips
            .iter()
            .max_by(|a, b| {
                let sa = self.nodes[a].blue_score;
                let sb = self.nodes[b].blue_score;
                sa.cmp(&sb).then_with(|| b.cmp(a))
            })
            .copied()
            .ok_or(DagError::UnknownBlock(self.genesis))
    }

    /// The header of a held block.
    #[must_use]
    pub fn header(&self, id: &Hash) -> Option<&Header> {
        self.nodes.get(id).map(|n| &n.header)
    }

    /// The height of a held block.
    #[must_use]
    pub fn height(&self, id: &Hash) -> Option<u64> {
        self.nodes.get(id).map(|n| n.header.height())
    }

    /// The blue score of a held block: one plus its blue set.
    #[must_use]
    pub fn blue_score(&self, id: &Hash) -> Option<u64> {
        self.nodes.get(id).map(|n| n.blue_score)
    }

    /// The blue ancestors of a held block, itself excluded.
    #[must_use]
    pub fn blues(&self, id: &Hash) -> Option<&BTreeSet<Hash>> {
        self.nodes.get(id).map(|n| &n.blues)
    }

    /// The selected parent of a held block; `None` for the genesis
    /// and for unknown ids.
    #[must_use]
    pub fn selected_parent(&self, id: &Hash) -> Option<Hash> {
        self.nodes.get(id).and_then(|n| n.selected_parent)
    }

    /// The consensus order of the view of a held block: the
    /// genesis plus every ancestor, in the order the ledger and
    /// the checkpoints consume.
    ///
    /// # Errors
    ///
    /// Returns [`DagError::UnknownBlock`] if the tip is not held.
    pub fn consensus_order(&self, tip: &Hash) -> Result<Vec<Hash>, DagError> {
        if !self.nodes.contains_key(tip) {
            return Err(DagError::UnknownBlock(*tip));
        }
        // The selected-parent chain of the tip, genesis first.
        let mut chain = vec![*tip];
        while let Some(parent) =
            self.nodes[chain.last().expect("the chain is started")].selected_parent
        {
            chain.push(parent);
        }
        chain.reverse();

        // order(genesis) = [genesis]; then each chain step appends
        // its new blocks, sorted by height then id.
        let mut order = Vec::with_capacity(self.nodes.len());
        order.push(self.genesis);
        let mut previous_view: BTreeSet<Hash> = BTreeSet::new();
        previous_view.insert(self.genesis);
        for id in &chain[1..] {
            let node = &self.nodes[id];
            let mut view = node.past.clone();
            view.insert(*id);
            let mut fresh: Vec<Hash> = view.difference(&previous_view).copied().collect();
            fresh.sort_by(|a, b| {
                let ha = self.nodes[a].header.height();
                let hb = self.nodes[b].header.height();
                ha.cmp(&hb).then(a.cmp(b))
            });
            order.extend(fresh);
            previous_view = view;
        }
        Ok(order)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow::mine;

    /// A tiny deterministic generator: xorshift64*, so the random
    /// DAG tests depend on no external crate and no machine
    /// state.
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

    /// Builds a child of the current tips (plus, sometimes, an
    /// older block, as a reorg miner would), with a payload of
    /// random transaction ids, mined under `bits`.
    fn child(dag: &Dag, rng: &mut XorShift, bits: u32) -> Block {
        let mut parents = dag.tips();
        let extra = (rng.next() % 4) as usize;
        let all = dag
            .consensus_order(&dag.best_tip().expect("a tip exists"))
            .expect("the order exists");
        for _ in 0..extra {
            let pick = all[(rng.next() % all.len() as u64) as usize];
            if !parents.contains(&pick) {
                parents.push(pick);
            }
        }
        parents.truncate(crate::header::MAX_PARENTS);
        parents.sort_unstable();
        parents.dedup();
        let height = parents
            .iter()
            .filter_map(|p| dag.height(p))
            .max()
            .map_or(1, |h| h + 1);
        let timestamp = 1
            + parents
                .iter()
                .filter_map(|p| dag.header(p))
                .map(|h| h.timestamp())
                .max()
                .expect("the parents are held")
            + rng.next() % 2_000;
        let count = (rng.next() % 3) as usize;
        let mut tx_ids: Vec<Hash> = (0..count)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&(rng.next() ^ (i as u64)).to_le_bytes());
                Hash(bytes)
            })
            .collect();
        tx_ids.sort_unstable();
        tx_ids.dedup();
        let root = payload_root(&tx_ids);
        let skeleton = Header::new(parents, height, timestamp, 0, root);
        let mined = mine(&skeleton, bits, 1 << 26).expect("the difficulty is low");
        Block::new(mined, tx_ids)
    }

    #[test]
    fn a_single_chain_scores_one_per_block() {
        let genesis = Block::devnet_genesis();
        let mut dag = Dag::new(&genesis).expect("the genesis opens");
        let mut rng = XorShift(0x61_61_80_33_39);
        for expected_height in 1..=10u64 {
            let block = child(&dag, &mut rng, 0);
            let id = dag
                .insert(&block, &Policy::VECTORS, u64::MAX)
                .expect("a chain block inserts");
            assert_eq!(dag.height(&id), Some(expected_height));
            assert_eq!(dag.blue_score(&id), Some(expected_height + 1));
        }
        let order = dag
            .consensus_order(&dag.best_tip().expect("a tip exists"))
            .expect("the order exists");
        assert_eq!(order.len(), 11);
        assert_eq!(order[0], dag.genesis());
    }

    #[test]
    fn parallel_blocks_are_ordered_not_rejected() {
        let genesis = Block::devnet_genesis();
        let mut dag = Dag::new(&genesis).expect("the genesis opens");
        let mut rng = XorShift(9);
        let genesis_id = dag.genesis();
        for _ in 0..10 {
            let header = Header::new(
                vec![genesis_id],
                1,
                GENESIS_TIMESTAMP_MS + 2_000,
                rng.next(),
                payload_root(&[]),
            );
            let block = Block::new(header, Vec::new());
            dag.insert(&block, &Policy::VECTORS, u64::MAX)
                .expect("a parallel block inserts");
        }
        assert_eq!(dag.tips().len(), 10);
        // The genesis stopped being a tip: it has children.
        assert!(!dag.tips().contains(&dag.genesis()));
        let mut rng = XorShift(99);
        let block = child(&dag, &mut rng, 0);
        let id = dag
            .insert(&block, &Policy::VECTORS, u64::MAX)
            .expect("the merge inserts");
        assert_eq!(dag.tips(), vec![id]);
        let order = dag.consensus_order(&id).expect("the order exists");
        assert_eq!(order.len(), 12);
        assert_eq!(*order.first().expect("non-empty"), dag.genesis());
        assert_eq!(*order.last().expect("non-empty"), id);
    }

    #[test]
    fn the_insertion_rules_reject_every_violation() {
        let genesis = Block::devnet_genesis();
        let mut dag = Dag::new(&genesis).expect("the genesis opens");
        let mut rng = XorShift(4);
        let first = child(&dag, &mut rng, Policy::DEVNET.difficulty_bits);
        let first_id = dag
            .insert(&first, &Policy::DEVNET, u64::MAX)
            .expect("the first block inserts");

        // A duplicate is rejected.
        assert_eq!(
            dag.insert(&first, &Policy::DEVNET, u64::MAX),
            Err(DagError::Duplicate(first_id))
        );

        // The zero parent is reserved to the genesis.
        let fake = Block::new(
            Header::new(
                vec![Hash::ZERO],
                1,
                GENESIS_TIMESTAMP_MS + 2_000,
                0,
                payload_root(&[]),
            ),
            Vec::new(),
        );
        assert_eq!(
            dag.insert(&fake, &Policy::DEVNET, u64::MAX),
            Err(DagError::ZeroParent)
        );

        // An unknown parent is rejected.
        let ghost = Block::new(
            Header::new(
                vec![Hash([0xab; 32])],
                1,
                GENESIS_TIMESTAMP_MS + 2_000,
                0,
                payload_root(&[]),
            ),
            Vec::new(),
        );
        assert_eq!(
            dag.insert(&ghost, &Policy::DEVNET, u64::MAX),
            Err(DagError::UnknownParent(Hash([0xab; 32])))
        );

        // A wrong height is rejected.
        let honest = child(&dag, &mut rng, 0);
        let wrong = Block::new(
            Header::new(
                honest.header().parents().to_vec(),
                honest.header().height() + 1,
                honest.header().timestamp(),
                honest.header().nonce(),
                honest.header().payload_root(),
            ),
            honest.tx_ids().to_vec(),
        );
        assert!(matches!(
            dag.insert(&wrong, &Policy::VECTORS, u64::MAX),
            Err(DagError::HeightMismatch { .. })
        ));

        // A timestamp behind a parent is rejected.
        let parent_ts = dag
            .header(&honest.header().parents()[0])
            .expect("the parent is held")
            .timestamp();
        let behind = Block::new(
            Header::new(
                honest.header().parents().to_vec(),
                honest.header().height(),
                parent_ts - 1,
                honest.header().nonce(),
                honest.header().payload_root(),
            ),
            honest.tx_ids().to_vec(),
        );
        assert!(matches!(
            dag.insert(&behind, &Policy::VECTORS, u64::MAX),
            Err(DagError::TimestampBehind { .. })
        ));

        // A future timestamp is rejected.
        let future = Block::new(
            Header::new(
                vec![first_id],
                2,
                1_000_000_000_000_000,
                0,
                payload_root(&[]),
            ),
            Vec::new(),
        );
        assert!(matches!(
            dag.insert(&future, &Policy::DEVNET, 0),
            Err(DagError::TimestampFuture { .. })
        ));

        // Insufficient work is rejected.
        let lazy = Block::new(
            Header::new(
                vec![first_id],
                2,
                GENESIS_TIMESTAMP_MS + 4_000,
                0,
                payload_root(&[]),
            ),
            Vec::new(),
        );
        assert!(matches!(
            dag.insert(&lazy, &Policy::DEVNET, u64::MAX),
            Err(DagError::InsufficientWork { .. })
        ));
    }

    #[test]
    fn the_order_is_topological_and_append_only() {
        let genesis = Block::devnet_genesis();
        let mut dag = Dag::new(&genesis).expect("the genesis opens");
        let mut rng = XorShift(1_618_033_988);
        let mut last_tip = dag.genesis();
        let mut last_order = vec![dag.genesis()];
        for _ in 0..40 {
            let block = child(&dag, &mut rng, 0);
            let id = dag
                .insert(&block, &Policy::VECTORS, u64::MAX)
                .expect("the block inserts");
            let order = dag.consensus_order(&id).expect("the order exists");
            // Topological: every parent of every block precedes
            // it, the zero parent apart.
            for (position, block_id) in order.iter().enumerate() {
                for parent in dag.header(block_id).expect("held").parents() {
                    if *parent == Hash::ZERO {
                        continue;
                    }
                    let parent_position = order
                        .iter()
                        .position(|h| h == parent)
                        .expect("the parent is in the view");
                    assert!(parent_position < position, "the order is topological");
                }
            }
            // Prefix stability along the selected-parent chain.
            let sp = dag.selected_parent(&id).expect("a parent block");
            if sp == last_tip {
                assert!(order.starts_with(&last_order), "the order never reshuffles");
            }
            last_tip = id;
            last_order = order;
            // The blue score covers the selected parent.
            let score = dag.blue_score(&id).expect("held");
            let sp_score = dag.blue_score(&sp).expect("held");
            assert!(score > sp_score);
        }
    }

    #[test]
    fn the_blue_set_is_inherited_and_bounded() {
        let genesis = Block::devnet_genesis();
        let mut dag = Dag::new(&genesis).expect("the genesis opens");
        let mut rng = XorShift(0xfeed);
        for _ in 0..30 {
            let block = child(&dag, &mut rng, 0);
            let id = dag
                .insert(&block, &Policy::VECTORS, u64::MAX)
                .expect("the block inserts");
            let node = dag.nodes.get(&id).expect("held");
            // The blue set lives in the past, the score is exact.
            for blue in &node.blues {
                assert!(node.past.contains(blue), "a blue block is an ancestor");
            }
            assert_eq!(node.blue_score, node.blues.len() as u64 + 1);
            // The selected parent is blue, its blues survive.
            let sp = node.selected_parent.expect("a parent block");
            assert!(node.blues.contains(&sp), "the selected parent is blue");
            let inherited = dag.blues(&sp).expect("held").clone();
            for blue in &inherited {
                assert!(node.blues.contains(blue), "a parent blue stays blue");
            }
        }
    }
}

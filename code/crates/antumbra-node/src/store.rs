//! The node store: the bookkeeping of every accepted block
//! (ADR-025).
//!
//! The reference [`Dag`] of the ordering layer is the normative
//! oracle, and it materializes the transitive past and the blue
//! set of every block: exact, and quadratic in memory. A day of
//! development blocks (43,200) would ask for tens of gigabytes.
//! This store is the production shape the reference announces:
//! one entry per block — header, payload ids, blue score,
//! selected parent, children, fresh set, order length — plus the
//! materialized consensus order of the best tip.
//!
//! Two paths color a block:
//!
//! - The **chain path**, for a single-parent block: its past is
//!   its parent's past plus the parent, so the candidate set of
//!   the coloring is empty, the blue set is the selected parent
//!   and its inherited blues, the blue score is the parent's plus
//!   one, and the fresh set is the block alone. Exact in O(1), no
//!   closure ever materialized, at any height. The day of DAG
//!   runs on this path.
//! - The **fork path**, for a merge: the node holds a live mirror
//!   of the reference `Dag` while the total block count stays
//!   within [`REFERENCE_WINDOW`], feeds it every accepted block,
//!   and copies its answers — selected parent, blue score, fresh
//!   set as the order suffix of the selected parent's order.
//!   Past the window the mirror is dropped and a merge is the
//!   policy rejection [`NodeError::MergeBeyondWindow`]: the solo
//!   devnet driver never merges, and deeper merge validation
//!   belongs to the P2P phase with a store of its own.
//!
//! The differential tests compare this store against an
//! independent reference instance on randomized fork-heavy DAGs,
//! after every insertion: tips, best tip, blue scores, selected
//! parents, full consensus orders, and the materialized best
//! order.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use antumbra_dag::payload_root;
use antumbra_dag::{leading_zero_bits, meets_difficulty, Block, Dag, DagError, Header, Policy};
use antumbra_primitives::Hash;

/// The number of accepted blocks for which the live reference
/// mirror is kept: merges are colored exactly within this window
/// and refused past it (ADR-025).
pub const REFERENCE_WINDOW: usize = 1_024;

/// The bound on the selected-parent walk before the materialized
/// order is rebuilt from scratch: a deeper walk costs the same
/// rebuild it would avoid.
const MAX_ORDER_WALK: usize = REFERENCE_WINDOW;

/// Every refusal of the store: a broken rule of the ordering
/// layer (named by the reference error) or the merge window
/// policy of this node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeError {
    /// A rule of the reference insertion battery, named exactly.
    Rule(DagError),
    /// A multi-parent block past the reference window: the solo
    /// devnet driver never merges, and the window is the policy
    /// of ADR-025.
    MergeBeyondWindow {
        /// The parent count of the refused merge.
        parents: usize,
        /// The window the store had exceeded.
        window: usize,
    },
}

impl core::fmt::Display for NodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rule(error) => write!(f, "store rule: {error}"),
            Self::MergeBeyondWindow { parents, window } => write!(
                f,
                "merge of {parents} parents past the reference window of {window} blocks"
            ),
        }
    }
}

impl std::error::Error for NodeError {}

/// The derived state of one accepted block: exactly what the
/// consumers read, and nothing materialized quadratically.
struct NodeData {
    header: Header,
    tx_ids: Vec<Hash>,
    blue_score: u64,
    selected_parent: Option<Hash>,
    children: BTreeSet<Hash>,
    /// The blocks this block's view adds over its selected
    /// parent's view: itself and the merged candidates, sorted by
    /// height then id, the append-only unit of the consensus
    /// order. The genesis alone carries itself.
    fresh: Vec<Hash>,
    /// The size of this block's view: its position in its own
    /// order is `order_len - 1`.
    order_len: u64,
}

/// The node store: every accepted block, the tips, and the
/// materialized consensus order of the best tip.
///
/// Every query is deterministic in the accepted set alone, and
/// the differential tests pin the answers to the reference crate.
pub struct Store {
    genesis: Hash,
    nodes: BTreeMap<Hash, NodeData>,
    tips: BTreeSet<Hash>,
    order: Vec<Hash>,
    positions: BTreeMap<Hash, u64>,
    order_tip: Hash,
    reference: Option<Dag>,
}

impl Store {
    /// Opens the store on the network genesis.
    ///
    /// The genesis must be the zero-parent, zero-height block of
    /// the network, with a payload root that commits its
    /// transaction list. The reference mirror is born with it.
    ///
    /// # Errors
    ///
    /// Returns a [`NodeError`] if the block is not of the genesis
    /// shape; the store then does not exist.
    pub fn new(genesis: &Block) -> Result<Self, NodeError> {
        let header = genesis.header();
        if header.parents().len() != 1 || header.parents()[0] != Hash::ZERO {
            return Err(NodeError::Rule(DagError::ZeroParent));
        }
        if header.height() != 0 {
            return Err(NodeError::Rule(DagError::HeightMismatch {
                announced: header.height(),
                computed: 0,
            }));
        }
        let computed = payload_root(genesis.tx_ids());
        if computed != header.payload_root() {
            return Err(NodeError::Rule(DagError::PayloadRootMismatch {
                announced: header.payload_root(),
                computed,
            }));
        }
        let id = genesis.id();
        let node = NodeData {
            header: header.clone(),
            tx_ids: genesis.tx_ids().to_vec(),
            blue_score: 1,
            selected_parent: None,
            children: BTreeSet::new(),
            fresh: vec![id],
            order_len: 1,
        };
        let mirror = Dag::new(genesis).map_err(NodeError::Rule)?;
        let mut nodes = BTreeMap::new();
        nodes.insert(id, node);
        let mut tips = BTreeSet::new();
        tips.insert(id);
        let mut positions = BTreeMap::new();
        positions.insert(id, 0);
        Ok(Self {
            genesis: id,
            nodes,
            tips,
            order: vec![id],
            positions,
            order_tip: id,
            reference: Some(mirror),
        })
    }

    /// Inserts a block after the full rule battery of the
    /// reference insertion, in the reference order: the payload
    /// root, the duplicate id, the parent list shape, every
    /// parent held, the announced height, the parent timestamps,
    /// the future bound, and the work under the policy. The
    /// coloring then follows the chain or the fork path of this
    /// module, the tips move, and the best order extends.
    ///
    /// # Errors
    ///
    /// Returns a [`NodeError`] naming the first violated rule, or
    /// [`NodeError::MergeBeyondWindow`] for a merge past the
    /// reference window. The store is unchanged.
    pub fn insert(
        &mut self,
        block: &Block,
        policy: &Policy,
        now_ms: u64,
    ) -> Result<Hash, NodeError> {
        let header = block.header();
        let computed_root = payload_root(block.tx_ids());
        if computed_root != header.payload_root() {
            return Err(NodeError::Rule(DagError::PayloadRootMismatch {
                announced: header.payload_root(),
                computed: computed_root,
            }));
        }
        let id = block.id();
        if self.nodes.contains_key(&id) {
            return Err(NodeError::Rule(DagError::Duplicate(id)));
        }
        if header.parents().len() == 1 && header.parents()[0] == Hash::ZERO {
            return Err(NodeError::Rule(DagError::ZeroParent));
        }
        let mut computed_height = 0;
        let mut max_parent_timestamp = 0;
        for parent in header.parents() {
            let node = self
                .nodes
                .get(parent)
                .ok_or(NodeError::Rule(DagError::UnknownParent(*parent)))?;
            computed_height = computed_height.max(node.header.height() + 1);
            max_parent_timestamp = max_parent_timestamp.max(node.header.timestamp());
        }
        if header.height() != computed_height {
            return Err(NodeError::Rule(DagError::HeightMismatch {
                announced: header.height(),
                computed: computed_height,
            }));
        }
        if header.timestamp() < max_parent_timestamp {
            return Err(NodeError::Rule(DagError::TimestampBehind {
                timestamp: header.timestamp(),
                parent: max_parent_timestamp,
            }));
        }
        let limit = now_ms.saturating_add(policy.max_future_ms);
        if header.timestamp() > limit {
            return Err(NodeError::Rule(DagError::TimestampFuture {
                timestamp: header.timestamp(),
                limit,
            }));
        }
        if !meets_difficulty(&id, policy.difficulty_bits) {
            return Err(NodeError::Rule(DagError::InsufficientWork {
                found: leading_zero_bits(&id),
                required: policy.difficulty_bits,
            }));
        }

        // The fork path needs the mirror before any mutation.
        let single_parent = header.parents().len() == 1;
        if !single_parent && self.reference.is_none() {
            return Err(NodeError::MergeBeyondWindow {
                parents: header.parents().len(),
                window: REFERENCE_WINDOW,
            });
        }
        // The mirror holds every accepted block while it lives:
        // the chain path does not read it, the fork path does.
        if let Some(mirror) = self.reference.as_mut() {
            mirror
                .insert(block, policy, now_ms)
                .map_err(NodeError::Rule)?;
        }

        let (blue_score, selected_parent, fresh, order_len) = if single_parent {
            // The chain path: the candidate set is provably empty
            // for a single parent, so the coloring is exact in
            // O(1) and nothing is materialized.
            let parent = header.parents()[0];
            let parent_node = self
                .nodes
                .get(&parent)
                .expect("the rule battery named every parent held");
            (
                parent_node.blue_score + 1,
                Some(parent),
                vec![id],
                parent_node.order_len + 1,
            )
        } else {
            // The fork path: the reference mirror just colored the
            // merge; the bookkeeping copies its answers.
            let mirror = self
                .reference
                .as_ref()
                .expect("the window check kept the mirror");
            let selected_parent = mirror
                .selected_parent(&id)
                .expect("the mirror holds the block");
            let blue_score = mirror.blue_score(&id).expect("the mirror holds the block");
            let order = mirror
                .consensus_order(&id)
                .expect("the mirror holds the tip");
            let parent_order = mirror
                .consensus_order(&selected_parent)
                .expect("the mirror holds the parent");
            let fresh = order[parent_order.len()..].to_vec();
            (blue_score, Some(selected_parent), fresh, order.len() as u64)
        };

        let node = NodeData {
            header: header.clone(),
            tx_ids: block.tx_ids().to_vec(),
            blue_score,
            selected_parent,
            children: BTreeSet::new(),
            fresh,
            order_len,
        };
        for parent in header.parents() {
            if let Some(parent_node) = self.nodes.get_mut(parent) {
                parent_node.children.insert(id);
            }
            self.tips.remove(parent);
        }
        self.nodes.insert(id, node);
        self.tips.insert(id);
        if self.nodes.len() >= REFERENCE_WINDOW {
            // The window is closed: the mirror is freed and merges
            // become the policy refusal of ADR-025.
            self.reference = None;
        }
        self.refresh_order();
        Ok(id)
    }

    /// Extends the materialized order to the new best tip when the
    /// best chain still ends at the materialized tip, and rebuilds
    /// it from scratch otherwise. The order is append-only along
    /// selected-parent chains, so the common case appends the
    /// fresh sets of a bounded walk.
    fn refresh_order(&mut self) {
        let best = self.best_tip();
        if best == self.order_tip {
            return;
        }
        let mut stack: Vec<Vec<Hash>> = Vec::new();
        let mut current = best;
        loop {
            if current == self.order_tip {
                for fresh in stack.iter().rev() {
                    for hash in fresh {
                        self.positions.insert(*hash, self.order.len() as u64);
                        self.order.push(*hash);
                    }
                }
                self.order_tip = best;
                return;
            }
            if stack.len() >= MAX_ORDER_WALK {
                break;
            }
            let node = self
                .nodes
                .get(&current)
                .expect("the chain walks held blocks only");
            match node.selected_parent {
                Some(parent) => {
                    stack.push(node.fresh.clone());
                    current = parent;
                }
                // The walk reached the genesis without meeting the
                // materialized tip: the best tip moved to a chain
                // that does not extend the current order.
                None => break,
            }
        }
        self.rebuild_order(best);
    }

    /// Rebuilds the materialized order and its positions from the
    /// selected-parent chain of a tip: the total, reproducible
    /// form of the append-only order, the reference rebuild.
    fn rebuild_order(&mut self, tip: Hash) {
        let mut stack: Vec<Vec<Hash>> = Vec::new();
        let mut current = tip;
        loop {
            let node = self
                .nodes
                .get(&current)
                .expect("the chain walks held blocks only");
            stack.push(node.fresh.clone());
            match node.selected_parent {
                Some(parent) => current = parent,
                None => break,
            }
        }
        self.order.clear();
        self.positions.clear();
        for fresh in stack.iter().rev() {
            for hash in fresh {
                self.positions.insert(*hash, self.order.len() as u64);
                self.order.push(*hash);
            }
        }
        self.order_tip = tip;
    }

    /// Whether the store holds a block.
    #[must_use]
    pub fn contains(&self, id: &Hash) -> bool {
        self.nodes.contains_key(id)
    }

    /// The genesis id the store opened on.
    #[must_use]
    pub const fn genesis(&self) -> Hash {
        self.genesis
    }

    /// The number of accepted blocks, the genesis included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the store holds the genesis alone.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The mining tips: blocks no accepted block builds on.
    #[must_use]
    pub fn tips(&self) -> Vec<Hash> {
        self.tips.iter().copied().collect()
    }

    /// The best tip: highest blue score, ties by smallest id, the
    /// rule of the reference. Always defined: the genesis is a tip
    /// until a first block arrives.
    #[must_use]
    pub fn best_tip(&self) -> Hash {
        *self
            .tips
            .iter()
            .max_by(|a, b| {
                let score_a = self.nodes[a].blue_score;
                let score_b = self.nodes[b].blue_score;
                score_a.cmp(&score_b).then_with(|| b.cmp(a))
            })
            .expect("the genesis is always a tip")
    }

    /// The header of a held block.
    #[must_use]
    pub fn header(&self, id: &Hash) -> Option<&Header> {
        self.nodes.get(id).map(|node| &node.header)
    }

    /// The height of a held block.
    #[must_use]
    pub fn height(&self, id: &Hash) -> Option<u64> {
        self.nodes.get(id).map(|node| node.header.height())
    }

    /// The transaction ids of a held block, in payload order.
    #[must_use]
    pub fn tx_ids(&self, id: &Hash) -> Option<&[Hash]> {
        self.nodes.get(id).map(|node| node.tx_ids.as_slice())
    }

    /// The blue score of a held block: one plus its blue set.
    #[must_use]
    pub fn blue_score(&self, id: &Hash) -> Option<u64> {
        self.nodes.get(id).map(|node| node.blue_score)
    }

    /// The selected parent of a held block; `None` for the genesis
    /// and for unknown ids.
    #[must_use]
    pub fn selected_parent(&self, id: &Hash) -> Option<Hash> {
        self.nodes.get(id).and_then(|node| node.selected_parent)
    }

    /// The size of the view of a held block: its position in its
    /// own order is one less.
    #[must_use]
    pub fn order_len(&self, id: &Hash) -> Option<u64> {
        self.nodes.get(id).map(|node| node.order_len)
    }

    /// The materialized consensus order of the best tip: the
    /// append-only sequence the ledger consumes.
    #[must_use]
    pub fn order(&self) -> &[Hash] {
        &self.order
    }

    /// The block whose order is materialized: always the best tip.
    #[must_use]
    pub const fn order_tip(&self) -> Hash {
        self.order_tip
    }

    /// The consensus order of the view of any held block, computed
    /// from the stored chain: the genesis first, then every
    /// ancestor, fresh set by fresh set.
    ///
    /// # Errors
    ///
    /// Returns a [`NodeError`] naming an unknown block; nothing is
    /// computed then.
    pub fn consensus_order(&self, tip: &Hash) -> Result<Vec<Hash>, NodeError> {
        if !self.nodes.contains_key(tip) {
            return Err(NodeError::Rule(DagError::UnknownBlock(*tip)));
        }
        let mut stack: Vec<Vec<Hash>> = Vec::new();
        let mut current = *tip;
        loop {
            let node = self
                .nodes
                .get(&current)
                .expect("the check above named the block held");
            stack.push(node.fresh.clone());
            match node.selected_parent {
                Some(parent) => current = parent,
                None => break,
            }
        }
        let mut order = Vec::with_capacity(stack.len());
        for fresh in stack.iter().rev() {
            order.extend_from_slice(fresh);
        }
        Ok(order)
    }

    /// The children of a held block, ascending.
    #[must_use]
    pub fn children(&self, id: &Hash) -> Option<Vec<Hash>> {
        self.nodes
            .get(id)
            .map(|node| node.children.iter().copied().collect())
    }
}

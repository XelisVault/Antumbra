//! The engine: the node as one running participant (ADR-025).
//!
//! The engine owns the store, the transaction bodies, the ledger,
//! the mempool and the devnet wallets, and it moves them together:
//! a block is assembled from the mempool and the coinbase of
//! ADR-024, mined under the devnet policy, inserted into the
//! store, and applied to the ledger as the suffix the best tip
//! adds over the ledger's frontier. When the best tip moves to a
//! chain whose order does not extend the frontier, the ledger is
//! rebuilt from scratch over the new order — the reference rebuild
//! of ADR-024 — and the trackers follow.
//!
//! Every refusal is a named breach and stops the day: the numbers
//! are published, not hidden.

use std::collections::BTreeMap;
use std::time::Instant;

use antumbra_dag::{mine, MAX_TXS};
use antumbra_dag::{payload_root, Block, Header};
use antumbra_primitives::Hash;
use antumbra_primitives::Writer;
use antumbra_state::coinbase::{
    reward_of_slot, treasury_active_at_slot, treasury_share_of, MATURITY,
};
use antumbra_state::ledger::Ledger;
use antumbra_state::ledger::StateError;
use antumbra_tx::{Amount, FeeSchedule, OutputRef, Transaction, TxType};

use crate::devnet::{clock, devnet_policy, MINING_ATTEMPTS};
use crate::mempool::{AdmitError, Mempool};
use crate::status::{Reported, Status};
use crate::store::{NodeError, Store};
use crate::wallet::{SpendError, TrackedWallet};

/// A breach: the named reason a day stops. One breach, one honest
/// failure; the run publishes it and exits red.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Breach {
    /// The store refused a block: a rule of the ordering layer or
    /// the merge window policy.
    Store(NodeError),
    /// The ledger rejected a payload: a rule of the state layer.
    Ledger(StateError),
    /// A wallet could not build the activity of the script.
    Wallet(SpendError),
    /// The mempool refused the activity of the script.
    Admission(AdmitError),
    /// The mining budget was exhausted without meeting the
    /// difficulty.
    MiningExhausted {
        /// The attempt budget that failed.
        attempts: u64,
    },
    /// An invariant of the battery failed after a block.
    Invariant(&'static str),
}

impl core::fmt::Display for Breach {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "breach, store: {error}"),
            Self::Ledger(error) => write!(f, "breach, ledger: {error}"),
            Self::Wallet(error) => write!(f, "breach, wallet: {error}"),
            Self::Admission(error) => write!(f, "breach, admission: {error}"),
            Self::MiningExhausted { attempts } => {
                write!(f, "breach, mining: {attempts} attempts met no work target")
            }
            Self::Invariant(rule) => write!(f, "breach, invariant: {rule}"),
        }
    }
}

impl std::error::Error for Breach {}

/// The independent recomputation of the emission the invariants
/// compare the ledger against: the node does not trust the
/// counters, it recomputes them from the calendar.
#[derive(Clone, Debug, Default)]
pub struct EmissionChecks {
    /// The sum of `reward_of_slot` over the applied slots.
    pub expected_emitted: u64,
    /// The sum of the treasury shares over the treasury-active
    /// slots.
    pub expected_treasury: u64,
}

impl EmissionChecks {
    /// Folds one applied slot into the recomputation. The genesis
    /// (slot zero) mints nothing.
    pub fn slot_applied(&mut self, slot: u64) {
        if slot == 0 {
            return;
        }
        let reward = reward_of_slot(slot);
        self.expected_emitted = self.expected_emitted.saturating_add(reward);
        if treasury_active_at_slot(slot) {
            self.expected_treasury = self
                .expected_treasury
                .saturating_add(treasury_share_of(reward));
        }
    }
}

/// The counters of a run.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    /// Blocks mined by this engine.
    pub mined: u64,
    /// Transfer transactions applied.
    pub transfers: u64,
    /// Coinbase transactions applied.
    pub coinbases: u64,
    /// Ledger rebuilds after reorganizations.
    pub rebuilds: u64,
}

/// The node: the store, the ledger, the mempool, the wallets, and
/// the frontier between the ordered DAG and the applied state.
pub struct Engine {
    policy: antumbra_dag::Policy,
    fees: FeeSchedule,
    store: Store,
    txs: BTreeMap<Hash, Transaction>,
    ledger: Ledger,
    mempool: Mempool,
    /// The devnet wallets of the activity script, with their
    /// trackers.
    pub wallets: DevnetWallets,
    frontier: Hash,
    checks: EmissionChecks,
    stats: Stats,
}

/// The three wallets of the devnet activity script (ADR-025): the
/// miner receives every coinbase, Alice receives a third of every
/// miner spend, Bob half of Alice's oldest output.
pub struct DevnetWallets {
    /// The solo miner.
    pub miner: TrackedWallet,
    /// The first hop of the activity script.
    pub alice: TrackedWallet,
    /// The second hop of the activity script.
    pub bob: TrackedWallet,
}

impl DevnetWallets {
    /// The devnet wallets from the fixed seeds.
    #[must_use]
    pub fn devnet() -> Self {
        Self {
            miner: TrackedWallet::new(crate::devnet::miner()),
            alice: TrackedWallet::new(crate::devnet::alice()),
            bob: TrackedWallet::new(crate::devnet::bob()),
        }
    }

    /// Resets the trackers: the prelude of a ledger rebuild.
    pub fn reset_trackers(&mut self) {
        self.miner.tracker = crate::wallet::Tracker::new();
        self.alice.tracker = crate::wallet::Tracker::new();
        self.bob.tracker = crate::wallet::Tracker::new();
    }

    /// Credits an output to the wallet of its address, when one of
    /// the three owns it.
    pub fn credit(
        &mut self,
        address: antumbra_primitives::Address,
        reference: OutputRef,
        amount: Amount,
        coinbase_slot: Option<u64>,
    ) {
        for wallet in [&mut self.miner, &mut self.alice, &mut self.bob] {
            if wallet.wallet.address() == address {
                wallet.credit(reference, amount, coinbase_slot);
            }
        }
    }

    /// Debits a reference on every wallet: a no-op where it was
    /// never credited.
    pub fn debit(&mut self, reference: OutputRef) {
        for wallet in [&mut self.miner, &mut self.alice, &mut self.bob] {
            wallet.debit(reference);
        }
    }
}

impl Engine {
    /// Boots the node on the frozen devnet genesis: the store
    /// opens, the ledger applies the empty genesis, the frontier
    /// is the genesis itself.
    ///
    /// # Errors
    ///
    /// Returns a [`NodeError`] only if the genesis constant itself
    /// is malformed — a protocol fault, not a runtime condition.
    pub fn boot(difficulty: u32) -> Result<Self, NodeError> {
        let genesis = Block::devnet_genesis();
        let store = Store::new(&genesis)?;
        let id = genesis.id();
        let mut ledger = Ledger::new();
        // The genesis applies first: height zero, empty payload,
        // the slot zero that mints nothing. It cannot fail.
        ledger
            .apply_block(0, &[])
            .expect("the devnet genesis applies: height zero, empty payload");
        Ok(Self {
            policy: devnet_policy(difficulty),
            fees: FeeSchedule::PROVISIONAL,
            store,
            txs: BTreeMap::new(),
            ledger,
            mempool: Mempool::new(),
            wallets: DevnetWallets::devnet(),
            frontier: id,
            checks: EmissionChecks::default(),
            stats: Stats::default(),
        })
    }

    /// The store: the ordering layer of the node.
    #[must_use]
    pub const fn store(&self) -> &Store {
        &self.store
    }

    /// The ledger: the state layer of the node.
    #[must_use]
    pub const fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// The mempool: the admission layer of the node.
    #[must_use]
    pub const fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    /// The block whose view the ledger applied.
    #[must_use]
    pub const fn frontier(&self) -> Hash {
        self.frontier
    }

    /// The independent emission recomputation.
    #[must_use]
    pub const fn checks(&self) -> &EmissionChecks {
        &self.checks
    }

    /// The counters of the run.
    #[must_use]
    pub const fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Registers a payload transaction in the engine's memory:
    /// the assembler does it for the blocks it builds, and the
    /// remote-block path of the tests does it by hand.
    pub fn register_payload(&mut self, transaction: &Transaction) {
        self.txs.insert(transaction.tx_id(), transaction.clone());
    }

    /// Submits a transaction to the mempool at the slot a
    /// transaction would land in.
    ///
    /// # Errors
    ///
    /// Returns an [`AdmitError`] naming the refused rule.
    pub fn submit(&mut self, transaction: &Transaction) -> Result<Hash, AdmitError> {
        let next_slot = self.ledger.applied();
        self.mempool
            .admit(transaction, &self.ledger, &self.fees, next_slot)
    }

    /// Assembles a block on a parent: the coinbase of ADR-024 at
    /// the parent's order length (the slot the block will occupy),
    /// the transfers beside it, the ids sorted, the header mined
    /// under the devnet policy. The payload transactions are
    /// registered in the engine's memory.
    ///
    /// # Errors
    ///
    /// Returns a [`Breach`] if the mining budget fails; assembly
    /// itself cannot fail honestly.
    pub fn assemble(&mut self, parent: Hash, transfers: Vec<Transaction>) -> Result<Block, Breach> {
        let slot = self
            .store
            .order_len(&parent)
            .expect("the parent is a held block");
        let height = self
            .store
            .height(&parent)
            .expect("the parent is a held block")
            + 1;
        let timestamp = clock(height);
        let fees = transfers
            .iter()
            .map(|transaction| transaction.fee().atomic())
            .fold(0, u64::saturating_add);
        let coinbase = self.wallets.miner.wallet.coinbase(height, slot, fees);
        let mut ids: Vec<Hash> = transfers
            .iter()
            .map(|transaction| transaction.tx_id())
            .collect();
        ids.push(coinbase.tx_id());
        ids.sort_unstable();
        ids.dedup();
        for transaction in &transfers {
            self.txs.insert(transaction.tx_id(), transaction.clone());
        }
        self.txs.insert(coinbase.tx_id(), coinbase.clone());
        let root = payload_root(&ids);
        let draft = Header::new(vec![parent], height, timestamp, 0, root);
        let header = mine(&draft, self.policy.difficulty_bits, MINING_ATTEMPTS).ok_or(
            Breach::MiningExhausted {
                attempts: MINING_ATTEMPTS,
            },
        )?;
        Ok(Block::new(header, ids))
    }

    /// Mines one block on the best tip from the mempool and
    /// applies it: the solo driver step.
    ///
    /// # Errors
    ///
    /// Returns the first [`Breach`] of the step; the day stops.
    pub fn mine_and_apply(&mut self) -> Result<Hash, Breach> {
        let best = self.store.best_tip();
        let transfers = self.mempool.take(MAX_TXS.saturating_sub(1));
        let block = self.assemble(best, transfers)?;
        let id = self.insert_block(&block)?;
        self.stats.mined += 1;
        Ok(id)
    }

    /// Inserts a block and applies the suffix the new best tip
    /// adds over the ledger's frontier, or rebuilds the ledger
    /// over the new order when the frontier is not on the best
    /// chain. The block's timestamp is the node's now.
    ///
    /// # Errors
    ///
    /// Returns the first [`Breach`]: a store refusal or a ledger
    /// rejection.
    pub fn insert_block(&mut self, block: &Block) -> Result<Hash, Breach> {
        let now = block.header().timestamp();
        let id = self
            .store
            .insert(block, &self.policy, now)
            .map_err(Breach::Store)?;
        self.sync_ledger().map_err(Breach::Ledger)?;
        Ok(id)
    }

    /// The suffix application or the total rebuild, after an
    /// insertion changed the best tip.
    fn sync_ledger(&mut self) -> Result<(), StateError> {
        let best = self.store.best_tip();
        let applied = self.ledger.applied() as usize;
        let extends = self.store.order().len() >= applied
            && self.store.order().get(applied - 1) == Some(&self.frontier);
        if extends {
            let suffix: Vec<Hash> = self.store.order()[applied..].to_vec();
            for id in suffix {
                let (height, txs) = self.payload_of(&id).ok_or(StateError::MissingPayload(id))?;
                let slot = self.ledger.applied();
                self.ledger.apply_block(height, &txs)?;
                self.after_apply(slot, &txs);
                self.frontier = id;
            }
        } else {
            self.rebuild_ledger(best)?;
        }
        Ok(())
    }

    /// The total rebuild of ADR-024: a fresh ledger over the
    /// consensus order of the new best tip, the trackers and the
    /// checks replayed with it.
    fn rebuild_ledger(&mut self, best: Hash) -> Result<(), StateError> {
        let order = self
            .store
            .consensus_order(&best)
            .expect("the best tip is held");
        let payloads: Vec<Option<(u64, Vec<Transaction>)>> =
            order.iter().map(|id| self.payload_of(id)).collect();
        let mut ledger = Ledger::new();
        self.wallets.reset_trackers();
        self.checks = EmissionChecks::default();
        // The replayed counters describe the new ledger: the
        // rebuild is a replay of the whole order, not more work.
        self.stats.transfers = 0;
        self.stats.coinbases = 0;
        for (position, payload) in payloads.into_iter().enumerate() {
            let (height, txs) = payload.ok_or(StateError::MissingPayload(order[position]))?;
            ledger.apply_block(height, &txs)?;
            self.after_apply(position as u64, &txs);
        }
        self.stats.rebuilds += 1;
        self.ledger = ledger;
        self.frontier = best;
        Ok(())
    }

    /// The payload of a held block: its height and its
    /// transactions, in payload order. `None` when a transaction
    /// body is missing from the engine's memory.
    fn payload_of(&self, id: &Hash) -> Option<(u64, Vec<Transaction>)> {
        let height = self.store.height(id)?;
        let ids = self.store.tx_ids(id)?;
        let mut txs = Vec::with_capacity(ids.len());
        for tx_id in ids {
            txs.push(self.txs.get(tx_id)?.clone());
        }
        Some((height, txs))
    }

    /// Folds an applied payload into the trackers, the checks and
    /// the counters.
    fn after_apply(&mut self, slot: u64, txs: &[Transaction]) {
        self.checks.slot_applied(slot);
        for transaction in txs {
            let tx_id = transaction.tx_id();
            let coinbase_slot = (transaction.tx_type() == TxType::Coinbase).then_some(slot);
            for (index, output) in transaction.outputs().iter().enumerate() {
                let reference = OutputRef::new(tx_id, index as u32);
                self.wallets
                    .credit(output.address(), reference, output.amount(), coinbase_slot);
            }
            for input in transaction.inputs() {
                self.wallets.debit(input.output_ref());
            }
            match transaction.tx_type() {
                TxType::Coinbase => self.stats.coinbases += 1,
                TxType::Transfer => self.stats.transfers += 1,
                _ => {
                    // The devnet payload carries transfers and
                    // coinbases only; the reserved types are
                    // rejected upstream.
                }
            }
        }
    }

    /// The miner wallet spends its oldest matured output worth
    /// spending: one third to Alice, the rest back as change, the
    /// fee the schedule minimum. Skipped deterministically when
    /// nothing matured and valuable enough is unspent — the early
    /// blocks and the dust of decayed lineages.
    ///
    /// # Errors
    ///
    /// Returns a [`Breach`] if the construction or the admission
    /// fails: a script failure is a driver fault, not a network
    /// event.
    pub fn activity_miner(&mut self) -> Result<(), Breach> {
        let next_slot = self.ledger.applied();
        let minimum = self
            .wallets
            .miner
            .wallet
            .minimum_spend_atomic(&self.fees)
            .unwrap_or(u64::MAX);
        let Some((reference, value)) = self
            .wallets
            .miner
            .tracker
            .first_spendable(next_slot, MATURITY, minimum)
        else {
            return Ok(());
        };
        let third = Amount::from_atomic(value.atomic() / 3);
        let destination = self.wallets.alice.wallet.address();
        let transaction = self
            .wallets
            .miner
            .wallet
            .spend_one(reference, value, destination, third, &self.fees)
            .map_err(Breach::Wallet)?;
        self.submit(&transaction).map_err(Breach::Admission)?;
        Ok(())
    }

    /// Alice spends half of her oldest unspent output worth
    /// spending to Bob. The decayed lineages below twice the
    /// minimum fee are dust and stay unspent.
    ///
    /// # Errors
    ///
    /// Returns a [`Breach`] on a construction or admission fault.
    pub fn activity_alice(&mut self) -> Result<(), Breach> {
        let next_slot = self.ledger.applied();
        let minimum = self
            .wallets
            .alice
            .wallet
            .minimum_spend_atomic(&self.fees)
            .unwrap_or(u64::MAX);
        let Some((reference, value)) = self
            .wallets
            .alice
            .tracker
            .first_spendable(next_slot, MATURITY, minimum)
        else {
            return Ok(());
        };
        let half = Amount::from_atomic(value.atomic() / 2);
        let destination = self.wallets.bob.wallet.address();
        let transaction = self
            .wallets
            .alice
            .wallet
            .spend_one(reference, value, destination, half, &self.fees)
            .map_err(Breach::Wallet)?;
        self.submit(&transaction).map_err(Breach::Admission)?;
        Ok(())
    }
}

/// The outcome of a day: the honest report of the network the
/// run held.
pub struct DayOutcome {
    /// The status of the last applied block with its wall clock:
    /// the numbers, the invariant verdicts, the deterministic id.
    pub reported: Reported,
}

/// Runs a day of the development network (ADR-025): `blocks`
/// blocks mined on the best tip, the activity script every
/// `spend_every` blocks, the invariant battery after every block,
/// the periodic checks every five hundred and twelve. The wall
/// clock is read for the report only; nothing of it enters
/// consensus data.
///
/// # Errors
///
/// Returns the first [`Breach`]; the day stops there and the
/// caller reports it.
pub fn run_day(
    blocks: u64,
    difficulty: u32,
    spend_every: u64,
    progress: &mut dyn FnMut(u64),
) -> Result<DayOutcome, Breach> {
    let start = Instant::now();
    let mut engine = Engine::boot(difficulty).map_err(Breach::Store)?;
    for n in 1..=blocks {
        if spend_every > 0 && n % spend_every == 0 {
            engine.activity_miner()?;
        }
        if spend_every > 0 && n % (spend_every * 2) == 0 {
            engine.activity_alice()?;
        }
        engine.mine_and_apply()?;
        progress(n);
        let (_, failures) = crate::invariants::check(&engine, true);
        if let Some(&first) = failures.first() {
            return Err(Breach::Invariant(first));
        }
        if n % 512 == 0 || n == blocks {
            let failures = crate::invariants::periodic(&engine);
            if let Some(&first) = failures.first() {
                return Err(Breach::Invariant(first));
            }
        }
    }
    let reported = Status::of(&engine, start.elapsed());
    Ok(DayOutcome { reported })
}

/// The canonical bytes of the run parameters: what a status id is
/// a function of, for the record.
#[must_use]
pub fn day_parameters(blocks: u64, difficulty: u32, spend_every: u64) -> Hash {
    let mut writer = Writer::new();
    writer.write_u64(blocks);
    writer.write_u32(difficulty);
    writer.write_u64(spend_every);
    antumbra_primitives::keccak256(&writer.finish())
}

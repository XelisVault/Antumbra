//! The mempool: the only road into a block (ADR-025).
//!
//! A transaction becomes a payload entry through admission here,
//! which checks everything checkable before consensus: the
//! container and fee rules of the transaction layer, the signature
//! verification, the existence and unspentness of every input in
//! the ledger and in the mempool itself, the maturity of coinbase
//! outputs, and **the key binding** — an input must claim the
//! spend key of the output's address. The ledger does not check
//! that binding yet (ADR-025 records the gap); the node does,
//! here, and the consensus rule with its vector set is the next
//! rail-C change.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use antumbra_state::coinbase::MATURITY;
use antumbra_state::ledger::Ledger;
use antumbra_tx::{FeeSchedule, OutputRef, Transaction, TxError};

/// Every refusal of an admission, named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmitError {
    /// A container or fee rule of the transaction layer.
    Rule(TxError),
    /// A signature failed verification.
    Signature,
    /// An input is not an unspent output of the ledger.
    UnknownOutput(OutputRef),
    /// An input is already spent by the ledger.
    DoubleSpend(OutputRef),
    /// An input is already claimed by an admitted transaction.
    Claimed(OutputRef),
    /// A coinbase output is not mature at the slot a transaction
    /// would land in.
    Immature {
        /// The output reference refused.
        reference: OutputRef,
        /// The slot of the coinbase that created it.
        creating_slot: u64,
        /// The earliest slot it may be spent at.
        earliest_slot: u64,
    },
    /// The input key is not the spend key of the output's address:
    /// the node-level key binding of ADR-025.
    KeyNotOwner {
        /// The output reference claimed.
        reference: OutputRef,
    },
}

impl core::fmt::Display for AdmitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rule(error) => write!(f, "admission rule: {error}"),
            Self::Signature => write!(f, "a signature failed verification"),
            Self::UnknownOutput(reference) => {
                write!(f, "an input is not an unspent output: {reference:?}")
            }
            Self::DoubleSpend(reference) => {
                write!(f, "an input is already spent: {reference:?}")
            }
            Self::Claimed(reference) => {
                write!(f, "an input is already claimed by an admitted transaction: {reference:?}")
            }
            Self::Immature {
                reference,
                creating_slot,
                earliest_slot,
            } => write!(
                f,
                "a coinbase output created at slot {creating_slot} matures at slot {earliest_slot}: {reference:?}"
            ),
            Self::KeyNotOwner { reference } => write!(
                f,
                "the input key is not the spend key of the output's address: {reference:?}"
            ),
        }
    }
}

impl std::error::Error for AdmitError {}

/// The mempool: admitted transactions by id, and the outputs they
/// claim.
#[derive(Debug, Default)]
pub struct Mempool {
    txs: BTreeMap<antumbra_primitives::Hash, Transaction>,
    claimed: BTreeSet<OutputRef>,
}

impl Mempool {
    /// The empty mempool.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            txs: BTreeMap::new(),
            claimed: BTreeSet::new(),
        }
    }

    /// Admits a transaction against the ledger at the slot a
    /// transaction would land in: every rule named above, in
    /// order. On success the transaction is held and its inputs
    /// are claimed.
    ///
    /// # Errors
    ///
    /// Returns an [`AdmitError`] naming the first violated rule;
    /// the mempool is unchanged.
    pub fn admit(
        &mut self,
        transaction: &Transaction,
        ledger: &Ledger,
        fees: &FeeSchedule,
        next_slot: u64,
    ) -> Result<antumbra_primitives::Hash, AdmitError> {
        transaction.validate(fees).map_err(AdmitError::Rule)?;
        transaction
            .verify_signatures()
            .map_err(|_| AdmitError::Signature)?;
        for input in transaction.inputs() {
            let reference = input.output_ref();
            if self.claimed.contains(&reference) {
                return Err(AdmitError::Claimed(reference));
            }
            if ledger.is_spent(&reference) {
                return Err(AdmitError::DoubleSpend(reference));
            }
            let entry = ledger
                .utxo(&reference)
                .ok_or(AdmitError::UnknownOutput(reference))?;
            if let Some(creating) = entry.coinbase_slot() {
                let earliest = creating + MATURITY;
                if next_slot < earliest {
                    return Err(AdmitError::Immature {
                        reference,
                        creating_slot: creating,
                        earliest_slot: earliest,
                    });
                }
            }
            if input.key().0 != entry.address().spend().0 {
                return Err(AdmitError::KeyNotOwner { reference });
            }
        }
        let id = transaction.tx_id();
        self.txs.insert(id, transaction.clone());
        for input in transaction.inputs() {
            self.claimed.insert(input.output_ref());
        }
        Ok(id)
    }

    /// Takes up to `max` admitted transactions, ascending by id:
    /// the payload order. The claims are released with them.
    pub fn take(&mut self, max: usize) -> Vec<Transaction> {
        let ids: Vec<antumbra_primitives::Hash> = self.txs.keys().copied().take(max).collect();
        let mut taken = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(transaction) = self.txs.remove(&id) {
                for input in transaction.inputs() {
                    self.claimed.remove(&input.output_ref());
                }
                taken.push(transaction);
            }
        }
        taken
    }

    /// The number of admitted transactions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Whether no transaction is admitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// The outputs claimed by admitted transactions.
    #[must_use]
    pub fn claimed(&self) -> Vec<OutputRef> {
        self.claimed.iter().copied().collect()
    }
}

//! The devnet wallets: key ownership, coinbases, and the output
//! trackers (ADR-025).
//!
//! A wallet of the development network is a fixed spend key and a
//! fixed view key under a devnet network byte. It builds the
//! coinbase of ADR-024 exactly as the state layer expects it, and
//! it signs the transfers of the activity script. The tracker
//! beside it is the wallet's own memory of what the ledger pays
//! it: credits on applied outputs, debits on spent inputs, matured
//! coinbase outputs included. The trackers are checked against
//! the ledger snapshot by the invariant battery, so a divergence
//! is a breach, not a silence.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use antumbra_primitives::{Address, Hash, KeyPair, Network};
use antumbra_state::coinbase::{devnet_treasury_address, expected_coinbase};
use antumbra_tx::{Amount, FeeSchedule, OutputRef, Transaction, TxError, TxIn, TxOut, TxType};

/// A devnet wallet: the spend key signs, the view key scans.
pub struct Wallet {
    spend: KeyPair,
    view: KeyPair,
    address: Address,
}

impl Wallet {
    /// A wallet from its two key pairs under a network byte.
    #[must_use]
    pub fn from_keys(spend: KeyPair, view: KeyPair, network: Network) -> Self {
        let address = Address::new(network, spend.public(), view.public());
        Self {
            spend,
            view,
            address,
        }
    }

    /// The address this wallet is paid at.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// The spend key pair: the signing authority.
    #[must_use]
    pub const fn spend(&self) -> &KeyPair {
        &self.spend
    }

    /// The view key pair: the scanning authority.
    #[must_use]
    pub const fn view(&self) -> &KeyPair {
        &self.view
    }

    /// The coinbase of a block at `height` paying the slot `slot`
    /// plus `fees_atomic` (ADR-024): the expected output count, the
    /// treasury share second, the declared height in the extra
    /// field. The treasury address is the consensus constant; the
    /// miner output pays this wallet.
    #[must_use]
    pub fn coinbase(&self, height: u64, slot: u64, fees_atomic: u64) -> Transaction {
        let (outputs, treasury_atomic, total) = expected_coinbase(slot, fees_atomic);
        let total = Amount::from_atomic(total);
        let treasury_atomic = Amount::from_atomic(treasury_atomic);
        let mut payload = Vec::with_capacity(outputs);
        if outputs == 2 {
            // The miner keeps the reward plus the fees minus the
            // treasury share; the share never exceeds the reward.
            let miner_atomic = total
                .checked_sub(treasury_atomic)
                .expect("the treasury share never exceeds the reward plus the fees");
            payload.push(TxOut::new(self.address, miner_atomic));
            payload.push(TxOut::new(devnet_treasury_address(), treasury_atomic));
        } else {
            payload.push(TxOut::new(self.address, total));
        }
        Transaction::new(
            TxType::Coinbase,
            Amount::ZERO,
            Vec::new(),
            payload,
            height.to_le_bytes().to_vec(),
        )
    }

    /// The smallest output value a one-input, two-output spend of
    /// this wallet can pay with: twice the schedule minimum fee,
    /// the worst split of the activity script (half out, half
    /// change, the fee on top). Outputs below it are dust: honest
    /// residue, never a breach.
    #[must_use]
    pub fn minimum_spend_atomic(&self, fees: &FeeSchedule) -> Option<u64> {
        let draft = Transaction::new(
            TxType::Transfer,
            Amount::ZERO,
            vec![TxIn::unsigned(
                OutputRef::new(Hash::ZERO, 0),
                self.spend.public(),
            )],
            vec![
                TxOut::new(self.address, Amount::ZERO),
                TxOut::new(self.address, Amount::ZERO),
            ],
            Vec::new(),
        );
        fees.minimum_fee(draft.encode().len(), 0)
            .map(|fee| 2 * fee.atomic())
    }

    /// A one-input, two-output transfer: `to_amount` to the
    /// destination, the rest of `value` minus the schedule minimum
    /// fee back to this wallet. The fee is computed to a fixed
    /// point over the encoded size, so a varint fee cannot shift
    /// the size it is computed from.
    ///
    /// # Errors
    ///
    /// Returns a [`SpendError`] when the minimum fee is not
    /// computable, when the value cannot cover the payment and the
    /// fee, or when signing fails.
    pub fn spend_one(
        &self,
        source: OutputRef,
        value: Amount,
        destination: Address,
        to_amount: Amount,
        fees: &FeeSchedule,
    ) -> Result<Transaction, SpendError> {
        let input = TxIn::unsigned(source, self.spend.public());
        // The draft fixes the byte size: the fee field and the
        // amounts are fixed-width, so the size does not move when
        // the fee is set.
        let draft = Transaction::new(
            TxType::Transfer,
            Amount::ZERO,
            vec![TxIn::unsigned(source, self.spend.public())],
            vec![
                TxOut::new(destination, to_amount),
                TxOut::new(self.address, Amount::ZERO),
            ],
            Vec::new(),
        );
        let mut fee = Amount::ZERO;
        for _ in 0..4 {
            let minimum = fees
                .minimum_fee(draft.encode().len(), 0)
                .ok_or(SpendError::FeeNotComputable)?;
            if fee == minimum {
                break;
            }
            fee = minimum;
        }
        let change = value
            .checked_sub(to_amount)
            .and_then(|rest| rest.checked_sub(fee))
            .ok_or(SpendError::InsufficientValue)?;
        let mut transaction = Transaction::new(
            TxType::Transfer,
            fee,
            vec![input],
            vec![
                TxOut::new(destination, to_amount),
                TxOut::new(self.address, change),
            ],
            Vec::new(),
        );
        transaction
            .sign(core::slice::from_ref(&self.spend))
            .map_err(SpendError::Signing)?;
        Ok(transaction)
    }
}

/// Every refusal of a wallet construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpendError {
    /// The schedule could not express a minimum fee.
    FeeNotComputable,
    /// The value cannot cover the payment and the fee.
    InsufficientValue,
    /// The signing failed: a transaction-layer rule.
    Signing(TxError),
}

impl core::fmt::Display for SpendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FeeNotComputable => write!(f, "the minimum fee is not computable"),
            Self::InsufficientValue => write!(f, "the value cannot cover the payment and the fee"),
            Self::Signing(error) => write!(f, "signing: {error}"),
        }
    }
}

impl std::error::Error for SpendError {}

/// The wallet's own memory of its outputs: what the ledger pays it
/// and what it has spent, in credit order. The activity script
/// spends the **oldest** spendable output — the design of ADR-025
/// — which keeps the script honest forever: the oldest output of
/// a growing pool is a full coinbase, not a decayed change.
#[derive(Debug, Default)]
pub struct Tracker {
    /// The credited outputs, by credit order: the order the
    /// ledger applied them.
    credits: BTreeMap<u64, Credited>,
    /// The reference of a credit, by output reference.
    by_reference: BTreeMap<OutputRef, u64>,
    /// The next credit order.
    next_order: u64,
}

/// One credited output of the tracker.
#[derive(Clone, Debug)]
struct Credited {
    reference: OutputRef,
    amount: Amount,
    coinbase_slot: Option<u64>,
    spent: bool,
}

impl Tracker {
    /// The empty tracker: nothing credited yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            credits: BTreeMap::new(),
            by_reference: BTreeMap::new(),
            next_order: 0,
        }
    }

    /// Credits an output: its reference, its amount, and the slot
    /// of the coinbase that created it, if it did. Credits are
    /// ordered by the ledger's application order.
    pub fn credit(&mut self, reference: OutputRef, amount: Amount, coinbase_slot: Option<u64>) {
        if self.by_reference.contains_key(&reference) {
            // A replayed credit after a rebuild: the reset cleared
            // the tracker, so this cannot happen; a duplicate
            // output reference is a ledger fault that never
            // reaches the tracker.
            return;
        }
        let order = self.next_order;
        self.next_order += 1;
        self.credits.insert(
            order,
            Credited {
                reference,
                amount,
                coinbase_slot,
                spent: false,
            },
        );
        self.by_reference.insert(reference, order);
    }

    /// Debits a reference: the wallet spent it, if it ever held
    /// it.
    pub fn debit(&mut self, reference: OutputRef) {
        if let Some(order) = self.by_reference.get(&reference) {
            if let Some(credited) = self.credits.get_mut(order) {
                credited.spent = true;
            }
        }
    }

    /// The oldest unspent entry worth spending — at least
    /// `minimum_atomic` — whose coinbase maturity is satisfied at
    /// the slot a transaction would land in: the deterministic
    /// choice of the activity script. Outputs below the minimum
    /// are dust and stay unspent.
    #[must_use]
    pub fn first_spendable(
        &self,
        next_slot: u64,
        maturity: u64,
        minimum_atomic: u64,
    ) -> Option<(OutputRef, Amount)> {
        self.credits
            .values()
            .find(|credited| {
                !credited.spent
                    && credited.amount.atomic() >= minimum_atomic
                    && match credited.coinbase_slot {
                        Some(creating) => next_slot >= creating + maturity,
                        None => true,
                    }
            })
            .map(|credited| (credited.reference, credited.amount))
    }

    /// The unspent references of the tracker, ascending.
    #[must_use]
    pub fn unspent(&self) -> BTreeSet<OutputRef> {
        self.credits
            .values()
            .filter(|credited| !credited.spent)
            .map(|credited| credited.reference)
            .collect()
    }

    /// The unspent entries with their creating coinbase slots,
    /// in credit order: the deterministic inventory the tests and
    /// the invariant battery read.
    #[must_use]
    pub fn unspent_with_slot(&self) -> Vec<(OutputRef, Amount, Option<u64>)> {
        self.credits
            .values()
            .filter(|credited| !credited.spent)
            .map(|credited| (credited.reference, credited.amount, credited.coinbase_slot))
            .collect()
    }

    /// The balance of the unspent entries, in atomic units.
    #[must_use]
    pub fn unspent_atomic(&self) -> u64 {
        self.credits
            .values()
            .filter(|credited| !credited.spent)
            .map(|credited| credited.amount.atomic())
            .fold(0, u64::saturating_add)
    }
}

/// A wallet and its tracker: the pair the engine moves together.
pub struct TrackedWallet {
    /// The keys and the address.
    pub wallet: Wallet,
    /// The credited and spent outputs.
    pub tracker: Tracker,
}

impl TrackedWallet {
    /// A wallet with an empty tracker.
    #[must_use]
    pub fn new(wallet: Wallet) -> Self {
        Self {
            wallet,
            tracker: Tracker::new(),
        }
    }

    /// Credits an output paid to this wallet's address.
    pub fn credit(&mut self, reference: OutputRef, amount: Amount, coinbase_slot: Option<u64>) {
        self.tracker.credit(reference, amount, coinbase_slot);
    }

    /// Debits a reference on every wallet: a no-op where it was
    /// never credited.
    pub fn debit(&mut self, reference: OutputRef) {
        self.tracker.debit(reference);
    }
}

/// Hashes a tracker's unspent set for comparisons: the references
/// alone, since the amounts follow from the ledger.
#[must_use]
pub fn unspent_hash(tracker: &Tracker) -> Hash {
    let mut writer = antumbra_primitives::Writer::new();
    for reference in tracker.unspent() {
        writer.write_array(reference.tx().as_bytes());
        writer.write_u32(reference.index());
    }
    antumbra_primitives::keccak256(&writer.finish())
}

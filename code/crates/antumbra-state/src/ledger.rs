//! The UTXO ledger: the state rules the ordering layer defers
//! (ADR-013), under the emission transaction (ADR-024) and the key
//! binding (ADR-026).
//!
//! The ledger consumes the consensus order of a tip and the
//! payloads of its blocks, and applies its rules, in order:
//! existence (a referenced output was created), unspentness (no
//! output is spent twice — the first spender of the total order
//! wins), the key binding (the key an input claims is the spend
//! key of the output's address — a theft is rejected, signature or
//! no signature), maturity (a coinbase output spends `MATURITY`
//! slots after its slot), and conservation (a transaction's inputs
//! equal its outputs plus its fee; a coinbase's outputs equal the
//! reward of the slot plus the fees of its block). Every rule is
//! enforced on a block before any mutation: a rejected block leaves
//! the ledger exactly where it was.
//!
//! The reference rebuild is total: a reorganization rebuilds from
//! the winning order, deterministically, like the reference DAG
//! rebuilds from its closures. Incremental application is the same
//! code on the same inputs: `apply_block` per block of the order,
//! in order.

use std::collections::{BTreeMap, BTreeSet};

use antumbra_primitives::{Address, Hash};
use antumbra_tx::{Amount, OutputRef, Transaction, TxType};

use crate::coinbase::{devnet_treasury_address, expected_coinbase, reward_of_slot, MATURITY};

/// One unspent output of the ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    address: Address,
    amount: Amount,
    /// The slot of the coinbase that created this output, when it
    /// did: `None` for the outputs of ordinary transactions. A
    /// coinbase output matures `MATURITY` slots after its creation.
    coinbase_slot: Option<u64>,
}

impl Entry {
    /// The address this output pays to.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// The amount this output carries.
    #[must_use]
    pub const fn amount(&self) -> Amount {
        self.amount
    }

    /// The creating coinbase slot, when this output is a coinbase
    /// output.
    #[must_use]
    pub const fn coinbase_slot(&self) -> Option<u64> {
        self.coinbase_slot
    }
}

/// The payload of one block of the order, as the ledger sees it:
/// the height of the block and its transactions, sorted by
/// ascending transaction id.
#[derive(Clone, Debug)]
pub struct BlockPayload {
    /// The height of the containing block.
    pub height: u64,
    /// The transactions of the payload, ascending by id.
    pub txs: Vec<Transaction>,
}

/// The ledger: unspent outputs, spent references, totals.
#[derive(Debug, Default)]
pub struct Ledger {
    utxos: BTreeMap<OutputRef, Entry>,
    spent: BTreeSet<OutputRef>,
    /// The slots applied so far, the genesis (slot 0) included.
    applied: u64,
    /// Total value ever created, coinbases included.
    created: u64,
    /// Total value ever consumed by inputs.
    spent_value: u64,
    /// Total emission (the rewards, not the recycled fees).
    emitted: u64,
}

impl Ledger {
    /// The empty ledger: the state before the genesis.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            utxos: BTreeMap::new(),
            spent: BTreeSet::new(),
            applied: 0,
            created: 0,
            spent_value: 0,
            emitted: 0,
        }
    }

    /// Applies an entire consensus order: the genesis first, then
    /// every block at its slot. `fetch` resolves a block id into
    /// its height and its sorted payload; a `None` is a missing
    /// payload, a fault of the caller.
    ///
    /// The first id of the order must be the genesis (height zero,
    /// empty payload). On any rejection the ledger stands at the
    /// state of the last accepted block, and the error names the
    /// violated rule.
    ///
    /// # Errors
    ///
    /// Returns a [`StateError`] naming the violated rule.
    pub fn apply_order(
        &mut self,
        order: &[Hash],
        fetch: &mut dyn FnMut(&Hash) -> Option<BlockPayload>,
    ) -> Result<(), StateError> {
        let mut first = true;
        for id in order {
            let payload = fetch(id).ok_or(StateError::MissingPayload(*id))?;
            if first {
                first = false;
                if payload.height != 0 {
                    return Err(StateError::NotGenesis(payload.height));
                }
                if !payload.txs.is_empty() {
                    return Err(StateError::GenesisPayload(payload.txs.len()));
                }
                self.applied = 1;
                continue;
            }
            self.apply_block(payload.height, &payload.txs)?;
        }
        Ok(())
    }

    /// Applies one block at the next slot, atomically: every rule
    /// is checked before any mutation.
    ///
    /// # Errors
    ///
    /// Returns a [`StateError`] naming the violated rule; the
    /// ledger is unchanged.
    pub fn apply_block(&mut self, height: u64, txs: &[Transaction]) -> Result<(), StateError> {
        let slot = self.applied;
        let scratch = self.validate_block(slot, height, txs)?;
        self.commit_block(scratch, txs);
        Ok(())
    }

    /// The pure phase: every rule over a scratch overlay, no
    /// mutation of the ledger.
    fn validate_block(
        &self,
        slot: u64,
        height: u64,
        txs: &[Transaction],
    ) -> Result<Scratch, StateError> {
        let mut scratch = Scratch::default();

        // The payload is sorted by ascending transaction id.
        for pair in txs.windows(2) {
            if pair[0].tx_id() >= pair[1].tx_id() {
                return Err(StateError::UnsortedPayload);
            }
        }

        // A height-zero block is the genesis by construction of the
        // order: it carries nothing.
        if height == 0 {
            if !txs.is_empty() {
                return Err(StateError::GenesisPayload(txs.len()));
            }
            return Ok(scratch);
        }

        // Exactly one coinbase per block.
        let coinbases = txs
            .iter()
            .filter(|t| t.tx_type() == TxType::Coinbase)
            .count();
        if coinbases != 1 {
            return Err(StateError::CoinbaseCount(coinbases));
        }

        // The fees of the block: the coinbase claims them all.
        let mut fees = 0u64;
        for tx in txs {
            if tx.tx_type() != TxType::Coinbase {
                fees = fees
                    .checked_add(tx.fee().atomic())
                    .ok_or(StateError::Overflow)?;
            }
        }

        for tx in txs {
            if tx.tx_type() == TxType::Coinbase {
                self.validate_coinbase(tx, slot, height, fees)?;
            } else {
                self.validate_transfer(tx, slot, &mut scratch)?;
            }
        }
        Ok(scratch)
    }

    /// The coinbase rules of ADR-024, state side: the height
    /// binding, the treasury shape, the value.
    fn validate_coinbase(
        &self,
        tx: &Transaction,
        slot: u64,
        height: u64,
        fees: u64,
    ) -> Result<(), StateError> {
        // The container rules, re-checked: the ledger does not
        // trust the transaction layer's verdict.
        if !tx.inputs().is_empty() {
            return Err(StateError::CoinbaseInputs(tx.inputs().len()));
        }
        if !tx.fee().is_zero() {
            return Err(StateError::CoinbaseFee);
        }
        let extra = tx.extra();
        if extra.len() != 8 {
            return Err(StateError::CoinbaseExtra(extra.len()));
        }
        let declared = u64::from_le_bytes([
            extra[0], extra[1], extra[2], extra[3], extra[4], extra[5], extra[6], extra[7],
        ]);
        if declared != height {
            return Err(StateError::CoinbaseHeight {
                declared,
                block: height,
            });
        }

        let (expected_count, expected_treasury, expected_total) = expected_coinbase(slot, fees);
        let outputs = tx.outputs();
        if outputs.len() != expected_count {
            return Err(StateError::CoinbaseOutputs {
                expected: expected_count,
                found: outputs.len(),
            });
        }
        let found_total = outputs
            .iter()
            .map(|o| o.amount().atomic())
            .try_fold(0u64, |acc, v| acc.checked_add(v))
            .ok_or(StateError::Overflow)?;
        if found_total != expected_total {
            return Err(StateError::CoinbaseValue {
                expected: expected_total,
                found: found_total,
            });
        }
        if expected_count == 2 {
            let treasury = &outputs[1];
            if treasury.address() != devnet_treasury_address() {
                return Err(StateError::CoinbaseTreasuryAddress);
            }
            if treasury.amount().atomic() != expected_treasury {
                return Err(StateError::CoinbaseTreasuryShare {
                    expected: expected_treasury,
                    found: treasury.amount().atomic(),
                });
            }
        }
        Ok(())
    }

    /// The transfer rules: existence, unspentness, maturity,
    /// conservation, resolved over the ledger and the scratch of
    /// the block being validated.
    fn validate_transfer(
        &self,
        tx: &Transaction,
        slot: u64,
        scratch: &mut Scratch,
    ) -> Result<(), StateError> {
        if tx.inputs().is_empty() {
            return Err(StateError::NoInputs);
        }

        let mut input_value = 0u64;
        for input in tx.inputs() {
            let reference = input.output_ref();
            // Existence: the ledger, or an earlier transaction of
            // the same block, created it.
            let entry = match (
                self.utxos.get(&reference),
                scratch.new_outputs.get(&reference),
            ) {
                (Some(e), _) => e,
                (None, Some(e)) => e,
                (None, None) => {
                    if self.spent.contains(&reference) || scratch.spent.contains(&reference) {
                        return Err(StateError::DoubleSpend(reference));
                    }
                    return Err(StateError::UnknownOutput(reference));
                }
            };
            // Unspentness inside the block.
            if scratch.spent.contains(&reference) {
                return Err(StateError::DoubleSpend(reference));
            }
            // The key binding (ADR-026): the claimed key must be
            // the spend key of the output's address. Existence and
            // unspentness first, ownership before the clock: a
            // reference both unbound and immature reports the
            // binding, so the reject names stay stable.
            if entry.address().spend() != input.key() {
                return Err(StateError::KeyNotBound(reference));
            }
            // Maturity: a coinbase output spends `MATURITY` slots
            // after its creating slot.
            if let Some(creating) = entry.coinbase_slot {
                if slot < creating + MATURITY {
                    return Err(StateError::ImmatureCoinbase {
                        reference,
                        creating_slot: creating,
                        slot,
                    });
                }
            }
            input_value = input_value
                .checked_add(entry.amount().atomic())
                .ok_or(StateError::Overflow)?;
            scratch.spent.insert(reference);
        }

        let mut output_value = tx.fee().atomic();
        for output in tx.outputs() {
            output_value = output_value
                .checked_add(output.amount().atomic())
                .ok_or(StateError::Overflow)?;
        }
        if input_value != output_value {
            return Err(StateError::Conservation {
                expected: input_value,
                found: output_value,
            });
        }
        scratch.spent_value = scratch
            .spent_value
            .checked_add(input_value)
            .ok_or(StateError::Overflow)?;

        // Register the new outputs in the scratch: same-block
        // chaining sees them, the commit moves them home.
        let tx_id = tx.tx_id();
        for (index, output) in tx.outputs().iter().enumerate() {
            let reference = OutputRef::new(tx_id, index as u32);
            if self.utxos.contains_key(&reference)
                || scratch.new_outputs.contains_key(&reference)
                || self.spent.contains(&reference)
            {
                // A collision with an existing output reference:
                // the block is invalid.
                return Err(StateError::OutputCollision(reference));
            }
            scratch.new_outputs.insert(
                reference,
                Entry {
                    address: output.address(),
                    amount: output.amount(),
                    coinbase_slot: None,
                },
            );
        }
        Ok(())
    }

    /// The mutation phase: the scratch becomes the ledger. Every
    /// rule has passed; nothing can fail here.
    fn commit_block(&mut self, scratch: Scratch, txs: &[Transaction]) {
        for tx in txs {
            let tx_id = tx.tx_id();
            for (index, output) in tx.outputs().iter().enumerate() {
                self.utxos.insert(
                    OutputRef::new(tx_id, index as u32),
                    Entry {
                        address: output.address(),
                        amount: output.amount(),
                        coinbase_slot: (tx.tx_type() == TxType::Coinbase).then_some(self.applied),
                    },
                );
                self.created = self.created.saturating_add(output.amount().atomic());
            }
            if tx.tx_type() == TxType::Coinbase {
                let reward = reward_of_slot(self.applied);
                self.emitted = self.emitted.saturating_add(reward);
            }
        }
        for reference in scratch.spent {
            self.utxos.remove(&reference);
            self.spent.insert(reference);
        }
        self.spent_value = self.spent_value.saturating_add(scratch.spent_value);
        self.applied += 1;
    }

    /// The unspent output a reference resolves to, if any.
    #[must_use]
    pub fn utxo(&self, reference: &OutputRef) -> Option<&Entry> {
        self.utxos.get(reference)
    }

    /// Whether the reference was spent in the applied history.
    #[must_use]
    pub fn is_spent(&self, reference: &OutputRef) -> bool {
        self.spent.contains(reference)
    }

    /// The number of applied slots, the genesis included.
    #[must_use]
    pub const fn applied(&self) -> u64 {
        self.applied
    }

    /// The total value ever created, in atomic units.
    #[must_use]
    pub const fn created(&self) -> u64 {
        self.created
    }

    /// The total value ever consumed by inputs, in atomic units.
    #[must_use]
    pub const fn spent_value(&self) -> u64 {
        self.spent_value
    }

    /// The total emission so far: the rewards, not the recycled
    /// fees.
    #[must_use]
    pub const fn emitted(&self) -> u64 {
        self.emitted
    }

    /// The number of unspent outputs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// Whether the ledger holds no unspent output.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// The conservation invariant: everything created equals
    /// everything spent plus everything emitted.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::Conservation`] when the identity
    /// fails: a consensus fault.
    pub fn check_conservation(&self) -> Result<(), StateError> {
        if self.created == self.spent_value + self.emitted {
            Ok(())
        } else {
            Err(StateError::Conservation {
                expected: self.created,
                found: self.spent_value.saturating_add(self.emitted),
            })
        }
    }

    /// Every unspent output, ascending by reference: the snapshot
    /// the cross vectors compare.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(OutputRef, Entry)> {
        self.utxos.iter().map(|(r, e)| (*r, e.clone())).collect()
    }
}

/// The overlay of the block being validated: the outputs created
/// and the references spent inside the block, invisible to the
/// ledger until the commit.
#[derive(Default)]
struct Scratch {
    new_outputs: BTreeMap<OutputRef, Entry>,
    spent: BTreeSet<OutputRef>,
    spent_value: u64,
}

/// Formats an output reference as `tx:index`.
fn reference_text(reference: &OutputRef) -> String {
    format!("{}:{}", reference.tx(), reference.index())
}

/// Every rule the ledger enforces, named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateError {
    /// The fetch of a block id returned no payload.
    MissingPayload(Hash),
    /// The first block of the order is not the genesis.
    NotGenesis(u64),
    /// The genesis (or a height-zero block) carries transactions.
    GenesisPayload(usize),
    /// The payload is not sorted by ascending transaction id.
    UnsortedPayload,
    /// The block does not carry exactly one coinbase.
    CoinbaseCount(usize),
    /// The coinbase carries inputs.
    CoinbaseInputs(usize),
    /// The coinbase declares a non-zero fee.
    CoinbaseFee,
    /// The extra field of the coinbase is not the eight-byte
    /// height.
    CoinbaseExtra(usize),
    /// The height the coinbase declares is not its block's height.
    CoinbaseHeight { declared: u64, block: u64 },
    /// The coinbase output count does not match the era: two
    /// during the treasury eclipses, one after.
    CoinbaseOutputs { expected: usize, found: usize },
    /// The coinbase value is not the reward plus the fees.
    CoinbaseValue { expected: u64, found: u64 },
    /// The treasury output does not pay the treasury address.
    CoinbaseTreasuryAddress,
    /// The treasury output is not the archived share.
    CoinbaseTreasuryShare { expected: u64, found: u64 },
    /// A transaction carries no input.
    NoInputs,
    /// A referenced output was never created.
    UnknownOutput(OutputRef),
    /// A referenced output is already spent: the first spender of
    /// the order wins.
    DoubleSpend(OutputRef),
    /// The claimed key is not the spend key of the spent output's
    /// address: a theft, signature or no signature (ADR-026).
    KeyNotBound(OutputRef),
    /// A coinbase output spent before maturity.
    ImmatureCoinbase {
        reference: OutputRef,
        creating_slot: u64,
        slot: u64,
    },
    /// A transaction does not conserve value.
    Conservation { expected: u64, found: u64 },
    /// An output reference collides with an existing one.
    OutputCollision(OutputRef),
    /// A checked addition overflowed: the amounts are protocol
    /// nonsense.
    Overflow,
}

impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingPayload(id) => write!(f, "no payload for block {id}"),
            Self::NotGenesis(h) => {
                write!(f, "the first block of the order has height {h}, not zero")
            }
            Self::GenesisPayload(n) => write!(f, "the genesis carries {n} transactions"),
            Self::UnsortedPayload => {
                write!(f, "the payload is not sorted by ascending transaction id")
            }
            Self::CoinbaseCount(n) => write!(f, "a block carries exactly one coinbase, found {n}"),
            Self::CoinbaseInputs(n) => write!(f, "the coinbase carries {n} inputs"),
            Self::CoinbaseFee => write!(f, "the coinbase declares a non-zero fee"),
            Self::CoinbaseExtra(n) => write!(
                f,
                "the extra field of the coinbase is the 8-byte height, found {n} bytes"
            ),
            Self::CoinbaseHeight { declared, block } => write!(
                f,
                "the coinbase declares height {declared} inside block {block}"
            ),
            Self::CoinbaseOutputs { expected, found } => write!(
                f,
                "the coinbase of this era carries {expected} outputs, found {found}"
            ),
            Self::CoinbaseValue { expected, found } => write!(
                f,
                "the coinbase pays {found} atomic, the reward plus fees are {expected}"
            ),
            Self::CoinbaseTreasuryAddress => {
                write!(f, "the treasury output does not pay the treasury address")
            }
            Self::CoinbaseTreasuryShare { expected, found } => write!(
                f,
                "the treasury output pays {found} atomic, the share is {expected}"
            ),
            Self::NoInputs => write!(f, "a transaction carries no input"),
            Self::UnknownOutput(reference) => {
                write!(f, "{} was never created", reference_text(reference))
            }
            Self::DoubleSpend(reference) => write!(
                f,
                "{} is already spent: the first spender of the order wins",
                reference_text(reference)
            ),
            Self::KeyNotBound(reference) => write!(
                f,
                "{} is claimed by a key that is not the spend key of its address",
                reference_text(reference)
            ),
            Self::ImmatureCoinbase {
                reference,
                creating_slot,
                slot,
            } => write!(
                f,
                "{} of coinbase slot {creating_slot} is spent at slot {slot}, before maturity {MATURITY}",
                reference_text(reference)
            ),
            Self::Conservation { expected, found } => write!(
                f,
                "the transaction consumes {expected} atomic and creates {found}"
            ),
            Self::OutputCollision(reference) => {
                write!(f, "{} collides with an existing output", reference_text(reference))
            }
            Self::Overflow => write!(f, "an amount addition overflowed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coinbase::{reward_of_slot, treasury_share_of};

    #[test]
    fn the_empty_ledger_conserves() {
        let ledger = Ledger::new();
        assert!(ledger.check_conservation().is_ok());
        assert!(ledger.is_empty());
        assert_eq!(ledger.applied(), 0);
    }

    #[test]
    fn display_names_every_rule() {
        let reference = OutputRef::new(Hash([7u8; 32]), 3);
        let errors = vec![
            StateError::MissingPayload(Hash([1u8; 32])),
            StateError::NotGenesis(4),
            StateError::GenesisPayload(2),
            StateError::UnsortedPayload,
            StateError::CoinbaseCount(0),
            StateError::CoinbaseInputs(1),
            StateError::CoinbaseFee,
            StateError::CoinbaseExtra(9),
            StateError::CoinbaseHeight {
                declared: 5,
                block: 6,
            },
            StateError::CoinbaseOutputs {
                expected: 2,
                found: 1,
            },
            StateError::CoinbaseValue {
                expected: 10,
                found: 9,
            },
            StateError::CoinbaseTreasuryAddress,
            StateError::CoinbaseTreasuryShare {
                expected: 6,
                found: 5,
            },
            StateError::NoInputs,
            StateError::UnknownOutput(reference),
            StateError::DoubleSpend(reference),
            StateError::KeyNotBound(reference),
            StateError::ImmatureCoinbase {
                reference,
                creating_slot: 1,
                slot: 5,
            },
            StateError::Conservation {
                expected: 10,
                found: 11,
            },
            StateError::OutputCollision(reference),
            StateError::Overflow,
        ];
        for error in &errors {
            let text = error.to_string();
            assert!(!text.is_empty(), "{error:?} has no text");
            assert!(!text.contains('{'), "{error:?} leaks debug braces: {text}");
        }
    }

    #[test]
    fn the_treasury_share_rounds_down() {
        // 6.18% of 9,792,158 atomic, rounded down.
        assert_eq!(treasury_share_of(9_792_158), 605_155);
        assert_eq!(treasury_share_of(10_000), 618);
        assert_eq!(treasury_share_of(0), 0);
        assert_eq!(reward_of_slot(1), 9_792_158);
    }

    #[test]
    fn a_reference_formats_as_tx_colon_index() {
        let reference = OutputRef::new(Hash([7u8; 32]), 3);
        assert_eq!(reference_text(&reference), format!("{}:3", Hash([7u8; 32])));
    }

    #[test]
    fn a_theft_is_rejected_before_the_clock_and_after_maturity() {
        use antumbra_primitives::{KeyPair, Network};
        use antumbra_tx::{TxIn, TxOut};

        fn coinbase_of(slot: u64, height: u64, payee: Address) -> Transaction {
            let (_, treasury, total) = expected_coinbase(slot, 0);
            Transaction::new(
                TxType::Coinbase,
                Amount::ZERO,
                Vec::new(),
                vec![
                    TxOut::new(payee, Amount::from_atomic(total - treasury)),
                    TxOut::new(devnet_treasury_address(), Amount::from_atomic(treasury)),
                ],
                height.to_le_bytes().to_vec(),
            )
        }

        // A miner, an owner paid by transfer, and a thief: distinct
        // seeds, distinct spend keys.
        let miner_spend = KeyPair::from_seed(&[1u8; 32]);
        let miner_view = KeyPair::from_seed(&[2u8; 32]);
        let miner_address =
            Address::new(Network::Devnet, miner_spend.public(), miner_view.public());
        let owner_spend = KeyPair::from_seed(&[3u8; 32]);
        let owner_view = KeyPair::from_seed(&[4u8; 32]);
        let owner_address =
            Address::new(Network::Devnet, owner_spend.public(), owner_view.public());
        let thief_spend = KeyPair::from_seed(&[5u8; 32]);
        let thief_view = KeyPair::from_seed(&[6u8; 32]);
        let thief_address =
            Address::new(Network::Devnet, thief_spend.public(), thief_view.public());
        assert_ne!(owner_spend.public(), thief_spend.public());

        let mut ledger = Ledger::new();
        ledger.apply_block(0, &[]).expect("the genesis is empty");

        // The coinbase of slot 1: the value and the treasury split
        // exactly as the calendar computes them.
        let (count, _treasury, _total) = expected_coinbase(1, 0);
        assert_eq!(count, 2);
        let coinbase = coinbase_of(1, 1, miner_address);
        ledger
            .apply_block(1, std::slice::from_ref(&coinbase))
            .expect("the coinbase applies");
        let miner_output = OutputRef::new(coinbase.tx_id(), 0);
        let miner_value = ledger
            .utxo(&miner_output)
            .expect("the miner output exists")
            .amount();

        // A coinbase-only chain to slot 11: the miner output of
        // slot 1 is mature from slot 11 on.
        let mut height: u64 = 1;
        while ledger.applied() < 1 + MATURITY {
            height += 1;
            let slot = ledger.applied();
            ledger
                .apply_block(height, &[coinbase_of(slot, height, miner_address)])
                .expect("the chain mines");
        }

        // The theft: the thief claims the miner's output with the
        // thief's key. The output is mature; the conservation is
        // exact; the signature would verify (the state layer never
        // looks). Only the binding can refuse it.
        let theft = Transaction::new(
            TxType::Transfer,
            Amount::ZERO,
            vec![TxIn::unsigned(miner_output, thief_spend.public())],
            vec![TxOut::new(thief_address, miner_value)],
            Vec::new(),
        );
        let mut payload = vec![
            coinbase_of(ledger.applied(), height + 1, miner_address),
            theft,
        ];
        payload.sort_by_key(Transaction::tx_id);
        let before = ledger.snapshot();
        match ledger.apply_block(height + 1, &payload) {
            Err(StateError::KeyNotBound(reference)) => assert_eq!(reference, miner_output),
            other => panic!("the theft must be refused, found {other:?}"),
        }
        assert_eq!(
            ledger.snapshot(),
            before,
            "the refused theft leaves the ledger where it stood"
        );

        // The honest spend of the same output applies.
        let honest = Transaction::new(
            TxType::Transfer,
            Amount::ZERO,
            vec![TxIn::unsigned(miner_output, miner_spend.public())],
            vec![TxOut::new(owner_address, miner_value)],
            Vec::new(),
        );
        let mut payload = vec![
            coinbase_of(ledger.applied(), height + 1, miner_address),
            honest,
        ];
        payload.sort_by_key(Transaction::tx_id);
        ledger
            .apply_block(height + 1, &payload)
            .expect("the honest spend applies");
        assert!(ledger.is_spent(&miner_output));
    }

    #[test]
    fn an_unbound_and_immature_reference_reports_the_binding() {
        use antumbra_primitives::{KeyPair, Network};
        use antumbra_tx::{TxIn, TxOut};

        // The rule order of ADR-026: existence, unspentness,
        // ownership, maturity. A reference both unbound and
        // immature names the binding, not the clock.
        let owner_spend = KeyPair::from_seed(&[7u8; 32]);
        let owner_address = Address::new(
            Network::Devnet,
            owner_spend.public(),
            KeyPair::from_seed(&[8u8; 32]).public(),
        );
        let thief_spend = KeyPair::from_seed(&[9u8; 32]);

        fn coinbase_of(slot: u64, height: u64, payee: Address) -> Transaction {
            let (_, treasury, total) = expected_coinbase(slot, 0);
            Transaction::new(
                TxType::Coinbase,
                Amount::ZERO,
                Vec::new(),
                vec![
                    TxOut::new(payee, Amount::from_atomic(total - treasury)),
                    TxOut::new(devnet_treasury_address(), Amount::from_atomic(treasury)),
                ],
                height.to_le_bytes().to_vec(),
            )
        }

        let mut ledger = Ledger::new();
        ledger.apply_block(0, &[]).expect("the genesis is empty");
        let (count, _treasury, _total) = expected_coinbase(1, 0);
        assert_eq!(count, 2);
        let coinbase = coinbase_of(1, 1, owner_address);
        ledger
            .apply_block(1, std::slice::from_ref(&coinbase))
            .expect("the coinbase applies");
        let reference = OutputRef::new(coinbase.tx_id(), 0);
        let value = ledger.utxo(&reference).expect("the output exists").amount();

        // Slot 2: the coinbase of slot 1 is immature (matures at
        // 11), and the key is the thief's: the binding fires.
        let theft = Transaction::new(
            TxType::Transfer,
            Amount::ZERO,
            vec![TxIn::unsigned(reference, thief_spend.public())],
            vec![TxOut::new(
                Address::new(
                    Network::Devnet,
                    thief_spend.public(),
                    KeyPair::from_seed(&[10u8; 32]).public(),
                ),
                value,
            )],
            Vec::new(),
        );
        let mut payload = vec![coinbase_of(2, 2, owner_address), theft];
        payload.sort_by_key(Transaction::tx_id);
        match ledger.apply_block(2, &payload) {
            Err(StateError::KeyNotBound(bound)) => assert_eq!(bound, reference),
            other => panic!("the binding fires before the clock, found {other:?}"),
        }

        // The same reference, honestly keyed, immature: the clock
        // fires — the binding passed.
        let early = Transaction::new(
            TxType::Transfer,
            Amount::ZERO,
            vec![TxIn::unsigned(reference, owner_spend.public())],
            vec![TxOut::new(owner_address, value)],
            Vec::new(),
        );
        let mut payload = vec![coinbase_of(2, 2, owner_address), early];
        payload.sort_by_key(Transaction::tx_id);
        match ledger.apply_block(2, &payload) {
            Err(StateError::ImmatureCoinbase {
                creating_slot: 1, ..
            }) => {}
            other => panic!("the immature spend must still be refused, found {other:?}"),
        }
    }
}

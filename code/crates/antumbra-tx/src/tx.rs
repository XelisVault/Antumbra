//! Version 1 transactions: the container and its transparent
//! scaffold (ADR-010).
//!
//! The canonical encoding is the single serialized form of a
//! transaction:
//!
//! ```text
//! version:u16 LE | type tag:u8 | fee:u64 LE
//! | input count:varint | input*
//! | output count:varint | output*
//! | extra:varint-length-prefixed bytes
//!
//! input    := tx hash:32B | index:u32 LE | key:32B | signature:64B
//! output   := address:69B raw | amount:u64 LE
//! ```
//!
//! Inputs are strictly ascending by (transaction hash, index): the
//! encoding is unique, transaction ids are non-malleable, and a
//! relay cannot manufacture a new id by reordering. The transaction
//! id is Keccak-256 of the signed encoding. Signatures cover the
//! encoding with all signatures zeroed: a fee, an output or a
//! reference cannot change without breaking every signature.

use antumbra_primitives::keys::verify as verify_ed25519;
use antumbra_primitives::{
    keccak256, Address, Hash, KeyPair, PublicKey, Reader, Signature, Writer,
};

use crate::amount::Amount;
use crate::error::TxError;
use crate::fee::FeeSchedule;

/// The transaction version of the transparent scaffold.
pub const VERSION_1: u16 = 1;

/// The maximum number of inputs (ADR-010).
pub const MAX_INPUTS: usize = 64;

/// The maximum number of outputs (ADR-010).
pub const MAX_OUTPUTS: usize = 32;

/// The maximum length of the extra data field (ADR-010).
pub const MAX_EXTRA_LEN: usize = 512;

/// The transaction types of the whitepaper, in table order.
///
/// Version 1 carries transfers and coinbases (ADR-024); the other
/// tags are reserved so that their final numbering is frozen now,
/// before any chain exists.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum TxType {
    /// A standard payment.
    Transfer,
    /// The emission of new units and the miner's fee claim
    /// (ADR-024). No inputs, a zero fee, one or two outputs, an
    /// eight-byte little-endian height in the extra field.
    Coinbase,
    /// An output with a release predicate.
    Mandate,
    /// An Ember or Cipher identity registration.
    IdentityRegistration,
    /// A Kleos witness attestation.
    KleosAttestation,
    /// A chamber vote.
    GovernanceVote,
    /// A Ring checkpoint over the ordered DAG tip.
    Checkpoint,
}

impl TxType {
    /// The wire tag of the type.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Transfer => 0,
            Self::Coinbase => 6,
            Self::Mandate => 1,
            Self::IdentityRegistration => 2,
            Self::KleosAttestation => 3,
            Self::GovernanceVote => 4,
            Self::Checkpoint => 5,
        }
    }

    /// Restores a type from its wire tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Transfer),
            6 => Some(Self::Coinbase),
            1 => Some(Self::Mandate),
            2 => Some(Self::IdentityRegistration),
            3 => Some(Self::KleosAttestation),
            4 => Some(Self::GovernanceVote),
            5 => Some(Self::Checkpoint),
            _ => None,
        }
    }
}

impl core::fmt::Display for TxType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Self::Transfer => "transfer",
            Self::Coinbase => "coinbase",
            Self::Mandate => "mandate",
            Self::IdentityRegistration => "identity registration",
            Self::KleosAttestation => "kleos attestation",
            Self::GovernanceVote => "governance vote",
            Self::Checkpoint => "checkpoint",
        };
        f.write_str(name)
    }
}

/// A reference to a prior output: transaction id plus index.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct OutputRef {
    tx: Hash,
    index: u32,
}

impl OutputRef {
    /// Builds an output reference.
    #[must_use]
    pub const fn new(tx: Hash, index: u32) -> Self {
        Self { tx, index }
    }

    /// The transaction that created the output.
    #[must_use]
    pub const fn tx(&self) -> Hash {
        self.tx
    }

    /// The index of the output inside that transaction.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }
}

/// One spent prior output, with its unlock key and proof.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxIn {
    output: OutputRef,
    key: PublicKey,
    signature: Signature,
}

impl TxIn {
    /// A fully specified input, as decoded or as replayed from
    /// vectors.
    #[must_use]
    pub const fn new(output: OutputRef, key: PublicKey, signature: Signature) -> Self {
        Self {
            output,
            key,
            signature,
        }
    }

    /// An unsigned input: the reference and the key it claims to
    /// unlock, with a zeroed signature awaiting [`Transaction::sign`].
    #[must_use]
    pub const fn unsigned(output: OutputRef, key: PublicKey) -> Self {
        Self {
            output,
            key,
            signature: Signature([0u8; 64]),
        }
    }

    /// The output being spent.
    #[must_use]
    pub const fn output_ref(&self) -> OutputRef {
        self.output
    }

    /// The public key the referenced output must pay to.
    #[must_use]
    pub const fn key(&self) -> PublicKey {
        self.key
    }

    /// The Ed25519 signature over the transaction signing message.
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }
}

/// One created output of the transparent scaffold: a full address
/// and a clear amount. Version 2 replaces this pair by a one-time
/// address and a Pedersen commitment.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxOut {
    address: Address,
    amount: Amount,
}

impl TxOut {
    /// Builds an output.
    #[must_use]
    pub const fn new(address: Address, amount: Amount) -> Self {
        Self { address, amount }
    }

    /// The address this output pays to.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// The clear amount of the scaffold.
    #[must_use]
    pub const fn amount(&self) -> Amount {
        self.amount
    }
}

/// A version 1 transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    version: u16,
    tx_type: TxType,
    fee: Amount,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    extra: Vec<u8>,
}

impl Transaction {
    /// Builds an unsigned version 1 transaction.
    ///
    /// Construction runs no validation: [`Transaction::decode`]
    /// enforces the canonical form and [`Transaction::validate`]
    /// the network rules. This split lets a builder assemble a
    /// transaction incrementally before it becomes checkable.
    #[must_use]
    pub fn new(
        tx_type: TxType,
        fee: Amount,
        inputs: Vec<TxIn>,
        outputs: Vec<TxOut>,
        extra: Vec<u8>,
    ) -> Self {
        Self {
            version: VERSION_1,
            tx_type,
            fee,
            inputs,
            outputs,
            extra,
        }
    }

    /// The transaction version; always 1 in this crate.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// The transaction type.
    #[must_use]
    pub const fn tx_type(&self) -> TxType {
        self.tx_type
    }

    /// The explicit fee, in clear.
    #[must_use]
    pub const fn fee(&self) -> Amount {
        self.fee
    }

    /// The inputs, in canonical order.
    #[must_use]
    pub fn inputs(&self) -> &[TxIn] {
        &self.inputs
    }

    /// The outputs.
    #[must_use]
    pub fn outputs(&self) -> &[TxOut] {
        &self.outputs
    }

    /// The bounded free-data field.
    #[must_use]
    pub fn extra(&self) -> &[u8] {
        &self.extra
    }

    /// The canonical encoding, the single serialized form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u16(self.version);
        w.write_u8(self.tx_type.tag());
        w.write_u64(self.fee.atomic());
        w.write_varint(self.inputs.len() as u64);
        for input in &self.inputs {
            w.write_array(input.output.tx.as_bytes());
            w.write_u32(input.output.index);
            w.write_array(&input.key.0);
            w.write_array(&input.signature.0);
        }
        w.write_varint(self.outputs.len() as u64);
        for output in &self.outputs {
            w.write_array(&output.address.as_bytes());
            w.write_u64(output.amount.atomic());
        }
        w.write_bytes(&self.extra);
        w.finish()
    }

    /// The message every input signature covers: the canonical
    /// encoding with all signatures zeroed.
    #[must_use]
    pub fn signing_message(&self) -> Vec<u8> {
        let zeroed = Self {
            version: self.version,
            tx_type: self.tx_type,
            fee: self.fee,
            inputs: self
                .inputs
                .iter()
                .map(|input| TxIn::unsigned(input.output, input.key))
                .collect(),
            outputs: self.outputs.clone(),
            extra: self.extra.clone(),
        };
        zeroed.encode()
    }

    /// The transaction id: Keccak-256 of the signed canonical
    /// encoding.
    #[must_use]
    pub fn tx_id(&self) -> Hash {
        keccak256(&self.encode())
    }

    /// Strictly decodes a transaction from its canonical bytes.
    ///
    /// Non-canonical input order, structural limit violations,
    /// invalid keys or addresses, and trailing bytes are all
    /// errors: a decoder must never normalize what the encoder
    /// could not have produced.
    ///
    /// # Errors
    ///
    /// Returns a [`TxError`] describing the first violation found.
    pub fn decode(bytes: &[u8]) -> Result<Self, TxError> {
        let mut r = Reader::new(bytes);

        let version = r.read_u16()?;
        if version != VERSION_1 {
            return Err(TxError::InvalidVersion(version));
        }
        let tag = r.read_u8()?;
        let tx_type = TxType::from_tag(tag).ok_or(TxError::UnknownType(tag))?;
        if !matches!(tx_type, TxType::Transfer | TxType::Coinbase) {
            return Err(TxError::UnsupportedType(tag));
        }
        let fee = Amount::from_atomic(r.read_u64()?);

        let input_count = r.read_varint()?;
        if input_count > MAX_INPUTS as u64 {
            return Err(TxError::TooManyInputs(input_count as usize));
        }
        let mut inputs = Vec::new();
        for _ in 0..input_count {
            let tx = Hash(r.read_array::<32>()?);
            let index = r.read_u32()?;
            let key = PublicKey::from_bytes(&r.read_array::<32>()?).map_err(TxError::Decode)?;
            let signature = Signature(r.read_array::<64>()?);
            inputs.push(TxIn::new(OutputRef::new(tx, index), key, signature));
        }
        for pair in inputs.windows(2) {
            if pair[0].output >= pair[1].output {
                return Err(TxError::UnsortedInputs);
            }
        }

        let output_count = r.read_varint()?;
        if output_count > MAX_OUTPUTS as u64 {
            return Err(TxError::TooManyOutputs(output_count as usize));
        }
        let mut outputs = Vec::new();
        for _ in 0..output_count {
            let raw = r.read_array::<69>()?;
            let address = Address::from_bytes(&raw).map_err(TxError::Decode)?;
            let amount = Amount::from_atomic(r.read_u64()?);
            outputs.push(TxOut::new(address, amount));
        }

        let extra_bytes = r.read_bytes()?;
        if extra_bytes.len() > MAX_EXTRA_LEN {
            return Err(TxError::ExtraTooLarge(extra_bytes.len()));
        }
        let extra = extra_bytes.to_vec();

        r.finish()?;
        Ok(Self::new(tx_type, fee, inputs, outputs, extra))
    }

    /// Validates the rules decidable from the transaction bytes
    /// alone: at least one input, at least one output, non-zero
    /// amounts, and a fee at or above the schedule minimum for the
    /// canonical size. A coinbase (ADR-024) replaces the input and
    /// fee rules by its own: no inputs, a zero fee, one or two
    /// outputs, an eight-byte little-endian height in the extra
    /// field.
    ///
    /// State-dependent rules (existence, unspentness, conservation
    /// against the referenced outputs, the coinbase value against
    /// the reward calendar, network consistency) belong to the
    /// ordering layer.
    ///
    /// # Errors
    ///
    /// Returns a [`TxError`] naming the violated rule.
    pub fn validate(&self, fees: &FeeSchedule) -> Result<(), TxError> {
        if self.tx_type == TxType::Coinbase {
            return self.validate_coinbase();
        }
        if self.inputs.is_empty() {
            return Err(TxError::NoInputs);
        }
        if self.outputs.is_empty() {
            return Err(TxError::NoOutputs);
        }
        for (index, output) in self.outputs.iter().enumerate() {
            if output.amount.is_zero() {
                return Err(TxError::ZeroAmount(index));
            }
        }
        // An uncomputable minimum rejects: the transaction cannot be
        // accepted under a fee the schedule cannot even express.
        let minimum = fees
            .minimum_fee(self.encode().len(), 0)
            .unwrap_or_else(|| Amount::from_atomic(u64::MAX));
        if self.fee < minimum {
            return Err(TxError::FeeTooLow {
                fee: self.fee,
                minimum,
            });
        }
        Ok(())
    }

    /// The container rules of the coinbase (ADR-024): no inputs, a
    /// zero fee, one or two outputs, an eight-byte extra field. The
    /// height the extra field carries is read by the state layer,
    /// which can see the containing block.
    ///
    /// # Errors
    ///
    /// Returns a [`TxError`] naming the violated rule.
    fn validate_coinbase(&self) -> Result<(), TxError> {
        if !self.inputs.is_empty() {
            return Err(TxError::CoinbaseInputs(self.inputs.len()));
        }
        if !self.fee.is_zero() {
            return Err(TxError::CoinbaseFee);
        }
        if self.outputs.is_empty() || self.outputs.len() > 2 {
            return Err(TxError::CoinbaseOutputs(self.outputs.len()));
        }
        for (index, output) in self.outputs.iter().enumerate() {
            if output.amount.is_zero() {
                return Err(TxError::ZeroAmount(index));
            }
        }
        if self.extra.len() != 8 {
            return Err(TxError::CoinbaseExtra(self.extra.len()));
        }
        Ok(())
    }

    /// Signs every input with the matching key.
    ///
    /// The key list must match the inputs one for one, in order;
    /// each key must be the spend key the corresponding input
    /// claims to unlock.
    ///
    /// # Errors
    ///
    /// Returns [`TxError::KeyCountMismatch`] on a length mismatch,
    /// [`TxError::KeyMismatch`] at the first diverging key.
    pub fn sign(&mut self, keys: &[KeyPair]) -> Result<(), TxError> {
        if keys.len() != self.inputs.len() {
            return Err(TxError::KeyCountMismatch {
                expected: self.inputs.len(),
                provided: keys.len(),
            });
        }
        let message = self.signing_message();
        for (index, (input, key)) in self.inputs.iter_mut().zip(keys).enumerate() {
            if input.key != key.public() {
                return Err(TxError::KeyMismatch(index));
            }
            input.signature = key.sign(&message);
        }
        Ok(())
    }

    /// Verifies every input signature against its key.
    ///
    /// # Errors
    ///
    /// Returns [`TxError::InvalidSignature`] at the first failing
    /// input index.
    pub fn verify_signatures(&self) -> Result<(), TxError> {
        let message = self.signing_message();
        for (index, input) in self.inputs.iter().enumerate() {
            if !verify_ed25519(&input.signature, &message, &input.key) {
                return Err(TxError::InvalidSignature(index));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fee::{F0_MAX, FEE_BASE};
    use antumbra_primitives::DecodeError;
    use antumbra_primitives::Network;

    /// A deterministic address from a seed byte pattern.
    fn address(seed: u8) -> Address {
        let seed = [seed; 32];
        Address::new(
            Network::Devnet,
            KeyPair::spend(&seed).public(),
            KeyPair::view(&seed).public(),
        )
    }

    /// A key pair from a seed byte pattern.
    fn key(seed: u8) -> KeyPair {
        KeyPair::from_seed(&[seed; 32])
    }

    /// A minimal unsigned two-input, two-output transaction whose
    /// fee always clears the provisional minimum.
    fn sample_tx() -> Transaction {
        let inputs = vec![
            TxIn::unsigned(OutputRef::new(Hash([1u8; 32]), 0), key(10).public()),
            TxIn::unsigned(OutputRef::new(Hash([2u8; 32]), 5), key(20).public()),
        ];
        let outputs = vec![
            TxOut::new(address(30), Amount::from_atu(2).expect("fits")),
            TxOut::new(address(31), Amount::from_atomic(7)),
        ];
        // Provisional minimum for ~200 bytes is 200,000 atomic:
        // one ATU clears it with margin.
        Transaction::new(
            TxType::Transfer,
            Amount::ONE_ATU,
            inputs,
            outputs,
            b"memo".to_vec(),
        )
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let mut tx = sample_tx();
        let keys = [key(10), key(20)];
        tx.sign(&keys).expect("keys match");
        assert_eq!(tx.verify_signatures(), Ok(()));
    }

    #[test]
    fn encode_decode_roundtrip_is_exact() {
        let mut tx = sample_tx();
        tx.sign(&[key(10), key(20)]).expect("keys match");
        let bytes = tx.encode();
        let decoded = Transaction::decode(&bytes).expect("canonical bytes");
        assert_eq!(decoded, tx);
        assert_eq!(decoded.encode(), bytes);
        assert_eq!(decoded.tx_id(), tx.tx_id());
    }

    #[test]
    fn tx_id_is_keccak_of_the_signed_encoding() {
        let mut tx = sample_tx();
        tx.sign(&[key(10), key(20)]).expect("keys match");
        assert_eq!(tx.tx_id(), keccak256(&tx.encode()));
    }

    #[test]
    fn signing_message_excludes_signatures() {
        let mut tx = sample_tx();
        let unsigned_message = tx.signing_message();
        tx.sign(&[key(10), key(20)]).expect("keys match");
        assert_eq!(tx.signing_message(), unsigned_message);
        // Flipping a signature changes the id, not the message.
        let id_before = tx.tx_id();
        let flipped = {
            let mut copy = tx.clone();
            copy.inputs[0].signature.0[0] ^= 0x01;
            copy
        };
        assert_ne!(flipped.tx_id(), id_before);
        assert_eq!(flipped.signing_message(), unsigned_message);
        assert_eq!(
            flipped.verify_signatures(),
            Err(TxError::InvalidSignature(0))
        );
    }

    #[test]
    fn tampered_fee_breaks_every_signature() {
        let mut tx = sample_tx();
        tx.sign(&[key(10), key(20)]).expect("keys match");
        let tampered = Transaction::new(
            TxType::Transfer,
            Amount::from_atomic(u64::MAX),
            tx.inputs().to_vec(),
            tx.outputs().to_vec(),
            tx.extra().to_vec(),
        );
        assert_ne!(tampered.fee(), tx.fee());
        assert_eq!(
            tampered.verify_signatures(),
            Err(TxError::InvalidSignature(0))
        );
    }

    #[test]
    fn sign_rejects_key_count_mismatch() {
        let mut tx = sample_tx();
        assert_eq!(
            tx.sign(&[key(10)]),
            Err(TxError::KeyCountMismatch {
                expected: 2,
                provided: 1
            })
        );
    }

    #[test]
    fn sign_rejects_wrong_key() {
        let mut tx = sample_tx();
        assert_eq!(tx.sign(&[key(10), key(99)]), Err(TxError::KeyMismatch(1)));
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let mut tx = sample_tx();
        tx.sign(&[key(10), key(20)]).expect("keys match");
        let mut bytes = tx.encode();
        // Version occupies the first two bytes, little-endian.
        bytes[0] = 0x02;
        bytes[1] = 0x00;
        assert_eq!(Transaction::decode(&bytes), Err(TxError::InvalidVersion(2)));
    }

    #[test]
    fn decode_rejects_unknown_type_tag() {
        let mut tx = sample_tx();
        tx.sign(&[key(10), key(20)]).expect("keys match");
        let mut bytes = tx.encode();
        bytes[2] = 0x63;
        assert_eq!(Transaction::decode(&bytes), Err(TxError::UnknownType(0x63)));
    }

    #[test]
    fn decode_rejects_reserved_type_tags() {
        for tag in 1..=5 {
            let mut tx = sample_tx();
            tx.sign(&[key(10), key(20)]).expect("keys match");
            let mut bytes = tx.encode();
            bytes[2] = tag;
            assert_eq!(
                Transaction::decode(&bytes),
                Err(TxError::UnsupportedType(tag)),
                "tag {tag} is reserved for later versions"
            );
        }
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut tx = sample_tx();
        tx.sign(&[key(10), key(20)]).expect("keys match");
        let mut bytes = tx.encode();
        bytes.push(0x00);
        assert!(matches!(
            Transaction::decode(&bytes),
            Err(TxError::Decode(DecodeError::Trailing(1)))
        ));
    }

    #[test]
    fn decode_rejects_unsorted_inputs() {
        // Build the swapped transaction in-module: two inputs in
        // descending order encode fine but are not canonical.
        let inputs = vec![
            TxIn::unsigned(OutputRef::new(Hash([2u8; 32]), 5), key(20).public()),
            TxIn::unsigned(OutputRef::new(Hash([1u8; 32]), 0), key(10).public()),
        ];
        let tx = Transaction::new(
            TxType::Transfer,
            Amount::ONE_ATU,
            inputs,
            vec![TxOut::new(address(30), Amount::ONE_ATU)],
            Vec::new(),
        );
        assert_eq!(
            Transaction::decode(&tx.encode()),
            Err(TxError::UnsortedInputs)
        );
    }

    #[test]
    fn decode_rejects_duplicate_input() {
        let reference = OutputRef::new(Hash([1u8; 32]), 0);
        let inputs = vec![
            TxIn::unsigned(reference, key(10).public()),
            TxIn::unsigned(reference, key(10).public()),
        ];
        let tx = Transaction::new(
            TxType::Transfer,
            Amount::ONE_ATU,
            inputs,
            vec![TxOut::new(address(30), Amount::ONE_ATU)],
            Vec::new(),
        );
        assert_eq!(
            Transaction::decode(&tx.encode()),
            Err(TxError::UnsortedInputs)
        );
    }

    #[test]
    fn decode_rejects_oversized_extra() {
        let tx = Transaction::new(
            TxType::Transfer,
            Amount::ONE_ATU,
            vec![TxIn::unsigned(
                OutputRef::new(Hash([1u8; 32]), 0),
                key(10).public(),
            )],
            vec![TxOut::new(address(30), Amount::ONE_ATU)],
            vec![0u8; MAX_EXTRA_LEN + 1],
        );
        assert_eq!(
            Transaction::decode(&tx.encode()),
            Err(TxError::ExtraTooLarge(MAX_EXTRA_LEN + 1))
        );
    }

    #[test]
    fn decode_rejects_more_inputs_than_the_limit() {
        let reference = Hash([1u8; 32]);
        let inputs: Vec<TxIn> = (0..=MAX_INPUTS as u32)
            .map(|index| TxIn::unsigned(OutputRef::new(reference, index), key(10).public()))
            .collect();
        let tx = Transaction::new(
            TxType::Transfer,
            Amount::ONE_ATU,
            inputs,
            vec![TxOut::new(address(30), Amount::ONE_ATU)],
            Vec::new(),
        );
        assert_eq!(
            Transaction::decode(&tx.encode()),
            Err(TxError::TooManyInputs(MAX_INPUTS + 1))
        );
    }

    #[test]
    fn decode_rejects_more_outputs_than_the_limit() {
        let outputs: Vec<TxOut> = (0..=MAX_OUTPUTS)
            .map(|_| TxOut::new(address(30), Amount::ONE_ATU))
            .collect();
        let tx = Transaction::new(
            TxType::Transfer,
            Amount::ONE_ATU,
            vec![TxIn::unsigned(
                OutputRef::new(Hash([1u8; 32]), 0),
                key(10).public(),
            )],
            outputs,
            Vec::new(),
        );
        assert_eq!(
            Transaction::decode(&tx.encode()),
            Err(TxError::TooManyOutputs(MAX_OUTPUTS + 1))
        );
    }

    #[test]
    fn validate_rejects_empty_sides() {
        let no_inputs = Transaction::new(
            TxType::Transfer,
            Amount::ONE_ATU,
            Vec::new(),
            vec![TxOut::new(address(30), Amount::ONE_ATU)],
            Vec::new(),
        );
        assert_eq!(
            no_inputs.validate(&FeeSchedule::PROVISIONAL),
            Err(TxError::NoInputs)
        );

        let no_outputs = Transaction::new(
            TxType::Transfer,
            Amount::ONE_ATU,
            vec![TxIn::unsigned(
                OutputRef::new(Hash([1u8; 32]), 0),
                key(10).public(),
            )],
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            no_outputs.validate(&FeeSchedule::PROVISIONAL),
            Err(TxError::NoOutputs)
        );
    }

    #[test]
    fn validate_rejects_zero_amount() {
        let tx = Transaction::new(
            TxType::Transfer,
            Amount::ONE_ATU,
            vec![TxIn::unsigned(
                OutputRef::new(Hash([1u8; 32]), 0),
                key(10).public(),
            )],
            vec![
                TxOut::new(address(30), Amount::ONE_ATU),
                TxOut::new(address(31), Amount::ZERO),
            ],
            Vec::new(),
        );
        assert_eq!(
            tx.validate(&FeeSchedule::PROVISIONAL),
            Err(TxError::ZeroAmount(1))
        );
    }

    #[test]
    fn validate_rejects_fee_below_minimum() {
        let mut tx = sample_tx();
        // The provisional minimum of ~200 bytes is 200,000 atomic.
        let too_low = FeeSchedule::PROVISIONAL
            .minimum_fee(tx.encode().len(), 0)
            .expect("fits");
        tx = Transaction::new(
            TxType::Transfer,
            too_low
                .checked_sub(Amount::from_atomic(1))
                .expect("minimum is positive"),
            tx.inputs().to_vec(),
            tx.outputs().to_vec(),
            tx.extra().to_vec(),
        );
        assert_eq!(
            tx.validate(&FeeSchedule::PROVISIONAL),
            Err(TxError::FeeTooLow {
                fee: tx.fee(),
                minimum: too_low,
            })
        );
    }

    #[test]
    fn validate_accepts_a_valid_transaction() {
        let mut tx = sample_tx();
        tx.sign(&[key(10), key(20)]).expect("keys match");
        assert_eq!(tx.verify_signatures(), Ok(()));
        assert_eq!(tx.validate(&FeeSchedule::PROVISIONAL), Ok(()));
    }

    #[test]
    fn every_type_tag_roundtrips_through_from_tag() {
        for tag in [0u8, 6, 1, 2, 3, 4, 5] {
            let tx_type = TxType::from_tag(tag).expect("the carried tags are defined");
            assert_eq!(tx_type.tag(), tag);
        }
        assert_eq!(TxType::from_tag(7), None);
        assert_eq!(TxType::from_tag(255), None);
    }

    #[test]
    fn fee_schedule_bounds_stay_coherent() {
        // The provisional base must sit inside the governance bounds
        // of ADR-009, and the bounds must be ordered.
        assert!(F0_MAX > FEE_BASE);
        assert!(FEE_BASE > crate::fee::F0_MIN);
    }

    #[test]
    fn canonical_layout_of_the_smallest_transaction() {
        // One input, one output, no extra: the first bytes of the
        // canonical form, asserted once so the layout is pinned.
        let inputs = vec![TxIn::unsigned(
            OutputRef::new(Hash([9u8; 32]), 3),
            key(10).public(),
        )];
        let tx = Transaction::new(
            TxType::Transfer,
            Amount::from_atomic(1),
            inputs,
            vec![TxOut::new(address(30), Amount::ONE_ATU)],
            Vec::new(),
        );
        let bytes = tx.encode();
        assert_eq!(&bytes[0..2], &[0x01, 0x00], "version 1, little-endian");
        assert_eq!(bytes[2], 0x00, "transfer tag");
        assert_eq!(&bytes[3..11], &1u64.to_le_bytes(), "fee 1 atomic");
        assert_eq!(bytes[11], 1, "one input");
        assert_eq!(
            &bytes[12..44],
            &[9u8; 32],
            "the referenced transaction hash"
        );
        assert_eq!(
            &bytes[44..48],
            &3u32.to_le_bytes(),
            "output index 3, little-endian"
        );
        assert_eq!(bytes[12 + 32 + 4 + 32 + 64], 1, "one output");
        // Total: 12 header + 132 input + 1 count + 77 output + 1
        // empty extra prefix.
        assert_eq!(bytes.len(), 12 + 132 + 1 + 77 + 1);
    }

    /// A minimal coinbase: no inputs, zero fee, one output, the
    /// height in the extra field (ADR-024).
    fn sample_coinbase(height: u64) -> Transaction {
        Transaction::new(
            TxType::Coinbase,
            Amount::ZERO,
            Vec::new(),
            vec![TxOut::new(address(40), Amount::from_atomic(9_792_157))],
            height.to_le_bytes().to_vec(),
        )
    }

    #[test]
    fn coinbase_decodes_and_roundtrips() {
        let tx = sample_coinbase(1);
        let bytes = tx.encode();
        let back = Transaction::decode(&bytes).expect("coinbase decodes");
        assert_eq!(back, tx, "encode-decode-encode is the identity");
        assert_eq!(back.tx_type(), TxType::Coinbase);
        assert_eq!(bytes[2], 6, "the coinbase wire tag is 6");
    }

    #[test]
    fn coinbase_validate_accepts_the_container() {
        let fees = FeeSchedule::PROVISIONAL;
        sample_coinbase(1)
            .validate(&fees)
            .expect("container rules hold");
        let two_outputs = Transaction::new(
            TxType::Coinbase,
            Amount::ZERO,
            Vec::new(),
            vec![
                TxOut::new(address(41), Amount::from_atomic(9_187_002)),
                TxOut::new(address(42), Amount::from_atomic(605_155)),
            ],
            7u64.to_le_bytes().to_vec(),
        );
        two_outputs
            .validate(&fees)
            .expect("two outputs are the treasury era form");
    }

    #[test]
    fn coinbase_validate_names_every_violation() {
        let fees = FeeSchedule::PROVISIONAL;
        let with_input = Transaction::new(
            TxType::Coinbase,
            Amount::ZERO,
            vec![TxIn::unsigned(
                OutputRef::new(Hash([1u8; 32]), 0),
                key(10).public(),
            )],
            vec![TxOut::new(address(40), Amount::from_atomic(1))],
            1u64.to_le_bytes().to_vec(),
        );
        assert_eq!(with_input.validate(&fees), Err(TxError::CoinbaseInputs(1)));

        let with_fee = Transaction::new(
            TxType::Coinbase,
            Amount::from_atomic(1),
            Vec::new(),
            vec![TxOut::new(address(40), Amount::from_atomic(1))],
            1u64.to_le_bytes().to_vec(),
        );
        assert_eq!(with_fee.validate(&fees), Err(TxError::CoinbaseFee));

        let three_outputs = Transaction::new(
            TxType::Coinbase,
            Amount::ZERO,
            Vec::new(),
            vec![
                TxOut::new(address(40), Amount::from_atomic(1)),
                TxOut::new(address(41), Amount::from_atomic(1)),
                TxOut::new(address(42), Amount::from_atomic(1)),
            ],
            1u64.to_le_bytes().to_vec(),
        );
        assert_eq!(
            three_outputs.validate(&fees),
            Err(TxError::CoinbaseOutputs(3))
        );

        let bad_extra = Transaction::new(
            TxType::Coinbase,
            Amount::ZERO,
            Vec::new(),
            vec![TxOut::new(address(40), Amount::from_atomic(1))],
            vec![0u8; 7],
        );
        assert_eq!(bad_extra.validate(&fees), Err(TxError::CoinbaseExtra(7)));
    }

    #[test]
    fn reserved_tags_stay_reserved_beyond_the_coinbase() {
        for tag in [1u8, 2, 3, 4, 5, 7] {
            let tx = sample_coinbase(1);
            let mut bytes = tx.encode();
            bytes[2] = tag;
            let expected = if tag < 6 {
                Err(TxError::UnsupportedType(tag))
            } else {
                Err(TxError::UnknownType(tag))
            };
            assert_eq!(Transaction::decode(&bytes), expected, "tag {tag}");
        }
    }
}

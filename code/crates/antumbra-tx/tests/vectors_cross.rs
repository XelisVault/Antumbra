//! Cross-implementation vector tests for the transaction layer
//! (CONTRIBUTING.md, layer 1).
//!
//! The archived vector set in `tests/vectors.json` is produced by
//! `code/scripts/gen_tx_vectors.py`, an independent implementation
//! of the amount format, the fee formula, the canonical encoding,
//! the signing message, the input signatures and the transaction
//! id (pycryptodome for Keccak-256 and Ed25519, from-spec
//! reimplementations for the rest). The Rust implementation must
//! agree bit for bit. A disagreement here is not a test failure:
//! it is a consensus fault, and it blocks the phase.

use antumbra_primitives::keys::KeyPair;
use antumbra_primitives::{Address, Hash, Network, Signature};
use antumbra_tx::amount::Amount;
use antumbra_tx::fee::FeeSchedule;
use antumbra_tx::{OutputRef, Transaction, TxIn, TxOut, TxType};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    #[allow(dead_code)] // archived metadata, read for completeness
    format: u32,
    amount: Vec<AmountVector>,
    fee: Vec<FeeVector>,
    transaction: Vec<TransactionVector>,
}

#[derive(Deserialize)]
struct AmountVector {
    atomic: u64,
    text: String,
}

#[derive(Deserialize)]
struct FeeVector {
    size: usize,
    ringed: u64,
    minimum: Option<u64>,
}

#[derive(Deserialize)]
struct TransactionVector {
    network: String,
    inputs: Vec<InputVector>,
    outputs: Vec<OutputVector>,
    fee: u64,
    extra_hex: String,
    canonical_hex: String,
    signing_message_hex: String,
    tx_id: String,
}

#[derive(Deserialize)]
struct InputVector {
    seed: String,
    tx: String,
    index: u32,
    key: String,
    signature: String,
}

#[derive(Deserialize)]
struct OutputVector {
    seed: String,
    address: String,
    amount: u64,
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

fn unhex64(s: &str) -> [u8; 64] {
    unhex(s).try_into().expect("64 bytes")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn network_by_name(name: &str) -> Network {
    match name {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        "devnet" => Network::Devnet,
        other => panic!("unknown network in vectors: {other}"),
    }
}

fn load() -> Vectors {
    let raw = include_str!("vectors.json");
    serde_json::from_str(raw).expect("valid archived vector set")
}

fn rebuild_transaction(v: &TransactionVector) -> Transaction {
    // Rebuild from the seeds, the references and the fields: the
    // same construction a wallet would perform.
    let mut inputs = Vec::with_capacity(v.inputs.len());
    for input in &v.inputs {
        let seed = unhex32(&input.seed);
        let keypair = KeyPair::spend(&seed);
        assert_eq!(
            keypair.public().to_string(),
            input.key,
            "spend key derivation diverged"
        );
        inputs.push(TxIn::new(
            OutputRef::new(Hash(unhex32(&input.tx)), input.index),
            keypair.public(),
            Signature(unhex64(&input.signature)),
        ));
    }

    let mut outputs = Vec::with_capacity(v.outputs.len());
    for output in &v.outputs {
        let seed = unhex32(&output.seed);
        let address = Address::new(
            network_by_name(&v.network),
            KeyPair::spend(&seed).public(),
            KeyPair::view(&seed).public(),
        );
        assert_eq!(
            address.to_string(),
            output.address,
            "address derivation diverged"
        );
        outputs.push(TxOut::new(address, Amount::from_atomic(output.amount)));
    }

    Transaction::new(
        TxType::Transfer,
        Amount::from_atomic(v.fee),
        inputs,
        outputs,
        unhex(&v.extra_hex),
    )
}

#[test]
fn amount_display_matches_the_independent_implementation() {
    for v in load().amount {
        assert_eq!(
            Amount::from_atomic(v.atomic).to_string(),
            v.text,
            "amount display diverged on {}",
            v.atomic
        );
    }
}

#[test]
fn minimum_fee_matches_the_independent_implementation() {
    for v in load().fee {
        let computed = FeeSchedule::PROVISIONAL.minimum_fee(v.size, v.ringed);
        assert_eq!(
            computed.map(|fee| fee.atomic()),
            v.minimum,
            "minimum fee diverged on size {} ringed {}",
            v.size,
            v.ringed
        );
    }
}

#[test]
fn transactions_match_the_independent_implementation() {
    for v in load().transaction {
        let tx = rebuild_transaction(&v);

        // Canonical encoding, bit for bit.
        assert_eq!(
            hex(&tx.encode()),
            v.canonical_hex,
            "canonical encoding diverged (fee {})",
            v.fee
        );

        // The signing message is the zeroed-signature encoding.
        assert_eq!(hex(&tx.signing_message()), v.signing_message_hex);

        // The id is Keccak-256 of the signed encoding.
        assert_eq!(tx.tx_id().to_string(), v.tx_id);

        // Every input signature verifies against its key.
        assert_eq!(
            tx.verify_signatures(),
            Ok(()),
            "a generated signature does not verify"
        );

        // Strict decoding of the archived bytes rebuilds the exact
        // transaction, and re-encoding is byte-identical.
        let canonical = unhex(&v.canonical_hex);
        let decoded = Transaction::decode(&canonical)
            .unwrap_or_else(|e| panic!("archived transaction decodes: {e}"));
        assert_eq!(decoded, tx);
        assert_eq!(hex(&decoded.encode()), v.canonical_hex);

        // The archived transaction passes the stateless rules
        // under the provisional schedule.
        assert_eq!(decoded.validate(&FeeSchedule::PROVISIONAL), Ok(()));
    }
}

#[test]
fn the_vector_set_covers_the_structural_boundaries() {
    let vectors = load().transaction;
    // The boundary shapes the ADR pins: the input limit, the
    // extra-data limit, and a wide output fan.
    assert!(vectors.iter().any(|v| v.inputs.len() == 64));
    assert!(vectors.iter().any(|v| unhex(&v.extra_hex).len() == 512));
    assert!(vectors.iter().any(|v| v.outputs.len() == 16));
    let networks: Vec<&str> = vectors.iter().map(|v| v.network.as_str()).collect();
    for expected in ["mainnet", "testnet", "devnet"] {
        assert!(networks.contains(&expected), "network {expected} covered");
    }
}
